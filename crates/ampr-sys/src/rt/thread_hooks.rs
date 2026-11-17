//! Thread creation hooks (both builds, every title, rt/hook.rs ids
//! 110..=111), the runtime's own thread creation and its thread budget.
//!
//! A game has a limit on live threads, and the runtime's threads take room
//! from it: a title's scePthreadCreate failed with 0x80020023 (EAGAIN) after
//! 94 creations while the runtime held ~39 threads. When a game creation
//! fails with EAGAIN, the hook asks the runtime's thread groups to give
//! threads back and retries while they can (`retry_with_room`); the thread
//! budget below keeps them from growing back.
//!
//! The runtime creates its own threads through `create_internal`, so they
//! never pass the hook. Debug builds log each failure as op b'P' (`FsEvents`
//! in rt/stats.rs) and serve `GET /threads` (rt/exports.rs) to measure the
//! limit.

use super::stats::{self, Stat};
use super::sys::{self, kernel_slot, EAGAIN, SCE_KERNEL_ERROR_EAGAIN};
use core::ffi::{c_char, c_int, c_void};

pub(crate) type ThreadEntry = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SceCreateFn = unsafe extern "C" fn(
    *mut *mut c_void,
    *const c_void,
    ThreadEntry,
    *mut c_void,
    *const c_char,
) -> c_int;
type PosixCreateFn =
    unsafe extern "C" fn(*mut *mut c_void, *const c_void, ThreadEntry, *mut c_void) -> c_int;

/// scePthreadCreate through libkernel's original entry point (the detour's
/// trampoline once installed, else the plain import), for every thread the
/// runtime creates itself. Without `attr` the thread gets a pool stack of
/// libkernel's default size (`create_internal_stack`); a caller's `attr`
/// (the debug thread hold) is passed as given.
pub(crate) unsafe fn create_internal(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    if attr.is_null() {
        return unsafe { create_internal_stack(thread, entry, arg, name, 0) };
    }
    unsafe { create_raw(thread, attr, entry, arg, name) }
}

unsafe fn create_raw(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    unsafe { original_create()(thread, attr, entry, arg, name) }
}

/// libkernel's scePthreadCreate: the detour's trampoline, or with an empty
/// slot the import. The slot is filled before the detour is written and
/// emptied only after the original bytes are back (rt/hook.rs), so with it
/// empty the import is the original, not the hook.
fn original_create() -> SceCreateFn {
    unsafe { kernel_slot::<SceCreateFn>(sys::hook::scePthreadCreate) }.unwrap_or(create_import)
}

/// The scePthreadCreate import as a `SceCreateFn`.
unsafe extern "C" fn create_import(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    unsafe { super::reactor::scePthreadCreate(thread.cast(), attr.cast(), entry, arg, name) }
}

type AttrFn = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
type StackSizeFn = unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int;
type GetStackSizeFn = unsafe extern "C" fn(*const *mut c_void, *mut usize) -> c_int;
type SetStackFn = unsafe extern "C" fn(*mut *mut c_void, *mut c_void, usize) -> c_int;
static ATTR_INIT: sys::LazySym = sys::LazySym::new(c"scePthreadAttrInit");
static ATTR_DESTROY: sys::LazySym = sys::LazySym::new(c"scePthreadAttrDestroy");
static ATTR_SET_STACK_SIZE: sys::LazySym = sys::LazySym::new(c"scePthreadAttrSetstacksize");
static ATTR_GET_STACK_SIZE: sys::LazySym = sys::LazySym::new(c"scePthreadAttrGetstacksize");
static ATTR_SET_STACK: sys::LazySym = sys::LazySym::new(c"scePthreadAttrSetstack");

/// The stack size of a fresh attribute, libkernel's default; 0 when it
/// will not say (the thread then gets libkernel's own stack).
unsafe fn default_stack_size(attr: &*mut c_void) -> usize {
    let Some(get) = (unsafe { ATTR_GET_STACK_SIZE.get::<GetStackSizeFn>() }) else {
        return 0;
    };
    let mut v = 0usize;
    match unsafe { get(attr, &mut v) } {
        0 => v,
        _ => 0,
    }
}

/// `create_internal` with a `stack`-byte stack (0: libkernel's default
/// size, read from a fresh attribute). The stack comes from the pool
/// (rt/thread_stack.rs) when the block has room and libkernel takes it;
/// otherwise libkernel allocates it as before, with the default stack when
/// it refuses the size.
pub(crate) unsafe fn create_internal_stack(
    thread: *mut *mut c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
    stack: usize,
) -> c_int {
    let init = unsafe { ATTR_INIT.get::<AttrFn>() };
    let mut attr: *mut c_void = core::ptr::null_mut();
    let have = init.is_some_and(|init| unsafe { init(&mut attr) } == 0);
    let mut slot = None;
    let mut set = false;
    if have {
        let size = match stack {
            0 => unsafe { default_stack_size(&attr) },
            n => n,
        };
        if let Some(put) = unsafe { ATTR_SET_STACK.get::<SetStackFn>() } {
            slot = unsafe { super::thread_stack::take(size, thread) };
            if let Some(s) = &slot {
                set = unsafe { put(&mut attr, s.addr, s.size) } == 0;
            }
        }
        if !set {
            if let Some(s) = slot.take() {
                unsafe { super::thread_stack::cancel(s) };
            }
            if stack != 0 {
                set = unsafe { ATTR_SET_STACK_SIZE.get::<StackSizeFn>() }
                    .is_some_and(|f| unsafe { f(&mut attr, stack) } == 0);
            }
        }
    }
    let attr_ptr: *const c_void = if set {
        (&attr as *const *mut c_void).cast()
    } else {
        core::ptr::null()
    };
    let rc = unsafe { create_raw(thread, attr_ptr, entry, arg, name) };
    match slot {
        Some(s) if rc == 0 => {
            super::thread_stack::bind(s, unsafe { *thread });
            stats::add(Stat::ThreadStacksPool, 1);
        }
        Some(s) => unsafe { super::thread_stack::cancel(s) },
        None if rc == 0 => stats::add(Stat::ThreadStacksLibkernel, 1),
        None => {}
    }
    if have {
        if let Some(destroy) = unsafe { ATTR_DESTROY.get::<AttrFn>() } {
            let _ = unsafe { destroy(&mut attr) };
        }
    }
    rc
}

/// Debug: a 'P' event (op letters at `FsEvents` in rt/stats.rs), path
/// "<call> <thread name>".
fn log_event(how: u8, rc: i64, call: &[u8], name: *const c_char) {
    if !cfg!(feature = "mem_report") {
        return;
    }
    let mut buf = [0u8; 96];
    let mut n = 0;
    for &b in call.iter().chain(b" ") {
        buf[n] = b;
        n += 1;
    }
    let mut i = 0;
    while !name.is_null() && n + 1 < buf.len() {
        let b = unsafe { *name.add(i) } as u8;
        if b == 0 {
            break;
        }
        buf[n] = b;
        n += 1;
        i += 1;
    }
    stats::fs_event(b'P', how, rc, buf.as_ptr().cast());
}

/// Debug: counts a game creation attempt; a failure is logged, lookup
/// `how` (b's' scePthreadCreate, b'p' pthread_create).
fn note(how: u8, rc: i64, call: &[u8], name: *const c_char) {
    stats::add(Stat::ThreadsCreated, 1);
    if rc < 0 {
        stats::add(Stat::ThreadCreateFailed, 1);
        log_event(how, rc, call, name);
    }
}

/// After a failed game creation (pressure mode): true when the runtime gave
/// threads back, so a retry may succeed. Every group gives its idle
/// threads: the read pool down to none (reads then go to kernel AIO), the
/// decode workers down to one. The budget
/// stops every group growing meanwhile.
fn make_room() -> bool {
    use super::{pack, reactor};
    let before = [reactor::pread_pool_live(), pack::pack_workers_live()];
    // Both asked first, then one wait: each thread leaves after its
    // current call, so the groups drain in parallel within the 50 ms.
    unsafe {
        let _ = reactor::pread_pool_ask(u32::MAX);
        let _ = pack::pack_workers_ask(u32::MAX);
    }
    // Includes exits another failing creation asked for: wait for them too,
    // and retry while some leave, since a request no thread can meet must
    // not keep the game retrying.
    // No exit pending may also mean every asked thread left already: the
    // reap below counts those, so the game's creation is still retried.
    let pending = pending_exits();
    for _ in 0..50 {
        if pending == 0 || pending_exits() == 0 {
            break;
        }
        unsafe { sys::sceKernelUsleep(1000) };
    }
    let left = unsafe { reactor::pread_pool_reap(before[0]) + pack::pack_workers_reap(before[1]) };
    left != 0 || pending_exits() < pending
}

/// Thread exits asked of the groups that have not happened yet.
fn pending_exits() -> u32 {
    super::reactor::pread_pool_pending_exits() + super::pack::pack_workers_pending_exits()
}

#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn scePthreadCreate_emul(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    // An empty slot (the uninstall window) takes the import, as the
    // runtime's own creations do, instead of failing the game's creation.
    let f = original_create();
    let rc = unsafe { f(thread, attr, entry, arg, name) };
    note(b's', rc.into(), b"scePthreadCreate", name);
    // Until it succeeds or the runtime has nothing left to give: games do not
    // expect a creation to fail, and one retry was not always enough.
    retry_with_room(rc, SCE_KERNEL_ERROR_EAGAIN, || {
        let rc = unsafe { f(thread, attr, entry, arg, name) };
        retried(rc == 0, rc.into(), b"scePthreadCreate", name);
        rc
    })
}

/// pthread_create returns a positive errno; it is logged negated.
pub(crate) unsafe extern "C" fn pthread_create_emul(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
) -> c_int {
    let Some(f) = (unsafe { kernel_slot::<PosixCreateFn>(sys::hook::pthread_create) }) else {
        return EAGAIN;
    };
    let rc = unsafe { f(thread, attr, entry, arg) };
    note(b'p', -i64::from(rc), b"pthread_create", core::ptr::null());
    retry_with_room(rc, EAGAIN, || {
        let rc = unsafe { f(thread, attr, entry, arg) };
        retried(rc == 0, -i64::from(rc), b"pthread_create", core::ptr::null());
        rc
    })
}

/// Counts the retry after threads were given back, logged as "<call>-retry"
/// so /fsfail keeps it apart from the first failure: rc -1 when it
/// succeeded, else its error.
fn retried(ok: bool, rc: i64, call: &[u8], name: *const c_char) {
    stats::add(Stat::ThreadCreateRetried, 1);
    if ok {
        stats::add(Stat::ThreadCreateRescued, 1);
    } else {
        stats::add(Stat::ThreadCreateFailed, 1);
    }
    let mut text = [0u8; 32];
    let n = call.len().min(text.len() - 6);
    text[..n].copy_from_slice(&call[..n]);
    text[n..n + 6].copy_from_slice(b"-retry");
    log_event(b'r', if ok { -1 } else { rc }, &text[..n + 6], name);
}

// ---- thread budget ----------------------------------------------------------
//
// One budget for every worker thread the runtime grows (read pool, pack
// workers): the lower of what failures left (BUDGET) and the
// `thread_budget` knob (16, read at each reservation). A group's first
// thread is always allowed, even past the knob, so no group is starved.
// Lowering the knob stops no thread: new reservations wait until the live
// count drops below it; raising it lets regrowth reach the new value. When a
// game creation fails with EAGAIN no group grows (`cut_at`), the groups give
// threads back, and the budget becomes what is left (`settle_at`). After
// tune::regrow_ns (5 s) with no failure it grows by one (`reserve`), up to
// one below the failure level, which is forgotten after FAIL_MEMORY_NS. So
// the runtime finds the game's room over a run instead of staying cut or
// failing the game again at every regrowth.

/// How long a failure level is remembered: a game's own thread count moves
/// between loading and play, so an old level stops being the limit.
const FAIL_MEMORY_NS: u64 = 300_000_000_000;
/// Worker threads now: reserved at creation, released when the thread
/// function returns (`counted_entry`) or the creation failed.
static LIVE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// What failures left of the budget; the knob caps it (`budget_with`).
static BUDGET: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(super::tune::THREAD_BUDGET);
/// Last cut or regrow; growth waits tune::regrow_ns after it.
static BUDGET_CHANGED_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Game creations between their failure and its settle: no group grows.
static CUTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Failure level: fewest worker threads the runtime held when a game
/// creation failed, and when. Regrowth stops one below it until
/// FAIL_MEMORY_NS passes without a failure. u32::MAX: none.
static FAIL_LEVEL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static FAIL_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The budget now: what failures left, at most the knob.
fn budget_now() -> u32 {
    budget_with(super::tune::thread_budget())
}

/// `budget_now` with the knob value passed in.
fn budget_with(max: u32) -> u32 {
    BUDGET.load(core::sync::atomic::Ordering::Relaxed).min(max)
}

/// A slot for one new worker thread; `first`: the group has none (always
/// allowed). False at the budget or while a game creation fails. The slot
/// is released by `create_counted`: when the thread returns, or at once
/// when its creation fails.
pub(crate) fn reserve(first: bool) -> bool {
    let max = super::tune::thread_budget();
    reserve_at(first, max, super::tune::regrow_ns(), super::services::time_counter_now)
}

/// `reserve` with the knobs (`max` budget, `regrow` ns) and the clock passed
/// in; the clock is read only at the budget.
fn reserve_at(first: bool, max: u32, regrow: u64, clock: impl Fn() -> u64) -> bool {
    use core::sync::atomic::Ordering::{AcqRel, Relaxed};
    if !first && CUTS.load(Relaxed) != 0 {
        return false;
    }
    let mut budget = budget_with(max);
    let live = LIVE.load(Relaxed);
    if !first && live >= budget {
        let now = clock();
        let level = FAIL_LEVEL.load(Relaxed);
        let limit = if level != u32::MAX && now.saturating_sub(FAIL_NS.load(Relaxed)) < FAIL_MEMORY_NS {
            level.saturating_sub(1).max(1).min(max)
        } else {
            max
        };
        // BUDGET at or past the knob: the knob is the limit, nothing grows.
        let cut = BUDGET.load(Relaxed);
        if cut >= limit
            || now.saturating_sub(BUDGET_CHANGED_NS.load(Relaxed)) < regrow
            || BUDGET.compare_exchange(cut, cut + 1, AcqRel, Relaxed).is_err()
        {
            return false;
        }
        BUDGET_CHANGED_NS.store(now, Relaxed);
        stats::add(Stat::ThreadBudgetRegrows, 1);
        budget = (cut + 1).min(max);
    }
    let mut cur = live;
    loop {
        if !first && cur >= budget {
            return false;
        }
        match LIVE.compare_exchange_weak(cur, cur + 1, AcqRel, Relaxed) {
            Ok(_) => return true,
            Err(v) => cur = v,
        }
    }
}

/// Releases a reservation whose creation failed.
pub(crate) fn unreserve() {
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
}

/// A game creation failed (once per failing call): no group grows until
/// that call settles, and the failure level takes what the runtime holds.
fn cut_at(now: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    CUTS.fetch_add(1, Relaxed);
    if now.saturating_sub(FAIL_NS.load(Relaxed)) >= FAIL_MEMORY_NS {
        FAIL_LEVEL.store(u32::MAX, Relaxed);
    }
    // fetch_min: two failing creations at once keep the lower level.
    FAIL_LEVEL.fetch_min(LIVE.load(Relaxed).max(1), Relaxed);
    FAIL_NS.store(now, Relaxed);
    PRESSURE_NS.store(now.max(1), Relaxed);
    stats::add(Stat::ThreadBudgetCuts, 1);
}

/// The failing call is through (whatever its result): the budget is at most
/// what the runtime holds now (at least 1); regrowth, and the end of pressure
/// mode, wait tune::regrow_ns from here.
fn settle_at(now: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let left = LIVE.load(Relaxed).max(1);
    let _ = BUDGET.fetch_min(left, Relaxed);
    BUDGET_CHANGED_NS.store(now, Relaxed);
    PRESSURE_NS.store(now.max(1), Relaxed);
    CUTS.fetch_sub(1, Relaxed);
}

/// Retries a failed game creation (`create` returns `failed` on EAGAIN)
/// while the runtime can give threads back, under a budget cut.
fn retry_with_room(mut rc: c_int, failed: c_int, mut create: impl FnMut() -> c_int) -> c_int {
    if rc != failed {
        return rc;
    }
    cut_at(super::services::time_counter_now());
    // At least one retry: threads another failing creation asked to leave
    // may be gone before this call's make_room looks, so it finds none to
    // count yet the room is there. Further retries only while room is made.
    let mut first = true;
    while rc == failed && (make_room() || core::mem::take(&mut first)) {
        rc = create();
    }
    settle_at(super::services::time_counter_now());
    rc
}

/// (worker threads live, budget now) for debug /metrics.
#[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
pub(crate) fn budget_state() -> (u32, u32) {
    (LIVE.load(core::sync::atomic::Ordering::Relaxed), budget_now())
}

/// Worker threads the budget still lets the runtime start (0 during a cut).
pub(crate) fn budget_room() -> u32 {
    use core::sync::atomic::Ordering::Relaxed;
    if CUTS.load(Relaxed) != 0 {
        return 0;
    }
    budget_now().saturating_sub(LIVE.load(Relaxed))
}

/// Start arguments of counted threads, by slot: (entry, arg); entry 0 free.
/// A slot is held only from creation to the thread's first instruction;
/// the budget plus each group's always-allowed first thread fits easily.
const COUNTED_SLOTS: usize = super::tune::THREAD_BUDGET as usize + 8;
static COUNTED_ENTRY: [core::sync::atomic::AtomicUsize; COUNTED_SLOTS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; COUNTED_SLOTS];
static COUNTED_ARG: [core::sync::atomic::AtomicUsize; COUNTED_SLOTS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; COUNTED_SLOTS];

unsafe extern "C" fn counted_entry(slot: *mut c_void) -> *mut c_void {
    use core::sync::atomic::Ordering::{AcqRel, Acquire};
    let i = slot as usize;
    let arg = COUNTED_ARG[i].load(Acquire) as *mut c_void;
    let entry = COUNTED_ENTRY[i].load(Acquire);
    COUNTED_ENTRY[i].store(0, core::sync::atomic::Ordering::Release);
    let entry: ThreadEntry = unsafe { core::mem::transmute(entry) };
    let rc = unsafe { entry(arg) };
    LIVE.fetch_sub(1, AcqRel);
    rc
}

/// `create_internal_stack` (stack 0: libkernel's default size) for a worker
/// thread holding a `reserve`d slot: the slot is released when `entry`
/// returns, or here when the creation fails.
pub(crate) unsafe fn create_counted(
    thread: *mut *mut c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
    stack: usize,
) -> c_int {
    use core::sync::atomic::Ordering::{AcqRel, Relaxed, Release};
    let Some(i) = (0..COUNTED_SLOTS).find(|&i| {
        COUNTED_ENTRY[i]
            .compare_exchange(0, usize::MAX, AcqRel, Relaxed)
            .is_ok()
    }) else {
        unreserve();
        return SCE_KERNEL_ERROR_EAGAIN;
    };
    COUNTED_ARG[i].store(arg as usize, Release);
    COUNTED_ENTRY[i].store(entry as usize, Release);
    let rc = unsafe { create_internal_stack(thread, counted_entry, i as *mut c_void, name, stack) };
    if rc != 0 {
        COUNTED_ENTRY[i].store(0, Release);
        unreserve();
        // Our own creation failed: the game is at its limit too, so the
        // budget is what is live, as after a game failure (`settle_at`).
        let _ = BUDGET.fetch_min(LIVE.load(Relaxed).max(1), Relaxed);
        BUDGET_CHANGED_NS.store(super::services::time_counter_now(), Relaxed);
    }
    rc
}

// ---- pressure-mode retirement ----
//
// A runtime thread, once started, stays: peak busy was 4 decode workers
// (~0.2 cores of work) and 4-5 disk threads with 9-11 runtime threads live
// on two titles (debug /metrics). Retiring by load churned: decode workers
// retired and restarted 164 times in 120 s, 509 in 159 s and 217 in 147 s
// on three runs (debug /metrics), and it was off by default before it was
// removed. Threads leave only in pressure mode (a game creation failed with
// EAGAIN in the last tune::regrow_ns, 5 s): idle threads leave at once and
// each group keeps at most one, while it has work or the one it started
// after the yield (`LoadGroup::held`), so a read stream does not create and
// retire a thread per read. The decode workers never go below one
// (`LoadGroup::floor`).

/// Last game creation failure (settled), ns; 0: none, normal mode.
static PRESSURE_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Exits a yield asks of a group with `live` threads: up to `want`, leaving
/// `keep` and not asking twice for the `pending` exits already asked.
pub(crate) fn exits_to_ask(want: u32, live: u32, keep: u32, pending: u32) -> u32 {
    want.min(live.saturating_sub(keep + pending))
}

/// A thread leaves (by load, under its group's lock): it meets one pending
/// exit request if any, so no request outlives the threads that could meet
/// it (make_room would wait on it and later threads would leave for it).
pub(crate) fn take_exit_request(requests: &core::sync::atomic::AtomicU32) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    // Requests change only under the group's lock: no race between the two.
    if requests.load(Relaxed) == 0 {
        return false;
    }
    requests.fetch_sub(1, Relaxed);
    true
}

/// Pressure mode at `now`: a failure at `last` (0: none) less than `window`
/// ago.
fn pressure_at(now: u64, last: u64, window: u64) -> bool {
    last != 0 && now.saturating_sub(last) < window
}

/// `pressure` with the clock and the window passed in.
#[cfg(test)]
fn pressure_with(now: u64, window: u64) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    CUTS.load(Relaxed) != 0 || pressure_at(now, PRESSURE_NS.load(Relaxed), window)
}

/// Pressure mode now: a game creation is failing, or failed less than
/// tune::regrow_ns ago. The clock is read only after a failure.
pub(crate) fn pressure() -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if CUTS.load(Relaxed) != 0 {
        return true;
    }
    let last = PRESSURE_NS.load(Relaxed);
    if last == 0 {
        return false;
    }
    if pressure_at(super::services::time_counter_now(), last, super::tune::regrow_ns()) {
        return true;
    }
    // Over: later checks skip the clock. A failure meanwhile stores a newer
    // time, which the exchange keeps.
    let _ = PRESSURE_NS.compare_exchange(last, 0, Relaxed, Relaxed);
    false
}

/// Debug counters and pressure state of one thread group; every method runs
/// under the group's lock, so Relaxed atomics are enough.
pub(crate) struct LoadGroup {
    peak: core::sync::atomic::AtomicU32,
    /// Threads the group may keep at the last retirement check.
    target: core::sync::atomic::AtomicU32,
    retired_pressure: core::sync::atomic::AtomicU32,
    /// Threads the group never retires below: 1 for the decode workers, whose
    /// queued jobs have no other thread to run on; 0 for the read groups,
    /// whose reads go to kernel AIO or run inline at none.
    floor: u32,
    /// A thread started under pressure since the last yield: pressure mode
    /// keeps it (target 1), so a group restarted by a read does not create
    /// and retire a thread per read.
    held: core::sync::atomic::AtomicBool,
}

impl LoadGroup {
    /// A group that keeps at least `floor` threads. All zero but `floor`,
    /// so a group static stays in .bss.
    pub(crate) const fn new(floor: u32) -> Self {
        use core::sync::atomic::{AtomicBool, AtomicU32};
        Self {
            peak: AtomicU32::new(0),
            target: AtomicU32::new(0),
            retired_pressure: AtomicU32::new(0),
            floor,
            held: AtomicBool::new(false),
        }
    }
    /// A thread started; `live` counts it.
    pub(crate) fn started(&self, live: u32) {
        self.started_with(live, pressure());
    }
    /// `started` with the mode passed in.
    fn started_with(&self, live: u32, pressure: bool) {
        use core::sync::atomic::Ordering::Relaxed;
        self.peak.fetch_max(live, Relaxed);
        if pressure {
            self.held.store(true, Relaxed);
        }
    }
    /// A failed game creation asks this group for threads: pressure mode
    /// stops keeping the one it restarted until it starts one again.
    pub(crate) fn asked(&self) {
        self.held.store(false, core::sync::atomic::Ordering::Relaxed);
    }
    /// A group with `live` threads may start one more: always in normal
    /// mode (cap and budget checked by the caller), only its first under
    /// pressure.
    pub(crate) fn may_grow(&self, live: u32) -> bool {
        live == 0 || !pressure()
    }
    /// A thread that finished its work leaves now: pressure mode, and
    /// `live` (it included) is above the target. `has_work`: work it could
    /// take next. Counts it.
    pub(crate) fn retire_due(&self, live: u32, cap: u32, has_work: bool) -> bool {
        self.retire_due_with(live, cap, has_work, pressure())
    }
    /// `retire_due` with the mode passed in.
    fn retire_due_with(&self, live: u32, cap: u32, has_work: bool, pressure: bool) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        if !pressure {
            self.held.store(false, Relaxed);
            return false;
        }
        // One thread while there is work or a restarted one is held, else 0.
        let hold = has_work || self.held.load(Relaxed);
        let target = (hold as u32).min(cap);
        self.target.store(target, Relaxed);
        if live <= target.max(self.floor) {
            return false;
        }
        self.retired_pressure.fetch_add(1, Relaxed);
        true
    }
    /// `n` threads left on a failed game creation's request.
    pub(crate) fn yielded(&self, n: u32) {
        self.retired_pressure.fetch_add(n, core::sync::atomic::Ordering::Relaxed);
    }
    /// Debug /metrics: (peak live, target, retired under pressure).
    #[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
    pub(crate) fn metrics(&self) -> [u64; 3] {
        use core::sync::atomic::Ordering::Relaxed;
        [
            self.peak.load(Relaxed).into(),
            self.target.load(Relaxed).into(),
            self.retired_pressure.load(Relaxed).into(),
        ]
    }
}

// ---- debug: thread limit probe ----------------------------------------------

/// `GET /threads?hold=N`: creates up to N more idle threads (16 KiB stacks
/// when libkernel allows), stops at the first failure, and keeps them until
/// `GET /threads?release=1`. Every 8th held thread goes to the black box (op
/// b'P', lookup b'h', rc = count), so a game that dies from the lack of
/// threads leaves the count in /data/ampr_emu_trace.txt.
#[cfg(feature = "mem_report")]
pub(crate) mod limit_probe {
    use super::*;
    use crate::rt::sync::{Condvar, Mutex};
    use core::sync::atomic::{AtomicBool, Ordering};

    pub(crate) const MAX_HELD: usize = 1024;
    const STACK: usize = 16 * 1024;

    static M: Mutex = Mutex::new();
    static CV: Condvar = Condvar::new();
    static RELEASE: AtomicBool = AtomicBool::new(false);
    struct Held {
        threads: [*mut c_void; MAX_HELD],
        count: usize,
        last_rc: i32,
    }
    static HELD: crate::rt::sync::SyncCell<Held> = crate::rt::sync::SyncCell::new(Held {
        threads: [core::ptr::null_mut(); MAX_HELD],
        count: 0,
        last_rc: 0,
    });

    unsafe extern "C" fn hold(_: *mut c_void) -> *mut c_void {
        let mut g = M.lock();
        while !RELEASE.load(Ordering::Acquire) {
            CV.wait(&mut g);
        }
        core::ptr::null_mut()
    }

    /// Held count, and the result of the last creation that failed (0 none).
    pub(crate) fn status() -> (usize, i32) {
        let h = unsafe { &*HELD.get() };
        (h.count, h.last_rc)
    }

    /// Creates up to `n` more held threads; stops at the first failure.
    pub(crate) unsafe fn grow(n: usize) {
        type AttrFn = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
        type StackFn = unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int;
        let init = unsafe { sys::resolve_kernel::<AttrFn>(c"scePthreadAttrInit") };
        let stack = unsafe { sys::resolve_kernel::<StackFn>(c"scePthreadAttrSetstacksize") };
        let destroy = unsafe { sys::resolve_kernel::<AttrFn>(c"scePthreadAttrDestroy") };
        let mut attr: *mut c_void = core::ptr::null_mut();
        let have_attr = match (init, stack) {
            (Some(init), Some(stack)) => unsafe {
                init(&mut attr) == 0 && stack(&mut attr, STACK) == 0
            },
            _ => false,
        };
        let attr_ptr: *const c_void = if have_attr {
            (&attr as *const *mut c_void).cast()
        } else {
            core::ptr::null()
        };
        RELEASE.store(false, Ordering::Release);
        let h = unsafe { &mut *HELD.get() };
        h.last_rc = 0;
        for _ in 0..n {
            if h.count >= MAX_HELD {
                break;
            }
            let mut t: *mut c_void = core::ptr::null_mut();
            let rc = unsafe {
                create_internal(&mut t, attr_ptr, hold, core::ptr::null_mut(), c"ampr_hold".as_ptr())
            };
            if rc != 0 {
                h.last_rc = rc;
                stats::fs_event(b'P', b'h', rc.into(), c"thread-hold failed".as_ptr());
                break;
            }
            h.threads[h.count] = t;
            h.count += 1;
            if h.count % 8 == 0 {
                stats::fs_event(b'P', b'h', h.count as i64, c"thread-hold".as_ptr());
            }
        }
        // Also when init passed and the stack size was refused.
        if !attr.is_null() {
            if let Some(destroy) = destroy {
                let _ = unsafe { destroy(&mut attr) };
            }
        }
    }

    /// Wakes and joins every held thread.
    pub(crate) unsafe fn release() {
        {
            let _g = M.lock();
            RELEASE.store(true, Ordering::Release);
            CV.notify_all();
        }
        let h = unsafe { &mut *HELD.get() };
        for t in &mut h.threads[..h.count] {
            let _ = unsafe { crate::rt::reactor::scePthreadJoin(*t, core::ptr::null_mut()) };
            *t = core::ptr::null_mut();
        }
        h.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget: up to 16 reserved, a group's first thread past it; a
    /// failing game creation stops growth until it settles, the budget is
    /// what is left, one more per regrow_ns quiet but not up to the failure
    /// level, and the level is forgotten after 5 min. A lower knob refuses
    /// new slots until live threads drop below it; a raised one lets the
    /// budget grow back to it. Knobs are passed in, not read, since the tune
    /// tests change them. Pressure mode is on while the failure settles
    /// and r after it. The only test that touches these statics.
    #[test]
    fn thread_budget() {
        let t0 = 1_000_000_000_000u64;
        let (max, r) = (super::super::tune::THREAD_BUDGET, 10_000_000_000u64);
        let state = |max| (LIVE.load(core::sync::atomic::Ordering::Relaxed), budget_with(max));
        for _ in 0..8 {
            assert!(reserve_at(false, max, r, || t0));
        }
        assert!(!pressure_with(t0, r));
        cut_at(t0); // the game failed with 8 of ours live: level 8
        assert!(pressure_with(t0 + 2 * r, r)); // pressure while it fails
        assert!(!reserve_at(false, max, r, || t0)); // no growth while it fails
        assert!(reserve_at(true, max, r, || t0)); // a first thread is always allowed
        for _ in 0..4 {
            unreserve(); // gave 4 back: 5 live
        }
        settle_at(t0);
        assert_eq!(state(max), (5, 5));
        assert!(pressure_with(t0 + r - 1, r)); // ends r (10 s) after the failure
        assert!(!pressure_with(t0 + r, r));
        assert!(!reserve_at(false, max, r, || t0 + r - 1)); // regrowth waits r
        assert!(reserve_at(false, max, r, || t0 + r));
        assert!(!reserve_at(false, max, r, || t0 + r + 1)); // one per r
        assert!(reserve_at(false, max, r, || t0 + 2 * r));
        assert_eq!(state(max), (7, 7));
        assert!(!reserve_at(false, max, r, || t0 + 3 * r)); // level 8: stops at 7
        let t1 = t0 + FAIL_MEMORY_NS;
        assert!(reserve_at(false, max, r, || t1)); // level forgotten
        assert_eq!(state(max), (8, 8));
        // Knob lowered to 4 with 8 live: none stops, none starts.
        assert!(!reserve_at(false, 4, r, || t1 + r));
        assert!(reserve_at(true, 4, r, || t1 + r)); // first thread still allowed
        for _ in 0..6 {
            unreserve(); // 3 live
        }
        assert!(reserve_at(false, 4, r, || t1 + r));
        assert!(!reserve_at(false, 4, r, || t1 + r));
        assert_eq!(state(4), (4, 4));
        // Knob raised back: up to what failures left (8) at once, then
        // one per r quiet from the last regrow (t1).
        for _ in 0..4 {
            assert!(reserve_at(false, max, r, || t1 + 1));
        }
        assert!(!reserve_at(false, max, r, || t1 + r - 1));
        assert!(reserve_at(false, max, r, || t1 + r));
        assert_eq!(state(max), (9, 9));
        for _ in 0..9 {
            unreserve();
        }
    }

    /// A yield leaves `keep` and does not ask twice; the decode workers
    /// pass keep 1, so they never give their last.
    #[test]
    fn yield_exits() {
        assert_eq!(exits_to_ask(u32::MAX, 4, 1, 0), 3);
        assert_eq!(exits_to_ask(u32::MAX, 1, 1, 0), 0); // decode floor
        assert_eq!(exits_to_ask(u32::MAX, 3, 0, 0), 3); // read pool: to none
        assert_eq!(exits_to_ask(u32::MAX, 4, 1, 2), 1); // 2 already asked
        assert_eq!(exits_to_ask(u32::MAX, 2, 1, 3), 0);
        assert_eq!(exits_to_ask(1, 4, 0, 0), 1);
    }

    /// Normal mode never retires; pressure: one thread stays while there
    /// is work, none without, those retirements are counted, and the target
    /// never passes the cap.
    #[test]
    fn load_group_retires_under_pressure_only() {
        let g = LoadGroup::new(0);
        for live in 0..8 {
            assert!(!g.retire_due_with(live, 4, false, false));
            assert!(!g.retire_due_with(live, 4, true, false));
        }
        let hot = |live, work| g.retire_due_with(live, 4, work, true);
        assert!(hot(2, true));
        assert!(!hot(1, true));
        assert!(hot(1, false));
        assert!(!hot(0, false));
        assert_eq!(g.metrics()[2], 2);
        assert!(g.retire_due_with(1, 0, true, true)); // cap 0: target 0
        assert_eq!(g.metrics()[1], 0);
        g.started_with(3, false);
        g.started_with(2, false);
        assert_eq!(g.metrics()[0], 3);
    }

    /// Pressure mode keeps the thread a group restarted after a yield
    /// (target 1, not 0, so no create and retire per read) but never more
    /// than one; the next yield drops that, and so does normal mode. The
    /// decode floor keeps one in every mode.
    #[test]
    fn pressure_keeps_restarted_thread() {
        let g = LoadGroup::new(0);
        let hot = |live, work| g.retire_due_with(live, 4, work, true);
        assert!(hot(1, false)); // started before the pressure: leaves
        g.started_with(1, true); // restarted under pressure
        assert!(!hot(1, false)); // kept with no work
        assert_eq!(g.metrics()[1], 1);
        assert!(hot(2, false)); // never above 1
        g.asked(); // a later failed creation asks again
        assert!(hot(1, false));
        g.started_with(1, true);
        assert!(!g.retire_due_with(1, 4, false, false)); // normal mode: stays
        assert!(hot(1, false)); // normal mode dropped it
        let decode = LoadGroup::new(1);
        assert!(!decode.retire_due_with(1, 4, false, true)); // floor 1
        assert!(decode.retire_due_with(2, 4, false, true));
        assert!(!decode.retire_due_with(1, 4, false, false));
    }
}
