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
/// runtime creates itself.
pub(crate) unsafe fn create_internal(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    match unsafe { kernel_slot::<SceCreateFn>(sys::hook::scePthreadCreate) } {
        Some(f) => unsafe { f(thread, attr, entry, arg, name) },
        // Not detoured (before install): the import is the original.
        None => unsafe {
            super::reactor::scePthreadCreate(thread.cast(), attr.cast(), entry, arg, name)
        },
    }
}

/// `create_internal` with a `stack`-byte stack; with the default stack
/// when libkernel refuses the attribute.
pub(crate) unsafe fn create_internal_stack(
    thread: *mut *mut c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
    stack: usize,
) -> c_int {
    type AttrFn = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
    type StackFn = unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int;
    let init = unsafe { sys::resolve_kernel::<AttrFn>(c"scePthreadAttrInit") };
    let set = unsafe { sys::resolve_kernel::<StackFn>(c"scePthreadAttrSetstacksize") };
    let destroy = unsafe { sys::resolve_kernel::<AttrFn>(c"scePthreadAttrDestroy") };
    let mut attr: *mut c_void = core::ptr::null_mut();
    let have = match (init, set) {
        (Some(init), Some(set)) => unsafe { init(&mut attr) == 0 && set(&mut attr, stack) == 0 },
        _ => false,
    };
    let attr_ptr: *const c_void = if have {
        (&attr as *const *mut c_void).cast()
    } else {
        core::ptr::null()
    };
    let rc = unsafe { create_internal(thread, attr_ptr, entry, arg, name) };
    if !attr.is_null() {
        if let Some(destroy) = destroy {
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
/// threads: the read pool and fd read threads down to none (reads then go
/// to kernel AIO or run inline), the decode workers down to one. The budget
/// stops every group growing meanwhile.
fn make_room() -> bool {
    use super::{pack, reactor};
    let before = [
        reactor::pread_pool_live(),
        pack::read_threads_live(),
        pack::pack_workers_live(),
    ];
    // All three asked first, then one wait: each thread leaves after its
    // current call, so the groups drain in parallel within the 50 ms.
    unsafe {
        let _ = reactor::pread_pool_ask(u32::MAX);
        let _ = pack::read_threads_ask(u32::MAX);
        let _ = pack::pack_workers_ask(u32::MAX);
    }
    // Includes exits another failing creation asked for: wait for them too,
    // and retry while some leave, since a request no thread can meet must
    // not keep the game retrying.
    let pending = pending_exits();
    if pending == 0 {
        return false;
    }
    for _ in 0..50 {
        unsafe { sys::sceKernelUsleep(1000) };
        if pending_exits() == 0 {
            break;
        }
    }
    let left = unsafe {
        reactor::pread_pool_reap(before[0])
            + pack::read_threads_reap(before[1])
            + pack::pack_workers_reap(before[2])
    };
    left != 0 || pending_exits() < pending
}

/// Thread exits asked of the groups that have not happened yet.
fn pending_exits() -> u32 {
    super::reactor::pread_pool_pending_exits()
        + super::pack::read_threads_pending_exits()
        + super::pack::pack_workers_pending_exits()
}

#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn scePthreadCreate_emul(
    thread: *mut *mut c_void,
    attr: *const c_void,
    entry: ThreadEntry,
    arg: *mut c_void,
    name: *const c_char,
) -> c_int {
    let Some(f) = (unsafe { kernel_slot::<SceCreateFn>(sys::hook::scePthreadCreate) }) else {
        return SCE_KERNEL_ERROR_EAGAIN;
    };
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
// One budget for every worker thread the runtime grows (read pool, fd read
// threads, pack workers): the lower of what failures left (BUDGET) and the
// `thread_budget` knob (16, read at each reservation). A group's first
// thread is always allowed, even past the knob, so no group is starved.
// Lowering the knob stops no thread: new reservations wait until the live
// count drops below it; raising it lets regrowth reach the new value. When a
// game creation fails with EAGAIN no group grows (`cut_at`), the groups give
// threads back, and the budget becomes what is left (`settle_at`). After
// tune::regrow_ns (10 s) with no failure it grows by one (`reserve`), up to
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
    while rc == failed && make_room() {
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

/// `create_internal_stack` (stack 0: libkernel's default) for a worker
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
    let rc = unsafe {
        if stack == 0 {
            create_internal(thread, core::ptr::null(), counted_entry, i as *mut c_void, name)
        } else {
            create_internal_stack(thread, counted_entry, i as *mut c_void, name, stack)
        }
    };
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

// ---- load-based retirement ----
//
// Each group (pack workers, read pool, fd read threads) keeps its last
// LOAD_SAMPLES busy-thread counts, taken at every job start and finish under
// the group's lock. A thread that finishes its work leaves while the group
// has more live threads than `load_target` + 1 (`load_target`: ceil(median x
// 1.5) + 1, at least 1) for RETIRE_STREAK finishes in a row. No idle timer:
// peak busy was 4 decode workers (~0.2 cores of work) and 4-5 disk threads
// with 9-11 runtime threads live on two titles (debug /metrics), and a game
// creation failed with 6 decoders alive. In pressure
// mode (a game creation failed with EAGAIN in the last tune::regrow_ns, 10 s)
// idle threads leave at once and each group keeps at most one: while it has
// work, or the one it started after the yield (`LoadGroup::held`), so a
// read stream does not create and retire a thread per read. The decode
// workers never go below one (`LoadGroup::floor`).

/// Busy-count samples kept per group: 8192, about 2.7 s at the ~1500 pack
/// jobs/s (two samples each) one title ran; 64 covered ~20 ms, so the median
/// flipped between 0 and 1 and decode workers retired and restarted 1.4 times
/// a second (164 in 120 s, debug /metrics). A running histogram keeps the
/// median O(LOAD_BUCKETS) at any window.
const LOAD_SAMPLES: usize = 8192;
/// Finishes in a row above the target before a thread retires (normal mode).
const RETIRE_STREAK: u32 = 8;
/// Samples are clamped below this (every group cap is lower).
const LOAD_BUCKETS: usize = 16;
/// Last game creation failure (settled), ns; 0: none, normal mode.
static PRESSURE_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Twice the median of `samples` (the two middle values summed when the
/// count is even); 0 when empty. Counting sort over LOAD_BUCKETS values;
/// the runtime keeps a running histogram instead (LoadGroup), tests use this.
#[cfg(test)]
pub(crate) fn load_median2(samples: &[u8]) -> u32 {
    let mut count = [0u32; LOAD_BUCKETS];
    for &s in samples {
        count[(s as usize).min(LOAD_BUCKETS - 1)] += 1;
    }
    median2_of(&count, samples.len() as u32)
}

/// Twice the median of `n` samples given as a histogram over LOAD_BUCKETS.
fn median2_of(count: &[u32; LOAD_BUCKETS], n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    // Values at sorted positions lo and hi (equal when n is odd).
    let (lo, hi) = ((n - 1) / 2, n / 2);
    let at = |k: u32| {
        let mut seen = 0;
        for (v, &c) in count.iter().enumerate() {
            seen += c;
            if seen > k {
                return v as u32;
            }
        }
        (LOAD_BUCKETS - 1) as u32
    };
    at(lo) + at(hi)
}

/// Threads a group may keep: normal, ceil(median x 1.5) + 1 in [1, cap]
/// (`median2` is twice the median); pressure, 1 while `hold` (work, or a
/// thread restarted under pressure, `LoadGroup::started`), else 0.
pub(crate) fn load_target(median2: u32, cap: u32, pressure: bool, hold: bool) -> u32 {
    if pressure {
        return (hold as u32).min(cap);
    }
    ((median2 * 3).div_ceil(4) + 1).clamp(1, cap.max(1))
}

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

/// Load samples and debug counters of one thread group; every method runs
/// under the group's lock, so Relaxed atomics are enough.
pub(crate) struct LoadGroup {
    ring: [core::sync::atomic::AtomicU8; LOAD_SAMPLES],
    /// Samples per busy count over the ring's current contents.
    hist: [core::sync::atomic::AtomicU32; LOAD_BUCKETS],
    taken: core::sync::atomic::AtomicU32,
    busy: core::sync::atomic::AtomicU32,
    peak: core::sync::atomic::AtomicU32,
    target: core::sync::atomic::AtomicU32,
    median2: core::sync::atomic::AtomicU32,
    retired_load: core::sync::atomic::AtomicU32,
    retired_pressure: core::sync::atomic::AtomicU32,
    /// Finishes in a row with the group above its target (normal mode).
    over: core::sync::atomic::AtomicU32,
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
    /// A group that keeps at least `floor` threads.
    pub(crate) const fn new(floor: u32) -> Self {
        use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8};
        Self {
            ring: [const { AtomicU8::new(0) }; LOAD_SAMPLES],
            hist: [const { AtomicU32::new(0) }; LOAD_BUCKETS],
            taken: AtomicU32::new(0),
            busy: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            target: AtomicU32::new(1),
            median2: AtomicU32::new(0),
            retired_load: AtomicU32::new(0),
            retired_pressure: AtomicU32::new(0),
            over: AtomicU32::new(0),
            floor,
            held: AtomicBool::new(false),
        }
    }
    fn sample(&self, busy: u32) {
        use core::sync::atomic::Ordering::Relaxed;
        let taken = self.taken.load(Relaxed);
        // Wraps after 2^32 samples; keep it at or above LOAD_SAMPLES so a full
        // ring stays full.
        let next = taken.checked_add(1).unwrap_or(LOAD_SAMPLES as u32);
        self.taken.store(next, Relaxed);
        let i = taken as usize % LOAD_SAMPLES;
        if taken as usize >= LOAD_SAMPLES {
            let old = self.ring[i].load(Relaxed) as usize;
            self.hist[old].fetch_sub(1, Relaxed);
        }
        let v = busy.min(LOAD_BUCKETS as u32 - 1) as u8;
        self.ring[i].store(v, Relaxed);
        self.hist[v as usize].fetch_add(1, Relaxed);
    }
    /// A thread took work.
    pub(crate) fn begin(&self) {
        let busy = self.busy.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        self.sample(busy);
    }
    /// A thread finished its work.
    pub(crate) fn end(&self) {
        use core::sync::atomic::Ordering::Relaxed;
        let busy = self.busy.load(Relaxed).saturating_sub(1);
        self.busy.store(busy, Relaxed);
        self.sample(busy);
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
    /// A thread that finished its work leaves now: `live` (it included) is
    /// above the target. `has_work`: work it could take next. Counts it.
    pub(crate) fn retire_due(&self, live: u32, cap: u32, has_work: bool) -> bool {
        self.retire_due_with(live, cap, has_work, pressure())
    }
    /// `retire_due` with the mode passed in.
    fn retire_due_with(&self, live: u32, cap: u32, has_work: bool, pressure: bool) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        let mut count = [0u32; LOAD_BUCKETS];
        for (c, h) in count.iter_mut().zip(&self.hist) {
            *c = h.load(Relaxed);
        }
        let n = (self.taken.load(Relaxed) as usize).min(LOAD_SAMPLES) as u32;
        let median2 = median2_of(&count, n);
        if !pressure {
            self.held.store(false, Relaxed);
        }
        let hold = has_work || self.held.load(Relaxed);
        let target = load_target(median2, cap, pressure, hold);
        self.median2.store(median2, Relaxed);
        self.target.store(target, Relaxed);
        // Normal mode keeps one thread above the target: retiring at the
        // target made a burst start a thread and retire it right after,
        // 509 decode worker retirements in 159 s on a console (debug
        // /metrics, decode_retired_load). Pressure mode retires to the target.
        let keep = (if pressure { target } else { target + 1 }).max(self.floor);
        if live <= keep {
            self.over.store(0, Relaxed);
            return false;
        }
        // Normal mode also waits for RETIRE_STREAK finishes in a row above
        // it: a title whose busy median flips between 0 and 1 still retired
        // and restarted 1.5 decode workers per second with the margin alone
        // (217 in 147 s, debug /metrics).
        if !pressure {
            let over = self.over.load(Relaxed) + 1;
            if over < RETIRE_STREAK {
                self.over.store(over, Relaxed);
                return false;
            }
            self.over.store(0, Relaxed);
        }
        let counter = if pressure { &self.retired_pressure } else { &self.retired_load };
        counter.fetch_add(1, Relaxed);
        true
    }
    /// `n` threads left on a failed game creation's request.
    pub(crate) fn yielded(&self, n: u32) {
        self.retired_pressure.fetch_add(n, core::sync::atomic::Ordering::Relaxed);
    }
    /// Debug /metrics: (peak, target, busy median rounded up, retired by
    /// load, retired under pressure).
    #[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
    pub(crate) fn metrics(&self) -> [u64; 5] {
        use core::sync::atomic::Ordering::Relaxed;
        [
            self.peak.load(Relaxed).into(),
            self.target.load(Relaxed).into(),
            self.median2.load(Relaxed).div_ceil(2).into(),
            self.retired_load.load(Relaxed).into(),
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

    /// Twice the median: odd and even counts, unsorted input, clamping.
    #[test]
    fn load_median() {
        assert_eq!(load_median2(&[]), 0);
        assert_eq!(load_median2(&[3]), 6);
        assert_eq!(load_median2(&[4, 1, 3]), 6);
        assert_eq!(load_median2(&[1, 0, 1, 0]), 1); // median 0.5
        assert_eq!(load_median2(&[4, 3, 4, 3, 4, 3]), 7); // median 3.5
        assert_eq!(load_median2(&[200, 200]), 30); // clamped to 15
    }

    /// Normal mode: ceil(median x 1.5) + 1, clamped to [1, cap], so never
    /// 0. Pressure: 1 with work, 0 without.
    #[test]
    fn load_target_math() {
        assert_eq!(load_target(0, 4, false, false), 1); // floor 1
        assert_eq!(load_target(0, 0, false, true), 1); // cap 0 still keeps 1
        assert_eq!(load_target(1, 4, false, false), 2); // 0.5 -> ceil(0.75) + 1
        assert_eq!(load_target(2, 4, false, false), 3); // 1 -> ceil(1.5) + 1
        assert_eq!(load_target(4, 6, false, true), 4); // 2 -> 3 + 1
        assert_eq!(load_target(7, 4, false, true), 4); // 3.5 -> 7, clamped
        assert_eq!(load_target(8, 6, false, false), 6); // 4 -> 7, clamped
        assert_eq!(load_target(8, 6, true, true), 1); // pressure: one
        assert_eq!(load_target(8, 6, true, false), 0); // pressure: none
        assert_eq!(load_target(0, 0, true, true), 0);
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

    /// The histogram follows the ring: a full window of 4s replaced by a
    /// full window of 1s gives median 1, and halfway the two meet.
    #[test]
    fn load_window_evicts_old_samples() {
        use core::sync::atomic::Ordering::Relaxed;
        let g = LoadGroup::new(0);
        let median2 = |g: &LoadGroup| {
            let mut count = [0u32; LOAD_BUCKETS];
            for (c, h) in count.iter_mut().zip(&g.hist) {
                *c = h.load(Relaxed);
            }
            median2_of(&count, (g.taken.load(Relaxed) as usize).min(LOAD_SAMPLES) as u32)
        };
        for _ in 0..LOAD_SAMPLES {
            g.sample(4);
        }
        assert_eq!(median2(&g), 8);
        for _ in 0..LOAD_SAMPLES / 2 {
            g.sample(1);
        }
        assert_eq!(median2(&g), 5); // 4096 of each: (1 + 4)
        for _ in 0..LOAD_SAMPLES / 2 {
            g.sample(1);
        }
        assert_eq!(median2(&g), 2);
        assert_eq!(g.hist.iter().map(|h| h.load(Relaxed)).sum::<u32>(), LOAD_SAMPLES as u32);
    }

    /// Retirement: normal mode keeps one thread above the target (target 4:
    /// 5 stay, a 6th leaves after RETIRE_STREAK finishes in a row), never
    /// drops below 1, and counts by load.
    #[test]
    fn load_group_retires_above_target() {
        let g = LoadGroup::new(0);
        let due = |live, cap, work| g.retire_due_with(live, cap, work, false);
        assert!(!due(1, 4, false)); // no samples: target 1, floor
        assert!(!due(2, 4, false)); // target + 1 stays
        // Above target + 1: leaves on the RETIRE_STREAK-th finish in a row.
        for _ in 1..RETIRE_STREAK {
            assert!(!due(3, 4, false));
        }
        assert!(due(3, 4, false));
        // A finish at or below target + 1 restarts the streak.
        for _ in 1..RETIRE_STREAK {
            assert!(!due(3, 4, false));
        }
        assert!(!due(2, 4, false));
        assert!(!due(3, 4, false));
        for _ in 0..2 {
            g.begin();
        }
        for _ in 0..40 {
            g.end();
            g.begin();
        }
        // Samples alternate 2 and 1 busy: median 1.5, target 4.
        assert!(!due(4, 4, true));
        assert!(!due(3, 4, false)); // no retirement below target
        assert!(!due(5, 6, true)); // target + 1 stays
        for _ in 1..RETIRE_STREAK {
            assert!(!due(6, 6, true));
        }
        assert!(due(6, 6, true));
        assert_eq!(g.metrics()[1..4], [4, 2, 2]); // target, median, by load
        // Pressure: one thread stays while there is work, none without,
        // and those retirements count apart.
        let hot = |live, work| g.retire_due_with(live, 4, work, true);
        assert!(hot(2, true));
        assert!(!hot(1, true));
        assert!(hot(1, false));
        assert!(!hot(0, false));
        assert_eq!(g.metrics()[4], 2);
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
        assert!(!g.retire_due_with(1, 4, false, false)); // normal: floor 1
        assert!(hot(1, false)); // normal mode dropped it
        let decode = LoadGroup::new(1);
        assert!(!decode.retire_due_with(1, 4, false, true)); // floor 1
        assert!(decode.retire_due_with(2, 4, false, true));
        assert!(!decode.retire_due_with(1, 4, false, false));
    }
}
