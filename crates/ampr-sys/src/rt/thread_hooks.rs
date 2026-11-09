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

/// Pool threads one failed game creation asks back. More than one, so the
/// game's next few creations find room too.
const YIELD_THREADS: u32 = 4;

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

/// After a failed game creation: true when the runtime gave threads back,
/// so a retry may succeed. The read pool first (down to none: kernel AIO
/// then), then the fd read threads (down to 1), then one pack worker
/// (down to 1). The budget stops every group growing meanwhile.
fn make_room() -> bool {
    if (unsafe { super::reactor::pread_pool_yield(YIELD_THREADS) }) != 0
        || (unsafe { super::pack::read_threads_yield(YIELD_THREADS) }) != 0
        || (unsafe { super::pack::pack_workers_yield(1) }) != 0
    {
        return true;
    }
    // Nothing more to ask, but exits another failing creation asked for are
    // on their way: wait up to 50 ms and retry while some do leave, since a
    // request no thread can meet must not keep the game retrying.
    let before = pending_exits();
    if before == 0 {
        return false;
    }
    for _ in 0..50 {
        unsafe { sys::sceKernelUsleep(1000) };
        if pending_exits() == 0 {
            break;
        }
    }
    pending_exits() < before
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
// threads, pack workers), 16 at most (debug `thread_budget` lowers it). A
// group's first thread is always allowed, so no group is starved. When a
// game creation fails with EAGAIN no group grows (`cut_at`), the groups give
// threads back, and the budget becomes what is left (`settle_at`). After
// BUDGET_REGROW_NS with no failure it grows by one (`reserve`), up to one
// below the failure level, which is forgotten after FAIL_MEMORY_NS. So the
// runtime finds the game's room over a run instead of staying cut or failing
// the game again at every regrowth.

/// The budget grows back by one per this long without a game failure.
const BUDGET_REGROW_NS: u64 = 30_000_000_000;
/// How long a failure level is remembered: a game's own thread count moves
/// between loading and play, so an old level stops being the limit.
const FAIL_MEMORY_NS: u64 = 300_000_000_000;
/// Worker threads now: reserved at creation, released when the thread
/// function returns (`counted_entry`) or the creation failed.
static LIVE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The budget now; 0 until first read (then `tune::thread_budget`).
static BUDGET: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Last cut or regrow; growth waits BUDGET_REGROW_NS after it.
static BUDGET_CHANGED_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Game creations between their failure and its settle: no group grows.
static CUTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Failure level: fewest worker threads the runtime held when a game
/// creation failed, and when. Regrowth stops one below it until
/// FAIL_MEMORY_NS passes without a failure. u32::MAX: none.
static FAIL_LEVEL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static FAIL_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn budget_now() -> u32 {
    use core::sync::atomic::Ordering::Relaxed;
    let b = BUDGET.load(Relaxed);
    if b != 0 {
        return b;
    }
    let max = super::tune::thread_budget();
    let _ = BUDGET.compare_exchange(0, max, Relaxed, Relaxed);
    BUDGET.load(Relaxed)
}

/// A slot for one new worker thread; `first`: the group has none (always
/// allowed). False at the budget or while a game creation fails. The slot
/// is released by `create_counted`: when the thread returns, or at once
/// when its creation fails.
pub(crate) fn reserve(first: bool) -> bool {
    reserve_at(first, super::services::time_counter_now)
}

/// `reserve` with the clock passed in (read only at the budget).
fn reserve_at(first: bool, clock: impl Fn() -> u64) -> bool {
    use core::sync::atomic::Ordering::{AcqRel, Relaxed};
    if !first && CUTS.load(Relaxed) != 0 {
        return false;
    }
    let mut budget = budget_now();
    let live = LIVE.load(Relaxed);
    if !first && live >= budget {
        let now = clock();
        let level = FAIL_LEVEL.load(Relaxed);
        let limit = if level != u32::MAX && now.saturating_sub(FAIL_NS.load(Relaxed)) < FAIL_MEMORY_NS {
            level.saturating_sub(1).max(1)
        } else {
            super::tune::thread_budget()
        };
        if budget >= limit
            || now.saturating_sub(BUDGET_CHANGED_NS.load(Relaxed)) < BUDGET_REGROW_NS
            || BUDGET.compare_exchange(budget, budget + 1, AcqRel, Relaxed).is_err()
        {
            return false;
        }
        BUDGET_CHANGED_NS.store(now, Relaxed);
        stats::add(Stat::ThreadBudgetRegrows, 1);
        budget += 1;
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
fn unreserve() {
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
    stats::add(Stat::ThreadBudgetCuts, 1);
}

/// The failing call is through (whatever its result): the budget is at most
/// what the runtime holds now (at least 1); regrowth waits BUDGET_REGROW_NS.
fn settle_at(now: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let left = LIVE.load(Relaxed).max(1);
    let _ = BUDGET.fetch_min(left, Relaxed);
    BUDGET_CHANGED_NS.store(now, Relaxed);
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

// ---- spare threads ----------------------------------------------------------

/// Decides when a thread group (pack workers, fd read threads) has one
/// thread too many: fewer than are live were busy at once for a whole
/// window. Per-thread idle timers fail for groups woken all at once, since
/// jobs rotate over every thread (4 pack workers stayed live through 67 s
/// of ~260 reads a second). Methods are called under the group's lock.
pub(crate) struct SpareWindow {
    start_ns: core::sync::atomic::AtomicU64,
    busy: core::sync::atomic::AtomicU32,
    busy_max: core::sync::atomic::AtomicU32,
}

/// Window length, and the wait an idle thread uses so a window is checked
/// even when no work comes.
pub(crate) const SPARE_WINDOW_US: u64 = 2_000_000;

impl SpareWindow {
    pub(crate) const fn new() -> Self {
        Self {
            start_ns: core::sync::atomic::AtomicU64::new(0),
            busy: core::sync::atomic::AtomicU32::new(0),
            busy_max: core::sync::atomic::AtomicU32::new(0),
        }
    }
    /// A thread took work.
    pub(crate) fn begin(&self) {
        use core::sync::atomic::Ordering::Relaxed;
        let busy = self.busy.fetch_add(1, Relaxed) + 1;
        self.busy_max.fetch_max(busy, Relaxed);
    }
    /// A thread finished its work.
    pub(crate) fn end(&self) {
        self.busy.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
    /// At the end of a window: true when one of `live` threads (more than
    /// one) was spare the whole window; starts the next window either way.
    pub(crate) fn spare_due(&self, live: u32) -> bool {
        self.spare_due_at(super::services::time_counter_now(), live)
    }
    fn spare_due_at(&self, now: u64, live: u32) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        let start = self.start_ns.load(Relaxed);
        if start == 0 {
            self.start_ns.store(now, Relaxed);
            return false;
        }
        if now.saturating_sub(start) < SPARE_WINDOW_US * 1000 {
            return false;
        }
        let spare = live > 1 && self.busy_max.load(Relaxed) < live;
        self.start_ns.store(now, Relaxed);
        self.busy_max.store(self.busy.load(Relaxed), Relaxed);
        spare
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
        if have_attr {
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
    /// what is left, one more per 30 s quiet but not up to the failure
    /// level, and the level is forgotten after 5 min. The only test that
    /// touches these statics.
    #[test]
    fn thread_budget() {
        let t0 = 1_000_000_000_000u64;
        for _ in 0..8 {
            assert!(reserve_at(false, || t0));
        }
        cut_at(t0); // the game failed with 8 of ours live: level 8
        assert!(!reserve_at(false, || t0)); // no growth while it fails
        assert!(reserve_at(true, || t0)); // a first thread is always allowed
        for _ in 0..4 {
            unreserve(); // gave 4 back: 5 live
        }
        settle_at(t0);
        assert_eq!(budget_state(), (5, 5));
        let r = BUDGET_REGROW_NS;
        assert!(!reserve_at(false, || t0 + r - 1)); // regrowth waits 30 s
        assert!(reserve_at(false, || t0 + r));
        assert!(!reserve_at(false, || t0 + r + 1)); // one per 30 s
        assert!(reserve_at(false, || t0 + 2 * r));
        assert_eq!(budget_state(), (7, 7));
        assert!(!reserve_at(false, || t0 + 3 * r)); // level 8: stops at 7
        assert!(reserve_at(false, || t0 + FAIL_MEMORY_NS)); // level forgotten
        assert_eq!(budget_state(), (8, 8));
    }

    /// One spare thread for a whole window is due; a window where every
    /// live thread was busy at once is not; each check starts a new window.
    #[test]
    fn spare_window() {
        let w = SpareWindow::new();
        let win = SPARE_WINDOW_US * 1000;
        assert!(!w.spare_due_at(1, 4)); // first call starts the window
        w.begin();
        w.begin();
        w.end();
        w.end();
        assert!(!w.spare_due_at(win / 2, 4)); // window not over
        assert!(w.spare_due_at(win + 1, 4)); // at most 2 of 4 busy
        for _ in 0..3 {
            w.begin();
        }
        for _ in 0..3 {
            w.end();
        }
        assert!(!w.spare_due_at(2 * win + 2, 3)); // all 3 busy at once
        assert!(!w.spare_due_at(4 * win, 1)); // never below one thread
    }
}
