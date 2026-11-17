//! Stacks of the runtime's own threads, from one 2 MiB pool block
//! (rt/index_memory.rs `STACK_MEMORY_MAX`) instead of the game's flexible
//! memory, where libkernel puts a default stack (about 1 MiB of stacks at
//! full load; 32 threads with 64 KiB stacks took 3 MiB,
//! reactor/pread_pool.rs).
//!
//! The block is carved at the first thread start and cut in 16 KiB pages,
//! first fit. Each stack takes its pages plus one page below it, set to no
//! access with the real mprotect the pool uses (rt/runtime_memory.rs):
//! libkernel adds no guard to a supplied stack, so an overflow would
//! otherwise run silently into the stack or pool block below. A stack is
//! free again only after scePthreadJoin returned for its thread
//! (reactor/mod.rs `scePthreadJoin`); every runtime group joins its
//! threads. A thread that gets no stack here (block full or refused, a
//! stack over `MAX_STACK`, the guard or the attribute refused) gets
//! libkernel's own, as before (rt/thread_hooks.rs `create_internal_stack`).

use super::index_memory::STACK_MEMORY_MAX;
use super::runtime_memory::ampr_internal_amm_pool_alloc;
use super::stats::{self, Stat};
use super::sync::{SpinLock, SyncCell};
use super::sys::{SCE_KERNEL_PAGE_SIZE, SCE_KERNEL_PROT_AMPR_ALL, SCE_KERNEL_PROT_CPU_RW};
use core::ffi::c_void;

/// Page of the block: a stack and its guard are whole pages.
const UNIT: usize = SCE_KERNEL_PAGE_SIZE;
const UNITS: usize = STACK_MEMORY_MAX / UNIT;
const WORDS: usize = UNITS.div_ceil(64);
/// Largest stack taken from the block, 128 KiB: the decode workers take
/// 64 KiB (pack/worker.rs `WORKER_STACK_MIN`) and the pread threads 64 KiB
/// (reactor/pread_pool.rs `PREAD_STACK_BYTES`); a larger one (a worker stack knob) is
/// libkernel's.
pub(crate) const MAX_STACK: usize = 128 << 10;
/// Stacks live at once: the 16-thread budget plus the reactor and the
/// metrics thread, with room for debug /bench threads.
const RECORDS: usize = 24;
const _: () = assert!(STACK_MEMORY_MAX % UNIT == 0);

// ---- page map (pure, host-tested) ------------------------------------------

/// One bit per page, set while taken.
struct Pages([u64; WORDS]);

impl Pages {
    const fn new() -> Self {
        Self([0; WORDS])
    }

    fn busy(&self, i: usize) -> bool {
        self.0[i / 64] & (1 << (i % 64)) != 0
    }

    fn mark(&mut self, at: usize, n: usize, on: bool) {
        for i in at..at + n {
            if on {
                self.0[i / 64] |= 1 << (i % 64);
            } else {
                self.0[i / 64] &= !(1 << (i % 64));
            }
        }
    }

    /// First run of `n` free pages, taken; None when none is long enough.
    fn take(&mut self, n: usize) -> Option<usize> {
        if n == 0 || n > UNITS {
            return None;
        }
        let mut run = 0;
        for i in 0..UNITS {
            run = if self.busy(i) { 0 } else { run + 1 };
            if run == n {
                let at = i + 1 - n;
                self.mark(at, n, true);
                return Some(at);
            }
        }
        None
    }

    fn give(&mut self, at: usize, n: usize) {
        self.mark(at, n, false);
    }
}

// ---- records -----------------------------------------------------------------

#[derive(Clone, Copy)]
struct Rec {
    used: bool,
    /// Thread handle once created; 0 while the creation runs.
    thread: usize,
    /// While the creation runs: where libkernel writes the handle (the
    /// creator's `thread` argument), so a join before `bind` finds the
    /// record; 0 once bound, cancelled or matched by such a join.
    out: usize,
    /// The thread was joined before `bind`: `bind` frees the stack.
    gone: bool,
    /// A join of the unbound thread is running (`detach` to `release`).
    joining: bool,
    /// First page (the guard) and page count, guard included.
    at: u16,
    n: u16,
}

const REC0: Rec = Rec {
    used: false,
    thread: 0,
    out: 0,
    gone: false,
    joining: false,
    at: 0,
    n: 0,
};

struct Stacks {
    /// The pool block, 0 until carved.
    base: usize,
    /// The pool refused the block: libkernel stacks from then on.
    refused: bool,
    pages: Pages,
    recs: [Rec; RECORDS],
    /// Pages taken, guards included (debug /metrics `thread_stack_bytes`).
    taken: usize,
}

static LOCK: SpinLock = SpinLock::new();
static STACKS: SyncCell<Stacks> = SyncCell::new(Stacks {
    base: 0,
    refused: false,
    pages: Pages::new(),
    recs: [REC0; RECORDS],
    taken: 0,
});

impl Stacks {
    /// A record and `n` pages for a new stack.
    fn reserve(&mut self, n: usize) -> Option<usize> {
        let r = self.recs.iter().position(|r| !r.used)?;
        let at = self.pages.take(n)?;
        self.recs[r] = Rec {
            used: true,
            thread: 0,
            out: 0,
            gone: false,
            joining: false,
            at: at as u16,
            n: n as u16,
        };
        self.taken += n;
        Some(r)
    }

    /// The record of a joined `thread`, if its stack is from the block.
    fn find(&self, thread: usize) -> Option<usize> {
        if thread == 0 {
            return None;
        }
        self.recs.iter().position(|r| r.used && r.thread == thread)
    }

    /// The record of a creation still running whose handle, written to its
    /// `out`, is `thread`: a thread joined before its creator bound it.
    fn find_unbound(&self, thread: usize) -> Option<usize> {
        if thread == 0 {
            return None;
        }
        self.recs.iter().position(|r| {
            // Read under LOCK: `out` is the creator's and stays valid until
            // its bind or cancel clears it, also under LOCK.
            r.used
                && r.thread == 0
                && r.out != 0
                && unsafe { (r.out as *const usize).read_volatile() } == thread
        })
    }

    /// Frees record `r` and its pages.
    fn free(&mut self, r: usize) {
        let rec = self.recs[r];
        self.pages.give(rec.at as usize, rec.n as usize);
        self.taken -= rec.n as usize;
        self.recs[r] = REC0;
    }
}

/// A stack from the block for one thread creation.
pub(crate) struct Slot {
    rec: usize,
    /// Lowest address of the stack (above its guard) and its size.
    pub(crate) addr: *mut c_void,
    pub(crate) size: usize,
}

/// Sets the guard page of `rec` to no access (`on`) or back to the pool's
/// protection. Host tests have no kernel.
unsafe fn guard(base: usize, rec: Rec, on: bool) -> bool {
    let prot = if on {
        0
    } else {
        SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL
    };
    let page = (base + rec.at as usize * UNIT) as *const c_void;
    cfg!(test) || unsafe { super::sys::real_mprotect(page, UNIT, prot) } == 0
}

/// A `size`-byte stack (rounded up to whole pages) with its guard page;
/// None when it is not to come from the block. `out`: where the creation
/// writes the thread handle, valid until `bind` or `cancel`.
pub(crate) unsafe fn take(size: usize, out: *mut *mut c_void) -> Option<Slot> {
    if size == 0 || size > MAX_STACK {
        return None;
    }
    let n = size.div_ceil(UNIT);
    let (base, r, rec) = {
        let _g = LOCK.lock();
        let s = unsafe { &mut *STACKS.get() };
        if s.base == 0 && !s.refused {
            let mut got = 0usize;
            let tag = c"thread stacks".as_ptr();
            let b = unsafe {
                ampr_internal_amm_pool_alloc(STACK_MEMORY_MAX, &mut got, tag, false, UNIT)
            };
            s.base = b as usize;
            s.refused = b.is_null();
        }
        if s.base == 0 {
            return None;
        }
        let r = s.reserve(n + 1)?;
        s.recs[r].out = out as usize;
        (s.base, r, s.recs[r])
    };
    if !unsafe { guard(base, rec, true) } {
        let _g = LOCK.lock();
        unsafe { (*STACKS.get()).free(r) };
        return None;
    }
    count();
    Some(Slot {
        rec: r,
        addr: (base + (rec.at as usize + 1) * UNIT) as *mut c_void,
        size: n * UNIT,
    })
}

/// Records the thread that runs on `slot`, so its join frees it. A thread
/// already joined (`detach` found it by its handle before this) is gone:
/// its stack is freed now. Another record bound to the same handle belongs
/// to a thread that was joined before its creator got here, by a handle
/// read from elsewhere (libkernel reuses the handle of a joined thread):
/// that thread is gone too, so its stack is freed now.
pub(crate) fn bind(slot: Slot, thread: *mut c_void) {
    let stale = {
        let _g = LOCK.lock();
        let s = unsafe { &mut *STACKS.get() };
        let r = slot.rec;
        s.recs[r].out = 0;
        if s.recs[r].gone {
            Some(r)
        } else {
            let stale = s.find(thread as usize);
            if let Some(o) = stale {
                s.recs[o].thread = 0;
            }
            s.recs[r].thread = thread as usize;
            stale
        }
    };
    if let Some(r) = stale {
        unsafe { give_back(r) };
    }
}

/// The creation on `slot` failed: the stack is free at once.
pub(crate) unsafe fn cancel(slot: Slot) {
    unsafe { give_back(slot.rec) };
}

/// A record detached for a join: (record, handle, the creator's `out` when
/// the thread was not bound yet, else 0).
pub(crate) type Detached = (usize, usize, usize);

/// Before scePthreadJoin for `thread`: detaches its record while the
/// handle still names it. Once the join returns, libkernel may give the
/// handle to a new thread, and a lookup by handle then would find the new
/// thread's record and free a live stack. A thread whose creator has not
/// bound it yet is found by its `out` and marked `joining`.
pub(crate) fn detach(thread: *mut c_void) -> Option<Detached> {
    let _g = LOCK.lock();
    let s = unsafe { &mut *STACKS.get() };
    if let Some(r) = s.find(thread as usize) {
        s.recs[r].thread = 0;
        return Some((r, thread as usize, 0));
    }
    let r = s.find_unbound(thread as usize)?;
    let out = s.recs[r].out;
    s.recs[r].out = 0;
    s.recs[r].joining = true;
    Some((r, thread as usize, out))
}

/// After the join: frees the detached stack when the join returned 0,
/// else binds it back to its still-running thread. A thread joined before
/// its creator bound it is freed by that bind (`gone`), or here when the
/// bind ran during the join.
pub(crate) unsafe fn release(rec: Option<Detached>, joined: bool) {
    let Some((r, thread, out)) = rec else { return };
    if out == 0 {
        if joined {
            unsafe { give_back(r) };
        } else {
            let _g = LOCK.lock();
            unsafe { (*STACKS.get()).recs[r].thread = thread };
        }
        return;
    }
    let free = {
        let _g = LOCK.lock();
        let s = unsafe { &mut *STACKS.get() };
        let rec = &mut s.recs[r];
        // Not `joining` any more: a later bind of the reused handle freed
        // it as stale, and the record may be another stack's now.
        if !rec.joining {
            return;
        }
        rec.joining = false;
        match (joined, rec.thread != 0) {
            // Bound during the join: the thread is gone, free it now.
            (true, true) => {
                rec.thread = 0;
                true
            }
            (true, false) => {
                rec.gone = true;
                false
            }
            // Still running; a later join may find it again while unbound.
            (false, bound) => {
                if !bound {
                    rec.out = out;
                }
                false
            }
        }
    };
    if free {
        unsafe { give_back(r) };
    }
}

/// Restores the guard page of record `r`, then frees its pages, so no page
/// is handed out while it is still no access. A guard that cannot be
/// restored keeps its pages: a stack on it would fault at once.
unsafe fn give_back(r: usize) {
    let (base, rec) = {
        let _g = LOCK.lock();
        let s = unsafe { &*STACKS.get() };
        (s.base, s.recs[r])
    };
    if !unsafe { guard(base, rec, false) } {
        // Unbound, so a later thread with the same handle does not free it.
        let _g = LOCK.lock();
        unsafe { (*STACKS.get()).recs[r].thread = 0 };
        return;
    }
    {
        let _g = LOCK.lock();
        unsafe { (*STACKS.get()).free(r) };
    }
    count();
}

/// Debug /metrics: pool stack bytes in use, guards included.
fn count() {
    let taken = {
        let _g = LOCK.lock();
        unsafe { (*STACKS.get()).taken }
    };
    stats::set(Stat::ThreadStackBytes, (taken * UNIT) as u64);
    stats::max(Stat::ThreadStackBytesMax, (taken * UNIT) as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that use the global STACKS run one at a time.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        M.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stacks() -> Stacks {
        Stacks {
            base: 0x1000_0000,
            refused: false,
            pages: Pages::new(),
            recs: [REC0; RECORDS],
            taken: 0,
        }
    }

    #[test]
    fn pages_are_first_fit_and_come_back() {
        let mut p = Pages::new();
        assert_eq!(p.take(5), Some(0));
        assert_eq!(p.take(9), Some(5));
        assert_eq!(p.take(5), Some(14));
        p.give(5, 9);
        // The hole takes what fits, a larger stack goes past it.
        assert_eq!(p.take(10), Some(19));
        assert_eq!(p.take(9), Some(5));
        assert_eq!(p.take(0), None);
        assert_eq!(p.take(UNITS + 1), None);
        // Runs cross the 64-page word boundary.
        let mut q = Pages::new();
        assert_eq!(q.take(60), Some(0));
        assert_eq!(q.take(10), Some(60));
        assert!(q.busy(63) && q.busy(64) && q.busy(69) && !q.busy(70));
    }

    #[test]
    fn the_block_holds_the_worst_case_thread_set() {
        // 4 x 128 KiB + 12 x 64 KiB + reactor and metrics at 64 KiB, each
        // with its guard page: 106 of 128 pages, 1.66 MiB.
        let mut s = stacks();
        let sizes = [128usize; 4].into_iter().chain([64usize; 14]);
        let mut recs = Vec::new();
        for kib in sizes {
            recs.push(s.reserve((kib << 10).div_ceil(UNIT) + 1).unwrap());
        }
        assert_eq!(s.taken, 4 * 9 + 14 * 5);
        assert!(s.taken * UNIT <= STACK_MEMORY_MAX);
        assert_eq!(s.taken * UNIT, (1 << 20) + (672 << 10));
        for r in recs {
            s.free(r);
        }
        assert_eq!(s.taken, 0);
        assert_eq!(s.pages.take(UNITS), Some(0));
    }

    #[test]
    fn a_join_frees_only_its_own_stack() {
        let mut s = stacks();
        let a = s.reserve(5).unwrap();
        let b = s.reserve(5).unwrap();
        s.recs[a].thread = 0xa000;
        s.recs[b].thread = 0xb000;
        // A thread with no pool stack, and an unbound slot, match nothing.
        assert_eq!(s.find(0xc000), None);
        assert_eq!(s.find(0), None);
        assert_eq!(s.find(0xb000), Some(b));
        s.free(b);
        assert_eq!(s.find(0xb000), None);
        assert_eq!(s.find(0xa000), Some(a));
        assert_eq!(s.taken, 5);
    }

    #[test]
    fn a_reused_handle_never_frees_a_live_stack() {
        let _serial = serial();
        let taken = || unsafe { (*STACKS.get()).taken };
        let a = unsafe { take(64 << 10, core::ptr::null_mut()) }.expect("pool stack");
        let a_rec = a.rec;
        bind(a, 0xa000 as *mut c_void);
        // Join of A: detached before the join, so the handle can be reused.
        let rec = detach(0xa000 as *mut c_void);
        let b = unsafe { take(64 << 10, core::ptr::null_mut()) }.expect("pool stack");
        let b_rec = b.rec;
        bind(b, 0xa000 as *mut c_void);
        unsafe { release(rec, true) };
        let s = unsafe { &*STACKS.get() };
        assert!(!s.recs[a_rec].used && s.recs[b_rec].used);
        // A failed join binds the stack back.
        let rec = detach(0xa000 as *mut c_void);
        unsafe { release(rec, false) };
        assert_eq!(unsafe { (*STACKS.get()).find(0xa000) }, Some(b_rec));
        // A thread joined before its creator bound it: the next bind of
        // the same handle frees the stale stack.
        let before = taken();
        let c = unsafe { take(64 << 10, core::ptr::null_mut()) }.expect("pool stack");
        let c_rec = c.rec;
        bind(c, 0xa000 as *mut c_void);
        assert!(!unsafe { (*STACKS.get()).recs[b_rec].used });
        assert!(unsafe { (*STACKS.get()).recs[c_rec].used });
        assert_eq!(taken(), before);
        unsafe { release(detach(0xa000 as *mut c_void), true) };
    }

    /// A thread joined before its creator bound it: found by the handle
    /// in the creator's `out`, freed by the bind after a join; a failed
    /// join leaves it to be found again, and a bind during the join leaves
    /// the free to the join's release.
    #[test]
    fn a_join_before_bind_frees_the_stack() {
        let _serial = serial();
        let used = |r: usize| unsafe { (*STACKS.get()).recs[r].used };
        // The creators' handle locations, as libkernel writes them.
        let out: *mut *mut c_void = Box::into_raw(Box::new(core::ptr::null_mut()));
        let out2: *mut *mut c_void = Box::into_raw(Box::new(core::ptr::null_mut()));
        let a = unsafe { take(64 << 10, out) }.expect("pool stack");
        let a_rec = a.rec;
        unsafe { *out = 0xd000 as *mut c_void };
        assert_eq!(detach(0xe000 as *mut c_void), None);
        let rec = detach(0xd000 as *mut c_void);
        assert!(rec.is_some());
        unsafe { release(rec, false) }; // failed join: found again
        let rec = detach(0xd000 as *mut c_void);
        unsafe { release(rec, true) };
        assert!(used(a_rec));
        bind(a, unsafe { *out });
        assert!(!used(a_rec));
        // Bound while the join ran: the release frees it.
        let b = unsafe { take(64 << 10, out2) }.expect("pool stack");
        let b_rec = b.rec;
        unsafe { *out2 = 0xd100 as *mut c_void };
        let rec = detach(0xd100 as *mut c_void);
        bind(b, unsafe { *out2 });
        assert!(used(b_rec));
        unsafe { release(rec, true) };
        assert!(!used(b_rec));
        assert_eq!(detach(0xd100 as *mut c_void), None);
        unsafe { drop((Box::from_raw(out), Box::from_raw(out2))) };
    }

    #[test]
    fn records_run_out_before_pages_corrupt() {
        let mut s = stacks();
        for _ in 0..RECORDS {
            assert!(s.reserve(2).is_some());
        }
        assert_eq!(s.reserve(2), None);
        // A stack larger than the free pages is refused, nothing taken.
        let mut t = stacks();
        assert!(t.reserve(UNITS).is_some());
        assert_eq!(t.reserve(1), None);
        assert_eq!(t.taken, UNITS);
    }

    #[test]
    fn the_largest_stack_fits_with_its_guard() {
        assert_eq!(MAX_STACK % UNIT, 0);
        assert!(MAX_STACK / UNIT + 1 <= UNITS);
        assert_eq!(UNITS, 128);
    }
}
