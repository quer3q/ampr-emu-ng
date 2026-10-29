//! Spin locks, pthread mutex/condvar, once.
//! Everything has a `const fn new` so it can live in a `static`; pthread
//! objects are created lazily on first use.

use super::sys::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// `ampr_spin_pause_or_yield`: pause, but usleep(1) every 256 spins past 4096.
#[inline]
pub fn spin_pause_or_yield(spins: &mut u32) {
    *spins = spins.wrapping_add(1);
    if *spins < 4096 || (*spins & 0xff) != 0 {
        core::hint::spin_loop();
        return;
    }
    unsafe { sceKernelUsleep(1) };
}

/// `UnsafeCell` that is `Sync`; for static state guarded by an external lock.
#[repr(transparent)]
pub struct SyncCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncCell<T> {}
impl<T> SyncCell<T> {
    /// Wraps `v`.
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    /// Raw pointer to the value; caller provides synchronization.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ---- spin lock -----------------------------------------------------------

/// `AmprSpinLock` / `AmprTrySpinLock` over a u32 word (0 = free, 1 = held).
#[repr(transparent)]
pub struct SpinLock(AtomicU32);

/// Releases the spin lock on drop.
pub struct SpinGuard<'a>(&'a AtomicU32);

impl SpinLock {
    /// Unlocked.
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
    /// Views an existing atomic word (e.g. a field of a `#[repr(C)]` struct) as a lock.
    pub fn from_atomic(a: &AtomicU32) -> &SpinLock {
        unsafe { &*(a as *const AtomicU32 as *const SpinLock) }
    }
    /// Spins (with usleep backoff) until acquired.
    pub fn lock(&self) -> SpinGuard<'_> {
        let mut spins = 0u32;
        // Test-and-test-and-set: wait on a plain load so waiters share the line.
        while self.0.swap(1, Ordering::Acquire) != 0 {
            while self.0.load(Ordering::Relaxed) != 0 {
                spin_pause_or_yield(&mut spins);
            }
        }
        SpinGuard(&self.0)
    }
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

// ---- lazy init state -----------------------------------------------------

const UNINIT: u32 = 0;
const INITING: u32 = 1;
const READY: u32 = 2;

/// Runs `init` exactly once across threads; others spin until READY.
#[inline]
fn lazy_init(state: &AtomicU32, init: impl FnOnce()) {
    if state.load(Ordering::Acquire) == READY {
        return;
    }
    if state
        .compare_exchange(UNINIT, INITING, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        init();
        state.store(READY, Ordering::Release);
        return;
    }
    let mut spins = 0u32;
    while state.load(Ordering::Acquire) != READY {
        spin_pause_or_yield(&mut spins);
    }
}

// ---- mutex ---------------------------------------------------------------

/// `AmprMutex` over scePthreadMutex*; any unexpected rc aborts.
pub struct Mutex {
    state: AtomicU32,
    m: UnsafeCell<ScePthreadMutex>,
}
unsafe impl Sync for Mutex {}
unsafe impl Send for Mutex {}

/// `AmprLockGuard` / `AmprUniqueLock`: unlocks on drop.
pub struct MutexGuard<'a> {
    m: &'a Mutex,
}

impl Mutex {
    /// Unlocked; the pthread mutex is created on first use.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(UNINIT),
            m: UnsafeCell::new(core::ptr::null_mut()),
        }
    }
    /// Native handle (initialized), as `native_handle()`.
    pub fn raw(&self) -> *mut ScePthreadMutex {
        lazy_init(&self.state, || {
            if unsafe {
                scePthreadMutexInit(self.m.get(), core::ptr::null(), c"ampr_mutex".as_ptr())
            } != 0
            {
                abort();
            }
        });
        self.m.get()
    }
    /// Blocks until acquired.
    pub fn lock(&self) -> MutexGuard<'_> {
        unsafe { self.lock_raw() };
        MutexGuard { m: self }
    }
    /// Non-blocking; None on EBUSY.
    pub fn try_lock(&self) -> Option<MutexGuard<'_>> {
        match unsafe { scePthreadMutexTrylock(self.raw()) } {
            0 => Some(MutexGuard { m: self }),
            rc if rc == SCE_KERNEL_ERROR_EBUSY || rc == EBUSY => None,
            _ => abort(),
        }
    }
    /// Locks without a guard; pair with `unlock_raw`.
    pub unsafe fn lock_raw(&self) {
        if unsafe { scePthreadMutexLock(self.raw()) } != 0 {
            abort();
        }
    }
    /// Unlocks a mutex held by this thread.
    pub unsafe fn unlock_raw(&self) {
        if unsafe { scePthreadMutexUnlock(self.raw()) } != 0 {
            abort();
        }
    }
}

impl Drop for Mutex {
    fn drop(&mut self) {
        if *self.state.get_mut() == READY {
            unsafe { scePthreadMutexDestroy(self.m.get()) };
        }
    }
}

impl<'a> MutexGuard<'a> {
    /// The locked mutex.
    pub fn mutex(&self) -> &'a Mutex {
        self.m
    }
}

impl Drop for MutexGuard<'_> {
    fn drop(&mut self) {
        unsafe { self.m.unlock_raw() };
    }
}

// ---- condition variable --------------------------------------------------

/// `AmprConditionVariable` over scePthreadCond*.
pub struct Condvar {
    state: AtomicU32,
    c: UnsafeCell<ScePthreadCond>,
}
unsafe impl Sync for Condvar {}
unsafe impl Send for Condvar {}

impl Condvar {
    /// The pthread cond is created on first use.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(UNINIT),
            c: UnsafeCell::new(core::ptr::null_mut()),
        }
    }
    fn raw(&self) -> *mut ScePthreadCond {
        lazy_init(&self.state, || {
            if unsafe { scePthreadCondInit(self.c.get(), core::ptr::null(), c"ampr_cond".as_ptr()) }
                != 0
            {
                abort();
            }
        });
        self.c.get()
    }
    /// Wakes one waiter.
    pub fn notify_one(&self) {
        unsafe { scePthreadCondSignal(self.raw()) };
    }
    /// Wakes all waiters.
    pub fn notify_all(&self) {
        unsafe { scePthreadCondBroadcast(self.raw()) };
    }
    /// Waits once (spurious wakeups possible); aborts on error.
    pub fn wait(&self, g: &mut MutexGuard<'_>) {
        if unsafe { scePthreadCondWait(self.raw(), g.mutex().raw()) } != 0 {
            abort();
        }
    }
    /// Waits until `done()` is true (predicate wait).
    pub fn wait_until(&self, g: &mut MutexGuard<'_>, mut done: impl FnMut() -> bool) {
        while !done() {
            self.wait(g);
        }
    }
    /// Timed wait (`wait_for`), usec clamped to u32::MAX; true if it timed out.
    pub fn wait_for_us(&self, g: &mut MutexGuard<'_>, usec: u64) -> bool {
        let us = if usec > u32::MAX as u64 {
            u32::MAX
        } else {
            usec as u32
        };
        match unsafe { scePthreadCondTimedwait(self.raw(), g.mutex().raw(), us) } {
            0 => false,
            rc if rc == SCE_KERNEL_ERROR_ETIMEDOUT || rc == ETIMEDOUT => true,
            _ => abort(),
        }
    }
}

impl Drop for Condvar {
    fn drop(&mut self) {
        if *self.state.get_mut() == READY {
            unsafe { scePthreadCondDestroy(self.c.get()) };
        }
    }
}

// ---- once ----------------------------------------------------------------

/// `AmprOnceFlag` + `ampr_call_once`: first caller runs, others spin until done.
pub struct Once(AtomicU32);

impl Once {
    /// Not yet run.
    pub const fn new() -> Self {
        Self(AtomicU32::new(UNINIT))
    }
    /// Runs `f` once; concurrent callers wait for it to finish.
    pub fn call_once(&self, f: impl FnOnce()) {
        lazy_init(&self.0, f);
    }
}
