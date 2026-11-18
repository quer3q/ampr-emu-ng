//! APR-only fixed-storage equeue overlay, the only APR equeue path. Native AMM packets never route through here.
//!
//! Layout:
//! 1. constants, fn types, slot ids, `SceKernelEvent`, records, state statics
//! 2. locks (`overlay_lock`, `ControlLock`), originals, deadlines
//! 3. init + hashes (queue, registration)
//! 4. queue control, allocation, pending, private wake
//! 5. native wait / forwarding helpers
//! 6. `apr_equeue_*` helpers and `*_emul` detour targets
//!
//! State: `OV` (`SyncCell<Overlay>`) holds the lock-protected overlay state;
//! take `overlay_lock()` and use `ov()`. Lock-free overlay fields are separate
//! atomic statics (`HOOKS_AVAILABLE`, `WAKE_TRIGGER_STATE`). Queue control
//! uses the recursive pthread mutex behind `ControlLock`. Every tracked wait
//! is a native kernel wait, which the overlay wakes privately to hand over
//! its own events.
//!
//! A queue is tracked from the game's first sceKernelAddAmprEvent on it; its
//! non-AMPR sources (timers, fds, user events, the AGC and VideoOut
//! producers, AMM command buffers) are not observed. A wait on a queue with
//! no AMPR registration (flip, vblank, timer queues) goes to the kernel
//! without the overlay lock (`bypass_wait`). Before, every queue was tracked
//! from its creation and every wait took the global lock twice. Tracking
//! cannot be off: with ids 50..=54 not installed a title's load hung once
//! its reads stopped, all 109,089 completions posted natively to one AMPR
//! id, which the kernel merges while one is unread (debug /queues
//! `eqtarget`). The queue classification (hooks 55..=63, five external
//! producer hooks, the AMM queue hash and command-buffer registry) fed only
//! the debug /queues flags and was removed; a failed install of one of
//! those hooks had turned tracking off.
#![allow(non_snake_case, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering,
};

use super::sync::{spin_pause_or_yield, Once, SpinGuard, SpinLock, SyncCell};
use super::sys::*;

// ---- constants -------------------------------------------------------------

/// Upstream sized the tables to its 4096 live command buffers (4096 queues,
/// 16384 registrations, 4096 extras, 1,507,392 B of `OV` on the host); they
/// are a quarter of that, 376,896 B, with no live peak measured yet (debug `/queues`
/// `eqpeak`). A full table degrades: a queue past it stays native only, a
/// registration past it is not mirrored (its publish posts a native
/// packet), and a second unread event past the extras is backpressured.
const TABLE_BASE: u32 = 1024;
pub(crate) const INVALID_INDEX: u32 = u32::MAX;
const HASH_TOMBSTONE: u32 = u32::MAX;
const QUEUE_CAPACITY: u32 = TABLE_BASE;
const REGISTRATION_CAPACITY: u32 = TABLE_BASE * 4;
/// Pending nodes past the first one of a registration: a second event on one
/// id before the game reads the first (kept, never merged).
const PENDING_EXTRA_CAPACITY: u32 = TABLE_BASE;
/// One node per registration, as a kernel knote, plus the extras: the first
/// event of a live registration is never refused, whatever other queues hold.
const PENDING_CAPACITY: u32 = REGISTRATION_CAPACITY + PENDING_EXTRA_CAPACITY;
const QUEUE_HASH_CAPACITY: u32 = QUEUE_CAPACITY * 2;
const REGISTRATION_HASH_CAPACITY: u32 = REGISTRATION_CAPACITY * 2;
const WAKE_ID_BASE: u32 = 0x5a4d_5000;
const WAKE_ATTACH_ATTEMPTS: u32 = 64;
const REGISTRATION_HASH_TOMBSTONE: u16 = u16::MAX;
const USECONDS_PER_SECOND: u64 = 1_000_000;
const MAX_SCALED_COUNTER_FREQUENCY: u64 = u64::MAX / USECONDS_PER_SECOND;
/// `EVFILT_AMPR`, the filter `sceKernelAddAmprEvent` registers.
pub(crate) const SCE_KERNEL_EVFILT_AMPR: i16 = -25;
/// SDK 10.000 sys/event.h assigns EVFILT_AMPR_SYSTEM the stable ABI value -30.
pub(crate) const SCE_KERNEL_EVFILT_AMPR_SYSTEM: i16 = -30;
/// FreeBSD `EVFILT_USER`.
pub(crate) const SCE_KERNEL_EVFILT_USER: i16 = -11;
const AMPR_EVENT_FILTER: i16 = SCE_KERNEL_EVFILT_AMPR;
const AMPR_SYSTEM_EVENT_FILTER: i16 = SCE_KERNEL_EVFILT_AMPR_SYSTEM;

const _: () = {
    assert!(AMPR_EVENT_FILTER != AMPR_SYSTEM_EVENT_FILTER);
    assert!(QUEUE_HASH_CAPACITY.is_power_of_two());
    assert!(REGISTRATION_HASH_CAPACITY.is_power_of_two());
    assert!(QUEUE_CAPACITY <= u16::MAX as u32 - 1);
    assert!(REGISTRATION_CAPACITY <= u16::MAX as u32 - 1);
    // registration_pending is a u16 per registration.
    assert!(PENDING_EXTRA_CAPACITY < u16::MAX as u32);
};

/// `AmprLibkernelHookId` equeue slots.
pub(crate) mod slot {
    pub const sceKernelCreateEqueue: usize = 50;
    pub const sceKernelWaitEqueue: usize = 51;
    pub const sceKernelDeleteEqueue: usize = 52;
    pub const sceKernelAddAmprEvent: usize = 53;
    pub const sceKernelDeleteAmprEvent: usize = 54;
    /// Never installed (rt/hook.rs `hook_enabled`); its SDK fallback adds
    /// the hidden wake (`attach_hidden_wake_unlocked`).
    pub const sceKernelAddUserEventEdge: usize = 60;
    const _: () = assert!(super::hook::sceKernelClose == 64);
}

// ---- kevent ABI ------------------------------------------------------------

/// `SceKernelEvent` = FreeBSD 11 `struct kevent` (32 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SceKernelEvent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut c_void,
}
const _: () = assert!(core::mem::size_of::<SceKernelEvent>() == 32);

// ---- original fn types -----------------------------------------------------

type WaitEqueueFn = unsafe extern "C" fn(
    SceKernelEqueue,
    *mut SceKernelEvent,
    c_int,
    *mut c_int,
    *mut SceKernelUseconds,
) -> c_int;
type CreateEqueueFn = unsafe extern "C" fn(*mut SceKernelEqueue, *const c_char) -> c_int;
type DeleteEqueueFn = unsafe extern "C" fn(SceKernelEqueue) -> c_int;
type AddAmprEventFn = unsafe extern "C" fn(SceKernelEqueue, c_int, *mut c_void) -> c_int;
type DeleteAmprEventFn = unsafe extern "C" fn(SceKernelEqueue, c_int) -> c_int;
type AddUserEventFn = unsafe extern "C" fn(SceKernelEqueue, c_int) -> c_int;

// ---- records ---------------------------------------------------------------

/// Result of `apr_equeue_try_publish` (header `AprEqueuePublishResult`, u8).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AprEqueuePublishResult {
    Published = 0,
    Backpressure = 1,
    NativeFallback = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueControlScope {
    None,
    Registration,
    WholeQueue,
}

#[derive(Clone, Copy)]
struct QueueControlState {
    id: i32,
    filter: i16,
    scope: QueueControlScope,
}
impl QueueControlState {
    const ZERO: Self = Self {
        id: 0,
        filter: 0,
        scope: QueueControlScope::None,
    };
}

const fn registration_control_conflicts(
    control: QueueControlState,
    filter: i16,
    id: c_int,
) -> bool {
    matches!(control.scope, QueueControlScope::WholeQueue)
        || (matches!(control.scope, QueueControlScope::Registration)
            && control.filter == filter
            && control.id == id)
}

#[derive(Clone, Copy)]
struct MirroredRegistration {
    next: u32,
    id: i32,
    udata: *mut c_void,
    generation: u64,
}
impl MirroredRegistration {
    const ZERO: Self = Self {
        next: 0,
        id: 0,
        udata: core::ptr::null_mut(),
        generation: 0,
    };
}

/// A published EVFILT_AMPR event. ident and udata are copied at publish, so a
/// node reserved by a private wake still carries its own request's values if
/// the registration slot is reused before the node is appended.
#[derive(Clone, Copy)]
struct PendingEvent {
    next: u32,
    registration_index: u32,
    ident: u32,
    data: isize,
    udata: *mut c_void,
}
impl PendingEvent {
    const ZERO: Self = Self {
        next: 0,
        registration_index: 0,
        ident: 0,
        data: 0,
        udata: core::ptr::null_mut(),
    };
}

/// One tracked equeue slot.
#[derive(Clone, Copy)]
struct TrackedEqueue {
    eq: SceKernelEqueue,
    next_free: u32,
    registration_head: u32,
    registration_cache: u32,
    pending_head: u32,
    pending_tail: u32,
    pending_count: u32,
    wake_id: u32,
    lifetime_generation: u64,
    native_wait_intent: u32,
    control_depth: u8,
    used: bool,
    wake_registered: bool,
    wake_ready: bool,
    wake_armed: bool,
    wake_triggering: bool,
}
impl TrackedEqueue {
    const ZERO: Self = Self {
        eq: core::ptr::null_mut(),
        next_free: 0,
        registration_head: 0,
        registration_cache: 0,
        pending_head: 0,
        pending_tail: 0,
        pending_count: 0,
        wake_id: 0,
        lifetime_generation: 0,
        native_wait_intent: 0,
        control_depth: 0,
        used: false,
        wake_registered: false,
        wake_ready: false,
        wake_armed: false,
        wake_triggering: false,
    };
}

#[derive(Clone, Copy)]
struct PrivateWakeRequest {
    eq: SceKernelEqueue,
    queue_index: u32,
    wake_id: u32,
    pending_index: u32,
    registration_index: u32,
    queue_generation: u64,
    registration_generation: u64,
}
impl PrivateWakeRequest {
    const DEFAULT: Self = Self {
        eq: core::ptr::null_mut(),
        queue_index: INVALID_INDEX,
        wake_id: 0,
        pending_index: INVALID_INDEX,
        registration_index: INVALID_INDEX,
        queue_generation: 0,
        registration_generation: 0,
    };
}

#[derive(Clone, Copy, Default)]
struct PrivateWakeCompletion {
    rc: c_int,
    publication_handled: bool,
    pending_count: u32,
}

#[derive(Clone, Copy)]
struct QueueControlTransaction {
    queue_index: u32,
    queue_generation: u64,
    /// The slot was allocated by this transaction (a first AMPR add).
    fresh: bool,
}
impl QueueControlTransaction {
    const DEFAULT: Self = Self {
        queue_index: INVALID_INDEX,
        queue_generation: 0,
        fresh: false,
    };
    /// True when the transaction holds a valid queue slot.
    fn ok(&self) -> bool {
        self.queue_index < QUEUE_CAPACITY
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum BeginPrivateWakeResult {
    AlreadyArmed,
    Scheduled,
    Unavailable,
}

#[derive(Clone, Copy, Default)]
struct NativeWaitTransition {
    synthetic_count: c_int,
    notify_reactor: bool,
    native_wait_intent_installed: bool,
}

/// `NativeWaitDeadline`: nonzero `counter_frequency` selects the process-time
/// counter domain; zero is the CLOCK_MONOTONIC nanosecond fallback.
#[derive(Clone, Copy, Default)]
struct NativeWaitDeadline {
    expires: u64,
    counter_frequency: u64,
}

/// Debug: live peaks of the fixed tables, each the highest count seen at
/// once since module_start. The sizes (1024 queues, 4096 registrations,
/// 5120 pending nodes) are not measured; these say whether they fit.
#[cfg(feature = "mem_report")]
#[derive(Clone, Copy, Default)]
pub(crate) struct Peaks {
    pub(crate) queues: u32,
    pub(crate) registrations: u32,
    pub(crate) pending: u32,
    /// Pending nodes past a registration's first (`PENDING_EXTRA_CAPACITY`).
    pub(crate) extras: u32,
}
#[cfg(feature = "mem_report")]
impl Peaks {
    const ZERO: Self = Self {
        queues: 0,
        registrations: 0,
        pending: 0,
        extras: 0,
    };
}

// ---- global state ----------------------------------------------------------

const QCAP: usize = QUEUE_CAPACITY as usize;
const RCAP: usize = REGISTRATION_CAPACITY as usize;
const PCAP: usize = PENDING_CAPACITY as usize;
const QHASH: usize = QUEUE_HASH_CAPACITY as usize;
const RHASH: usize = REGISTRATION_HASH_CAPACITY as usize;

/// Lock-protected overlay state (guarded by `OVERLAY_LOCK`).
/// Zero-initialized in .bss; `initialize_locked` seeds free lists/generations.
struct Overlay {
    initialized: bool,
    queue_free_head: u32,
    registration_free_head: u32,
    pending_free_head: u32,
    next_wake_id: u32,
    next_lifetime_generation: u64,
    next_registration_generation: u64,
    live_queues: u32,
    live_registrations: u32,
    live_pending: u32,
    /// Registrations with at least one pending node; live_pending minus this
    /// is the extras in use.
    registrations_with_pending: u32,
    queue_hash_tombstones: u32,
    registration_hash_tombstones: u32,
    pending_pool_backpressured: bool,
    /// Debug: the most queues, registrations and pending nodes live at
    /// once, so the table sizes can be cut to a measured peak (/queues).
    #[cfg(feature = "mem_report")]
    peaks: Peaks,
    controls: [QueueControlState; QCAP],
    queues: [TrackedEqueue; QCAP],
    registrations: [MirroredRegistration; RCAP],
    pending: [PendingEvent; PCAP],
    queue_hash: [u32; QHASH],
    registration_hash: [u16; RHASH],
    registration_owners: [u16; RCAP],
    registration_filters: [i16; RCAP],
    registration_pending: [u16; RCAP],
}

static OV: SyncCell<Overlay> = SyncCell::new(Overlay {
    initialized: false,
    queue_free_head: 0,
    registration_free_head: 0,
    pending_free_head: 0,
    next_wake_id: 0,
    next_lifetime_generation: 0,
    next_registration_generation: 0,
    live_queues: 0,
    live_registrations: 0,
    live_pending: 0,
    registrations_with_pending: 0,
    queue_hash_tombstones: 0,
    registration_hash_tombstones: 0,
    pending_pool_backpressured: false,
    #[cfg(feature = "mem_report")]
    peaks: Peaks::ZERO,
    controls: [QueueControlState::ZERO; QCAP],
    queues: [TrackedEqueue::ZERO; QCAP],
    registrations: [MirroredRegistration::ZERO; RCAP],
    pending: [PendingEvent::ZERO; PCAP],
    queue_hash: [0; QHASH],
    registration_hash: [0; RHASH],
    registration_owners: [0; RCAP],
    registration_filters: [0; RCAP],
    registration_pending: [0; RCAP],
});

/// Overlay state; caller holds `overlay_lock()` (or is single-threaded init).
#[inline(always)]
unsafe fn ov() -> &'static mut Overlay {
    unsafe { &mut *OV.get() }
}

#[repr(C, align(64))]
struct Align64<T>(T);

static OVERLAY_LOCK: SpinLock = SpinLock::new();
static HOOKS_AVAILABLE: AtomicBool = AtomicBool::new(false);
/// Set once by `initialize_control_once` (0 = use CLOCK_MONOTONIC).
static PROCESS_TIME_COUNTER_FREQUENCY: AtomicU64 = AtomicU64::new(0);
/// Slot-local wake trigger state, for waiting after the overlay lock drops
/// (the bit in `TrackedEqueue` is the lock-protected hot-path predicate).
static WAKE_TRIGGER_STATE: Align64<[AtomicU8; QCAP]> = Align64([const { AtomicU8::new(0) }; QCAP]);

/// Buckets of the lock-free tracked test (`bypass_bucket`). A queue that
/// shares a bucket with a tracked one only takes the locked path, which is
/// correct for any queue; 256 keeps that rare at a few AMPR queues.
const BYPASS_BUCKETS: usize = 256;
/// Tracked queues per bucket, changed under the overlay lock.
static TRACKED_IN_BUCKET: [AtomicU32; BYPASS_BUCKETS] =
    [const { AtomicU32::new(0) }; BYPASS_BUCKETS];
/// Waits in the kernel through `bypass_wait` per bucket. A first AMPR
/// registration that sees one wakes its queue once, so a waiter that went
/// direct before the queue was tracked comes back through the overlay.
static BYPASS_WAITERS: [AtomicU32; BYPASS_BUCKETS] =
    [const { AtomicU32::new(0) }; BYPASS_BUCKETS];

fn bypass_bucket(eq: SceKernelEqueue) -> usize {
    hash_queue(eq) as usize & (BYPASS_BUCKETS - 1)
}

/// A thread may be in a kernel wait on `q` that a synthetic event must
/// wake: a tracked native wait, or a direct one that began before `q` was
/// tracked (`BYPASS_WAITERS` counts its bucket, so another queue's direct
/// waiter costs at most a hidden wake no one reads). The first-add wake
/// frees one direct waiter; this keeps waking until none are left.
fn kernel_waiters_locked(q: &TrackedEqueue) -> bool {
    q.native_wait_intent != 0 || BYPASS_WAITERS[bypass_bucket(q.eq)].load(Ordering::SeqCst) != 0
}

static CONTROL_ONCE: Once = Once::new();
static CONTROL_MUTEX: SyncCell<ScePthreadMutex> = SyncCell::new(core::ptr::null_mut());
static CONTROL_INIT_RC: AtomicI32 = AtomicI32::new(SCE_KERNEL_ERROR_EAGAIN);


// ---- locks -----------------------------------------------------------------

/// Takes the overlay spin lock.
#[inline]
fn overlay_lock() -> SpinGuard<'static> {
    OVERLAY_LOCK.lock()
}

fn initialize_control_once() {
    let mut rc;
    let mut attr: ScePthreadMutexattr = core::ptr::null_mut();
    unsafe {
        rc = scePthreadMutexattrInit(&mut attr);
        if rc == 0 {
            rc = scePthreadMutexattrSettype(&mut attr, SCE_PTHREAD_MUTEX_RECURSIVE);
            if rc == 0 {
                rc = scePthreadMutexInit(CONTROL_MUTEX.get(), &attr, c"ampr_eq_control".as_ptr());
            }
            scePthreadMutexattrDestroy(&mut attr);
        }
    }
    let freq = unsafe { sceKernelGetProcessTimeCounterFrequency() };
    PROCESS_TIME_COUNTER_FREQUENCY.store(
        if freq <= MAX_SCALED_COUNTER_FREQUENCY {
            freq
        } else {
            0
        },
        Ordering::Relaxed,
    );
    CONTROL_INIT_RC.store(rc, Ordering::Release);
}

fn ensure_control_initialized() {
    CONTROL_ONCE.call_once(initialize_control_once);
    if CONTROL_INIT_RC.load(Ordering::Acquire) != 0 {
        abort();
    }
}

/// Queue control lock: recursive pthread mutex, aborts on any failure.
struct ControlLock(());
impl ControlLock {
    fn new() -> Self {
        ensure_control_initialized();
        if unsafe { scePthreadMutexLock(CONTROL_MUTEX.get()) } != 0 {
            abort();
        }
        ControlLock(())
    }
}
impl Drop for ControlLock {
    fn drop(&mut self) {
        if unsafe { scePthreadMutexUnlock(CONTROL_MUTEX.get()) } != 0 {
            abort();
        }
    }
}

// ---- original libkernel entry points ---------------------------------------

#[inline]
fn original_wait_equeue() -> Option<WaitEqueueFn> {
    unsafe { kernel_slot(slot::sceKernelWaitEqueue) }
}
#[inline]
fn original_create_equeue() -> Option<CreateEqueueFn> {
    unsafe { kernel_slot(slot::sceKernelCreateEqueue) }
}
#[inline]
fn original_delete_equeue() -> Option<DeleteEqueueFn> {
    unsafe { kernel_slot(slot::sceKernelDeleteEqueue) }
}
#[inline]
fn original_add_ampr_event() -> Option<AddAmprEventFn> {
    unsafe { kernel_slot(slot::sceKernelAddAmprEvent) }
}
#[inline]
fn original_delete_ampr_event() -> Option<DeleteAmprEventFn> {
    unsafe { kernel_slot(slot::sceKernelDeleteAmprEvent) }
}
#[inline]
fn original_add_user_event_edge() -> Option<AddUserEventFn> {
    unsafe { kernel_slot(slot::sceKernelAddUserEventEdge) }
}

// ---- deadlines -------------------------------------------------------------

// `monotonic_ns` comes from sys.rs (same contract: 0 on failure).

fn timeout_to_counter_ticks(timeout: SceKernelUseconds, frequency: u64) -> u64 {
    let t = timeout as u64;
    let whole = t / USECONDS_PER_SECOND;
    let partial_us = t % USECONDS_PER_SECOND;
    if whole != 0 && frequency > u64::MAX / whole {
        return u64::MAX;
    }
    let ticks = whole * frequency;
    let num = partial_us * frequency;
    let partial = num / USECONDS_PER_SECOND + (num % USECONDS_PER_SECOND != 0) as u64;
    if partial > u64::MAX - ticks {
        return u64::MAX;
    }
    ticks + partial
}

fn make_native_wait_deadline(
    timeout: SceKernelUseconds,
    counter_frequency: u64,
) -> NativeWaitDeadline {
    let mut d = NativeWaitDeadline::default();
    let (start, duration);
    if counter_frequency != 0 {
        d.counter_frequency = counter_frequency;
        start = unsafe { sceKernelGetProcessTimeCounter() };
        duration = timeout_to_counter_ticks(timeout, counter_frequency);
    } else {
        start = monotonic_ns();
        if start == 0 {
            return NativeWaitDeadline::default();
        }
        duration = timeout as u64 * 1000;
    }
    d.expires = start.checked_add(duration).unwrap_or(u64::MAX);
    d
}

fn next_generation64(value: &mut u64) -> u64 {
    let mut out = *value;
    *value = value.wrapping_add(1);
    if out == 0 {
        out = *value;
        *value = value.wrapping_add(1);
    }
    out
}

// ---- init + queue hash -----------------------------------------------------

unsafe fn initialize_locked() {
    let o = unsafe { ov() };
    if o.initialized {
        return;
    }
    for i in 0..QCAP {
        WAKE_TRIGGER_STATE.0[i].store(0, Ordering::Relaxed);
        o.controls[i] = QueueControlState::ZERO;
        o.queues[i] = TrackedEqueue::ZERO;
        o.queues[i].next_free = if i + 1 < QCAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
    }
    for i in 0..RCAP {
        o.registrations[i] = MirroredRegistration::ZERO;
        o.registrations[i].next = if i + 1 < RCAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
        o.registration_owners[i] = 0;
        o.registration_filters[i] = 0;
        o.registration_pending[i] = 0;
    }
    for i in 0..PCAP {
        o.pending[i] = PendingEvent::ZERO;
        o.pending[i].next = if i + 1 < PCAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
        o.pending[i].registration_index = INVALID_INDEX;
    }
    o.queue_hash.fill(0);
    o.registration_hash.fill(0);
    o.queue_free_head = 0;
    o.registration_free_head = 0;
    o.pending_free_head = 0;
    o.next_wake_id = WAKE_ID_BASE;
    o.next_lifetime_generation = 1;
    o.next_registration_generation = 1;
    o.live_queues = 0;
    o.live_registrations = 0;
    o.live_pending = 0;
    o.registrations_with_pending = 0;
    o.queue_hash_tombstones = 0;
    o.registration_hash_tombstones = 0;
    o.pending_pool_backpressured = false;
    o.initialized = true;
}

/// Full-value hash (handles may be small fds or aligned addresses): the high
/// product bits mix every input bit.
fn hash_queue(eq: SceKernelEqueue) -> u32 {
    let mut v = eq as usize;
    v ^= v >> 17;
    v = v.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    ((v >> 32) as u32) & (QUEUE_HASH_CAPACITY - 1)
}

// ---- queue lookup ----------------------------------------------------------

unsafe fn find_queue_index_locked(eq: SceKernelEqueue) -> u32 {
    let o = unsafe { ov() };
    if eq.is_null() || !o.initialized {
        return INVALID_INDEX;
    }
    let mut slot = hash_queue(eq);
    for _ in 0..QUEUE_HASH_CAPACITY {
        let v = o.queue_hash[slot as usize];
        if v == 0 {
            return INVALID_INDEX;
        }
        if v != HASH_TOMBSTONE {
            let i = v - 1;
            if i < QUEUE_CAPACITY && o.queues[i as usize].used && o.queues[i as usize].eq == eq {
                return i;
            }
        }
        slot = (slot + 1) & (QUEUE_HASH_CAPACITY - 1);
    }
    INVALID_INDEX
}

const _: () = {
    let reg = QueueControlState {
        id: 1,
        filter: AMPR_EVENT_FILTER,
        scope: QueueControlScope::Registration,
    };
    assert!(!registration_control_conflicts(
        QueueControlState::ZERO,
        AMPR_EVENT_FILTER,
        1
    ));
    assert!(registration_control_conflicts(reg, AMPR_EVENT_FILTER, 1));
    assert!(!registration_control_conflicts(reg, AMPR_EVENT_FILTER, 2));
    assert!(!registration_control_conflicts(
        reg,
        AMPR_SYSTEM_EVENT_FILTER,
        1
    ));
    let whole = QueueControlState {
        id: 0,
        filter: 0,
        scope: QueueControlScope::WholeQueue,
    };
    assert!(registration_control_conflicts(whole, AMPR_EVENT_FILTER, 1));
};

// ---- queue control ---------------------------------------------------------

/// `track` starts tracking an untracked queue (an AMPR add); a delete only
/// finds one.
fn begin_queue_control(
    eq: SceKernelEqueue,
    filter: i16,
    id: c_int,
    track: bool,
) -> QueueControlTransaction {
    let mut t = QueueControlTransaction::DEFAULT;
    let _g = overlay_lock();
    if !HOOKS_AVAILABLE.load(Ordering::Relaxed) {
        return t;
    }
    t.queue_index = unsafe { find_queue_index_locked(eq) };
    if t.queue_index >= QUEUE_CAPACITY && track && !eq.is_null() {
        t.queue_index = unsafe { allocate_queue_locked(eq) };
        t.fresh = true;
    }
    if t.queue_index >= QUEUE_CAPACITY {
        return t;
    }
    let o = unsafe { ov() };
    let i = t.queue_index as usize;
    let q = &mut o.queues[i];
    t.queue_generation = q.lifetime_generation;
    let c = &mut o.controls[i];
    if q.control_depth == 0 {
        *c = QueueControlState {
            id,
            filter,
            scope: QueueControlScope::Registration,
        };
    } else {
        // Recursive same-queue reentry: conservative until the outer one ends.
        c.scope = QueueControlScope::WholeQueue;
    }
    q.control_depth += 1;
    t
}

/// Returns the transaction's queue index if it still names the same queue.
unsafe fn find_queue_control_locked(t: &QueueControlTransaction) -> Option<u32> {
    let o = unsafe { ov() };
    if !t.ok() {
        return None;
    }
    let q = &o.queues[t.queue_index as usize];
    if !q.used || q.lifetime_generation != t.queue_generation {
        return None;
    }
    Some(t.queue_index)
}

unsafe fn finish_queue_control_locked(queue_index: u32) {
    let o = unsafe { ov() };
    let q = &mut o.queues[queue_index as usize];
    if q.control_depth != 0 {
        q.control_depth -= 1;
    }
    if q.control_depth == 0 && queue_index < QUEUE_CAPACITY {
        o.controls[queue_index as usize] = QueueControlState::ZERO;
    }
}

unsafe fn queue_control_conflicts_with_registration_locked(
    queue_index: u32,
    q: &TrackedEqueue,
    filter: i16,
    id: c_int,
) -> bool {
    if q.control_depth == 0 {
        return false;
    }
    if queue_index >= QUEUE_CAPACITY {
        return true;
    }
    let c = unsafe { ov() }.controls[queue_index as usize];
    matches!(c.scope, QueueControlScope::None) || registration_control_conflicts(c, filter, id)
}

// ---- queue hash + allocation -----------------------------------------------

/// Debug: raises the live peaks after an allocation; empty in release.
#[inline(always)]
unsafe fn note_peaks_locked() {
    #[cfg(feature = "mem_report")]
    {
        let o = unsafe { ov() };
        let p = &mut o.peaks;
        p.queues = p.queues.max(o.live_queues);
        p.registrations = p.registrations.max(o.live_registrations);
        p.pending = p.pending.max(o.live_pending);
        p.extras = p
            .extras
            .max(o.live_pending.saturating_sub(o.registrations_with_pending));
    }
}

unsafe fn insert_queue_hash_raw_locked(eq: SceKernelEqueue, queue_index: u32) -> bool {
    let o = unsafe { ov() };
    let mut slot = hash_queue(eq);
    let mut tomb = INVALID_INDEX;
    for _ in 0..QUEUE_HASH_CAPACITY {
        let v = o.queue_hash[slot as usize];
        if v == HASH_TOMBSTONE && tomb == INVALID_INDEX {
            tomb = slot;
        } else if v == 0 {
            let target = if tomb != INVALID_INDEX { tomb } else { slot };
            o.queue_hash[target as usize] = queue_index + 1;
            if tomb != INVALID_INDEX && o.queue_hash_tombstones != 0 {
                o.queue_hash_tombstones -= 1;
            }
            return true;
        }
        slot = (slot + 1) & (QUEUE_HASH_CAPACITY - 1);
    }
    if tomb != INVALID_INDEX {
        o.queue_hash[tomb as usize] = queue_index + 1;
        if o.queue_hash_tombstones != 0 {
            o.queue_hash_tombstones -= 1;
        }
        return true;
    }
    false
}

unsafe fn rebuild_queue_hash_locked() -> bool {
    let o = unsafe { ov() };
    o.queue_hash.fill(0);
    o.queue_hash_tombstones = 0;
    for i in 0..QUEUE_CAPACITY {
        let q = o.queues[i as usize];
        if q.used && !unsafe { insert_queue_hash_raw_locked(q.eq, i) } {
            return false;
        }
    }
    true
}

unsafe fn insert_queue_hash_locked(eq: SceKernelEqueue, queue_index: u32) -> bool {
    if unsafe { ov() }.queue_hash_tombstones >= QUEUE_CAPACITY / 2 {
        // Cold path: rebuild so lookups do not degrade after create/delete churn.
        if !unsafe { rebuild_queue_hash_locked() } {
            return false;
        }
        return unsafe { find_queue_index_locked(eq) } == queue_index;
    }
    unsafe { insert_queue_hash_raw_locked(eq, queue_index) }
}

unsafe fn erase_queue_hash_locked(eq: SceKernelEqueue) {
    let o = unsafe { ov() };
    let mut slot = hash_queue(eq);
    for _ in 0..QUEUE_HASH_CAPACITY {
        let v = o.queue_hash[slot as usize];
        if v == 0 {
            return;
        }
        if v != HASH_TOMBSTONE {
            let i = v - 1;
            if i < QUEUE_CAPACITY && o.queues[i as usize].used && o.queues[i as usize].eq == eq {
                o.queue_hash[slot as usize] = HASH_TOMBSTONE;
                o.queue_hash_tombstones += 1;
                return;
            }
        }
        slot = (slot + 1) & (QUEUE_HASH_CAPACITY - 1);
    }
}

unsafe fn allocate_queue_locked(eq: SceKernelEqueue) -> u32 {
    unsafe { initialize_locked() };
    let o = unsafe { ov() };
    let index = o.queue_free_head;
    if index >= QUEUE_CAPACITY {
        return INVALID_INDEX;
    }
    let i = index as usize;
    o.queue_free_head = o.queues[i].next_free;
    o.queues[i] = TrackedEqueue {
        eq,
        used: true,
        registration_head: INVALID_INDEX,
        registration_cache: INVALID_INDEX,
        pending_head: INVALID_INDEX,
        pending_tail: INVALID_INDEX,
        next_free: INVALID_INDEX,
        lifetime_generation: next_generation64(&mut o.next_lifetime_generation),
        ..TrackedEqueue::ZERO
    };
    o.controls[i] = QueueControlState::ZERO;
    if !unsafe { insert_queue_hash_locked(eq, index) } {
        let o = unsafe { ov() };
        o.queues[i] = TrackedEqueue {
            next_free: o.queue_free_head,
            ..TrackedEqueue::ZERO
        };
        o.queue_free_head = index;
        return INVALID_INDEX;
    }
    unsafe { ov() }.live_queues += 1;
    unsafe { note_peaks_locked() };
    // SeqCst against `bypass_wait`: it counts itself, then reads this.
    TRACKED_IN_BUCKET[bypass_bucket(eq)].fetch_add(1, Ordering::SeqCst);
    index
}

// ---- registration hash + allocation ----------------------------------------

fn hash_registration(queue_index: u32, filter: i16, id: i32) -> u32 {
    let mut v = id as u32;
    v ^= queue_index.wrapping_mul(0x9e37_79b9);
    v ^= (filter as u16 as u32).wrapping_mul(0x27d4_eb2d);
    v ^= v >> 16;
    v = v.wrapping_mul(0x85eb_ca6b);
    v ^= v >> 13;
    v & (REGISTRATION_HASH_CAPACITY - 1)
}

unsafe fn registration_hash_entry_matches_locked(
    value: u16,
    queue_index: u32,
    filter: i16,
    id: i32,
) -> bool {
    if value == 0 || value == REGISTRATION_HASH_TOMBSTONE {
        return false;
    }
    let o = unsafe { ov() };
    let r = (value - 1) as usize;
    r < RCAP
        && o.registration_owners[r] as u32 == queue_index + 1
        && o.registration_filters[r] == filter
        && o.registrations[r].id == id
}

unsafe fn insert_registration_hash_raw_locked(
    queue_index: u32,
    filter: i16,
    id: i32,
    reg_index: u32,
) -> bool {
    let o = unsafe { ov() };
    let mut slot = hash_registration(queue_index, filter, id);
    let mut tomb = INVALID_INDEX;
    for _ in 0..REGISTRATION_HASH_CAPACITY {
        let v = o.registration_hash[slot as usize];
        if v == REGISTRATION_HASH_TOMBSTONE && tomb == INVALID_INDEX {
            tomb = slot;
        } else if v == 0 {
            let target = if tomb != INVALID_INDEX { tomb } else { slot };
            o.registration_hash[target as usize] = (reg_index + 1) as u16;
            if tomb != INVALID_INDEX && o.registration_hash_tombstones != 0 {
                o.registration_hash_tombstones -= 1;
            }
            return true;
        }
        slot = (slot + 1) & (REGISTRATION_HASH_CAPACITY - 1);
    }
    if tomb != INVALID_INDEX {
        o.registration_hash[tomb as usize] = (reg_index + 1) as u16;
        if o.registration_hash_tombstones != 0 {
            o.registration_hash_tombstones -= 1;
        }
        return true;
    }
    false
}

unsafe fn rebuild_registration_hash_locked() -> bool {
    let o = unsafe { ov() };
    o.registration_hash.fill(0);
    o.registration_hash_tombstones = 0;
    for r in 0..REGISTRATION_CAPACITY {
        let owner = o.registration_owners[r as usize];
        if owner != 0
            && !unsafe {
                insert_registration_hash_raw_locked(
                    owner as u32 - 1,
                    o.registration_filters[r as usize],
                    o.registrations[r as usize].id,
                    r,
                )
            }
        {
            return false;
        }
    }
    true
}

unsafe fn insert_registration_hash_locked(
    queue_index: u32,
    filter: i16,
    id: i32,
    reg_index: u32,
) -> bool {
    if unsafe { ov() }.registration_hash_tombstones >= REGISTRATION_CAPACITY / 2
        && !unsafe { rebuild_registration_hash_locked() }
    {
        return false;
    }
    unsafe { insert_registration_hash_raw_locked(queue_index, filter, id, reg_index) }
}

unsafe fn erase_registration_hash_locked(queue_index: u32, filter: i16, id: i32) {
    let o = unsafe { ov() };
    let mut slot = hash_registration(queue_index, filter, id);
    for _ in 0..REGISTRATION_HASH_CAPACITY {
        let v = o.registration_hash[slot as usize];
        if v == 0 {
            return;
        }
        if unsafe { registration_hash_entry_matches_locked(v, queue_index, filter, id) } {
            o.registration_hash[slot as usize] = REGISTRATION_HASH_TOMBSTONE;
            o.registration_hash_tombstones += 1;
            return;
        }
        slot = (slot + 1) & (REGISTRATION_HASH_CAPACITY - 1);
    }
}

unsafe fn find_registration_locked(queue_index: u32, filter: i16, id: i32) -> u32 {
    let o = unsafe { ov() };
    let cache = o.queues[queue_index as usize].registration_cache;
    if cache < REGISTRATION_CAPACITY {
        let c = cache as usize;
        if o.registration_owners[c] as u32 == queue_index + 1
            && o.registration_filters[c] == filter
            && o.registrations[c].id == id
        {
            return cache;
        }
    }
    let mut slot = hash_registration(queue_index, filter, id);
    for _ in 0..REGISTRATION_HASH_CAPACITY {
        let v = o.registration_hash[slot as usize];
        if v == 0 {
            return INVALID_INDEX;
        }
        if unsafe { registration_hash_entry_matches_locked(v, queue_index, filter, id) } {
            let r = (v - 1) as u32;
            o.queues[queue_index as usize].registration_cache = r;
            return r;
        }
        slot = (slot + 1) & (REGISTRATION_HASH_CAPACITY - 1);
    }
    INVALID_INDEX
}

unsafe fn allocate_registration_locked(
    queue_index: u32,
    filter: i16,
    id: i32,
    udata: *mut c_void,
    out_notify_reactor: Option<&mut bool>,
) -> u32 {
    let qi = queue_index as usize;
    let mut index = unsafe { find_registration_locked(queue_index, filter, id) };
    if index < REGISTRATION_CAPACITY {
        if unsafe { purge_pending_registration_locked(queue_index, index) } {
            if let Some(n) = out_notify_reactor {
                *n = true;
            }
        }
        let o = unsafe { ov() };
        let r = &mut o.registrations[index as usize];
        r.udata = udata;
        r.generation = next_generation64(&mut o.next_registration_generation);
        return index;
    }
    let o = unsafe { ov() };
    index = o.registration_free_head;
    if index >= REGISTRATION_CAPACITY {
        return INVALID_INDEX;
    }
    let ri = index as usize;
    o.registration_free_head = o.registrations[ri].next;
    o.registrations[ri] = MirroredRegistration {
        id,
        udata,
        generation: next_generation64(&mut o.next_registration_generation),
        next: o.queues[qi].registration_head,
    };
    o.registration_filters[ri] = filter;
    if !unsafe { insert_registration_hash_locked(queue_index, filter, id, index) } {
        let o = unsafe { ov() };
        o.registration_filters[ri] = 0;
        o.registrations[ri] = MirroredRegistration {
            next: o.registration_free_head,
            ..MirroredRegistration::ZERO
        };
        o.registration_free_head = index;
        return INVALID_INDEX;
    }
    // Publish ownership only after insertion: a tombstone-driven rebuild inside
    // insert_registration_hash_locked would otherwise insert this slot twice.
    let o = unsafe { ov() };
    o.registration_owners[ri] = (queue_index + 1) as u16;
    o.queues[qi].registration_head = index;
    o.queues[qi].registration_cache = index;
    o.live_registrations += 1;
    unsafe { note_peaks_locked() };
    index
}

unsafe fn remove_registration_locked(
    queue_index: u32,
    filter: i16,
    id: i32,
    out_notify_reactor: Option<&mut bool>,
) {
    let qi = queue_index as usize;
    let mut previous = INVALID_INDEX;
    let mut index = unsafe { ov() }.queues[qi].registration_head;
    while index < REGISTRATION_CAPACITY {
        let ri = index as usize;
        let (next, rid, rfilter) = {
            let o = unsafe { ov() };
            (
                o.registrations[ri].next,
                o.registrations[ri].id,
                o.registration_filters[ri],
            )
        };
        if rid == id && rfilter == filter {
            if unsafe { purge_pending_registration_locked(queue_index, index) } {
                if let Some(n) = out_notify_reactor {
                    *n = true;
                }
            }
            unsafe { erase_registration_hash_locked(queue_index, filter, id) };
            let o = unsafe { ov() };
            if previous < REGISTRATION_CAPACITY {
                o.registrations[previous as usize].next = next;
            } else {
                o.queues[qi].registration_head = next;
            }
            if o.queues[qi].registration_cache == index {
                o.queues[qi].registration_cache = INVALID_INDEX;
            }
            o.registration_owners[ri] = 0;
            o.registration_filters[ri] = 0;
            o.registrations[ri] = MirroredRegistration {
                next: o.registration_free_head,
                ..MirroredRegistration::ZERO
            };
            o.registration_free_head = index;
            if o.live_registrations != 0 {
                o.live_registrations -= 1;
            }
            // No 64 KB clear at zero live: the tombstone rebuild threshold bounds probes.
            next_generation64(&mut o.next_registration_generation);
            return;
        }
        previous = index;
        index = next;
    }
}

// ---- pending FIFO ----------------------------------------------------------

/// Reserves a node for `registration_index`. The first pending event of a
/// registration always gets one (PENDING_CAPACITY holds one per
/// registration, as the kernel holds one knote per registration); further
/// unread events on the same id share PENDING_EXTRA_CAPACITY.
unsafe fn allocate_pending_locked(registration_index: u32) -> u32 {
    let o = unsafe { ov() };
    let ri = registration_index as usize;
    if ri >= RCAP {
        return INVALID_INDEX;
    }
    let first = o.registration_pending[ri] == 0;
    if !first && unsafe { pending_extras_full_locked() } {
        return INVALID_INDEX;
    }
    let index = o.pending_free_head;
    if index >= PENDING_CAPACITY {
        return INVALID_INDEX;
    }
    let pi = index as usize;
    o.pending_free_head = o.pending[pi].next;
    o.pending[pi] = PendingEvent {
        next: INVALID_INDEX,
        registration_index,
        ..PendingEvent::ZERO
    };
    o.live_pending += 1;
    o.registration_pending[ri] += 1;
    if first {
        o.registrations_with_pending += 1;
    }
    unsafe { note_peaks_locked() };
    index
}

unsafe fn release_pending_locked(index: u32) {
    if index >= PENDING_CAPACITY {
        return;
    }
    let o = unsafe { ov() };
    let ri = o.pending[index as usize].registration_index as usize;
    if ri < RCAP && o.registration_pending[ri] != 0 {
        o.registration_pending[ri] -= 1;
        if o.registration_pending[ri] == 0 && o.registrations_with_pending != 0 {
            o.registrations_with_pending -= 1;
        }
    }
    o.pending[index as usize] = PendingEvent {
        next: o.pending_free_head,
        registration_index: INVALID_INDEX,
        ..PendingEvent::ZERO
    };
    o.pending_free_head = index;
    if o.live_pending != 0 {
        o.live_pending -= 1;
    }
}

/// live_pending minus registrations_with_pending is the extras in use.
unsafe fn pending_extras_full_locked() -> bool {
    let o = unsafe { ov() };
    o.live_pending.saturating_sub(o.registrations_with_pending) >= PENDING_EXTRA_CAPACITY
}

/// Progress for a backpressured publish is a free extra: a first node is
/// always granted, so a freed one does not let the refused publish through.
unsafe fn take_pending_backpressure_progress_locked() -> bool {
    let o = unsafe { ov() };
    if !o.pending_pool_backpressured
        || o.pending_free_head >= PENDING_CAPACITY
        || unsafe { pending_extras_full_locked() }
    {
        return false;
    }
    o.pending_pool_backpressured = false;
    true
}

unsafe fn purge_pending_registration_locked(queue_index: u32, registration_index: u32) -> bool {
    let qi = queue_index as usize;
    let mut previous = INVALID_INDEX;
    let mut index = unsafe { ov() }.queues[qi].pending_head;
    let mut released = false;
    while index < PENDING_CAPACITY {
        let o = unsafe { ov() };
        let next = o.pending[index as usize].next;
        if o.pending[index as usize].registration_index == registration_index {
            if previous < PENDING_CAPACITY {
                o.pending[previous as usize].next = next;
            } else {
                o.queues[qi].pending_head = next;
            }
            let q = &mut o.queues[qi];
            if q.pending_tail == index {
                q.pending_tail = previous;
            }
            if q.pending_count != 0 {
                q.pending_count -= 1;
            }
            unsafe { release_pending_locked(index) };
            released = true;
        } else {
            previous = index;
        }
        index = next;
    }
    released && unsafe { take_pending_backpressure_progress_locked() }
}

unsafe fn append_pending_locked(queue_index: u32, index: u32) {
    let o = unsafe { ov() };
    let q = &mut o.queues[queue_index as usize];
    if q.pending_tail < PENDING_CAPACITY {
        o.pending[q.pending_tail as usize].next = index;
    } else {
        q.pending_head = index;
    }
    q.pending_tail = index;
    q.pending_count += 1;
}

unsafe fn wake_registration_is_current_locked(queue_index: u32, req: &PrivateWakeRequest) -> bool {
    let o = unsafe { ov() };
    let r = req.registration_index as usize;
    r < RCAP
        && o.registration_owners[r] as u32 == queue_index + 1
        && o.registrations[r].generation == req.registration_generation
}

/// Moves up to `capacity` pending events of the queue into `events`.
unsafe fn drain_pending_locked(
    queue_index: u32,
    events: *mut SceKernelEvent,
    capacity: c_int,
    out_notify_reactor: Option<&mut bool>,
) -> c_int {
    let qi = queue_index as usize;
    let mut count: c_int = 0;
    let mut released = false;
    loop {
        let o = unsafe { ov() };
        let index = o.queues[qi].pending_head;
        if index >= PENDING_CAPACITY || count >= capacity {
            break;
        }
        let p = o.pending[index as usize];
        let event = SceKernelEvent {
            ident: p.ident as usize,
            filter: SCE_KERNEL_EVFILT_AMPR,
            flags: EV_ADD | EV_CLEAR,
            fflags: 0,
            data: p.data,
            udata: p.udata,
        };
        let q = &mut o.queues[qi];
        q.pending_head = p.next;
        if q.pending_head >= PENDING_CAPACITY {
            q.pending_tail = INVALID_INDEX;
        }
        if q.pending_count != 0 {
            q.pending_count -= 1;
        }
        unsafe { *events.add(count as usize) = event };
        count += 1;
        unsafe { release_pending_locked(index) };
        released = true;
    }
    if released {
        if let Some(n) = out_notify_reactor {
            if unsafe { take_pending_backpressure_progress_locked() } {
                *n = true;
            }
        }
    }
    count
}

// ---- private wake ----------------------------------------------------------

fn private_wake_in_flight_locked(q: &TrackedEqueue) -> bool {
    q.wake_triggering
}

unsafe fn begin_private_wake_locked(
    queue_index: u32,
    pending_index: u32,
    request: Option<&mut PrivateWakeRequest>,
) -> BeginPrivateWakeResult {
    let o = unsafe { ov() };
    let q = &mut o.queues[queue_index as usize];
    if q.wake_armed {
        return BeginPrivateWakeResult::AlreadyArmed;
    }
    let Some(req) = request else {
        return BeginPrivateWakeResult::Unavailable;
    };
    if !q.wake_ready || private_wake_in_flight_locked(q) {
        return BeginPrivateWakeResult::Unavailable;
    }
    q.wake_triggering = true;
    WAKE_TRIGGER_STATE.0[queue_index as usize].store(1, Ordering::Relaxed);
    req.eq = q.eq;
    req.queue_index = queue_index;
    req.wake_id = q.wake_id;
    req.pending_index = pending_index;
    req.queue_generation = q.lifetime_generation;
    if pending_index < PENDING_CAPACITY {
        req.registration_index = o.pending[pending_index as usize].registration_index;
        if req.registration_index < REGISTRATION_CAPACITY {
            req.registration_generation =
                o.registrations[req.registration_index as usize].generation;
        }
    }
    BeginPrivateWakeResult::Scheduled
}

fn wait_for_private_wake(queue_index: u32) {
    use super::stats::{self, Stat};
    let mut spins = 0u32;
    stats::enter(Stat::EqueuePrivateSpinNow);
    while queue_index < QUEUE_CAPACITY
        && WAKE_TRIGGER_STATE.0[queue_index as usize].load(Ordering::Acquire) != 0
    {
        spin_pause_or_yield(&mut spins);
    }
    stats::leave(Stat::EqueuePrivateSpinNow);
}

/// Triggers the queue's private user event outside the overlay lock, then
/// publishes (or drops) the reserved pending node under it.
fn execute_private_wake(req: &PrivateWakeRequest) -> PrivateWakeCompletion {
    let mut r = PrivateWakeCompletion::default();
    // udata is the TrackedEqueue slot address. Taken as a raw place, since
    // the overlay lock is not held here and a `&mut` to `queues` would alias
    // the lock holder's.
    let udata = unsafe { core::ptr::addr_of_mut!((*OV.get()).queues) }
        .cast::<TrackedEqueue>()
        .wrapping_add(req.queue_index as usize);
    r.rc = unsafe { sceKernelTriggerUserEvent(req.eq, req.wake_id as c_int, udata.cast()) };
    let g = overlay_lock();
    if req.queue_index < QUEUE_CAPACITY {
        let q = &mut unsafe { ov() }.queues[req.queue_index as usize];
        if q.used
            && q.lifetime_generation == req.queue_generation
            && private_wake_in_flight_locked(q)
        {
            q.wake_armed = r.rc == 0;
            if r.rc == 0 && req.pending_index < PENDING_CAPACITY {
                // A stale late packet is consumed, not sent to a replacement
                // native registration (old drain-time drop semantics).
                if unsafe { wake_registration_is_current_locked(req.queue_index, req) } {
                    unsafe { append_pending_locked(req.queue_index, req.pending_index) };
                } else {
                    unsafe { release_pending_locked(req.pending_index) };
                }
                r.publication_handled = true;
            } else if r.rc != 0 {
                // Trigger failures are permanent for this (equeue, id): keep
                // FIFO nodes drainable, route later publications natively.
                unsafe { ov() }.queues[req.queue_index as usize].wake_ready = false;
            }
            let q = &mut unsafe { ov() }.queues[req.queue_index as usize];
            q.wake_triggering = false;
            r.pending_count = q.pending_count;
        }
    }
    if req.pending_index < PENDING_CAPACITY && !r.publication_handled {
        unsafe { release_pending_locked(req.pending_index) };
    }
    if req.queue_index < QUEUE_CAPACITY {
        WAKE_TRIGGER_STATE.0[req.queue_index as usize].store(0, Ordering::Release);
    }
    drop(g);
    r
}

/// A replacement wake covers nodes already in the synthetic FIFO.
fn execute_replacement_wake(req: &PrivateWakeRequest) {
    let result = execute_private_wake(req);
    if result.rc == 0 || result.pending_count == 0 {
        return;
    }
    {
        let _g = overlay_lock();
        if req.queue_index >= QUEUE_CAPACITY {
            return;
        }
        let q = &mut unsafe { ov() }.queues[req.queue_index as usize];
        if !q.used
            || q.lifetime_generation != req.queue_generation
            || q.wake_id != req.wake_id
            || q.pending_count == 0
            || !kernel_waiters_locked(q)
        {
            return;
        }
        q.wake_registered = false;
    }
    if !attach_hidden_wake_unlocked(req.queue_index, req.queue_generation) {
        return;
    }
    let mut replacement = PrivateWakeRequest::DEFAULT;
    let retry = {
        let _g = overlay_lock();
        let q = &unsafe { ov() }.queues[req.queue_index as usize];
        q.used
            && q.lifetime_generation == req.queue_generation
            && q.pending_count != 0
            && kernel_waiters_locked(q)
            && unsafe {
                begin_private_wake_locked(req.queue_index, INVALID_INDEX, Some(&mut replacement))
            } == BeginPrivateWakeResult::Scheduled
    };
    if retry {
        let _ = execute_private_wake(&replacement);
    }
}

fn attach_hidden_wake_unlocked(queue_index: u32, queue_generation: u64) -> bool {
    let Some(add_edge) = original_add_user_event_edge() else {
        return false;
    };
    let qi = queue_index as usize;
    let live = |o: &Overlay| {
        queue_index < QUEUE_CAPACITY
            && o.queues[qi].used
            && o.queues[qi].lifetime_generation == queue_generation
    };
    for _ in 0..WAKE_ATTACH_ATTEMPTS {
        let (eq, candidate) = {
            let _g = overlay_lock();
            let o = unsafe { ov() };
            if !live(o) {
                return false;
            }
            if o.queues[qi].wake_registered {
                return true;
            }
            let mut candidate = o.next_wake_id;
            o.next_wake_id = o.next_wake_id.wrapping_add(1);
            if candidate < WAKE_ID_BASE || candidate == 0 || candidate > i32::MAX as u32 {
                o.next_wake_id = WAKE_ID_BASE + 1;
                candidate = WAKE_ID_BASE;
            }
            (o.queues[qi].eq, candidate)
        };
        let rc = unsafe { add_edge(eq, candidate as c_int) };
        if rc == 0 {
            let (mut committed, mut duplicate) = (false, false);
            {
                let _g = overlay_lock();
                let o = unsafe { ov() };
                if live(o) {
                    let q = &mut o.queues[qi];
                    if !q.wake_registered {
                        q.wake_id = candidate;
                        q.wake_registered = true;
                        q.wake_ready = true;
                        committed = true;
                    } else {
                        duplicate = true;
                    }
                }
            }
            if duplicate {
                unsafe { sceKernelDeleteUserEvent(eq, candidate as c_int) };
                return true;
            }
            return committed;
        }
        if rc != SCE_KERNEL_ERROR_EEXIST {
            return false;
        }
    }
    false
}

/// Frees the queue slot with all its registrations and pending nodes.
/// Returns true when the reactor should be told about freed pending capacity.
unsafe fn release_queue_locked(queue_index: u32) -> bool {
    let o = unsafe { ov() };
    let qi = queue_index as usize;
    if queue_index >= QUEUE_CAPACITY || !o.queues[qi].used {
        return false;
    }
    // Nodes first: each one is counted against its registration.
    while o.queues[qi].pending_head < PENDING_CAPACITY {
        let index = o.queues[qi].pending_head;
        o.queues[qi].pending_head = o.pending[index as usize].next;
        unsafe { release_pending_locked(index) };
    }
    while o.queues[qi].registration_head < REGISTRATION_CAPACITY {
        let index = o.queues[qi].registration_head;
        let ri = index as usize;
        o.queues[qi].registration_head = o.registrations[ri].next;
        unsafe {
            erase_registration_hash_locked(
                queue_index,
                o.registration_filters[ri],
                o.registrations[ri].id,
            )
        };
        o.registration_owners[ri] = 0;
        o.registration_filters[ri] = 0;
        o.registrations[ri] = MirroredRegistration {
            next: o.registration_free_head,
            ..MirroredRegistration::ZERO
        };
        o.registration_free_head = index;
        if o.live_registrations != 0 {
            o.live_registrations -= 1;
        }
    }
    let notify_reactor = unsafe { take_pending_backpressure_progress_locked() };
    let eq = o.queues[qi].eq;
    unsafe { erase_queue_hash_locked(eq) };
    TRACKED_IN_BUCKET[bypass_bucket(eq)].fetch_sub(1, Ordering::SeqCst);
    o.controls[qi] = QueueControlState::ZERO;
    o.queues[qi] = TrackedEqueue {
        next_free: o.queue_free_head,
        ..TrackedEqueue::ZERO
    };
    o.queue_free_head = queue_index;
    if o.live_queues != 0 {
        o.live_queues -= 1;
    }
    if o.live_queues == 0 {
        o.queue_hash.fill(0);
        o.queue_hash_tombstones = 0;
    } else if o.queue_hash_tombstones >= QUEUE_CAPACITY / 2 {
        unsafe { rebuild_queue_hash_locked() };
    }
    notify_reactor
}

fn release_native_wait_intent(queue_index: u32, queue_generation: u64) {
    let _g = overlay_lock();
    if queue_index >= QUEUE_CAPACITY {
        return;
    }
    let q = &mut unsafe { ov() }.queues[queue_index as usize];
    if q.used && q.lifetime_generation == queue_generation && q.native_wait_intent != 0 {
        q.native_wait_intent -= 1;
    }
}

// ---- native wait helpers ---------------------------------------------------

/// Drains pending synthetic events, or installs a native wait intent when
/// there are none. Waits out an in-flight private wake first.
fn prepare_native_wait(
    queue_index: u32,
    queue_generation: u64,
    events: *mut SceKernelEvent,
    num: c_int,
) -> NativeWaitTransition {
    loop {
        let mut r = NativeWaitTransition::default();
        {
            let _g = overlay_lock();
            let o = unsafe { ov() };
            if queue_index >= QUEUE_CAPACITY
                || !o.queues[queue_index as usize].used
                || o.queues[queue_index as usize].lifetime_generation != queue_generation
            {
                return r;
            }
            if !private_wake_in_flight_locked(&o.queues[queue_index as usize]) {
                r.synthetic_count = unsafe {
                    drain_pending_locked(queue_index, events, num, Some(&mut r.notify_reactor))
                };
                if r.synthetic_count == 0 {
                    unsafe { ov() }.queues[queue_index as usize].native_wait_intent += 1;
                    r.native_wait_intent_installed = true;
                }
                return r;
            }
        }
        wait_for_private_wake(queue_index);
    }
}

/// `token` is the `TrackedEqueue` slot address used as the wake's udata.
/// Matches any id from the private wake range rather than one captured at
/// wait entry, so a wake attached after the wait began is still hidden.
fn is_hidden_wake(event: &SceKernelEvent, token: *const TrackedEqueue) -> bool {
    is_private_wake_ident(event) && event.udata as *const TrackedEqueue == token
}

/// The filter and id range of every private wake (`attach_hidden_wake_unlocked`).
fn is_private_wake_ident(event: &SceKernelEvent) -> bool {
    event.filter == SCE_KERNEL_EVFILT_USER
        && (WAKE_ID_BASE..=i32::MAX as u32).contains(&(event.ident as u32))
}

fn remaining_timeout_us(d: &NativeWaitDeadline) -> SceKernelUseconds {
    if d.expires == 0 {
        return 0;
    }
    let max = u32::MAX as u64;
    let us = if d.counter_frequency != 0 {
        let now = unsafe { sceKernelGetProcessTimeCounter() };
        if now >= d.expires {
            return 0;
        }
        let ticks = d.expires - now;
        let f = d.counter_frequency;
        let whole = ticks / f;
        if whole > max / USECONDS_PER_SECOND {
            return u32::MAX;
        }
        let num = (ticks % f) * USECONDS_PER_SECOND;
        whole * USECONDS_PER_SECOND + num / f + (num % f != 0) as u64
    } else {
        let now = monotonic_ns();
        if now == 0 || now >= d.expires {
            return 0;
        }
        let ns = d.expires - now;
        ns / 1000 + (ns % 1000 != 0) as u64
    };
    us.min(max) as SceKernelUseconds
}

// ---- AMPR registration forwarding ------------------------------------------

use super::reactor::apr_reactor_notify_external_progress;

fn notify_reactor_progress() {
    unsafe { apr_reactor_notify_external_progress() };
}

/// Forwards the native add, then attaches the hidden wake and mirrors the
/// registration. With no wake or a full registration table the id stays
/// native only: a publish to it falls back to a native packet.
fn forward_ampr_registration_add(
    eq: SceKernelEqueue,
    filter: i16,
    id: c_int,
    udata: *mut c_void,
    call: impl FnOnce() -> c_int,
) -> c_int {
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) {
        return call();
    }
    let control = ControlLock::new();
    let t = begin_queue_control(eq, filter, id, true);
    let rc = call();
    if !t.ok() {
        return rc;
    }
    let mut wake_available = rc == 0;
    let mut bypass_wake = PrivateWakeRequest::DEFAULT;
    let mut exec_bypass_wake = false;
    // This add attached the queue's hidden wake: the first one that can
    // reach a direct waiter started before the queue was tracked.
    let mut attached = false;
    if rc == 0 {
        let needs_wake = {
            let _g = overlay_lock();
            unsafe { find_queue_control_locked(&t) }
                .is_some_and(|i| !unsafe { ov() }.queues[i as usize].wake_registered)
        };
        if needs_wake {
            wake_available = attach_hidden_wake_unlocked(t.queue_index, t.queue_generation);
            attached = wake_available;
        }
    }
    let mut notify_reactor = false;
    {
        let _g = overlay_lock();
        let Some(qidx) = (unsafe { find_queue_control_locked(&t) }) else {
            return rc;
        };
        let qi = qidx as usize;
        if rc == 0 && wake_available && unsafe { ov() }.queues[qi].wake_registered {
            unsafe {
                allocate_registration_locked(qidx, filter, id, udata, Some(&mut notify_reactor))
            };
            // A thread may be in a direct kernel wait on this queue, started
            // before it was tracked: no native intent, so a publish would
            // not wake it. Wake it once (the queue went tracked before this
            // load, SeqCst). Armed or in flight, the edge is already coming.
            // Further direct waiters are woken by later publishes and drains
            // (`kernel_waiters_locked`).
            if attached && BYPASS_WAITERS[bypass_bucket(eq)].load(Ordering::SeqCst) != 0 {
                exec_bypass_wake = unsafe {
                    begin_private_wake_locked(qidx, INVALID_INDEX, Some(&mut bypass_wake))
                } == BeginPrivateWakeResult::Scheduled;
            }
        }
        unsafe { finish_queue_control_locked(qidx) };
        // A failed first add (a stale or refused handle) gives its slot back,
        // so repeated failures cannot fill the table or keep the bucket off
        // the bypass.
        // One a tracked waiter already entered stays, so that waiter stays
        // counted in its native wait intent.
        let q = &unsafe { ov() }.queues[qi];
        if rc != 0 && t.fresh && q.registration_head >= REGISTRATION_CAPACITY && q.native_wait_intent == 0
        {
            notify_reactor |= unsafe { release_queue_locked(qidx) };
        }
    }
    // Outside the lifecycle lock, as in Delete: the trigger may enter
    // another queue hook, which waits for this wake to finish.
    drop(control);
    if exec_bypass_wake {
        let _ = execute_private_wake(&bypass_wake);
    }
    if notify_reactor {
        notify_reactor_progress();
    }
    rc
}

/// Forwards the native delete of an AMPR registration.
fn forward_ampr_registration_delete(
    eq: SceKernelEqueue,
    filter: i16,
    id: c_int,
    call: impl FnOnce() -> c_int,
) -> c_int {
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) {
        return call();
    }
    let _control = ControlLock::new();
    let t = begin_queue_control(eq, filter, id, false);
    let rc = call();
    if !t.ok() {
        return rc;
    }
    let mut notify_reactor = false;
    {
        let _g = overlay_lock();
        if let Some(qidx) = unsafe { find_queue_control_locked(&t) } {
            if rc == 0 {
                unsafe { remove_registration_locked(qidx, filter, id, Some(&mut notify_reactor)) };
            }
            unsafe { finish_queue_control_locked(qidx) };
        }
    }
    if notify_reactor {
        notify_reactor_progress();
    }
    rc
}

// ---- public overlay API ----------------------------------------------------

const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;

/// Queues a synthetic EVFILT_AMPR event on a mirrored registration.
pub unsafe fn apr_equeue_try_publish(
    eq: SceKernelEqueue,
    id: i32,
    data: u64,
) -> AprEqueuePublishResult {
    use AprEqueuePublishResult::*;
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) {
        return NativeFallback;
    }
    {
        let mut wake_request = PrivateWakeRequest::DEFAULT;
        let mut execute_wake = false;
        {
            let _g = overlay_lock();
            if !HOOKS_AVAILABLE.load(Ordering::Relaxed) {
                return NativeFallback;
            }
            let qidx = unsafe { find_queue_index_locked(eq) };
            if qidx >= QUEUE_CAPACITY {
                return NativeFallback;
            }
            let qi = qidx as usize;
            let o = unsafe { ov() };
            if unsafe {
                queue_control_conflicts_with_registration_locked(
                    qidx,
                    &o.queues[qi],
                    AMPR_EVENT_FILTER,
                    id,
                )
            } {
                return NativeFallback;
            } else if private_wake_in_flight_locked(&o.queues[qi]) {
                return Backpressure;
            } else {
                let ridx = unsafe { find_registration_locked(qidx, SCE_KERNEL_EVFILT_AMPR, id) };
                if ridx >= REGISTRATION_CAPACITY || !o.queues[qi].wake_ready {
                    return NativeFallback;
                }
                // Only a second unread event on this id can be refused: the
                // first always has its registration's node.
                let pidx = unsafe { allocate_pending_locked(ridx) };
                if pidx >= PENDING_CAPACITY {
                    o.pending_pool_backpressured = true;
                    return Backpressure;
                }
                let udata = o.registrations[ridx as usize].udata;
                let p = &mut o.pending[pidx as usize];
                p.ident = id as u32;
                p.data = data as isize;
                p.udata = udata;
                // A future waiter drains an already-pending event directly. A
                // waiter committed to the native call needs the private edge;
                // the reserved node is published by the wake completion.
                if kernel_waiters_locked(&o.queues[qi]) {
                    match unsafe { begin_private_wake_locked(qidx, pidx, Some(&mut wake_request)) }
                    {
                        BeginPrivateWakeResult::Scheduled => execute_wake = true,
                        BeginPrivateWakeResult::AlreadyArmed => unsafe {
                            append_pending_locked(qidx, pidx)
                        },
                        BeginPrivateWakeResult::Unavailable => {
                            unsafe { release_pending_locked(pidx) };
                            return NativeFallback;
                        }
                    }
                } else {
                    unsafe { append_pending_locked(qidx, pidx) };
                }
            }
        }
        if execute_wake && !execute_private_wake(&wake_request).publication_handled {
            return NativeFallback;
        }
    }
    Published
}

/// Turns queue tracking on or off. On needs ids 50..=54 (create, wait,
/// delete, AMPR add and delete; rt/hook.rs `refresh`): an untracked queue
/// gets AMPR events from the kernel, which merges two of one id before the
/// game reads them (a save load hung that way).
pub unsafe fn apr_equeue_overlay_set_hook_availability(hooks_available: bool) {
    let _g = overlay_lock();
    HOOKS_AVAILABLE.store(hooks_available, Ordering::Release);
}

pub unsafe fn apr_equeue_overlay_shutdown() {
    unsafe { apr_equeue_overlay_set_hook_availability(false) };
    let _control = ControlLock::new();
    {
        let _g = overlay_lock();
        let o = unsafe { ov() };
        if !o.initialized {
            return;
        }
        // Keep in-flight hooks from finding or reusing a slot while private
        // wake syscalls run unlocked.
        o.initialized = false;
    }
    let mut notify_reactor = false;
    let mut qi = 0u32;
    loop {
        let (mut wake_eq, mut wake_id, mut delete_wake, mut wait_wake) =
            (core::ptr::null_mut(), 0, false, false);
        {
            let _g = overlay_lock();
            let o = unsafe { ov() };
            while qi < QUEUE_CAPACITY && !o.queues[qi as usize].used {
                qi += 1;
            }
            if qi >= QUEUE_CAPACITY {
                break;
            }
            let q = o.queues[qi as usize];
            if private_wake_in_flight_locked(&q) {
                wait_wake = true;
            } else {
                wake_eq = q.eq;
                wake_id = q.wake_id;
                delete_wake = q.wake_registered;
                notify_reactor |= unsafe { release_queue_locked(qi) };
                qi += 1;
            }
        }
        if wait_wake {
            wait_for_private_wake(qi);
            continue;
        }
        if delete_wake {
            unsafe { sceKernelDeleteUserEvent(wake_eq, wake_id as c_int) };
        }
    }
    if notify_reactor {
        notify_reactor_progress();
    }
}

// ---- hook targets ----------------------------------------------------------

pub unsafe extern "C" fn sceKernelCreateEqueue_emul(
    eq: *mut SceKernelEqueue,
    name: *const c_char,
) -> c_int {
    let Some(original) = original_create_equeue() else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) {
        return unsafe { original(eq, name) };
    }
    let mut control = ControlLock::new();
    let rc = unsafe { original(eq, name) };
    if rc == 0 && !eq.is_null() && !unsafe { *eq }.is_null() {
        let e = unsafe { *eq };
        let mut notify_reactor = false;
        loop {
            let mut wait_qi = INVALID_INDEX;
            {
                let _g = overlay_lock();
                if HOOKS_AVAILABLE.load(Ordering::Relaxed) {
                    // The kernel just handed out `e`: a tracked entry with this
                    // handle is a queue closed without the Delete hook.
                    let stale = unsafe { find_queue_index_locked(e) };
                    // The new queue stays untracked until its first AMPR add.
                    if stale < QUEUE_CAPACITY {
                        if private_wake_in_flight_locked(&unsafe { ov() }.queues[stale as usize]) {
                            wait_qi = stale;
                        } else {
                            notify_reactor |= unsafe { release_queue_locked(stale) };
                        }
                    }
                }
            }
            if wait_qi >= QUEUE_CAPACITY {
                break;
            }
            // As in Delete: do not hold the lifecycle mutex while the trigger
            // owner completes.
            drop(control);
            wait_for_private_wake(wait_qi);
            control = ControlLock::new();
        }
        if notify_reactor {
            notify_reactor_progress();
        }
    }
    drop(control);
    rc
}

pub unsafe extern "C" fn sceKernelAddAmprEvent_emul(
    eq: SceKernelEqueue,
    id: c_int,
    udata: *mut c_void,
) -> c_int {
    match original_add_ampr_event() {
        Some(f) => {
            forward_ampr_registration_add(eq, SCE_KERNEL_EVFILT_AMPR, id, udata, || unsafe {
                f(eq, id, udata)
            })
        }
        None => SCE_KERNEL_ERROR_ENOSYS,
    }
}

pub unsafe extern "C" fn sceKernelDeleteAmprEvent_emul(eq: SceKernelEqueue, id: c_int) -> c_int {
    match original_delete_ampr_event() {
        Some(f) => forward_ampr_registration_delete(eq, SCE_KERNEL_EVFILT_AMPR, id, || unsafe {
            f(eq, id)
        }),
        None => SCE_KERNEL_ERROR_ENOSYS,
    }
}

pub unsafe extern "C" fn sceKernelDeleteEqueue_emul(eq: SceKernelEqueue) -> c_int {
    let Some(original) = original_delete_equeue() else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) {
        return unsafe { original(eq) };
    }
    loop {
        let mut wait_qi = INVALID_INDEX;
        {
            let _control = ControlLock::new();
            let mut t = QueueControlTransaction::DEFAULT;
            let mut forward_direct = false;
            {
                let _g = overlay_lock();
                let qidx = if HOOKS_AVAILABLE.load(Ordering::Relaxed) {
                    unsafe { find_queue_index_locked(eq) }
                } else {
                    INVALID_INDEX
                };
                if qidx >= QUEUE_CAPACITY {
                    forward_direct = true;
                } else {
                    let o = unsafe { ov() };
                    let qi = qidx as usize;
                    if private_wake_in_flight_locked(&o.queues[qi]) {
                        wait_qi = qidx;
                    } else {
                        let q = &mut o.queues[qi];
                        t.queue_index = qidx;
                        t.queue_generation = q.lifetime_generation;
                        o.controls[qi].scope = QueueControlScope::WholeQueue;
                        q.control_depth += 1;
                    }
                }
            }
            if wait_qi >= QUEUE_CAPACITY {
                if forward_direct {
                    return unsafe { original(eq) };
                }
                let rc = unsafe { original(eq) };
                let mut notify_reactor = false;
                {
                    let _g = overlay_lock();
                    if let Some(qidx) = unsafe { find_queue_control_locked(&t) } {
                        if rc == 0 {
                            // The real deletion already removed the private EVFILT_USER.
                            notify_reactor = unsafe { release_queue_locked(qidx) };
                        } else {
                            unsafe { finish_queue_control_locked(qidx) };
                        }
                    }
                }
                if notify_reactor {
                    notify_reactor_progress();
                }
                return rc;
            }
        }
        // Do not hold the lifecycle mutex while the trigger owner completes:
        // its libkernel call may synchronously enter another lifecycle hook.
        wait_for_private_wake(wait_qi);
    }
}

pub unsafe extern "C" fn sceKernelWaitEqueue_emul(
    eq: SceKernelEqueue,
    events: *mut SceKernelEvent,
    num: c_int,
    out: *mut c_int,
    timeout: *mut SceKernelUseconds,
) -> c_int {
    use super::stats::{self, Stat};
    stats::enter(Stat::EqueueWaitNow);
    #[cfg(feature = "mem_report")]
    let slot = wait_table_enter(eq, timeout);
    let rc = unsafe { wait_equeue(eq, events, num, out, timeout) };
    #[cfg(feature = "mem_report")]
    wait_table_leave(slot);
    stats::leave(Stat::EqueueWaitNow);
    rc
}

// ---- debug wait table ----

/// Debug /metrics (rt/exports.rs): the sceKernelWaitEqueue calls in progress
/// and the overlay's state of their queue, plus every tracked queue holding
/// pending events. A tracked queue with pending events and a waiter in the
/// native call is an event published locally and never delivered.
#[cfg(feature = "mem_report")]
const WAIT_TABLE: usize = 32;
#[cfg(feature = "mem_report")]
use core::sync::atomic::AtomicUsize;
#[cfg(feature = "mem_report")]
static WAIT_EQ: [AtomicUsize; WAIT_TABLE] = [const { AtomicUsize::new(0) }; WAIT_TABLE];
#[cfg(feature = "mem_report")]
static WAIT_START_NS: [AtomicU64; WAIT_TABLE] = [const { AtomicU64::new(0) }; WAIT_TABLE];
/// Timeout in us, u64::MAX for none.
#[cfg(feature = "mem_report")]
static WAIT_TIMEOUT_US: [AtomicU64; WAIT_TABLE] = [const { AtomicU64::new(0) }; WAIT_TABLE];

#[cfg(feature = "mem_report")]
fn wait_table_enter(eq: SceKernelEqueue, timeout: *mut SceKernelUseconds) -> usize {
    for i in 0..WAIT_TABLE {
        // Handle + 1, so a null eq still marks the slot used. Not `| 1`:
        // a handle may be a small fd, and an odd one would read back as its
        // even neighbour.
        let tagged = (eq as usize).wrapping_add(1);
        if WAIT_EQ[i]
            .compare_exchange(0, tagged, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            WAIT_START_NS[i].store(super::services::time_counter_now(), Ordering::Relaxed);
            let t = if timeout.is_null() {
                u64::MAX
            } else {
                unsafe { *timeout as u64 }
            };
            WAIT_TIMEOUT_US[i].store(t, Ordering::Relaxed);
            // Republish so a reader that sees the slot sees the fields above.
            WAIT_EQ[i].store(tagged, Ordering::Release);
            return i;
        }
    }
    WAIT_TABLE
}

#[cfg(feature = "mem_report")]
fn wait_table_leave(slot: usize) {
    if slot < WAIT_TABLE {
        WAIT_EQ[slot].store(0, Ordering::Release);
    }
}

#[cfg(feature = "mem_report")]
#[derive(Clone, Copy, Default)]
pub(crate) struct EqueueView {
    /// False for a tracked queue listed for its pending events alone.
    pub(crate) waiting: bool,
    pub(crate) eq: usize,
    pub(crate) timeout_us: u64,
    pub(crate) age_ms: u64,
    pub(crate) tracked: bool,
    pub(crate) pending: u32,
    pub(crate) registrations: u32,
    pub(crate) native_intent: u32,
    pub(crate) trigger: u8,
    /// Bits: 8 wake ready, 16 wake armed, 32 wake triggering, 64 wake
    /// registered. 1, 2 and 4 held the removed queue classification and stay
    /// unused, so readings from older builds compare.
    pub(crate) flags: u32,
}

#[cfg(feature = "mem_report")]
unsafe fn fill_queue_view(v: &mut EqueueView, qidx: u32) {
    let o = unsafe { ov() };
    let q = &o.queues[qidx as usize];
    v.tracked = true;
    v.pending = q.pending_count;
    v.native_intent = q.native_wait_intent;
    v.trigger = WAKE_TRIGGER_STATE.0[qidx as usize].load(Ordering::Relaxed);
    v.flags = (q.wake_ready as u32) << 3
        | (q.wake_armed as u32) << 4
        | (q.wake_triggering as u32) << 5
        | (q.wake_registered as u32) << 6;
    let mut r = q.registration_head;
    let mut n = 0;
    while r < REGISTRATION_CAPACITY && n < REGISTRATION_CAPACITY {
        n += 1;
        r = o.registrations[r as usize].next;
    }
    v.registrations = n;
}

/// Debug: the live peaks and, in the same order, the table capacities.
#[cfg(feature = "mem_report")]
pub(crate) fn equeue_peaks() -> (Peaks, Peaks) {
    let _g = overlay_lock();
    let caps = Peaks {
        queues: QUEUE_CAPACITY,
        registrations: REGISTRATION_CAPACITY,
        pending: PENDING_CAPACITY,
        extras: PENDING_EXTRA_CAPACITY,
    };
    (unsafe { ov() }.peaks, caps)
}

/// Waits in progress, then tracked queues with pending events and no
/// waiter listed; returns how many views are filled.
#[cfg(feature = "mem_report")]
pub(crate) fn equeue_views(out: &mut [EqueueView; 48]) -> usize {
    let now = super::services::time_counter_now();
    let mut n = 0;
    let _g = overlay_lock();
    for i in 0..WAIT_TABLE {
        let tagged = WAIT_EQ[i].load(Ordering::Acquire);
        if tagged == 0 || n == out.len() {
            continue;
        }
        let eq = tagged.wrapping_sub(1);
        let mut v = EqueueView {
            waiting: true,
            eq,
            timeout_us: WAIT_TIMEOUT_US[i].load(Ordering::Relaxed),
            age_ms: now.saturating_sub(WAIT_START_NS[i].load(Ordering::Relaxed)) / 1_000_000,
            ..EqueueView::default()
        };
        let qidx = unsafe { find_queue_index_locked(eq as SceKernelEqueue) };
        if qidx < QUEUE_CAPACITY {
            unsafe { fill_queue_view(&mut v, qidx) };
        }
        out[n] = v;
        n += 1;
    }
    let o = unsafe { ov() };
    if !o.initialized {
        return n;
    }
    for qidx in 0..QUEUE_CAPACITY {
        let q = &o.queues[qidx as usize];
        if !q.used || q.pending_count == 0 || n == out.len() {
            continue;
        }
        if out[..n].iter().any(|v| v.eq == q.eq as usize) {
            continue;
        }
        let mut v = EqueueView {
            eq: q.eq as usize,
            ..EqueueView::default()
        };
        unsafe { fill_queue_view(&mut v, qidx) };
        out[n] = v;
        n += 1;
    }
    n
}

// ---- untracked bypass ------------------------------------------------------

enum Bypass {
    /// The kernel's answer, for the game.
    Done(c_int),
    /// A tracked queue shares the bucket: take the overlay path.
    Locked,
    /// Only stray private wakes came back; the timeout left, in us.
    Retry(SceKernelUseconds),
}

/// A wait on a queue that shares no bucket with a tracked one goes straight
/// to the kernel, without the overlay lock.
#[inline(always)]
unsafe fn bypass_wait(
    original: WaitEqueueFn,
    eq: SceKernelEqueue,
    events: *mut SceKernelEvent,
    num: c_int,
    out: *mut c_int,
    timeout: *mut SceKernelUseconds,
) -> Bypass {
    let b = bypass_bucket(eq);
    if TRACKED_IN_BUCKET[b].load(Ordering::Relaxed) != 0 {
        return Bypass::Locked;
    }
    // Count, then read: with the SeqCst add and load in
    // `forward_ampr_registration_add` either this sees the queue tracked or
    // the add sees this waiter and wakes the queue.
    BYPASS_WAITERS[b].fetch_add(1, Ordering::SeqCst);
    if TRACKED_IN_BUCKET[b].load(Ordering::SeqCst) != 0 {
        BYPASS_WAITERS[b].fetch_sub(1, Ordering::Release);
        return Bypass::Locked;
    }
    unsafe { direct_wait(original, b, eq, events, num, out, timeout) }
}

/// The kernel wait of an untracked queue, counted in `BYPASS_WAITERS[b]` by
/// the caller (`bypass_wait`, or `wait_equeue` under the overlay lock when
/// the queue's bucket holds a tracked one). A private wake in its answer
/// means the queue was tracked during the wait (its first AMPR add or a
/// publish woke it): it is dropped and disarmed, and the caller waits again
/// through the overlay when nothing else came back.
#[inline(always)]
unsafe fn direct_wait(
    original: WaitEqueueFn,
    b: usize,
    eq: SceKernelEqueue,
    events: *mut SceKernelEvent,
    num: c_int,
    out: *mut c_int,
    timeout: *mut SceKernelUseconds,
) -> Bypass {
    let deadline = match unsafe { timeout.as_ref() } {
        Some(&t) if t != 0 => make_native_wait_deadline(
            t,
            PROCESS_TIME_COUNTER_FREQUENCY.load(Ordering::Relaxed),
        ),
        _ => NativeWaitDeadline::default(),
    };
    let rc = unsafe { original(eq, events, num, out, timeout) };
    BYPASS_WAITERS[b].fetch_sub(1, Ordering::Release);
    // The count only once the kernel succeeded: a failed wait need not
    // write it.
    if rc != 0 {
        return Bypass::Done(rc);
    }
    let n = unsafe { *out };
    if n <= 0 || n > num {
        return Bypass::Done(rc);
    }
    let mut real: c_int = 0;
    let mut stray = None;
    for i in 0..n {
        let ev = unsafe { *events.add(i as usize) };
        if let Some(qi) = stray_wake_slot(&ev) {
            stray = Some(qi);
            continue;
        }
        if real != i {
            unsafe { *events.add(real as usize) = ev };
        }
        real += 1;
    }
    if let Some(qi) = stray {
        disarm_stray_wake(qi, eq, real != 0);
    }
    // A timeout after a stray wake must not report the dropped event.
    unsafe { *out = real };
    if real != 0 {
        return Bypass::Done(0);
    }
    Bypass::Retry(remaining_timeout_us(&deadline))
}

/// The slot of a private wake (`execute_private_wake` sets udata to the
/// `TrackedEqueue` slot address), for a waiter that has no token.
fn stray_wake_slot(ev: &SceKernelEvent) -> Option<usize> {
    if !is_private_wake_ident(ev) {
        return None;
    }
    let base = unsafe { core::ptr::addr_of!((*OV.get()).queues) } as usize;
    let off = (ev.udata as usize).wrapping_sub(base);
    let size = core::mem::size_of::<TrackedEqueue>();
    (off % size == 0 && off / size < QCAP).then_some(off / size)
}

/// The edge was consumed outside the overlay: clear `wake_armed`, as the
/// tracked path does on a hidden wake, or later publishes would see it armed
/// and never trigger it again. `rewake` (this waiter returns without
/// draining): a tracked waiter still in the kernel gets a new edge for the
/// pending events, as after a tracked drain.
#[cold]
fn disarm_stray_wake(qi: usize, eq: SceKernelEqueue, rewake: bool) {
    let mut req = PrivateWakeRequest::DEFAULT;
    loop {
        {
            let _g = overlay_lock();
            let q = &mut unsafe { ov() }.queues[qi];
            if !private_wake_in_flight_locked(q) {
                if !q.used || q.eq != eq {
                    return;
                }
                q.wake_armed = false;
                if !(rewake && q.pending_count != 0 && kernel_waiters_locked(q))
                    || unsafe { begin_private_wake_locked(qi as u32, INVALID_INDEX, Some(&mut req)) }
                        != BeginPrivateWakeResult::Scheduled
                {
                    return;
                }
                break;
            }
        }
        wait_for_private_wake(qi as u32);
    }
    execute_replacement_wake(&req);
}

/// `sceKernelWaitEqueue_emul` without the debug gauge.
unsafe fn wait_equeue(
    eq: SceKernelEqueue,
    events: *mut SceKernelEvent,
    num: c_int,
    out: *mut c_int,
    timeout: *mut SceKernelUseconds,
) -> c_int {
    let Some(original) = original_wait_equeue() else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    // Untracked or invalid calls keep libkernel's exact validation behavior.
    if !HOOKS_AVAILABLE.load(Ordering::Acquire) || events.is_null() || out.is_null() || num <= 0 {
        return unsafe { original(eq, events, num, out, timeout) };
    }
    let mut timeout = timeout;
    let mut retry_timeout: SceKernelUseconds;
    let mut direct = unsafe { bypass_wait(original, eq, events, num, out, timeout) };
    let mut tracked_qi = INVALID_INDEX;
    let mut queue_generation = 0u64;
    let mut counter_frequency = 0u64;
    let mut wake_token: *const TrackedEqueue = core::ptr::null();
    let mut native_intent = false;
    loop {
        match direct {
            Bypass::Done(rc) => return rc,
            Bypass::Locked => {}
            Bypass::Retry(left) => {
                // Only the stray wake came back: wait out the rest through
                // the overlay. A poll (0) or a spent timeout still drains
                // once, since the publish that woke it may be pending; with
                // nothing pending its native poll times out.
                if !timeout.is_null() {
                    retry_timeout = left;
                    timeout = &mut retry_timeout;
                }
            }
        }
        direct = Bypass::Locked;
        let mut tracked = false;
        let mut notify_reactor = false;
        let mut replacement = PrivateWakeRequest::DEFAULT;
        let mut exec_replacement = false;
        let mut wait_qi = INVALID_INDEX;
        {
            let _g = overlay_lock();
            let qidx = unsafe { find_queue_index_locked(eq) };
            if qidx < QUEUE_CAPACITY {
                let qi = qidx as usize;
                let o = unsafe { ov() };
                if private_wake_in_flight_locked(&o.queues[qi]) {
                    wait_qi = qidx;
                } else {
                    tracked = true;
                    tracked_qi = qidx;
                    queue_generation = o.queues[qi].lifetime_generation;
                    counter_frequency = PROCESS_TIME_COUNTER_FREQUENCY.load(Ordering::Relaxed);
                    wake_token = o.queues.as_ptr().wrapping_add(qi);
                    unsafe { *out = 0 };
                    let synthetic = unsafe {
                        drain_pending_locked(qidx, events, num, Some(&mut notify_reactor))
                    };
                    let q = &unsafe { ov() }.queues[qi];
                    if synthetic != 0 {
                        unsafe { *out = synthetic };
                        if q.pending_count != 0 && kernel_waiters_locked(q) {
                            exec_replacement = unsafe {
                                begin_private_wake_locked(
                                    qidx,
                                    INVALID_INDEX,
                                    Some(&mut replacement),
                                )
                            } == BeginPrivateWakeResult::Scheduled;
                        }
                    } else {
                        unsafe { ov() }.queues[qi].native_wait_intent += 1;
                        native_intent = true;
                    }
                }
            } else {
                // Untracked, in a bucket a tracked queue shares: count the
                // direct wait under the lock, so a first AMPR add that
                // tracks this queue afterwards sees it and wakes it.
                BYPASS_WAITERS[bypass_bucket(eq)].fetch_add(1, Ordering::SeqCst);
            }
        }
        if wait_qi != INVALID_INDEX {
            wait_for_private_wake(wait_qi);
            continue;
        }
        if exec_replacement {
            execute_replacement_wake(&replacement);
        }
        if !tracked {
            let b = bypass_bucket(eq);
            direct = unsafe { direct_wait(original, b, eq, events, num, out, timeout) };
            continue;
        }
        if unsafe { *out } != 0 {
            if notify_reactor {
                notify_reactor_progress();
            }
            return 0;
        }
        break;
    }
    let requested = if timeout.is_null() {
        0
    } else {
        unsafe { *timeout }
    };
    unsafe {
        native_wait_loop(
            original,
            eq,
            events,
            num,
            out,
            timeout,
            requested,
            counter_frequency,
            tracked_qi,
            queue_generation,
            wake_token,
            native_intent,
        )
    }
}

/// Second half of `sceKernelWaitEqueue_emul`: native waits on a tracked queue,
/// filtering the hidden wake and appending synthetic events after real ones.
#[allow(clippy::too_many_arguments)]
unsafe fn native_wait_loop(
    original: WaitEqueueFn,
    eq: SceKernelEqueue,
    events: *mut SceKernelEvent,
    num: c_int,
    out: *mut c_int,
    timeout: *mut SceKernelUseconds,
    requested: SceKernelUseconds,
    counter_frequency: u64,
    tracked_qi: u32,
    queue_generation: u64,
    wake_token: *const TrackedEqueue,
    mut native_intent: bool,
) -> c_int {
    let mut deadline = NativeWaitDeadline::default();
    if !timeout.is_null() && requested != 0 {
        deadline = make_native_wait_deadline(requested, counter_frequency);
    }
    let mut first = true;
    let mut attempted = false;
    loop {
        if !native_intent {
            let tr = prepare_native_wait(tracked_qi, queue_generation, events, num);
            native_intent = tr.native_wait_intent_installed;
            if tr.notify_reactor {
                notify_reactor_progress();
            }
            if tr.synthetic_count != 0 {
                unsafe { *out = tr.synthetic_count };
                return 0;
            }
        }
        let mut local_timeout: SceKernelUseconds;
        let mut local_timeout_ptr: *mut SceKernelUseconds = core::ptr::null_mut();
        if !timeout.is_null() {
            local_timeout = if first || deadline.expires == 0 {
                requested
            } else {
                remaining_timeout_us(&deadline)
            };
            if !first && local_timeout == 0 && attempted {
                if native_intent {
                    release_native_wait_intent(tracked_qi, queue_generation);
                }
                return SCE_KERNEL_ERROR_ETIMEDOUT;
            }
            local_timeout_ptr = &mut local_timeout;
        }
        first = false;
        let mut native_count: c_int = 0;
        attempted = true;
        let rc = unsafe { original(eq, events, num, &mut native_count, local_timeout_ptr) };
        if native_intent {
            release_native_wait_intent(tracked_qi, queue_generation);
            native_intent = false;
        }
        if rc != 0 {
            return rc;
        }
        if native_count < 0 || native_count > num {
            return SCE_KERNEL_ERROR_EIO;
        }
        let mut real: c_int = 0;
        let mut saw_hidden = false;
        for i in 0..native_count {
            let ev = unsafe { *events.add(i as usize) };
            if is_hidden_wake(&ev, wake_token) {
                saw_hidden = true;
                continue;
            }
            if real != i {
                unsafe { *events.add(real as usize) = ev };
            }
            real += 1;
        }
        let mut synthetic: c_int = 0;
        let mut notify_reactor = false;
        let mut replacement = PrivateWakeRequest::DEFAULT;
        let mut exec_replacement = false;
        loop {
            {
                let _g = overlay_lock();
                let o = unsafe { ov() };
                let qi = tracked_qi as usize;
                if tracked_qi >= QUEUE_CAPACITY
                    || !o.queues[qi].used
                    || o.queues[qi].lifetime_generation != queue_generation
                {
                    break;
                }
                if !private_wake_in_flight_locked(&o.queues[qi]) {
                    if saw_hidden {
                        o.queues[qi].wake_armed = false;
                    }
                    synthetic = unsafe {
                        drain_pending_locked(
                            tracked_qi,
                            events.add(real as usize),
                            num - real,
                            Some(&mut notify_reactor),
                        )
                    };
                    let q = &unsafe { ov() }.queues[qi];
                    if q.pending_count != 0 && kernel_waiters_locked(q) {
                        exec_replacement = unsafe {
                            begin_private_wake_locked(
                                tracked_qi,
                                INVALID_INDEX,
                                Some(&mut replacement),
                            )
                        } == BeginPrivateWakeResult::Scheduled;
                    }
                    break;
                }
            }
            wait_for_private_wake(tracked_qi);
        }
        if exec_replacement {
            execute_replacement_wake(&replacement);
        }
        if notify_reactor {
            notify_reactor_progress();
        }
        let total = real + synthetic;
        if total != 0 {
            unsafe { *out = total };
            return 0;
        }
        // A stale private edge is invisible to the application: loop for one
        // locked drain/intent transition and a timeout from the same deadline.
    }
}
