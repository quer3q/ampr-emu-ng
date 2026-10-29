//! APR AIO reactor.
//!
//! This file holds the shared items of the reactor: data layouts, constants,
//! global state and pools. Function bodies live in role-named part files.
//!
//! Conventions for parts:
//! - Free functions are `pub(crate) fn`, so the glob re-exports below make
//!   them visible to every part.
//! - Reactor methods are `pub(crate)` `impl` methods; impl blocks may be split
//!   across part files. Methods without a receiver are associated fns
//!   (`AprAioReactor::name` / `Self::name`). Methods of helper types go on
//!   that type (e.g. `ActiveReadList`, `ReadIssueBudget`,
//!   `DirectReadSubmitOutcome`).
//! - Reactor constants, helper types and field names are camelCase
//!   module-level items, so parts call each other by name without
//!   coordination.
//! - Variants of one function with different args get a suffix: `_const` for
//!   a `&self` variant, otherwise `_2`, `_3`.
//! - `AprAioReactor::construct(this: *mut Self)` (worker.rs) builds the reactor in
//!   place; it must call `AprAioReactor::init_members(this)` (below) first.
//! - By-reference params are `&mut T` / `&T`; `JobPtr` stays a raw pointer.
//! - There is no logging, telemetry counters or log-summary code.
//!   `abort()` terminates the process.
#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

mod helpers;
pub(crate) use helpers::*;
mod submit;
pub(crate) use submit::*;
mod external;
mod pools;
mod poll_deadline;
mod setup;
mod job_state;
mod idle;
mod limits;
mod backoff;
mod read_window;
mod admission;
mod flush;
mod software;
mod batch_buffer;
mod native;
mod progress;
mod capacity;
mod worker;
pub(crate) use worker::{
    apr_reactor_notify_external_progress, apr_reactor_shutdown, apr_reactor_submit,
    apr_reactor_submit_external_aio_read, apr_reactor_submit_external_aio_read_group,
    apr_reactor_wait_synthetic_submit_id,
};
mod pread_pool;

pub(crate) use super::sync::{Condvar, Mutex, MutexGuard, SpinLock, SyncCell};
pub(crate) use super::sys::*;
pub(crate) use core::ffi::{c_char, c_int, c_uint, c_void};
pub(crate) use core::mem::{align_of, offset_of, size_of, MaybeUninit};
pub(crate) use core::ptr::{self, addr_of, addr_of_mut, null, null_mut};
pub(crate) use core::sync::atomic::{
    fence, AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

// ---- config (values as built) ---------------------------------------------

pub(crate) const AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS: u64 = 10_000;
pub(crate) const AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_DELAY_NS: u64 = 10_000_000;
pub(crate) const AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT: u32 = 64;
pub(crate) const AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT: usize = 4;
pub(crate) const AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS: u64 = 100_000;
pub(crate) const AMPR_EMU_APR_AIO_COMPLETION_RETRY_DELAY_NS: u64 = 1_000_000;
pub(crate) const AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT: u32 = 64;
pub(crate) const AMPR_EMU_APR_AIO_DELETE_RETRY_LIMIT: u32 = 4096;
pub(crate) const AMPR_EMU_APR_AIO_DELETE_TIMEOUT_NS: u64 = 5_000_000_000;
pub(crate) const AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES: u32 = 0x80000;
pub(crate) const AMPR_EMU_APR_AIO_INFLIGHT: u32 = 32;
pub(crate) const AMPR_EMU_APR_AIO_LATENCY_ESCAPE_SLOTS: u32 = 4;
pub(crate) const AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS: u32 = 250_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS: u32 = 1_000_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS: u32 = 10_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS: u32 = 250_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS: u32 = 500_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS: u32 = 100_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS: u32 = 50_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS: u64 = 10_000_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS: u32 = 500_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS: u32 = 50_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS: u64 = 100_000_000;
pub(crate) const AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS: u32 = 5_000_000;
pub(crate) const AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT: c_int = 128;
pub(crate) const AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE: c_int = 128;
pub(crate) const AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS: u64 = 500;
pub(crate) const AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS: u64 =
    AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS;
pub(crate) const AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS: u64 = 250;
pub(crate) const AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT: u32 = 64;
pub(crate) const AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES: u64 = 0x10000;
pub(crate) const AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS: u64 = 50;
pub(crate) const AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT: u32 = 75;
pub(crate) const AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS: u64 = 50_000;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS: u64 = 1000;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT: u32 = 8;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS: u64 = 250;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT: u32 = 24;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS: u64 = 100;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS: u64 = 50;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS: u64 = 250;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS: u64 = 500;
pub(crate) const AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT: u32 = 16;
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_BALANCED_BACKOFF_MAX_NS: u32 = 200_000;
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_BALANCED_INITIAL_NS: u32 = 50_000;
/// Pack backing reads (internal SSD) complete in ~1 ms; a slower schedule
/// (bulk: first poll >= 250 us, cap 1 ms) noticed them ~750 us late.
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_BULK_INITIAL_NS: u32 = 50_000;
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_BULK_BACKOFF_MAX_NS: u32 = 200_000;
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_LATENCY_BACKOFF_MAX_NS: u32 = 100_000;
pub(crate) const AMPR_EMU_APR_EXTERNAL_AIO_POLL_LATENCY_INITIAL_NS: u32 = 50_000;
pub(crate) const AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS: u64 = 2000;
pub(crate) const AMPR_EMU_APR_GROUP_SOFT_TARGETS: bool = true;
pub(crate) const AMPR_EMU_APR_LOCAL_EQUEUE: bool = true;
pub(crate) const AMPR_EMU_APR_PER_READ_ACTIVE_BYTES: u64 = 0x200000;
pub(crate) const AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS: u32 = 4;
pub(crate) const AMPR_EMU_APR_REACTOR_THREAD_AFFINITY: u64 = 0x3f;
pub(crate) const AMPR_EMU_APR_REACTOR_THREAD_PRIORITY: c_int = 256;
pub(crate) const AMPR_EMU_APR_READ_CHUNK_QUANTUM: u32 = 8;
pub(crate) const AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES: u64 = 0x10000;
pub(crate) const AMPR_EMU_APR_READ_PASS_MAX_BYTES: u64 = 0x80000;
/// Blocking pread pool for the pack's physical reads (pread_pool.rs). Kernel AIO on BFS
/// serves 1-2 requests at a time; 32 parallel preads reached 1.6-2.0 GB/s on
/// the console (2026-10-25 bench). Release: one thread per pipeline (16; the
/// console peak was 1.9 busy, 8 queued). The debug build has room for 32 and
/// starts `tune::pread_threads()`.
pub(crate) const AMPR_EMU_PACK_PREAD_WORKERS: usize = if crate::rt::tune::ON {
    32
} else {
    crate::rt::tune::RELEASE_PREAD_THREADS as usize
};
pub(crate) const AMPR_EMU_PACK_PREAD_TASKS: usize = 128;
pub(crate) const AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX: usize = 4096;
pub(crate) const AMPR_EMU_FD_OPEN_BUDGET_CAP: usize = 50;
pub(crate) const AMPR_EMU_FD_CACHE_CAP: usize = 45; // min(50, max(50*90/100, 1))
pub(crate) const AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS: u64 = 10_000_000_000;
pub(crate) const AMPR_EMU_FD_CACHE_IDLE_SCAN_NS: u64 = 250_000_000;
pub(crate) const AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT: c_uint = 100;
pub(crate) const AMPR_EMU_FD_DIRECT_CAP_PRESSURE_PERCENT: usize = 60;
pub(crate) const AMPR_EMU_FD_DIRECT_CAP_RESERVE: usize = 12;
pub(crate) const AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE: usize = 6;
pub(crate) const AMPR_EMU_LOOSE_COALESCE_MAX_BYTES: u64 = 0x80000;
pub(crate) const AMPR_EMU_LOOSE_COALESCE_MAX_COMMANDS: u32 = 8;
pub(crate) const AMPR_EMU_LOOSE_GS_COALESCE_MAX_BYTES: u64 = AMPR_EMU_LOOSE_COALESCE_MAX_BYTES;
pub(crate) const AMPR_EMU_LOOSE_GS_COALESCE_MAX_COMMANDS: u32 =
    AMPR_EMU_LOOSE_COALESCE_MAX_COMMANDS;
/// Base cap of the fd open budget.
pub(crate) const kFdOpenBudgetBaseCap: usize = AMPR_EMU_FD_OPEN_BUDGET_CAP;
/// Maximum number of live APR command buffers.
pub(crate) const kAprCommandBufferLiveMax: usize = AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX;

// ---- SDK AIO / pthread ------------------------------------------------------

pub(crate) type SceKernelAioSubmitId = c_int;
pub(crate) type ScePthread = *mut c_void;
pub(crate) type ScePthreadAttr = *mut c_void;
pub(crate) type SceKernelCpumask = u64;

pub(crate) const SCE_KERNEL_AIO_PRIORITY_LOW: c_int = 1;
pub(crate) const SCE_KERNEL_AIO_PRIORITY_MID: c_int = 2;
pub(crate) const SCE_KERNEL_AIO_PRIORITY_HIGH: c_int = 3;
pub(crate) const SCE_KERNEL_AIO_STATE_NOTIFIED: c_int = 0x10000;
pub(crate) const SCE_KERNEL_AIO_STATE_COMPLETED: c_int = 3;
pub(crate) const SCE_KERNEL_AIO_STATE_ABORTED: c_int = 4;
pub(crate) const SCE_KERNEL_AIO_SCHED_WINDOW_MAX: c_int = 128;
pub(crate) const SCE_KERNEL_AIO_DELAYED_COUNT_MAX: c_int = 128;
pub(crate) const SCE_KERNEL_AIO_DISABLE_SPLIT: u32 = 0;
pub(crate) const SCE_KERNEL_AIO_SPLIT_SIZE_DEFAULT: u32 = 0x100000;
pub(crate) const SCE_KERNEL_AIO_SPLIT_CHUNK_SIZE_DEFAULT: u32 = 0x100000;
pub(crate) const SCE_KERNEL_AIO_REQUEST_NUM_MAX: usize = 128;
pub(crate) const SCE_KERNEL_AIO_ID_NUM_MAX: usize = 128;
pub(crate) const SCE_KERNEL_PRIO_FIFO_HIGHEST: c_int = 256;
pub(crate) const SCE_KERNEL_PRIO_FIFO_LOWEST: c_int = 767;
pub(crate) const O_RDONLY: c_int = 0;
pub(crate) const O_NONBLOCK: c_int = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SceKernelAioResult {
    pub(crate) returnValue: i64,
    pub(crate) state: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SceKernelAioRWRequest {
    pub(crate) offset: off_t,
    pub(crate) nbyte: usize,
    pub(crate) buf: *mut c_void,
    pub(crate) result: *mut SceKernelAioResult,
    pub(crate) fd: c_int,
}
impl Default for SceKernelAioRWRequest {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SceKernelAioSchedulingParam {
    pub(crate) schedulingWindowSize: c_int,
    pub(crate) delayedCountLimit: c_int,
    pub(crate) enableSplit: u32,
    pub(crate) splitSize: u32,
    pub(crate) splitChunkSize: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SceKernelAioParam {
    pub(crate) low: SceKernelAioSchedulingParam,
    pub(crate) mid: SceKernelAioSchedulingParam,
    pub(crate) high: SceKernelAioSchedulingParam,
}
const _: () = {
    assert!(size_of::<SceKernelAioResult>() == 16);
    assert!(
        size_of::<SceKernelAioRWRequest>() == 40 && offset_of!(SceKernelAioRWRequest, fd) == 32
    );
    assert!(size_of::<SceKernelAioParam>() == 60);
};

pub(crate) use super::pack::{sceKernelAioDeleteRequests, sceKernelAioPollRequests};

pub(crate) unsafe fn sceKernelAioSubmitReadCommandsMultiple(
    requests: *mut SceKernelAioRWRequest,
    count: c_int,
    priority: c_int,
    ids: *mut SceKernelAioSubmitId,
) -> c_int {
    // The reactor and pack request layouts are identical.
    unsafe {
        super::pack::sceKernelAioSubmitReadCommandsMultiple(requests.cast(), count, priority, ids)
    }
}

const _: () = {
    assert!(size_of::<SceKernelAioRWRequest>() == size_of::<super::pack::SceKernelAioRWRequest>());
    assert!(
        offset_of!(SceKernelAioRWRequest, result)
            == offset_of!(super::pack::SceKernelAioRWRequest, result)
    );
    assert!(size_of::<SceKernelAioResult>() == size_of::<super::pack::SceKernelAioResult>());
};

unsafe extern "C" {
    pub(crate) fn sceKernelAioInitializeImpl(param: *mut c_void, size: c_int) -> c_int;
    pub(crate) fn sceKernelAioInitializeParam(param: *mut SceKernelAioParam);
    pub(crate) fn sceKernelAioSetParam(
        param: *mut SceKernelAioSchedulingParam,
        schedulingWindowSize: c_int,
        delayedCountLimit: c_int,
        enableSplit: u32,
        splitSize: u32,
        splitChunkSize: u32,
    ) -> c_int;
    pub(crate) fn sceKernelNanosleep(
        rqtp: *const SceKernelTimespec,
        rmtp: *mut SceKernelTimespec,
    ) -> c_int;
    pub(crate) fn scePthreadCreate(
        thread: *mut ScePthread,
        attr: *const ScePthreadAttr,
        entry: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        name: *const c_char,
    ) -> c_int;
    pub(crate) fn scePthreadJoin(thread: ScePthread, value: *mut *mut c_void) -> c_int;
    pub(crate) fn scePthreadSelf() -> ScePthread;
    pub(crate) fn scePthreadRename(thread: ScePthread, name: *const c_char) -> c_int;
    pub(crate) fn scePthreadGetprio(thread: ScePthread, prio: *mut c_int) -> c_int;
    pub(crate) fn scePthreadSetprio(thread: ScePthread, prio: c_int) -> c_int;
    pub(crate) fn scePthreadSetaffinity(thread: ScePthread, mask: SceKernelCpumask) -> c_int;
}

/// SDK macro `sceKernelAioInitialize(param)`.
pub(crate) unsafe fn sceKernelAioInitialize(param: *mut SceKernelAioParam) -> c_int {
    unsafe { sceKernelAioInitializeImpl(param.cast(), size_of::<SceKernelAioParam>() as c_int) }
}

// ---- other runtime modules (called directly) -------------------------------

pub(crate) use super::amm::{
    ammTrySubmitCommandBufferLeaf, ammWriteMapCommand2, ammWriteMapDirectCommand,
};
pub(crate) use super::command_buffer::{
    ampr_decode_apr_packed_op, ampr_op_layout_checked, ampr_strict_write_op,
    ampr_write_op_with_layout, PackedOpLayout,
};
pub(crate) use super::equeue::{apr_equeue_try_publish, AprEqueuePublishResult};
pub(crate) use super::fd_cache::{
    ampr_index_acquire_cached_fd, ampr_index_fd_cache_mark_open_pressure,
    ampr_index_fd_cache_open_pressure_generation, ampr_index_fd_cache_release_idle_percent,
    ampr_index_fd_cache_release_open_fd_budget_headroom,
    ampr_index_fd_cache_release_open_fd_headroom, ampr_index_fd_cache_release_stale,
    ampr_index_fd_cache_set_effective_cap, ampr_index_fd_cache_stats,
    ampr_index_fd_common_open_budget_headroom_available, ampr_index_fd_direct_note_close,
    ampr_index_fd_direct_note_open, ampr_index_fd_direct_open_count,
    ampr_index_fd_open_budget_set_effective_cap, ampr_index_fd_pressure_current_caps,
    ampr_index_fd_uncached_open_count, ampr_index_release_cached_fd_pin, FileEntryView,
    PressureCaps as AmprIndexFdPressureCaps,
};
pub(crate) use super::index::ampr_index_get_entry_view;
pub(crate) use super::services::{apr_libkernel_rc_to_sce, time_counter_now};
pub(crate) use ampr_command::{op_type::*, OpRecord as Op, SceAmprCommandBuffer};
// Errno, kernel file/memory and sync helpers under their `ampr_*` names.
// Lock guards are `MutexGuard`; timed cv waits use `Condvar::wait_for_us`.
pub(crate) use super::sync::spin_pause_or_yield as ampr_spin_pause_or_yield;
pub(crate) use super::sys::{
    posix_errno_from_sce as ampr_posix_errno_from_sce,
    posix_errno_is_fd_open_pressure as ampr_posix_errno_is_fd_open_pressure,
    real_mprotect as ampr_real_sceKernelMprotect, real_posix_open as ampr_real_posix_open,
    sce_errno_from_posix as ampr_sce_errno_from_posix,
};
/// Command op type (values in `ampr_command::op_type`).
pub(crate) type OpType = u8;
/// `SceAprResultBuffer` == `SceAmmResultBuffer` ({int result; uint32 errorOffset}).
pub(crate) type SceAprResultBuffer = SceAmmResultBuffer;
/// `sce::Ampr::Emu::kAmmSubmitRetryRc`.
pub(crate) const kAmmSubmitRetryRc: c_int = -2147352541;

// Pack backend entry points (defined in `rt::pack`, linked by symbol).
pub(crate) use super::pack::{ampr_pack_is_virtual_fd, ampr_pack_try_open_indexed};

// ---- reactor jobs and priorities --------------------------------------------

pub(crate) const kAprPriorityMax: u8 = 6;
pub(crate) const kAprPriorityArrayCount: u8 = kAprPriorityMax + 1;

pub(crate) fn apr_clamp_priority(prio: u32) -> u8 {
    prio.min(kAprPriorityMax as u32) as u8
}
pub(crate) fn apr_scheduler_priority_lane(prio: u32) -> u8 {
    apr_clamp_priority(prio)
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)] // ABI values: decoded from services.rs `Job.submit_mode`
pub(crate) enum AprSubmitMode {
    #[default]
    kSubmit = 0,
    kSubmitAndGetResult = 1,
    kSubmitAndGetId = 2,
}

/// `Job`; shared with services.rs (`#[repr(C)]` layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Job {
    pub(crate) id: u64,
    pub(crate) sourceBuffer: *const c_void,
    pub(crate) sourceBytes: u32,
    pub(crate) sourceCommandCount: u32,
    pub(crate) submitMode: AprSubmitMode,
    pub(crate) nativeSubmitType: c_int,
    pub(crate) nativePrio: u32,
    pub(crate) aprRes: *mut SceAprResultBuffer,
}
const _: () = assert!(
    size_of::<Job>() == 48
        && offset_of!(Job, sourceBytes) == 16
        && offset_of!(Job, submitMode) == 24
        && offset_of!(Job, nativeSubmitType) == 28
        && offset_of!(Job, nativePrio) == 32
        && offset_of!(Job, aprRes) == 40
);

// ---- external AIO broker -------------------------------------------------------

pub(crate) const kAprExternalAioCapacity: u32 = 32;
pub(crate) const kAprExternalAioGroupMaxRequests: usize = 32;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)] // These values match the pack's scheduling classes.
pub(crate) enum AprExternalAioClass {
    Latency = 0,
    #[default]
    Balanced = 1,
    Bulk = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum AprExternalAioEvent {
    Submitted = 0,
    SubmitDeferred = 1,
    #[default]
    SubmitFailed = 2,
    Completed = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct AprExternalAioNotification {
    pub(crate) event: AprExternalAioEvent,
    pub(crate) value: c_int,
    pub(crate) firstExternalInSubmitBatch: bool,
}
const _: () = assert!(size_of::<AprExternalAioNotification>() == 12);

/// Callback `(context, notification)`; null is `None`.
pub(crate) type AprExternalAioCallback = Option<
    unsafe extern "C" fn(context: *mut c_void, notification: *const AprExternalAioNotification),
>;

// ---- reactor common helpers ---------------------------------------------------

const HOOK_APR_SUBMIT: usize = 27; // kAmprLibkernelHook_sceKernelAprSubmitCommandBuffer
const HOOK_APR_SUBMIT_AND_GET_RESULT: usize = 29;
const HOOK_APR_SUBMIT_AND_GET_ID: usize = 31;
const HOOK_APR_WAIT: usize = 32;

/// `NativeAprCommandBufferView` == retail `sce::Ampr::AprCommandBuffer` (40 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NativeAprCommandBufferView {
    pub(crate) m_commandBuffer: SceAmprCommandBuffer,
    pub(crate) m_mapState: u64,
    pub(crate) m_scatterGatherState: u64,
}
const _: () = assert!(
    size_of::<NativeAprCommandBufferView>() == 40 && align_of::<NativeAprCommandBufferView>() == 8
);
impl Default for NativeAprCommandBufferView {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// `apr_native_submit_dispatch`; `cb` is the retail AprCommandBuffer.
pub(crate) unsafe fn apr_native_submit_dispatch(
    cb: *mut NativeAprCommandBufferView,
    prio: u32,
    mode: AprSubmitMode,
    result: *mut SceAprResultBuffer,
    id: *mut SceAprSubmitId,
    raw_rc_out: *mut c_int,
) -> c_int {
    type Submit = unsafe extern "C" fn(*mut NativeAprCommandBufferView, u32) -> c_int;
    type GetResult = unsafe extern "C" fn(
        *mut NativeAprCommandBufferView,
        u32,
        *mut SceAprResultBuffer,
        *mut SceAprSubmitId,
    ) -> c_int;
    type GetId =
        unsafe extern "C" fn(*mut NativeAprCommandBufferView, u32, *mut SceAprSubmitId) -> c_int;
    let rc = unsafe {
        match mode {
            AprSubmitMode::kSubmit => kernel_slot::<Submit>(HOOK_APR_SUBMIT).map(|f| f(cb, prio)),
            AprSubmitMode::kSubmitAndGetResult => {
                kernel_slot::<GetResult>(HOOK_APR_SUBMIT_AND_GET_RESULT)
                    .map(|f| f(cb, prio, result, id))
            }
            AprSubmitMode::kSubmitAndGetId => {
                kernel_slot::<GetId>(HOOK_APR_SUBMIT_AND_GET_ID).map(|f| f(cb, prio, id))
            }
        }
    };
    match rc {
        Some(rc) => {
            unsafe { *raw_rc_out = rc };
            0
        }
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

/// `apr_native_wait_dispatch`.
pub(crate) unsafe fn apr_native_wait_dispatch(id: SceAprSubmitId, raw_rc_out: *mut c_int) -> c_int {
    if raw_rc_out.is_null() {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    type Wait = unsafe extern "C" fn(SceAprSubmitId) -> c_int;
    match unsafe { kernel_slot::<Wait>(HOOK_APR_WAIT) } {
        Some(f) => {
            unsafe { *raw_rc_out = f(id) };
            0
        }
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

/// True for the APR read op types.
pub(crate) fn cb_op_is_apr_read(t: OpType) -> bool {
    matches!(
        t,
        APR_READ_FILE | APR_READ_GATHER | APR_READ_SCATTER | APR_READ_GATHER_SCATTER
    )
}

/// `sce::Ampr::WaitCompare` / `WaitFlush`.
#[allow(dead_code)] // ABI values
pub(crate) mod WaitCompare {
    pub(crate) const kEqual: u8 = 0;
    pub(crate) const kGreaterThanUnsigned: u8 = 1;
    pub(crate) const kLessThanUnsigned: u8 = 2;
    pub(crate) const kNotEqual: u8 = 3;
    pub(crate) const kGreaterThanOrEqualWrapped: u8 = 4;
    pub(crate) const kGreaterThanSigned: u8 = 5;
    pub(crate) const kLessThanSigned: u8 = 6;
}
#[allow(dead_code)] // ABI values
pub(crate) mod WaitFlush {
    pub(crate) const kDisable: u8 = 0;
    pub(crate) const kEnable: u8 = 1;
}

/// SCE AMPR APR error codes.
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDCOMMANDDATAFORMAT: c_int = -2121195516;
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDWAITONADDRESSADDRESS: c_int = -2121195514;
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDWRITEADDRESSSOURCE: c_int = -2121195513;
pub(crate) const SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS: c_int = -2121195487;
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDFILEID: c_int = -2121195463;
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET: c_int = -2121195462;
pub(crate) const SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE: c_int = -2121195461;
pub(crate) const SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID: c_int = -2121195460;
pub(crate) const SCE_AMPR_APR_FILEID_INVALID: u32 = u32::MAX;

// ---- loose adaptive reads -----------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum AmprLooseReadClass {
    Latency = 0,
    #[default]
    Balanced = 1,
    Bulk = 2,
    Count = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum AmprLooseGsReadKind {
    #[default]
    File = 0,
    Gather = 1,
    Scatter = 2,
    GatherScatter = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct AmprLooseGsState {
    pub(crate) nextOffset: u64,
    pub(crate) nextBuffer: usize,
    pub(crate) fileId: u32,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AmprLooseGsCommand {
    pub(crate) kind: AmprLooseGsReadKind,
    pub(crate) fileId: u32,
    pub(crate) buffer: usize,
    pub(crate) length: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AmprLooseGsResolvedRead {
    pub(crate) fileId: u32,
    pub(crate) buffer: usize,
    pub(crate) length: u64,
    pub(crate) offset: u64,
    pub(crate) valid: bool,
}

pub(crate) fn ampr_loose_chain_chunk_limit(
    readClass: AmprLooseReadClass,
    waitingLatency: bool,
    constrained: bool,
    shared: bool,
    hardLimit: u32,
) -> u32 {
    if hardLimit == 0 {
        0
    } else if waitingLatency || constrained || readClass == AmprLooseReadClass::Latency {
        1
    } else if shared || readClass != AmprLooseReadClass::Bulk {
        hardLimit.min(2)
    } else {
        hardLimit
    }
}

pub(crate) fn ampr_loose_gs_resolve(
    state: &AmprLooseGsState,
    command: &AmprLooseGsCommand,
) -> AmprLooseGsResolvedRead {
    let mut read = AmprLooseGsResolvedRead {
        length: command.length,
        ..Default::default()
    };
    let (file_id, buffer, offset) = match command.kind {
        AmprLooseGsReadKind::File => (command.fileId, command.buffer, command.offset),
        AmprLooseGsReadKind::Gather if state.fileId != 0 && state.nextBuffer != 0 => {
            (state.fileId, state.nextBuffer, command.offset)
        }
        AmprLooseGsReadKind::Scatter if state.fileId != 0 && state.nextOffset != 0 => {
            (state.fileId, command.buffer, state.nextOffset)
        }
        AmprLooseGsReadKind::GatherScatter if state.fileId != 0 => {
            (state.fileId, command.buffer, command.offset)
        }
        _ => return read,
    };
    read.fileId = file_id;
    read.buffer = buffer;
    read.offset = offset;
    read.valid = true;
    read
}

pub(crate) fn ampr_loose_gs_advance(
    read: &AmprLooseGsResolvedRead,
    offsetMaxExclusive: u64,
) -> AmprLooseGsState {
    if !read.valid || offsetMaxExclusive == 0 {
        return AmprLooseGsState::default();
    }
    AmprLooseGsState {
        fileId: read.fileId,
        nextOffset: if read.offset < offsetMaxExclusive
            && read.length < offsetMaxExclusive - read.offset
        {
            read.offset + read.length
        } else {
            offsetMaxExclusive - 1
        },
        nextBuffer: read
            .buffer
            .checked_add(read.length as usize)
            .unwrap_or(usize::MAX),
    }
}

// ---- native micro/batch constants and pools ------------------------------------

pub(crate) const kAprNativeMicroCompletionDone: u64 = 0x4150524d444f4e45;
pub(crate) const kAprNativeMicroCommandCapacity: u32 = 64;
pub(crate) const kAprNativeMicroCompletionBytes: u32 = 16;
pub(crate) const kAprNativeMicroAmmPriority: u32 = 0;
pub(crate) const kAprNativeMicroResultPending: c_int = i32::MIN;

/// Native-visible micro command buffer slot (64-byte aligned).
#[repr(C, align(64))]
pub(crate) struct AprNativeMicroSlot {
    pub(crate) commands: [u8; kAprNativeMicroCommandCapacity as usize],
    pub(crate) completionTemplate: [u8; kAprNativeMicroCompletionBytes as usize],
    /// volatile: access with read_volatile/write_volatile.
    pub(crate) completion: u64,
    pub(crate) result: SceAprResultBuffer,
}
pub(crate) const kAprNativeMicroRawBytes: usize =
    size_of::<AprNativeMicroSlot>() * kAprCommandBufferLiveMax;
pub(crate) const kAprNativeMicroPoolBytes: usize =
    kAprNativeMicroRawBytes.div_ceil(SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;

pub(crate) const kAprNativeBatchBufferCountPerLane: u32 = 2;
pub(crate) const kAprNativeBatchRequestedPacketCount: u32 = 1024;
pub(crate) const kAprNativeBatchPacketsPerGroup: u32 = 8;
pub(crate) const kAprNativeBatchPaddingHeaderCount: u32 = 5;
pub(crate) const kAprNativeBatchGateBytes: u32 = 16;
pub(crate) const kAprNativeBatchPayloadSlotBytes: u32 = 24;
pub(crate) const kAprNativeBatchPayloadRegionBytes: u32 =
    kAprNativeBatchPayloadSlotBytes * kAprNativeBatchPacketsPerGroup;
pub(crate) const kAprNativeBatchCheckpointBytes: u32 = 16;
pub(crate) const kAprNativeBatchGroupBytes: u32 =
    kAprNativeBatchGateBytes + kAprNativeBatchPayloadRegionBytes + kAprNativeBatchCheckpointBytes;
pub(crate) const kAprNativeBatchSubmitBytes: u32 = kAprNativeBatchGroupBytes
    * (kAprNativeBatchRequestedPacketCount / kAprNativeBatchPacketsPerGroup);
pub(crate) const kAprNativeBatchGroupCount: u32 =
    kAprNativeBatchRequestedPacketCount / kAprNativeBatchPacketsPerGroup - 1;
pub(crate) const kAprNativeBatchPacketCount: u32 =
    kAprNativeBatchGroupCount * kAprNativeBatchPacketsPerGroup;
pub(crate) const kAprNativeBatchExecutableBytes: u32 =
    kAprNativeBatchGroupBytes * kAprNativeBatchGroupCount;
pub(crate) const kAprNativeBatchReleaseOffset: u32 = kAprNativeBatchExecutableBytes;
pub(crate) const kAprNativeBatchProgressOffset: u32 = kAprNativeBatchReleaseOffset + 8;
pub(crate) const kAprNativeBatchCommandCountPerGroup: u32 = 2 + 2 * kAprNativeBatchPacketsPerGroup;
pub(crate) const kAprNativeBatchCommandCount: u32 =
    kAprNativeBatchCommandCountPerGroup * kAprNativeBatchGroupCount;
pub(crate) const kAprNativeBatchTokenBase: u64 = 0x4150524200000000;
pub(crate) const kAprNativeBatchResultPending: c_int = i32::MIN;

/// Native-visible APR batch slot; `commands` tail holds the release/progress words.
#[repr(C, align(64))]
pub(crate) struct AprNativeBatchSlot {
    pub(crate) commands: [u8; kAprNativeBatchSubmitBytes as usize],
    pub(crate) defaultPayload: [u8; kAprNativeBatchPayloadRegionBytes as usize],
    pub(crate) result: SceAprResultBuffer,
}
pub(crate) const kAprNativeBatchSlotCount: u32 =
    kAprPriorityArrayCount as u32 * kAprNativeBatchBufferCountPerLane;
pub(crate) const kAprNativeBatchRawBytes: usize =
    size_of::<AprNativeBatchSlot>() * kAprNativeBatchSlotCount as usize;
pub(crate) const kAprNativeBatchPoolBytes: usize =
    kAprNativeBatchRawBytes.div_ceil(SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;

const _: () = {
    assert!(offset_of!(AprNativeMicroSlot, completion) == 80);
    assert!(kAprNativeBatchSubmitBytes == 0x7000 && kAprNativeBatchExecutableBytes == 0x6f20);
    assert!(kAprNativeBatchGroupBytes == 224);
    assert!(kAprNativeBatchPayloadSlotBytes == (kAprNativeBatchPaddingHeaderCount + 1) * 4);
};

/// Page-aligned static byte pool (`alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t[]`).
#[repr(C, align(16384))]
pub(crate) struct PagePool<const N: usize>(pub(crate) [u8; N]);
const _: () = assert!(align_of::<PagePool<1>>() == SCE_KERNEL_PAGE_SIZE);

pub(crate) static g_apr_native_micro_pool: SyncCell<PagePool<kAprNativeMicroPoolBytes>> =
    SyncCell::new(PagePool([0; kAprNativeMicroPoolBytes]));
pub(crate) static g_apr_native_batch_pool: SyncCell<PagePool<kAprNativeBatchPoolBytes>> =
    SyncCell::new(PagePool([0; kAprNativeBatchPoolBytes]));

#[derive(Clone, Copy, Default)]
pub(crate) struct JobResult {
    pub(crate) rc: c_int,
    pub(crate) errorOffset: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct AprAioReadDesc {
    pub(crate) fileId: u32,
    pub(crate) fd: c_int,
    pub(crate) buffer: *mut c_void,
    pub(crate) length: u64,
    pub(crate) offset: u64,
    pub(crate) fileSize: usize,
    pub(crate) filePath: *const c_char,
    pub(crate) filePathLength: u32,
    pub(crate) errorOff: u32,
    pub(crate) readClass: AmprLooseReadClass,
    pub(crate) coalescedCommandCount: u8,
    pub(crate) bypassFdCache: bool,
    pub(crate) closeAfter: bool,
    pub(crate) closeAfterPhysical: bool,
    pub(crate) cachePinned: bool,
    pub(crate) borrowedFd: bool,
    pub(crate) fileMetadataValid: bool,
}
impl Default for AprAioReadDesc {
    fn default() -> Self {
        Self {
            fd: -1,
            readClass: AmprLooseReadClass::Balanced,
            coalescedCommandCount: 1,
            ..unsafe { core::mem::zeroed() }
        }
    }
}

pub(crate) const kAprAioOpenFlags: c_int = O_RDONLY | O_NONBLOCK;
pub(crate) const kAprAioRequestOffsetMax: u64 = i64::MAX as u64;

// ---- AprAioReactor constants ---------------------------------------------------

pub(crate) const kSoftwareReadChunkMax: u64 = AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES as u64;
pub(crate) const kSoftwareReadLengthMax: u64 = 0x100000000;
pub(crate) const kSoftwareReadOffsetMaxExclusive: u64 = 0x10000000000;
pub(crate) const kSoftwareReadUserVaMax: u64 = 0xF00000000000;
pub(crate) const kPriorityCount: u8 = kAprPriorityArrayCount;
pub(crate) const PRIO_N: usize = kPriorityCount as usize;
const fn umin(a: u32, b: u32) -> u32 {
    if a < b {
        a
    } else {
        b
    }
}
pub(crate) const kConfiguredBaseActiveReads: u32 = if AMPR_EMU_APR_AIO_INFLIGHT > 0 {
    AMPR_EMU_APR_AIO_INFLIGHT
} else {
    1
};
pub(crate) const kConfiguredSmallReadActiveReads: u32 =
    if AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT > kConfiguredBaseActiveReads {
        AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT
    } else {
        kConfiguredBaseActiveReads
    };
pub(crate) const kConfiguredActiveReads: u32 = kConfiguredSmallReadActiveReads;
pub(crate) const kMaxActiveReads: u32 =
    umin(kConfiguredActiveReads, SCE_KERNEL_AIO_ID_NUM_MAX as u32);
pub(crate) const kBaseActiveReads: u32 = umin(kConfiguredBaseActiveReads, kMaxActiveReads);
pub(crate) const kSmallReadActiveReads: u32 =
    umin(kConfiguredSmallReadActiveReads, kMaxActiveReads);
pub(crate) const kReadChainPoolCapacity: u32 = kMaxActiveReads + kPriorityCount as u32 * 2 + 1;
pub(crate) const kReadChainAwaitingInitialSubmit: u64 = u64::MAX;
pub(crate) const kAioPollBatchLimit: usize = SCE_KERNEL_AIO_REQUEST_NUM_MAX;
pub(crate) const kAioCombinedSubmitRequestLimit: usize = 64;
pub(crate) const kAioPollPressureThreshold: u32 = (kBaseActiveReads * 3 + 3) / 4;
pub(crate) const kConfiguredAioCapacityPollBatchLimit: usize =
    if AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT != 0 {
        AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT
    } else {
        1
    };
pub(crate) const kAioCapacityPollBatchLimit: usize =
    if kConfiguredAioCapacityPollBatchLimit < kAioPollBatchLimit {
        kConfiguredAioCapacityPollBatchLimit
    } else {
        kAioPollBatchLimit
    };
pub(crate) const kHotPollQueueCapacity: u32 = kMaxActiveReads * 2;
pub(crate) const kExternalAioCapacity: u32 = kAprExternalAioCapacity;
pub(crate) const kReadCompletionInitialBits: u32 = 576;
pub(crate) const kReadCompletionRingWords: usize = (kReadCompletionInitialBits as usize + 63) / 64;
pub(crate) const kReadCompletionRingBits: u64 = (kReadCompletionRingWords * 64) as u64;
pub(crate) const kJobStatePoolCapacity: u32 = kAprCommandBufferLiveMax as u32;
pub(crate) const kSyntheticRequestCapacity: u32 = 4096;
pub(crate) const kSyntheticDoneCapacity: u32 = 4096;
pub(crate) const kSyntheticLowerSlotCapacity: u32 = 512;
pub(crate) const kSyntheticSubmitIdTag: u32 = 0xA5000000;
pub(crate) const kSyntheticSubmitIdTagMask: u32 = 0xFF000000;
pub(crate) const kNativeCompletionTimeoutNs: u64 = 10_000_000_000;
pub(crate) const kFdCacheMaintenanceBusyStride: u32 = 256;
pub(crate) const kFdCacheMaintenanceIntervalNs: u64 = if AMPR_EMU_FD_CACHE_IDLE_SCAN_NS != 0 {
    AMPR_EMU_FD_CACHE_IDLE_SCAN_NS
} else {
    AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS
};
pub(crate) const kSyntheticSubmitIdSlotMask: u32 = 0x000001FF;
pub(crate) const kSyntheticSubmitIdGenerationMask: u32 = 0x00FFFE00;
pub(crate) const kSyntheticSubmitIdGenerationShift: u32 = 9;
pub(crate) const kAioInitUninitialized: u32 = 0;
pub(crate) const kAioInitInitializing: u32 = 1;
pub(crate) const kAioInitReady: u32 = 2;
pub(crate) const kAioInitExternalBusy: u32 = 3;
/// `ActiveReadList::kInvalid`.
pub(crate) const kInvalid: u32 = u32::MAX;

const _: () = {
    assert!(kMaxActiveReads == 64 && kBaseActiveReads == 32 && kReadChainPoolCapacity == 79);
    assert!(kMaxActiveReads as usize + kExternalAioCapacity as usize <= SCE_KERNEL_AIO_ID_NUM_MAX);
    assert!(kAprExternalAioGroupMaxRequests <= kAioCombinedSubmitRequestLimit);
    assert!(kReadCompletionRingBits > kMaxActiveReads as u64);
    assert!(kSyntheticLowerSlotCapacity <= kSyntheticSubmitIdSlotMask + 1);
};

// ---- AprAioReactor helper types -------------------------------------------------

/// All-zero `Default` for types whose fields all start at zero.
macro_rules! zeroed_default {
    ($($t:ty),*) => {$(
        impl Default for $t {
            fn default() -> Self {
                unsafe { core::mem::zeroed() }
            }
        }
    )*};
}

pub(crate) type JobPtr = *mut JobState;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GatherScatterState {
    pub(crate) nextOffset: u64,
    pub(crate) nextBuffer: *mut c_void,
    pub(crate) fileId: u32,
}
const _: () = assert!(size_of::<GatherScatterState>() == 24);

#[derive(Clone, Copy)]
pub(crate) struct ReadChain {
    pub(crate) job: JobPtr,
    pub(crate) ownerDesc: AprAioReadDesc,
    pub(crate) nextBuffer: *mut c_void,
    pub(crate) nextOffset: u64,
    pub(crate) remaining: u64,
    pub(crate) seq: u64,
    pub(crate) retryNotBeforeNs: u64,
    pub(crate) commandIndex: usize,
    pub(crate) activeCount: u32,
    pub(crate) activeBytes: u64,
    pub(crate) poolSlot: u32,
    pub(crate) pendingFinalGs: GatherScatterState,
    pub(crate) gatherScatterCommandCount: u8,
    pub(crate) hasPendingFinalGs: bool,
    pub(crate) allIssued: bool,
}
impl Default for ReadChain {
    fn default() -> Self {
        Self {
            ownerDesc: AprAioReadDesc::default(),
            poolSlot: u32::MAX,
            ..unsafe { core::mem::zeroed() }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ReadIssueBudget {
    pub(crate) requestsLeft: u32,
    pub(crate) bytesLeft: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum AdaptiveReadWindowMode {
    #[default]
    Pressure = 0,
    Contended = 1,
    Shared = 2,
    Exclusive = 3,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AdaptiveReadWindow {
    pub(crate) chunks: u32,
    pub(crate) bytes: u64,
    pub(crate) mode: AdaptiveReadWindowMode,
}

#[derive(Clone, Copy)]
pub(crate) struct ReadChainSlot {
    pub(crate) value: ReadChain,
    pub(crate) nextFree: u32,
    pub(crate) active: bool,
}
impl Default for ReadChainSlot {
    fn default() -> Self {
        Self {
            value: ReadChain::default(),
            nextFree: u32::MAX,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SyntheticWaitSlot {
    pub(crate) submitId: SceAprSubmitId,
    pub(crate) result: c_int,
    pub(crate) ownerJob: *mut JobState,
    pub(crate) prioIndex: u8,
    pub(crate) active: bool,
    pub(crate) done: bool,
    pub(crate) waiterClaimed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SyntheticDoneSlot {
    pub(crate) submitId: SceAprSubmitId,
    pub(crate) result: c_int,
    pub(crate) next: u32,
    pub(crate) prev: u32,
    pub(crate) active: bool,
}
impl Default for SyntheticDoneSlot {
    fn default() -> Self {
        Self {
            submitId: 0,
            result: 0,
            next: u32::MAX,
            prev: u32::MAX,
            active: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SyntheticLowerSlot {
    pub(crate) generation: u32,
    pub(crate) active: bool,
    pub(crate) generationWrapped: bool,
    /// Lookup hints (index + 1, 0 = none) for the wait/done slot last assigned to an
    /// id on this lower slot. Always validated against `submitId`; may be stale.
    pub(crate) waitSlotHint: u32,
    pub(crate) doneSlotHint: u32,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NativeMicroEngine {
    #[default]
    None = 0,
    AprBatch = 1,
    Apr = 2,
    Amm = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NativeBatchPhase {
    #[default]
    Free = 0,
    Filling = 1,
    Active = 2,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct NativeBatchState {
    pub(crate) phase: NativeBatchPhase,
    pub(crate) generation: u32,
    pub(crate) nextGroup: u32,
    pub(crate) openGroupPackets: u32,
    pub(crate) packetCount: u32,
    pub(crate) nativeSubmitType: u32,
    pub(crate) observedProgress: u64,
    pub(crate) firstSequence: u64,
    pub(crate) lastSequence: u64,
    pub(crate) submitTimeNs: u64,
    pub(crate) lastReleaseTimeNs: u64,
    pub(crate) submitId: SceAprSubmitId,
}

#[derive(Clone, Copy)]
pub(crate) struct NativeBatchLane {
    pub(crate) activeBuffer: i8,
    pub(crate) issuedSequence: u64,
    pub(crate) completedSequence: u64,
    pub(crate) blockingWaitSequence: u64,
    pub(crate) deferredReleaseSequence: u64,
    pub(crate) deferredReleaseJobId: u64,
    pub(crate) deferredReleaseBufferIndex: u32,
    pub(crate) deferredReleaseGroupIndex: u32,
    pub(crate) buffers: [NativeBatchState; kAprNativeBatchBufferCountPerLane as usize],
}
impl Default for NativeBatchLane {
    fn default() -> Self {
        Self {
            activeBuffer: -1,
            ..unsafe { core::mem::zeroed() }
        }
    }
}

zeroed_default!(GatherScatterState, SyntheticWaitSlot);

pub(crate) struct JobState {
    pub(crate) id: u64,
    pub(crate) sourceBuffer: *const u8,
    pub(crate) sourceBytes: u32,
    pub(crate) sourceOffset: u32,
    pub(crate) sourceCommandIndex: u32,
    pub(crate) decodedOpCache: Op,
    pub(crate) decodedOpCacheBytes: u32,
    pub(crate) poolSlot: u32,
    pub(crate) mapActive: bool,
    pub(crate) nativeCommandBuffer: *mut c_void,
    pub(crate) commandCount: u32,
    pub(crate) processingComplete: bool,
    pub(crate) nativePrio: u32,
    pub(crate) prioIndex: u8,
    pub(crate) submitMode: AprSubmitMode,
    pub(crate) aprRes: *mut SceAprResultBuffer,
    pub(crate) result: JobResult,

    pub(crate) nextReadSeq: u64,
    pub(crate) latestSubmittedReadSeq: u64,
    pub(crate) completedReadSeq: u64,
    pub(crate) completedOutOfOrderWords: [u64; kReadCompletionRingWords],
    pub(crate) cursorReadChain: *mut ReadChain,
    pub(crate) activeReadCount: u32,
    pub(crate) activeReadHead: u32,
    pub(crate) activeReadTail: u32,
    pub(crate) nativeSubmitted: AtomicBool,
    /// volatile: access with read_volatile.
    pub(crate) nativeCompletionAddress: *mut u64,
    pub(crate) nativeSubmitTimeNs: u64,
    pub(crate) nativeSubmitRetryAtNs: u64,
    pub(crate) nativeRetrySourceBytes: u32,
    pub(crate) nativeRetryMapBegin: bool,
    pub(crate) nativeMicroEngine: NativeMicroEngine,
    pub(crate) nativeMicroSubmitId: SceAprSubmitId,
    pub(crate) nativeBatchSequence: u64,
    pub(crate) nativeBatchReleaseReadSequence: u64,
    pub(crate) nativeBatchReleasePending: bool,
    pub(crate) nativeSourceOffset: u32,
    pub(crate) nativeSourceType: OpType,
    pub(crate) syntheticSubmitId: SceAprSubmitId,
    pub(crate) syntheticWaitSlot: u32,
    pub(crate) syntheticLowerSlot: u32,
    pub(crate) syntheticLowerGeneration: u32,
    pub(crate) syntheticWaitPublished: bool,
    pub(crate) schedulingWaiterClaimed: AtomicBool,
    pub(crate) nativeSubmitBytes: u32,
    pub(crate) nativeSubmitFirstType: OpType,
    pub(crate) nativeSubmitType: c_int,
    pub(crate) failed: AtomicBool,
    pub(crate) hasCommandError: bool,
    pub(crate) activeListed: bool,
    pub(crate) activePrev: *mut JobState,
    pub(crate) activeNext: *mut JobState,
    pub(crate) priorityPrev: *mut JobState,
    pub(crate) priorityNext: AtomicPtr<JobState>,
}
impl JobState {
    /// Initializes a fresh `JobState` in place at `p` (pool slot storage).
    pub(crate) unsafe fn init_in_place(p: *mut JobState) {
        unsafe {
            ptr::write_bytes(p, 0, 1);
            (*p).poolSlot = u32::MAX;
            (*p).nextReadSeq = 1;
            (*p).activeReadHead = u32::MAX;
            (*p).activeReadTail = u32::MAX;
            (*p).nativeSourceType = NOP;
            (*p).syntheticWaitSlot = u32::MAX;
            (*p).syntheticLowerSlot = u32::MAX;
            (*p).nativeSubmitFirstType = NOP;
        }
    }
}

pub(crate) struct JobStateSlot {
    pub(crate) active: bool,
    pub(crate) nextFree: u32,
    /// `alignas(JobState) unsigned char storage[sizeof(JobState)]`.
    pub(crate) storage: MaybeUninit<JobState>,
}
impl JobStateSlot {
    pub(crate) fn job(&mut self) -> *mut JobState {
        self.storage.as_mut_ptr()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ActiveRead {
    pub(crate) job: JobPtr,
    pub(crate) desc: AprAioReadDesc,
    pub(crate) chain: *mut ReadChain,
    pub(crate) result: SceKernelAioResult,
    pub(crate) request: SceKernelAioRWRequest,
    pub(crate) aioId: SceKernelAioSubmitId,
    pub(crate) aioPrio: c_int,
    pub(crate) seq: u64,
    pub(crate) commandIndex: usize,
    pub(crate) readCreditBytes: u64,
    pub(crate) submitTimeNs: u64,
    pub(crate) nextPollTimeNs: u64,
    pub(crate) pollBackoffNs: u32,
    pub(crate) ammEfaultRetries: u32,
    pub(crate) aioCompletionRetries: u32,
    pub(crate) aioDeleteRetries: u32,
    pub(crate) aioDeleteFirstFailureNs: u64,
    pub(crate) retryNotBeforeNs: u64,
    pub(crate) listSlot: u32,
    pub(crate) listGeneration: u32,
    pub(crate) pollDeadlineHeapIndex: u32,
    pub(crate) jobPrevSlot: u32,
    pub(crate) jobNextSlot: u32,
    pub(crate) hotPollQueued: bool,
    pub(crate) awaitingBatchSubmit: bool,
    pub(crate) awaitingResubmit: bool,
    pub(crate) nativeCapacityCharged: bool,
    pub(crate) submitAccounted: bool,
    /// mem_report counters (always 0 in normal builds): `stats::now()` at the
    /// kernel submit, at the last "not done" poll, and polls since submit.
    pub(crate) statSubmitNs: u64,
    pub(crate) statLastPollNs: u64,
    pub(crate) statPolls: u32,
}
impl Default for ActiveRead {
    fn default() -> Self {
        Self {
            desc: AprAioReadDesc::default(),
            aioId: -1,
            aioPrio: SCE_KERNEL_AIO_PRIORITY_MID,
            listSlot: u32::MAX,
            pollDeadlineHeapIndex: u32::MAX,
            jobPrevSlot: u32::MAX,
            jobNextSlot: u32::MAX,
            nativeCapacityCharged: true,
            ..unsafe { core::mem::zeroed() }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveReadRef {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}
impl Default for ActiveReadRef {
    fn default() -> Self {
        Self {
            slot: u32::MAX,
            generation: 0,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ExternalAioState {
    #[default]
    Free = 0,
    Pending = 1,
    AwaitingBatchSubmit = 2,
    Deferred = 3,
    Submitted = 4,
}

pub(crate) struct ExternalAioRead {
    pub(crate) requests: [SceKernelAioRWRequest; kAprExternalAioGroupMaxRequests],
    pub(crate) aioIds: [SceKernelAioSubmitId; kAprExternalAioGroupMaxRequests],
    pub(crate) deleteRetries: [u32; kAprExternalAioGroupMaxRequests],
    pub(crate) deleteFirstFailureNs: [u64; kAprExternalAioGroupMaxRequests],
    pub(crate) context: *mut c_void,
    pub(crate) callback: AprExternalAioCallback,
    pub(crate) submitTimeNs: u64,
    pub(crate) retryNotBeforeNs: u64,
    pub(crate) nextPollTimeNs: u64,
    pub(crate) pollBackoffNs: u32,
    pub(crate) generation: u32,
    pub(crate) requestCount: u32,
    pub(crate) remainingCount: u32,
    pub(crate) totalBytes: u64,
    pub(crate) completionState: c_int,
    pub(crate) aioPriority: c_int,
    pub(crate) ioClass: AprExternalAioClass,
    pub(crate) state: ExternalAioState,
    pub(crate) grouped: bool,
    /// Served by the pread pool (pread_pool.rs) instead of kernel AIO; set at submit.
    pub(crate) preadBacked: bool,
    pub(crate) published: AtomicBool,
    /// mem_report counters per request (see `ActiveRead::statSubmitNs`).
    pub(crate) statSubmitNs: [u64; kAprExternalAioGroupMaxRequests],
    pub(crate) statLastPollNs: [u64; kAprExternalAioGroupMaxRequests],
    pub(crate) statPolls: [u32; kAprExternalAioGroupMaxRequests],
}
impl ExternalAioRead {
    /// Applies the non-zero member initializers to zeroed storage.
    pub(crate) fn init_defaults(&mut self) {
        self.completionState = SCE_KERNEL_AIO_STATE_COMPLETED;
        self.aioPriority = SCE_KERNEL_AIO_PRIORITY_MID;
        self.ioClass = AprExternalAioClass::Balanced;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExternalAioRef {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}
impl Default for ExternalAioRef {
    fn default() -> Self {
        Self {
            slot: u32::MAX,
            generation: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AioItemRef {
    pub(crate) active: ActiveReadRef,
    pub(crate) external: ExternalAioRef,
    pub(crate) isExternal: bool,
    pub(crate) externalWasDeferred: bool,
    pub(crate) externalRequestIndex: u32,
}

pub(crate) struct AioSubmitBatch {
    pub(crate) requests: [SceKernelAioRWRequest; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
    pub(crate) ids: [SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
    pub(crate) items: [AioItemRef; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
    pub(crate) count: usize,
    pub(crate) aioPriority: c_int,
}

pub(crate) struct ExternalAioGroupBatch {
    pub(crate) items: [AioItemRef; kAprExternalAioCapacity as usize],
    pub(crate) count: usize,
    pub(crate) aioPriority: c_int,
}

pub(crate) struct AioSubmitRound {
    pub(crate) batches: [AioSubmitBatch; 3],
    pub(crate) groupedExternal: [ExternalAioGroupBatch; 3],
}
impl AioSubmitRound {
    /// Resets in place to the empty state (no large stack temporaries).
    pub(crate) fn reset(&mut self) {
        for b in &mut self.batches {
            b.requests = [SceKernelAioRWRequest::default(); SCE_KERNEL_AIO_REQUEST_NUM_MAX];
            b.ids = [0; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
            b.items = [AioItemRef::default(); SCE_KERNEL_AIO_REQUEST_NUM_MAX];
            b.count = 0;
            b.aioPriority = SCE_KERNEL_AIO_PRIORITY_MID;
        }
        for g in &mut self.groupedExternal {
            g.items = [AioItemRef::default(); kAprExternalAioCapacity as usize];
            g.count = 0;
            g.aioPriority = SCE_KERNEL_AIO_PRIORITY_MID;
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ActiveReadListSlot {
    pub(crate) value: ActiveRead,
    pub(crate) prev: u32,
    pub(crate) next: u32,
    pub(crate) generation: u32,
    pub(crate) active: bool,
}
impl Default for ActiveReadListSlot {
    fn default() -> Self {
        Self {
            value: ActiveRead::default(),
            prev: kInvalid,
            next: kInvalid,
            generation: 0,
            active: false,
        }
    }
}

/// `ActiveReadList`; methods (empty/size/begin/end/push_back/erase/...) are in pools.rs.
pub(crate) struct ActiveReadList {
    pub(crate) slots_: [ActiveReadListSlot; kMaxActiveReads as usize],
    pub(crate) head_: u32,
    pub(crate) tail_: u32,
    pub(crate) freeCursor_: u32,
    pub(crate) count_: usize,
}
impl ActiveReadList {
    /// Applies the member initializers to zeroed storage.
    pub(crate) fn init_defaults(&mut self) {
        for s in &mut self.slots_ {
            *s = ActiveReadListSlot::default();
        }
        self.head_ = kInvalid;
        self.tail_ = kInvalid;
        self.freeCursor_ = 0;
        self.count_ = 0;
    }
}

/// `ActiveReadList::iterator` (also used for `const_iterator`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveReadIt {
    pub(crate) owner_: *mut ActiveReadList,
    pub(crate) index_: u32,
}
pub(crate) type const_iterator = ActiveReadIt;
impl Default for ActiveReadIt {
    fn default() -> Self {
        Self {
            owner_: null_mut(),
            index_: kInvalid,
        }
    }
}
impl ActiveReadIt {
    /// `operator->`.
    pub(crate) fn ptr(self) -> *mut ActiveRead {
        unsafe { addr_of_mut!((*self.owner_).slots_[self.index_ as usize].value) }
    }
    /// `operator*`; the slot must be live.
    pub(crate) unsafe fn get<'a>(self) -> &'a mut ActiveRead {
        unsafe { &mut *self.ptr() }
    }
    /// `operator++`.
    pub(crate) fn inc(&mut self) -> &mut Self {
        if self.index_ != kInvalid {
            self.index_ = unsafe { (*self.owner_).slots_[self.index_ as usize].next };
        }
        self
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AioAdmissionSnapshot {
    pub(crate) activeCount: usize,
    pub(crate) smallCount: usize,
    pub(crate) classActive: [usize; AmprLooseReadClass::Count as usize],
    pub(crate) oldestSubmittedTimeNs: u64,
    pub(crate) oldestSubmittedAgeMs: u64,
    /// U, H, N
    pub(crate) groupActive: [u32; 3],
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AioAdmissionContext {
    pub(crate) snapshot: AioAdmissionSnapshot,
    pub(crate) laneNowNs: u64,
    pub(crate) effectiveLimit: u32,
    pub(crate) directFdCap: usize,
    pub(crate) laneDemandMask: u8,
    pub(crate) fdPressure: bool,
    pub(crate) initialized: bool,
    pub(crate) laneNowValid: bool,
    pub(crate) current: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum AioAgeThrottleLevel {
    #[default]
    Normal = 0,
    Medium = 1,
    Severe = 2,
    Emergency = 3,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct CursorReadWaitHint {
    pub(crate) valid: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum A53ReadGroup {
    #[default]
    Urgent = 0,
    High = 1,
    Normal = 2,
    Count = 3,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct A53ReadGroupCounts {
    pub(crate) values: [u32; A53ReadGroup::Count as usize],
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum DirectReadSubmitResult {
    Pending = 0,
    Staged = 1,
    #[default]
    Failed = 2,
}

/// `has_error()` is in read_window.rs.
#[derive(Clone, Copy)]
pub(crate) struct DirectReadSubmitOutcome {
    pub(crate) result: DirectReadSubmitResult,
    pub(crate) errorReason: *const c_char,
    pub(crate) errorRc: c_int,
    pub(crate) errorOffset: u32,
    pub(crate) backendRc: c_int,
}
impl Default for DirectReadSubmitOutcome {
    fn default() -> Self {
        Self {
            result: DirectReadSubmitResult::Failed,
            errorReason: null(),
            errorRc: 0,
            errorOffset: 0,
            backendRc: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SoftwareRead {
    pub(crate) fileId: u32,
    pub(crate) buffer: *mut c_void,
    pub(crate) length: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct CoalescedSoftwareRead {
    pub(crate) read: SoftwareRead,
    pub(crate) finalGs: GatherScatterState,
    pub(crate) sourceBytes: u32,
    pub(crate) commandCount: u32,
    pub(crate) gatherScatterCommandCount: u32,
}
impl Default for CoalescedSoftwareRead {
    fn default() -> Self {
        Self {
            commandCount: 1,
            ..unsafe { core::mem::zeroed() }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AioObservationResult {
    pub(crate) polled: bool,
    pub(crate) completed: bool,
}

pub(crate) struct AioPollBatch {
    pub(crate) items: [AioItemRef; kAioPollBatchLimit],
    pub(crate) ids: [SceKernelAioSubmitId; kAioPollBatchLimit],
    pub(crate) states: [c_int; kAioPollBatchLimit],
    pub(crate) count: usize,
}
impl Default for AioPollBatch {
    fn default() -> Self {
        Self {
            items: [AioItemRef::default(); kAioPollBatchLimit],
            ids: [0; kAioPollBatchLimit],
            states: [0; kAioPollBatchLimit],
            count: 0,
        }
    }
}

zeroed_default!(SoftwareRead);

pub(crate) const PREAD_FREE: u32 = 0;
pub(crate) const PREAD_QUEUED: u32 = 1;
pub(crate) const PREAD_RUNNING: u32 = 2;
pub(crate) const PREAD_DONE: u32 = 3;

/// One request of a pread-backed external group. Only the reactor publishes
/// or retires a slot; a pool thread claims it under preadMutex and publishes
/// completion with Release.
pub(crate) struct PreadTask {
    pub(crate) state: AtomicU32,
    pub(crate) request: SceKernelAioRWRequest,
    pub(crate) targetSlot: u32,
    pub(crate) targetGeneration: u32,
    pub(crate) requestIndex: u32,
    pub(crate) priority: c_int,
    pub(crate) sequence: u64,
    pub(crate) statQueuedNs: u64,
}

// ---- AprAioReactor ----------------------------------------------------------------

/// APR AIO reactor state. There are no log-only counters (aioInitLastRc,
/// aioInit{Attempt,Success,Busy,Fail}Count, aioSubmitEagainCount); parts skip
/// those writes. Members changed from `&self` methods are `Cell`s.
pub(crate) struct AprAioReactor {
    pub(crate) passWaitOnAddressPending: bool,
    pub(crate) passReadBlockedOnAioCapacity: bool,
    pub(crate) passReadBlockedOnFdBudget: bool,
    pub(crate) passLocalEqueueBackpressure: bool,
    pub(crate) capacityPollRequested: bool,
    pub(crate) nextCapacityPollNs: u64,
    pub(crate) capacityPollCursorSlot: u32,

    pub(crate) workerLifecycleMutex: Mutex,
    pub(crate) m: Mutex,
    pub(crate) reactorCv: Condvar,
    pub(crate) jobStateAvailableCv: Condvar,
    pub(crate) syntheticRequestAvailableCv: Condvar,
    pub(crate) syntheticLowerSlotAvailableCv: Condvar,
    pub(crate) syntheticWaitCvs: [Condvar; PRIO_N],
    pub(crate) stop: bool,
    pub(crate) shutdownRequested: AtomicBool,
    pub(crate) started: AtomicBool,
    pub(crate) reactorWakeEpoch: AtomicU64,
    /// Set by notify_external_progress (a pack job finished): the next poll pass
    /// polls every submitted active read instead of only the due ones.
    pub(crate) externalProgressPollAll: AtomicBool,
    pub(crate) workerObservedWakeEpoch: u64,
    pub(crate) nextFdCacheMaintenanceNs: u64,
    pub(crate) fdCacheMaintenanceBusyLoops: u32,
    pub(crate) aioInitState: AtomicU32,
    pub(crate) workerThread: ScePthread,
    /// Pread pool (pread_pool.rs); zeroed storage is the valid initial state.
    pub(crate) preadMutex: Mutex,
    pub(crate) preadCv: Condvar,
    pub(crate) preadThreads: [ScePthread; AMPR_EMU_PACK_PREAD_WORKERS],
    pub(crate) preadThreadCount: usize,
    pub(crate) preadStop: bool,
    pub(crate) preadPendingCount: u32,
    pub(crate) preadNextSequence: u64,
    pub(crate) preadTasks: [PreadTask; AMPR_EMU_PACK_PREAD_TASKS],

    pub(crate) activeJobHead: JobPtr,
    pub(crate) activeJobTail: JobPtr,
    pub(crate) activePriorityHeads: [JobPtr; PRIO_N],
    pub(crate) activePriorityTails: [JobPtr; PRIO_N],
    pub(crate) gatherScatterStates: [GatherScatterState; PRIO_N],
    pub(crate) activeJobCountAtomic: AtomicUsize,
    /// Spin lock word: `SpinLock::from_atomic(&self.jobStatePoolLock).lock()`.
    pub(crate) jobStatePoolLock: AtomicU32,
    pub(crate) jobStateFreeCount: AtomicU32,
    pub(crate) jobStateWaiterCount: AtomicU32,
    pub(crate) jobStateSlots: [JobStateSlot; kJobStatePoolCapacity as usize],
    pub(crate) jobStateFreeHead: u32,
    pub(crate) readChainSlots: [ReadChainSlot; kReadChainPoolCapacity as usize],
    pub(crate) readChainFreeHead: u32,
    pub(crate) liveReadChainCount: u32,
    pub(crate) activeReads: ActiveReadList,
    pub(crate) externalAioReads: [ExternalAioRead; kExternalAioCapacity as usize],
    pub(crate) aioSubmitRound: AioSubmitRound,
    pub(crate) submittedActiveReadCount: u32,
    pub(crate) deferredActiveReadCount: u32,
    pub(crate) externalAioLiveCount: AtomicU32,
    pub(crate) externalAioSubmittedCount: AtomicU32,
    pub(crate) externalAioDeferredCount: AtomicU32,
    pub(crate) cursorReadWaitHints: [CursorReadWaitHint; PRIO_N],
    pub(crate) aioAgeThrottleLevel: AioAgeThrottleLevel,
    pub(crate) aioSmallReadBoostBlockedUntilNs: u64,
    pub(crate) hotPollQueue: [ActiveReadRef; kHotPollQueueCapacity as usize],
    pub(crate) hotPollQueueHead: u32,
    pub(crate) hotPollQueueTail: u32,
    pub(crate) hotPollQueueCount: u32,
    pub(crate) activePollDeadlineHeap: [*mut ActiveRead; kMaxActiveReads as usize],
    pub(crate) activePollDeadlineHeapSize: u32,
    /// Spin lock word.
    pub(crate) nativeExecutionPoolLock: AtomicU32,
    pub(crate) nativeExecutionPoolInitAttempted: bool,
    pub(crate) nativeExecutionPoolReady: bool,
    pub(crate) nativeBatchPaddingHeaders: [u32; kAprNativeBatchPaddingHeaderCount as usize],
    pub(crate) nativeMicroTemplateReady: [bool; kJobStatePoolCapacity as usize],
    pub(crate) nativeBatchLanes: [NativeBatchLane; PRIO_N],
    pub(crate) syntheticWaitSlots: [SyntheticWaitSlot; kSyntheticRequestCapacity as usize],
    pub(crate) syntheticDoneSlots: [SyntheticDoneSlot; kSyntheticDoneCapacity as usize],
    pub(crate) syntheticLowerSlots: [SyntheticLowerSlot; kSyntheticLowerSlotCapacity as usize],
    pub(crate) syntheticWaitAllocCursor: u32,
    pub(crate) syntheticDoneHead: u32,
    pub(crate) syntheticDoneTail: u32,
    pub(crate) syntheticDoneFreeHead: u32,
    pub(crate) syntheticLowerAllocCursor: u32,
    pub(crate) slowAioCooldownUntilNs: u64,
    pub(crate) fdPressureUntilNs: core::cell::Cell<u64>,
    pub(crate) fdCachePressureCapApplied: core::cell::Cell<bool>,
    pub(crate) fdCacheOpenPressureSeen: core::cell::Cell<u64>,
}

impl AprAioReactor {
    /// Field initial values, applied in place (the object is ~2.5 MB,
    /// so it is never built on the stack). `construct` (worker.rs) calls this first.
    pub(crate) unsafe fn init_members(this: *mut Self) {
        unsafe { ptr::write_bytes(this, 0, 1) };
        // All-zero is a valid value for every field (Mutex/Condvar zero == new()).
        let r = unsafe { &mut *this };
        r.capacityPollCursorSlot = u32::MAX;
        r.jobStateFreeCount = AtomicU32::new(kJobStatePoolCapacity);
        for s in &mut r.jobStateSlots {
            s.nextFree = u32::MAX;
        }
        r.jobStateFreeHead = u32::MAX;
        for s in &mut r.readChainSlots {
            *s = ReadChainSlot::default();
        }
        r.readChainFreeHead = u32::MAX;
        r.activeReads.init_defaults();
        for e in &mut r.externalAioReads {
            e.init_defaults();
        }
        r.aioSubmitRound.reset();
        for h in &mut r.cursorReadWaitHints {
            *h = CursorReadWaitHint::default();
        }
        for q in &mut r.hotPollQueue {
            *q = ActiveReadRef::default();
        }
        for l in &mut r.nativeBatchLanes {
            *l = NativeBatchLane::default();
        }
        for d in &mut r.syntheticDoneSlots {
            *d = SyntheticDoneSlot::default();
        }
        r.syntheticDoneHead = u32::MAX;
        r.syntheticDoneTail = u32::MAX;
        r.syntheticDoneFreeHead = u32::MAX;
    }
}

// ---- globals; `apr_aio_reactor()` is in worker.rs----------------------------------

pub(crate) static g_apr_aio_reactor: AtomicPtr<AprAioReactor> = AtomicPtr::new(null_mut());
pub(crate) static g_apr_aio_reactor_init: AtomicU32 = AtomicU32::new(0);
pub(crate) static g_apr_aio_reactor_storage: SyncCell<MaybeUninit<AprAioReactor>> =
    SyncCell::new(MaybeUninit::zeroed());
