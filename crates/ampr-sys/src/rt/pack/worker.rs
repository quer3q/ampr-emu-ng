//! Virtual job completion, cache/fd waiter queues and the decode worker loop.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicI64};

pub(crate) unsafe fn complete_virtual_job(
    state: *mut PackState,
    index: u32,
    return_value: i64,
    completion_state: c_int,
) {
    let was_fd_waiter = (*state).virtual_aio[index as usize].phase == VirtualAioPhase::WaitingFd
        && (*state).virtual_aio[index as usize].pipeline_index != INVALID_INDEX;
    release_pipeline_locked(state, index);
    if was_fd_waiter {
        PACK_FD_WAITER_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
    if (*state).virtual_aio[index as usize].prefetch_chunks != 0 {
        finish_prefetch_locked(state, index);
        return;
    }
    let split_group = (*state).virtual_aio[index as usize].split_group;
    let job = &mut (*state).virtual_aio[index as usize];
    let job_ns = stats::since(job.submit_ns);
    stats::add(stats::Stat::PackJobs, 1);
    stats::add(stats::Stat::PackJobNs, job_ns);
    stats::max(stats::Stat::PackJobNsMax, job_ns);
    if return_value < 0 {
        stats::add(stats::Stat::PackJobErrors, 1);
    }
    job.return_value = return_value;
    job.completion_state = completion_state;
    let result = job.request.result;
    if !result.is_null() {
        unsafe {
            AtomicI64::from_ptr(&raw mut (*result).return_value)
                .store(return_value, Ordering::Relaxed);
            AtomicU32::from_ptr(&raw mut (*result).state)
                .store(completion_state as u32, Ordering::Release);
        }
    }
    job.phase = VirtualAioPhase::Done;
    // zstd: the last child of a split read writes the caller's result.
    if split_group != INVALID_INDEX {
        unsafe { finish_split_child_locked(state, split_group) };
    }
    (*state).aio_completion_epoch += 1;
    // Broadcast: AIO_CV waiters are game threads waiting on different ids
    // (aio_wait.rs), and a single signal could reach one this job is not for.
    AIO_CV.notify_all();
    unsafe { apr_reactor_notify_external_progress() };
}

/// Debug: the job parks now (`kind` b'i' disk, b'c' cache page, b'f' fd).
fn note_park(job: &mut VirtualAioSlot, kind: u8) {
    if cfg!(feature = "mem_report") {
        (job.parked_ns, job.park_kind, job.requeued_ns) = (stats::now(), kind, 0);
    }
}

/// Debug: a parked job is picked up again; splits its wait at the requeue.
fn note_unpark(job: &mut VirtualAioSlot) {
    if job.parked_ns == 0 {
        return;
    }
    let now = stats::now();
    let requeued = if job.requeued_ns == 0 {
        now
    } else {
        job.requeued_ns
    };
    let (count, ns) = match job.park_kind {
        b'i' => (stats::Stat::ParkIos, stats::Stat::ParkIoNs),
        b'c' => (stats::Stat::ParkCaches, stats::Stat::ParkCacheNs),
        _ => (stats::Stat::ParkFds, stats::Stat::ParkFdNs),
    };
    stats::add(count, 1);
    stats::add(ns, requeued.saturating_sub(job.parked_ns));
    stats::add(stats::Stat::Requeues, 1);
    stats::add(stats::Stat::RequeueNs, now.saturating_sub(requeued));
    (job.parked_ns, job.requeued_ns) = (0, 0);
}

/// zstd: frees `worker`'s decoder (thread create failure, pack shutdown).
pub(crate) unsafe fn release_worker_decoder(worker: &mut WorkerContext) {
    if !worker.decoder.is_null() {
        drop(unsafe { alloc::boxed::Box::from_raw(worker.decoder) });
        worker.decoder = null_mut();
    }
}

pub(crate) unsafe fn queue_cache_waiter_locked(
    state: *mut PackState,
    owner: u32,
    queued_at_usec: u64,
) {
    if owner as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS
        || (*state).virtual_aio[owner as usize].phase != VirtualAioPhase::WaitingCache
        || (*state).cache_waiter_count == 0
    {
        abort();
    }
    (*state).cache_waiter_count -= 1;
    queue_push_locked(state, owner, queued_at_usec);
}

pub(crate) unsafe fn queue_fd_waiter_locked(
    state: *mut PackState,
    owner: u32,
    queued_at_usec: u64,
) {
    if owner as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS
        || (*state).virtual_aio[owner as usize].phase != VirtualAioPhase::WaitingFd
        || (*state).fd_waiter_count == 0
    {
        abort();
    }
    (*state).fd_waiter_count -= 1;
    PACK_FD_WAITER_COUNT.fetch_sub(1, Ordering::SeqCst);
    queue_push_locked(state, owner, queued_at_usec);
}

pub(crate) unsafe fn wake_cache_waiters_locked(state: *mut PackState) -> bool {
    if (*state).cache_waiter_count == 0 {
        return false;
    }
    let mut queued = false;
    let now_usec = pack_telemetry_usecs();
    for index in 0..(*state).pipeline_capacity as usize {
        let p = &(*state).pipelines[index];
        let epoch = cache_wait_epoch(state, p.cache_wait_domain, p.cache_wait_bucket as u32);
        let (active, owner, wait_epoch) = (p.active, p.owner, p.cache_wait_epoch);
        if !active || owner == INVALID_INDEX || wait_epoch == epoch {
            continue;
        }
        if (*state).virtual_aio[owner as usize].phase != VirtualAioPhase::WaitingCache {
            continue;
        }
        (*state).pipelines[index].cache_wait_epoch = epoch;
        queue_cache_waiter_locked(state, owner, now_usec);
        queued = true;
    }
    queued
}

pub(crate) unsafe fn wake_fd_waiters_locked(state: *mut PackState) -> bool {
    if (*state).fd_waiter_count == 0 {
        return false;
    }
    let epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Acquire);
    let budget_epoch = ampr_index_fd_open_budget_progress_generation();
    let mut queued = false;
    let now_usec = pack_telemetry_usecs();
    for index in 0..(*state).pipeline_capacity as usize {
        let p = &mut (*state).pipelines[index];
        if !p.active
            || p.owner == INVALID_INDEX
            || (p.fd_wait_epoch == epoch && p.fd_budget_wait_epoch == budget_epoch)
        {
            continue;
        }
        let owner = p.owner;
        if (*state).virtual_aio[owner as usize].phase != VirtualAioPhase::WaitingFd {
            continue;
        }
        let p = &mut (*state).pipelines[index];
        p.fd_wait_epoch = epoch;
        p.fd_budget_wait_epoch = budget_epoch;
        queue_fd_waiter_locked(state, owner, now_usec);
        queued = true;
    }
    queued
}

// ---- worker count ----
//
// Pack workers start at PACK_WORKERS_START (1). When a job is queued and no
// worker waits, one more starts, up to the ceiling (AMPR_EMU_PACK_WORKERS, 4;
// debug `workers`) and the thread budget (rt/thread_hooks.rs). A worker
// that finishes a job leaves when more are live than the load target
// (thread_hooks::LoadGroup). Under pressure (a game thread creation
// failed) workers leave down to one. The last never leaves, in any mode: a
// queued job has no other thread to run on, and a restart can fail with
// the game at its limit, which left a job queued with no worker and no
// later call to start one. Only the thread leaves: each worker's
// 1 MiB scratch is made once at prepare (ensure_workers_locked) and kept
// until shutdown, so a restart allocates nothing but the zstd decoder.
// Decode took ~0.21 cores on a zstd title (debug /metrics worker_step_ns).

const PACK_WORKERS_START: u32 = 1;
/// Busy-worker samples and the load target (rt/thread_hooks.rs).
/// Floor 1: the last worker stays (see above).
static WORKER_LOAD: super::super::thread_hooks::LoadGroup =
    super::super::thread_hooks::LoadGroup::new(1);

/// Live workers, waiting workers, exits asked and the ceiling (0 until the
/// workers start), all under PACK_M.
static WORKERS_LIVE: AtomicU32 = AtomicU32::new(0);
static WORKERS_IDLE: AtomicU32 = AtomicU32::new(0);
static WORKER_EXIT_REQUESTS: AtomicU32 = AtomicU32::new(0);
static WORKERS_CEILING: AtomicU32 = AtomicU32::new(0);
const WORKER_RUNNING: u8 = 0;
const WORKER_EXITED: u8 = 1;
/// A worker left: the next worker through its loop joins it (under PACK_M),
/// since an exited thread not yet joined may still count against the game's
/// limit.
static WORKER_REAP_PENDING: AtomicBool = AtomicBool::new(false);
static WORKER_EXIT_STATE: [core::sync::atomic::AtomicU8; AMPR_EMU_PACK_WORKER_CAPACITY] =
    [const { core::sync::atomic::AtomicU8::new(WORKER_RUNNING) }; AMPR_EMU_PACK_WORKER_CAPACITY];

/// Smallest worker stack the `worker_stack_kib` knob may set. The deepest
/// worker chain in the debug PRX is ~30 KiB: pack_worker_entry 17.5 KiB
/// frame (advance_virtual_read_aio inlined), cleanup_pipeline_continuation
/// 8 KiB, abandon_mandatory_page_plan 2 KiB; the zstd path is
/// prepare_mandatory_page_group_capped 4.4 KiB plus
/// zstd_append_mandatory_requests 4.4 KiB, and zstd decode frames stay under
/// 1 KiB each (DCtx is heap). 64 KiB, libkernel's default, keeps 2x margin
/// for libkernel and libc calls below those frames.
const WORKER_STACK_MIN: usize = 64 * 1024;

/// Worker stack size for create_counted: 0 (libkernel default) or the knob,
/// raised to WORKER_STACK_MIN.
fn worker_stack() -> usize {
    match super::super::tune::worker_stack_bytes() {
        0 => 0,
        bytes => bytes.max(WORKER_STACK_MIN),
    }
}

// ---- idle spin ----
//
// With tune::spin_us() > 0 an idle worker spins that long, PACK_M released,
// before it parks on QUEUE_CV, so a job queued right after the last one
// finished skips a cond wake. At most one worker spins (WORKER_SPINNING).
// The spinner stays counted in WORKERS_IDLE, so no worker starts for a job
// it will take, and it re-checks under PACK_M before parking, so a signal
// sent while it spun (none was waiting) loses nothing.

/// Bumped under PACK_M on every queue push and pipeline release
/// (schedule.rs); the spinner polls it without the lock.
pub(crate) static QUEUE_EPOCH: AtomicU32 = AtomicU32::new(0);
static WORKER_SPINNING: AtomicBool = AtomicBool::new(false);

/// Under PACK_M (held by `g`): spins up to tune::spin_us() with the lock
/// released until queue, fd, exit or stop state moves. Returns false at
/// once when spinning is off or another worker spins. PACK_M is held again
/// on return either way.
fn idle_spin(g: &mut crate::rt::sync::MutexGuard<'_>) -> bool {
    let spin_us = super::super::tune::spin_us();
    if spin_us == 0
        || WORKER_SPINNING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return false;
    }
    let queue_epoch = QUEUE_EPOCH.load(Ordering::Relaxed);
    let fd_epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Relaxed);
    let moved = || {
        QUEUE_EPOCH.load(Ordering::Relaxed) != queue_epoch
            || PACK_FD_PROGRESS_EPOCH.load(Ordering::Relaxed) != fd_epoch
            || WORKER_EXIT_REQUESTS.load(Ordering::Relaxed) != 0
            || WORKER_REAP_PENDING.load(Ordering::Relaxed)
            || WORKER_STOP_REQUESTED.load(Ordering::Relaxed)
    };
    let mutex = g.mutex();
    let end = super::super::services::time_counter_now() + spin_us as u64 * 1000;
    unsafe { mutex.unlock_raw() };
    let mut spins = 0u32;
    while !moved() && super::super::services::time_counter_now() < end {
        crate::rt::sync::spin_pause_or_yield(&mut spins);
    }
    unsafe { mutex.lock_raw() };
    WORKER_SPINNING.store(false, Ordering::Release);
    true
}

// ---- queue wake-ups ----

/// Under PACK_M: jobs in the scheduling queues (not read-ahead).
unsafe fn queued_jobs_locked(state: *const PackState) -> u32 {
    unsafe { (*state).queue_depth.iter().sum() }
}

/// Under PACK_M: one QUEUE_CV signal serves `queued` new jobs when there is
/// at most one and any waiting worker can take it (no latency reserve,
/// which keeps reserved workers off bulk jobs). Same rule as aio.rs and
/// fd_read.rs. A signal with no waiter loses no job: busy workers and the
/// spinner re-check the queue under PACK_M before they park.
pub(crate) unsafe fn single_wake_locked(state: *const PackState, queued: u32) -> bool {
    queued <= 1 && unsafe { effective_latency_reserve_locked(state) } == 0
}

/// Wakes one waiting worker when `single` (single_wake_locked), else all.
pub(crate) fn wake_queue_workers(single: bool) {
    if single {
        QUEUE_CV.notify_one();
    } else {
        QUEUE_CV.notify_all();
    }
}

/// Under PACK_M: pack work a worker must finish: queued or read-ahead jobs,
/// or a live pipeline (its job parked on I/O, cache or a descriptor).
unsafe fn pack_work_locked(state: *const PackState) -> bool {
    unsafe {
        queued_jobs_locked(state) != 0
            || (*state).prefetch_head != INVALID_INDEX
            || (*state).pipeline_active_count != 0
    }
}

/// Under PACK_M: an exit is asked and another worker stays (the last never
/// leaves, see the worker count notes).
fn worker_exit_due() -> bool {
    WORKER_EXIT_REQUESTS.load(Ordering::Relaxed) != 0 && WORKERS_LIVE.load(Ordering::Relaxed) > 1
}

/// Debug /metrics: live workers and their ceiling.
#[cfg(feature = "mem_report")]
pub(crate) fn pack_workers_state() -> (u32, u32) {
    (
        WORKERS_LIVE.load(Ordering::Relaxed),
        WORKERS_CEILING.load(Ordering::Relaxed),
    )
}

/// Debug /metrics: the decode group's load counters (LoadGroup::metrics).
#[cfg(feature = "mem_report")]
pub(crate) fn pack_workers_load() -> [u64; 5] {
    let _g = PACK_M.lock();
    WORKER_LOAD.metrics()
}

/// Under PACK_M: joins workers that left (they hold no lock any more once
/// PACK_M is free to take) and frees their slots for a restart.
unsafe fn reap_workers_locked(state: *mut PackState) {
    // Shutdown joins every worker itself (fd_read.rs `ampr_pack_shutdown`,
    // after taking PACK_M once so no reap is in progress).
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return;
    }
    for i in 0..AMPR_EMU_PACK_WORKER_CAPACITY {
        if WORKER_EXIT_STATE[i].load(Ordering::Acquire) != WORKER_EXITED {
            continue;
        }
        let worker = &mut (*state).workers[i];
        if worker.started {
            let _ = unsafe { scePthreadJoin(worker.thread, null_mut()) };
            unsafe { release_worker_decoder(worker) };
            worker.started = false;
            (*state).workers_started = (*state).workers_started.saturating_sub(1);
            PROFILE_STARTED_WORKERS.store((*state).workers_started, Ordering::Release);
        }
        WORKER_EXIT_STATE[i].store(WORKER_RUNNING, Ordering::Release);
    }
}

/// Under PACK_M: starts the thread of prepared worker slot `i`; on failure
/// the ceiling drops to the live count (no room).
unsafe fn spawn_worker_locked(state: *mut PackState, i: usize) -> bool {
    let worker = &mut (*state).workers[i];
    if worker.started || worker.decoded_scratch.is_null() {
        return false;
    }
    // The runtime-wide thread budget (rt/thread_hooks.rs), before the
    // decoder: a worker the budget refuses keeps no heap.
    if !super::super::thread_hooks::reserve(WORKERS_LIVE.load(Ordering::Relaxed) == 0) {
        return false;
    }
    // zstd only: one decoder per live worker, not per possible one, since it
    // comes out of the game's libc heap. Its buffers are allocated now, not on
    // a game read; the scratch holds a whole zstd chunk (256 KiB, zstd.rs).
    if zstd_mode() && worker.decoder.is_null() {
        let mut decoder = alloc::boxed::Box::new(ampr_codec::ZstdDecoder::new());
        if super::super::tune::zstd_verify() {
            let _ = decoder.set_verify_checksum(true);
        }
        let scratch = unsafe {
            core::slice::from_raw_parts_mut(worker.decoded_scratch, worker.decoded_scratch_size)
        };
        let _ = decoder.warm_up(scratch);
        worker.decoder = alloc::boxed::Box::into_raw(decoder);
    }
    let arg = worker as *mut WorkerContext as *mut c_void;
    let rc = unsafe {
        super::super::thread_hooks::create_counted(
            (&mut worker.thread as *mut ScePthread).cast(),
            pack_worker_entry,
            arg,
            c"ampr_pack_worker".as_ptr(),
            worker_stack(),
        )
    };
    if rc != 0 {
        // create_counted released the slot and cut the budget; the ceiling
        // stays, so the workers grow again when the budget does.
        unsafe { release_worker_decoder(worker) };
        stats::add(stats::Stat::PackWorkerCreateFailed, 1);
        return false;
    }
    worker.started = true;
    WORKER_EXIT_STATE[i].store(WORKER_RUNNING, Ordering::Release);
    let live = WORKERS_LIVE.fetch_add(1, Ordering::Release) + 1;
    WORKER_LOAD.started(live);
    (*state).workers_started += 1;
    PROFILE_STARTED_WORKERS.store((*state).workers_started, Ordering::Release);
    (*state).worker_capacity = (*state).worker_capacity.max((*state).workers_started);
    stats::add(stats::Stat::PackWorkersStarted, 1);
    true
}

/// Under PACK_M, after a job was queued: one more worker when none waits,
/// only the first under pressure (LoadGroup::may_grow). Before the workers
/// were prepared the ceiling is 0, so nothing starts here.
pub(crate) unsafe fn maybe_grow_workers_locked(state: *mut PackState) {
    let live = WORKERS_LIVE.load(Ordering::Relaxed);
    if WORKERS_IDLE.load(Ordering::Relaxed) != 0
        || live >= WORKERS_CEILING.load(Ordering::Relaxed)
        || WORKER_STOP_REQUESTED.load(Ordering::Acquire)
        || !WORKER_LOAD.may_grow(live)
    {
        return;
    }
    unsafe { reap_workers_locked(state) };
    if let Some(i) = (0..AMPR_EMU_PACK_WORKER_CAPACITY)
        .find(|&i| !(*state).workers[i].started && !(*state).workers[i].decoded_scratch.is_null())
    {
        let _ = unsafe { spawn_worker_locked(state, i) };
    }
}

/// Under PACK_M, after read-ahead was queued: a worker when none is live
/// (all left under pressure). Read-ahead alone grows no more than that.
pub(crate) unsafe fn start_first_worker_locked(state: *mut PackState) {
    if WORKERS_LIVE.load(Ordering::Relaxed) == 0 {
        unsafe { maybe_grow_workers_locked(state) };
    }
}

/// Pack worker exits asked (`pack_workers_ask`) not yet done; none after
/// shutdown began, which joins every worker without meeting them.
pub(crate) fn pack_workers_pending_exits() -> u32 {
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return 0;
    }
    WORKER_EXIT_REQUESTS.load(Ordering::Relaxed)
}

/// Live pack workers (make_room counts what a yield gave from it).
pub(crate) fn pack_workers_live() -> u32 {
    WORKERS_LIVE.load(Ordering::Acquire)
}

/// Asks up to `want` pack workers to leave, never the last, and wakes them.
/// Returns how many it asked. Called from a game thread whose creation
/// failed, which then waits (`make_room`) and calls `pack_workers_reap`.
pub(crate) unsafe fn pack_workers_ask(want: u32) -> u32 {
    let state = g_pack_state.load(Ordering::Acquire);
    if state.is_null() {
        return 0;
    }
    let _g = PACK_M.lock();
    WORKER_LOAD.asked();
    // Exits other yields already asked for are not given twice.
    let give = super::super::thread_hooks::exits_to_ask(
        want,
        WORKERS_LIVE.load(Ordering::Relaxed),
        1,
        WORKER_EXIT_REQUESTS.load(Ordering::Relaxed),
    );
    if give != 0 {
        WORKER_EXIT_REQUESTS.fetch_add(give, Ordering::Relaxed);
        // Broadcast: every waiting worker re-checks worker_exit_due.
        QUEUE_CV.notify_all();
    }
    give
}

/// Joins the workers that left since `before` were live and counts them.
pub(crate) unsafe fn pack_workers_reap(before: u32) -> u32 {
    let state = g_pack_state.load(Ordering::Acquire);
    if state.is_null() {
        return 0;
    }
    let _g = PACK_M.lock();
    unsafe { reap_workers_locked(state) };
    let released = before.saturating_sub(WORKERS_LIVE.load(Ordering::Relaxed));
    stats::add(stats::Stat::PackWorkersYielded, released as u64);
    WORKER_LOAD.yielded(released);
    released
}

/// `pack_workers_ask`, up to 50 ms for the workers to leave, then
/// `pack_workers_reap` (debug /threads).
#[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
pub(crate) unsafe fn pack_workers_yield(want: u32) -> u32 {
    let before = pack_workers_live();
    let give = unsafe { pack_workers_ask(want) };
    if give == 0 {
        return 0;
    }
    for _ in 0..50 {
        if WORKER_EXIT_REQUESTS.load(Ordering::Acquire) == 0 {
            break;
        }
        unsafe { sceKernelUsleep(1000) };
    }
    unsafe { pack_workers_reap(before) }
}

pub(crate) unsafe extern "C" fn pack_worker_entry(argument: *mut c_void) -> *mut c_void {
    let worker = argument as *mut WorkerContext;
    if worker.is_null() {
        return null_mut();
    }
    let sp: *mut PackState = unsafe { pack_state() };
    unsafe {
        let _ = scePthreadSetprio(scePthreadSelf(), AMPR_EMU_PACK_WORKER_PRIORITY);
        if AMPR_EMU_PACK_WORKER_AFFINITY != 0 {
            let _ = scePthreadSetaffinity(scePthreadSelf(), AMPR_EMU_PACK_WORKER_AFFINITY);
        }
    }
    let worker_index = unsafe { (*worker).index };
    // A job just finished: the next pass decides whether this worker stays.
    let mut finished = false;
    loop {
        let index: u32;
        let pipeline: *mut ReadPipelineContext;
        {
            let mut g = PACK_M.lock();
            let state = sp;
            // One spin per idle stretch: after it, the worker parks.
            let mut spun = false;
            // On stop, stay until every pipeline is released: a native read
            // still in flight requeues its owner, which needs a worker to
            // clean up (release_pipeline_locked aborts on a live pipeline).
            loop {
                if WORKER_REAP_PENDING.swap(false, Ordering::AcqRel) {
                    unsafe { reap_workers_locked(state) };
                }
                let stopping = WORKER_STOP_REQUESTED.load(Ordering::Acquire);
                let ready = (stopping && (*state).pipeline_active_count == 0)
                    || worker_exit_due()
                    || wake_fd_waiters_locked(state)
                    || queue_has_work_for_worker_locked(state, worker_index)
                    || prefetch_has_work_for_worker_locked(state, worker_index);
                // After a job, above the load target: leave (never the
                // last, WORKER_LOAD's floor), meeting an exit asked of the
                // group if any.
                if core::mem::take(&mut finished)
                    && !stopping
                    && WORKER_LOAD.retire_due(
                        WORKERS_LIVE.load(Ordering::Relaxed),
                        WORKERS_CEILING.load(Ordering::Relaxed),
                        ready || pack_work_locked(state),
                    )
                {
                    let _ = super::super::thread_hooks::take_exit_request(&WORKER_EXIT_REQUESTS);
                    WORKERS_LIVE.fetch_sub(1, Ordering::Release);
                    WORKER_EXIT_STATE[worker_index as usize]
                        .store(WORKER_EXITED, Ordering::Release);
                    WORKER_REAP_PENDING.store(true, Ordering::Release);
                    // Pass the wake-up on in case it was meant for a queued
                    // job; another worker also reaps this one.
                    wake_queue_workers(single_wake_locked(state, 1));
                    return null_mut();
                }
                if ready {
                    break;
                }
                WORKERS_IDLE.fetch_add(1, Ordering::Relaxed);
                if !spun && idle_spin(&mut g) {
                    // Re-check under PACK_M before parking.
                    spun = true;
                    WORKERS_IDLE.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                QUEUE_CV.wait(&mut g);
                WORKERS_IDLE.fetch_sub(1, Ordering::Relaxed);
            }
            // Given back to the game: leave between jobs, and pass the
            // wake-up on in case it was meant for a queued job. A wait ends
            // on at most one signal, and pack_workers_ask already
            // broadcast to the rest, so one is enough.
            if worker_exit_due() && !WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
                WORKER_EXIT_REQUESTS.fetch_sub(1, Ordering::Relaxed);
                WORKERS_LIVE.fetch_sub(1, Ordering::Release);
                WORKER_EXIT_STATE[worker_index as usize].store(WORKER_EXITED, Ordering::Release);
                WORKER_REAP_PENDING.store(true, Ordering::Release);
                wake_queue_workers(single_wake_locked(state, 1));
                return null_mut();
            }
            if WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                && (*state).pipeline_active_count == 0
                && !queue_has_work_for_worker_locked(state, worker_index)
            {
                // Shutdown: every worker must see the stop and leave
                // (release_pipeline_locked may wake only one).
                QUEUE_CV.notify_all();
                return null_mut();
            }
            index = match queue_pop_locked(state, worker_index) {
                INVALID_INDEX => prefetch_pop_locked(state, worker_index),
                popped => popped,
            };
            if index == INVALID_INDEX {
                continue;
            }
            let pipeline_index = (*state).virtual_aio[index as usize].pipeline_index;
            if pipeline_index == INVALID_INDEX {
                pipeline = acquire_pipeline_locked(state, index);
                if pipeline.is_null() {
                    queue_push_locked(state, index, 0);
                    continue;
                }
                stats::add(stats::Stat::JobsStarted, 1);
                stats::add(
                    stats::Stat::QueueFirstNs,
                    stats::since((*state).virtual_aio[index as usize].submit_ns),
                );
            } else {
                if pipeline_index >= (*state).pipeline_capacity {
                    abort();
                }
                pipeline = &raw mut (*state).pipelines[pipeline_index as usize];
                let p = unsafe { &*pipeline };
                if !p.active || p.owner != index {
                    abort();
                }
                note_unpark(&mut (*state).virtual_aio[index as usize]);
            }
            (*state).virtual_aio[index as usize].phase = VirtualAioPhase::Running;
            WORKER_LOAD.begin();
        }

        let job: *mut VirtualAioSlot = unsafe { &raw mut (*sp).virtual_aio[index as usize] };
        let mut return_value: i64 = 0;
        let mut pipeline_error: c_int = 0;
        let step_start = stats::now();
        let mut step = unsafe {
            advance_virtual_read_aio(
                &mut *job,
                &mut *worker,
                &mut *pipeline,
                &mut return_value,
                &mut pipeline_error,
            )
        };
        stats::add(stats::Stat::WorkerStepNs, stats::since(step_start));
        // Read-ahead never competes for pack descriptors. (It skips decoded
        // chunks being loaded, so a cache wait here is on a physical page.)
        if unsafe { (*job).prefetch_chunks } != 0 && step == PipelineStep::YieldFd {
            unsafe { cleanup_pipeline_continuation(&mut *pipeline, SCE_KERNEL_ERROR_EAGAIN) };
            step = PipelineStep::Failed;
        }
        let mut notify_workers;
        let queued_before;
        let single_wake;
        {
            let _g = PACK_M.lock();
            WORKER_LOAD.end();
            finished = true;
            let state = sp;
            queued_before = unsafe { queued_jobs_locked(state) };
            let p = unsafe { &mut *pipeline };
            notify_workers = wake_cache_waiters_locked(state);
            let canceled_or_stopping = || unsafe { job_canceled_or_stopping(job) };
            match step {
                PipelineStep::YieldIo => {
                    if canceled_or_stopping() {
                        queue_push_locked(state, index, pack_telemetry_usecs());
                        notify_workers = true;
                    } else if submit_pipeline_io_locked(state, index, job, p) {
                        notify_workers = true;
                    }
                }
                PipelineStep::YieldCache => {
                    if park_on_cache_locked(state, index, job, p) {
                        notify_workers = true;
                    }
                }
                PipelineStep::YieldFd => {
                    if park_on_fd_locked(state, index, job, p) {
                        notify_workers = true;
                    }
                }
                PipelineStep::Complete => unsafe {
                    complete_virtual_job(
                        state,
                        index,
                        return_value,
                        SCE_KERNEL_AIO_STATE_COMPLETED,
                    );
                },
                PipelineStep::Failed => {
                    let canceled = pipeline_error == SCE_KERNEL_ERROR_ECANCELED
                        || unsafe { (*job).cancel_requested.load(Ordering::Relaxed) };
                    let completion = if canceled {
                        SCE_KERNEL_AIO_STATE_ABORTED
                    } else {
                        SCE_KERNEL_AIO_STATE_COMPLETED
                    };
                    unsafe {
                        complete_virtual_job(state, index, pipeline_error as i64, completion)
                    };
                }
                PipelineStep::Ready => abort(),
            }
            // Nothing pops in this block, so the depth grew by the jobs it
            // queued (requeue, woken cache waiters).
            let queued = unsafe { queued_jobs_locked(state) }.saturating_sub(queued_before);
            single_wake = unsafe { single_wake_locked(state, queued) };
        }
        if notify_workers {
            wake_queue_workers(single_wake);
        }
    }
}

#[inline]
unsafe fn job_canceled_or_stopping(job: *mut VirtualAioSlot) -> bool {
    (unsafe { (*job).cancel_requested.load(Ordering::Acquire) })
        || WORKER_STOP_REQUESTED.load(Ordering::Acquire)
}

/// Hands the pipeline's backing read (mandatory group or window) to the
/// reactor. A refused submit requeues the job to finish with that error;
/// returns true then (workers to wake).
unsafe fn submit_pipeline_io_locked(
    state: *mut PackState,
    index: u32,
    job: *mut VirtualAioSlot,
    p: &mut ReadPipelineContext,
) -> bool {
    unsafe {
        (*state).virtual_aio[index as usize].phase = VirtualAioPhase::IoQueued;
        p.native_accepted = true;
        let count = p.mandatory_request_count;
        let mandatory_group = p.mandatory_plan_active && count != 0;
        let physical_bytes: usize = if mandatory_group {
            p.mandatory_requests[..count].iter().map(|r| r.nbyte).sum()
        } else {
            p.native_request.nbyte
        };
        let (priority, work_class) = ((*job).priority, (*job).work_class);
        let aio_priority = native_pack_priority(priority);
        let io_class = native_pack_io_class(work_class, physical_bytes);
        let ctx = p as *mut ReadPipelineContext as *mut c_void;
        let submit_rc = if mandatory_group && count > 1 {
            reactor::apr_reactor_submit_external_aio_read_group(
                p.mandatory_requests.as_ptr().cast(),
                count,
                aio_priority,
                io_class.into(),
                ctx,
                Some(complete_pack_backing_aio_adapter),
            )
        } else {
            let request = if mandatory_group {
                &p.mandatory_requests[0]
            } else {
                &p.native_request
            };
            reactor::apr_reactor_submit_external_aio_read(
                (request as *const SceKernelAioRWRequest).cast(),
                aio_priority,
                io_class.into(),
                ctx,
                Some(complete_pack_backing_aio_adapter),
            )
        };
        if submit_rc == 0 {
            note_park(&mut (*state).virtual_aio[index as usize], b'i');
            let reads = if mandatory_group { count } else { 1 };
            stats::add(stats::Stat::PackDiskReads, reads as u64);
            disk_inflight_add(p, reads as u32);
            stats::add(stats::Stat::PackDiskBytes, physical_bytes as u64);
        }
        if submit_rc != 0 {
            p.native_accepted = false;
            p.native_io_error = submit_rc;
            p.native_completion_ready = true;
            queue_push_locked(state, index, pack_telemetry_usecs());
            return true;
        }
        false
    }
}

/// Parks the job until its cache wait bucket moves, or requeues it when the
/// bucket already moved or the job is canceled or stopping (returns true).
unsafe fn park_on_cache_locked(
    state: *mut PackState,
    index: u32,
    job: *mut VirtualAioSlot,
    p: &mut ReadPipelineContext,
) -> bool {
    unsafe {
        let epoch = cache_wait_epoch(state, p.cache_wait_domain, p.cache_wait_bucket as u32);
        if job_canceled_or_stopping(job) || epoch != p.cache_wait_epoch {
            p.cache_wait_epoch = epoch;
            queue_push_locked(state, index, pack_telemetry_usecs());
            return true;
        }
        (*state).virtual_aio[index as usize].phase = VirtualAioPhase::WaitingCache;
        note_park(&mut (*state).virtual_aio[index as usize], b'c');
        (*state).cache_waiter_count += 1;
        false
    }
}

/// Parks the job until pack fd progress, or requeues it when an fd or open
/// budget already moved or the job is canceled or stopping (returns true).
unsafe fn park_on_fd_locked(
    state: *mut PackState,
    index: u32,
    job: *mut VirtualAioSlot,
    p: &mut ReadPipelineContext,
) -> bool {
    unsafe {
        PACK_FD_WAITER_COUNT.fetch_add(1, Ordering::SeqCst);
        core::sync::atomic::fence(Ordering::SeqCst);
        let epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Acquire);
        let budget_epoch = ampr_index_fd_open_budget_progress_generation();
        if job_canceled_or_stopping(job)
            || epoch != p.fd_wait_epoch
            || budget_epoch != p.fd_budget_wait_epoch
        {
            PACK_FD_WAITER_COUNT.fetch_sub(1, Ordering::SeqCst);
            p.fd_wait_epoch = epoch;
            p.fd_budget_wait_epoch = budget_epoch;
            queue_push_locked(state, index, pack_telemetry_usecs());
            return true;
        }
        (*state).virtual_aio[index as usize].phase = VirtualAioPhase::WaitingFd;
        note_park(&mut (*state).virtual_aio[index as usize], b'f');
        (*state).fd_waiter_count += 1;
        false
    }
}

pub(crate) unsafe fn ensure_workers_locked(state: *mut PackState) -> bool {
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return false;
    }
    if (*state).workers_started != 0 {
        return true;
    }
    if (*state).pipeline_capacity == 0 {
        (*state).pipeline_free_head = INVALID_INDEX;
        for i in 0..super::super::tune::pipelines().min(AMPR_EMU_PACK_PIPELINE_SLOTS) {
            let pipeline = &mut (*state).pipelines[i];
            pipeline.io_window_pack_id = u16::MAX;
            pipeline.owner = INVALID_INDEX;
            pipeline.next_free = (*state).pipeline_free_head;
            (*state).pipeline_free_head = i as u32;
            (*state).pipeline_capacity += 1;
        }
    }
    if (*state).pipeline_capacity == 0 {
        return false;
    }

    let requested_workers = (*state).requested_workers.min((*state).pipeline_capacity);
    // Every worker's scratch now, kept until shutdown; threads start at
    // PACK_WORKERS_START and grow on demand (maybe_grow_workers_locked).
    let mut prepared = 0u32;
    for i in 0..requested_workers as usize {
        let worker = &mut (*state).workers[i];
        worker.index = i as u32;
        // Prepared by an earlier call whose first spawn failed: reuse it, or
        // each retry would allocate new scratch over it and leak it.
        if !worker.decoded_scratch.is_null() {
            prepared += 1;
            continue;
        }
        // The pool, under the Buffer ledger (rt/index_memory.rs).
        let (scratch, _) = unsafe {
            crate::rt::index_memory::buffer_alloc(
                PACK_MAX_BLOCK_BYTES,
                c"apr.pack.worker.decoded".as_ptr(),
            )
        };
        if scratch.is_null() {
            *worker = WorkerContext::EMPTY;
            continue;
        }
        worker.decoded_scratch = scratch;
        worker.decoded_scratch_size = PACK_MAX_BLOCK_BYTES;
        // The zstd decoder (libc heap) is made when the thread starts and
        // freed when it leaves (spawn_worker_locked, reap_workers_locked).
        prepared += 1;
    }
    WORKERS_CEILING.store(prepared, Ordering::Relaxed);
    let mut started = 0;
    for i in 0..requested_workers as usize {
        if started >= PACK_WORKERS_START {
            break;
        }
        if unsafe { spawn_worker_locked(state, i) } {
            started += 1;
        }
    }
    (*state).workers_started != 0
}

pub(crate) fn reset_virtual_aio_slot(
    slot: &mut VirtualAioSlot,
    generation: u16,
    phase: VirtualAioPhase,
) {
    slot.request = SceKernelAioRWRequest::EMPTY;
    slot.file_id = 0;
    slot.next = INVALID_INDEX;
    slot.pipeline_index = INVALID_INDEX;
    slot.generation = generation;
    slot.priority = 0;
    slot.work_class = PackWorkClass::Balanced;
    slot.wait_notified = false;
    slot.phase = phase;
    slot.cancel_requested.store(false, Ordering::Relaxed);
    slot.completion_state = 0;
    slot.return_value = 0;
    slot.submit_ns = 0;
    slot.prefetch_chunks = 0;
    slot.split_group = INVALID_INDEX;
}
