//! Virtual job completion, cache/fd waiter queues and the decode worker loop.

use super::*;
use core::sync::atomic::AtomicI64;

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
    loop {
        let index: u32;
        let pipeline: *mut ReadPipelineContext;
        {
            let mut g = PACK_M.lock();
            let state = sp;
            // On stop, stay until every pipeline is released: a native read
            // still in flight requeues its owner, which needs a worker to
            // clean up (release_pipeline_locked aborts on a live pipeline).
            QUEUE_CV.wait_until(&mut g, || {
                (WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                    && (*state).pipeline_active_count == 0)
                    || wake_fd_waiters_locked(state)
                    || queue_has_work_for_worker_locked(state, worker_index)
                    || prefetch_has_work_for_worker_locked(state, worker_index)
            });
            if WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                && (*state).pipeline_active_count == 0
                && !queue_has_work_for_worker_locked(state, worker_index)
            {
                // release_pipeline_locked wakes only one worker.
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
        {
            let _g = PACK_M.lock();
            let state = sp;
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
        }
        if notify_workers {
            QUEUE_CV.notify_all();
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
        // Classify on demand bytes: read-extension pages (page_plan.rs)
        // must not move a Latency read to Balanced.
        let extension_bytes: usize = if mandatory_group {
            p.mandatory_pages[..p.mandatory_page_count]
                .iter()
                .filter(|pg| pg.extension && pg.acquired.kind == PhysicalCacheAcquireKind::Load)
                .map(|pg| pg.size as usize)
                .sum()
        } else {
            0
        };
        let io_class =
            native_pack_io_class(work_class, physical_bytes.saturating_sub(extension_bytes));
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
    const DECODED_BYTES: usize = PACK_MAX_BLOCK_BYTES;
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
    for i in 0..requested_workers as usize {
        let started = (*state).workers_started;
        let worker = &mut (*state).workers[i];
        worker.index = started;
        let mut actual_decoded: usize = 0;
        worker.decoded_scratch = unsafe {
            ampr_internal_amm_pool_alloc(
                DECODED_BYTES,
                &mut actual_decoded,
                c"apr.pack.worker.decoded".as_ptr(),
                false,
                64,
            )
        } as *mut u8;
        if worker.decoded_scratch.is_null() || actual_decoded < DECODED_BYTES {
            if !worker.decoded_scratch.is_null() {
                let _ = unsafe {
                    ampr_internal_amm_pool_free(
                        worker.decoded_scratch.cast(),
                        c"apr.pack.worker.decoded.fail".as_ptr(),
                    )
                };
            }
            *worker = WorkerContext::EMPTY;
            continue;
        }
        worker.decoded_scratch_size = DECODED_BYTES;
        // zstd only: LZ4 needs no decoder state (and no libc heap).
        if zstd_mode() {
            let mut decoder = alloc::boxed::Box::new(ampr_codec::ZstdDecoder::new());
            // Allocate the decoder's fixed buffers now, not on a game read.
            // The scratch holds a whole zstd chunk (256 KiB; asserted in zstd.rs).
            let scratch =
                unsafe { core::slice::from_raw_parts_mut(worker.decoded_scratch, DECODED_BYTES) };
            let _ = decoder.warm_up(scratch);
            worker.decoder = alloc::boxed::Box::into_raw(decoder);
        }
        let arg = worker as *mut WorkerContext as *mut c_void;
        let create_rc = unsafe {
            scePthreadCreate(
                &mut worker.thread,
                null(),
                pack_worker_entry,
                arg,
                c"ampr_pack_worker".as_ptr(),
            )
        };
        if create_rc != 0 {
            let _ = unsafe {
                ampr_internal_amm_pool_free(
                    worker.decoded_scratch.cast(),
                    c"apr.pack.worker.decoded.create-fail".as_ptr(),
                )
            };
            unsafe { release_worker_decoder(worker) };
            *worker = WorkerContext::EMPTY;
            continue;
        }
        worker.started = true;
        (*state).workers_started += 1;
        PROFILE_STARTED_WORKERS.store((*state).workers_started, Ordering::Release);
        (*state).worker_capacity = (*state).worker_capacity.max((*state).workers_started);
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
