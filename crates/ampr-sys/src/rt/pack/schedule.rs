//! Work classification, scheduling queues and pipeline acquire/release.

use super::*;

pub(crate) fn queue_priority(priority: c_int) -> u8 {
    if priority == SCE_KERNEL_AIO_PRIORITY_HIGH {
        2
    } else if priority == SCE_KERNEL_AIO_PRIORITY_MID {
        1
    } else {
        0
    }
}

pub(crate) fn classify_work(flags: u32, request: &SceKernelAioRWRequest) -> PackWorkClass {
    let request_bytes = request.nbyte as u64;
    if request_bytes <= AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES
        || (flags & AMPR_PACK_FILE_HOT != 0 && request_bytes < AMPR_EMU_PACK_BULK_READ_MIN_BYTES)
    {
        return PackWorkClass::Latency;
    }
    if flags & AMPR_PACK_FILE_STREAMING != 0 || request_bytes >= AMPR_EMU_PACK_BULK_READ_MIN_BYTES {
        return PackWorkClass::Bulk;
    }
    PackWorkClass::Balanced
}

pub(crate) fn work_class_index(work_class: PackWorkClass) -> u32 {
    work_class as u32
}

pub(crate) unsafe fn effective_latency_reserve_locked(state: *const PackState) -> u32 {
    if (*state).workers_started <= 1 {
        return 0;
    }
    (*state)
        .latency_reserve_workers
        .min((*state).workers_started - 1)
}

pub(crate) unsafe fn worker_is_latency_reserved_locked(
    state: *const PackState,
    worker_index: u32,
) -> bool {
    worker_index < effective_latency_reserve_locked(state)
}

// update_queue_depth_peak: telemetry, dropped.

pub(crate) unsafe fn queue_push_locked(state: *mut PackState, index: u32, _queued_at_usec: u64) {
    let job = &mut (*state).virtual_aio[index as usize];
    if job.parked_ns != 0 && job.requeued_ns == 0 {
        job.requeued_ns = stats::now();
    }
    let priority = job.priority as usize;
    let work_class = work_class_index(job.work_class) as usize;
    job.next = INVALID_INDEX;
    let tail = (*state).queue_tail[priority][work_class];
    if tail != INVALID_INDEX {
        (*state).virtual_aio[tail as usize].next = index;
    } else {
        (*state).queue_head[priority][work_class] = index;
    }
    (*state).queue_tail[priority][work_class] = index;
    if (*state).queue_depth[work_class] == u32::MAX {
        abort();
    }
    (*state).queue_depth[work_class] += 1;
    (*state).virtual_aio[index as usize].phase = VirtualAioPhase::Queued;
}

pub(crate) unsafe fn queue_pop_lane_locked(
    state: *mut PackState,
    lane: u32,
    work_class: PackWorkClass,
    require_retained_pipeline: bool,
) -> u32 {
    let lane = lane as usize;
    let class_index = work_class_index(work_class) as usize;
    let mut previous = INVALID_INDEX;
    let mut index = (*state).queue_head[lane][class_index];
    while index != INVALID_INDEX
        && require_retained_pipeline
        && (*state).virtual_aio[index as usize].pipeline_index == INVALID_INDEX
    {
        previous = index;
        index = (*state).virtual_aio[index as usize].next;
    }
    if index == INVALID_INDEX {
        return INVALID_INDEX;
    }
    let next = (*state).virtual_aio[index as usize].next;
    if previous == INVALID_INDEX {
        (*state).queue_head[lane][class_index] = next;
    } else {
        (*state).virtual_aio[previous as usize].next = next;
    }
    if (*state).queue_tail[lane][class_index] == index {
        (*state).queue_tail[lane][class_index] = previous;
    }
    if (*state).queue_head[lane][class_index] == INVALID_INDEX {
        (*state).queue_tail[lane][class_index] = INVALID_INDEX;
    }
    (*state).virtual_aio[index as usize].next = INVALID_INDEX;
    if (*state).queue_depth[class_index] == 0 {
        abort();
    }
    (*state).queue_depth[class_index] -= 1;
    index
}

pub(crate) unsafe fn queue_remove_locked(state: *mut PackState, index: u32) -> bool {
    if index as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
        return false;
    }
    if (*state).virtual_aio[index as usize].prefetch_chunks != 0
        && (*state).virtual_aio[index as usize].pipeline_index == INVALID_INDEX
    {
        return prefetch_queue_remove_locked(state, index);
    }
    let lane = (*state).virtual_aio[index as usize].priority as usize;
    let class_index = work_class_index((*state).virtual_aio[index as usize].work_class) as usize;
    let mut previous = INVALID_INDEX;
    let mut current = (*state).queue_head[lane][class_index];
    while current != INVALID_INDEX {
        let next = (*state).virtual_aio[current as usize].next;
        if current == index {
            if previous == INVALID_INDEX {
                (*state).queue_head[lane][class_index] = next;
            } else {
                (*state).virtual_aio[previous as usize].next = next;
            }
            if (*state).queue_tail[lane][class_index] == index {
                (*state).queue_tail[lane][class_index] = previous;
            }
            (*state).virtual_aio[current as usize].next = INVALID_INDEX;
            if (*state).queue_depth[class_index] == 0 {
                abort();
            }
            (*state).queue_depth[class_index] -= 1;
            return true;
        }
        previous = current;
        current = next;
    }
    false
}

pub(crate) unsafe fn queue_has_matching_work_for_worker_locked(
    state: *const PackState,
    worker_index: u32,
    require_retained_pipeline: bool,
) -> bool {
    let reserved = worker_is_latency_reserved_locked(state, worker_index);
    for priority in 0..3usize {
        for class_index in 0..PACK_WORK_CLASS_COUNT {
            if reserved && class_index as u32 == work_class_index(PackWorkClass::Bulk) {
                continue;
            }
            let mut index = (*state).queue_head[priority][class_index];
            while index != INVALID_INDEX {
                if !require_retained_pipeline
                    || (*state).virtual_aio[index as usize].pipeline_index != INVALID_INDEX
                {
                    return true;
                }
                index = (*state).virtual_aio[index as usize].next;
            }
        }
    }
    false
}

pub(crate) unsafe fn queue_has_work_for_worker_locked(
    state: *const PackState,
    worker_index: u32,
) -> bool {
    if queue_has_matching_work_for_worker_locked(state, worker_index, true) {
        return true;
    }
    (*state).pipeline_free_head != INVALID_INDEX
        && queue_has_matching_work_for_worker_locked(state, worker_index, false)
}

/// Weighted high:mid:low service (4:2:1), with immediate fallback to any
/// non-empty queue; within one priority latency < balanced < bulk. A
/// latency-reserved worker never consumes bulk work.
pub(crate) unsafe fn queue_pop_scheduled_locked(
    state: *mut PackState,
    worker_index: u32,
    require_retained_pipeline: bool,
) -> u32 {
    const SCHEDULE: [u8; 7] = [2, 2, 2, 2, 1, 1, 0];
    const CLASS_ORDER: [PackWorkClass; 3] = [
        PackWorkClass::Latency,
        PackWorkClass::Balanced,
        PackWorkClass::Bulk,
    ];
    let reserved = worker_is_latency_reserved_locked(state, worker_index);
    for _ in 0..7 {
        let lane = SCHEDULE[((*state).queue_pick_counter % 7) as usize] as u32;
        (*state).queue_pick_counter = (*state).queue_pick_counter.wrapping_add(1);
        for work_class in CLASS_ORDER {
            if reserved && work_class == PackWorkClass::Bulk {
                continue;
            }
            let index = queue_pop_lane_locked(state, lane, work_class, require_retained_pipeline);
            if index != INVALID_INDEX {
                return index;
            }
        }
    }
    for lane in (0..3u32).rev() {
        for work_class in CLASS_ORDER {
            if reserved && work_class == PackWorkClass::Bulk {
                continue;
            }
            let index = queue_pop_lane_locked(state, lane, work_class, require_retained_pipeline);
            if index != INVALID_INDEX {
                return index;
            }
        }
    }
    INVALID_INDEX
}

/// Resume completed/cache-ready pipelines before admitting new logical reads.
pub(crate) unsafe fn queue_pop_locked(state: *mut PackState, worker_index: u32) -> u32 {
    let retained = queue_pop_scheduled_locked(state, worker_index, true);
    if retained != INVALID_INDEX {
        return retained;
    }
    if (*state).pipeline_free_head == INVALID_INDEX {
        return INVALID_INDEX;
    }
    queue_pop_scheduled_locked(state, worker_index, false)
}

fn native_submitted(pipeline: &mut ReadPipelineContext) -> &AtomicBool {
    unsafe { AtomicBool::from_ptr(&mut pipeline.native_submitted) }
}

/// Clears the per-read fields shared by acquire and release.
fn reset_pipeline_io(pipeline: &mut ReadPipelineContext) {
    pipeline.io_window_offset = 0;
    pipeline.io_window_size = 0;
    pipeline.io_window_pack_id = u16::MAX;
    pipeline.io_window_valid = false;
    pipeline.io_window_data = null();
    pipeline.io_range = PipelineIoRange::EMPTY;
    pipeline.task_index = 0;
    pipeline.task_count = 0;
}

fn reset_pipeline_tail(pipeline: &mut ReadPipelineContext) {
    pipeline.mandatory_page_count = 0;
    pipeline.mandatory_task_end = 0;
    pipeline.mandatory_skip_task = usize::MAX;
    pipeline.mandatory_request_count = 0;
    pipeline.mandatory_fd_count = 0;
    pipeline.mandatory_plan_active = false;
}

fn reset_pipeline_native(pipeline: &mut ReadPipelineContext) {
    pipeline.native_request = SceKernelAioRWRequest::EMPTY;
    pipeline.native_result = SceKernelAioResult::EMPTY;
    pipeline.cache_wait_epoch = 0;
    pipeline.cache_wait_bucket = 0;
    pipeline.cache_wait_domain = CacheWaitDomain::Decoded;
    pipeline.fd_wait_epoch = 0;
    pipeline.fd_budget_wait_epoch = 0;
    pipeline.native_io_error = 0;
    pipeline.native_completion_ready = false;
    pipeline.native_accepted = false;
    native_submitted(pipeline).store(false, Ordering::Relaxed);
}

pub(crate) unsafe fn acquire_pipeline_locked(
    state: *mut PackState,
    owner: u32,
) -> *mut ReadPipelineContext {
    if owner as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS
        || (*state).pipeline_free_head == INVALID_INDEX
    {
        return null_mut();
    }
    let index = (*state).pipeline_free_head;
    if index >= (*state).pipeline_capacity || index as usize >= AMPR_EMU_PACK_PIPELINE_SLOTS {
        abort();
    }
    let pipeline = &mut (*state).pipelines[index as usize];
    (*state).pipeline_free_head = pipeline.next_free;
    pipeline.next_free = INVALID_INDEX;
    pipeline.owner = owner;
    reset_pipeline_io(pipeline);
    pipeline.decoded_lease = CacheLease::EMPTY;
    // io_pages and the mandatory_* arrays are only read below their counts,
    // which are reset here; refilling ~19 KiB under PACK_M is unnecessary.
    pipeline.io_page_count = 0;
    reset_pipeline_tail(pipeline);
    pipeline.pack_fd = -1;
    reset_pipeline_native(pipeline);
    pipeline.active = true;
    let pipeline: *mut ReadPipelineContext = pipeline;
    (*state).virtual_aio[owner as usize].pipeline_index = index;
    if (*state).pipeline_active_count >= (*state).pipeline_capacity {
        abort();
    }
    (*state).pipeline_active_count += 1;
    pipeline
}

pub(crate) unsafe fn release_pipeline_locked(state: *mut PackState, owner: u32) {
    if owner as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
        return;
    }
    let index = (*state).virtual_aio[owner as usize].pipeline_index;
    if index == INVALID_INDEX {
        return;
    }
    if index >= (*state).pipeline_capacity || index as usize >= AMPR_EMU_PACK_PIPELINE_SLOTS {
        abort();
    }
    {
        let pipeline = &(*state).pipelines[index as usize];
        if !pipeline.active || pipeline.owner != owner {
            abort();
        }
    }
    match (*state).virtual_aio[owner as usize].phase {
        VirtualAioPhase::WaitingCache => {
            if (*state).cache_waiter_count == 0 {
                abort();
            }
            (*state).cache_waiter_count -= 1;
        }
        VirtualAioPhase::WaitingFd => {
            if (*state).fd_waiter_count == 0 {
                abort();
            }
            (*state).fd_waiter_count -= 1;
        }
        _ => {}
    }
    let free_head = (*state).pipeline_free_head;
    let pipeline = &mut (*state).pipelines[index as usize];
    if pipeline.pack_fd >= 0
        || pipeline.mandatory_fd_count != 0
        || pipeline.native_accepted
        || native_submitted(pipeline).load(Ordering::Acquire)
        || pipeline.decoded_lease.entry != INVALID_INDEX
    {
        abort();
    }
    if pipeline.io_pages[..pipeline.io_page_count]
        .iter()
        .any(|p| p.lease.entry != INVALID_INDEX)
    {
        abort();
    }
    if pipeline.mandatory_pages[..pipeline.mandatory_page_count]
        .iter()
        .any(|p| p.acquired.lease.entry != INVALID_INDEX)
    {
        abort();
    }
    pipeline.owner = INVALID_INDEX;
    reset_pipeline_io(pipeline);
    pipeline.io_page_count = 0;
    reset_pipeline_tail(pipeline);
    reset_pipeline_native(pipeline);
    pipeline.active = false;
    pipeline.next_free = free_head;
    (*state).pipeline_free_head = index;
    (*state).virtual_aio[owner as usize].pipeline_index = INVALID_INDEX;
    if (*state).pipeline_active_count == 0 {
        abort();
    }
    (*state).pipeline_active_count -= 1;
    QUEUE_CV.notify_one();
}
