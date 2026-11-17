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

// ---- queues ----
//
// Each (priority, work class) has two FIFO lists: jobs queued while holding a
// pipeline (a parked read resumed after its disk read, cache page or fd
// wait) and new jobs. A worker resumes retained jobs first and admits a new
// one only with a pipeline free (`queue_pop_locked`). With one shared list
// the retained pass walked every queued job under PACK_M whenever no
// pipeline was free; now each pop takes a list head.

type QueueLanes = [[u32; PACK_WORK_CLASS_COUNT]; 3];

/// (heads, tails) of the retained (`true`) or new job lists. PACK_M held.
unsafe fn queue_lists(state: *mut PackState, retained: bool) -> (*mut QueueLanes, *mut QueueLanes) {
    if retained {
        (&raw mut (*state).retained_head, &raw mut (*state).retained_tail)
    } else {
        (&raw mut (*state).queue_head, &raw mut (*state).queue_tail)
    }
}

pub(crate) unsafe fn queue_push_locked(state: *mut PackState, index: u32) {
    let job = &mut (*state).virtual_aio[index as usize];
    if job.parked_ns != 0 && job.requeued_ns == 0 {
        job.requeued_ns = stats::now();
    }
    let priority = job.priority as usize;
    let work_class = work_class_index(job.work_class) as usize;
    let retained = job.pipeline_index != INVALID_INDEX;
    job.next = INVALID_INDEX;
    let (heads, tails) = unsafe { queue_lists(state, retained) };
    let tail = (*tails)[priority][work_class];
    if tail != INVALID_INDEX {
        (*state).virtual_aio[tail as usize].next = index;
    } else {
        (*heads)[priority][work_class] = index;
    }
    (*tails)[priority][work_class] = index;
    if (*state).queue_depth[work_class] == u32::MAX {
        abort();
    }
    (*state).queue_depth[work_class] += 1;
    (*state).virtual_aio[index as usize].phase = VirtualAioPhase::Queued;
    // Tells a spinning idle worker (worker.rs idle_spin) to re-check.
    super::worker::QUEUE_EPOCH.fetch_add(1, Ordering::Relaxed);
    unsafe { super::worker::maybe_grow_workers_locked() };
}

/// Pops the head of lane `lane`, class `work_class` of the retained or new
/// list. PACK_M held.
pub(crate) unsafe fn queue_pop_lane_locked(
    state: *mut PackState,
    lane: u32,
    work_class: PackWorkClass,
    retained: bool,
) -> u32 {
    let (lane, class_index) = (lane as usize, work_class_index(work_class) as usize);
    let (heads, tails) = unsafe { queue_lists(state, retained) };
    let index = (*heads)[lane][class_index];
    if index == INVALID_INDEX {
        return INVALID_INDEX;
    }
    let next = (*state).virtual_aio[index as usize].next;
    (*heads)[lane][class_index] = next;
    if next == INVALID_INDEX {
        (*tails)[lane][class_index] = INVALID_INDEX;
    }
    (*state).virtual_aio[index as usize].next = INVALID_INDEX;
    if (*state).queue_depth[class_index] == 0 {
        abort();
    }
    (*state).queue_depth[class_index] -= 1;
    index
}

/// Unlinks queued job `index` from whichever list holds it (cancel paths).
/// PACK_M held.
pub(crate) unsafe fn queue_remove_locked(state: *mut PackState, index: u32) -> bool {
    if index as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
        return false;
    }
    let lane = (*state).virtual_aio[index as usize].priority as usize;
    let class_index = work_class_index((*state).virtual_aio[index as usize].work_class) as usize;
    for retained in [false, true] {
        let (heads, tails) = unsafe { queue_lists(state, retained) };
        let mut previous = INVALID_INDEX;
        let mut current = (*heads)[lane][class_index];
        while current != INVALID_INDEX {
            let next = (*state).virtual_aio[current as usize].next;
            if current == index {
                if previous == INVALID_INDEX {
                    (*heads)[lane][class_index] = next;
                } else {
                    (*state).virtual_aio[previous as usize].next = next;
                }
                if (*tails)[lane][class_index] == index {
                    (*tails)[lane][class_index] = previous;
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
    }
    false
}

/// Whether the retained or new list holds a job `worker_index` may take (a
/// latency-reserved worker takes no bulk work). PACK_M held.
pub(crate) unsafe fn queue_has_matching_work_for_worker_locked(
    state: *const PackState,
    worker_index: u32,
    retained: bool,
) -> bool {
    let reserved = worker_is_latency_reserved_locked(state, worker_index);
    let (heads, _) = unsafe { queue_lists(state.cast_mut(), retained) };
    (0..3usize).any(|priority| {
        (0..PACK_WORK_CLASS_COUNT).any(|class_index| {
            !(reserved && class_index as u32 == work_class_index(PackWorkClass::Bulk))
                && (*heads)[priority][class_index] != INVALID_INDEX
        })
    })
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
/// latency-reserved worker never consumes bulk work. `retained` picks the
/// retained or the new job lists.
pub(crate) unsafe fn queue_pop_scheduled_locked(
    state: *mut PackState,
    worker_index: u32,
    retained: bool,
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
            let index = queue_pop_lane_locked(state, lane, work_class, retained);
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
            let index = queue_pop_lane_locked(state, lane, work_class, retained);
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

fn reset_pipeline_native(pipeline: &mut ReadPipelineContext) {
    pipeline.native_request = SceKernelAioRWRequest::EMPTY;
    pipeline.native_result = SceKernelAioResult::EMPTY;
    pipeline.cache_wait_epoch = 0;
    pipeline.cache_wait_bucket = 0;
    // The parked-on load key belongs to the job that parked; a job reset
    // here must not let the next one take a failed load's error as its own.
    pipeline.decoded_wait_key = 0;
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
        || pipeline.native_accepted
        || native_submitted(pipeline).load(Ordering::Acquire)
        || pipeline.decoded_lease.entry != INVALID_INDEX
    {
        abort();
    }
    pipeline.owner = INVALID_INDEX;
    reset_pipeline_io(pipeline);
    reset_pipeline_native(pipeline);
    pipeline.active = false;
    pipeline.next_free = free_head;
    (*state).pipeline_free_head = index;
    (*state).virtual_aio[owner as usize].pipeline_index = INVALID_INDEX;
    if (*state).pipeline_active_count == 0 {
        abort();
    }
    (*state).pipeline_active_count -= 1;
    // A free pipeline admits one new read: one worker, unless a latency
    // reserve could hand the signal to a worker that may not take the job.
    super::worker::QUEUE_EPOCH.fetch_add(1, Ordering::Relaxed);
    let single = unsafe { super::worker::single_wake_locked(state, 1) };
    super::worker::wake_queue_workers(single);
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed `PackState` with empty queues, as `pack_state_create` leaves it.
    fn queue_state() -> *mut PackState {
        let layout = std::alloc::Layout::new::<PackState>();
        let state = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<PackState>();
        assert!(!state.is_null());
        unsafe {
            (*state).queue_head = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            (*state).queue_tail = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            (*state).retained_head = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            (*state).retained_tail = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            (*state).pipeline_free_head = INVALID_INDEX;
        }
        state
    }

    /// Queues job `index` at high priority, balanced class, holding a
    /// pipeline when `retained`.
    unsafe fn push(state: *mut PackState, index: u32, retained: bool) {
        let job = &mut (*state).virtual_aio[index as usize];
        job.priority = 2;
        job.work_class = PackWorkClass::Balanced;
        job.pipeline_index = if retained { 0 } else { INVALID_INDEX };
        unsafe { queue_push_locked(state, index) };
    }

    /// Jobs holding a pipeline pop first, in FIFO order, with no pipeline
    /// free; new jobs then pop in FIFO order once one is free. A removal
    /// from the middle or tail keeps both lists linked.
    #[test]
    fn retained_jobs_pop_first_in_fifo_order() {
        let state = queue_state();
        unsafe {
            for (index, retained) in [(1, false), (2, false), (3, true), (4, false), (5, true)] {
                push(state, index, retained);
            }
            assert_eq!((*state).queue_depth[1], 5);
            assert!(queue_has_work_for_worker_locked(state, 0));
            assert_eq!(queue_pop_locked(state, 0), 3);
            assert_eq!(queue_pop_locked(state, 0), 5);
            assert_eq!(queue_pop_locked(state, 0), INVALID_INDEX, "no pipeline free");
            assert!(!queue_has_work_for_worker_locked(state, 0));
            (*state).pipeline_free_head = 0;
            assert!(queue_has_work_for_worker_locked(state, 0));
            push(state, 6, false);
            assert!(queue_remove_locked(state, 2), "middle of the new list");
            assert!(queue_remove_locked(state, 6), "tail of the new list");
            assert!(!queue_remove_locked(state, 6));
            push(state, 7, false);
            assert_eq!(queue_pop_locked(state, 0), 1);
            assert_eq!(queue_pop_locked(state, 0), 4);
            assert_eq!(queue_pop_locked(state, 0), 7);
            assert_eq!(queue_pop_locked(state, 0), INVALID_INDEX);
            assert_eq!((*state).queue_depth[1], 0);
            push(state, 8, true);
            assert!(queue_remove_locked(state, 8), "retained list");
            assert_eq!((*state).retained_tail[2][1], INVALID_INDEX);
            std::alloc::dealloc(state.cast(), std::alloc::Layout::new::<PackState>());
        }
    }
}
