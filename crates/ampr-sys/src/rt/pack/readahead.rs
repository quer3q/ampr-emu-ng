//! Sequential read-ahead.
//!
//! A virtual read of a packed file that ends in local chunk `b` queues
//! decoded-cache loads of local chunks `b+1 ..= b+K` (K =
//! AMPR_EMU_PACK_READAHEAD_CHUNKS, clipped to the file) that are not already
//! in the decoded cache. Each run of missing chunks becomes one prefetch job:
//! a virtual AIO slot with `prefetch_chunks != 0`, no destination, no result
//! and no id. Jobs wait in their own FIFO and start only on a worker that found
//! no game work, while more than a quarter of the pipelines are free; otherwise
//! they are dropped. Jobs are also dropped, at queue and at start, while the
//! pack has AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT physical backing reads in
//! flight. A started job runs the normal pipeline (Bulk class, LOW AIO priority
//! so the kernel serves game reads first) but only loads chunks it gets a Load lease for;
//! it may wait for a physical page another read is loading, but uses only an
//! already-open pack descriptor and is dropped instead of waiting for one (worker.rs). A game read of a chunk being
//! prefetched sees the Loading entry and waits like any concurrent load.

use super::*;

/// Read-ahead window in chunks (live in the debug build, rt/tune.rs).
fn k() -> u32 {
    super::super::tune::ra()
}
/// Capacity of the per-job chunk array: the largest `k()` this build allows.
const K_CAP: usize = if super::super::tune::ON {
    super::super::tune::RA_MAX as usize
} else {
    AMPR_EMU_PACK_READAHEAD_CHUNKS as usize
};
/// Bound on the chunks of all prefetch jobs in flight. Console metrics: with 2K
/// and a half-free start gate, ~40% of candidates were dropped during load
/// bursts while the disk sat at ~2 outstanding reads.
fn prefetch_max_inflight_chunks() -> u32 {
    k() * 4
}
/// Queue priority of prefetch jobs: maps to SCE_KERNEL_AIO_PRIORITY_LOW
/// (native_pack_priority).
const PREFETCH_PRIORITY: u8 = 0;

/// The pack's physical backing reads in flight (submitted to the reactor, not
/// yet completed or failed). Console metrics: the storage path saturates at
/// ~300 MB/s, and extra read-ahead during load bursts raised game latency.
pub(crate) static PACK_DISK_INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// Records `reads` accepted backing reads of `pipeline`. PACK_M held.
pub(crate) fn disk_inflight_add(pipeline: &mut ReadPipelineContext, reads: u32) {
    pipeline.disk_inflight += reads;
    PACK_DISK_INFLIGHT.fetch_add(reads, Ordering::AcqRel);
}

/// Retires the backing reads `pipeline` recorded (terminal reactor event).
/// PACK_M held; never underflows.
pub(crate) fn disk_inflight_release(pipeline: &mut ReadPipelineContext) {
    let reads = core::mem::take(&mut pipeline.disk_inflight);
    if reads != 0 {
        let mut current = PACK_DISK_INFLIGHT.load(Ordering::Acquire);
        while let Err(seen) = PACK_DISK_INFLIGHT.compare_exchange_weak(
            current,
            current.saturating_sub(reads),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            current = seen;
        }
    }
}

fn disk_saturated() -> bool {
    PACK_DISK_INFLIGHT.load(Ordering::Acquire) >= super::super::tune::ra_gate()
}

/// Last local chunk `request` reads in packed file `file_id`, or None when it
/// reads no chunk. PACK_M held; the caller validated the file id.
pub(crate) unsafe fn readahead_last_chunk(
    state: *const PackState,
    file_id: u32,
    request: &SceKernelAioRWRequest,
) -> Option<u32> {
    if k() == 0 || (*state).files.is_null() || request.offset < 0 || request.nbyte == 0 {
        return None;
    }
    let file = unsafe { &*(*state).files.add(file_id as usize - 1) };
    let (flags, logical_size, shift) =
        ({ file.flags }, { file.logical_size }, { file.block_shift }
            as u32);
    let offset = request.offset as u64;
    if flags & AMPR_PACK_FILE_PACKED == 0 || offset >= logical_size || shift >= 64 {
        return None;
    }
    Some(((offset + (request.nbyte as u64).min(logical_size - offset) - 1) >> shift) as u32)
}

/// Advances virtual fd `fd_index`'s read-ahead window past local chunk `last`
/// (the highest one a submit batch reads in the fd's file) and returns the
/// local chunks [start, end) newly due (empty when none), so a sequential
/// stream keeps the window K chunks ahead without re-queuing it. PACK_M held.
pub(crate) unsafe fn readahead_window_locked(
    state: *mut PackState,
    fd_index: u32,
    last: u32,
) -> (u32, u32) {
    let slot = &mut (*state).virtual_fds[fd_index as usize];
    let file = unsafe { &*(*state).files.add(slot.file_id as usize - 1) };
    let flags = { file.flags };
    let last = last as u64;
    let k = k() as u64;
    let end = (last + 1 + k).min({ file.chunk_count } as u64);
    if flags & AMPR_PACK_FILE_RANDOM_ACCESS != 0 {
        stats::add(stats::Stat::PrefetchSkipped, end.saturating_sub(last + 1));
        return (0, 0);
    }
    let next = slot.readahead_next as u64;
    let start = if next > last && next <= last + 1 + k {
        next
    } else {
        last + 1
    };
    slot.readahead_next = start.max(end) as u32;
    if start >= end {
        return (0, 0);
    }
    (start as u32, end as u32)
}

/// Queues prefetch jobs for the local chunks [start, end) of `file_id` that
/// are not in the decoded cache, unless the disk is saturated. Returns whether
/// a job was queued (the caller notifies QUEUE_CV). No lock held.
pub(crate) unsafe fn queue_readahead(file_id: u32, start: u32, end: u32) -> bool {
    let k = k();
    if k == 0 || start >= end || end - start > k {
        return false;
    }
    if disk_saturated() {
        stats::add(stats::Stat::PrefetchSkipped, (end - start) as u64);
        return false;
    }
    let state = unsafe { pack_state() };
    let file = unsafe { &*(*state).files.add(file_id as usize - 1) };
    let (logical_size, shift) = ({ file.logical_size }, { file.block_shift } as u32);
    let count = end - start;
    let offset = (start as u64) << shift;
    let length = ((end as u64) << shift).min(logical_size) - offset;
    let file_ptr = file as *const AmprPackFileRecord as *const u8;

    let mut chunks = [AmprPackChunkView::default(); K_CAP];
    let mut planned = 0;
    while planned < count {
        let mut task = AmprPackBlockReadTask::default();
        if unsafe {
            ampr_pack_core_make_task(
                &(*state).core_view,
                file_ptr,
                offset,
                length,
                planned as usize,
                &mut task,
            )
        } != AMPR_PACK_CORE_OK
        {
            break;
        }
        chunks[planned as usize] = task.chunk;
        planned += 1;
    }
    // Bit i: local chunk start + i is neither cached nor being loaded.
    let mut missing = 0u64;
    if !(*state).cache_base.is_null() && (*state).cache_page_count != 0 {
        let _lock = CACHE_MUTEX.lock();
        for (i, chunk) in chunks[..planned as usize].iter().enumerate() {
            if cache_find_locked(state, chunk, chunk_key_hash(chunk)) == INVALID_INDEX {
                missing |= 1 << i;
            }
        }
    }

    let mut skipped = count - missing.count_ones();
    let mut queued = 0;
    {
        let _lock = PACK_M.lock();
        let mut i = 0;
        while i < count {
            if missing & (1 << i) == 0 {
                i += 1;
                continue;
            }
            let mut run = 1;
            while i + run < count && missing & (1 << (i + run)) != 0 {
                run += 1;
            }
            let take = run.min(
                prefetch_max_inflight_chunks().saturating_sub((*state).prefetch_chunks_inflight),
            );
            let index = if take != 0
                && (*state).pipeline_free_head != INVALID_INDEX
                && !WORKER_STOP_REQUESTED.load(Ordering::Acquire)
            {
                allocate_virtual_aio_locked(state)
            } else {
                INVALID_INDEX
            };
            if index == INVALID_INDEX {
                skipped += run;
                i += run;
                continue;
            }
            skipped += run - take;
            let first = ((start + i) as u64) << shift;
            let job = &mut (*state).virtual_aio[index as usize];
            job.request.offset = first as off_t;
            job.request.nbyte =
                ((((start + i + take) as u64) << shift).min(logical_size) - first) as usize;
            job.request.fd = -1;
            job.file_id = file_id;
            job.priority = PREFETCH_PRIORITY;
            job.work_class = PackWorkClass::Bulk;
            job.prefetch_chunks = take;
            (*state).prefetch_chunks_inflight += take;
            prefetch_queue_push_locked(state, index);
            queued += take;
            i += run;
        }
    }
    stats::add(stats::Stat::PrefetchChunks, queued as u64);
    stats::add(stats::Stat::PrefetchSkipped, skipped as u64);
    queued != 0
}

pub(crate) unsafe fn prefetch_queue_push_locked(state: *mut PackState, index: u32) {
    (*state).virtual_aio[index as usize].next = INVALID_INDEX;
    if (*state).prefetch_tail != INVALID_INDEX {
        (*state).virtual_aio[(*state).prefetch_tail as usize].next = index;
    } else {
        (*state).prefetch_head = index;
    }
    (*state).prefetch_tail = index;
    (*state).virtual_aio[index as usize].phase = VirtualAioPhase::Queued;
}

pub(crate) unsafe fn prefetch_queue_remove_locked(state: *mut PackState, index: u32) -> bool {
    let mut previous = INVALID_INDEX;
    let mut current = (*state).prefetch_head;
    while current != INVALID_INDEX {
        let next = (*state).virtual_aio[current as usize].next;
        if current == index {
            if previous == INVALID_INDEX {
                (*state).prefetch_head = next;
            } else {
                (*state).virtual_aio[previous as usize].next = next;
            }
            if (*state).prefetch_tail == index {
                (*state).prefetch_tail = previous;
            }
            (*state).virtual_aio[index as usize].next = INVALID_INDEX;
            return true;
        }
        previous = current;
        current = next;
    }
    false
}

pub(crate) unsafe fn prefetch_has_work_for_worker_locked(
    state: *const PackState,
    worker_index: u32,
) -> bool {
    (*state).prefetch_head != INVALID_INDEX
        && !worker_is_latency_reserved_locked(state, worker_index)
}

/// Pops the next prefetch job for a worker that found no game work, or
/// INVALID_INDEX. Jobs that cannot start now (pipelines scarce, disk
/// saturated, stopping) are dropped and counted as skipped.
pub(crate) unsafe fn prefetch_pop_locked(state: *mut PackState, worker_index: u32) -> u32 {
    if worker_is_latency_reserved_locked(state, worker_index) {
        return INVALID_INDEX;
    }
    while (*state).prefetch_head != INVALID_INDEX {
        let index = (*state).prefetch_head;
        prefetch_queue_remove_locked(state, index);
        let free_pipelines = (*state).pipeline_capacity - (*state).pipeline_active_count;
        if (*state).pipeline_free_head != INVALID_INDEX
            && free_pipelines > (*state).pipeline_capacity / 4
            && !disk_saturated()
            && !WORKER_STOP_REQUESTED.load(Ordering::Acquire)
        {
            return index;
        }
        stats::add(
            stats::Stat::PrefetchSkipped,
            (*state).virtual_aio[index as usize].prefetch_chunks as u64,
        );
        finish_prefetch_locked(state, index);
    }
    INVALID_INDEX
}

/// Retires a prefetch job (its pipeline already released): no completion is
/// published, the slot is freed at once.
pub(crate) unsafe fn finish_prefetch_locked(state: *mut PackState, index: u32) {
    let chunks = (*state).virtual_aio[index as usize].prefetch_chunks;
    if (*state).prefetch_chunks_inflight < chunks {
        abort();
    }
    (*state).prefetch_chunks_inflight -= chunks;
    free_virtual_aio_locked(state, index);
}

/// Bench helper for the metrics endpoint: when the manifest is mounted (loads
/// it like a first read would), writes the NUL-terminated absolute path of pack
/// volume 0 (as acquire_pack_fd opens it; `ampr_zstd-000.pak` in the zstd build)
/// into `out` and returns (path length without NUL, volume file size from the
/// manifest pack record or the zstd volume record).
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn bench_volume_path(out: &mut [u8; 1024]) -> Option<(usize, u64)> {
    if !unsafe { ensure_manifest_ready() } {
        return None;
    }
    let state = unsafe { pack_state() };
    let _lock = PACK_M.lock();
    if !unsafe { build_pack_path(state, 0, out.as_mut_ptr() as *mut c_char, out.len()) } {
        return None;
    }
    let length = out.iter().position(|&b| b == 0)?;
    let file_size = if zstd_mode() {
        zstd::zstd_volume_size(0)?
    } else {
        unsafe { (*(*state).packs).file_size }
    };
    Some((length, file_size))
}
