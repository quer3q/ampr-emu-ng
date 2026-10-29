//! Cache-only virtual reads, pipeline windows, chunk decode and the
//! virtual read AIO state machine.

use super::*;
use core::ptr::copy_nonoverlapping;

/// A copy of decoded bytes into the caller's buffer, timed in debug builds.
#[inline(always)]
unsafe fn timed_copy(src: *const u8, dst: *mut u8, len: usize) {
    let start = stats::now();
    unsafe { copy_nonoverlapping(src, dst, len) };
    stats::add(stats::Stat::CopyNs, stats::since(start));
    stats::add(stats::Stat::CopyBytes, len as u64);
}

/// Packed one-based `file_id`: the `file` argument of `ampr_pack_core_task_count`
/// and `ampr_pack_core_make_task`, its logical size and cache flags (none in
/// zstd). None when the mount is not ready, the id is out of range, or the
/// file is loose.
pub(crate) unsafe fn packed_read_file(
    state: *const PackState,
    file_id: u32,
) -> Option<(*const u8, u64, u32)> {
    if zstd_mode() {
        let zstd_id = zstd::zstd_file_for_ampr_id(file_id)?;
        let size = zstd::zstd_index()?.file(zstd_id).ok()?.logical_size;
        return Some((zstd::zstd_task_file(file_id), size, 0));
    }
    unsafe {
        if (*state).header.is_null()
            || (*state).files.is_null()
            || file_id == 0
            || file_id as u64 > { (*(*state).header).file_count }
        {
            return None;
        }
        let file = &*(*state).files.add(file_id as usize - 1);
        if file.flags & AMPR_PACK_FILE_PACKED == 0 {
            return None;
        }
        Some((
            file as *const AmprPackFileRecord as *const u8,
            file.logical_size,
            file.flags,
        ))
    }
}

pub(crate) unsafe fn try_process_virtual_read_cache_only(
    job: &mut VirtualAioSlot,
    completed_bytes: *mut u64,
) -> bool {
    unsafe {
        if !completed_bytes.is_null() {
            *completed_bytes = 0;
        }
        let state = pack_state();
        if job.request.result.is_null() || job.request.offset < 0 {
            return false;
        }
        let Some((file_ptr, logical_size, _)) = packed_read_file(state, job.file_id) else {
            return false;
        };
        let offset = job.request.offset as u64;
        if job.request.nbyte == 0 || offset >= logical_size {
            return true;
        }
        if job.request.buf.is_null() {
            return false;
        }
        // Task destination offsets are u32: a read of 4 GiB or more is cut
        // to a short read at that limit instead of failing part-way with EIO.
        let length = (job.request.nbyte as u64).min(logical_size - offset).min(u32::MAX as u64);
        // Decoded cache off (the default, AMPR_EMU_PACK_DECODED_CACHE_BYTES = 0):
        // no chunk can be Ready, so skip the task build and pin attempts.
        if (*state).cache_base.is_null() || (*state).cache_page_count == 0 {
            return false;
        }

        let task_count = ampr_pack_core_task_count(file_ptr, offset, length);
        if task_count == 0 || task_count > AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS {
            return false;
        }
        let mut tasks = [AmprPackBlockReadTask::default(); AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS];
        let mut leases = [CacheLease::EMPTY; AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS];
        let mut pinned = 0;
        for task_index in 0..task_count {
            if ampr_pack_core_make_task(
                &(*state).core_view,
                file_ptr,
                offset,
                length,
                task_index,
                &mut tasks[task_index],
            ) != AMPR_PACK_CORE_OK
                || tasks[task_index].chunk_index as u64 >= pack_chunk_count(state)
                || tasks[task_index].destination_offset as u64
                    + tasks[task_index].copy_length as u64
                    > length
            {
                break;
            }
            let chunk = tasks[task_index].chunk;
            if !cache_try_pin_ready(&chunk, &mut leases[task_index]) {
                break;
            }
            pinned += 1;
        }
        if pinned != task_count {
            for lease in &mut leases[..pinned] {
                cache_release(lease);
            }
            // Not counted here: the worker pipeline looks these chunks up again.
            return false;
        }
        stats::add(stats::Stat::CacheHits, task_count as u64);

        let output = job.request.buf as *mut u8;
        for (task, lease) in tasks[..task_count].iter().zip(&leases[..task_count]) {
            copy_nonoverlapping(
                lease.data.add(task.source_offset as usize),
                output.add(task.destination_offset as usize),
                task.copy_length as usize,
            );
        }
        for lease in &mut leases[..task_count] {
            cache_release(lease);
        }
        if !completed_bytes.is_null() {
            *completed_bytes = length;
        }
        true
    }
}

pub(crate) unsafe fn cleanup_pipeline_continuation(
    pipeline: &mut ReadPipelineContext,
    error: c_int,
) {
    unsafe {
        if pipeline.decoded_lease.entry != INVALID_INDEX {
            // A failed read-ahead drops its entry (transient error), so a later
            // game read of the chunk loads it again instead of seeing Failed.
            // Read through the raw state pointer: `pipeline` lives inside PackState.
            let owner = pipeline.owner;
            let prefetch = owner != INVALID_INDEX
                && (*pack_state_create()).virtual_aio[owner as usize].prefetch_chunks != 0;
            cache_publish(
                &mut pipeline.decoded_lease,
                if prefetch {
                    SCE_KERNEL_ERROR_EAGAIN
                } else {
                    error
                },
            );
            cache_release(&mut pipeline.decoded_lease);
        }
        abandon_pipeline_page_plan(pipeline, error);
        if !pipeline.native_accepted {
            abandon_mandatory_page_plan(pipeline, error);
        }
        if pipeline.pack_fd >= 0 && !pipeline.native_accepted {
            release_pack_fd(pipeline.io_range.pack_id);
            pipeline.pack_fd = -1;
        }
        pipeline.io_range = PipelineIoRange::EMPTY;
        pipeline.io_window_valid = false;
        pipeline.io_window_data = null();
        pipeline.native_request = SceKernelAioRWRequest::EMPTY;
        pipeline.native_result = SceKernelAioResult::EMPTY;
        pipeline.native_io_error = 0;
        pipeline.native_completion_ready = false;
        AtomicBool::from_ptr(&mut pipeline.native_submitted).store(false, Ordering::Release);
    }
}

pub(crate) unsafe fn make_pipeline_window_range(
    chunk: &AmprPackChunkView,
    out: *mut PipelineIoRange,
) -> c_int {
    unsafe {
        if out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        *out = PipelineIoRange::EMPTY;
        let state = pack_state();
        let Some(io_page_size) = pack_io_page_size(state, chunk.pack_id) else {
            return SCE_KERNEL_ERROR_EIO;
        };
        let mut chunk_end = 0u64;
        let mut range_end = 0u64;
        if !checked_add_u64(chunk.offset, chunk.stored_size as u64, &mut chunk_end)
            || !align_up_u64(chunk_end, io_page_size as u64, &mut range_end)
        {
            return SCE_KERNEL_ERROR_EIO;
        }
        let range_begin = align_down_u64(chunk.offset, io_page_size as u64);
        if range_end < range_begin
            || range_end - range_begin > u32::MAX as u64
            || range_end - range_begin > PACK_PIPELINE_IO_BYTES as u64
        {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        *out = PipelineIoRange {
            offset: range_begin,
            length: (range_end - range_begin) as u32,
            io_page_size,
            pack_id: chunk.pack_id,
        };
        0
    }
}

pub(crate) unsafe fn bind_mandatory_page_window(
    chunk: &AmprPackChunkView,
    pipeline: &mut ReadPipelineContext,
) -> bool {
    unsafe {
        if !pipeline.mandatory_plan_active || pipeline.mandatory_page_count == 0 {
            return false;
        }
        let mut chunk_end = 0u64;
        if !checked_add_u64(chunk.offset, chunk.stored_size as u64, &mut chunk_end) {
            return false;
        }
        for page_index in 0..pipeline.mandatory_page_count {
            let page = pipeline.mandatory_pages[page_index];
            let mut page_end = 0u64;
            if page.pack_id != chunk.pack_id
                || page.acquired.kind != PhysicalCacheAcquireKind::Ready
                || !checked_add_u64(page.offset, page.size as u64, &mut page_end)
                || chunk.offset < page.offset
                || chunk_end > page_end
            {
                continue;
            }
            release_pipeline_window_pages(pipeline);
            pipeline.io_window_offset = page.offset;
            pipeline.io_window_size = page.size;
            pipeline.io_window_pack_id = page.pack_id;
            pipeline.io_window_data = page.acquired.lease.data;
            pipeline.io_window_valid = true;
            pipeline.io_range = PipelineIoRange::EMPTY;
            return true;
        }
        false
    }
}

/// The one compressed codec id of `decode_pipeline_chunk`: LZ4 (AMPRPAK4)
/// or zstd, by mode. Raw is 0 in both formats.
const PIPELINE_COMPRESSED_CODEC: u8 = AMPR_PACK_CHUNK_LZ4;
// zstd codec ids share the AMPRPAK4 values (raw 0, compressed 1), so the
// raw-bypass tests in this file read `codec` the same way in both modes.
const _: () = assert!(
    ampr_codec::ZSTD_CODEC_RAW == AMPR_PACK_CHUNK_RAW
        && ampr_codec::ZSTD_CODEC_ZSTD == AMPR_PACK_CHUNK_LZ4
);

pub(crate) unsafe fn decode_pipeline_chunk(
    worker: &WorkerContext,
    chunk: &AmprPackChunkView,
    destination: *mut u8,
    pipeline: &mut ReadPipelineContext,
    raw_offset: usize,
    raw_length: usize,
) -> c_int {
    unsafe {
        let relative = (chunk.offset - pipeline.io_window_offset) as usize;
        let stored = pipeline.io_window_data.add(relative);
        let mut rc = 0;
        if chunk.codec == AMPR_PACK_CHUNK_RAW {
            // Bypassed partial reads need no full-chunk decoded scratch copy.
        } else if chunk.codec == PIPELINE_COMPRESSED_CODEC {
            let raw_size = chunk.raw_size as usize;
            let input = core::slice::from_raw_parts(stored, chunk.stored_size as usize);
            let output = core::slice::from_raw_parts_mut(destination, raw_size);
            // zstd: one zstd frame per chunk (content size checked).
            let decoded = if zstd_mode() {
                match worker.decoder.as_mut() {
                    Some(decoder) => {
                        decoder.decode(ampr_codec::ZSTD_CODEC_ZSTD, raw_size, input, output)
                    }
                    None => Err(ampr_codec::Error::InvalidArgument),
                }
            } else {
                ampr_lz4::decode_chunk(AMPR_PACK_CHUNK_LZ4, 0, raw_size, input, output)
            };
            if decoded.is_err() {
                invalidate_physical_pages_for_chunk(chunk);
                rc = SCE_KERNEL_ERROR_EIO;
            }
        } else {
            rc = SCE_KERNEL_ERROR_EINVAL;
        }
        if rc == 0 && chunk.codec == AMPR_PACK_CHUNK_RAW {
            copy_nonoverlapping(stored.add(raw_offset), destination, raw_length);
        }
        rc
    }
}

/// Fails the read: cleans up the continuation and reports `error`.
unsafe fn fail_virtual_read(
    pipeline: &mut ReadPipelineContext,
    error: c_int,
    error_out: *mut c_int,
) -> PipelineStep {
    unsafe {
        cleanup_pipeline_continuation(pipeline, error);
        if !error_out.is_null() {
            *error_out = error;
        }
    }
    PipelineStep::Failed
}

pub(crate) unsafe fn advance_virtual_read_aio(
    job: &mut VirtualAioSlot,
    worker: &mut WorkerContext,
    pipeline: &mut ReadPipelineContext,
    return_value: *mut i64,
    error_out: *mut c_int,
) -> PipelineStep {
    unsafe {
        if !return_value.is_null() {
            *return_value = 0;
        }
        if !error_out.is_null() {
            *error_out = 0;
        }
        let set_error = |error: c_int| {
            if !error_out.is_null() {
                *error_out = error;
            }
            PipelineStep::Failed
        };
        let state = pack_state();
        // A read-ahead job (readahead.rs) has no result or destination: it only loads
        // missing chunks into the decoded cache and skips every other chunk.
        let prefetch = job.prefetch_chunks != 0;
        if (job.request.result.is_null() && !prefetch) || job.request.offset < 0 {
            return set_error(SCE_KERNEL_ERROR_EINVAL);
        }
        let Some((file_ptr, logical_size, file_flags)) = packed_read_file(state, job.file_id)
        else {
            return set_error(SCE_KERNEL_ERROR_ENOENT);
        };
        let offset = job.request.offset as u64;
        if job.request.nbyte == 0 || offset >= logical_size {
            return PipelineStep::Complete;
        }
        if job.request.buf.is_null() && !prefetch {
            return set_error(SCE_KERNEL_ERROR_EFAULT);
        }
        // Task destination offsets are u32: a read of 4 GiB or more is cut
        // to a short read at that limit instead of failing part-way with EIO.
        let length = (job.request.nbyte as u64).min(logical_size - offset).min(u32::MAX as u64);
        if pipeline.task_count == 0 {
            pipeline.task_count = ampr_pack_core_task_count(file_ptr, offset, length);
            if pipeline.task_count == 0 {
                return set_error(SCE_KERNEL_ERROR_EIO);
            }
        }
        if pipeline.native_completion_ready {
            if let Some(step) = finish_virtual_read_native_io(pipeline, error_out) {
                return step;
            }
        }
        let output = job.request.buf as *mut u8;
        while pipeline.task_index < pipeline.task_count {
            if pipeline.mandatory_plan_active && pipeline.task_index >= pipeline.mandatory_task_end
            {
                release_pipeline_window_pages(pipeline);
                pipeline.io_window_valid = false;
                pipeline.io_window_data = null();
                release_mandatory_page_plan(pipeline);
            }
            if pipeline.mandatory_skip_task != pipeline.task_index {
                pipeline.mandatory_skip_task = usize::MAX;
            }
            if job.cancel_requested.load(Ordering::Acquire) {
                return fail_virtual_read(pipeline, SCE_KERNEL_ERROR_ECANCELED, error_out);
            }
            let mut task = AmprPackBlockReadTask::default();
            let task_rc = ampr_pack_core_make_task(
                &(*state).core_view,
                file_ptr,
                offset,
                length,
                pipeline.task_index,
                &mut task,
            );
            if task_rc != AMPR_PACK_CORE_OK
                || task.chunk_index as u64 >= pack_chunk_count(state)
                || task.destination_offset as u64 + task.copy_length as u64 > length
            {
                return fail_virtual_read(pipeline, SCE_KERNEL_ERROR_EIO, error_out);
            }
            let chunk = task.chunk;
            if !pipeline.mandatory_plan_active
                && pipeline.mandatory_skip_task != pipeline.task_index
                && !pipeline_window_contains(pipeline, &chunk)
            {
                let mut group_error = 0;
                let grouped = prepare_mandatory_page_group(
                    file_ptr,
                    offset,
                    length,
                    pipeline,
                    prefetch,
                    &mut group_error,
                );
                if matches!(
                    grouped,
                    PipelineStep::YieldIo | PipelineStep::YieldCache | PipelineStep::YieldFd
                ) {
                    return grouped;
                }
                if grouped == PipelineStep::Failed {
                    return fail_virtual_read(pipeline, group_error, error_out);
                }
            }
            if pipeline.decoded_lease.entry == INVALID_INDEX {
                match acquire_task_decoded_chunk(
                    pipeline, &chunk, &task, file_flags, prefetch, output, error_out,
                ) {
                    Ok(true) => {
                        pipeline.task_index += 1;
                        continue;
                    }
                    Ok(false) => {}
                    Err(step) => return step,
                }
            }

            if !pipeline_window_contains(pipeline, &chunk)
                && !bind_mandatory_page_window(&chunk, pipeline)
            {
                if let Some(step) = prepare_task_window(pipeline, &chunk, prefetch, error_out) {
                    return step;
                }
            }

            let decode_rc =
                decode_task_chunk(state, worker, pipeline, &chunk, &task, prefetch, output);
            if decode_rc != 0 {
                return fail_virtual_read(pipeline, decode_rc, error_out);
            }
            pipeline.task_index += 1;
        }
        release_pipeline_window_pages(pipeline);
        release_mandatory_page_plan(pipeline);
        pipeline.io_window_valid = false;
        pipeline.io_window_data = null();
        if !return_value.is_null() {
            *return_value = length as i64;
        }
        PipelineStep::Complete
    }
}

/// Finishes the completed native read (mandatory group or window). Some(step)
/// when the read must return: a refused submit to retry or a failure.
unsafe fn finish_virtual_read_native_io(
    pipeline: &mut ReadPipelineContext,
    error_out: *mut c_int,
) -> Option<PipelineStep> {
    // Only a refused reactor submit (every external slot still
    // published) leaves EAGAIN here; SubmitFailed never carries it.
    let submit_eagain = pipeline.native_io_error == SCE_KERNEL_ERROR_EAGAIN;
    let finish_rc = if pipeline.mandatory_plan_active && pipeline.mandatory_request_count != 0 {
        finish_mandatory_page_group(pipeline)
    } else {
        finish_pipeline_window_aio(pipeline)
    };
    if submit_eagain && finish_rc == SCE_KERNEL_ERROR_EAGAIN {
        // The pages were dropped as transient: retry the submit. The
        // reactor frees its slot right after the callback, and
        // reset_native_wait cleared the fd wait epochs, so worker.rs requeues
        // this job at once instead of parking it.
        return Some(PipelineStep::YieldFd);
    }
    if finish_rc != 0 {
        return Some(fail_virtual_read(pipeline, finish_rc, error_out));
    }
    None
}

/// Looks the task's chunk up in the decoded cache: a hit is copied out, a
/// miss takes the loader lease. Ok(true) when the task is finished (copied,
/// or nothing to prefetch), Ok(false) when the chunk must be decoded,
/// Err(step) to return.
#[allow(clippy::too_many_arguments)]
unsafe fn acquire_task_decoded_chunk(
    pipeline: &mut ReadPipelineContext,
    chunk: &AmprPackChunkView,
    task: &AmprPackBlockReadTask,
    file_flags: u32,
    prefetch: bool,
    output: *mut u8,
    error_out: *mut c_int,
) -> Result<bool, PipelineStep> {
    prepare_cache_wait(pipeline, CacheWaitDomain::Decoded, chunk_key_hash(chunk));
    let mut cache = cache_acquire(chunk, file_flags, false, prefetch);
    if prefetch && cache.kind != CacheAcquireKind::Load {
        // Cached, being loaded, failed or no room: nothing to prefetch.
        cache_release(&mut cache.lease);
        return Ok(true);
    }
    // Pending retries the lookup after the loader publishes; count the final kind only.
    match cache.kind {
        CacheAcquireKind::Load | CacheAcquireKind::Bypass => {
            let repeat =
                cfg!(feature = "mem_report") && stats::chunk_seen_before(chunk_key_hash(chunk));
            if !prefetch {
                stats::add(stats::Stat::CacheMisses, 1);
                stats::add(
                    if repeat {
                        stats::Stat::CacheMissRepeat
                    } else {
                        stats::Stat::CacheMissFirst
                    },
                    1,
                );
            }
        }
        _ if prefetch => {}
        CacheAcquireKind::Ready => stats::add(stats::Stat::CacheHits, 1),
        CacheAcquireKind::Pending | CacheAcquireKind::Failed => {}
    }
    match cache.kind {
        CacheAcquireKind::Pending => return Err(PipelineStep::YieldCache),
        CacheAcquireKind::Failed => {
            let error = if cache.lease.error != 0 {
                cache.lease.error
            } else {
                SCE_KERNEL_ERROR_EIO
            };
            return Err(fail_virtual_read(pipeline, error, error_out));
        }
        CacheAcquireKind::Ready => {
            timed_copy(
                cache.lease.data.add(task.source_offset as usize),
                output.add(task.destination_offset as usize),
                task.copy_length as usize,
            );
            cache_release(&mut cache.lease);
            return Ok(true);
        }
        CacheAcquireKind::Load => pipeline.decoded_lease = cache.lease,
        CacheAcquireKind::Bypass => {}
    }
    Ok(false)
}

/// Prepares the single-chunk I/O window of a chunk outside every window.
/// Some(step) when the read must return (I/O, cache or fd wait, failure).
#[inline]
unsafe fn prepare_task_window(
    pipeline: &mut ReadPipelineContext,
    chunk: &AmprPackChunkView,
    prefetch: bool,
    error_out: *mut c_int,
) -> Option<PipelineStep> {
    let mut range = PipelineIoRange::EMPTY;
    let range_rc = make_pipeline_window_range(chunk, &mut range);
    if range_rc != 0 {
        return Some(fail_virtual_read(pipeline, range_rc, error_out));
    }
    let mut prepare_error = 0;
    let prepared = prepare_pipeline_window_aio(&range, pipeline, prefetch, &mut prepare_error);
    if matches!(
        prepared,
        PipelineStep::YieldIo | PipelineStep::YieldCache | PipelineStep::YieldFd
    ) {
        return Some(prepared);
    }
    if prepared == PipelineStep::Failed {
        return Some(fail_virtual_read(pipeline, prepare_error, error_out));
    }
    None
}

/// Decodes the task's chunk from the bound window into the loader lease, the
/// destination or the worker scratch, publishes a loader lease and copies
/// the task's bytes out. Returns the decode result.
#[allow(clippy::too_many_arguments)]
unsafe fn decode_task_chunk(
    state: *mut PackState,
    worker: &mut WorkerContext,
    pipeline: &mut ReadPipelineContext,
    chunk: &AmprPackChunkView,
    task: &AmprPackBlockReadTask,
    prefetch: bool,
    output: *mut u8,
) -> c_int {
    let cache_loader = pipeline.decoded_lease.entry != INVALID_INDEX;
    let decoded = if cache_loader {
        pipeline.decoded_lease.data
    } else if chunk.codec == AMPR_PACK_CHUNK_RAW
        || (task.source_offset == 0 && task.copy_length == chunk.raw_size)
    {
        output.add(task.destination_offset as usize)
    } else {
        worker.decoded_scratch
    };
    let raw_bypass = !cache_loader && chunk.codec == AMPR_PACK_CHUNK_RAW;
    let raw_length = if raw_bypass {
        task.copy_length as usize
    } else {
        chunk.raw_size as usize
    };
    let decode_start = stats::now();
    let decode_rc = decode_pipeline_chunk(
        worker,
        chunk,
        decoded,
        pipeline,
        if raw_bypass {
            task.source_offset as usize
        } else {
            0
        },
        raw_length,
    );
    stats::add(stats::Stat::Decodes, 1);
    stats::add(stats::Stat::DecodeNs, stats::since(decode_start));
    if decode_rc == 0 {
        stats::add(stats::Stat::DecodedBytes, raw_length as u64);
    } else {
        stats::add(stats::Stat::DecodeErrors, 1);
    }
    if cache_loader {
        let publish_rc = if prefetch && decode_rc != 0 {
            SCE_KERNEL_ERROR_EAGAIN
        } else {
            decode_rc
        };
        let waited = cache_publish(&mut pipeline.decoded_lease, publish_rc);
        if waited || prefetch {
            // Requeue game reads parked on this chunk now, not after the whole run.
            let g = PACK_M.lock();
            if wake_cache_waiters_locked(state) {
                drop(g);
                QUEUE_CV.notify_all();
            }
        }
        if decode_rc == 0 && !prefetch {
            timed_copy(
                pipeline.decoded_lease.data.add(task.source_offset as usize),
                output.add(task.destination_offset as usize),
                task.copy_length as usize,
            );
        }
        cache_release(&mut pipeline.decoded_lease);
    } else if decode_rc == 0 && decoded == worker.decoded_scratch {
        timed_copy(
            decoded.add(task.source_offset as usize),
            output.add(task.destination_offset as usize),
            task.copy_length as usize,
        );
    }
    decode_rc
}
