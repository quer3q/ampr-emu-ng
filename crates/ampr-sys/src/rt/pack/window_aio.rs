//! Pipeline window AIO: one exact-size native read per window and its
//! completion, and pack fd release.

use super::*;

unsafe fn clear_native_submitted(pipeline: &mut ReadPipelineContext) {
    unsafe { AtomicBool::from_ptr(&mut pipeline.native_submitted) }.store(false, Ordering::Release);
}

#[inline]
unsafe fn set_error_out(error_out: *mut c_int, error: c_int) {
    if !error_out.is_null() {
        *error_out = error;
    }
}

pub(crate) unsafe fn release_pack_fd(pack_id: u16) {
    let state = pack_state();
    let mut wake_workers = false;
    {
        let _lock = PACK_M.lock();
        if pack_id as u32 >= pack_volume_count(state) {
            return;
        }
        let handle = &mut (*state).pack_handles[pack_id as usize];
        if handle.pins != 0 {
            handle.pins -= 1;
            PACK_FD_PROGRESS_EPOCH.fetch_add(1, Ordering::Release);
            wake_workers = wake_fd_waiters_locked(state);
        }
        (*state).pack_handles[pack_id as usize].last_use = (*state).tick;
        (*state).tick += 1;
    }
    if wake_workers {
        QUEUE_CV.notify_all();
    }
}

pub(crate) unsafe fn pipeline_window_contains(
    pipeline: &ReadPipelineContext,
    chunk: &AmprPackChunkView,
) -> bool {
    if !pipeline.io_window_valid || pipeline.io_window_pack_id != chunk.pack_id {
        return false;
    }
    let mut chunk_end = 0u64;
    let mut window_end = 0u64;
    checked_add_u64(chunk.offset, chunk.stored_size as u64, &mut chunk_end)
        && checked_add_u64(
            pipeline.io_window_offset,
            pipeline.io_window_size as u64,
            &mut window_end,
        )
        && chunk.offset >= pipeline.io_window_offset
        && chunk_end <= window_end
}

pub(crate) unsafe fn ensure_pipeline_io_scratch(pipeline: &mut ReadPipelineContext) -> bool {
    if !pipeline.io_scratch.is_null() {
        return pipeline.io_scratch_size >= PACK_PIPELINE_IO_BYTES;
    }
    // The worker start (worker.rs `ensure_workers_locked`) gives every
    // pipeline its window, so this is a defensive check: refused, the
    // read fails ENOMEM.
    let (scratch, actual) = crate::rt::index_memory::buffer_alloc(
        PACK_PIPELINE_IO_BYTES,
        c"apr.pack.pipeline.io-window".as_ptr(),
    );
    if scratch.is_null() {
        return false;
    }
    pipeline.io_scratch = scratch;
    pipeline.io_scratch_size = actual;
    true
}

// ---- exact-size chunk reads ----
//
// Every chunk is read as its stored bytes only (virtual_read.rs
// `prepare_exact_task_window`), into the pipeline io scratch. The
// decoded-chunk cache is unaffected (acquired before the window).

/// One native read of exactly `range` (any byte offset and length, no page
/// alignment; the pack fd has no direct I/O) into the pipeline io scratch:
/// pins the pack fd and sets up the request for the reactor (worker.rs).
/// finish_pipeline_window_aio binds the scratch as the window
/// [range.offset, + range.length).
pub(crate) unsafe fn prepare_exact_window_aio(
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    prefetch: bool,
    error_out: *mut c_int,
) -> PipelineStep {
    unsafe {
        set_error_out(error_out, 0);
        if range.length == 0 || range.length as usize > PACK_PIPELINE_IO_BYTES {
            set_error_out(error_out, SCE_KERNEL_ERROR_EINVAL);
            return PipelineStep::Failed;
        }
        pipeline.io_window_valid = false;
        pipeline.io_window_data = null();
        pipeline.io_range = *range;
        if !ensure_pipeline_io_scratch(pipeline) {
            pipeline.io_range = PipelineIoRange::EMPTY;
            set_error_out(error_out, SCE_KERNEL_ERROR_ENOMEM);
            return PipelineStep::Failed;
        }
        pipeline.fd_wait_epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Acquire);
        pipeline.fd_budget_wait_epoch = ampr_index_fd_open_budget_progress_generation();
        let fd = acquire_pack_fd(range.pack_id, prefetch);
        if fd < 0 {
            pipeline.io_range = PipelineIoRange::EMPTY;
            if fd == SCE_KERNEL_ERROR_EAGAIN {
                return PipelineStep::YieldFd;
            }
            set_error_out(error_out, fd);
            return PipelineStep::Failed;
        }
        let state = pack_state();
        let mut in_range = false;
        {
            let _lock = PACK_M.lock();
            // zstd: [payload_begin, payload_end) is [0, volume size).
            if (range.pack_id as u32) < pack_volume_count(state) {
                let handle = &(*state).pack_handles[range.pack_id as usize];
                let mut end = 0u64;
                in_range = handle.fd == fd
                    && checked_add_u64(range.offset, range.length as u64, &mut end)
                    && range.offset >= handle.payload_begin
                    && end <= handle.payload_end;
            }
        }
        if !in_range {
            release_pack_fd(range.pack_id);
            pipeline.io_range = PipelineIoRange::EMPTY;
            set_error_out(error_out, SCE_KERNEL_ERROR_EIO);
            return PipelineStep::Failed;
        }

        pipeline.pack_fd = fd;
        pipeline.native_result = SceKernelAioResult::EMPTY;
        pipeline.native_request.offset = range.offset as off_t;
        pipeline.native_request.nbyte = range.length as usize;
        pipeline.native_request.buf = pipeline.io_scratch as *mut c_void;
        pipeline.native_request.result = &mut pipeline.native_result;
        pipeline.native_request.fd = fd;
        pipeline.native_io_error = 0;
        pipeline.native_completion_ready = false;
        clear_native_submitted(pipeline);
        PipelineStep::YieldIo
    }
}

unsafe fn reset_native_wait(pipeline: &mut ReadPipelineContext) {
    pipeline.cache_wait_epoch = 0;
    pipeline.cache_wait_bucket = 0;
    pipeline.fd_wait_epoch = 0;
    pipeline.fd_budget_wait_epoch = 0;
    pipeline.native_io_error = 0;
    pipeline.native_completion_ready = false;
    unsafe { clear_native_submitted(pipeline) };
}

/// Completes the window read: a short read is EIO, and the scratch becomes
/// the window. The read ends at a chunk end, inside the volume, so it
/// needs no volume-end completion.
pub(crate) unsafe fn finish_pipeline_window_aio(pipeline: &mut ReadPipelineContext) -> c_int {
    unsafe {
        let mut error = pipeline.native_io_error;
        let range = pipeline.io_range;
        let return_value = pipeline.native_result.return_value;
        if error == 0 && return_value != pipeline.native_request.nbyte as i64 {
            error = if return_value < 0 {
                return_value as c_int
            } else {
                SCE_KERNEL_ERROR_EIO
            };
        }
        if pipeline.pack_fd >= 0 {
            // A stale-fd error becomes EAGAIN once: the job retries on a
            // reopened fd (leases.rs).
            let read_error = error;
            let read_ran =
                AtomicBool::from_ptr(&mut pipeline.native_submitted).load(Ordering::Acquire);
            error =
                release_pack_fd_after_read(range.pack_id, pipeline.pack_fd, read_error, read_ran);
            pipeline.fd_reopen_retry =
                pack_fd_error_wants_reopen(read_error) && error == SCE_KERNEL_ERROR_EAGAIN;
            pipeline.pack_fd = -1;
        }
        pipeline.native_request = SceKernelAioRWRequest::EMPTY;
        pipeline.native_result = SceKernelAioResult::EMPTY;
        reset_native_wait(pipeline);
        if error != 0 {
            pipeline.io_window_data = null();
            pipeline.io_range = PipelineIoRange::EMPTY;
            return error;
        }
        pipeline.io_window_offset = range.offset;
        pipeline.io_window_size = range.length;
        pipeline.io_window_pack_id = range.pack_id;
        pipeline.io_window_valid = true;
        pipeline.io_window_data = pipeline.io_scratch;
        pipeline.io_range = PipelineIoRange::EMPTY;
        0
    }
}

