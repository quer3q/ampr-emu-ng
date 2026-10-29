//! Pipeline window AIO submission and completion, mandatory group finish
//! and physical page invalidation.

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

pub(crate) unsafe fn prepare_pipeline_window_aio(
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    prefetch: bool,
    error_out: *mut c_int,
) -> PipelineStep {
    unsafe {
        let set_err = |e: c_int| set_error_out(error_out, e);
        set_err(0);
        let state = pack_state();
        let io_page_size = match pack_io_page_size(state, range.pack_id) {
            Some(size) if range.length != 0 && range.length as usize <= PACK_PIPELINE_IO_BYTES => {
                size
            }
            _ => {
                set_err(SCE_KERNEL_ERROR_EINVAL);
                return PipelineStep::Failed;
            }
        };
        if range.io_page_size != io_page_size
            || (range.offset & (io_page_size as u64).wrapping_sub(1)) != 0
            || (range.length & io_page_size.wrapping_sub(1)) != 0
        {
            set_err(SCE_KERNEL_ERROR_EIO);
            return PipelineStep::Failed;
        }
        let page_count = (range.length / io_page_size) as usize;
        if page_count == 0 || page_count > PACK_PIPELINE_MAX_IO_PAGES {
            set_err(SCE_KERNEL_ERROR_ENOMEM);
            return PipelineStep::Failed;
        }

        release_pipeline_window_pages(pipeline);
        pipeline.io_window_valid = false;
        pipeline.io_window_data = null();
        pipeline.io_range = *range;
        pipeline.io_page_count = page_count;
        let mut acq = WindowAcquire {
            needs_physical_io: false,
            waits_for_loader: false,
            pending_pages: 0,
            all_ready: true,
            all_load: true,
            cache_contiguous: true,
            cache_window: null_mut(),
            error: 0,
        };
        if !acquire_window_pages(state, range, pipeline, page_count, io_page_size, &mut acq) {
            abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
            pipeline.io_range = PipelineIoRange::EMPTY;
            set_err(SCE_KERNEL_ERROR_EIO);
            return PipelineStep::Failed;
        }
        // zstd: with pages of its own to load, read the pending ones too (a
        // shared chunk-boundary page, ~0.7 ms of waiting saved); with none,
        // the other job's read brings everything: wait for it, not re-read.
        if acq.pending_pages != 0 {
            if acq.needs_physical_io {
                stats::add(stats::Stat::PrivatePageReads, acq.pending_pages);
            } else {
                acq.waits_for_loader = true;
            }
        }
        let error = acq.error;
        if error != 0 || acq.waits_for_loader {
            // Do not retain a loader lease while waiting for another page: that
            // could form a cycle between two exact windows. EAGAIN is transient
            // and release removes the temporary failed entry once unpinned.
            abandon_pipeline_page_plan(
                pipeline,
                if error != 0 {
                    error
                } else {
                    SCE_KERNEL_ERROR_EAGAIN
                },
            );
            pipeline.io_range = PipelineIoRange::EMPTY;
            if error != 0 {
                set_err(error);
                return PipelineStep::Failed;
            }
            return PipelineStep::YieldCache;
        }
        if !acq.needs_physical_io {
            return finish_cached_window(
                range,
                pipeline,
                page_count,
                io_page_size,
                &acq,
                error_out,
            );
        }
        submit_window_read(
            state,
            range,
            pipeline,
            prefetch,
            page_count,
            io_page_size,
            &acq,
            error_out,
        )
    }
}

/// What acquiring the pages of one pipeline window found.
struct WindowAcquire {
    needs_physical_io: bool,
    waits_for_loader: bool,
    /// zstd: pages another job is loading (see the Pending arm below).
    pending_pages: u64,
    all_ready: bool,
    all_load: bool,
    cache_contiguous: bool,
    cache_window: *mut u8,
    error: c_int,
}

/// Acquires every page of the window in one batch and classifies the
/// results into `acq`. False when the batch acquired nothing.
unsafe fn acquire_window_pages(
    state: *mut PackState,
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    page_count: usize,
    io_page_size: u32,
    acq: &mut WindowAcquire,
) -> bool {
    let zstd_on = zstd_mode();
    // Every item in [..page_count] is written below; skip zero-filling 12 KiB.
    let mut acquire_items = [const { MaybeUninit::<PhysicalCacheAcquireBatchItem>::uninit() };
        PACK_PIPELINE_MAX_IO_PAGES];
    let mut wait_buckets = [0u16; PACK_PIPELINE_MAX_IO_PAGES];
    let mut wait_epochs = [0u64; PACK_PIPELINE_MAX_IO_PAGES];
    for page in 0..page_count {
        let page_offset = range.offset + page as u64 * io_page_size as u64;
        let key_hash = physical_cache_key_hash(range.pack_id, page_offset, io_page_size);
        wait_buckets[page] = cache_wait_bucket(key_hash) as u16;
        wait_epochs[page] =
            cache_wait_epoch(state, CacheWaitDomain::Physical, wait_buckets[page] as u32);
        pipeline.io_pages[page] = PhysicalCacheAcquireResult::EMPTY;
        acquire_items[page].write(PhysicalCacheAcquireBatchItem {
            result: &mut pipeline.io_pages[page],
            offset: page_offset,
            size: io_page_size,
            pack_id: range.pack_id,
        });
    }
    let acquired_count = physical_cache_acquire_batch(acquire_items.as_ptr().cast(), page_count);
    if acquired_count == 0 {
        return false;
    }
    for page in 0..page_count {
        let acquired = pipeline.io_pages[page];
        match acquired.kind {
            PhysicalCacheAcquireKind::Ready => acq.all_load = false,
            PhysicalCacheAcquireKind::Load => {
                acq.all_ready = false;
                acq.needs_physical_io = true;
            }
            PhysicalCacheAcquireKind::Bypass => {
                acq.all_ready = false;
                acq.all_load = false;
                acq.cache_contiguous = false;
                acq.needs_physical_io = true;
            }
            // zstd: a page another job is loading is read privately
            // into the I/O window (a Pending result holds no lease) when
            // this window goes to disk anyway; decided after the loop.
            PhysicalCacheAcquireKind::Pending if zstd_on => {
                acq.all_ready = false;
                acq.all_load = false;
                acq.cache_contiguous = false;
                acq.pending_pages += 1;
                pipeline.cache_wait_domain = CacheWaitDomain::Physical;
                pipeline.cache_wait_bucket = wait_buckets[page];
                pipeline.cache_wait_epoch = wait_epochs[page];
            }
            PhysicalCacheAcquireKind::Pending => {
                acq.all_ready = false;
                acq.all_load = false;
                acq.waits_for_loader = true;
                pipeline.cache_wait_domain = CacheWaitDomain::Physical;
                pipeline.cache_wait_bucket = wait_buckets[page];
                pipeline.cache_wait_epoch = wait_epochs[page];
            }
            PhysicalCacheAcquireKind::Failed => {
                acq.all_ready = false;
                acq.all_load = false;
                acq.error = if acquired.lease.error != 0 {
                    acquired.lease.error
                } else {
                    SCE_KERNEL_ERROR_EIO
                };
            }
        }
        if acquired.lease.entry != INVALID_INDEX {
            let expected = if !acq.cache_window.is_null() {
                acq.cache_window.add(page * io_page_size as usize)
            } else {
                acquired.lease.data
            };
            if acq.cache_window.is_null() {
                acq.cache_window = acquired.lease.data;
            }
            if acquired.lease.data != expected {
                acq.cache_contiguous = false;
            }
        } else {
            acq.cache_contiguous = false;
        }
        if acq.error != 0 {
            break;
        }
    }
    true
}

/// A window whose pages are all cached: served from the cache memory when
/// contiguous, else copied into the pipeline io scratch.
unsafe fn finish_cached_window(
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    page_count: usize,
    io_page_size: u32,
    acq: &WindowAcquire,
    error_out: *mut c_int,
) -> PipelineStep {
    if !acq.all_ready {
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
        pipeline.io_range = PipelineIoRange::EMPTY;
        set_error_out(error_out, SCE_KERNEL_ERROR_EIO);
        return PipelineStep::Failed;
    }
    if acq.cache_contiguous && !acq.cache_window.is_null() {
        pipeline.io_window_data = acq.cache_window;
    } else {
        if !ensure_pipeline_io_scratch(pipeline) {
            release_pipeline_window_pages(pipeline);
            pipeline.io_range = PipelineIoRange::EMPTY;
            set_error_out(error_out, SCE_KERNEL_ERROR_ENOMEM);
            return PipelineStep::Failed;
        }
        for page in 0..page_count {
            core::ptr::copy_nonoverlapping(
                pipeline.io_pages[page].lease.data,
                pipeline.io_scratch.add(page * io_page_size as usize),
                io_page_size as usize,
            );
        }
        release_pipeline_window_pages(pipeline);
        pipeline.io_window_data = pipeline.io_scratch;
    }
    pipeline.io_window_offset = range.offset;
    pipeline.io_window_size = range.length;
    pipeline.io_window_pack_id = range.pack_id;
    pipeline.io_window_valid = true;
    PipelineStep::Ready
}

/// A window that goes to disk: pins the pack fd and sets up one native read
/// into the cache memory (all pages loading and contiguous) or the scratch.
#[allow(clippy::too_many_arguments)]
unsafe fn submit_window_read(
    state: *mut PackState,
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    prefetch: bool,
    page_count: usize,
    io_page_size: u32,
    acq: &WindowAcquire,
    error_out: *mut c_int,
) -> PipelineStep {
    // Count only windows that go to disk: all-Ready windows mostly re-read
    // pages a mandatory group (page_plan.rs) just loaded and counted.
    let misses = pipeline.io_pages[..page_count]
        .iter()
        .filter(|p| {
            matches!(
                p.kind,
                PhysicalCacheAcquireKind::Load | PhysicalCacheAcquireKind::Bypass
            )
        })
        .count();
    stats::add(stats::Stat::PhysHits, (page_count - misses) as u64);
    stats::add(stats::Stat::PhysMisses, misses as u64);
    let cache_window = acq.cache_window;
    let direct_cache_read = acq.all_load && acq.cache_contiguous && !cache_window.is_null();
    if !direct_cache_read && !ensure_pipeline_io_scratch(pipeline) {
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_ENOMEM);
        pipeline.io_range = PipelineIoRange::EMPTY;
        set_error_out(error_out, SCE_KERNEL_ERROR_ENOMEM);
        return PipelineStep::Failed;
    }
    pipeline.fd_wait_epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Acquire);
    pipeline.fd_budget_wait_epoch = ampr_index_fd_open_budget_progress_generation();
    let fd = acquire_pack_fd(range.pack_id, prefetch);
    if fd < 0 {
        abandon_pipeline_page_plan(pipeline, fd);
        pipeline.io_range = PipelineIoRange::EMPTY;
        if fd == SCE_KERNEL_ERROR_EAGAIN {
            return PipelineStep::YieldFd;
        }
        set_error_out(error_out, fd);
        return PipelineStep::Failed;
    }
    let mut in_range = false;
    {
        let _lock = PACK_M.lock();
        // zstd: [payload_begin, payload_end) is [0, volume size aligned up).
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
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
        pipeline.io_range = PipelineIoRange::EMPTY;
        set_error_out(error_out, SCE_KERNEL_ERROR_EIO);
        return PipelineStep::Failed;
    }

    pipeline.pack_fd = fd;
    pipeline.native_result = SceKernelAioResult::EMPTY;
    pipeline.native_request.offset = range.offset as off_t;
    pipeline.native_request.nbyte = range.length as usize;
    pipeline.native_request.buf = if direct_cache_read {
        cache_window
    } else {
        pipeline.io_scratch
    } as *mut c_void;
    if zstd_mode() && !direct_cache_read {
        zstd_trim_window_read(range, pipeline, page_count, io_page_size);
    }
    pipeline.native_request.result = &mut pipeline.native_result;
    pipeline.native_request.fd = fd;
    pipeline.native_io_error = 0;
    pipeline.native_completion_ready = false;
    clear_native_submitted(pipeline);
    PipelineStep::YieldIo
}

/// zstd: read only the span of pages not already cached; the cached pages
/// outside it are copied into the window here (their leases are pinned). A
/// page another job is loading is in the span (read privately), so the
/// window never re-reads its cached neighbours.
#[inline]
unsafe fn zstd_trim_window_read(
    range: &PipelineIoRange,
    pipeline: &mut ReadPipelineContext,
    page_count: usize,
    io_page_size: u32,
) {
    let missing = |k: usize| pipeline.io_pages[k].kind != PhysicalCacheAcquireKind::Ready;
    if let (Some(first), Some(last)) = (
        (0..page_count).find(|&k| missing(k)),
        (0..page_count).rfind(|&k| missing(k)),
    ) {
        let size = io_page_size as usize;
        for k in (0..first).chain(last + 1..page_count) {
            core::ptr::copy_nonoverlapping(
                pipeline.io_pages[k].lease.data,
                pipeline.io_scratch.add(k * size),
                size,
            );
        }
        pipeline.native_request.offset = (range.offset + (first * size) as u64) as off_t;
        pipeline.native_request.nbyte = (last + 1 - first) * size;
        pipeline.native_request.buf = pipeline.io_scratch.add(first * size).cast();
    }
}

/// zstd: completes each mandatory backing read that stopped exactly at its
/// volume end (the last page is aligned past it; `zstd_complete_eof_read`).
/// The request's pages name its volume.
unsafe fn zstd_complete_mandatory_eof_reads(pipeline: &mut ReadPipelineContext) {
    for request_index in 0..pipeline.mandatory_request_count {
        let Some(page) = pipeline.mandatory_pages[..pipeline.mandatory_page_count]
            .iter()
            .find(|p| p.request_index as usize == request_index)
        else {
            continue;
        };
        let request = pipeline.mandatory_requests[request_index];
        if request.offset < 0 {
            continue;
        }
        unsafe {
            zstd_complete_eof_read(
                page.pack_id,
                request.offset as u64,
                request.nbyte,
                request.buf as *mut u8,
                &mut pipeline.mandatory_results[request_index].return_value,
            )
        };
    }
}

unsafe fn reset_native_wait(pipeline: &mut ReadPipelineContext) {
    pipeline.cache_wait_epoch = 0;
    pipeline.cache_wait_bucket = 0;
    pipeline.cache_wait_domain = CacheWaitDomain::Decoded;
    pipeline.fd_wait_epoch = 0;
    pipeline.fd_budget_wait_epoch = 0;
    pipeline.native_io_error = 0;
    pipeline.native_completion_ready = false;
    unsafe { clear_native_submitted(pipeline) };
}

pub(crate) unsafe fn finish_mandatory_page_group(pipeline: &mut ReadPipelineContext) -> c_int {
    unsafe {
        let completion_error = pipeline.native_io_error;
        let mut group_error = completion_error;
        if zstd_mode() && completion_error == 0 {
            zstd_complete_mandatory_eof_reads(pipeline);
        }
        release_mandatory_fds(pipeline);
        let mut publications = [PhysicalCachePublication::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES];
        let mut publication_count = 0usize;
        for page_index in 0..pipeline.mandatory_page_count {
            let page = &mut pipeline.mandatory_pages[page_index];
            if page.acquired.kind != PhysicalCacheAcquireKind::Load {
                continue;
            }
            // A group-level lifecycle error invalidates the complete set. Once
            // native completion succeeds, each SDK result owns only the cache
            // pages covered by that request; one failed ID must not poison
            // successful sibling requests.
            let mut page_error = completion_error;
            let request_index = page.request_index as usize;
            if request_index >= pipeline.mandatory_request_count {
                page_error = SCE_KERNEL_ERROR_EIO;
            } else if page_error == 0 {
                let nbyte = pipeline.mandatory_requests[request_index].nbyte;
                let return_value = pipeline.mandatory_results[request_index].return_value;
                if return_value != nbyte as i64 {
                    page_error = if return_value < 0 {
                        return_value as c_int
                    } else {
                        SCE_KERNEL_ERROR_EIO
                    };
                }
            }
            if page_error == 0 && page.staging_offset != INVALID_INDEX {
                let staging_offset = page.staging_offset as usize;
                if pipeline.io_scratch.is_null()
                    || staging_offset > pipeline.io_scratch_size
                    || page.size as usize > pipeline.io_scratch_size - staging_offset
                {
                    page_error = SCE_KERNEL_ERROR_EIO;
                } else {
                    core::ptr::copy_nonoverlapping(
                        pipeline.io_scratch.add(staging_offset),
                        page.acquired.lease.data,
                        page.size as usize,
                    );
                }
            }
            // A failed read-extension page (page_plan.rs) is dropped as transient: no
            // task needs it, and a later read must not see it Failed.
            let publish_error = if page.extension && page_error != 0 {
                SCE_KERNEL_ERROR_EAGAIN
            } else {
                page_error
            };
            publications[publication_count] = PhysicalCachePublication {
                lease: &mut page.acquired.lease,
                error: publish_error,
            };
            publication_count += 1;
            page.acquired.kind = if page_error == 0 {
                PhysicalCacheAcquireKind::Ready
            } else {
                PhysicalCacheAcquireKind::Failed
            };
            if group_error == 0 && page_error != 0 && !page.extension {
                group_error = page_error;
            }
        }
        physical_cache_publish_batch(publications.as_ptr(), publication_count);
        clear_mandatory_requests(pipeline);
        reset_native_wait(pipeline);
        if group_error != 0 {
            release_mandatory_page_plan(pipeline);
        }
        group_error
    }
}

pub(crate) unsafe fn finish_pipeline_window_aio(pipeline: &mut ReadPipelineContext) -> c_int {
    unsafe {
        let mut error = pipeline.native_io_error;
        let range = pipeline.io_range;
        // zstd reads only part of the window into the scratch (prepare_pipeline_window_aio);
        // anywhere inside the scratch is a scratch read, not a cache window.
        let buf = pipeline.native_request.buf as *mut u8;
        let direct_cache_window = pipeline.io_scratch.is_null()
            || buf < pipeline.io_scratch
            || buf >= pipeline.io_scratch.wrapping_add(pipeline.io_scratch_size);
        let native_window_data = if direct_cache_window {
            buf as *const u8
        } else {
            pipeline.io_scratch as *const u8
        };
        if zstd_mode() && error == 0 {
            zstd_complete_eof_read(
                range.pack_id,
                pipeline.native_request.offset as u64,
                pipeline.native_request.nbyte,
                buf,
                &mut pipeline.native_result.return_value,
            );
        }
        let return_value = pipeline.native_result.return_value;
        if error == 0 && return_value != pipeline.native_request.nbyte as i64 {
            error = if return_value < 0 {
                return_value as c_int
            } else {
                SCE_KERNEL_ERROR_EIO
            };
        }
        if pipeline.pack_fd >= 0 {
            release_pack_fd(range.pack_id);
            pipeline.pack_fd = -1;
        }
        let mut publications = [PhysicalCachePublication::EMPTY; PACK_PIPELINE_MAX_IO_PAGES];
        let mut publication_count = 0usize;
        for page in 0..pipeline.io_page_count {
            let acquired = &mut pipeline.io_pages[page];
            if acquired.kind == PhysicalCacheAcquireKind::Load {
                if error == 0 && !direct_cache_window {
                    let page_size = range.io_page_size as usize;
                    core::ptr::copy_nonoverlapping(
                        pipeline.io_scratch.add(page * page_size),
                        acquired.lease.data,
                        page_size,
                    );
                }
                publications[publication_count] = PhysicalCachePublication {
                    lease: &mut acquired.lease,
                    error,
                };
                publication_count += 1;
                if error == 0 {
                    acquired.kind = PhysicalCacheAcquireKind::Ready;
                }
            }
        }
        physical_cache_publish_batch(publications.as_ptr(), publication_count);
        if error != 0 || !direct_cache_window {
            release_pipeline_window_pages(pipeline);
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
        pipeline.io_window_data = if direct_cache_window {
            native_window_data
        } else {
            pipeline.io_scratch
        };
        pipeline.io_range = PipelineIoRange::EMPTY;
        0
    }
}

pub(crate) unsafe fn invalidate_physical_pages_for_chunk(chunk: &AmprPackChunkView) {
    unsafe {
        let state = pack_state();
        let Some(page_size) = pack_io_page_size(state, chunk.pack_id) else {
            return;
        };
        let mut chunk_end = 0u64;
        let mut page_end = 0u64;
        if !checked_add_u64(chunk.offset, chunk.stored_size as u64, &mut chunk_end)
            || !align_up_u64(chunk_end, page_size as u64, &mut page_end)
        {
            return;
        }
        let mut page = align_down_u64(chunk.offset, page_size as u64);
        while page < page_end {
            physical_cache_invalidate(chunk.pack_id, page, page_size);
            page += page_size as u64;
        }
    }
}
