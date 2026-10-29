//! Pack fd release, pipeline page plans and mandatory page group preparation.

use super::*;

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

pub(crate) unsafe fn abandon_pipeline_page_plan(pipeline: &mut ReadPipelineContext, error: c_int) {
    // Only [..publication_count] is written and read; skip zero-filling 8 KiB.
    let mut publications =
        [const { MaybeUninit::<PhysicalCachePublication>::uninit() }; PACK_PIPELINE_MAX_IO_PAGES];
    let mut publication_count = 0;
    for page in 0..pipeline.io_page_count {
        let acquired = &mut pipeline.io_pages[page];
        if acquired.kind == PhysicalCacheAcquireKind::Load {
            publications[publication_count].write(PhysicalCachePublication {
                lease: &mut acquired.lease,
                error,
            });
            publication_count += 1;
        }
    }
    physical_cache_publish_batch(publications.as_ptr().cast(), publication_count);
    release_pipeline_window_pages(pipeline);
    pipeline.io_window_data = null();
}

pub(crate) unsafe fn release_pipeline_window_pages(pipeline: &mut ReadPipelineContext) {
    let count = pipeline.io_page_count;
    if count == 0 {
        return;
    }
    {
        let state = pack_state();
        let _lock = PHYSICAL_CACHE_MUTEX.lock();
        for acquired in &mut pipeline.io_pages[..count] {
            physical_cache_release_locked(state, &mut acquired.lease);
        }
    }
    pipeline.io_pages[..count].fill(PhysicalCacheAcquireResult::EMPTY);
    pipeline.io_page_count = 0;
}

pub(crate) unsafe fn release_mandatory_fds(pipeline: &mut ReadPipelineContext) {
    for fd_index in 0..pipeline.mandatory_fd_count {
        release_pack_fd(pipeline.mandatory_fd_pack_ids[fd_index]);
        pipeline.mandatory_fd_pack_ids[fd_index] = u16::MAX;
        pipeline.mandatory_fds[fd_index] = -1;
    }
    pipeline.mandatory_fd_count = 0;
}

pub(crate) fn clear_mandatory_requests(pipeline: &mut ReadPipelineContext) {
    for i in 0..pipeline.mandatory_request_count {
        pipeline.mandatory_requests[i] = SceKernelAioRWRequest::EMPTY;
        pipeline.mandatory_results[i] = SceKernelAioResult::EMPTY;
        pipeline.mandatory_request_uses_scratch[i] = false;
    }
    pipeline.mandatory_request_count = 0;
}

pub(crate) unsafe fn abandon_mandatory_page_plan(pipeline: &mut ReadPipelineContext, error: c_int) {
    let mut publications = [PhysicalCachePublication::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut publication_count = 0;
    for i in 0..pipeline.mandatory_page_count {
        let page = &mut pipeline.mandatory_pages[i];
        if page.acquired.kind == PhysicalCacheAcquireKind::Load {
            // Read-extension pages never stay Failed: no task asked for them.
            let error = if page.extension {
                SCE_KERNEL_ERROR_EAGAIN
            } else {
                error
            };
            publications[publication_count] = PhysicalCachePublication {
                lease: &mut page.acquired.lease,
                error,
            };
            publication_count += 1;
        }
    }
    physical_cache_publish_batch(publications.as_ptr(), publication_count);
    release_mandatory_page_plan(pipeline);
    release_mandatory_fds(pipeline);
    clear_mandatory_requests(pipeline);
}

pub(crate) unsafe fn release_mandatory_page_plan(pipeline: &mut ReadPipelineContext) {
    let mut leases = [null_mut::<PhysicalCacheLease>(); PACK_MANDATORY_GROUP_MAX_PAGES];
    for i in 0..pipeline.mandatory_page_count {
        leases[i] = &mut pipeline.mandatory_pages[i].acquired.lease;
    }
    physical_cache_release_batch(leases.as_ptr(), pipeline.mandatory_page_count);
    for i in 0..pipeline.mandatory_page_count {
        pipeline.mandatory_pages[i] = PipelineMandatoryPage::EMPTY;
    }
    pipeline.mandatory_page_count = 0;
    pipeline.mandatory_task_end = 0;
    pipeline.mandatory_plan_active = false;
}

pub(crate) fn find_mandatory_page(
    pipeline: &ReadPipelineContext,
    pack_id: u16,
    offset: u64,
    size: u32,
) -> usize {
    pipeline.mandatory_pages[..pipeline.mandatory_page_count]
        .iter()
        .position(|p| p.pack_id == pack_id && p.offset == offset && p.size == size)
        .unwrap_or(usize::MAX)
}

pub(crate) unsafe fn ensure_pipeline_io_scratch(pipeline: &mut ReadPipelineContext) -> bool {
    if !pipeline.io_scratch.is_null() {
        return pipeline.io_scratch_size >= PACK_PIPELINE_IO_BYTES;
    }
    let mut actual = 0usize;
    let scratch = ampr_internal_amm_pool_alloc(
        PACK_PIPELINE_IO_BYTES,
        &mut actual,
        c"apr.pack.pipeline.io-window".as_ptr(),
        false,
        64,
    ) as *mut u8;
    if scratch.is_null() || actual < PACK_PIPELINE_IO_BYTES {
        if !scratch.is_null() {
            ampr_internal_amm_pool_free(
                scratch.cast(),
                c"apr.pack.pipeline.io-window.fail".as_ptr(),
            );
        }
        return false;
    }
    pipeline.io_scratch = scratch;
    pipeline.io_scratch_size = actual;
    true
}

// ---- prepare_mandatory_page_group ---------------------------------------------

unsafe fn mandatory_fail(
    pipeline: &mut ReadPipelineContext,
    error: c_int,
    error_out: *mut c_int,
) -> PipelineStep {
    abandon_mandatory_page_plan(pipeline, error);
    if !error_out.is_null() {
        *error_out = error;
    }
    PipelineStep::Failed
}

/// Plans the mandatory page set of the tasks from `task_index` on (loop
/// head of prepare_mandatory_page_group), at most `max_pages` pages and, past
/// PACK_MANDATORY_GROUP_MAX_REQUESTS pages, at most PACK_PIPELINE_IO_BYTES.
/// Returns the task end, or Err(step).
unsafe fn plan_mandatory_pages(
    state: *const PackState,
    file: *const u8,
    logical_offset: u64,
    logical_length: u64,
    pipeline: &mut ReadPipelineContext,
    max_pages: usize,
    error_out: *mut c_int,
) -> Result<usize, PipelineStep> {
    let first_task = pipeline.task_index;
    let mut task_end = first_task;
    let mut planned_pack_count = 0usize;
    let mut planned_bytes = 0u64;
    for task_index in first_task..pipeline.task_count {
        let mut task = AmprPackBlockReadTask::default();
        let task_rc = ampr_pack_core_make_task(
            &(*state).core_view,
            file,
            logical_offset,
            logical_length,
            task_index,
            &mut task,
        );
        if task_rc != AMPR_PACK_CORE_OK || task.chunk_index as u64 >= pack_chunk_count(state) {
            return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
        }
        let chunk = task.chunk;
        // A file may span volumes: each chunk plans pages of its own volume.
        let io_page_size = match pack_io_page_size(state, chunk.pack_id) {
            Some(size) if chunk.stored_size != 0 => size,
            _ => return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out)),
        };
        let planned = &pipeline.mandatory_pages[..pipeline.mandatory_page_count];
        let pack_already_planned = planned.iter().any(|p| p.pack_id == chunk.pack_id);
        // A complete mandatory set owns all of its pack descriptors until its
        // backing AIO retires; never build one that cannot fit the FD cap.
        if !pack_already_planned && planned_pack_count >= AMPR_EMU_PACK_OPEN_PACK_FD_CAP as usize {
            break;
        }
        let mut chunk_end = 0u64;
        let mut page_end = 0u64;
        if !checked_add_u64(chunk.offset, chunk.stored_size as u64, &mut chunk_end)
            || !align_up_u64(chunk_end, io_page_size as u64, &mut page_end)
        {
            return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
        }
        let page_begin = align_down_u64(chunk.offset, io_page_size as u64);
        let mut missing_page_offsets = [0u64; PACK_MANDATORY_GROUP_MAX_PAGES];
        let mut missing_page_count = 0;
        let available_pages = max_pages - pipeline.mandatory_page_count;
        let mut page_capacity_exceeded = false;
        let mut page_offset = page_begin;
        while page_offset < page_end {
            if find_mandatory_page(pipeline, chunk.pack_id, page_offset, io_page_size) == usize::MAX
            {
                if missing_page_count >= available_pages {
                    page_capacity_exceeded = true;
                    break;
                }
                missing_page_offsets[missing_page_count] = page_offset;
                missing_page_count += 1;
            }
            page_offset += io_page_size as u64;
        }
        // Past one page per request, also cap the group at one staging window
        // (binds only for io pages above 16 KiB).
        let new_bytes = planned_bytes + missing_page_count as u64 * io_page_size as u64;
        if page_capacity_exceeded
            || (pipeline.mandatory_page_count + missing_page_count
                > PACK_MANDATORY_GROUP_MAX_REQUESTS
                && new_bytes > PACK_PIPELINE_IO_BYTES as u64)
        {
            break;
        }
        planned_bytes = new_bytes;
        planned_pack_count += !pack_already_planned as usize;
        for &offset in &missing_page_offsets[..missing_page_count] {
            pipeline.mandatory_pages[pipeline.mandatory_page_count] = PipelineMandatoryPage {
                acquired: PhysicalCacheAcquireResult::EMPTY,
                offset,
                size: io_page_size,
                request_index: INVALID_INDEX,
                staging_offset: INVALID_INDEX,
                pack_id: chunk.pack_id,
                extension: false,
            };
            pipeline.mandatory_page_count += 1;
        }
        task_end = task_index + 1;
    }
    Ok(task_end)
}

pub(crate) unsafe fn prepare_mandatory_page_group(
    file: *const u8,
    logical_offset: u64,
    logical_length: u64,
    pipeline: &mut ReadPipelineContext,
    prefetch: bool,
    error_out: *mut c_int,
) -> PipelineStep {
    let mut request_overflow = false;
    let step = prepare_mandatory_page_group_capped(
        file,
        logical_offset,
        logical_length,
        pipeline,
        prefetch,
        PACK_MANDATORY_GROUP_MAX_PAGES,
        &mut request_overflow,
        error_out,
    );
    if !request_overflow {
        return step;
    }
    // The cold pages were too fragmented for PACK_MANDATORY_GROUP_MAX_REQUESTS
    // backing requests and the plan was abandoned: plan no more pages than
    // requests, so each page needs at most one request.
    let step = prepare_mandatory_page_group_capped(
        file,
        logical_offset,
        logical_length,
        pipeline,
        prefetch,
        PACK_MANDATORY_GROUP_MAX_REQUESTS,
        &mut request_overflow,
        error_out,
    );
    if request_overflow {
        return mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out);
    }
    step
}

/// Acquires the physical cache entries of the planned pages in one batch.
/// Err(step) when a page is pending, bypassed or failed (plan abandoned).
unsafe fn acquire_mandatory_pages(
    state: *const PackState,
    pipeline: &mut ReadPipelineContext,
    first_task: usize,
    page_count: usize,
    error_out: *mut c_int,
) -> Result<(), PipelineStep> {
    let mut acquire_items = [PhysicalCacheAcquireBatchItem::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut wait_buckets = [0u16; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut wait_epochs = [0u64; PACK_MANDATORY_GROUP_MAX_PAGES];
    for i in 0..page_count {
        let page = &mut pipeline.mandatory_pages[i];
        let key_hash = physical_cache_key_hash(page.pack_id, page.offset, page.size);
        wait_buckets[i] = cache_wait_bucket(key_hash) as u16;
        wait_epochs[i] = cache_wait_epoch(state, CacheWaitDomain::Physical, wait_buckets[i] as u32);
        acquire_items[i] = PhysicalCacheAcquireBatchItem {
            result: &mut page.acquired,
            offset: page.offset,
            size: page.size,
            pack_id: page.pack_id,
        };
    }
    let acquired_count = physical_cache_acquire_batch(acquire_items.as_ptr(), page_count);
    for i in 0..acquired_count {
        let acquired = pipeline.mandatory_pages[i].acquired;
        match acquired.kind {
            PhysicalCacheAcquireKind::Ready | PhysicalCacheAcquireKind::Load => continue,
            // zstd: compressed chunks share their boundary page, so split
            // siblings and neighbouring reads often find it still loading.
            // When this group loads pages of its own anyway, the single-chunk
            // window (window_aio.rs) reads that page privately instead of waiting ~0.7
            // ms. A group whose missing pages all belong to another job's
            // load waits for it: one disk read, not two (re-reading those
            // doubled cache misses).
            PhysicalCacheAcquireKind::Pending
                if zstd_mode()
                    && pipeline.mandatory_pages[..acquired_count]
                        .iter()
                        .any(|p| p.acquired.kind == PhysicalCacheAcquireKind::Load) =>
            {
                abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
                pipeline.mandatory_skip_task = first_task;
                return Err(PipelineStep::Ready);
            }
            PhysicalCacheAcquireKind::Pending => {
                pipeline.cache_wait_domain = CacheWaitDomain::Physical;
                pipeline.cache_wait_bucket = wait_buckets[i];
                pipeline.cache_wait_epoch = wait_epochs[i];
                abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
                return Err(PipelineStep::YieldCache);
            }
            PhysicalCacheAcquireKind::Bypass => {
                abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
                pipeline.mandatory_skip_task = first_task;
                return Err(PipelineStep::Ready);
            }
            PhysicalCacheAcquireKind::Failed => {
                let error = if acquired.lease.error != 0 {
                    acquired.lease.error
                } else {
                    SCE_KERNEL_ERROR_EIO
                };
                return Err(mandatory_fail(pipeline, error, error_out));
            }
        }
    }
    if acquired_count != page_count {
        return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
    }
    Ok(())
}

/// Pins the pack fd of every cold (Load) page and checks the page lies in its
/// volume payload. Fills `load_order` with the cold page indices in plan
/// order and returns their count, or Err(step) (plan abandoned).
unsafe fn open_mandatory_load_pages(
    state: *const PackState,
    pipeline: &mut ReadPipelineContext,
    page_count: usize,
    prefetch: bool,
    load_order: &mut [usize; PACK_MANDATORY_GROUP_MAX_PAGES],
    error_out: *mut c_int,
) -> Result<usize, PipelineStep> {
    let mut load_count = 0;
    for i in 0..page_count {
        let page = pipeline.mandatory_pages[i];
        if page.acquired.kind != PhysicalCacheAcquireKind::Load {
            continue;
        }
        let mut fd_index = 0;
        while fd_index < pipeline.mandatory_fd_count
            && pipeline.mandatory_fd_pack_ids[fd_index] != page.pack_id
        {
            fd_index += 1;
        }
        if fd_index == pipeline.mandatory_fd_count {
            let fd = acquire_pack_fd(page.pack_id, prefetch);
            if fd < 0 {
                abandon_mandatory_page_plan(pipeline, fd);
                if fd == SCE_KERNEL_ERROR_EAGAIN {
                    return Err(PipelineStep::YieldFd);
                }
                if !error_out.is_null() {
                    *error_out = fd;
                }
                return Err(PipelineStep::Failed);
            }
            pipeline.mandatory_fd_pack_ids[fd_index] = page.pack_id;
            pipeline.mandatory_fds[fd_index] = fd;
            pipeline.mandatory_fd_count += 1;
        }
        let in_range = {
            let _lock = PACK_M.lock();
            let mut end = 0u64;
            // zstd: payload_begin is page 0, so the page holding the first
            // chunk (offset 64) is in range.
            (page.pack_id as u32) < pack_volume_count(state) && {
                let handle = &(*state).pack_handles[page.pack_id as usize];
                handle.fd == pipeline.mandatory_fds[fd_index]
                    && checked_add_u64(page.offset, page.size as u64, &mut end)
                    && page.offset >= handle.payload_begin
                    && end <= handle.payload_end
            }
        };
        if !in_range {
            return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
        }
        load_order[load_count] = i;
        load_count += 1;
    }
    Ok(load_count)
}

/// One planning attempt of at most `max_pages` pages. Sets `request_overflow`
/// (plan abandoned, returns Ready) when the cold pages need more backing
/// requests than one group may issue.
#[allow(clippy::too_many_arguments)]
unsafe fn prepare_mandatory_page_group_capped(
    file: *const u8,
    logical_offset: u64,
    logical_length: u64,
    pipeline: &mut ReadPipelineContext,
    prefetch: bool,
    max_pages: usize,
    request_overflow: &mut bool,
    error_out: *mut c_int,
) -> PipelineStep {
    *request_overflow = false;
    if !error_out.is_null() {
        *error_out = 0;
    }
    let state = pack_state();
    if !pack_mount_ready(state)
        || pipeline.task_index >= pipeline.task_count
        || pipeline.mandatory_page_count != 0
        || pipeline.mandatory_request_count != 0
        || pipeline.mandatory_fd_count != 0
    {
        if !error_out.is_null() {
            *error_out = SCE_KERNEL_ERROR_EINVAL;
        }
        return PipelineStep::Failed;
    }
    let first_task = pipeline.task_index;
    let task_end = match plan_mandatory_pages(
        state,
        file,
        logical_offset,
        logical_length,
        pipeline,
        max_pages,
        error_out,
    ) {
        Ok(end) => end,
        Err(step) => return step,
    };
    if task_end == first_task || pipeline.mandatory_page_count == 0 {
        abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
        pipeline.mandatory_skip_task = first_task;
        return PipelineStep::Ready;
    }

    let page_count = pipeline.mandatory_page_count;
    if let Err(step) = acquire_mandatory_pages(state, pipeline, first_task, page_count, error_out) {
        return step;
    }
    let misses = pipeline.mandatory_pages[..page_count]
        .iter()
        .filter(|p| p.acquired.kind == PhysicalCacheAcquireKind::Load)
        .count();
    stats::add(stats::Stat::PhysHits, (page_count - misses) as u64);
    stats::add(stats::Stat::PhysMisses, misses as u64);
    // Extension is decided once per plan: only while the disk is quiet.
    let extend = super::super::tune::ext_bytes() != 0 && misses != 0 && read_extend_allowed();
    if extend {
        mandatory_reserve_extension(pipeline, page_count, max_pages);
    }

    pipeline.mandatory_task_end = task_end;
    pipeline.mandatory_plan_active = true;
    pipeline.fd_wait_epoch = PACK_FD_PROGRESS_EPOCH.load(Ordering::Acquire);
    pipeline.fd_budget_wait_epoch = ampr_index_fd_open_budget_progress_generation();
    let mut load_order = [0usize; PACK_MANDATORY_GROUP_MAX_PAGES];
    let load_count = match open_mandatory_load_pages(
        state,
        pipeline,
        page_count,
        prefetch,
        &mut load_order,
        error_out,
    ) {
        Ok(count) => count,
        Err(step) => return step,
    };

    // Cache allocation follows logical task order, which can interleave pack
    // lanes. Sort only the cold-page index list so physically adjacent pages
    // can share one backing AIO without changing task or cache ordering.
    let pages = &pipeline.mandatory_pages;
    load_order[..load_count].sort_unstable_by_key(|&i| (pages[i].pack_id, pages[i].offset));

    // zstd plans every backing read of the group itself (as few requests as
    // possible, bridging small cached gaps); the AMPRPAK4 loop below then has
    // no cold pages left.
    let load_count = if zstd_mode() {
        match zstd_append_mandatory_requests(
            pipeline,
            &load_order[..load_count],
            page_count,
            extend,
            request_overflow,
            error_out,
        ) {
            Ok(()) => 0,
            Err(step) => return step,
        }
    } else {
        load_count
    };

    if let Err(step) = append_mandatory_page_requests(
        pipeline,
        &load_order[..load_count],
        extend,
        max_pages,
        request_overflow,
        error_out,
    ) {
        return step;
    }
    if pipeline.mandatory_request_count == 0 {
        return PipelineStep::Ready;
    }
    pipeline.native_io_error = 0;
    pipeline.native_completion_ready = false;
    AtomicBool::from_ptr(&mut pipeline.native_submitted).store(false, Ordering::Release);
    PipelineStep::YieldIo
}

#[inline]
fn mandatory_order_size(pipeline: &ReadPipelineContext, order: &[usize], o: usize) -> usize {
    pipeline.mandatory_pages[order[o]].size as usize
}

/// AMPRPAK4 backing requests of the cold pages in `order` (sorted by pack and
/// offset): physically adjacent pages form spans, each span splits into
/// batches, and each batch becomes one coalesced request or one request per
/// page. Err(step) when the plan was abandoned.
unsafe fn append_mandatory_page_requests(
    pipeline: &mut ReadPipelineContext,
    order: &[usize],
    extend: bool,
    max_pages: usize,
    request_overflow: &mut bool,
    error_out: *mut c_int,
) -> Result<(), PipelineStep> {
    let load_count = order.len();
    let mut scratch_used = 0usize;
    let mut span_begin = 0;
    while span_begin < load_count {
        let span_end = mandatory_span_end(pipeline, order, span_begin);

        let mut batch_begin = span_begin;
        while batch_begin < span_end {
            let (batch_end, batch_bytes) =
                mandatory_batch_bounds(pipeline, order, batch_begin, span_end);

            // The batch's pages in request order; read extension (span's last
            // batch only) appends the following uncached pages of the volume.
            let mut seq = [0usize; PACK_MANDATORY_GROUP_MAX_PAGES];
            let batch_len = batch_end - batch_begin;
            seq[..batch_len].copy_from_slice(&order[batch_begin..batch_end]);
            let mut seq_len = batch_len;
            let mut extend_bytes = 0;
            if batch_end == span_end && extend {
                // Keep scratch for the later spans' own coalesced requests.
                let later: usize = (span_end..load_count)
                    .map(|o| mandatory_order_size(pipeline, order, o))
                    .sum();
                extend_bytes = mandatory_extend_batch(
                    pipeline,
                    &mut seq,
                    &mut seq_len,
                    batch_bytes,
                    scratch_used + later,
                    max_pages,
                );
            }
            let appended = mandatory_append_coalesced(
                pipeline,
                &seq,
                seq_len,
                batch_len,
                batch_bytes,
                extend_bytes,
                &mut scratch_used,
            );
            if !appended {
                mandatory_append_single_pages(
                    pipeline,
                    order,
                    batch_begin,
                    batch_end,
                    request_overflow,
                    error_out,
                )?;
            }
            batch_begin = batch_end;
        }
        span_begin = span_end;
    }
    Ok(())
}

/// End of the run of physically adjacent pages (same pack) from `span_begin`.
#[inline]
fn mandatory_span_end(pipeline: &ReadPipelineContext, order: &[usize], span_begin: usize) -> usize {
    let mut span_end = span_begin + 1;
    while span_end < order.len() {
        let previous = &pipeline.mandatory_pages[order[span_end - 1]];
        let next = &pipeline.mandatory_pages[order[span_end]];
        if previous.pack_id != next.pack_id
            || previous.offset.checked_add(previous.size as u64) != Some(next.offset)
        {
            break;
        }
        span_end += 1;
    }
    span_end
}

/// The batch from `batch_begin`: as many pages as fit
/// PACK_COALESCED_AIO_MAX_BYTES (at least one), then trailing pages moved to
/// the span's tail while that tail stays under PACK_COALESCED_AIO_MIN_BYTES.
/// Returns (batch_end, batch_bytes).
fn mandatory_batch_bounds(
    pipeline: &ReadPipelineContext,
    order: &[usize],
    batch_begin: usize,
    span_end: usize,
) -> (usize, usize) {
    let size_at = |o: usize| mandatory_order_size(pipeline, order, o);
    let mut batch_end = batch_begin;
    let mut batch_bytes = 0usize;
    while batch_end < span_end {
        let page_bytes = size_at(batch_end);
        if page_bytes > PACK_COALESCED_AIO_MAX_BYTES - batch_bytes {
            break;
        }
        batch_bytes += page_bytes;
        batch_end += 1;
    }
    if batch_end == batch_begin {
        batch_end = batch_begin + 1;
        batch_bytes = size_at(batch_begin);
    }

    let mut tail_bytes: usize = (batch_end..span_end).map(size_at).sum();
    while tail_bytes != 0
        && tail_bytes < PACK_COALESCED_AIO_MIN_BYTES
        && batch_end - batch_begin > 1
    {
        let moved_bytes = size_at(batch_end - 1);
        if batch_bytes - moved_bytes < PACK_COALESCED_AIO_MIN_BYTES {
            break;
        }
        batch_end -= 1;
        batch_bytes -= moved_bytes;
        tail_bytes += moved_bytes;
    }
    (batch_end, batch_bytes)
}

/// Appends `seq[..seq_len]` as one coalesced request: into the pages' cache
/// memory when it is contiguous, otherwise through the pipeline io scratch.
/// An extension that fits no single request is dropped and the bare batch
/// retried. Returns whether a request was appended.
unsafe fn mandatory_append_coalesced(
    pipeline: &mut ReadPipelineContext,
    seq: &[usize],
    mut seq_len: usize,
    batch_len: usize,
    batch_bytes: usize,
    mut extend_bytes: usize,
    scratch_used: &mut usize,
) -> bool {
    let mut appended;
    loop {
        let request_bytes = batch_bytes + extend_bytes;
        let seq = &seq[..seq_len];
        let can_coalesce = seq_len > 1
            && request_bytes >= PACK_COALESCED_AIO_MIN_BYTES
            && request_bytes <= PACK_COALESCED_AIO_MAX_BYTES;
        let mut cache_contiguous = can_coalesce;
        let mut o = 1;
        while cache_contiguous && o < seq_len {
            let previous = &pipeline.mandatory_pages[seq[o - 1]];
            let next = &pipeline.mandatory_pages[seq[o]];
            let previous_data = previous.acquired.lease.data as usize;
            cache_contiguous = previous_data.checked_add(previous.size as usize)
                == Some(next.acquired.lease.data as usize);
            o += 1;
        }

        appended = false;
        if can_coalesce && cache_contiguous {
            let buffer = pipeline.mandatory_pages[seq[0]].acquired.lease.data;
            appended = mandatory_append_request(
                pipeline,
                seq,
                0,
                seq_len,
                request_bytes,
                buffer,
                usize::MAX,
            );
        } else if can_coalesce
            && request_bytes <= PACK_PIPELINE_IO_BYTES
            && *scratch_used <= PACK_PIPELINE_IO_BYTES - request_bytes
            && ensure_pipeline_io_scratch(pipeline)
        {
            let buffer = pipeline.io_scratch.add(*scratch_used);
            appended = mandatory_append_request(
                pipeline,
                seq,
                0,
                seq_len,
                request_bytes,
                buffer,
                *scratch_used,
            );
            if appended {
                *scratch_used += request_bytes;
            }
        }
        if appended || extend_bytes == 0 {
            break;
        }
        // The extended batch fits no single request: drop the extension
        // rather than read it with extra requests.
        mandatory_drop_extension(pipeline, seq[batch_len], seq_len - batch_len);
        seq_len = batch_len;
        extend_bytes = 0;
    }
    if appended && extend_bytes != 0 {
        stats::add(stats::Stat::ReadExtendBytes, extend_bytes as u64);
    }
    appended
}

/// One request per page of `order[batch_begin..batch_end]`, the fallback for
/// a batch that could not be coalesced. Err(Ready) with `request_overflow`
/// set when the group runs out of requests.
unsafe fn mandatory_append_single_pages(
    pipeline: &mut ReadPipelineContext,
    order: &[usize],
    batch_begin: usize,
    batch_end: usize,
    request_overflow: &mut bool,
    error_out: *mut c_int,
) -> Result<(), PipelineStep> {
    for o in batch_begin..batch_end {
        if pipeline.mandatory_request_count >= PACK_MANDATORY_GROUP_MAX_REQUESTS {
            abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
            *request_overflow = true;
            return Err(PipelineStep::Ready);
        }
        let page = pipeline.mandatory_pages[order[o]];
        if !mandatory_append_request(
            pipeline,
            order,
            o,
            o + 1,
            page.size as usize,
            page.acquired.lease.data,
            usize::MAX,
        ) {
            return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
        }
    }
    Ok(())
}

/// True while fewer than AMPR_EMU_PACK_READ_EXTEND_MAX_DISK_INFLIGHT pack disk
/// reads are outstanding; otherwise the read sends only the pages it needs.
fn read_extend_allowed() -> bool {
    let quiet = PACK_DISK_INFLIGHT.load(Ordering::Acquire) < super::super::tune::ext_gate();
    if !quiet {
        stats::add(stats::Stat::ReadExtendGated, 1);
    }
    quiet
}

/// Read extension, reserved right after the demand acquire (before the fd and
/// payload checks) so a concurrent read of the following pages finds them
/// Loading and waits for this group's request instead of issuing its own. Takes
/// Load leases for the pages after each pack's highest cold page, at most
/// AMPR_EMU_PACK_READ_EXTEND_BYTES - one page; mandatory_extend_batch trims them.
unsafe fn mandatory_reserve_extension(
    pipeline: &mut ReadPipelineContext,
    page_count: usize,
    max_pages: usize,
) {
    let cap = max_pages.min(PACK_MANDATORY_GROUP_MAX_PAGES);
    for i in 0..page_count {
        let page = pipeline.mandatory_pages[i];
        let cold = |p: &PipelineMandatoryPage| {
            p.acquired.kind == PhysicalCacheAcquireKind::Load && p.pack_id == page.pack_id
        };
        if !cold(&page)
            || pipeline.mandatory_pages[..page_count]
                .iter()
                .any(|p| cold(p) && p.offset > page.offset)
        {
            continue;
        }
        let first = pipeline.mandatory_page_count;
        let pages = (super::super::tune::ext_bytes() / page.size as usize)
            .saturating_sub(1)
            .min(cap.saturating_sub(first));
        let Some(start) = page.offset.checked_add(page.size as u64) else {
            continue;
        };
        if pages != 0 {
            pipeline.mandatory_page_count += physical_cache_acquire_extension(
                page.pack_id,
                start,
                page.size,
                &mut pipeline.mandatory_pages[first..first + pages],
            );
        }
    }
}

/// Read extension of a batch ending at page `seq[seq_len - 1]`: Load leases for
/// the following uncached pages of the same volume (the reserved ones, else
/// newly acquired), as `extension` plan pages appended to `seq`, so the batch's
/// request also fills them. Bounded by AMPR_EMU_PACK_READ_EXTEND_BYTES total
/// request bytes, the 2 MiB request limit, the scratch left after
/// `scratch_reserved`, the plan's page capacity and the payload end; reserved
/// pages past the bound are dropped. Returns the extension bytes.
unsafe fn mandatory_extend_batch(
    pipeline: &mut ReadPipelineContext,
    seq: &mut [usize; PACK_MANDATORY_GROUP_MAX_PAGES],
    seq_len: &mut usize,
    batch_bytes: usize,
    scratch_reserved: usize,
    max_pages: usize,
) -> usize {
    let last = pipeline.mandatory_pages[seq[*seq_len - 1]];
    let Some(start) = last.offset.checked_add(last.size as u64) else {
        return 0;
    };
    let payload_end = {
        let state = pack_state();
        let _lock = PACK_M.lock();
        (*state).pack_handles[last.pack_id as usize].payload_end
    };
    let limit_bytes = super::super::tune::ext_bytes()
        .saturating_sub(batch_bytes)
        .min(PACK_COALESCED_AIO_MAX_BYTES.saturating_sub(batch_bytes))
        .min(PACK_PIPELINE_IO_BYTES.saturating_sub(batch_bytes + scratch_reserved));
    let limit = (limit_bytes / last.size as usize)
        .min((payload_end.saturating_sub(start) / last.size as u64) as usize);
    let total = pipeline.mandatory_page_count;
    let is_next = |p: &PipelineMandatoryPage, k: usize| {
        p.extension
            && p.acquired.kind == PhysicalCacheAcquireKind::Load
            && p.pack_id == last.pack_id
            && p.size == last.size
            && start.checked_add(k as u64 * last.size as u64) == Some(p.offset)
    };
    let (first, count) = if let Some(r) = pipeline.mandatory_pages[..total]
        .iter()
        .position(|p| is_next(p, 0))
    {
        let mut n = 1;
        while r + n < total && is_next(&pipeline.mandatory_pages[r + n], n) {
            n += 1;
        }
        let take = n.min(limit);
        if take < n {
            mandatory_drop_extension(pipeline, r + take, n - take);
        }
        (r, take)
    } else {
        let pages = limit.min(
            max_pages
                .min(PACK_MANDATORY_GROUP_MAX_PAGES)
                .saturating_sub(total),
        );
        if pages == 0 {
            return 0;
        }
        let count = physical_cache_acquire_extension(
            last.pack_id,
            start,
            last.size,
            &mut pipeline.mandatory_pages[total..total + pages],
        );
        pipeline.mandatory_page_count += count;
        (total, count)
    };
    for i in first..first + count {
        seq[*seq_len] = i;
        *seq_len += 1;
    }
    count * last.size as usize
}

/// Releases the extension Load leases of plan pages `first..first + count` as
/// transient failures, so no entry stays Loading and none is left Failed. The
/// pages become EMPTY in place; trailing EMPTY pages are cut from the plan.
unsafe fn mandatory_drop_extension(pipeline: &mut ReadPipelineContext, first: usize, count: usize) {
    let mut publications = [PhysicalCachePublication::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut leases = [null_mut::<PhysicalCacheLease>(); PACK_MANDATORY_GROUP_MAX_PAGES];
    for (i, page) in pipeline.mandatory_pages[first..first + count]
        .iter_mut()
        .enumerate()
    {
        publications[i] = PhysicalCachePublication {
            lease: &mut page.acquired.lease,
            error: SCE_KERNEL_ERROR_EAGAIN,
        };
        leases[i] = &mut page.acquired.lease;
    }
    physical_cache_publish_batch(publications.as_ptr(), count);
    physical_cache_release_batch(leases.as_ptr(), count);
    pipeline.mandatory_pages[first..first + count].fill(PipelineMandatoryPage::EMPTY);
    while pipeline.mandatory_page_count != 0
        && pipeline.mandatory_pages[pipeline.mandatory_page_count - 1].pack_id == u16::MAX
    {
        pipeline.mandatory_page_count -= 1;
    }
}

/// `findFd` lambda of prepare_mandatory_page_group.
fn mandatory_find_fd(pipeline: &ReadPipelineContext, pack_id: u16) -> c_int {
    (0..pipeline.mandatory_fd_count)
        .find(|&i| pipeline.mandatory_fd_pack_ids[i] == pack_id)
        .map_or(-1, |i| pipeline.mandatory_fds[i])
}

/// `appendRequest` lambda: one backing AIO over the contiguous pages
/// `load_order[first_order..end_order]`; `scratch_offset` == usize::MAX means
/// the read lands directly in the cache pages.
fn mandatory_append_request(
    pipeline: &mut ReadPipelineContext,
    load_order: &[usize],
    first_order: usize,
    end_order: usize,
    request_bytes: usize,
    request_buffer: *mut u8,
    scratch_offset: usize,
) -> bool {
    if first_order >= end_order
        || pipeline.mandatory_request_count >= PACK_MANDATORY_GROUP_MAX_REQUESTS
    {
        return false;
    }
    let first = pipeline.mandatory_pages[load_order[first_order]];
    let fd = mandatory_find_fd(pipeline, first.pack_id);
    if fd < 0 || request_buffer.is_null() {
        return false;
    }
    let mut verified_bytes = 0usize;
    let mut expected_offset = first.offset;
    for &i in &load_order[first_order..end_order] {
        let page = &pipeline.mandatory_pages[i];
        if page.pack_id != first.pack_id || page.offset != expected_offset {
            return false;
        }
        let (Some(next_offset), Some(bytes)) = (
            page.offset.checked_add(page.size as u64),
            verified_bytes.checked_add(page.size as usize),
        ) else {
            return false;
        };
        verified_bytes = bytes;
        expected_offset = next_offset;
    }
    if verified_bytes != request_bytes {
        return false;
    }
    let request_index = pipeline.mandatory_request_count;
    pipeline.mandatory_request_count += 1;
    pipeline.mandatory_results[request_index] = SceKernelAioResult::EMPTY;
    pipeline.mandatory_request_uses_scratch[request_index] = scratch_offset != usize::MAX;
    let result = &mut pipeline.mandatory_results[request_index] as *mut SceKernelAioResult;
    pipeline.mandatory_requests[request_index] = SceKernelAioRWRequest {
        offset: first.offset as off_t,
        nbyte: request_bytes,
        buf: request_buffer.cast(),
        result,
        fd,
    };
    let mut page_offset = 0usize;
    for &i in &load_order[first_order..end_order] {
        let page = &mut pipeline.mandatory_pages[i];
        page.request_index = request_index as u32;
        page.staging_offset = if scratch_offset == usize::MAX {
            INVALID_INDEX
        } else {
            (scratch_offset + page_offset) as u32
        };
        page_offset += page.size as usize;
    }
    page_offset == verified_bytes
}

// ---- zstd backing-read plan ---------------------------------------------------

/// zstd: the most cached (or unplanned) bytes between two cold pages that one
/// backing read reads through, instead of splitting into two requests. Console
/// storage: each request costs ~0.5 ms; 64 KiB more at ~300 MB/s ~0.2 ms.
pub(crate) const ZSTD_READ_GAP_MAX_BYTES: u64 = 64 * 1024;

/// zstd: one page for `zstd_plan_backing_reads`, in (pack, offset) order.
/// `data` is the address of its cache page (contiguity test only).
#[derive(Clone, Copy)]
pub(crate) struct ZstdColdPage {
    pub pack_id: u16,
    pub offset: u64,
    pub size: u32,
    pub data: usize,
    /// Read-extension page: joins a request only, never adds one.
    pub extension: bool,
}
impl ZstdColdPage {
    pub(crate) const EMPTY: Self = Self {
        pack_id: u16::MAX,
        offset: 0,
        size: 0,
        data: 0,
        extension: false,
    };
    fn end(&self) -> u64 {
        self.offset.saturating_add(self.size as u64)
    }
}

/// zstd: one planned backing read over pages `[first, end)`: `bytes` from
/// `offset`. `scratch_offset` == usize::MAX reads straight into the (gapless,
/// cache-contiguous) pages; otherwise into the pipeline scratch at that offset.
#[derive(Clone, Copy)]
pub(crate) struct ZstdReadRequest {
    pub first: usize,
    pub end: usize,
    pub offset: u64,
    pub bytes: usize,
    pub scratch_offset: usize,
}

pub(crate) struct ZstdReadPlan {
    pub requests: [ZstdReadRequest; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub count: usize,
    pub scratch_used: usize,
    /// Bytes read through gaps (discarded) and read-extension bytes kept.
    pub gap_bytes: usize,
    pub extension_bytes: usize,
}
impl ZstdReadPlan {
    pub(crate) const EMPTY: Self = Self {
        requests: [ZstdReadRequest {
            first: 0,
            end: 0,
            offset: 0,
            bytes: 0,
            scratch_offset: usize::MAX,
        }; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        count: 0,
        scratch_used: 0,
        gap_bytes: 0,
        extension_bytes: 0,
    };

    fn push(&mut self, pages: &[ZstdColdPage], first: usize, end: usize, scratch: bool) -> bool {
        if self.count >= PACK_MANDATORY_GROUP_MAX_REQUESTS {
            return false;
        }
        let offset = pages[first].offset;
        let bytes = (pages[end - 1].end() - offset) as usize;
        let page_bytes: usize = pages[first..end].iter().map(|p| p.size as usize).sum();
        let extension: usize = pages[first..end]
            .iter()
            .filter(|p| p.extension)
            .map(|p| p.size as usize)
            .sum();
        let scratch_offset = if scratch {
            let at = self.scratch_used;
            self.scratch_used += bytes;
            at
        } else {
            usize::MAX
        };
        self.requests[self.count] = ZstdReadRequest {
            first,
            end,
            offset,
            bytes,
            scratch_offset,
        };
        self.count += 1;
        self.gap_bytes += bytes - page_bytes;
        self.extension_bytes += extension;
        true
    }
}

/// True when pages `[first, end)` follow each other on disk with no gap.
fn zstd_pages_gapless(pages: &[ZstdColdPage], first: usize, end: usize) -> bool {
    pages[first..end]
        .windows(2)
        .all(|w| w[0].pack_id == w[1].pack_id && w[0].end() == w[1].offset)
}

/// True when the cache pages of `[first, end)` are adjacent in memory.
fn zstd_cache_contiguous(pages: &[ZstdColdPage], first: usize, end: usize) -> bool {
    pages[first].data != 0
        && pages[first..end]
            .windows(2)
            .all(|w| w[0].data.checked_add(w[0].size as usize) == Some(w[1].data))
}

/// zstd: plans the backing reads of a group's cold pages (`pages`, sorted by
/// pack and offset) in as few requests as possible. A run of cold pages of
/// one volume becomes one request while each gap between them is at most
/// ZSTD_READ_GAP_MAX_BYTES and the run spans at most
/// PACK_COALESCED_AIO_MAX_BYTES. A gapless run whose cache pages are adjacent
/// is read into them; any other run is read into the pipeline scratch (at
/// most `scratch_cap` bytes in all), its gaps discarded. A run that fits
/// neither first drops its read-extension pages, then splits at its gaps, and
/// only then reads page by page. Read-extension pages join only a request
/// whose span stays within `extension_limit`, with no gap, and never add a
/// request; `dropped` marks the ones left out. False when the group needs more
/// than PACK_MANDATORY_GROUP_MAX_REQUESTS requests.
pub(crate) fn zstd_plan_backing_reads(
    pages: &[ZstdColdPage],
    scratch_cap: usize,
    extension_limit: usize,
    dropped: &mut [bool],
    plan: &mut ZstdReadPlan,
) -> bool {
    *plan = ZstdReadPlan::EMPTY;
    dropped[..pages.len()].fill(false);
    let mut first = 0;
    while first < pages.len() {
        let head = pages[first];
        if head.extension {
            dropped[first] = true;
            first += 1;
            continue;
        }
        let mut run_end = head.end();
        let mut end = first + 1;
        while end < pages.len() {
            let next = &pages[end];
            if next.pack_id != head.pack_id || next.offset < run_end {
                break;
            }
            let (gap_max, span_max) = if next.extension {
                (0, extension_limit.min(PACK_COALESCED_AIO_MAX_BYTES) as u64)
            } else {
                (ZSTD_READ_GAP_MAX_BYTES, PACK_COALESCED_AIO_MAX_BYTES as u64)
            };
            if next.offset - run_end > gap_max || next.end() - head.offset > span_max {
                break;
            }
            run_end = next.end();
            end += 1;
        }
        if !zstd_plan_run(pages, first, end, scratch_cap, dropped, plan) {
            return false;
        }
        first = end;
    }
    true
}

/// One run of `zstd_plan_backing_reads`: `[first, end)` starts with a demand
/// page; its read-extension pages, if any, are its tail.
fn zstd_plan_run(
    pages: &[ZstdColdPage],
    first: usize,
    mut end: usize,
    scratch_cap: usize,
    dropped: &mut [bool],
    plan: &mut ZstdReadPlan,
) -> bool {
    let demand_end = (first..end)
        .rfind(|&k| !pages[k].extension)
        .map_or(first + 1, |k| k + 1);
    loop {
        let bytes = (pages[end - 1].end() - pages[first].offset) as usize;
        if zstd_pages_gapless(pages, first, end) && zstd_cache_contiguous(pages, first, end) {
            return plan.push(pages, first, end, false);
        }
        if bytes <= scratch_cap.saturating_sub(plan.scratch_used) {
            return plan.push(pages, first, end, true);
        }
        if end == demand_end {
            break;
        }
        dropped[demand_end..end].fill(true);
        end = demand_end;
    }
    // No single request fits: one per gapless piece, else one per page.
    let mut piece = first;
    while piece < end {
        let mut piece_end = piece + 1;
        while piece_end < end && zstd_pages_gapless(pages, piece_end - 1, piece_end + 1) {
            piece_end += 1;
        }
        let bytes = (pages[piece_end - 1].end() - pages[piece].offset) as usize;
        let pushed = if zstd_cache_contiguous(pages, piece, piece_end) {
            plan.push(pages, piece, piece_end, false)
        } else if piece_end - piece > 1 && bytes <= scratch_cap.saturating_sub(plan.scratch_used) {
            plan.push(pages, piece, piece_end, true)
        } else {
            (piece..piece_end).all(|k| plan.push(pages, k, k + 1, false))
        };
        if !pushed {
            return false;
        }
        piece = piece_end;
    }
    true
}

/// zstd: appends the backing requests of the group's cold pages (`demand`,
/// sorted plan indices) and of its reserved read-extension pages (plan
/// indices from `page_count` on) per `zstd_plan_backing_reads`. Too many
/// requests abandons the plan and sets `request_overflow` (Err(Ready)), as the
/// AMPRPAK4 loop does.
unsafe fn zstd_append_mandatory_requests(
    pipeline: &mut ReadPipelineContext,
    demand: &[usize],
    page_count: usize,
    extend: bool,
    request_overflow: &mut bool,
    error_out: *mut c_int,
) -> Result<(), PipelineStep> {
    let mut order = [0usize; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut count = demand.len();
    order[..count].copy_from_slice(demand);
    if extend {
        // Reserved extension pages read only inside their volume's payload.
        let state = pack_state();
        for i in page_count..pipeline.mandatory_page_count {
            let page = pipeline.mandatory_pages[i];
            if !page.extension || page.acquired.kind != PhysicalCacheAcquireKind::Load {
                continue;
            }
            let in_range = mandatory_find_fd(pipeline, page.pack_id) >= 0 && {
                let _lock = PACK_M.lock();
                (page.pack_id as u32) < pack_volume_count(state)
                    && page.end_within((*state).pack_handles[page.pack_id as usize].payload_end)
            };
            if in_range && count < order.len() {
                order[count] = i;
                count += 1;
            } else {
                mandatory_drop_extension(pipeline, i, 1);
            }
        }
        let pages = &pipeline.mandatory_pages;
        order[..count].sort_unstable_by_key(|&i| (pages[i].pack_id, pages[i].offset));
    }
    let order = &order[..count];
    let mut cold = [ZstdColdPage::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES];
    for (slot, &i) in cold.iter_mut().zip(order) {
        let page = &pipeline.mandatory_pages[i];
        *slot = ZstdColdPage {
            pack_id: page.pack_id,
            offset: page.offset,
            size: page.size,
            data: page.acquired.lease.data as usize,
            extension: page.extension,
        };
    }
    let cold = &cold[..count];
    let extension_limit = if extend {
        super::super::tune::ext_bytes()
    } else {
        0
    };
    let mut dropped = [false; PACK_MANDATORY_GROUP_MAX_PAGES];
    let mut plan = ZstdReadPlan::EMPTY;
    let mut fits = zstd_plan_backing_reads(
        cold,
        PACK_PIPELINE_IO_BYTES,
        extension_limit,
        &mut dropped,
        &mut plan,
    );
    if fits && plan.scratch_used != 0 && !ensure_pipeline_io_scratch(pipeline) {
        fits = zstd_plan_backing_reads(cold, 0, extension_limit, &mut dropped, &mut plan);
    }
    if !fits {
        abandon_mandatory_page_plan(pipeline, SCE_KERNEL_ERROR_EAGAIN);
        *request_overflow = true;
        return Err(PipelineStep::Ready);
    }
    for (k, &i) in order.iter().enumerate() {
        if dropped[k] {
            mandatory_drop_extension(pipeline, i, 1);
        }
    }
    for request in &plan.requests[..plan.count] {
        if !zstd_append_request(pipeline, order, request) {
            return Err(mandatory_fail(pipeline, SCE_KERNEL_ERROR_EIO, error_out));
        }
    }
    stats::add(stats::Stat::ReadExtendBytes, plan.extension_bytes as u64);
    stats::add(stats::Stat::ReadGapBytes, plan.gap_bytes as u64);
    Ok(())
}

/// zstd `appendRequest`: one backing AIO of `request` over the plan pages
/// `order[request.first..request.end]` of one volume, in offset order inside
/// `[request.offset, + request.bytes)`. A cache-direct request must be
/// gapless; a scratch one stages each page at its distance from the start.
unsafe fn zstd_append_request(
    pipeline: &mut ReadPipelineContext,
    order: &[usize],
    request: &ZstdReadRequest,
) -> bool {
    let direct = request.scratch_offset == usize::MAX;
    if request.first >= request.end
        || request.end > order.len()
        || pipeline.mandatory_request_count >= PACK_MANDATORY_GROUP_MAX_REQUESTS
        || (!direct
            && (pipeline.io_scratch.is_null()
                || request.bytes > pipeline.io_scratch_size
                || request.scratch_offset > pipeline.io_scratch_size - request.bytes))
    {
        return false;
    }
    let first = pipeline.mandatory_pages[order[request.first]];
    let fd = mandatory_find_fd(pipeline, first.pack_id);
    let Some(request_end) = request.offset.checked_add(request.bytes as u64) else {
        return false;
    };
    if fd < 0 || first.offset != request.offset {
        return false;
    }
    let mut expected = request.offset;
    for &i in &order[request.first..request.end] {
        let page = &pipeline.mandatory_pages[i];
        if page.pack_id != first.pack_id
            || page.offset < expected
            || (direct && page.offset != expected)
            || !page.end_within(request_end)
        {
            return false;
        }
        expected = page.offset + page.size as u64;
    }
    if expected != request_end {
        return false;
    }
    let buffer = if direct {
        first.acquired.lease.data
    } else {
        pipeline.io_scratch.add(request.scratch_offset)
    };
    if buffer.is_null() {
        return false;
    }
    let request_index = pipeline.mandatory_request_count;
    pipeline.mandatory_request_count += 1;
    pipeline.mandatory_results[request_index] = SceKernelAioResult::EMPTY;
    pipeline.mandatory_request_uses_scratch[request_index] = !direct;
    let result = &mut pipeline.mandatory_results[request_index] as *mut SceKernelAioResult;
    pipeline.mandatory_requests[request_index] = SceKernelAioRWRequest {
        offset: request.offset as off_t,
        nbyte: request.bytes,
        buf: buffer.cast(),
        result,
        fd,
    };
    for &i in &order[request.first..request.end] {
        let page = &mut pipeline.mandatory_pages[i];
        page.request_index = request_index as u32;
        page.staging_offset = if direct {
            INVALID_INDEX
        } else {
            (request.scratch_offset + (page.offset - request.offset) as usize) as u32
        };
    }
    true
}

impl PipelineMandatoryPage {
    /// True when the page ends at or before `limit` (no overflow).
    fn end_within(&self, limit: u64) -> bool {
        self.offset
            .checked_add(self.size as u64)
            .is_some_and(|end| end <= limit)
    }
}

#[cfg(test)]
mod zstd_plan_tests {
    use super::*;

    const PAGE: u64 = PACK_CACHE_PAGE_BYTES as u64;
    const BASE: usize = 0x1000_0000;

    /// Cold page `index` of volume `pack`, in cache slot `slot`.
    fn page(pack: u16, index: u64, slot: usize, extension: bool) -> ZstdColdPage {
        ZstdColdPage {
            pack_id: pack,
            offset: index * PAGE,
            size: PAGE as u32,
            data: BASE + slot * PAGE as usize,
            extension,
        }
    }

    /// Pages `indices` of volume 0 in cache slots 0, 1, 2... (adjacent).
    fn run(indices: &[u64]) -> Vec<ZstdColdPage> {
        indices
            .iter()
            .enumerate()
            .map(|(slot, &i)| page(0, i, slot, false))
            .collect()
    }

    fn plan(pages: &[ZstdColdPage], scratch: usize, ext: usize) -> (bool, ZstdReadPlan, Vec<bool>) {
        let mut dropped = vec![false; pages.len()];
        let mut plan = ZstdReadPlan::EMPTY;
        let fits = zstd_plan_backing_reads(pages, scratch, ext, &mut dropped, &mut plan);
        (fits, plan, dropped)
    }

    fn spans(plan: &ZstdReadPlan) -> Vec<(u64, usize, bool)> {
        plan.requests[..plan.count]
            .iter()
            .map(|r| {
                (
                    r.offset / PAGE,
                    r.bytes / PAGE as usize,
                    r.scratch_offset != usize::MAX,
                )
            })
            .collect()
    }

    #[test]
    fn small_contiguous_chunk_is_one_direct_read() {
        // 7 pages = 112 KiB: below the AMPRPAK4 128 KiB coalescing minimum,
        // which read it as 7 separate 16 KiB requests.
        let (fits, plan, _) = plan(&run(&[3, 4, 5, 6, 7, 8, 9]), PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(3, 7, false)]);
        assert_eq!((plan.scratch_used, plan.gap_bytes), (0, 0));
    }

    #[test]
    fn single_page_is_one_direct_read() {
        let (fits, plan, _) = plan(&run(&[42]), 0, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(42, 1, false)]);
    }

    #[test]
    fn scattered_cache_slots_use_one_scratch_read() {
        let pages = [
            page(0, 10, 5, false),
            page(0, 11, 0, false),
            page(0, 12, 9, false),
        ];
        let (fits, plan, _) = plan(&pages, PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 3, true)]);
        assert_eq!(plan.scratch_used, 3 * PAGE as usize);
    }

    #[test]
    fn small_cached_gap_is_read_through() {
        // Pages 12-15 are cached (64 KiB): one read, the gap discarded.
        let (fits, plan, _) = plan(&run(&[10, 11, 16, 17]), PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 8, true)]);
        assert_eq!(plan.gap_bytes, 4 * PAGE as usize);
        assert_eq!(plan.requests[0].scratch_offset, 0);
    }

    #[test]
    fn large_cached_gap_splits() {
        // 80 KiB gap: two reads, each straight into its cache pages.
        let (fits, plan, _) = plan(&run(&[10, 11, 17, 18]), PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 2, false), (17, 2, false)]);
        assert_eq!(plan.gap_bytes, 0);
    }

    #[test]
    fn volumes_never_share_a_read() {
        let pages = [page(0, 10, 0, false), page(1, 11, 1, false)];
        let (fits, plan, _) = plan(&pages, PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(plan.count, 2);
    }

    #[test]
    fn run_stops_at_the_io_window() {
        // 129 contiguous pages (> 2 MiB) need two reads.
        let indices: Vec<u64> = (0..129).collect();
        let (fits, plan, _) = plan(&run(&indices), PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(spans(&plan), [(0, 128, false), (128, 1, false)]);
    }

    #[test]
    fn scratch_is_bounded_by_the_window() {
        // Two bridged runs of 71 pages (~1.1 MiB) each: the second no longer
        // fits the 2 MiB scratch and falls back to one read per gapless piece.
        let mut pages = Vec::new();
        for (base, slot) in [(0u64, 0usize), (1000, 200)] {
            for k in 0..48 {
                // 48 pages with a one-page gap after every second page.
                let index = base + k + k / 2;
                pages.push(page(0, index, slot + k as usize, false));
            }
        }
        let (fits, plan, _) = plan(&pages, PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert!(plan.scratch_used <= PACK_PIPELINE_IO_BYTES);
        assert_eq!(plan.requests[0].scratch_offset, 0);
        assert_eq!(plan.requests[0].end, 48);
        assert_eq!(plan.count, 1 + 24);
        assert!(plan.requests[1..plan.count]
            .iter()
            .all(|r| r.scratch_offset == usize::MAX));
    }

    #[test]
    fn no_scratch_falls_back_to_gapless_pieces() {
        let pages = [
            page(0, 10, 0, false),
            page(0, 11, 1, false),
            page(0, 13, 7, false),
            page(0, 14, 3, false),
        ];
        let (fits, plan, _) = plan(&pages, 0, 0);
        assert!(fits);
        // 10-11 direct; 13-14 not cache-adjacent: one read per page.
        assert_eq!(
            spans(&plan),
            [(10, 2, false), (13, 1, false), (14, 1, false)]
        );
    }

    #[test]
    fn extension_joins_without_adding_reads() {
        let pages = [
            page(0, 10, 0, false),
            page(0, 11, 1, false),
            page(0, 12, 2, true),
            page(0, 13, 3, true),
            page(0, 14, 4, true),
        ];
        // Request bytes capped at 4 pages: the last extension page is dropped.
        let (fits, plan, dropped) = plan(&pages, PACK_PIPELINE_IO_BYTES, 4 * PAGE as usize);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 4, false)]);
        assert_eq!(dropped, [false, false, false, false, true]);
        assert_eq!(plan.extension_bytes, 2 * PAGE as usize);
    }

    #[test]
    fn extension_is_dropped_before_splitting_demand() {
        // Demand is cache-adjacent, the extension page is not, and there is
        // no scratch: drop the extension, read the demand directly.
        let pages = [
            page(0, 10, 0, false),
            page(0, 11, 1, false),
            page(0, 12, 9, true),
        ];
        let (fits, plan, dropped) = plan(&pages, 0, PACK_PIPELINE_IO_BYTES);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 2, false)]);
        assert_eq!(dropped, [false, false, true]);
        assert_eq!(plan.extension_bytes, 0);
    }

    #[test]
    fn extension_never_bridges_a_gap() {
        let pages = [page(0, 10, 0, false), page(0, 12, 1, true)];
        let (fits, plan, dropped) = plan(&pages, PACK_PIPELINE_IO_BYTES, PACK_PIPELINE_IO_BYTES);
        assert!(fits);
        assert_eq!(spans(&plan), [(10, 1, false)]);
        assert_eq!(dropped, [false, true]);
    }

    #[test]
    fn too_many_requests_overflow() {
        // 33 pages, each 80 KiB from the next: 33 requests > 32.
        let indices: Vec<u64> = (0..33).map(|k| k * 6).collect();
        let (fits, _, _) = plan(&run(&indices), PACK_PIPELINE_IO_BYTES, 0);
        assert!(!fits);
        let (fits, plan, _) = plan(&run(&indices[..32]), PACK_PIPELINE_IO_BYTES, 0);
        assert!(fits);
        assert_eq!(plan.count, 32);
    }
}
