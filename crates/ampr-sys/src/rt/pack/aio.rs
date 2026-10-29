//! Close/fstat/getdents/lseek interposers and AIO submit, poll and cancel.

use super::*;
use core::sync::atomic::AtomicI64;

// ampr_pack_runtime_stats: telemetry, not implemented (see mod.rs).

pub unsafe fn sceKernelClose(fd: c_int) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_close_fd(fd, &mut handled) };
    if handled {
        return rc;
    }
    match unsafe { real_sce_close() } {
        Some(f) => unsafe { f(fd) },
        None => SCE_KERNEL_ERROR_EIO,
    }
}

pub unsafe extern "C" fn sceKernelClose_emul(fd: c_int) -> c_int {
    unsafe { sceKernelClose(fd) }
}

/// A real POSIX fallback can already have produced -1 with the precise errno;
/// synthetic virtual-fd failures use SCE error values instead.
pub(crate) fn posix_result_from_pack<R: Copy + Into<i64> + From<i32>>(rc: R) -> R {
    let v: i64 = rc.into();
    if v >= 0 {
        return rc;
    }
    if v != -1 {
        set_errno(posix_errno_from_sce(v as c_int));
    }
    R::from(-1)
}

pub(crate) fn posix_missing_original<R: From<i32>>() -> R {
    set_errno(EIO);
    R::from(-1)
}

pub unsafe extern "C" fn posix_close_emul(fd: c_int) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_close_fd(fd, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    match unsafe { real_close() } {
        Some(f) => unsafe { f(fd) },
        None => posix_missing_original(),
    }
}

pub unsafe extern "C" fn posix_fstat_emul(fd: c_int, stat: *mut SceKernelStat) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_fstat_fd(fd, stat, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    match unsafe { real_fstat() } {
        Some(f) => unsafe { f(fd, stat) },
        None => posix_missing_original(),
    }
}

pub unsafe extern "C" fn sceKernelFstat_emul(fd: c_int, stat: *mut SceKernelStat) -> c_int {
    sce_result(unsafe { posix_fstat_emul(fd, stat) })
}

pub unsafe extern "C" fn sceKernelLseek_emul(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    sce_result(unsafe { posix_lseek_emul(fd, offset, whence) })
}

pub unsafe extern "C" fn sceKernelGetdents_emul(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
) -> c_int {
    sce_result(unsafe { posix_getdents_emul(fd, buffer, size) })
}

pub unsafe extern "C" fn sceKernelGetdirentries_emul(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
) -> c_int {
    sce_result(unsafe { posix_getdirentries_emul(fd, buffer, size, basep) })
}

pub unsafe extern "C" fn posix_getdents_emul(fd: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_getdents_fd(fd, buffer, size, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    match unsafe { real_getdents() } {
        Some(f) => unsafe { f(fd, buffer, size) },
        None => posix_missing_original(),
    }
}

pub unsafe extern "C" fn posix_getdirentries_emul(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_getdirentries_fd(fd, buffer, size, basep, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    match unsafe { real_getdirentries() } {
        Some(f) => unsafe { f(fd, buffer, size, basep) },
        None => posix_missing_original(),
    }
}

pub unsafe extern "C" fn posix_lseek_emul(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_lseek_fd(fd, offset, whence, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    match unsafe { real_lseek() } {
        Some(f) => unsafe { f(fd, offset, whence) },
        None => posix_missing_original(),
    }
}

unsafe fn has_virtual_fd(requests: *const SceKernelAioRWRequest, count: c_int) -> bool {
    (0..count as usize)
        .any(|i| unsafe { decode_virtual_fd((*requests.add(i)).fd, null_mut(), null_mut()) })
}

#[allow(dead_code)]
pub unsafe fn sceKernelAioSubmitReadCommands(
    requests: *mut SceKernelAioRWRequest,
    count: c_int,
    priority: c_int,
    id: *mut SceKernelAioSubmitId,
) -> c_int {
    if requests.is_null()
        || id.is_null()
        || count <= 0
        || count as usize > SCE_KERNEL_AIO_REQUEST_NUM_MAX
    {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    unsafe {
        if !has_virtual_fd(requests, count) {
            return match real_aio_submit_single() {
                Some(f) => f(requests, count, priority, id),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }

        let state = pack_state();
        let submission = PackSubmission::new(state);
        if !submission.admitted() {
            return SCE_KERNEL_ERROR_EBUSY;
        }
        let group_index;
        let group_generation;
        {
            let _lock = PACK_M.lock();
            group_index = allocate_virtual_aio_group_locked(state);
            if group_index == INVALID_INDEX {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            group_generation = (*state).virtual_aio_groups[group_index as usize].generation;
        }

        let mut child_ids = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let submit_rc = sceKernelAioSubmitReadCommandsMultiple(
            requests,
            count,
            priority,
            child_ids.as_mut_ptr(),
        );
        if submit_rc != 0 {
            let _lock = PACK_M.lock();
            let group = &(*state).virtual_aio_groups[group_index as usize];
            if group.active && group.generation == group_generation {
                free_virtual_aio_group_locked(state, group_index);
            }
            return submit_rc;
        }

        let mut group_published = false;
        {
            let _lock = PACK_M.lock();
            let group = &mut (*state).virtual_aio_groups[group_index as usize];
            if group.active && group.generation == group_generation {
                let n = count as usize;
                group.children[..n].copy_from_slice(&child_ids[..n]);
                group.child_count = count as u16;
                for &child in &child_ids[..n] {
                    // A zstd split read's id is a virtual group, not native.
                    group.has_native_children = group.has_native_children
                        || (!decode_virtual_aio(child, null_mut(), null_mut())
                            && !decode_virtual_aio_group(child, null_mut(), null_mut()));
                }
                *id = encode_virtual_aio_group(group_index, group_generation);
                group_published = true;
            }
        }
        if !group_published {
            let mut child_results = [0 as c_int; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
            let _ = sceKernelAioDeleteRequests(
                child_ids.as_mut_ptr(),
                count,
                child_results.as_mut_ptr(),
            );
            return SCE_KERNEL_ERROR_EIO;
        }
        0
    }
}

pub unsafe fn sceKernelAioSubmitReadCommandsMultiple(
    requests: *mut SceKernelAioRWRequest,
    count: c_int,
    priority: c_int,
    ids: *mut SceKernelAioSubmitId,
) -> c_int {
    if requests.is_null()
        || ids.is_null()
        || count <= 0
        || count as usize > SCE_KERNEL_AIO_REQUEST_NUM_MAX
    {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    unsafe {
        if !has_virtual_fd(requests, count) {
            return match real_aio_submit() {
                Some(f) => f(requests, count, priority, ids),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        const N: usize = SCE_KERNEL_AIO_REQUEST_NUM_MAX;
        let state = pack_state();
        let mut real_requests = [SceKernelAioRWRequest::EMPTY; N];
        let submission = PackSubmission::new(state);
        if !submission.admitted() {
            return SCE_KERNEL_ERROR_EBUSY;
        }
        let mut real_positions = [0usize; N];
        // Virtual jobs of this call: a zstd split read takes one per child,
        // and there are never more jobs than virtual AIO slots.
        const J: usize = AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
        let mut virtual_indexes = [0u32; J];
        let mut virtual_positions = [0usize; J];
        // zstd: split group of each request position, or INVALID_INDEX.
        let mut split_groups = [INVALID_INDEX; N];
        // Per virtual request: (fd index, file_id, last local chunk read or u32::MAX);
        // then per file: (file_id, first local chunk, end local chunk) to read ahead.
        const RA: usize = if AMPR_EMU_PACK_READAHEAD_CHUNKS == 0 && !super::super::tune::ON {
            0
        } else {
            N
        };
        let mut readahead_reads = [(0u32, 0u32, u32::MAX); RA];
        let mut readahead = [(0u32, 0u32, 0u32); RA];
        let readahead_count;
        let mut real_count = 0usize;
        let mut virtual_count = 0usize;
        // Virtual requests (split or not); equals virtual_count without splits.
        let mut virtual_requests = 0usize;
        let mut prepare_rc = 0;

        {
            let _lock = PACK_M.lock();
            for i in 0..count as usize {
                let req = *requests.add(i);
                let (mut fd_index, mut fd_generation) = (0u32, 0u16);
                if !decode_virtual_fd(req.fd, &mut fd_index, &mut fd_generation) {
                    real_positions[real_count] = i;
                    real_requests[real_count] = req;
                    real_count += 1;
                    continue;
                }
                let fd_slot = (*state).virtual_fds[fd_index as usize];
                if !fd_slot.active || fd_slot.generation != fd_generation {
                    prepare_rc = SCE_KERNEL_ERROR_EBADF;
                    break;
                }
                let aio_index = allocate_virtual_aio_locked(state);
                if aio_index == INVALID_INDEX {
                    prepare_rc = SCE_KERNEL_ERROR_EAGAIN;
                    break;
                }
                let Some((_file_ptr, _file_size, file_flags)) =
                    packed_read_file(state, fd_slot.file_id)
                else {
                    free_virtual_aio_locked(state, aio_index);
                    prepare_rc = SCE_KERNEL_ERROR_EIO;
                    break;
                };
                let aio = &mut (*state).virtual_aio[aio_index as usize];
                aio.request = req;
                aio.file_id = fd_slot.file_id;
                aio.priority = queue_priority(priority);
                aio.work_class = classify_work(file_flags, &aio.request);
                aio.cancel_requested.store(false, Ordering::Relaxed);
                let result = aio.request.result;
                if !result.is_null() {
                    AtomicI64::from_ptr(&raw mut (*result).return_value)
                        .store(0, Ordering::Relaxed);
                    AtomicU32::from_ptr(&raw mut (*result).state).store(0, Ordering::Release);
                }
                if RA != 0 {
                    let last =
                        readahead_last_chunk(state, fd_slot.file_id, &req).unwrap_or(u32::MAX);
                    readahead_reads[virtual_requests] = (fd_index, fd_slot.file_id, last);
                }
                virtual_indexes[virtual_count] = aio_index;
                virtual_positions[virtual_count] = i;
                virtual_count += 1;
                virtual_requests += 1;
                // zstd: a read over >= 2 chunks becomes parallel child jobs,
                // while the rest of the batch and SPLIT_MIN_FREE_SLOTS keep
                // free slots (else it stays one job).
                if zstd_mode() {
                    let mut children = [0u32; SPLIT_MAX_CHILDREN];
                    let rest = count as usize - i - 1;
                    if let Some((group_index, n)) = split_virtual_read_locked(
                        state,
                        aio_index,
                        _file_ptr,
                        _file_size,
                        rest + SPLIT_MIN_FREE_SLOTS,
                        &mut children,
                    ) {
                        if virtual_count + (n - 1) + rest > J {
                            abort();
                        }
                        for &child in &children[1..n] {
                            virtual_indexes[virtual_count] = child;
                            virtual_positions[virtual_count] = i;
                            virtual_count += 1;
                        }
                        split_groups[i] = group_index;
                    }
                }
            }
            if prepare_rc == 0 && virtual_count != 0 && !ensure_workers_locked(state) {
                prepare_rc = SCE_KERNEL_ERROR_ENOMEM;
            }
            if prepare_rc != 0 {
                for &index in &virtual_indexes[..virtual_count] {
                    free_virtual_aio_locked(state, index);
                }
                free_split_groups_locked(state, &split_groups[..count as usize]);
            }
            let reads = &readahead_reads[..if prepare_rc == 0 {
                virtual_requests.min(RA)
            } else {
                0
            }];
            readahead_count = plan_batch_readahead_locked(state, reads, &mut readahead);
        }
        if prepare_rc != 0 {
            return prepare_rc;
        }

        if real_count != 0 {
            let rc = submit_real_requests(
                state,
                &mut real_requests[..real_count],
                &real_positions[..real_count],
                priority,
                ids,
                &virtual_indexes[..virtual_count],
                &split_groups[..count as usize],
            );
            if rc != 0 {
                return rc;
            }
        }

        if virtual_count != 0 {
            publish_virtual_jobs(
                state,
                ids,
                &virtual_indexes[..virtual_count],
                &virtual_positions[..virtual_count],
                &split_groups,
                &readahead[..readahead_count],
            );
        }
        0
    }
}

/// One read-ahead window per file, past the highest chunk the whole batch
/// reads in it, so read-ahead never covers chunks this batch reads itself.
/// `reads` holds (fd index, file_id, last chunk read or u32::MAX) per
/// virtual request; returns the windows written to `readahead`.
#[inline]
unsafe fn plan_batch_readahead_locked(
    state: *mut PackState,
    reads: &[(u32, u32, u32)],
    readahead: &mut [(u32, u32, u32)],
) -> usize {
    let mut readahead_count = 0usize;
    for (i, &(_, file_id, last)) in reads.iter().enumerate() {
        if last == u32::MAX || reads[..i].iter().any(|r| r.1 == file_id && r.2 != u32::MAX) {
            continue;
        }
        let mut best = i;
        for (j, r) in reads.iter().enumerate().skip(i + 1) {
            if r.1 == file_id && r.2 != u32::MAX && r.2 >= reads[best].2 {
                best = j;
            }
        }
        let (start, end) = unsafe { readahead_window_locked(state, reads[best].0, reads[best].2) };
        if start < end {
            readahead[readahead_count] = (file_id, start, end);
            readahead_count += 1;
        }
    }
    readahead_count
}

/// Submits the batch's real-fd requests to the kernel and stores their ids
/// at their positions. On failure frees the batch's virtual jobs and split
/// groups and returns the kernel rc.
unsafe fn submit_real_requests(
    state: *mut PackState,
    real_requests: &mut [SceKernelAioRWRequest],
    real_positions: &[usize],
    priority: c_int,
    ids: *mut SceKernelAioSubmitId,
    virtual_indexes: &[u32],
    split_groups: &[u32],
) -> c_int {
    unsafe {
        let mut real_ids = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let real_count = real_requests.len();
        let rc = match real_aio_submit() {
            Some(f) => f(
                real_requests.as_mut_ptr(),
                real_count as c_int,
                priority,
                real_ids.as_mut_ptr(),
            ),
            None => SCE_KERNEL_ERROR_EIO,
        };
        if rc != 0 {
            let _lock = PACK_M.lock();
            for &index in virtual_indexes {
                free_virtual_aio_locked(state, index);
            }
            free_split_groups_locked(state, split_groups);
            return rc;
        }
        for i in 0..real_count {
            *ids.add(real_positions[i]) = real_ids[i];
        }
        0
    }
}

/// Completes the virtual jobs served from the decoded cache inline, queues
/// the rest for the pack workers, stores every caller id and queues the
/// batch's read-ahead windows.
unsafe fn publish_virtual_jobs(
    state: *mut PackState,
    ids: *mut SceKernelAioSubmitId,
    virtual_indexes: &[u32],
    virtual_positions: &[usize],
    split_groups: &[u32],
    readahead: &[(u32, u32, u32)],
) {
    unsafe {
        const J: usize = AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
        let virtual_count = virtual_indexes.len();
        let mut inline_completed = [false; J];
        let mut inline_bytes = [0u64; J];
        for i in 0..virtual_count {
            inline_completed[i] = try_process_virtual_read_cache_only(
                &mut (*state).virtual_aio[virtual_indexes[i] as usize],
                &mut inline_bytes[i],
            );
        }
        let queued_at_usec = pack_telemetry_usecs();
        let mut queued = 0usize;
        let notify_one;
        {
            let _lock = PACK_M.lock();
            for i in 0..virtual_count {
                let index = virtual_indexes[i];
                let id = encode_virtual_aio(index, (*state).virtual_aio[index as usize].generation);
                let id = split_caller_id(state, split_groups[virtual_positions[i]], id);
                *ids.add(virtual_positions[i]) = id;
                if inline_completed[i] {
                    complete_virtual_job(
                        state,
                        index,
                        inline_bytes[i] as i64,
                        SCE_KERNEL_AIO_STATE_COMPLETED,
                    );
                } else {
                    queue_push_locked(state, index, queued_at_usec);
                    queued += 1;
                }
            }
            notify_one = queued == 1 && effective_latency_reserve_locked(state) == 0;
        }
        if queued != 0 {
            if notify_one {
                QUEUE_CV.notify_one();
            } else {
                QUEUE_CV.notify_all();
            }
        }
        let mut prefetch_queued = false;
        for &(file_id, start, end) in readahead {
            prefetch_queued |= queue_readahead(file_id, start, end);
        }
        if prefetch_queued {
            QUEUE_CV.notify_all();
        }
    }
}

/// zstd: runs `single` on each group id of `ids` and `batch` once on all the
/// others, so a split read's group id mixed into a reactor batch does not
/// turn every native id into its own kernel call. First nonzero rc wins.
pub(crate) unsafe fn groups_single_rest_batched(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    out: *mut c_int,
    single: unsafe fn(SceKernelAioSubmitId, *mut c_int) -> c_int,
    batch: unsafe fn(*mut SceKernelAioSubmitId, c_int, *mut c_int) -> c_int,
) -> c_int {
    const M: usize = SCE_KERNEL_AIO_ID_NUM_MAX;
    let mut rest_ids = [0 as SceKernelAioSubmitId; M];
    let mut rest_out = [0 as c_int; M];
    let mut rest_positions = [0usize; M];
    let mut rest_count = 0usize;
    unsafe {
        for i in 0..count as usize {
            let id = *ids.add(i);
            if decode_virtual_aio_group(id, null_mut(), null_mut()) {
                let rc = single(id, out.add(i));
                if rc != 0 {
                    return rc;
                }
            } else {
                rest_ids[rest_count] = id;
                rest_positions[rest_count] = i;
                rest_count += 1;
            }
        }
        if rest_count != 0 {
            let rc = batch(
                rest_ids.as_mut_ptr(),
                rest_count as c_int,
                rest_out.as_mut_ptr(),
            );
            if rc != 0 {
                return rc;
            }
            for k in 0..rest_count {
                *out.add(rest_positions[k]) = rest_out[k];
            }
        }
    }
    0
}

pub unsafe fn sceKernelAioPollRequests(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    states: *mut c_int,
) -> c_int {
    if ids.is_null() || states.is_null() || count <= 0 || count as usize > SCE_KERNEL_AIO_ID_NUM_MAX
    {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    unsafe {
        let n = count as usize;
        let mut has_group = false;
        let mut has_virtual = false;
        for i in 0..n {
            if decode_virtual_aio_group(*ids.add(i), null_mut(), null_mut()) {
                has_group = true;
                break;
            }
            has_virtual = has_virtual || decode_virtual_aio(*ids.add(i), null_mut(), null_mut());
        }
        if !has_group && !has_virtual {
            return match real_aio_poll() {
                Some(f) => f(ids, count, states),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        if zstd_mode() && has_group {
            return groups_single_rest_batched(
                ids,
                count,
                states,
                sceKernelAioPollRequest,
                sceKernelAioPollRequests,
            );
        }
        if has_group {
            for i in 0..n {
                let rc = sceKernelAioPollRequest(*ids.add(i), states.add(i));
                if rc != 0 {
                    return rc;
                }
            }
            return 0;
        }
        const M: usize = SCE_KERNEL_AIO_ID_NUM_MAX;
        let mut real_ids = [0 as SceKernelAioSubmitId; M];
        let mut real_states = [0 as c_int; M];
        let mut real_positions = [0usize; M];
        let mut real_count = 0usize;
        let state = pack_state();
        {
            let _lock = PACK_M.lock();
            for i in 0..n {
                let id = *ids.add(i);
                if !has_virtual_aio_tag(id) {
                    real_positions[real_count] = i;
                    real_ids[real_count] = id;
                    real_count += 1;
                    continue;
                }
                let aio = lookup_virtual_aio_locked(state, id, null_mut());
                *states.add(i) = if aio.is_null() {
                    SCE_KERNEL_ERROR_ESRCH
                } else {
                    match (*aio).phase {
                        VirtualAioPhase::Reserved
                        | VirtualAioPhase::Queued
                        | VirtualAioPhase::WaitingCache
                        | VirtualAioPhase::WaitingFd => SCE_KERNEL_AIO_STATE_SUBMITTED,
                        VirtualAioPhase::IoQueued => {
                            let p = (*aio).pipeline_index;
                            if p < (*state).pipeline_capacity
                                && AtomicBool::from_ptr(
                                    &raw mut (*state).pipelines[p as usize].native_submitted,
                                )
                                .load(Ordering::Acquire)
                            {
                                SCE_KERNEL_AIO_STATE_PROCESSING
                            } else {
                                SCE_KERNEL_AIO_STATE_SUBMITTED
                            }
                        }
                        VirtualAioPhase::Running => SCE_KERNEL_AIO_STATE_PROCESSING,
                        VirtualAioPhase::Done => (*aio).completion_state,
                        _ => SCE_KERNEL_ERROR_ESRCH,
                    }
                };
            }
        }
        if real_count != 0 {
            let Some(f) = real_aio_poll() else {
                return SCE_KERNEL_ERROR_EIO;
            };
            let rc = f(
                real_ids.as_mut_ptr(),
                real_count as c_int,
                real_states.as_mut_ptr(),
            );
            if rc != 0 {
                return rc;
            }
            for i in 0..real_count {
                *states.add(real_positions[i]) = real_states[i];
            }
        }
        0
    }
}

#[allow(dead_code)]
pub unsafe fn sceKernelAioCancelRequests(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    states: *mut c_int,
) -> c_int {
    if ids.is_null() || states.is_null() || count <= 0 || count as usize > SCE_KERNEL_AIO_ID_NUM_MAX
    {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    unsafe {
        let n = count as usize;
        let mut has_virtual = false;
        for i in 0..n {
            has_virtual = has_virtual || decode_virtual_aio(*ids.add(i), null_mut(), null_mut());
            if decode_virtual_aio_group(*ids.add(i), null_mut(), null_mut()) {
                for k in 0..n {
                    let rc = sceKernelAioCancelRequest(*ids.add(k), states.add(k));
                    if rc != 0 {
                        return rc;
                    }
                }
                return 0;
            }
        }
        if !has_virtual {
            return match real_aio_cancel() {
                Some(f) => f(ids, count, states),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        const M: usize = SCE_KERNEL_AIO_ID_NUM_MAX;
        let mut real_ids = [0 as SceKernelAioSubmitId; M];
        let mut real_states = [0 as c_int; M];
        let mut real_positions = [0usize; M];
        let mut real_count = 0usize;
        let mut completed_queued_job = false;
        let state = pack_state();
        {
            let _lock = PACK_M.lock();
            for i in 0..n {
                let id = *ids.add(i);
                if !decode_virtual_aio(id, null_mut(), null_mut()) {
                    real_positions[real_count] = i;
                    real_ids[real_count] = id;
                    real_count += 1;
                    continue;
                }
                let mut index = 0u32;
                let aio = lookup_virtual_aio_locked(state, id, &mut index);
                if aio.is_null() {
                    *states.add(i) = SCE_KERNEL_ERROR_ESRCH;
                    continue;
                }
                let out = &mut *states.add(i);
                match (*aio).phase {
                    VirtualAioPhase::Reserved => {
                        (*aio).cancel_requested.store(true, Ordering::Release);
                        complete_virtual_job(
                            state,
                            index,
                            SCE_KERNEL_ERROR_ECANCELED as i64,
                            SCE_KERNEL_AIO_STATE_ABORTED,
                        );
                        *out = SCE_KERNEL_AIO_STATE_ABORTED;
                        completed_queued_job = true;
                    }
                    VirtualAioPhase::Queued => {
                        (*aio).cancel_requested.store(true, Ordering::Release);
                        if (*aio).pipeline_index != INVALID_INDEX
                            || !queue_remove_locked(state, index)
                        {
                            *out = SCE_KERNEL_AIO_STATE_PROCESSING;
                        } else {
                            complete_virtual_job(
                                state,
                                index,
                                SCE_KERNEL_ERROR_ECANCELED as i64,
                                SCE_KERNEL_AIO_STATE_ABORTED,
                            );
                            *out = SCE_KERNEL_AIO_STATE_ABORTED;
                            completed_queued_job = true;
                        }
                    }
                    VirtualAioPhase::WaitingCache => {
                        (*aio).cancel_requested.store(true, Ordering::Release);
                        queue_cache_waiter_locked(state, index, pack_telemetry_usecs());
                        *out = SCE_KERNEL_AIO_STATE_PROCESSING;
                        completed_queued_job = true;
                    }
                    VirtualAioPhase::WaitingFd => {
                        (*aio).cancel_requested.store(true, Ordering::Release);
                        queue_fd_waiter_locked(state, index, pack_telemetry_usecs());
                        *out = SCE_KERNEL_AIO_STATE_PROCESSING;
                        completed_queued_job = true;
                    }
                    VirtualAioPhase::Running | VirtualAioPhase::IoQueued => {
                        (*aio).cancel_requested.store(true, Ordering::Release);
                        *out = SCE_KERNEL_AIO_STATE_PROCESSING;
                    }
                    VirtualAioPhase::Done => *out = (*aio).completion_state,
                    _ => *out = SCE_KERNEL_ERROR_ESRCH,
                }
            }
        }
        if completed_queued_job {
            QUEUE_CV.notify_all();
        }
        if real_count != 0 {
            let Some(f) = real_aio_cancel() else {
                return SCE_KERNEL_ERROR_EIO;
            };
            let rc = f(
                real_ids.as_mut_ptr(),
                real_count as c_int,
                real_states.as_mut_ptr(),
            );
            if rc != 0 {
                return rc;
            }
            for i in 0..real_count {
                *states.add(real_positions[i]) = real_states[i];
            }
        }
        0
    }
}
