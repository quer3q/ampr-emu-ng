//! AIO wait and delete, plus the single-request AIO entry points.

use super::*;

pub(crate) fn aio_state_terminal(state: c_int) -> bool {
    if state < 0 {
        return true;
    }
    let base = state & !SCE_KERNEL_AIO_STATE_NOTIFIED;
    base == SCE_KERNEL_AIO_STATE_COMPLETED || base == SCE_KERNEL_AIO_STATE_ABORTED
}

pub(crate) unsafe fn mark_virtual_wait_notified(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    states: *mut c_int,
) {
    unsafe {
        let state = pack_state();
        let _lock = PACK_M.lock();
        for i in 0..count as usize {
            let st = &mut *states.add(i);
            if !aio_state_terminal(*st) || *st < 0 {
                continue;
            }
            let id = *ids.add(i);
            let aio = lookup_virtual_aio_locked(state, id, null_mut());
            if !aio.is_null() {
                if (*aio).wait_notified {
                    *st |= SCE_KERNEL_AIO_STATE_NOTIFIED;
                }
                (*aio).wait_notified = true;
                continue;
            }
            let group = lookup_virtual_aio_group_locked(state, id, null_mut());
            if !group.is_null() {
                if (*group).wait_notified {
                    *st |= SCE_KERNEL_AIO_STATE_NOTIFIED;
                }
                (*group).wait_notified = true;
            }
        }
    }
}

/// Hook id 105: the game's own wait; ids from a packed submit are served
/// here, the rest go to the original.
pub unsafe extern "C" fn sceKernelAioWaitRequests_emul(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    states: *mut c_int,
    mode: u32,
    usec: *mut SceKernelUseconds,
) -> c_int {
    unsafe {
        if !game_ids_emulated(ids, count) {
            return match real_aio_wait() {
                Some(f) => f(ids, count, states, mode, usec),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioWaitRequests(ids, count, states, mode, usec)
    }
}

#[inline(never)]
pub unsafe fn sceKernelAioWaitRequests(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    states: *mut c_int,
    mode: u32,
    usec: *mut SceKernelUseconds,
) -> c_int {
    unsafe {
        if ids.is_null()
            || states.is_null()
            || count <= 0
            || count as usize > SCE_KERNEL_AIO_ID_NUM_MAX
            || (count > 1 && mode != SCE_KERNEL_AIO_WAIT_AND && mode != SCE_KERNEL_AIO_WAIT_OR)
        {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut has_synthetic = false;
        let mut needs_native_polling = false;
        for i in 0..count as usize {
            let id = *ids.add(i);
            let direct = decode_virtual_aio(id, null_mut(), null_mut());
            let group = decode_virtual_aio_group(id, null_mut(), null_mut());
            has_synthetic |= direct || group;
            needs_native_polling |= !direct && !group;
        }
        if !has_synthetic {
            return match real_aio_wait() {
                Some(f) => f(ids, count, states, mode, usec),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }

        let wait_all = count == 1 || mode == SCE_KERNEL_AIO_WAIT_AND;
        let timeout = if usec.is_null() { 0 } else { *usec as u64 };
        let start = pack_monotonic_usecs();
        let pack = pack_state();
        let mut observed_epoch;
        {
            let _lock = PACK_M.lock();
            observed_epoch = (*pack).aio_completion_epoch;
            // A plain group's native children complete in the kernel
            // without bumping the epoch: poll, never sleep on AIO_CV alone.
            for i in 0..count as usize {
                let group = lookup_virtual_aio_group_locked(pack, *ids.add(i), null_mut());
                if !group.is_null() && (*group).has_native_children {
                    needs_native_polling = true;
                }
            }
        }

        loop {
            let poll_rc = sceKernelAioPollRequests(ids, count, states);
            if poll_rc != 0 {
                return poll_rc;
            }
            let mut any_terminal = false;
            let mut all_terminal = true;
            for i in 0..count as usize {
                let terminal = aio_state_terminal(*states.add(i));
                any_terminal |= terminal;
                all_terminal &= terminal;
            }
            if (wait_all && all_terminal) || (!wait_all && any_terminal) {
                if !usec.is_null() {
                    let now = pack_monotonic_usecs();
                    let elapsed = if now >= start { now - start } else { timeout };
                    *usec = if elapsed < timeout {
                        (timeout - elapsed) as SceKernelUseconds
                    } else {
                        0
                    };
                }
                mark_virtual_wait_notified(ids, count, states);
                return 0;
            }

            let mut wait_usecs = if needs_native_polling {
                1000u64
            } else {
                u64::MAX
            };
            if !usec.is_null() {
                let now = pack_monotonic_usecs();
                let elapsed = if now >= start { now - start } else { timeout };
                if elapsed >= timeout {
                    *usec = 0;
                    return SCE_KERNEL_ERROR_ETIMEDOUT;
                }
                wait_usecs = wait_usecs.min(timeout - elapsed);
            }

            let mut lock = PACK_M.lock();
            if (*pack).aio_completion_epoch != observed_epoch {
                observed_epoch = (*pack).aio_completion_epoch;
                continue;
            }
            if wait_usecs == u64::MAX {
                AIO_CV.wait(&mut lock);
            } else {
                AIO_CV.wait_for_us(&mut lock, wait_usecs);
            }
            observed_epoch = (*pack).aio_completion_epoch;
        }
    }
}

/// Hook id 107: the game's own delete.
pub unsafe extern "C" fn sceKernelAioDeleteRequests_emul(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    results: *mut c_int,
) -> c_int {
    unsafe {
        if !game_ids_emulated(ids, count) {
            return match real_aio_delete() {
                Some(f) => f(ids, count, results),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioDeleteRequests(ids, count, results)
    }
}

#[inline(never)]
pub unsafe fn sceKernelAioDeleteRequests(
    ids: *mut SceKernelAioSubmitId,
    count: c_int,
    results: *mut c_int,
) -> c_int {
    unsafe {
        if ids.is_null()
            || results.is_null()
            || count <= 0
            || count as usize > SCE_KERNEL_AIO_ID_NUM_MAX
        {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let n = count as usize;
        let mut has_group = false;
        let mut has_virtual = false;
        for i in 0..n {
            if decode_virtual_aio_group(*ids.add(i), null_mut(), null_mut()) {
                has_group = true;
                break;
            }
            has_virtual |= decode_virtual_aio(*ids.add(i), null_mut(), null_mut());
        }
        if !has_group && !has_virtual {
            return match real_aio_delete() {
                Some(f) => f(ids, count, results),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        if has_group {
            return groups_single_rest_batched(
                ids,
                count,
                results,
                sceKernelAioDeleteRequest,
                sceKernelAioDeleteRequests,
            );
        }
        let mut real_ids = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_ID_NUM_MAX];
        let mut real_results = [0 as c_int; SCE_KERNEL_AIO_ID_NUM_MAX];
        let mut real_positions = [0usize; SCE_KERNEL_AIO_ID_NUM_MAX];
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
                let mut index = 0u32;
                let aio = lookup_virtual_aio_locked(state, id, &mut index);
                if aio.is_null() {
                    *results.add(i) = SCE_KERNEL_ERROR_ESRCH;
                    continue;
                }
                if (*aio).phase != VirtualAioPhase::Done {
                    (*aio).cancel_requested.store(true, Ordering::Release);
                    *results.add(i) = SCE_KERNEL_ERROR_EBUSY;
                    continue;
                }
                free_virtual_aio_locked(state, index);
                *results.add(i) = 0;
            }
        }
        if real_count != 0 {
            let Some(f) = real_aio_delete() else {
                return SCE_KERNEL_ERROR_EIO;
            };
            let rc = f(
                real_ids.as_mut_ptr(),
                real_count as c_int,
                real_results.as_mut_ptr(),
            );
            if rc != 0 {
                return rc;
            }
            for i in 0..real_count {
                *results.add(real_positions[i]) = real_results[i];
            }
        }
        0
    }
}

/// Copies a group's child ids under `PACK_M` (shared by the single-id group
/// paths). Err is the early return code; Ok(None) means the group is unknown;
/// Ok(Some(count)) is the child count. Split and plain groups are handled
/// alike: a plain group's children can be native ids or split group ids.
unsafe fn copy_group_children(
    id: SceKernelAioSubmitId,
    children: &mut [SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
) -> Result<Option<usize>, c_int> {
    unsafe {
        let state = pack_state();
        let _lock = PACK_M.lock();
        let group = lookup_virtual_aio_group_locked(state, id, null_mut());
        if group.is_null() {
            return Ok(None);
        }
        let child_count = (*group).child_count as usize;
        if child_count == 0 || child_count > SCE_KERNEL_AIO_REQUEST_NUM_MAX {
            return Err(SCE_KERNEL_ERROR_EIO);
        }
        children[..child_count].copy_from_slice(&(&(*group).children)[..child_count]);
        Ok(Some(child_count))
    }
}

/// Hook id 102: the game's own single-id poll.
pub unsafe extern "C" fn sceKernelAioPollRequest_emul(
    id: SceKernelAioSubmitId,
    state_out: *mut c_int,
) -> c_int {
    unsafe {
        if !runtime_aio_id(id) {
            return match real_aio_poll_single() {
                Some(f) => f(id, state_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioPollRequest(id, state_out)
    }
}

#[inline(never)]
pub unsafe fn sceKernelAioPollRequest(id: SceKernelAioSubmitId, state_out: *mut c_int) -> c_int {
    unsafe {
        if state_out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut id = id;
        if decode_virtual_aio(id, null_mut(), null_mut()) {
            return sceKernelAioPollRequests(&mut id, 1, state_out);
        }
        if !decode_virtual_aio_group(id, null_mut(), null_mut()) {
            return match real_aio_poll_single() {
                Some(f) => f(id, state_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        let mut children = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let child_count = match copy_group_children(id, &mut children) {
            Err(rc) => return rc,
            Ok(None) => {
                *state_out = SCE_KERNEL_ERROR_ESRCH;
                return 0;
            }
            Ok(Some(n)) => n,
        };
        let mut child_states = [0 as c_int; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let poll_rc = sceKernelAioPollRequests(
            children.as_mut_ptr(),
            child_count as c_int,
            child_states.as_mut_ptr(),
        );
        if poll_rc != 0 {
            return poll_rc;
        }
        let mut terminal = true;
        let mut aborted = false;
        let mut processing = false;
        for &cs in &child_states[..child_count] {
            if cs < 0 {
                *state_out = cs;
                return 0;
            }
            let base = cs & !SCE_KERNEL_AIO_STATE_NOTIFIED;
            if base == SCE_KERNEL_AIO_STATE_ABORTED {
                aborted = true;
            } else if base != SCE_KERNEL_AIO_STATE_COMPLETED {
                terminal = false;
                processing |= base == SCE_KERNEL_AIO_STATE_PROCESSING;
            }
        }
        *state_out = if !terminal {
            // A group reports like one job: a split read like the job it
            // replaces, a plain group the same way, since 0 is not an AIO
            // state (what the kernel reports for a pending single-id
            // submit is not measured).
            if processing {
                SCE_KERNEL_AIO_STATE_PROCESSING
            } else {
                SCE_KERNEL_AIO_STATE_SUBMITTED
            }
        } else if aborted {
            SCE_KERNEL_AIO_STATE_ABORTED
        } else {
            SCE_KERNEL_AIO_STATE_COMPLETED
        };
        0
    }
}

/// Hook id 104: the game's own single-id wait.
pub unsafe extern "C" fn sceKernelAioWaitRequest_emul(
    id: SceKernelAioSubmitId,
    state_out: *mut c_int,
    usec: *mut SceKernelUseconds,
) -> c_int {
    unsafe {
        if !runtime_aio_id(id) {
            return match real_aio_wait_single() {
                Some(f) => f(id, state_out, usec),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioWaitRequest(id, state_out, usec)
    }
}

/// Serves the game's own single-id wait on a packed submit's id (issue
/// #22); native ids go to the kernel.
#[inline(never)]
pub unsafe fn sceKernelAioWaitRequest(
    id: SceKernelAioSubmitId,
    state_out: *mut c_int,
    usec: *mut SceKernelUseconds,
) -> c_int {
    unsafe {
        if state_out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut id = id;
        if !decode_virtual_aio(id, null_mut(), null_mut())
            && !decode_virtual_aio_group(id, null_mut(), null_mut())
        {
            return match real_aio_wait_single() {
                Some(f) => f(id, state_out, usec),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioWaitRequests(&mut id, 1, state_out, SCE_KERNEL_AIO_WAIT_AND, usec)
    }
}

/// Hook id 108: the game's own single-id cancel.
pub unsafe extern "C" fn sceKernelAioCancelRequest_emul(
    id: SceKernelAioSubmitId,
    state_out: *mut c_int,
) -> c_int {
    unsafe {
        if !runtime_aio_id(id) {
            return match real_aio_cancel_single() {
                Some(f) => f(id, state_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioCancelRequest(id, state_out)
    }
}

/// Serves the game's own single-id cancel on a packed submit's id (issue
/// #22). A group cancels its children and reports `cancel_group_state`.
#[inline(never)]
pub unsafe fn sceKernelAioCancelRequest(id: SceKernelAioSubmitId, state_out: *mut c_int) -> c_int {
    unsafe {
        if state_out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut id = id;
        if decode_virtual_aio(id, null_mut(), null_mut()) {
            return sceKernelAioCancelRequests(&mut id, 1, state_out);
        }
        if !decode_virtual_aio_group(id, null_mut(), null_mut()) {
            return match real_aio_cancel_single() {
                Some(f) => f(id, state_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        let mut children = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let child_count = match copy_group_children(id, &mut children) {
            Err(rc) => return rc,
            Ok(None) => {
                *state_out = SCE_KERNEL_ERROR_ESRCH;
                return 0;
            }
            Ok(Some(n)) => n,
        };
        let mut child_states = [0 as c_int; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let cancel_rc = sceKernelAioCancelRequests(
            children.as_mut_ptr(),
            child_count as c_int,
            child_states.as_mut_ptr(),
        );
        if cancel_rc != 0 {
            return cancel_rc;
        }
        *state_out = cancel_group_state(&child_states[..child_count]);
        0
    }
}

/// Hook id 106: the game's own single-id delete.
pub unsafe extern "C" fn sceKernelAioDeleteRequest_emul(
    id: SceKernelAioSubmitId,
    result_out: *mut c_int,
) -> c_int {
    unsafe {
        if !runtime_aio_id(id) {
            return match real_aio_delete_single() {
                Some(f) => f(id, result_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        sceKernelAioDeleteRequest(id, result_out)
    }
}

#[inline(never)]
pub unsafe fn sceKernelAioDeleteRequest(id: SceKernelAioSubmitId, result_out: *mut c_int) -> c_int {
    unsafe {
        if result_out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut id = id;
        if decode_virtual_aio(id, null_mut(), null_mut()) {
            return sceKernelAioDeleteRequests(&mut id, 1, result_out);
        }
        if !decode_virtual_aio_group(id, null_mut(), null_mut()) {
            return match real_aio_delete_single() {
                Some(f) => f(id, result_out),
                None => SCE_KERNEL_ERROR_EIO,
            };
        }
        let mut children = [0 as SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let child_count = match copy_group_children(id, &mut children) {
            Err(rc) => return rc,
            Ok(None) => return SCE_KERNEL_ERROR_ESRCH,
            Ok(Some(n)) => n,
        };
        let mut child_results = [0 as c_int; SCE_KERNEL_AIO_REQUEST_NUM_MAX];
        let delete_rc = sceKernelAioDeleteRequests(
            children.as_mut_ptr(),
            child_count as c_int,
            child_results.as_mut_ptr(),
        );
        if delete_rc != 0 {
            return delete_rc;
        }

        let state = pack_state();
        let _lock = PACK_M.lock();
        let mut group_index = 0u32;
        let group = lookup_virtual_aio_group_locked(state, id, &mut group_index);
        if group.is_null() {
            return SCE_KERNEL_ERROR_ESRCH;
        }
        let group = &mut *group;
        let mut remaining = 0usize;
        for i in 0..child_count {
            if child_results[i] == SCE_KERNEL_ERROR_EBUSY {
                group.children[remaining] = children[i];
                remaining += 1;
            } else if child_results[i] != 0 && group.delete_result == 0 {
                group.delete_result = child_results[i];
            }
        }
        group.child_count = remaining as u16;
        if remaining != 0 {
            *result_out = SCE_KERNEL_ERROR_EBUSY;
            return 0;
        }
        *result_out = group.delete_result;
        free_virtual_aio_group_locked(state, group_index);
        0
    }
}

/// A group's state after a cancel, from its children's: an error first,
/// then SUBMITTED or PROCESSING while any child is not terminal (a running
/// child can still write the caller's buffer, so ABORTED must wait for it),
/// then ABORTED if any child was aborted, else COMPLETED.
pub(crate) fn cancel_group_state(child_states: &[c_int]) -> c_int {
    let (mut aborted, mut submitted, mut processing) = (false, false, false);
    for &cs in child_states {
        if cs < 0 {
            return cs;
        }
        match cs & !SCE_KERNEL_AIO_STATE_NOTIFIED {
            SCE_KERNEL_AIO_STATE_ABORTED => aborted = true,
            SCE_KERNEL_AIO_STATE_PROCESSING => processing = true,
            SCE_KERNEL_AIO_STATE_COMPLETED => {}
            _ => submitted = true,
        }
    }
    if processing {
        SCE_KERNEL_AIO_STATE_PROCESSING
    } else if submitted {
        SCE_KERNEL_AIO_STATE_SUBMITTED
    } else if aborted {
        SCE_KERNEL_AIO_STATE_ABORTED
    } else {
        SCE_KERNEL_AIO_STATE_COMPLETED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canceled_group_stays_open_while_a_child_runs() {
        let (a, p, s, c) = (
            SCE_KERNEL_AIO_STATE_ABORTED,
            SCE_KERNEL_AIO_STATE_PROCESSING,
            SCE_KERNEL_AIO_STATE_SUBMITTED,
            SCE_KERNEL_AIO_STATE_COMPLETED,
        );
        assert_eq!(cancel_group_state(&[a, p]), p);
        assert_eq!(cancel_group_state(&[s, a]), s);
        assert_eq!(cancel_group_state(&[a, c]), a);
        assert_eq!(
            cancel_group_state(&[c, c | SCE_KERNEL_AIO_STATE_NOTIFIED]),
            c
        );
        assert_eq!(cancel_group_state(&[c, -5, p]), -5);
    }

    /// The game's own AIO reaches the emulation only with a runtime id; a
    /// native or malformed call goes to the kernel untouched.
    #[test]
    fn game_aio_routes_only_runtime_ids() {
        let group = encode_virtual_aio_group(3, 1);
        let mut ids = [5 as SceKernelAioSubmitId, 0x0100_0001, group];
        assert!(runtime_aio_id(group));
        assert!(!runtime_aio_id(5));
        unsafe {
            assert!(game_ids_emulated(ids.as_ptr(), 3));
            assert!(!game_ids_emulated(ids.as_ptr(), 2));
            assert!(!game_ids_emulated(ids.as_ptr(), 0));
            assert!(!game_ids_emulated(core::ptr::null(), 3));
            ids[0] = group;
            assert!(!game_ids_emulated(ids.as_ptr(), 1 + SCE_KERNEL_AIO_ID_NUM_MAX as c_int));
        }
    }
}
