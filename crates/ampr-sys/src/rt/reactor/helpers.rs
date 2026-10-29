//! Native batch/micro slot helpers, SCE error-code mapping and AIO read descriptor preparation.

use super::*;

pub(crate) const fn apr_read_completion_window_exhausted(
    latestSubmitted: u64,
    completed: u64,
    capacity: u64,
) -> bool {
    latestSubmitted >= completed && latestSubmitted - completed >= capacity
}

/// Volatile release word inside the submitted range (access via read/write_volatile).
pub(crate) unsafe fn apr_native_batch_release_ptr(slot: *mut AprNativeBatchSlot) -> *mut u64 {
    unsafe {
        (addr_of_mut!((*slot).commands) as *mut u8).add(kAprNativeBatchReleaseOffset as usize)
            as *mut u64
    }
}

pub(crate) unsafe fn apr_native_batch_progress_ptr(slot: *mut AprNativeBatchSlot) -> *mut u64 {
    unsafe {
        (addr_of_mut!((*slot).commands) as *mut u8).add(kAprNativeBatchProgressOffset as usize)
            as *mut u64
    }
}

pub(crate) fn apr_native_micro_slot(slot: usize) -> *mut AprNativeMicroSlot {
    if slot >= kAprCommandBufferLiveMax {
        return null_mut();
    }
    unsafe { (g_apr_native_micro_pool.get() as *mut AprNativeMicroSlot).add(slot) }
}

pub(crate) fn apr_native_batch_slot(lane: usize, bufferIndex: usize) -> *mut AprNativeBatchSlot {
    if lane >= kAprPriorityArrayCount as usize
        || bufferIndex >= kAprNativeBatchBufferCountPerLane as usize
    {
        return null_mut();
    }
    let slot = lane * kAprNativeBatchBufferCountPerLane as usize + bufferIndex;
    unsafe { (g_apr_native_batch_pool.get() as *mut AprNativeBatchSlot).add(slot) }
}

pub(crate) const fn apr_native_batch_token(groupIndex: u32) -> u64 {
    kAprNativeBatchTokenBase + groupIndex as u64 + 1
}

/// APR 0 -> HIGH, 1..3 -> MID, 4..6 -> LOW (fixed, no load-based remap).
pub(crate) fn apr_aio_priority_from_apr(prio: u8) -> c_int {
    match prio {
        0 => SCE_KERNEL_AIO_PRIORITY_HIGH,
        1..=3 => SCE_KERNEL_AIO_PRIORITY_MID,
        _ => SCE_KERNEL_AIO_PRIORITY_LOW,
    }
}

pub(crate) fn apr_aio_api_rc_to_sce(rc: c_int) -> c_int {
    if rc == 0 || (rc as u32 & 0xFFFF0000) == 0x80020000 {
        return rc;
    }
    ampr_sce_errno_from_posix(rc.wrapping_abs())
}

pub(crate) fn apr_aio_submit_sce_rc_is_deferred(rc: c_int) -> bool {
    rc == SCE_KERNEL_ERROR_EAGAIN
}

pub(crate) fn apr_fd_acquire_sce_rc_is_deferred(rc: c_int) -> bool {
    rc == SCE_KERNEL_ERROR_EAGAIN || rc == SCE_KERNEL_ERROR_EMFILE || rc == SCE_KERNEL_ERROR_ENFILE
}

pub(crate) fn apr_aio_completion_sce_rc_is_retryable(rc: c_int) -> bool {
    rc == SCE_KERNEL_ERROR_EAGAIN || rc == SCE_KERNEL_ERROR_EBUSY || rc == SCE_KERNEL_ERROR_EINTR
}

pub(crate) fn apr_aio_result_to_sce(value: i64) -> c_int {
    if value >= 0 {
        return 0;
    }
    let rc = value as c_int;
    if (rc as u32 & 0xFFFF0000) == 0x80020000 {
        return rc;
    }
    let err = if value > -256 { (-value) as c_int } else { EIO };
    ampr_sce_errno_from_posix(err)
}

pub(crate) fn apr_file_id_is_invalid(fileId: u32) -> bool {
    fileId == 0 || fileId == SCE_AMPR_APR_FILEID_INVALID
}

pub(crate) fn apr_file_id_lookup_error(fileId: u32) -> c_int {
    if apr_file_id_is_invalid(fileId) {
        SCE_AMPR_ERROR_APR_INVALIDFILEID
    } else {
        SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID
    }
}

pub(crate) fn apr_result_is_ampr_error(rc: c_int) -> bool {
    (rc as u32 & 0xffffff00) == 0x81912000
}

pub(crate) fn apr_backend_read_error_to_apr(rc: c_int) -> c_int {
    if rc == 0 || apr_result_is_ampr_error(rc) {
        rc
    } else if rc == SCE_KERNEL_ERROR_EFAULT {
        SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS
    } else {
        SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID
    }
}

pub(crate) fn apr_backend_read_error_is_missing_path(rc: c_int) -> bool {
    rc == SCE_KERNEL_ERROR_ENOENT || rc == SCE_KERNEL_ERROR_ENOTDIR
}

pub(crate) fn apr_prepare_aio_read_desc(
    _jobId: u64,
    fileId: u32,
    buffer: *mut c_void,
    length: u64,
    offset: u64,
    errorOff: u32,
    out: &mut AprAioReadDesc,
    outRc: &mut c_int,
) -> bool {
    *outRc = 0;
    if buffer.is_null() {
        *outRc = SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS;
        return false;
    }
    if length == 0 || offset > kAprAioRequestOffsetMax {
        *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        return false;
    }
    let mut entry: FileEntryView = unsafe { core::mem::zeroed() };
    if unsafe { ampr_index_get_entry_view(fileId, &mut entry) } != 0 {
        *outRc = apr_file_id_lookup_error(fileId);
        return false;
    }
    let fileSize = entry.size as u64;
    if offset > fileSize || length > fileSize - offset {
        *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        return false;
    }
    *out = AprAioReadDesc {
        fileId,
        buffer,
        length,
        offset,
        errorOff,
        fileSize: entry.size,
        filePath: entry.path,
        filePathLength: entry.path_length,
        fileMetadataValid: true,
        ..AprAioReadDesc::default()
    };
    true
}

pub(crate) const fn apr_read_is_single_quantum_full_file(
    offset: u64,
    length: u64,
    fileSize: u64,
) -> bool {
    fileSize != 0
        && offset == 0
        && length == fileSize
        && fileSize <= AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES as u64
}

const _: () = {
    const Q: u64 = AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES as u64;
    assert!(apr_read_is_single_quantum_full_file(0, Q, Q));
    assert!(!apr_read_is_single_quantum_full_file(0, Q + 1, Q + 1));
    assert!(!apr_read_is_single_quantum_full_file(0, Q / 2, Q));
    assert!(
        AMPR_EMU_LOOSE_COALESCE_MAX_COMMANDS >= 1
            && AMPR_EMU_LOOSE_COALESCE_MAX_COMMANDS <= u8::MAX as u32
    );
    assert!(
        AMPR_EMU_LOOSE_GS_COALESCE_MAX_COMMANDS >= 1
            && AMPR_EMU_LOOSE_GS_COALESCE_MAX_COMMANDS <= AMPR_EMU_LOOSE_COALESCE_MAX_COMMANDS
    );
    assert!(
        AMPR_EMU_LOOSE_GS_COALESCE_MAX_BYTES != 0
            && AMPR_EMU_LOOSE_GS_COALESCE_MAX_BYTES <= AMPR_EMU_LOOSE_COALESCE_MAX_BYTES
    );
};
