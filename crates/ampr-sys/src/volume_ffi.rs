//! AMPRDAT3 volume-header check at the caller-owned C++ boundary.

use ampr_lz4::manifest::check_volume_header;

/// # Safety
/// The header and build-id pointers must each reference the stated initialized
/// readable bytes. Output pointers must reference writable u64 values.
pub unsafe fn ampr_rust_volume_header_validate(
    header: *const u8,
    build_id: *const u8,
    pack_id: u32,
    flags: u32,
    file_size: u64,
    payload_bytes: u64,
    io_page_size: u32,
    actual_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> u32 {
    if header.is_null()
        || build_id.is_null()
        || payload_begin.is_null()
        || payload_end.is_null()
        || (header as usize)
            .checked_add(ampr_lz4::DAT_HEADER)
            .is_none()
        || (build_id as usize).checked_add(16).is_none()
    {
        return 0;
    }
    let header = unsafe { core::slice::from_raw_parts(header, ampr_lz4::DAT_HEADER) };
    let build_id = unsafe { core::slice::from_raw_parts(build_id, 16) };
    let Ok((begin, end)) = check_volume_header(
        header,
        pack_id,
        build_id,
        flags,
        file_size,
        payload_bytes,
        io_page_size,
        actual_size,
    ) else {
        return 0;
    };
    unsafe {
        core::ptr::write(payload_begin, begin);
        core::ptr::write(payload_end, end);
    }
    1
}
