//! Pointer-level shims for the directory overlay, called from
//! `rt/pack/state.rs` and `rt/pack/directories.rs`. Those keep PackState,
//! slots and locking; they pass the view a successful
//! `ampr_pack_core_mount` filled plus the fields each helper needs.
//!
//! zstd mode has no AMPRPAK4 manifest: the manifest arguments are
//! ignored and the helpers read the mounted zstd index and its directory
//! order (rt/pack/zstd.rs). An `order` array then holds zstd file ids, and
//! nothing is packed until the zstd projection is ready.

use crate::rt::pack::{zstd, zstd_mode, AmprPackCoreView};
use ampr_lz4::manifest::Manifest;
use ampr_lz4::overlay;

/// # Safety
/// A non-null `ptr` must name `len` readable bytes, immutable for the borrow.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    (!ptr.is_null() && len <= isize::MAX as usize)
        .then(|| unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// As `bytes`; a null `ptr` with `len == 0` is an empty slice.
unsafe fn bytes_or_empty<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else {
        unsafe { bytes(ptr, len) }
    }
}

/// # Safety
/// A non-null `ptr` must name `len` writable bytes, unaliased for the borrow.
unsafe fn bytes_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    (!ptr.is_null() && len <= isize::MAX as usize)
        .then(|| unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

/// # Safety
/// A non-null `view` must name a view filled by `ampr_pack_core_mount`
/// (no re-validation here).
unsafe fn manifest(view: *const AmprPackCoreView) -> Option<crate::rt::pack::Lz4Manifest> {
    unsafe { view.as_ref() }?.manifest
}

/// # Safety
/// A non-null `order` must name `count` readable `u32`s.
unsafe fn order<'a>(order: *const u32, count: u32) -> &'a [u32] {
    if order.is_null() || count == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(order, count as usize) }
    }
}

/// # Safety
/// A non-null `value` must name `len` readable bytes.
pub unsafe fn ampr_rust_overlay_folded_hash(value: *const u8, len: usize) -> u64 {
    overlay::folded_hash(unsafe { bytes_or_empty(value, len) }.unwrap_or(&[]))
}

/// `normalize_overlay_path`. Reads `input` up to its NUL, stopping early
/// once `output` overflows.
///
/// # Safety
/// `input` must be NUL-terminated, `output` must name `capacity` writable
/// bytes, and a non-null `out_len` one writable `u16`.
pub unsafe fn ampr_rust_overlay_normalize_path(
    input: *const u8,
    output: *mut u8,
    capacity: usize,
    out_len: *mut u16,
) -> bool {
    if !out_len.is_null() {
        unsafe { *out_len = 0 };
    }
    let Some(out) = (unsafe { bytes_mut(output, capacity) }) else {
        return false;
    };
    if input.is_null() {
        return false;
    }
    let mut at = 0usize;
    let chars = core::iter::from_fn(|| {
        let ch = unsafe { *input.add(at) };
        at += 1;
        (ch != 0).then_some(ch)
    });
    match overlay::normalize_path(chars, out) {
        Some(len) => {
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            true
        }
        None => false,
    }
}

/// AMPRPAK4 packed record count; zero when the manifest view is rejected.
/// zstd builds its order with the projection instead.
///
/// # Safety
/// `view` as `manifest`.
pub unsafe fn ampr_rust_overlay_packed_count(view: *const AmprPackCoreView) -> u32 {
    unsafe { manifest(view) }.map_or(0, |m| overlay::packed_count(&m))
}

/// `build_packed_file_order` into a caller-allocated array of `count`
/// (`ampr_rust_overlay_packed_count`) entries.
///
/// # Safety
/// `view` as `manifest`; `out` must name `count` writable `u32`s.
pub unsafe fn ampr_rust_overlay_build_order(
    view: *const AmprPackCoreView,
    out: *mut u32,
    count: u32,
) -> bool {
    let Some(m) = (unsafe { manifest(view) }) else {
        return false;
    };
    if out.is_null() {
        return count == 0 && overlay::packed_count(&m) == 0;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(out, count as usize) };
    overlay::build_packed_order(&m, out)
}

/// `find_virtual_directory_range` over the sorted packed order: `Ok(true)`
/// with the span written, `Ok(false)` when no packed path lies below
/// `directory`, `Err(Io)` when a path of the paged index could not be read
/// (the directory may be packed, so the caller answers EIO, not ENOENT).
///
/// # Safety
/// `view` as `manifest`; `order` must name `count` `u32`s, `directory`
/// `directory_len` bytes; non-null outputs one `u32`.
pub unsafe fn ampr_rust_overlay_directory_range(
    view: *const AmprPackCoreView,
    order_ptr: *const u32,
    count: u32,
    directory: *const u8,
    directory_len: u16,
    out_begin: *mut u32,
    out_end: *mut u32,
) -> ampr_format::Result<bool> {
    let dir = unsafe { bytes(directory, usize::from(directory_len)) };
    let order = unsafe { order(order_ptr, count) };
    let range = if zstd_mode() {
        zstd::zstd_index()
            .zip(dir)
            .map_or(Ok(None), |(index, dir)| {
                zstd::zstd_directory_range(index, order, dir)
            })
    } else {
        unsafe { manifest(view) }
            .zip(dir)
            .map_or(Ok(None), |(m, dir)| {
                overlay::directory_range(&m, order, dir)
            })
    };
    let range = range?;
    let (begin, end) = range.unwrap_or((0, 0));
    if !out_begin.is_null() {
        unsafe { *out_begin = begin };
    }
    if !out_end.is_null() {
        unsafe { *out_end = end };
    }
    Ok(range.is_some())
}

/// Pure core of `resolve_packed_file` after the AMPRIDX3 lookup.
///
/// # Safety
/// `view` as `manifest`.
pub unsafe fn ampr_rust_overlay_packed_file_matches(
    view: *const AmprPackCoreView,
    file_id: u32,
    indexed_size: u64,
) -> ampr_format::Result<bool> {
    // zstd: a one-based AMPRIDX3 id without a zstd record is loose.
    if zstd_mode() {
        zstd::zstd_packed_file_matches(file_id, indexed_size)
    } else {
        unsafe { manifest(view) }.map_or(Ok(false), |m| {
            overlay::packed_file_matches(&m, file_id, indexed_size)
        })
    }
}

/// `service_name_hidden`; a null or empty view skips pack names.
///
/// # Safety
/// Each non-null pointer must name its length in readable bytes.
pub unsafe fn ampr_rust_overlay_service_name_hidden(
    view: *const AmprPackCoreView,
    directory: *const u8,
    directory_len: u16,
    name: *const u8,
    name_len: usize,
) -> bool {
    let (Some(dir), Some(name)) = (
        unsafe { bytes(directory, usize::from(directory_len)) },
        unsafe { bytes(name, name_len) },
    ) else {
        return false;
    };
    // zstd: the fixed service names plus ampr_zstd.index and mounted volumes.
    if zstd_mode() {
        overlay::service_name_hidden(None::<&Manifest>, dir, name)
            || zstd::zstd_name_hidden(dir, name)
    } else {
        let m = unsafe { manifest(view) };
        overlay::service_name_hidden(m.as_ref(), dir, name)
    }
}
