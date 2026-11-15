//! Pointer-level shims for the directory overlay, called from
//! `rt/pack/state.rs`: path folding and normalization, and the service
//! names a listing hides. Packed lookups and listings walk the view
//! (rt/pack/directories.rs), not these.
//!
//! zstd mode has no AMPRPAK4 manifest: the manifest argument is ignored
//! and the hidden names come from the mounted zstd volumes
//! (rt/pack/zstd.rs).

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
