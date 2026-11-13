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
use ampr_format::overlay::folded_compare;
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
    // pkg: `open_pkg` returns a `view_trusted` view, which never reports its
    // records sorted, so `build_packed_order` would sort them with two path
    // reads per compare, through the index page cache when the manifest is
    // paged. One pass in record order (one path read per record) finds the
    // usual already-sorted manifest first; a read error or an out-of-order
    // pair falls back to the sort.
    if crate::rt::pack::pkg_mode() && packed_in_path_order(&m, out) {
        return true;
    }
    overlay::build_packed_order(&m, out)
}

/// Fills `out` with the packed record indexes in record order; true when
/// that is already `compare_paths` order (every path read, ties by index).
fn packed_in_path_order<S: ampr_format::source::Source + ?Sized>(
    m: &Manifest<'_, S>,
    out: &mut [u32],
) -> bool {
    let packed = |i: u32| {
        m.file_record(i)
            .is_ok_and(|r| r.flags & ampr_lz4::FILE_PACKED != 0)
    };
    let mut ids = (0..m.file_count()).filter(|&i| packed(i));
    let mut bufs = [[0u8; ampr_format::source::PATH_BUF]; 2];
    let mut prev_len = None;
    for (n, slot) in out.iter_mut().enumerate() {
        let Some(id) = ids.next() else {
            return false;
        };
        *slot = id;
        let [a, b] = &mut bufs;
        let (cur, prev) = if n & 1 == 0 { (a, &*b) } else { (b, &*a) };
        let Some(len) = overlay::file_path(m, id, cur).map(<[u8]>::len) else {
            return false;
        };
        if prev_len.is_some_and(|p: usize| folded_compare(&prev[..p], &cur[..len]).is_gt()) {
            return false;
        }
        prev_len = Some(len);
    }
    ids.next().is_none()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ampr_lz4::{
        header_crc, ENDIAN_MARKER, FILE_PACKED, FILE_RECORD, PAK_HEADER, PAK_HEADER_CRC_AT,
        PAK_MAGIC,
    };

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Header-CRC-valid manifest of (path, flags) records, as in
    /// ampr-lz4 overlay.rs tests.
    fn manifest(files: &[(&[u8], u32)]) -> std::vec::Vec<u8> {
        let strings_at = PAK_HEADER + files.len() * FILE_RECORD;
        let mut b = std::vec![0u8; strings_at];
        for (i, (path, flags)) in files.iter().enumerate() {
            let at = PAK_HEADER + i * FILE_RECORD;
            let off = (b.len() - strings_at) as u32;
            put32(&mut b, at + 32, off);
            put32(&mut b, at + 36, path.len() as u32);
            put32(&mut b, at + 40, *flags);
            b.extend_from_slice(path);
            b.push(0);
        }
        b[..8].copy_from_slice(PAK_MAGIC);
        for (at, v) in [(8, 4), (12, PAK_HEADER as u32), (20, ENDIAN_MARKER)] {
            put32(&mut b, at, v);
        }
        for (at, v) in [(60, 48), (64, 12), (68, 32)] {
            put32(&mut b, at, v);
        }
        put64(&mut b, 40, files.len() as u64);
        put64(&mut b, 72, PAK_HEADER as u64);
        for at in [80, 88, 96] {
            put64(&mut b, at, strings_at as u64);
        }
        let strings_len = (b.len() - strings_at) as u64;
        put64(&mut b, 104, strings_len);
        let crc = header_crc(&b, PAK_HEADER, PAK_HEADER_CRC_AT).unwrap();
        put32(&mut b, PAK_HEADER_CRC_AT, crc);
        b
    }

    /// Records already in folded path order (ties allowed) pass in one
    /// pass with the same order the sort gives; any other order does not.
    #[test]
    fn packed_in_path_order_matches_the_sort() {
        let sorted = manifest(&[
            (b"/app0/a.bin", FILE_PACKED),
            (b"/app0/B/x.bin", FILE_PACKED),
            (b"/app0/c.bin", 0),
            (b"/app0/b/x.bin", FILE_PACKED),
            (b"/app0/c2.bin", FILE_PACKED),
        ]);
        let m = Manifest::view_trusted(&sorted[..]).unwrap();
        let (mut fast, mut slow) = ([0u32; 4], [0u32; 4]);
        assert!(packed_in_path_order(&m, &mut fast));
        assert!(overlay::build_packed_order(&m, &mut slow));
        assert_eq!((fast, slow), ([0, 1, 3, 4], [0, 1, 3, 4]));

        let unsorted = manifest(&[(b"/app0/b.bin", FILE_PACKED), (b"/app0/a.bin", FILE_PACKED)]);
        let m = Manifest::view_trusted(&unsorted[..]).unwrap();
        assert!(!packed_in_path_order(&m, &mut [0u32; 2]));
        assert!(!packed_in_path_order(&m, &mut [0u32; 1]), "count mismatch");
    }
}
