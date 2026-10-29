//! AMPRPAK4 manifest overlay and packed-path logic.
use core::cmp::Ordering;

use crate::manifest::Manifest;
use crate::FILE_PACKED;
pub use ampr_format::overlay::*;

/// The zero-based record's path, if well-formed.
pub fn file_path<'a>(m: &Manifest<'a>, index: u32) -> Option<&'a [u8]> {
    let r = m.file_record(index).ok()?;
    m.string(r.path_offset, r.path_length).ok()
}

/// Orders records by folded path, then record index.
pub fn compare_paths(m: &Manifest<'_>, left: u32, right: u32) -> Ordering {
    match (file_path(m, left), file_path(m, right)) {
        (Some(a), Some(b)) => folded_compare(a, b).then(left.cmp(&right)),
        _ => left.cmp(&right),
    }
}

/// Compares a record path with `key`; a record without a path sorts after `key`.
pub fn compare_key(m: &Manifest<'_>, index: u32, key: &[u8]) -> Ordering {
    file_path(m, index).map_or(Ordering::Greater, |p| folded_compare(p, key))
}

fn packed(m: &Manifest<'_>, index: u32) -> bool {
    m.file_record(index)
        .map_or(false, |r| r.flags & FILE_PACKED != 0)
}

/// Number of packed records: the length `build_packed_order` needs.
pub fn packed_count(m: &Manifest<'_>) -> u32 {
    (0..m.file_count()).filter(|&i| packed(m, i)).count() as u32
}

/// Fills `out` with the packed record indexes in `compare_paths` order.
/// `out.len()` must equal `packed_count`.
pub fn build_packed_order(m: &Manifest<'_>, out: &mut [u32]) -> bool {
    let mut cursor = 0usize;
    for i in (0..m.file_count()).filter(|&i| packed(m, i)) {
        let Some(slot) = out.get_mut(cursor) else {
            return false;
        };
        *slot = i;
        cursor += 1;
    }
    if cursor != out.len() {
        return false;
    }
    out.sort_unstable_by(|&a, &b| compare_paths(m, a, b));
    true
}

/// Whether a packed path lies strictly below `directory`.
pub fn directory_exists(m: &Manifest<'_>, order: &[u32], directory: &[u8]) -> bool {
    directory_range(m, order, directory).is_some()
}

/// The `[begin, end)` span of `order`
/// whose paths lie strictly below `directory`.
pub fn directory_range(m: &Manifest<'_>, order: &[u32], directory: &[u8]) -> Option<(u32, u32)> {
    if order.is_empty() || directory.is_empty() || directory.len() >= PATH_MAX - 1 {
        return None;
    }
    let mut buffer = [0u8; PATH_MAX];
    buffer[..directory.len()].copy_from_slice(directory);
    let mut n = directory.len();
    if buffer[n - 1] != b'/' {
        buffer[n] = b'/';
        n += 1;
    }
    prefix_range(order, &mut buffer[..n], |i| file_path(m, i))
}

/// Packed-file resolution check: one-based `file_id` from the
/// AMPRIDX3 lookup names a packed record of the indexed size.
pub fn packed_file_matches(m: &Manifest<'_>, file_id: u32, indexed_size: u64) -> bool {
    file_id
        .checked_sub(1)
        .and_then(|i| m.file_record(i).ok())
        .map_or(false, |r| {
            r.flags & FILE_PACKED != 0 && r.logical_size == indexed_size
        })
}

/// Emulator files, manifest pack volumes and stale default-named volumes
/// never appear in directory listings.
pub fn service_name_hidden(m: Option<&Manifest<'_>>, directory: &[u8], name: &[u8]) -> bool {
    const FIXED: [&[u8]; 5] = [
        b"/app0/ampr_emu.index",
        b"/app0/ampr_assets.index",
        b"/app0/ampr_commands.bin",
        b"/app0/ampr_emu.log",
        INDEX_PATH,
    ];
    if FIXED.iter().any(|t| joined_matches(directory, name, t)) {
        return true;
    }
    if let Some(m) = m {
        // Pack names are deployment-relative; listings use logical /app0.
        let mut target = [0u8; PATH_MAX];
        let root = LOGICAL_ROOT.len();
        target[..root].copy_from_slice(LOGICAL_ROOT);
        target[root] = b'/';
        for id in 0..m.pack_count() {
            let Ok(pack) = m.pack_name(id) else { continue };
            let len = root + 1 + pack.len();
            if len >= PATH_MAX {
                continue;
            }
            target[root + 1..len].copy_from_slice(pack);
            if joined_matches(directory, name, &target[..len]) {
                return true;
            }
        }
    }
    const PREFIX: &[u8] = b"ampr_assets-";
    const SUFFIX: &[u8] = b".pak";
    folded_equal(directory, LOGICAL_ROOT)
        && name.len() > PREFIX.len()
        && name.len() >= SUFFIX.len()
        && folded_equal(&name[..PREFIX.len()], PREFIX)
        && folded_equal(&name[name.len() - SUFFIX.len()..], SUFFIX)
}

/// The child at `order[cursor]` of a directory
/// whose normalized path is `dir_len` bytes, merged with following entries
/// of the same folded name (a directory if any of them has descendants).
pub fn next_child(
    m: &Manifest<'_>,
    order: &[u32],
    range_end: u32,
    dir_len: usize,
    cursor: u32,
    name: &mut [u8],
) -> Option<Child> {
    ampr_format::overlay::next_child(order, range_end, dir_len, cursor, name, |i| file_path(m, i))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{header_crc, ENDIAN_MARKER, FILE_RECORD, PAK_HEADER, PAK_HEADER_CRC_AT, PAK_MAGIC};
    use std::vec::Vec;

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    // Header-CRC-valid manifest view of (path, flags) records, no chunks/packs.
    fn manifest(files: &[(&[u8], u32)]) -> Vec<u8> {
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
        put32(&mut b, 8, 4);
        put32(&mut b, 12, PAK_HEADER as u32);
        put32(&mut b, 20, ENDIAN_MARKER);
        put64(&mut b, 40, files.len() as u64);
        put32(&mut b, 60, 48);
        put32(&mut b, 64, 12);
        put32(&mut b, 68, 32);
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

    #[test]
    fn packed_order_drives_directory_listing() {
        let bytes = manifest(&[
            (b"/app0/B/x.bin", FILE_PACKED),
            (b"/app0/a.bin", FILE_PACKED),
            (b"/app0/c.bin", 0),
            (b"/app0/b/y.bin", FILE_PACKED),
            (b"/app0/ab.bin", FILE_PACKED),
            (b"/app0/c2.bin", FILE_PACKED),
        ]);
        let m = Manifest::view_trusted(&bytes).unwrap();
        let mut order = [0u32; 5];
        assert_eq!(packed_count(&m), 5);
        assert!(build_packed_order(&m, &mut order));
        assert_eq!(order, [1, 4, 0, 3, 5]);

        let mut dir = [0u8; 64];
        let len = normalize_path(b"\\APP0//B/".iter().copied(), &mut dir).unwrap();
        assert_eq!(&dir[..=usize::from(len)], b"/APP0/B\0");
        assert_eq!(directory_range(&m, &order, &dir[..7]), Some((2, 4)));
        assert_eq!(directory_range(&m, &order, b"/app0/c.bin"), None);
        assert!(directory_exists(&m, &order, &dir[..7]));
        assert!(!directory_exists(&m, &order, b"/app0/c.bin"));

        let (begin, end) = directory_range(&m, &order, b"/app0").unwrap();
        assert_eq!((begin, end), (0, 5));
        let mut name = [0u8; 256];
        let mut seen = Vec::new();
        let mut cursor = begin;
        while let Some(c) = next_child(&m, &order, end, 5, cursor, &mut name) {
            seen.push((name[..usize::from(c.len)].to_vec(), c.kind));
            cursor = c.next;
        }
        let want: [(&[u8], u8); 4] = [
            (b"a.bin", DT_REG),
            (b"ab.bin", DT_REG),
            (b"B", DT_DIR),
            (b"c2.bin", DT_REG),
        ];
        assert_eq!(seen.len(), 4);
        for ((got, kind), (n, k)) in seen.iter().zip(want) {
            assert_eq!((got.as_slice(), *kind), (n, k));
        }

        let mut d = [0xffu8; 20];
        assert_eq!(
            emit_dirent(&mut d, b"ab.bin", DT_REG, 0x1_8000_0002),
            Some(16)
        );
        assert_eq!(&d[..16], b"\x03\0\0\0\x10\0\x08\x06ab.bin\0\0");
        assert_eq!(emit_dirent(&mut d[..15], b"ab.bin", DT_REG, 0), None);
        assert!(service_name_hidden(None, b"/APP0", b"AMPR_assets-7.PAK"));
        assert!(!service_name_hidden(
            None,
            b"/app0/sub",
            b"ampr_assets-7.pak"
        ));
    }
}
