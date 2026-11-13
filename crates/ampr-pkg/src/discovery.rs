//! Finding the title's .pkg: the launcher writes its path, relative to
//! /app0, into `/app0/kraken.image` and mounts the folder that holds it
//! read-only at `/app0/kraken`. The runtime does the I/O; the checks are
//! here.

use crate::pkg_payload_end;
use ampr_lz4::{
    u32_at, u64_at, CHUNK_RECORD, ENDIAN_MARKER, FILE_RECORD, PACK_RECORD, PAK_HEADER, PAK_MAGIC,
};

// ---- kraken.image ----

/// The .pkg path named by `kraken.image`, relative to /app0: the bytes
/// before the first `\n` or `\r`. None when that is longer than `max` or
/// fails `safe_components`: empty, absolute, or with an empty, `.` or `..`
/// component, a NUL or a backslash.
pub fn kraken_image_path(contents: &[u8], max: usize) -> Option<&[u8]> {
    let end = contents
        .iter()
        .position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(contents.len());
    let path = &contents[..end];
    (path.len() <= max && ampr_format::safe_components(path)).then_some(path)
}

// ---- manifest identity ----

/// What a .pkg must match to be the pack 0 the manifest was built from:
/// pack record 0's aligned size and page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub pack0_file_size: u64,
    pub io_page_size: u32,
}

// AMPRPAK4 fields read here; the full layout is in ampr_lz4::manifest.

/// Reads the AMPRPAK4 header and pack record 0 through `read(offset, buf)`,
/// which returns false unless it filled `buf`. None on a failed read, a bad
/// magic, version, header or record size, endian marker, a zero file or
/// pack count, or a pack 0 page that is not a power of two.
pub fn manifest_identity(mut read: impl FnMut(u64, &mut [u8]) -> bool) -> Option<ManifestIdentity> {
    let mut h = [0u8; PAK_HEADER];
    if !read(0, &mut h) {
        return None;
    }
    let ok = &h[..8] == PAK_MAGIC
        && u32_at(&h, 8).ok()? == 4
        && u32_at(&h, 12).ok()? == PAK_HEADER as u32
        && u32_at(&h, 20).ok()? == ENDIAN_MARKER
        && u32_at(&h, 60).ok()? == FILE_RECORD as u32
        && u32_at(&h, 64).ok()? == CHUNK_RECORD as u32
        && u32_at(&h, 68).ok()? == PACK_RECORD as u32
        && u64_at(&h, 40).ok()? != 0
        && u32_at(&h, 56).ok()? != 0;
    if !ok {
        return None;
    }
    let mut pack = [0u8; PACK_RECORD];
    if !read(u64_at(&h, 88).ok()?, &mut pack) {
        return None;
    }
    let id = ManifestIdentity {
        pack0_file_size: u64_at(&pack, 8).ok()?,
        io_page_size: u32_at(&pack, 28).ok()?,
    };
    (id.pack0_file_size != 0 && id.io_page_size.is_power_of_two()).then_some(id)
}

/// True when a .pkg of `size` bytes, aligned up to the page, is pack 0's
/// size. No mtime check: the launcher rebuilds the manifest when the .pkg
/// changes, and an mtime check refused a valid .pkg.
pub fn pkg_size_matches(size: u64, id: &ManifestIdentity) -> bool {
    pkg_payload_end(size, id.io_page_size, id.pack0_file_size).is_some()
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_path_trims_and_refuses() {
        fn p(s: &[u8]) -> Option<&[u8]> {
            kraken_image_path(s, 262)
        }
        assert_eq!(
            p(b"kraken/stellar_ru_sound.pkg"),
            Some(&b"kraken/stellar_ru_sound.pkg"[..])
        );
        assert_eq!(p(b"kraken/a.pkg\n"), Some(&b"kraken/a.pkg"[..]));
        assert_eq!(p(b"kraken/a.pkg\r\nrest"), Some(&b"kraken/a.pkg"[..]));
        assert_eq!(p(b"kraken/a.pkg\rx\n"), Some(&b"kraken/a.pkg"[..]));
        for bad in [
            &b""[..],
            b"\n",
            b"/app0/kraken/a.pkg",
            b"kraken/../a.pkg",
            b"../a.pkg",
            b"kraken/./a.pkg",
            b"kraken//a.pkg",
            b"kraken/a.pkg/",
            b"kraken\\a.pkg",
            b"kraken/a\0.pkg",
        ] {
            assert_eq!(p(bad), None, "{bad:?}");
        }
        // `..` inside a name is a legal file name, not a parent step.
        assert_eq!(p(b"kraken/Game..v1.pkg"), Some(&b"kraken/Game..v1.pkg"[..]));
        assert_eq!(kraken_image_path(&[b'n'; 263], 262), None);
        assert_eq!(
            kraken_image_path(&[b'n'; 262], 262).map(<[u8]>::len),
            Some(262)
        );
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Header, one file record and one pack record, laid out as the
    /// manifest writer does (files, chunks, packs, strings in order).
    fn manifest() -> [u8; 256] {
        let mut m = [0u8; 256];
        m[..8].copy_from_slice(PAK_MAGIC);
        put32(&mut m, 8, 4);
        put32(&mut m, 12, 128);
        put32(&mut m, 20, 0x0102_0304);
        put64(&mut m, 40, 1);
        put64(&mut m, 48, 1);
        put32(&mut m, 56, 1);
        put32(&mut m, 60, 48);
        put32(&mut m, 64, 12);
        put32(&mut m, 68, 32);
        put64(&mut m, 72, 128);
        put64(&mut m, 80, 176);
        put64(&mut m, 88, 188);
        put64(&mut m, 96, 220);
        put64(&mut m, 188 + 8, 0x30000);
        put32(&mut m, 188 + 28, 0x10000);
        m
    }

    fn identity(m: &[u8]) -> Option<ManifestIdentity> {
        manifest_identity(|at, buf| {
            let Some(src) = usize::try_from(at)
                .ok()
                .and_then(|a| m.get(a..a + buf.len()))
            else {
                return false;
            };
            buf.copy_from_slice(src);
            true
        })
    }

    const ID: ManifestIdentity = ManifestIdentity {
        pack0_file_size: 0x30000,
        io_page_size: 0x10000,
    };

    #[test]
    fn manifest_identity_reads_pack_zero() {
        assert_eq!(identity(&manifest()), Some(ID));
        assert_eq!(identity(&manifest()[..200]), None);
        assert_eq!(manifest_identity(|_, _| false), None);
    }

    #[test]
    fn manifest_identity_refuses_bad_fields() {
        let cases: &[(usize, u64, bool)] = &[
            (0, 0, false),            // magic
            (8, 3, false),            // version
            (12, 64, false),          // header size
            (20, 0x0403_0201, false), // endian marker
            (40, 0, true),            // file count
            (56, 0, false),           // pack count
            (60, 40, false),          // file record size
            (64, 16, false),          // chunk record size
            (68, 16, false),          // pack record size
            (88, 1 << 40, true),      // packs offset past the end
            (188 + 8, 0, true),       // pack 0 size
            (188 + 28, 3000, false),  // pack 0 page
        ];
        for &(at, v, wide) in cases {
            let mut m = manifest();
            if wide {
                put64(&mut m, at, v);
            } else {
                put32(&mut m, at, v as u32);
            }
            assert_eq!(identity(&m), None, "field @{at}");
        }
    }

    /// Only the aligned size counts: no title id, no mtime.
    #[test]
    fn pkg_size_matches_aligned_size() {
        assert!(pkg_size_matches(0x2_0001, &ID));
        assert!(pkg_size_matches(0x3_0000, &ID));
        assert!(!pkg_size_matches(0x2_0000, &ID));
        assert!(!pkg_size_matches(0x3_0001, &ID));
        assert!(!pkg_size_matches(0, &ID));
    }
}
