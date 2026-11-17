//! Joins a pack index to the compiled index view at mount, so an open
//! finds a packed file's pack data by its view id with no path compare.
//!
//! The join probes by hash only. A hash on the view's collision list has no
//! row here (`Builder::find_hash`), so that file is left loose: without the
//! AMPRIDX3 source the join cannot read the stored path to tell the two
//! files apart, and the list is expected to be empty (about 3 in 10^8 at
//! 1,000,000 files).
use crate::source::{Source, PATH_BUF};
use crate::view::Builder;
use crate::{view_hash_parts, zstd, Error, Result};

/// Joins every zstd file record, in id order, to its view row: the row is
/// the one whose hash is `/app0/` plus the record's relative path, case
/// folded, so a path that differs from the AMPRIDX3 path only in case is
/// joined. Sets the row's first chunk and links it packed. A record with no
/// row is skipped (not served, as before the view); a row whose size
/// differs from the record is `Invalid`, which invalidates the mount.
/// Returns the number of records joined.
pub fn join_zstd<S: Source + ?Sized>(b: &mut Builder<'_>, z: &zstd::Index<'_, S>) -> Result<u32> {
    let mut buf = [0u8; PATH_BUF];
    let mut packed = 0u32;
    for i in 0..z.file_count() {
        let rec = z.file(i)?;
        let path = z.path(&rec, &mut buf)?;
        // A row whose 64-bit hash another AMPRIDX3 file shares has no
        // find_hash answer and stays loose: confirming it by path would need
        // the AMPRIDX3 source here, for a case no real index has shown.
        let Some(id) = b.find_hash(view_hash_parts(&[b"/app0/", path])) else {
            continue;
        };
        if b.size(id) != rec.logical_size {
            return Err(Error::Invalid);
        }
        // A second record that folds to a linked row (a case variant) is
        // skipped, so the first record's chunk stays.
        if b.link_packed(id) {
            b.set_chunk(id, rec.first_chunk);
            packed += 1;
        }
    }
    Ok(packed)
}

/// Joins LZ4 (and pkg) records by position: record `i` belongs to view id
/// `i + 1`. `record(i)` answers `Some((size, pak_path_hash))` for a packed
/// record and `None` for a loose one. A packed record whose id is past the
/// view, or whose size or hash differs from the row, sets bit `id` of
/// `mismatch` (byte `id / 8`, bit `id % 8`) and is not linked: the mount
/// stays valid and an open of that id answers as a failed per-open check
/// did. `mismatch` is cleared first and must hold `files + 1` bits, else
/// `Invalid`; a bit past its end is dropped, since no view id reaches it.
/// Returns the number of records linked.
pub fn join_records(
    b: &mut Builder<'_>,
    count: u32,
    mut record: impl FnMut(u32) -> Result<Option<(u64, u64)>>,
    mismatch: &mut [u8],
) -> Result<u32> {
    let files = b.files();
    if mismatch.len() < (files as usize + 1).div_ceil(8) {
        return Err(Error::Invalid);
    }
    mismatch.fill(0);
    let mut packed = 0u32;
    for i in 0..count {
        let Some((size, hash)) = record(i)? else {
            continue;
        };
        let id = i + 1;
        if id > files || size != b.size(id) || hash != b.lz4_hash(id) {
            if let Some(byte) = mismatch.get_mut(id as usize / 8) {
                *byte |= 1 << (id % 8);
            }
            continue;
        }
        b.link_packed(id);
        packed += 1;
    }
    Ok(packed)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::index::{tests::image, Index};
    use crate::view::{build, sizes, Buffers, Dir, Hit, Packs, Row, DIR_PACKED, NO_CHUNK};
    use crate::zstd::{path_hash, INDEX_HEADER_SIZE, INDEX_MAGIC, VOLUME_HEADER_SIZE};
    use crate::{crc32, pak_path_hash};
    use std::vec;
    use std::vec::Vec;

    /// Owned memory for every `Buffers` slice.
    struct Mem {
        rows: Vec<Row>,
        lz4_hash: Vec<u64>,
        u32s: [Vec<u32>; 5],
        dirs: Vec<Dir>,
    }

    impl Mem {
        fn new(files: u32, dir_cap: u32, packs: Packs) -> Self {
            let sz = sizes(files, dir_cap).unwrap();
            let n = files as usize;
            let (chunk, lz4) = sz.pack_columns(packs);
            let (fs, ds) = (sz.file_slots as usize, sz.dir_slots as usize);
            Mem {
                rows: vec![Row::default(); n],
                lz4_hash: vec![0; lz4],
                u32s: [chunk, fs, ds, 256, n].map(|l| vec![0; l]),
                dirs: vec![Dir::default(); dir_cap as usize],
            }
        }

        fn bufs(&mut self) -> Buffers<'_> {
            let [chunk, slots, dir_slots, collide, dir_of] = &mut self.u32s;
            Buffers {
                rows: &mut self.rows,
                chunk,
                slots,
                dirs: &mut self.dirs,
                dir_slots,
                collide,
                dir_of,
                lz4_hash: &mut self.lz4_hash,
            }
        }
    }

    /// A zstd index of `files` (relative path, size under one chunk): one
    /// raw chunk per file, all in volume 0, records in (hash, path) order.
    fn zstd_image(files: &[(&[u8], u64)]) -> Vec<u8> {
        let mut files = files.to_vec();
        files.sort_by(|a, b| (path_hash(a.0), a.0).cmp(&(path_hash(b.0), b.0)));
        let n = files.len() as u64;
        let (mut recs, mut chunks, mut strings) = (Vec::new(), Vec::new(), Vec::new());
        let mut offset = VOLUME_HEADER_SIZE as u64;
        for (i, &(path, size)) in files.iter().enumerate() {
            recs.extend_from_slice(&path_hash(path).to_le_bytes());
            recs.extend_from_slice(&size.to_le_bytes());
            recs.extend_from_slice(&(i as u32).to_le_bytes()); // first_chunk
            recs.extend_from_slice(&(strings.len() as u32).to_le_bytes());
            recs.extend_from_slice(&(path.len() as u16).to_le_bytes());
            recs.extend_from_slice(&[0; 6]); // flags, reserved
            chunks.extend_from_slice(&(offset | ((size - 1) << 44)).to_le_bytes());
            offset += size;
            strings.extend_from_slice(path);
        }
        let total: u64 = files.iter().map(|f| f.1).sum();
        let mut out = vec![0u8; INDEX_HEADER_SIZE];
        out.extend_from_slice(&recs);
        out.extend_from_slice(&chunks);
        out.extend_from_slice(&offset.to_le_bytes()); // volume 0 size
        out.extend_from_slice(&strings);
        let h = &mut out[..INDEX_HEADER_SIZE];
        h[..8].copy_from_slice(INDEX_MAGIC);
        h[8..12].copy_from_slice(&1u32.to_le_bytes());
        h[12..16].copy_from_slice(&(INDEX_HEADER_SIZE as u32).to_le_bytes());
        h[16] = crate::zstd::CHUNK_SHIFT;
        h[17] = 5;
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        let files_at = INDEX_HEADER_SIZE as u64;
        let strings_at = files_at + 40 * n + 8;
        for (at, value) in [
            (40, n),
            (48, n),
            (56, files_at),
            (64, files_at + 32 * n),
            (72, files_at + 40 * n),
            (80, strings_at),
            (88, strings.len() as u64),
            (96, total),
        ] {
            h[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        // The header CRC covers the header with bytes 112..120 still zero.
        let header_crc = crc32(&out[..INDEX_HEADER_SIZE]);
        let payload_crc = crc32(&out[INDEX_HEADER_SIZE..]);
        out[112..116].copy_from_slice(&payload_crc.to_le_bytes());
        out[116..120].copy_from_slice(&header_crc.to_le_bytes());
        out
    }

    /// AMPRIDX3 rows; `image` gives row `i` the size `10 * (i + 1)`.
    const ROWS: [&[u8]; 5] = [
        b"/app0/Data/A.bin",
        b"/app0/data/b.bin",
        b"/app0/c.bin",
        b"/app0/loose/d.bin",
        b"/app0/e.bin",
    ];

    /// `Hit::Dir` id of the folded directory `key`.
    fn dir_id(v: &crate::view::View<'_>, img: &[u8], key: &[u8]) -> u32 {
        match v.lookup(img, key).unwrap() {
            Hit::Dir(d) => d,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn join_zstd_sets_chunks_and_links_packed_rows() {
        let img = image(&ROWS);
        let idx = Index::open(&img[..]).unwrap();
        // `data/a.bin` differs from row 1 only in case; `missing.bin` has
        // no row and is skipped.
        let entries: [(&[u8], u64); 4] = [
            (b"data/a.bin", 10),
            (b"data/b.bin", 20),
            (b"c.bin", 30),
            (b"missing.bin", 99),
        ];
        let zimg = zstd_image(&entries);
        let z = zstd::Index::open(&zimg[..]).unwrap();
        let mut first = [NO_CHUNK; 5];
        let mut buf = [0u8; PATH_BUF];
        for i in 0..z.file_count() {
            let rec = z.file(i).unwrap();
            let path = z.path(&rec, &mut buf).unwrap();
            let row = ROWS.iter().position(|r| r[6..].eq_ignore_ascii_case(path));
            if let Some(row) = row {
                first[row] = rec.first_chunk;
            }
        }
        assert!(first[..3].iter().all(|&c| c != NO_CHUNK));
        let mut mem = Mem::new(5, 16, Packs::Zstd);
        let mut b = build(&idx, mem.bufs()).unwrap();
        assert_eq!(join_zstd(&mut b, &z), Ok(3));
        let v = b.finish();
        for id in 1..=5u32 {
            let i = id as usize - 1;
            assert_eq!(v.chunk(id), first[i], "id {id}");
            assert_eq!(v.packed(id), i < 3, "id {id}");
        }
        for key in [&b"/app0"[..], b"/app0/data"] {
            assert_ne!(v.dir(dir_id(&v, &img, key)).flags & DIR_PACKED, 0);
        }
        assert_eq!(v.dir(dir_id(&v, &img, b"/app0/loose")).flags, 0);
    }

    #[test]
    fn join_zstd_refuses_a_size_mismatch() {
        let img = image(&ROWS);
        let idx = Index::open(&img[..]).unwrap();
        let zimg = zstd_image(&[(b"data/b.bin", 20), (b"c.bin", 31)]);
        let z = zstd::Index::open(&zimg[..]).unwrap();
        let mut mem = Mem::new(5, 16, Packs::Zstd);
        let mut b = build(&idx, mem.bufs()).unwrap();
        assert_eq!(join_zstd(&mut b, &z), Err(Error::Invalid));
    }

    #[test]
    fn join_records_links_matches_and_flags_mismatches() {
        let img = image(&ROWS);
        let idx = Index::open(&img[..]).unwrap();
        let ok = |i: usize| Some((10 * (i as u64 + 1), pak_path_hash(ROWS[i])));
        // Record 0 matches, 1 is loose, 2 has a wrong size, 3 a wrong hash,
        // 4 matches and 5 is past the view's 5 files.
        let records = [
            ok(0),
            None,
            Some((31, pak_path_hash(ROWS[2]))),
            Some((40, pak_path_hash(b"/app0/other.bin"))),
            ok(4),
            Some((60, 1)),
        ];
        let mut mem = Mem::new(5, 16, Packs::Lz4);
        let mut b = build(&idx, mem.bufs()).unwrap();
        let mut mismatch = [0xffu8; 1];
        let got = join_records(&mut b, 6, |i| Ok(records[i as usize]), &mut mismatch);
        assert_eq!(got, Ok(2));
        assert_eq!(mismatch[0], (1 << 3) | (1 << 4) | (1 << 6));
        let v = b.finish();
        let packed: Vec<bool> = (1..=5).map(|id| v.packed(id)).collect();
        assert_eq!(packed, [true, false, false, false, true]);
        assert!((1..=5).all(|id| v.chunk(id) == NO_CHUNK));
    }

    #[test]
    fn join_records_refuses_a_short_bitmap_and_passes_errors_on() {
        // 8 files need 9 bits, two bytes.
        let paths: Vec<Vec<u8>> = (0..8)
            .map(|i| std::format!("/app0/f{i}").into_bytes())
            .collect();
        let refs: Vec<&[u8]> = paths.iter().map(|p| &p[..]).collect();
        let img = image(&refs);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(8, 16, Packs::Lz4);
        let mut b = build(&idx, mem.bufs()).unwrap();
        let none = |_| Ok(None);
        assert_eq!(
            join_records(&mut b, 8, none, &mut [0; 1]),
            Err(Error::Invalid)
        );
        assert_eq!(join_records(&mut b, 8, none, &mut [0; 2]), Ok(0));
        let fail = |_| Err(Error::Io);
        assert_eq!(join_records(&mut b, 8, fail, &mut [0; 2]), Err(Error::Io));
    }
}
