//! Read-planning cases: chunk views, page flags, read tasks and error classes.
use ampr_lz4::manifest::{Chunk, FileRecord, Manifest};
use ampr_lz4::plan::{task_count, ChunkView, CoreError, ReadTask};
use ampr_lz4::{
    crc32, crc32_seeded, pak_path_hash, CHUNK_LZ4, CHUNK_PAGE_ALIGNED as AL,
    CHUNK_PAGE_CONTAINED as CO, CHUNK_RAW, FILE_PACKED, FILE_STORE_ONLY, PACK_IO_PAGE_LAYOUT,
};

struct F {
    path: &'static [u8],
    size: u64,
    first: u32,
    count: u32,
    flags: u32,
    shift: u8,
}

fn desc(stored: u32, codec: u32, flags: u32) -> u32 {
    (stored - 1) | codec << 20 | flags << 22
}

/// Writes an AMPRPAK4 manifest with one pack named `p.pak` and valid CRCs.
fn build(files: &[F], chunks: &[(u64, u32)], pack: (u64, u64, u32)) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut recs = Vec::new();
    for f in files {
        let at = strings.len() as u32;
        strings.extend_from_slice(f.path);
        strings.push(0);
        recs.extend_from_slice(&pak_path_hash(f.path).to_le_bytes());
        recs.extend_from_slice(&f.size.to_le_bytes());
        recs.extend_from_slice(&7i64.to_le_bytes());
        for v in [f.first, f.count, at, f.path.len() as u32, f.flags] {
            recs.extend_from_slice(&v.to_le_bytes());
        }
        recs.extend_from_slice(&[f.shift, 0, 0, 0]);
    }
    let name_at = strings.len() as u32;
    strings.extend_from_slice(b"p.pak\0");
    let mut b = vec![0u8; 128];
    b[..8].copy_from_slice(b"AMPRPAK4");
    let files_at = 128u64;
    let chunks_at = files_at + recs.len() as u64;
    let packs_at = chunks_at + chunks.len() as u64 * 12;
    let strings_at = packs_at + 32;
    for (at, v) in [
        (8, 4u32),
        (12, 128),
        (20, 0x0102_0304),
        (56, 1),
        (60, 48),
        (64, 12),
        (68, 32),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    let w64 = [
        (40, files.len() as u64),
        (48, chunks.len() as u64),
        (72, files_at),
        (80, chunks_at),
        (88, packs_at),
        (96, strings_at),
        (104, strings.len() as u64),
    ];
    for (at, v) in w64 {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&recs);
    for &(loc, d) in chunks {
        b.extend_from_slice(&loc.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
    }
    let (payload, file_size, page) = pack;
    b.extend_from_slice(&payload.to_le_bytes());
    b.extend_from_slice(&file_size.to_le_bytes());
    for v in [name_at, 5, PACK_IO_PAGE_LAYOUT, page] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&strings);
    let payload_crc = crc32(&b[128..]);
    b[112..116].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32(&b[..128]);
    b[116..120].copy_from_slice(&header_crc.to_le_bytes());
    b
}

const PS: u32 = FILE_PACKED | FILE_STORE_ONLY;

/// a.bin: 3 raw 16 KiB blocks, last one short (7232); B.txt loose; c.lz4: one
/// page-contained LZ4 chunk. Manifest::open accepts it.
fn sample() -> Vec<u8> {
    build(
        &[
            F {
                path: b"/app0/a.bin",
                size: 40000,
                first: 0,
                count: 3,
                flags: PS,
                shift: 14,
            },
            F {
                path: b"/app0/Dir/B.txt",
                size: 7,
                first: 0,
                count: 0,
                flags: 0,
                shift: 0,
            },
            F {
                path: b"/app0/c.lz4",
                size: 1000,
                first: 3,
                count: 1,
                flags: FILE_PACKED,
                shift: 14,
            },
        ],
        &[
            (4096, desc(16384, 0, AL as u32)),
            (20480, desc(16384, 0, AL as u32)),
            (36864, desc(7232, 0, AL as u32)),
            (45056, desc(500, 1, CO as u32)),
        ],
        (45056, 49152, 4096),
    )
}

fn chunk(offset: u64, stored_size: u32, codec: u8, flags: u8) -> Chunk {
    Chunk {
        offset,
        pack_id: 0,
        stored_size,
        codec,
        flags,
    }
}

fn task(chunk_index: u32, src: u32, len: u32, dst: u32, c: Chunk, raw: u32) -> ReadTask {
    ReadTask {
        chunk_index,
        source_offset: src,
        copy_length: len,
        destination_offset: dst,
        chunk: ChunkView {
            chunk: c,
            raw_size: raw,
        },
    }
}

/// Fixture written by the upstream Python pack tools (drakmor/ampr_emu
/// tools/build_ampr_index.py and tools/ampr_pack_format.py).
#[test]
fn python_fixture_reads_and_plans_one_raw_block() {
    let bytes = include_bytes!("fixtures/python_manifest.bin");
    let m = Manifest::open(&bytes[..]).expect("Python writer manifest must be accepted");
    assert_eq!(
        m.build_id,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!((m.file_count(), m.chunk_count(), m.pack_count()), (2, 1, 1));
    let packed = m.file(0).unwrap();
    let mut buf = [0u8; ampr_format::source::PATH_BUF];
    assert_eq!(m.path(&packed, &mut buf).unwrap(), b"/app0/Data/Test.bin");
    assert_eq!((packed.logical_size, packed.mtime), (16384, 123));
    let loose = m.file(1).unwrap();
    assert_eq!(m.path(&loose, &mut buf).unwrap(), b"/app0/readme.txt");
    assert_eq!(
        (loose.logical_size, loose.mtime, loose.chunk_count),
        (7, 456, 0)
    );
    let chunk0 = m.chunk(0).unwrap();
    assert_eq!(
        (chunk0.offset, chunk0.pack_id, chunk0.stored_size),
        (4096, 0, 16384)
    );
    assert_eq!((chunk0.codec, chunk0.flags), (CHUNK_RAW, AL));
    let pack = m.pack(0).unwrap();
    assert_eq!(m.pack_name(0, &mut buf).unwrap(), b"ampr_assets-000.pak");
    assert_eq!(
        (pack.payload_offset(), pack.payload_bytes, pack.file_size),
        (4096, 16384, 20480)
    );
    assert_eq!(pack.io_page_size, 4096);

    let f = m.file_record(0).unwrap();
    assert_eq!(f, FileRecord::parse(&bytes[128..176]).unwrap());
    assert_eq!(
        (f.logical_size, f.chunk_count, f.block_shift, f.flags),
        (16384, 1, 14, PS)
    );
    let c = chunk(4096, 16384, CHUNK_RAW, AL);
    assert_eq!(task_count(&f, 0, 16384), 1);
    assert_eq!(
        m.read_task(&f, 0, 16384, 0),
        Ok(task(0, 0, 16384, 0, c, 16384))
    );
    assert_eq!(
        m.read_task(&f, 100, 50, 0),
        Ok(task(0, 100, 50, 0, c, 16384))
    );
    assert_eq!(
        m.validate_logical_file(1, b"/APP0\\data/test.BIN", 16384),
        Ok(())
    );
    let loose = m.file_record(1).unwrap();
    assert_eq!(task_count(&loose, 0, 7), 0);
    assert_eq!(
        m.read_task(&loose, 0, 7, 0),
        Err(CoreError::InvalidArgument)
    );
    assert_eq!(
        FileRecord::parse(&bytes[128..175]).err(),
        Some(ampr_lz4::Error::Invalid)
    );
}

#[test]
fn tasks_split_requests_at_block_boundaries() {
    let b = sample();
    let m = Manifest::open(&b[..]).unwrap();
    let f = m.file_record(0).unwrap();
    let c = [
        chunk(4096, 16384, CHUNK_RAW, AL),
        chunk(20480, 16384, CHUNK_RAW, AL),
        chunk(36864, 7232, CHUNK_RAW, AL),
    ];
    // Spans all three blocks, including the short last one.
    assert_eq!(task_count(&f, 100, 39900), 3);
    assert_eq!(
        m.read_task(&f, 100, 39900, 0),
        Ok(task(0, 100, 16284, 0, c[0], 16384))
    );
    assert_eq!(
        m.read_task(&f, 100, 39900, 1),
        Ok(task(1, 0, 16384, 16284, c[1], 16384))
    );
    assert_eq!(
        m.read_task(&f, 100, 39900, 2),
        Ok(task(2, 0, 7232, 32668, c[2], 7232))
    );
    assert_eq!(m.read_task(&f, 100, 39900, 3), Err(CoreError::OutOfRange));
    assert_eq!(
        m.read_task(&f, 100, 39900, usize::MAX),
        Err(CoreError::OutOfRange)
    );
    // Straddles one boundary.
    assert_eq!(task_count(&f, 16000, 1000), 2);
    assert_eq!(
        m.read_task(&f, 16000, 1000, 1),
        Ok(task(1, 0, 616, 384, c[1], 16384))
    );
    // Last byte at EOF.
    assert_eq!(task_count(&f, 39999, 1), 1);
    assert_eq!(
        m.read_task(&f, 39999, 1, 0),
        Ok(task(2, 7231, 1, 0, c[2], 7232))
    );
    // offset == size, zero length, past EOF.
    for (off, len) in [
        (40000, 0),
        (40000, 1),
        (0, 0),
        (0, 40001),
        (39999, 2),
        (1, u64::MAX),
    ] {
        assert_eq!(task_count(&f, off, len), 0, "{off} {len}");
        assert_eq!(
            m.read_task(&f, off, len, 0),
            Err(CoreError::InvalidArgument)
        );
    }
    assert_eq!(task_count(&f, 0, 40000), 3);
    let lz = m.file_record(2).unwrap();
    let lc = chunk(45056, 500, CHUNK_LZ4, CO);
    assert_eq!(
        m.read_task(&lz, 999, 1, 0),
        Ok(task(3, 999, 1, 0, lc, 1000))
    );
    // Logical-file checks fold case and separators.
    assert_eq!(m.validate_logical_file(1, b"/APP0/A.BIN", 40000), Ok(()));
    assert_eq!(m.validate_logical_file(2, b"\\app0\\dir\\b.txt", 7), Ok(()));
    let bad = CoreError::ChecksumMismatch;
    assert_eq!(m.validate_logical_file(1, b"/app0/a.bin", 39999), Err(bad));
    assert_eq!(m.validate_logical_file(1, b"/app0/b.bin", 40000), Err(bad));
    assert_eq!(
        m.validate_logical_file(1, b"/app0/a.bin\0", 40000),
        Err(bad)
    );
    for id in [0, 4, u32::MAX] {
        assert_eq!(
            m.validate_logical_file(id, b"/app0/a.bin", 40000),
            Err(CoreError::InvalidArgument)
        );
    }
}

#[test]
fn bad_records_keep_error_classes() {
    let b = sample();
    let m = Manifest::open(&b[..]).unwrap();
    let base = m.file_record(0).unwrap();
    for shift in [13, 21] {
        let f = FileRecord {
            block_shift: shift,
            ..base
        };
        assert_eq!(task_count(&f, 0, 1), 0);
        assert_eq!(m.read_task(&f, 0, 1, 0), Err(CoreError::InvalidArgument));
    }
    // Chunk run past the manifest: make_task rejects.
    let f = FileRecord {
        first_chunk: 2,
        ..base
    };
    assert_eq!(m.read_task(&f, 0, 1, 0), Err(CoreError::InvalidArgument));
    // Fewer chunks than the request needs.
    let f = FileRecord {
        chunk_count: 1,
        ..base
    };
    assert_eq!(task_count(&f, 0, 40000), 3);
    assert!(m.read_task(&f, 0, 40000, 0).is_ok());
    assert_eq!(m.read_task(&f, 0, 40000, 1), Err(CoreError::OutOfRange));
    assert_eq!(
        CoreError::from(ampr_lz4::Error::Checksum),
        CoreError::ChecksumMismatch
    );
    // Stale header CRC: open rejects it; truncated views never panic.
    assert_eq!(crc32_seeded(b"56789", crc32(b"1234")), 0xcbf4_3926);
    let mut stale = sample();
    stale[24] ^= 1;
    assert_eq!(
        Manifest::open(&stale[..]).err(),
        Some(ampr_lz4::Error::Checksum)
    );
    assert!(Manifest::view_trusted(&stale[..]).is_ok());
    for n in 0..stale.len() {
        let _ = Manifest::view_trusted(&stale[..n]);
    }
    assert!(Manifest::view_trusted(&stale[..stale.len() - 1]).is_err());
    // Codec 3 and unknown flag bits are not checked by `chunk_record`, which read planning uses.
    let f = |count| F {
        path: b"/app0/x",
        size: 16384 * count as u64,
        first: 0,
        count,
        flags: FILE_PACKED,
        shift: 14,
    };
    let b = build(
        &[f(2)],
        &[(4096, desc(64, 3, 0xff)), (8192, desc(64, 0, 0) | 1 << 30)],
        (8192, 16384, 4096),
    );
    assert!(Manifest::open(&b[..]).is_err());
    let m = Manifest::view_trusted(&b[..]).unwrap();
    let r = m.file_record(0).unwrap();
    let c = chunk(4096, 64, 3, 0xff);
    assert_eq!(
        m.read_task(&r, 0, 16385, 0),
        Ok(task(0, 0, 16384, 0, c, 16384))
    );
    assert_eq!(m.read_task(&r, 0, 16385, 1), Err(CoreError::InvalidFormat));
}

/// A source that is not a slice: counts reads and can fail like a file.
struct Counting {
    bytes: Vec<u8>,
    reads: std::cell::Cell<usize>,
    fail: std::cell::Cell<bool>,
}

impl ampr_format::source::Source for Counting {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_lz4::Result<()> {
        self.reads.set(self.reads.get() + 1);
        if self.fail.get() {
            return Err(ampr_lz4::Error::Io);
        }
        self.bytes[..].read_at(at, out)
    }
}

#[test]
fn manifest_reads_through_a_non_slice_source() {
    use ampr_format::source::PATH_BUF;
    let b = sample();
    let src = Counting {
        bytes: b.clone(),
        reads: std::cell::Cell::new(0),
        fail: std::cell::Cell::new(false),
    };
    let (paged, plain) = (
        Manifest::open(&src).unwrap(),
        Manifest::open(&b[..]).unwrap(),
    );
    assert!(src.reads.get() > 0);
    assert_eq!(paged.build_id, plain.build_id);
    let counts = ampr_lz4::manifest::header_counts(&b[..ampr_lz4::PAK_HEADER]);
    assert_eq!(
        counts,
        Ok((plain.file_count(), plain.chunk_count(), plain.pack_count()))
    );
    assert_eq!(
        ampr_lz4::manifest::header_counts(&b[8..]),
        Err(ampr_lz4::Error::Invalid)
    );
    let (mut x, mut y) = ([0u8; PATH_BUF], [0u8; PATH_BUF]);
    for id in 0..plain.file_count() {
        let (a, p) = (paged.file(id).unwrap(), plain.file(id).unwrap());
        assert_eq!(a, p);
        assert_eq!(paged.path(&a, &mut x), plain.path(&p, &mut y));
        assert_eq!(paged.file_record(id), plain.file_record(id));
    }
    assert_eq!(
        paged.path(&paged.file(0).unwrap(), &mut x).unwrap(),
        b"/app0/a.bin"
    );
    assert_eq!(
        paged.path(&paged.file(0).unwrap(), &mut [0u8; 4]).err(),
        Some(ampr_lz4::Error::Invalid)
    );
    assert_eq!(paged.chunk(3), plain.chunk(3));
    assert_eq!(paged.pack(0), plain.pack(0));
    assert_eq!(paged.pack_name(0, &mut x).unwrap(), b"p.pak");
    let f = paged.file_record(0).unwrap();
    assert_eq!(
        paged.read_task(&f, 100, 39900, 2),
        plain.read_task(&f, 100, 39900, 2)
    );
    assert_eq!(paged.validate_logical_file(3, b"/APP0/C.LZ4", 1000), Ok(()));
    assert_eq!(
        paged.validate_logical_file(3, b"/app0/c.lz5", 1000),
        Err(CoreError::ChecksumMismatch)
    );
    // A read error is not a mismatch or a loose file.
    src.fail.set(true);
    assert_eq!(
        paged.validate_logical_file(3, b"/APP0/C.LZ4", 1000),
        Err(CoreError::Io)
    );
    assert_eq!(
        ampr_lz4::overlay::packed_file_matches(&paged, 1, 40000),
        Err(ampr_lz4::Error::Io)
    );
    src.fail.set(false);
    // A path of PATH_BUF bytes or longer is refused (the PS5 path limit).
    let long: &'static [u8] = {
        let mut p = b"/app0/".to_vec();
        p.resize(PATH_BUF, b'a');
        p.leak()
    };
    for (path, ok) in [(&long[..PATH_BUF - 1], true), (long, false)] {
        let img = build(
            &[F {
                path,
                size: 7,
                first: 0,
                count: 0,
                flags: 0,
                shift: 0,
            }],
            &[],
            (4096, 8192, 4096),
        );
        assert_eq!(Manifest::open(&img[..]).is_ok(), ok);
    }
    src.fail.set(true);
    assert_eq!(paged.file(0).err(), Some(ampr_lz4::Error::Io));
    assert_eq!(Manifest::open(&src).err(), Some(ampr_lz4::Error::Io));
    assert!(Manifest::view_trusted(&src).is_err());
}

#[test]
fn fast_table_gives_the_same_answers_without_record_reads() {
    let b = sample();
    let src = Counting {
        bytes: b.clone(),
        reads: std::cell::Cell::new(0),
        fail: std::cell::Cell::new(false),
    };
    let plain = Manifest::open(&src).unwrap();
    let mut fast = vec![0u8; plain.fast_len()];
    assert_eq!(fast.len(), 3 * 48 + 4 * 12 + 32);
    assert_eq!(
        plain.fill_fast(&mut fast[1..]),
        Err(ampr_lz4::Error::Invalid)
    );
    plain.fill_fast(&mut fast).unwrap();
    assert!(plain.with_fast(&fast[1..]).is_err());
    let m = plain.with_fast(&fast).unwrap();
    assert!(m.has_fast() && !plain.has_fast());
    // Records, chunks, packs and read tasks come from memory only.
    src.reads.set(0);
    for id in 0..m.file_count() {
        assert_eq!(m.file_record(id), plain.file_record(id));
        assert_eq!(m.file_record_raw(id), plain.file_record_raw(id));
    }
    for id in 0..m.chunk_count() {
        assert_eq!(m.chunk(id), plain.chunk(id));
    }
    assert_eq!(m.chunk_record(4).err(), plain.chunk_record(4).err());
    assert_eq!(m.pack_record_raw(0), plain.pack_record_raw(0));
    let f = m.file_record(0).unwrap();
    assert_eq!(
        m.read_task(&f, 100, 39900, 2),
        plain.read_task(&f, 100, 39900, 2)
    );
    assert!(src.reads.get() > 0, "the plain manifest reads its source");
    src.reads.set(0);
    m.read_task(&f, 100, 39900, 2).unwrap();
    assert_eq!(src.reads.get(), 0, "read tasks read no source");
    // Paths still come from the source, and its errors still surface.
    src.fail.set(true);
    assert_eq!(m.file(0).err(), Some(ampr_lz4::Error::Io));
    assert!(m.file_record(0).is_ok());
}

/// Packed empty files (no chunks) at `paths`, all valid for `open`.
fn empty_packed(paths: &[&'static [u8]]) -> Vec<u8> {
    let files: Vec<F> = paths
        .iter()
        .map(|&path| F {
            path,
            size: 0,
            first: 0,
            count: 0,
            flags: FILE_PACKED,
            shift: 14,
        })
        .collect();
    build(&files, &[], (4096, 8192, 4096))
}

/// Records in folded order give the packed order without a path read, and
/// it equals the path sort, case-variant ties ordered by index.
#[test]
fn sorted_records_give_the_path_sort_order_with_ties() {
    use ampr_lz4::overlay::{build_packed_order, compare_paths, packed_count};
    let b = empty_packed(&[
        b"/app0/A.bin",
        b"/app0/a.bin",
        b"/app0/B/x",
        b"/app0/b/X",
        b"/app0/b/y",
        b"/APP0/b/Y",
        b"/app0/c",
    ]);
    let m = Manifest::open(&b[..]).unwrap();
    assert!(m.records_sorted());
    let mut fast = vec![0u32; packed_count(&m) as usize];
    assert!(build_packed_order(&m, &mut fast));
    let mut sorted = fast.clone();
    sorted.reverse();
    sorted.sort_unstable_by(|&a, &b| compare_paths(&m, a, b));
    assert_eq!(fast, sorted);
    assert_eq!(fast, (0..7).collect::<Vec<u32>>());

    // Out of folded order: the order is sorted by path.
    let b = empty_packed(&[b"/app0/b", b"/app0/A", b"/app0/a"]);
    let m = Manifest::open(&b[..]).unwrap();
    assert!(!m.records_sorted());
    let mut order = vec![0u32; 3];
    assert!(build_packed_order(&m, &mut order));
    assert_eq!(order, [1, 2, 0]);
    assert!(!Manifest::open(&sample()[..]).unwrap().records_sorted());
    assert!(!Manifest::view_trusted(&b[..]).unwrap().records_sorted());
}
