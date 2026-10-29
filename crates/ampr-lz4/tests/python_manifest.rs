//! Fixture written by the upstream Python pack tools (drakmor/ampr_emu
//! tools/build_ampr_index.py and tools/ampr_pack_format.py).
use ampr_lz4::{manifest::Manifest, CHUNK_PAGE_ALIGNED, CHUNK_RAW};

#[test]
fn reads_python_writer_manifest() {
    let bytes = include_bytes!("fixtures/python_manifest.bin");
    let m = Manifest::open(bytes).expect("Python writer manifest must be accepted");
    assert_eq!(
        m.build_id,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!((m.file_count(), m.chunk_count(), m.pack_count()), (2, 1, 1));

    let packed = m.file(0).unwrap();
    assert_eq!(packed.path, b"/app0/Data/Test.bin");
    assert_eq!((packed.logical_size, packed.mtime), (16384, 123));
    assert_eq!(
        (packed.first_chunk, packed.chunk_count, packed.block_shift),
        (0, 1, 14)
    );
    let loose = m.file(1).unwrap();
    assert_eq!(loose.path, b"/app0/readme.txt");
    assert_eq!(
        (loose.logical_size, loose.mtime, loose.chunk_count),
        (7, 456, 0)
    );

    let chunk = m.chunk(0).unwrap();
    assert_eq!(
        (chunk.offset, chunk.pack_id, chunk.stored_size),
        (4096, 0, 16384)
    );
    assert_eq!((chunk.codec, chunk.flags), (CHUNK_RAW, CHUNK_PAGE_ALIGNED));
    let pack = m.pack(0).unwrap();
    assert_eq!(pack.name, b"ampr_assets-000.pak");
    assert_eq!(
        (pack.payload_offset(), pack.payload_bytes, pack.file_size),
        (4096, 16384, 20480)
    );
    assert_eq!(pack.io_page_size, 4096);
}
