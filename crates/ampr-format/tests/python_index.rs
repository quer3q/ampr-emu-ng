//! Fixture written by the upstream Python pack tools (drakmor/ampr_emu
//! tools/build_ampr_index.py and tools/ampr_pack_format.py).
use ampr_format::{idx_path_hash, index::Index};

#[test]
fn reads_python_writer_index_and_probe_chain() {
    let bytes = include_bytes!("fixtures/python_index.bin");
    let index = Index::open(bytes).expect("Python writer index must be accepted");
    let records_end = 48 + index.len() as usize * 24;
    let path_bytes = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
    let slots_at = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let slot_count = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
    let split = Index::open_parts(
        &bytes[..48],
        &bytes[48..records_end],
        &bytes[records_end..records_end + path_bytes],
        &bytes[slots_at..slots_at + slot_count * 16],
    )
    .expect("separate initialized sections must be accepted");
    assert_eq!(split.find(b"/app0/zeta05.bin").unwrap(), Some(2));
    assert_eq!(split.record(3).unwrap().path, b"/app0/\xc3\x84.bin");
    assert_eq!(index.len(), 3);
    let expected: [(&[u8], u64, i64); 3] = [
        (b"/app0/Data/Mixed.PAK", 123, -5),
        (b"/app0/zeta05.bin", 456, 999),
        (b"/app0/\xc3\x84.bin", 789, 0),
    ];
    for (id, &(path, size, mtime)) in expected.iter().enumerate() {
        let record = index.record(id as u32 + 1).unwrap();
        assert_eq!(
            (record.path, record.size, record.mtime),
            (path, size, mtime)
        );
        assert_eq!(index.find(path).unwrap(), Some(id as u32 + 1));
    }
    assert_eq!(
        idx_path_hash(expected[0].0) & 7,
        idx_path_hash(expected[1].0) & 7
    );
    assert_eq!(index.find(b"/APP0/data/mixed.pak").unwrap(), Some(1));
    assert_eq!(index.find(b"/app0/ZETA05.BIN").unwrap(), Some(2));
    assert_eq!(index.find(b"/app0/missing").unwrap(), None);
}
