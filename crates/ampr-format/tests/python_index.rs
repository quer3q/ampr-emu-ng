//! Fixture written by the upstream Python pack tools (drakmor/ampr_emu
//! tools/build_ampr_index.py and tools/ampr_pack_format.py).
use ampr_format::index::{Index, Layout};
use ampr_format::{idx_path_hash, source::PATH_BUF};

#[test]
fn reads_python_writer_index_and_probe_chain() {
    let bytes = include_bytes!("fixtures/python_index.bin");
    let bytes = &bytes[..];
    let index = Index::open(bytes).expect("Python writer index must be accepted");
    let layout = Layout::parse(&bytes[..48]).unwrap();
    let view = Index::view_validated(bytes, &layout).expect("a checked image must be viewable");
    assert_eq!(view.find(b"/app0/zeta05.bin").unwrap(), Some(2));
    let mut buf = [0u8; PATH_BUF];
    let third = view.record(3).unwrap();
    assert_eq!(view.path(&third, &mut buf).unwrap(), b"/app0/\xc3\x84.bin");
    assert!(index.records_sorted());
    assert_eq!(index.len(), 3);
    let expected: [(&[u8], u64, i64); 3] = [
        (b"/app0/Data/Mixed.PAK", 123, -5),
        (b"/app0/zeta05.bin", 456, 999),
        (b"/app0/\xc3\x84.bin", 789, 0),
    ];
    for (id, &(path, size, mtime)) in expected.iter().enumerate() {
        let record = index.record(id as u32 + 1).unwrap();
        assert_eq!(
            (
                index.path(&record, &mut buf).unwrap(),
                record.size,
                record.mtime
            ),
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
