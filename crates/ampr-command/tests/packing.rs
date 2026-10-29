use ampr_command::{
    decode_packed_op, op_type, AprMapState, Command, CommandBuffer, DecodeError, Error, Layout,
    OpRecord,
};

#[repr(align(4))]
struct Aligned<const N: usize>([u8; N]);

fn words(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
}

#[test]
fn apr_read_file_and_gather_match_reference_words() {
    let mut storage = Aligned([0xcc; 64]);
    let mut cb = CommandBuffer::new(&mut storage.0).unwrap();
    let read = Command::ReadFile {
        file_id: 0x8000_0055,
        address: 0x1234_5678_9abc,
        length: 0x1000,
        offset: 0x12345,
    };
    assert_eq!(read.measure(), Ok(20));
    cb.append(read).unwrap();
    assert_eq!(cb.header().offset, 20);
    assert_eq!(cb.header().num, 1);
    assert_eq!(cb.header().r#type, 0x10000);
    assert_eq!(
        words(cb.encoded()).collect::<Vec<_>>(),
        [0x1234_5428, 0xfff, 0x55, 0x5678_9abc, 0x1234]
    );

    let gather = Command::ReadGather {
        length: 1,
        offset: 0x40000,
    };
    assert_eq!(gather.measure(), Ok(12));
    cb.append(gather).unwrap();
    assert_eq!(cb.header().offset, 32);
    assert_eq!(cb.header().num, 2);
    assert_eq!(
        words(&cb.encoded()[20..]).collect::<Vec<_>>(),
        [0x229, 0, 1]
    );
}

#[test]
fn high_offset_and_capacity_boundaries() {
    let mut storage = Aligned([0xcc; 28]);
    let mut cb = CommandBuffer::new(&mut storage.0).unwrap();
    let read = Command::ReadFile {
        file_id: 1,
        address: 0,
        length: 1,
        offset: 0x1_0000_0000,
    };
    assert_eq!(read.measure(), Ok(24));
    cb.append(read).unwrap();
    assert_eq!(
        words(cb.encoded()).collect::<Vec<_>>(),
        [0x528, 0, 1, 0, 0, 1]
    );
    let before = *cb.header();
    assert_eq!(
        cb.append(Command::ReadGather {
            length: 1,
            offset: 0
        }),
        Err(Error::Full)
    );
    assert_eq!(cb.header().offset, before.offset);
    assert_eq!(cb.header().num, before.num);
    assert_eq!(cb.encoded().len(), 24);
    assert_eq!(storage.0[24..], [0xcc; 4]);
}

#[test]
fn validation_and_gather_state() {
    let mut storage = Aligned([0; 32]);
    let mut cb = CommandBuffer::new(&mut storage.0).unwrap();
    assert_eq!(
        cb.append(Command::ReadGather {
            length: 1,
            offset: 0
        }),
        Err(Error::NoGatherState)
    );
    assert_eq!(
        Command::ReadFile {
            file_id: 0,
            address: 0,
            length: 0,
            offset: 0
        }
        .measure(),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        Command::ReadFile {
            file_id: 0,
            address: 0xf000_0000_0000,
            length: 1,
            offset: 0
        }
        .measure(),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        Command::ReadGather {
            length: 1,
            offset: 0x100_0000_0000
        }
        .measure(),
        Err(Error::InvalidArgument)
    );
    assert_eq!(cb.header().offset, 0);
    assert_eq!(cb.header().num, 0);
}

#[test]
fn map_state_uses_header_bit_positions() {
    let state = AprMapState::new(true, 0x1f_ffff, 0x3_ffff_ffff).unwrap();
    assert_eq!(state.raw(), 0x00ff_ffff_ffff_ffff);
    let raw = |b, n, va| AprMapState::new(b, n, va).unwrap().raw();
    assert_eq!(raw(true, 0, 0), 1);
    assert_eq!(raw(false, 1, 0), 1 << 1);
    assert_eq!(raw(false, 0x1f_ffff, 0), 0x1f_ffff << 1);
    assert_eq!(raw(false, 0, 1), 1 << 22);
    assert_eq!(raw(false, 0, 0x3_ffff_ffff), 0x3_ffff_ffff << 22);
    assert!(AprMapState::new(false, 0x20_0000, 0).is_none());
    assert!(AprMapState::new(false, 0, 0x4_0000_0000).is_none());
}

/// Expected words are fixed reference encodings.
#[test]
fn op_record_encodings_match_reference_words() {
    let fixed = |op: OpRecord, expected: &[u32]| {
        let bytes = expected.len() as u32 * 4;
        assert_eq!(
            op.layout(),
            Ok(Layout {
                bytes,
                command_count: 1
            })
        );
        let (w, count) = op.encode_words().unwrap();
        assert_eq!(&w[..count], expected);
    };
    fixed(
        OpRecord {
            op_type: op_type::WAIT_ON_ADDRESS,
            ptra: 0x1234_5678_9ab8,
            u64a: 0x11_2233_4455,
            u32a: 3,
            u32c: 1,
            ..Default::default()
        },
        &[0x1234_7301, 0x5678_9ab8, 0x2233_4455, 0x11],
    );
    fixed(
        OpRecord {
            op_type: op_type::WRITE_COUNTER,
            u8a: 7,
            u64a: 0x1_2345_6789,
            u32b: 4,
            u32c: 1,
            ..Default::default()
        },
        &[0x0778_9276, 0x0412_3456, 1],
    );
    fixed(
        OpRecord {
            op_type: op_type::APR_MAP_DIRECT_BEGIN,
            u64a: 0x7fff_0000_4000,
            u64b: 0x1234_0000,
            u64c: 0x20_0000,
            u32a: 3,
            u32b: 0x33,
            ..Default::default()
        },
        &[0x1803_332d, 0xfffc_0001, 0x8000_0201, 0x48d0],
    );

    let marker = OpRecord {
        op_type: op_type::MARKER_SET,
        u32a: 0xff00_ff00,
        u32b: 1,
        text: 1,
        text_length: 5,
        ..Default::default()
    };
    assert_eq!(
        marker.layout(),
        Ok(Layout {
            bytes: 16,
            command_count: 1
        })
    );
    let mut out = [0xcc; 16];
    assert_eq!(marker.encode_marker(b"hello\0", &mut out), Ok(16));
    assert_eq!(
        words(&out).collect::<Vec<_>>(),
        [0x5452_530f, 0xff00_ff00, 0x6c6c_6568, 0x6f]
    );

    let amm = OpRecord {
        op_type: 12,
        ..Default::default()
    };
    assert_eq!(amm.layout(), Err(Error::InvalidArgument));

    let wait = [0x1234_7301u32, 0x5678_9ab8, 0x2233_4455, 0x11];
    let bytes: Vec<u8> = wait.iter().flat_map(|w| w.to_le_bytes()).collect();
    let (op, size) = decode_packed_op(&bytes, 0).unwrap();
    assert_eq!(size, 16);
    assert_eq!(
        (op.op_type, op.ptra, op.u64a, op.u32a, op.u32c),
        (
            op_type::WAIT_ON_ADDRESS,
            0x1234_5678_9ab8,
            0x11_2233_4455,
            3,
            1
        )
    );
    assert_eq!(
        decode_packed_op(&bytes[..12], 0),
        Err(DecodeError::InvalidAt)
    );
}
