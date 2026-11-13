//! pkg mode validation: `Manifest::open` stays strict, `open_pkg` loosens
//! the chunk rules for pack 0 (the .pkg) only.
use ampr_lz4::manifest::Manifest;
use ampr_lz4::{
    crc32, pak_path_hash, Error, CHUNK_PAGE_ALIGNED, CHUNK_RAW, FILE_PACKED, FILE_STORE_ONLY,
    PACK_IO_PAGE_LAYOUT,
};
use ampr_pkg::{open_pkg, pkg_chunk, CHUNK_KRAKEN};

// ---- manifest builder ----

const PAGE: u32 = 4096;
/// Pack file size; the payload starts one page in, after the header page.
const PACK_SIZE: u64 = 65536;

fn desc(stored: u32, codec: u8) -> u32 {
    (stored - 1) | u32::from(codec) << 20
}

fn loc(offset: u64, pack_id: u16) -> u64 {
    offset | u64::from(pack_id) << 48
}

/// KRAKEN location: offset | even_len << 40 | mode << 59, pack 0 implied.
fn kraken_loc(offset: u64, even_len: u64, mode: u64) -> u64 {
    offset | even_len << 40 | mode << 59
}

/// AMPRPAK4 manifest with one packed file `/app0/f.bin` of `size` bytes in
/// 16 KiB blocks over `chunks`, and two packs `p0.pak`, `p1.pak`.
fn build(size: u64, flags: u32, chunks: &[(u64, u32)]) -> Vec<u8> {
    let path: &[u8] = b"/app0/f.bin";
    let mut strings = path.to_vec();
    strings.push(0);
    let mut rec = Vec::new();
    rec.extend_from_slice(&pak_path_hash(path).to_le_bytes());
    rec.extend_from_slice(&size.to_le_bytes());
    rec.extend_from_slice(&7i64.to_le_bytes());
    for v in [0, chunks.len() as u32, 0, path.len() as u32, flags] {
        rec.extend_from_slice(&v.to_le_bytes());
    }
    rec.extend_from_slice(&[14, 0, 0, 0]);
    let mut names = Vec::new();
    for name in [&b"p0.pak"[..], b"p1.pak"] {
        names.push(strings.len() as u32);
        strings.extend_from_slice(name);
        strings.push(0);
    }
    let mut b = vec![0u8; 128];
    b[..8].copy_from_slice(b"AMPRPAK4");
    let chunks_at = 128 + rec.len() as u64;
    let packs_at = chunks_at + chunks.len() as u64 * 12;
    let strings_at = packs_at + 2 * 32;
    for (at, v) in [
        (8, 4u32),
        (12, 128),
        (20, 0x0102_0304),
        (56, 2),
        (60, 48),
        (64, 12),
        (68, 32),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    for (at, v) in [
        (40, 1u64),
        (48, chunks.len() as u64),
        (72, 128),
        (80, chunks_at),
        (88, packs_at),
        (96, strings_at),
        (104, strings.len() as u64),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&rec);
    for &(l, d) in chunks {
        b.extend_from_slice(&l.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
    }
    for name_at in names {
        b.extend_from_slice(&(PACK_SIZE - u64::from(PAGE)).to_le_bytes());
        b.extend_from_slice(&PACK_SIZE.to_le_bytes());
        for v in [name_at, 6, PACK_IO_PAGE_LAYOUT, PAGE] {
            b.extend_from_slice(&v.to_le_bytes());
        }
    }
    b.extend_from_slice(&strings);
    let payload_crc = crc32(&b[128..]);
    b[112..116].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32(&b[..128]);
    b[116..120].copy_from_slice(&header_crc.to_le_bytes());
    b
}

/// One KRAKEN chunk of 500 stored bytes at an unaligned offset, even half
/// `even_len`, decoding to a 1000-byte file.
fn kraken_file(even_len: u64) -> Vec<u8> {
    let at = u64::from(PAGE) + 4;
    build(
        1000,
        FILE_PACKED,
        &[(kraken_loc(at, even_len, 3), desc(500, CHUNK_KRAKEN))],
    )
}

/// One 16 KiB RAW chunk on `pack_id` at an offset 4 bytes past a page, with
/// no page-layout flags.
fn unaligned_raw(pack_id: u16) -> Vec<u8> {
    let at = u64::from(PAGE) + 4;
    build(
        16384,
        FILE_PACKED | FILE_STORE_ONLY,
        &[(loc(at, pack_id), desc(16384, CHUNK_RAW))],
    )
}

// ---- cases ----

/// Control: the same file with a page-aligned RAW chunk passes strict
/// `open` on either pack, so the rejections below come from the chunk rules.
#[test]
fn strict_open_accepts_aligned_raw_chunk() {
    for pack in [0, 1] {
        let d = desc(16384, CHUNK_RAW) | u32::from(CHUNK_PAGE_ALIGNED) << 22;
        let b = build(
            16384,
            FILE_PACKED | FILE_STORE_ONLY,
            &[(loc(u64::from(PAGE), pack), d)],
        );
        assert!(Manifest::open(b.as_slice()).is_ok(), "pack {pack}");
        assert!(open_pkg(&b[..]).is_ok(), "pack {pack}");
    }
}

#[test]
fn strict_open_rejects_kraken_chunk() {
    assert_eq!(
        Manifest::open(kraken_file(300).as_slice()).err(),
        Some(Error::Invalid)
    );
}

#[test]
fn open_pkg_accepts_kraken_chunk_on_pack_0() {
    let b = kraken_file(300);
    let m = open_pkg(&b[..]).expect("pkg mode takes a KRAKEN chunk");
    let c = m.chunk_record(0).unwrap();
    let (offset, pack_id, kraken) = pkg_chunk(c);
    assert_eq!((c.codec, pack_id, offset), (CHUNK_KRAKEN, 0, 4100));
    assert_eq!((kraken & 0x7_ffff, kraken >> 19), (300, 3));
}

#[test]
fn open_pkg_rejects_kraken_even_half_past_stored() {
    let b = kraken_file(501);
    assert_eq!(open_pkg(&b[..]).err(), Some(Error::Invalid));
}

#[test]
fn strict_open_rejects_unaligned_raw_chunk() {
    for pack in [0, 1] {
        let b = unaligned_raw(pack);
        assert_eq!(
            Manifest::open(b.as_slice()).err(),
            Some(Error::Invalid),
            "pack {pack}"
        );
    }
}

#[test]
fn open_pkg_accepts_unaligned_raw_on_pack_0_only() {
    assert!(open_pkg(&unaligned_raw(0)[..]).is_ok());
    let b = unaligned_raw(1);
    assert_eq!(open_pkg(&b[..]).err(), Some(Error::Invalid));
}

/// `open_pkg` keeps upstream's header checks: a flipped payload byte fails
/// the CRC, a wrong version fails the fields, as with strict `open`.
#[test]
fn open_pkg_keeps_header_checks() {
    let mut b = kraken_file(300);
    let last = b.len() - 1;
    b[last] ^= 1;
    assert_eq!(open_pkg(&b[..]).err(), Some(Error::Checksum));
    let mut b = kraken_file(300);
    b[8] = 5;
    assert_eq!(open_pkg(&b[..]).err(), Some(Error::Invalid));
    assert_eq!(open_pkg(&b[..100]).err(), Some(Error::Invalid));
}

/// A source read in small pieces, like the runtime's index page cache: no
/// reader may borrow the image, and every read must stay in bounds.
struct Paged(Vec<u8>);

impl ampr_format::source::Source for Paged {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_lz4::Result<()> {
        assert!(out.len() <= 4096, "reads stay page-sized");
        self.0[..].read_at(at, out)
    }
}

/// A paged manifest opens and is checked like a resident one.
#[test]
fn open_pkg_reads_a_paged_source() {
    let src = Paged(kraken_file(300));
    let m = open_pkg(&src).expect("paged pkg manifest opens");
    assert_eq!(pkg_chunk(m.chunk_record(0).unwrap()).0, 4100);
    let mut b = kraken_file(300);
    let last = b.len() - 1;
    b[last] ^= 1;
    assert_eq!(open_pkg(&Paged(b)).err(), Some(Error::Checksum));
    assert_eq!(
        open_pkg(&Paged(kraken_file(501))).err(),
        Some(Error::Invalid)
    );
}
