//! Pure logic of pkg mode: a title whose launcher names its .pkg in
//! `/app0/kraken.image` reads pack 0 straight from that .pkg, with no AMPRDAT3
//! header. The runtime (`ampr-sys`) does the I/O; this crate holds the
//! checks and arithmetic so the host tests can cover them.
#![no_std]
// Safe code everywhere but the decoder, whose hot loops use unchecked copies.
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// KRAKEN chunk decoder (port of ps5upload-fpkg; to be replaced).
#[allow(unsafe_code)]
#[macro_use]
pub mod kraken;

mod discovery;
mod manifest;

pub use discovery::*;
pub use manifest::{open_pkg, pkg_chunk};

// ---- chunk codec and flags ----

/// Chunk codec of one Kraken block of a .pkg. Its location is offset
/// (bits 0..39) | even_len (40..58) | mode (59..63), pack 0 implied, so the
/// manifest keeps the block descriptor the decoder needs.
pub const CHUNK_KRAKEN: u8 = 2;
/// KRAKEN chunks only: the block's logical length is `KRAKEN_BLOCK`, longer
/// than the chunk's raw length; decode it whole and keep the first raw bytes.
/// Without it the logical length is the raw length.
pub const CHUNK_KRAKEN_FULL: u8 = 0x10;
/// The largest Kraken block (`kraken::BLOCK`).
pub const KRAKEN_BLOCK: u64 = kraken::BLOCK as u64;

/// Bits of a KRAKEN location that hold the .pkg byte offset.
const OFFSET_BITS: u32 = 40;
/// Bits of the descriptor that hold even_len; mode sits above them.
const EVEN_LEN_BITS: u32 = 19;

// ---- KRAKEN location ----

/// Splits a KRAKEN chunk location into the .pkg byte offset and the packed
/// descriptor `even_len | mode << 19`.
pub fn split_kraken_location(loc: u64) -> (u64, u32) {
    (
        loc & ((1u64 << OFFSET_BITS) - 1),
        (loc >> OFFSET_BITS) as u32,
    )
}

/// Unpacks `even_len | mode << 19` into (even_len, mode).
pub fn kraken_desc(kraken: u32) -> (u32, u8) {
    (
        kraken & ((1 << EVEN_LEN_BITS) - 1),
        ((kraken >> EVEN_LEN_BITS) & 0x1f) as u8,
    )
}

/// A KRAKEN chunk decodes to at most one block, and its even half lies
/// inside the stored bytes; anything else would make the decoder read or
/// write past its buffers.
pub fn kraken_chunk_ok(raw: u64, stored: u64, kraken: u32) -> bool {
    let (even_len, _) = kraken_desc(kraken);
    stored >= 1 && raw <= KRAKEN_BLOCK && u64::from(even_len) <= stored
}

/// Bytes a KRAKEN chunk decodes to before truncation to `raw`: a
/// `CHUNK_KRAKEN_FULL` block must be decoded whole.
pub fn kraken_decode_len(raw: usize, full: bool) -> usize {
    if full {
        KRAKEN_BLOCK as usize
    } else {
        raw
    }
}

// ---- pkg volume ----

/// Payload end of the .pkg as pack 0. The manifest records the .pkg size
/// aligned up to the I/O page, so a .pkg other than the one the manifest
/// was built from is refused. The page must be a power of two, as in an
/// AMPRDAT3 pack record. The runtime ends the payload at the real .pkg
/// size: chunks are read with exact-size reads that never pass it.
pub fn pkg_payload_end(file_size: u64, io_page_size: u32, record_file_size: u64) -> Option<u64> {
    if file_size == 0 || !io_page_size.is_power_of_two() {
        return None;
    }
    let mask = u64::from(io_page_size) - 1;
    let aligned = file_size.checked_add(mask)? & !mask;
    (aligned == record_file_size).then_some(aligned)
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kraken_location_splits_offset_and_desc() {
        let loc = 0x12_3456_789a | (0x4_0001u64 << 40) | (0x1fu64 << 59);
        let (offset, kraken) = split_kraken_location(loc);
        assert_eq!(offset, 0x12_3456_789a);
        assert_eq!(kraken, 0x4_0001 | 0x1f << 19);
        assert_eq!(kraken_desc(kraken), (0x4_0001, 0x1f));
        assert_eq!(split_kraken_location(u64::MAX), ((1 << 40) - 1, 0xff_ffff));
        assert_eq!(kraken_desc(0xff_ffff), (0x7_ffff, 0x1f));
        assert_eq!(kraken_desc(3 << 19 | 5), (5, 3));
    }

    #[test]
    fn kraken_chunk_limits() {
        assert!(kraken_chunk_ok(KRAKEN_BLOCK, 100, 100));
        assert!(kraken_chunk_ok(1, 1, 0));
        assert!(kraken_chunk_ok(10, 100, 100 | 7 << 19));
        assert!(!kraken_chunk_ok(KRAKEN_BLOCK + 1, 100, 0));
        assert!(!kraken_chunk_ok(10, 100, 101));
        assert!(!kraken_chunk_ok(10, 0, 0));
    }

    #[test]
    fn kraken_decode_len_full_block() {
        assert_eq!(kraken_decode_len(100, false), 100);
        assert_eq!(kraken_decode_len(100, true), KRAKEN_BLOCK as usize);
    }

    #[test]
    fn payload_end_matches_record() {
        assert_eq!(pkg_payload_end(0x10001, 0x10000, 0x20000), Some(0x20000));
        assert_eq!(pkg_payload_end(0x20000, 0x10000, 0x20000), Some(0x20000));
        assert_eq!(pkg_payload_end(0x20001, 0x10000, 0x20000), None);
        assert_eq!(pkg_payload_end(0x10000, 0x10000, 0x20000), None);
        assert_eq!(pkg_payload_end(0, 0x10000, 0), None);
        assert_eq!(pkg_payload_end(100, 0, 100), None);
        assert_eq!(pkg_payload_end(100, 3000, 3000), None);
        assert_eq!(pkg_payload_end(u64::MAX, 0x1000, 0), None);
        let top: u64 = !0xfff;
        assert_eq!(pkg_payload_end(top, 0x1000, top), Some(top));
    }
}
