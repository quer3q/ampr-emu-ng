//! Shared byte helpers, index readers and overlay utilities.
#![no_std]
#![forbid(unsafe_code)]

pub mod cache;
pub mod handles;
pub mod index;
pub mod index_key;
pub mod overlay;
pub mod zstd;

pub const IDX_MAGIC: &[u8; 8] = b"AMPRIDX3";
pub const IDX_HEADER: usize = 48;
pub const IDX_RECORD: usize = 24;
pub const IDX_SLOT: usize = 16;
pub const ENDIAN_MARKER: u32 = 0x0102_0304;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Invalid,
    Checksum,
    OutOfRange,
}

pub type Result<T> = core::result::Result<T, Error>;

/// `AmprPackCoreResult` error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CoreError {
    InvalidArgument = -1,
    InvalidFormat = -2,
    ChecksumMismatch = -3,
    OutOfRange = -4,
    Unsupported = -5,
}

impl CoreError {
    pub fn code(self) -> i32 {
        self as i32
    }
}

impl From<Error> for CoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::Truncated | Error::Invalid => Self::InvalidFormat,
            Error::Checksum => Self::ChecksumMismatch,
            Error::OutOfRange => Self::OutOfRange,
        }
    }
}

pub type CoreResult<T> = core::result::Result<T, CoreError>;

pub fn range(bytes: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    bytes
        .get(at..at.checked_add(len).ok_or(Error::Invalid)?)
        .ok_or(Error::Truncated)
}

pub fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(bytes, at, 2)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

pub fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, at, 4)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

pub fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        range(bytes, at, 8)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

pub fn i64_at(bytes: &[u8], at: usize) -> Result<i64> {
    Ok(i64::from_le_bytes(
        range(bytes, at, 8)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

pub fn section(bytes: &[u8], at: u64, len: u64) -> Result<&[u8]> {
    let at = usize::try_from(at).map_err(|_| Error::Invalid)?;
    let len = usize::try_from(len).map_err(|_| Error::Invalid)?;
    range(bytes, at, len)
}

pub fn folded(byte: u8) -> u8 {
    match byte {
        b'\\' => b'/',
        b'A'..=b'Z' => byte + 32,
        _ => byte,
    }
}

fn hash(path: &[u8], basis: u64) -> u64 {
    let mut value = basis;
    for &byte in path {
        value = (value ^ u64::from(folded(byte))).wrapping_mul(1_099_511_628_211);
    }
    if value == 0 {
        1
    } else {
        value
    }
}

pub fn pak_path_hash(path: &[u8]) -> u64 {
    hash(path, 14_695_981_039_346_656_037)
}
pub fn idx_path_hash(path: &[u8]) -> u64 {
    hash(path, 1_469_598_103_934_665_603)
}

pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_seeded(bytes, 0)
}

/// Seeded CRC-32: `crc32_seeded(b, crc32(a)) == crc32(a ++ b)`.
pub fn crc32_seeded(bytes: &[u8], seed: u32) -> u32 {
    !crc32_update(!seed, bytes)
}

const CRC_TABLE: [u32; 256] = make_crc_table();

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < table.len() {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(value & 1)));
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}

fn crc32_update(mut value: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        value = CRC_TABLE[((value ^ u32::from(byte)) & 0xff) as usize] ^ (value >> 8);
    }
    value
}

pub fn crc32_parts(parts: &[&[u8]]) -> u32 {
    !parts
        .iter()
        .fold(!0u32, |value, part| crc32_update(value, part))
}

pub fn header_crc(bytes: &[u8], len: usize, zero_at: usize) -> Result<u32> {
    let h = range(bytes, 0, len)?;
    Ok(crc32_parts(&[&h[..zero_at], &[0; 4], &h[zero_at + 4..]]))
}

/// `strings[off..off + len]` followed by a NUL; the content is not scanned.
pub fn terminated_slice(strings: &[u8], off: u32, len: u32) -> Result<&[u8]> {
    let off = off as usize;
    let end = off.checked_add(len as usize).ok_or(Error::Invalid)?;
    if strings.get(end) != Some(&0) {
        return Err(Error::Invalid);
    }
    strings.get(off..end).ok_or(Error::Invalid)
}

pub fn terminated_string(strings: &[u8], off: u32, len: u32) -> Result<&[u8]> {
    let s = terminated_slice(strings, off, len)?;
    if s.contains(&0) {
        return Err(Error::Invalid);
    }
    Ok(s)
}

pub fn logical_path(path: &[u8]) -> bool {
    path.len() > 6
        && path[0] == b'/'
        && path[5] == b'/'
        && path[1..5]
            .iter()
            .copied()
            .map(folded)
            .eq(b"app0".iter().copied())
        && safe_components(&path[6..])
}

pub fn safe_components(path: &[u8]) -> bool {
    !path.is_empty()
        && path.split(|&b| b == b'/').all(|c| {
            !c.is_empty() && c != b"." && c != b".." && !c.iter().any(|&b| b == 0 || b == b'\\')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn borrowed_index_checks_record_and_hash_slot() {
        let path = b"/app0/One.bin";
        let slots_at = 96;
        let mut b = [0u8; 128];
        b[..8].copy_from_slice(IDX_MAGIC);
        put32(&mut b, 8, 3);
        put32(&mut b, 12, IDX_RECORD as u32);
        put64(&mut b, 16, 1);
        put64(&mut b, 24, (path.len() + 1) as u64);
        put64(&mut b, 32, slots_at as u64);
        put32(&mut b, 40, IDX_SLOT as u32);
        put32(&mut b, 44, 2);
        put32(&mut b, 52, path.len() as u32);
        put64(&mut b, 56, 42);
        b[72..72 + path.len()].copy_from_slice(path);
        let slot = slots_at + (idx_path_hash(path) as usize & 1) * IDX_SLOT;
        put64(&mut b, slot, idx_path_hash(path));
        put32(&mut b, slot + 8, 1);
        let index = index::Index::open(&b).unwrap();
        assert_eq!(index.record(1).unwrap().size, 42);
        assert_eq!(index.find(b"/APP0/one.BIN").unwrap(), Some(1));
        b[slot] ^= 1;
        assert!(index::Index::open(&b).is_err());
    }
}
