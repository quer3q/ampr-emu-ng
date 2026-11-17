//! Shared byte helpers, index readers and overlay utilities.
#![no_std]
#![forbid(unsafe_code)]

pub mod cache;
pub mod handles;
pub mod index;
pub mod index_key;
pub mod overlay;
pub mod run;
pub mod source;
pub mod view;
pub mod view_join;
pub mod view_list;
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
    /// The backing file of a paged index could not be read.
    Io,
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
    /// The backing file of a paged index could not be read: not a miss.
    Io = -6,
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
            Error::Io => Self::Io,
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

/// FNV-1a of the folded path. AMPRPAK4 records and AMPRIDX3 slots store
/// it (one basis each), so it stays byte-serial and fixed.
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

// ---- view hash ----

/// Hash of a folded key for the compiled index view's columns and slots.
/// Unlike `idx_path_hash`, which AMPRIDX3 stores in its slots, this one is
/// never written to or read from a file (the view computes it at build,
/// at the pack join and per lookup), so it can change between builds. It
/// takes 8 bytes per step with the fold done on the word (`fold_word`),
/// where `idx_path_hash` does one multiply and one fold per byte (about
/// 50 per 48-byte path, 6 here). 0 is never returned.
pub fn view_hash(path: &[u8]) -> u64 {
    let mut h = ViewHasher::new();
    h.write(path);
    h.finish()
}

/// `view_hash` of the parts joined, without a buffer to join them in.
pub fn view_hash_parts(parts: &[&[u8]]) -> u64 {
    let mut h = ViewHasher::new();
    for part in parts {
        h.write(part);
    }
    h.finish()
}

const VIEW_MUL: u64 = 0x9e37_79b9_7f4a_7c15;
const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// `folded` of each byte of `w`: `A..=Z` get bit 5 set, `\` becomes `/`.
/// No per-byte sum carries into the next byte (the largest is 0xfe).
fn fold_word(w: u64) -> u64 {
    let low = w & !HI;
    // High bit set where the low 7 bits are >= 'A', and where > 'Z'.
    let ge_a = low + LO * u64::from(0x80 - b'A');
    let gt_z = low + LO * u64::from(0x80 - b'Z' - 1);
    let upper = ge_a & !gt_z & !w & HI;
    // High bit set exactly where the byte is a backslash.
    let t = w ^ (LO * u64::from(b'\\'));
    let slash = !(((t & !HI) + !HI) | t) & HI;
    w ^ (upper >> 2) ^ ((slash >> 7) * u64::from(b'\\' ^ b'/'))
}

/// Streaming state: full words are mixed as they come, the last partial
/// word is zero-padded, and the length goes into the final mix.
struct ViewHasher {
    h: u64,
    pend: u64,
    pend_len: u32,
    len: u64,
}

impl ViewHasher {
    fn new() -> Self {
        Self {
            h: 0x243f_6a88_85a3_08d3,
            pend: 0,
            pend_len: 0,
            len: 0,
        }
    }

    fn mix(&mut self, w: u64) {
        self.h = (self.h.rotate_left(23) ^ fold_word(w)).wrapping_mul(VIEW_MUL);
    }

    fn write(&mut self, mut bytes: &[u8]) {
        self.len += bytes.len() as u64;
        while self.pend_len != 0 && !bytes.is_empty() {
            self.pend |= u64::from(bytes[0]) << (8 * self.pend_len);
            self.pend_len = (self.pend_len + 1) % 8;
            bytes = &bytes[1..];
            if self.pend_len == 0 {
                let w = core::mem::take(&mut self.pend);
                self.mix(w);
            }
        }
        if bytes.is_empty() {
            return;
        }
        // Here `pend` is empty and word-aligned to the hashed stream.
        let (words, rest) = bytes.as_chunks::<8>();
        for &w in words {
            self.mix(u64::from_le_bytes(w));
        }
        for (i, &b) in rest.iter().enumerate() {
            self.pend |= u64::from(b) << (8 * i);
        }
        self.pend_len = rest.len() as u32;
    }

    fn finish(mut self) -> u64 {
        if self.pend_len != 0 {
            let w = self.pend;
            self.mix(w);
        }
        // murmur3 fmix64: the slots index by the low bits.
        let mut v = self.h ^ self.len;
        v ^= v >> 33;
        v = v.wrapping_mul(0xff51_afd7_ed55_8ccd);
        v ^= v >> 33;
        v = v.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        v ^= v >> 33;
        v.max(1)
    }
}

// ---- crc ----

pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_seeded(bytes, 0)
}

/// Seeded CRC-32: `crc32_seeded(b, crc32(a)) == crc32(a ++ b)`.
pub fn crc32_seeded(bytes: &[u8], seed: u32) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(seed);
    h.update(bytes);
    h.finalize()
}

/// CRC-32 of the parts joined. crc32fast replaced a byte-at-a-time table
/// here (one load and table lookup per byte; inferred tens of ms on a
/// 20 MiB zstd index at mount, not measured on a console).
pub fn crc32_parts(parts: &[&[u8]]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

pub fn header_crc(bytes: &[u8], len: usize, zero_at: usize) -> Result<u32> {
    let h = range(bytes, 0, len)?;
    let zero_end = zero_at.checked_add(4).ok_or(Error::Invalid)?;
    if zero_end > len {
        return Err(Error::Invalid);
    }
    Ok(crc32_parts(&[&h[..zero_at], &[0; 4], &h[zero_end..]]))
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
    fn fold_word_folds_every_byte_in_every_lane() {
        for lane in 0..8 {
            for b in 0..=255u8 {
                let w = 0x4142_5c2f_7a5b_405a ^ (u64::from(b ^ 0x41) << (8 * lane));
                let want = u64::from_le_bytes(w.to_le_bytes().map(folded));
                assert_eq!(fold_word(w), want, "byte {b:#x} lane {lane}");
            }
        }
    }

    #[test]
    fn view_hash_folds_and_joins_parts() {
        let path = b"/APP0/Data\\Sub/A_Long_File_Name.BIN";
        let lower = b"/app0/data/sub/a_long_file_name.bin";
        assert_eq!(view_hash(path), view_hash(lower));
        for cut in 0..=path.len() {
            for cut2 in cut..=path.len() {
                let parts: [&[u8]; 4] = [&path[..cut], b"", &path[cut..cut2], &path[cut2..]];
                assert_eq!(view_hash_parts(&parts), view_hash(path), "{cut} {cut2}");
            }
        }
        assert_eq!(view_hash_parts(&[]), view_hash(b""));
        assert_ne!(view_hash(b"a"), view_hash(b"a\0"));
        assert_ne!(view_hash(b"/app0/a"), view_hash(b"/app0/b"));
        assert_ne!(view_hash(b""), 0);
    }

    #[test]
    fn view_hash_spreads_low_bits() {
        // 4096 sibling paths over 8192 slots: the low 13 bits should
        // leave few keys sharing a home slot (a random hash: about 1/5).
        let mut seen = [0u8; 8192];
        let mut buf = [0u8; 32];
        for i in 0..4096u32 {
            let s = b"/app0/dir/file_";
            buf[..s.len()].copy_from_slice(s);
            let mut n = s.len();
            for d in [i / 1000, i / 100 % 10, i / 10 % 10, i % 10] {
                buf[n] = b'0' + d as u8;
                n += 1;
            }
            let slot = view_hash(&buf[..n]) as usize & 8191;
            seen[slot] = seen[slot].saturating_add(1);
        }
        let shared: usize = seen.iter().map(|&c| usize::from(c.saturating_sub(1))).sum();
        assert!(shared < 1200, "{shared}");
    }

    #[test]
    fn crc32_matches_the_reference_and_seeds() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
        let a = b"first part ";
        let b = b"and the second";
        let mut joined = [0u8; 25];
        joined[..11].copy_from_slice(a);
        joined[11..].copy_from_slice(b);
        assert_eq!(crc32_seeded(b, crc32(a)), crc32(&joined));
        assert_eq!(crc32_parts(&[a, b"", b]), crc32(&joined));
    }

    #[test]
    fn borrowed_index_checks_record_and_hash_slot() {
        assert_eq!(header_crc(&[0; 8], 8, 5), Err(Error::Invalid));
        assert_eq!(header_crc(&[0; 8], 8, usize::MAX), Err(Error::Invalid));
        let mut slots = [0u8; IDX_SLOT * 2];
        let mut record = [0u8; IDX_RECORD];
        put32(&mut record, 0, u32::MAX);
        put32(&mut record, 4, u32::MAX);
        assert_eq!(
            index::fill_slots(&record, b"/app0/x\0", &mut slots),
            Err(Error::Invalid)
        );
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
        let index = index::Index::open(&b[..]).unwrap();
        assert_eq!(index.record(1).unwrap().size, 42);
        assert_eq!(index.find(b"/APP0/one.BIN").unwrap(), Some(1));
        b[slot] ^= 1;
        assert!(index::Index::open(&b[..]).is_err());
    }
}
