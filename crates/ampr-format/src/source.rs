//! Read-at-offset access to an index file, so the readers work the same
//! over a resident image (`[u8]`) and over the runtime's index page cache
//! (ampr-sys rt/index_pages.rs), which keeps only part of a large index
//! in memory and reads the rest from the file on a miss.
use crate::{Error, Result};

/// Longest path a reader copies out (SCE_KERNEL_PATH_MAX). Paths are read
/// into a caller buffer of this size, not borrowed from the image.
pub const PATH_BUF: usize = crate::index_key::PATH_MAX;

pub trait Source {
    /// File length in bytes.
    fn len(&self) -> u64;
    /// Copies `[at, at + out.len())` into `out`. `Truncated` past the end,
    /// `Io` when the backing file cannot be read.
    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()>;
}

impl Source for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let at = usize::try_from(at).map_err(|_| Error::Truncated)?;
        let end = at.checked_add(out.len()).ok_or(Error::Truncated)?;
        out.copy_from_slice(self.get(at..end).ok_or(Error::Truncated)?);
        Ok(())
    }
}

pub fn src_u16(s: &(impl Source + ?Sized), at: u64) -> Result<u16> {
    let mut b = [0; 2];
    s.read_at(at, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

pub fn src_u32(s: &(impl Source + ?Sized), at: u64) -> Result<u32> {
    let mut b = [0; 4];
    s.read_at(at, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

pub fn src_u64(s: &(impl Source + ?Sized), at: u64) -> Result<u64> {
    let mut b = [0; 8];
    s.read_at(at, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

pub fn src_i64(s: &(impl Source + ?Sized), at: u64) -> Result<i64> {
    Ok(src_u64(s, at)? as i64)
}

/// `len` bytes at `at` copied into `buf`; `Invalid` when longer than `buf`.
pub fn src_bytes<'b>(
    s: &(impl Source + ?Sized),
    at: u64,
    len: usize,
    buf: &'b mut [u8],
) -> Result<&'b [u8]> {
    let out = buf.get_mut(..len).ok_or(Error::Invalid)?;
    s.read_at(at, out)?;
    Ok(out)
}

/// CRC-32 of `[from, to)`, streamed in 4 KiB steps (no_std threads have
/// small stacks), seeded like `crc32_seeded`.
pub fn src_crc32(s: &(impl Source + ?Sized), from: u64, to: u64, seed: u32) -> Result<u32> {
    let mut buf = [0u8; 4096];
    let (mut at, mut crc) = (from, seed);
    while at < to {
        let n = (to - at).min(buf.len() as u64) as usize;
        s.read_at(at, &mut buf[..n])?;
        crc = crate::crc32_seeded(&buf[..n], crc);
        at += n as u64;
    }
    Ok(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_source_reads_and_bounds() {
        let b: &[u8] = &[1, 0, 2, 0, 0, 0, 9];
        assert_eq!(src_u16(b, 0), Ok(1));
        assert_eq!(src_u32(b, 2), Ok(2));
        assert_eq!(src_u32(b, 4), Err(Error::Truncated));
        let mut buf = [0u8; 2];
        assert_eq!(src_bytes(b, 5, 3, &mut buf), Err(Error::Invalid));
        assert_eq!(src_crc32(b, 0, 7, 0), Ok(crate::crc32_seeded(b, 0)));
    }
}
