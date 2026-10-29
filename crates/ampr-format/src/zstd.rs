//! Borrowed readers for zstd pack indexes (AMPRZPK1 v1) and volumes (AMPRZDT1 v1).
//! The convention (magics, layout, names, chunk records, the volume header) comes
//! from the `ampr-zstd` crate, used in `no_std`; the index reader here stays
//! borrowed and zero-copy (runtime memory).
use crate::{crc32, crc32_parts, range, u16_at, u32_at, u64_at, Error, Result};
use core::cmp::Ordering;
use ampr_zstd as format;

pub use format::{
    path_hash_bytes as path_hash, VolumeHeader, CHUNK_RECORD_SIZE, CHUNK_SHIFT, CHUNK_SIZE,
    FILE_RECORD_SIZE, FORMAT_VERSION, INDEX_HEADER_CRC_AT, INDEX_HEADER_SIZE, INDEX_MAGIC,
    INDEX_NAME, INDEX_PAYLOAD_CRC_AT, MAX_VOLUMES, VOLUME_HEADER_SIZE, VOLUME_LIMIT, VOLUME_MAGIC,
    VOLUME_PREFIX, VOLUME_RECORD_SIZE, VOLUME_SUFFIX, ZSTD_LEVELS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRecord<'a> {
    pub path: &'a [u8],
    pub path_hash: u64,
    pub logical_size: u64,
    pub first_chunk: u32,
    pub chunk_count: u32,
    pub store_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkRecord {
    pub offset: u32,
    pub volume_id: u16,
    pub stored_size: u32,
    pub codec: u8,
}

pub struct Index<'a> {
    files: &'a [u8],
    chunks: &'a [u8],
    volumes: &'a [u8],
    strings: &'a [u8],
    archive_id: [u8; 16],
    total_logical_bytes: u64,
}

impl<'a> Index<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        let h = range(bytes, 0, INDEX_HEADER_SIZE)?;
        if &h[..8] != INDEX_MAGIC
            || u32_at(h, 8)? != FORMAT_VERSION
            || u32_at(h, 12)? != INDEX_HEADER_SIZE as u32
            || h[16] != CHUNK_SHIFT
            || !ZSTD_LEVELS.contains(&h[17])
            || u16_at(h, 18)? != 0
            || u64_at(h, 104)? != 0
            || u64_at(h, 120)? != 0
        {
            return Err(Error::Invalid);
        }
        let crc_end = INDEX_HEADER_CRC_AT + 4;
        if crc32_parts(&[&h[..INDEX_PAYLOAD_CRC_AT], &[0; 8], &h[crc_end..]])
            != u32_at(h, INDEX_HEADER_CRC_AT)?
            || crc32(&bytes[INDEX_HEADER_SIZE..]) != u32_at(h, INDEX_PAYLOAD_CRC_AT)?
        {
            return Err(Error::Checksum);
        }
        let volume_count = u32_at(h, 20)?;
        let file_count = u64_at(h, 40)?;
        let chunk_count = u64_at(h, 48)?;
        if volume_count as usize > MAX_VOLUMES || chunk_count > u32::MAX as u64 {
            return Err(Error::Invalid);
        }
        let files_off = u64_at(h, 56)?;
        let chunks_off = u64_at(h, 64)?;
        let volumes_off = u64_at(h, 72)?;
        let strings_off = u64_at(h, 80)?;
        let strings_len = u64_at(h, 88)?;
        if files_off != INDEX_HEADER_SIZE as u64
            || files_off.checked_add(
                file_count
                    .checked_mul(FILE_RECORD_SIZE as u64)
                    .ok_or(Error::Invalid)?,
            ) != Some(chunks_off)
            || chunks_off.checked_add(chunk_count * CHUNK_RECORD_SIZE as u64) != Some(volumes_off)
            || volumes_off.checked_add(u64::from(volume_count) * VOLUME_RECORD_SIZE as u64)
                != Some(strings_off)
            || strings_off.checked_add(strings_len) != Some(bytes.len() as u64)
            || strings_len > u32::MAX as u64
            || (chunk_count == 0) != (volume_count == 0)
        {
            return Err(Error::Invalid);
        }
        let start = |n: u64| usize::try_from(n).map_err(|_| Error::Invalid);
        let files = &bytes[start(files_off)?..start(chunks_off)?];
        let chunks = &bytes[start(chunks_off)?..start(volumes_off)?];
        let volumes = &bytes[start(volumes_off)?..start(strings_off)?];
        let strings = &bytes[start(strings_off)?..];
        let mut archive_id = [0; 16];
        archive_id.copy_from_slice(&h[24..40]);
        let index = Self {
            files,
            chunks,
            volumes,
            strings,
            archive_id,
            total_logical_bytes: u64_at(h, 96)?,
        };
        index.validate()?;
        Ok(index)
    }

    pub fn archive_id(&self) -> &[u8; 16] {
        &self.archive_id
    }
    pub fn file_count(&self) -> u64 {
        (self.files.len() / FILE_RECORD_SIZE) as u64
    }
    pub fn chunk_count(&self) -> u32 {
        (self.chunks.len() / CHUNK_RECORD_SIZE) as u32
    }
    pub fn volume_count(&self) -> u32 {
        (self.volumes.len() / VOLUME_RECORD_SIZE) as u32
    }

    pub fn file(&self, id: u64) -> Result<FileRecord<'a>> {
        let at = usize::try_from(id)
            .ok()
            .and_then(|n| n.checked_mul(FILE_RECORD_SIZE))
            .ok_or(Error::OutOfRange)?;
        let end = at.checked_add(FILE_RECORD_SIZE).ok_or(Error::OutOfRange)?;
        let r = self.files.get(at..end).ok_or(Error::OutOfRange)?;
        let path_off = u32_at(r, 20)? as usize;
        let path_len = u16_at(r, 24)? as usize;
        let path = self
            .strings
            .get(path_off..path_off.checked_add(path_len).ok_or(Error::Invalid)?)
            .ok_or(Error::Invalid)?;
        let size = u64_at(r, 8)?;
        let chunk_count = size / CHUNK_SIZE + u64::from(size % CHUNK_SIZE != 0);
        Ok(FileRecord {
            path,
            path_hash: u64_at(r, 0)?,
            logical_size: size,
            first_chunk: u32_at(r, 16)?,
            chunk_count: u32::try_from(chunk_count).map_err(|_| Error::Invalid)?,
            store_only: u16_at(r, 26)? & 1 != 0,
        })
    }

    pub fn chunk(&self, id: u32) -> Result<ChunkRecord> {
        let at = id as usize * CHUNK_RECORD_SIZE;
        let packed = u64_at(
            self.chunks
                .get(at..at + CHUNK_RECORD_SIZE)
                .ok_or(Error::OutOfRange)?,
            0,
        )?;
        // The format crate's record layout; a record it refuses (codec 2 or 3,
        // or out of a volume's bounds) is invalid.
        let chunk = format::Chunk::unpack(packed).map_err(|_| Error::Invalid)?;
        Ok(ChunkRecord {
            offset: chunk.offset,
            volume_id: chunk.volume_id,
            stored_size: chunk.stored_size,
            codec: match chunk.codec {
                format::Codec::Raw => 0,
                format::Codec::Zstd => 1,
            },
        })
    }

    pub fn volume_size(&self, id: u32) -> Result<u64> {
        u64_at(
            self.volumes
                .get(
                    id as usize * VOLUME_RECORD_SIZE
                        ..id as usize * VOLUME_RECORD_SIZE + VOLUME_RECORD_SIZE,
                )
                .ok_or(Error::OutOfRange)?,
            0,
        )
    }

    /// Zero-based file id in sorted (hash, path) order.
    pub fn find(&self, path: &[u8]) -> Result<Option<u64>> {
        if !valid_path(path) {
            return Err(Error::Invalid);
        }
        let hash = path_hash(path);
        let (mut low, mut high) = (0u64, self.file_count());
        while low < high {
            let mid = low + (high - low) / 2;
            let record = self.file(mid)?;
            if (record.path_hash, record.path).cmp(&(hash, path)) == Ordering::Less {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(
            if low < self.file_count()
                && self.file(low)?.path == path
                && self.file(low)?.path_hash == hash
            {
                Some(low)
            } else {
                None
            },
        )
    }

    fn validate(&self) -> Result<()> {
        let (mut next_chunk, mut next_string, mut logical_total) = (0u32, 0usize, 0u64);
        let mut previous: Option<(u64, &[u8])> = None;
        let (mut current_volume, mut next_offset) = (0u32, VOLUME_HEADER_SIZE as u64);
        for id in 0..self.file_count() {
            let at = usize::try_from(id).map_err(|_| Error::Invalid)? * FILE_RECORD_SIZE;
            let raw = &self.files[at..at + FILE_RECORD_SIZE];
            let file = self.file(id)?;
            if u32_at(raw, 20)? as usize != next_string
                || u32_at(raw, 28)? != 0
                || u16_at(raw, 26)? & !1 != 0
                || !valid_path(file.path)
                || file.path_hash != path_hash(file.path)
                || file.first_chunk != next_chunk
                || previous.is_some_and(|p| p >= (file.path_hash, file.path))
            {
                return Err(Error::Invalid);
            }
            next_string = next_string
                .checked_add(file.path.len())
                .ok_or(Error::Invalid)?;
            next_chunk = next_chunk
                .checked_add(file.chunk_count)
                .ok_or(Error::Invalid)?;
            logical_total = logical_total
                .checked_add(file.logical_size)
                .ok_or(Error::Invalid)?;
            previous = Some((file.path_hash, file.path));
            for n in 0..file.chunk_count {
                let chunk_id = file.first_chunk + n;
                let chunk = self.chunk(chunk_id)?;
                let decoded = (file.logical_size - u64::from(n) * CHUNK_SIZE).min(CHUNK_SIZE);
                if chunk.codec > 1
                    || u32::from(chunk.volume_id) >= self.volume_count()
                    || (chunk.codec == 0 && u64::from(chunk.stored_size) != decoded)
                    || (chunk.codec == 1 && u64::from(chunk.stored_size) >= decoded)
                    || (file.store_only && chunk.codec != 0)
                {
                    return Err(Error::Invalid);
                }
                let volume = u32::from(chunk.volume_id);
                if volume != current_volume {
                    if volume != current_volume + 1
                        || next_offset != self.volume_size(current_volume)?
                    {
                        return Err(Error::Invalid);
                    }
                    current_volume = volume;
                    next_offset = VOLUME_HEADER_SIZE as u64;
                }
                if u64::from(chunk.offset) != next_offset {
                    return Err(Error::Invalid);
                }
                next_offset = next_offset
                    .checked_add(u64::from(chunk.stored_size))
                    .ok_or(Error::Invalid)?;
                if next_offset > self.volume_size(volume)? {
                    return Err(Error::Invalid);
                }
            }
        }
        if next_string != self.strings.len()
            || next_chunk != self.chunk_count()
            || logical_total != self.total_logical_bytes
        {
            return Err(Error::Invalid);
        }
        for volume in 0..self.volume_count() {
            if !(VOLUME_HEADER_SIZE as u64..=VOLUME_LIMIT).contains(&self.volume_size(volume)?) {
                return Err(Error::Invalid);
            }
        }
        if self.volume_count() > 0
            && (current_volume + 1 != self.volume_count()
                || next_offset != self.volume_size(current_volume)?)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

fn valid_path(path: &[u8]) -> bool {
    core::str::from_utf8(path).is_ok_and(format::valid_path)
}

/// Parses a 64-byte header, or the first 64 bytes of a complete volume, and
/// matches it to the checked index and its declared size for volume `id`.
pub fn volume_header(bytes: &[u8], index: &Index<'_>, id: u32) -> Result<VolumeHeader> {
    let header = format::decode_volume_header(bytes).map_err(|_| Error::Invalid)?;
    if header.id != id
        || header.count != index.volume_count()
        || header.archive_id != *index.archive_id()
        || header.payload_bytes.checked_add(VOLUME_HEADER_SIZE as u64)
            != Some(index.volume_size(id)?)
    {
        return Err(Error::Invalid);
    }
    Ok(header)
}

/// Writes `ampr_zstd-000.pak` for volume zero, with additional digits past 999.
pub fn volume_name(id: u32, out: &mut [u8]) -> Result<&str> {
    if id as usize >= MAX_VOLUMES {
        return Err(Error::OutOfRange);
    }
    format::write_volume_name(id, out).map_err(|_| Error::Truncated)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn record(offset: u32, stored_size: u32, codec: u64) -> u64 {
        u64::from(offset) | (u64::from(stored_size - 1) << 44) | (codec << 62)
    }

    /// One file of a full raw chunk plus a 10-byte tail stored as 9 zstd bytes.
    fn image(shift: u8, tail_codec: u64) -> Vec<u8> {
        let size = CHUNK_SIZE + 10;
        let path = b"a.bin";
        let first = VOLUME_HEADER_SIZE as u32;
        let records = [
            record(first, CHUNK_SIZE as u32, 0),
            record(first + CHUNK_SIZE as u32, 9, tail_codec),
        ];
        let mut out = std::vec![0u8; INDEX_HEADER_SIZE];
        out.extend_from_slice(&path_hash(path).to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // first_chunk
        out.extend_from_slice(&0u32.to_le_bytes()); // path_off
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 6]); // flags, reserved
        records
            .iter()
            .for_each(|r| out.extend_from_slice(&r.to_le_bytes()));
        let volume = VOLUME_HEADER_SIZE as u64 + CHUNK_SIZE + 9;
        out.extend_from_slice(&volume.to_le_bytes());
        out.extend_from_slice(path);
        let h = &mut out[..INDEX_HEADER_SIZE];
        h[..8].copy_from_slice(INDEX_MAGIC);
        h[8..12].copy_from_slice(&1u32.to_le_bytes());
        h[12..16].copy_from_slice(&(INDEX_HEADER_SIZE as u32).to_le_bytes());
        h[16] = shift;
        h[17] = 5;
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        h[24..40].copy_from_slice(&[7; 16]);
        for (at, value) in [
            (40, 1u64),
            (48, 2),
            (56, 128),
            (64, 160),
            (72, 176),
            (80, 184),
            (88, path.len() as u64),
            (96, size),
        ] {
            h[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        // The header CRC covers the header with bytes 112..120 still zero.
        let header_crc = crc32(&out[..INDEX_HEADER_SIZE]);
        let payload_crc = crc32(&out[INDEX_HEADER_SIZE..]);
        out[112..116].copy_from_slice(&payload_crc.to_le_bytes());
        out[116..120].copy_from_slice(&header_crc.to_le_bytes());
        out
    }

    #[test]
    fn index_reads_256_kib_chunks() {
        let bytes = image(CHUNK_SHIFT, 1);
        let index = Index::open(&bytes).unwrap();
        let file = index.file(0).unwrap();
        assert_eq!(file.chunk_count, 2);
        let full = index.chunk(0).unwrap();
        assert_eq!((full.offset, full.volume_id), (64, 0));
        assert_eq!((full.stored_size, full.codec), (1 << 18, 0));
        let tail = index.chunk(1).unwrap();
        assert_eq!(
            (tail.offset, tail.stored_size, tail.codec),
            (64 + (1 << 18), 9, 1)
        );
    }

    #[test]
    fn index_rejects_other_shift_and_codecs() {
        // A 64 KiB (shift 16) index fails cleanly.
        assert_eq!(Index::open(&image(16, 1)).err(), Some(Error::Invalid));
        for codec in [2, 3] {
            assert_eq!(
                Index::open(&image(CHUNK_SHIFT, codec)).err(),
                Some(Error::Invalid)
            );
        }
    }

    #[test]
    fn volume_name_pads_to_three_digits() {
        let mut buf = [0u8; 32];
        assert_eq!(super::volume_name(0, &mut buf).unwrap(), "ampr_zstd-000.pak");
        assert_eq!(super::volume_name(1, &mut buf).unwrap(), "ampr_zstd-001.pak");
        assert_eq!(super::volume_name(999, &mut buf).unwrap(), "ampr_zstd-999.pak");
        assert_eq!(super::volume_name(1000, &mut buf).unwrap(), "ampr_zstd-1000.pak");
    }
}
