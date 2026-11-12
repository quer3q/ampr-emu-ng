//! Readers for zstd pack indexes (AMPRZPK1 v1) and volumes (AMPRZDT1 v1).
//! The convention (magics, layout, names, chunk records, the volume header) comes
//! from the `ampr-zstd` crate, used in `no_std`; the index reader reads through a
//! `Source`, so the runtime can page a large index instead of holding it whole.
use crate::source::{src_bytes, src_crc32, src_u64, Source, PATH_BUF};
use crate::{crc32_parts, u16_at, u32_at, u64_at, Error, Result};
use ampr_zstd as format;
use core::cmp::Ordering;

pub use format::{
    path_hash_bytes as path_hash, VolumeHeader, CHUNK_RECORD_SIZE, CHUNK_SHIFT, CHUNK_SIZE,
    FILE_RECORD_SIZE, FORMAT_VERSION, INDEX_HEADER_CRC_AT, INDEX_HEADER_SIZE, INDEX_MAGIC,
    INDEX_NAME, INDEX_PAYLOAD_CRC_AT, MAX_VOLUMES, VOLUME_HEADER_SIZE, VOLUME_LIMIT,
    VOLUME_PREFIX, VOLUME_RECORD_SIZE, VOLUME_SUFFIX, ZSTD_LEVELS,
};

/// A file record by value: the path stays in the source at `path_at`
/// (absolute offset) and is copied out with `Index::path`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRecord {
    pub path_at: u64,
    pub path_len: u16,
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

/// The fast table: what lookups and read jobs need, held in memory by the
/// caller and filled by one sequential pass (`Index::fill_fast`). With it
/// `chunk`, `volume_size` and `logical_size` never read the source and
/// `find` reads it only to confirm a path whose hash matches; paths and
/// full file records stay in the source. 16 B per file and 8 B per chunk
/// and volume (about 7.9 MiB at 300k files and 100 GB of 256 KiB chunks).
#[derive(Clone, Copy, Debug)]
pub struct Fast<'f> {
    /// `path_hash` of every file record, in record (hash, path) order.
    pub hashes: &'f [u64],
    /// `logical_size` of every file record, in the same order: a read job
    /// needs it and the runtime projection does not hold it.
    pub sizes: &'f [u64],
    /// Every packed chunk record.
    pub chunks: &'f [u64],
    /// Every volume size.
    pub volumes: &'f [u64],
}

/// Reads records through `src` at absolute table offsets, so the same
/// reader serves a resident image and the runtime's index page cache.
pub struct Index<'s, S: Source + ?Sized = [u8]> {
    src: &'s S,
    fast: Option<Fast<'s>>,
    files_at: u64,
    file_count: u64,
    chunks_at: u64,
    chunk_count: u32,
    volumes_at: u64,
    volume_count: u32,
    strings_at: u64,
    strings_len: u64,
    archive_id: [u8; 16],
    total_logical_bytes: u64,
}

impl<'s, S: Source + ?Sized> Index<'s, S> {
    pub fn open(src: &'s S) -> Result<Self> {
        let mut h = [0u8; INDEX_HEADER_SIZE];
        src.read_at(0, &mut h)?;
        if &h[..8] != INDEX_MAGIC
            || u32_at(&h, 8)? != FORMAT_VERSION
            || u32_at(&h, 12)? != INDEX_HEADER_SIZE as u32
            || h[16] != CHUNK_SHIFT
            || !ZSTD_LEVELS.contains(&h[17])
            || u16_at(&h, 18)? != 0
            || u64_at(&h, 104)? != 0
            || u64_at(&h, 120)? != 0
        {
            return Err(Error::Invalid);
        }
        let crc_end = INDEX_HEADER_CRC_AT + 4;
        if crc32_parts(&[&h[..INDEX_PAYLOAD_CRC_AT], &[0; 8], &h[crc_end..]])
            != u32_at(&h, INDEX_HEADER_CRC_AT)?
            || src_crc32(src, INDEX_HEADER_SIZE as u64, src.len(), 0)?
                != u32_at(&h, INDEX_PAYLOAD_CRC_AT)?
        {
            return Err(Error::Checksum);
        }
        let volume_count = u32_at(&h, 20)?;
        let file_count = u64_at(&h, 40)?;
        let chunk_count = u64_at(&h, 48)?;
        if volume_count as usize > MAX_VOLUMES || chunk_count > u32::MAX as u64 {
            return Err(Error::Invalid);
        }
        let files_off = u64_at(&h, 56)?;
        let chunks_off = u64_at(&h, 64)?;
        let volumes_off = u64_at(&h, 72)?;
        let strings_off = u64_at(&h, 80)?;
        let strings_len = u64_at(&h, 88)?;
        if files_off != INDEX_HEADER_SIZE as u64
            || files_off.checked_add(
                file_count
                    .checked_mul(FILE_RECORD_SIZE as u64)
                    .ok_or(Error::Invalid)?,
            ) != Some(chunks_off)
            || chunks_off.checked_add(chunk_count * CHUNK_RECORD_SIZE as u64) != Some(volumes_off)
            || volumes_off.checked_add(u64::from(volume_count) * VOLUME_RECORD_SIZE as u64)
                != Some(strings_off)
            || strings_off.checked_add(strings_len) != Some(src.len())
            || strings_len > u32::MAX as u64
            || (chunk_count == 0) != (volume_count == 0)
        {
            return Err(Error::Invalid);
        }
        let mut archive_id = [0; 16];
        archive_id.copy_from_slice(&h[24..40]);
        let index = Self {
            src,
            fast: None,
            files_at: files_off,
            file_count,
            chunks_at: chunks_off,
            chunk_count: chunk_count as u32,
            volumes_at: volumes_off,
            volume_count,
            strings_at: strings_off,
            strings_len,
            archive_id,
            total_logical_bytes: u64_at(&h, 96)?,
        };
        index.validate()?;
        Ok(index)
    }

    pub fn archive_id(&self) -> &[u8; 16] {
        &self.archive_id
    }
    pub fn file_count(&self) -> u64 {
        self.file_count
    }
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }
    pub fn volume_count(&self) -> u32 {
        self.volume_count
    }

    // ---- fast table ----

    /// Lengths of the fast table's arrays: (files, chunks, volumes);
    /// `hashes` and `sizes` both have `files` entries.
    pub fn fast_lens(&self) -> (usize, usize, usize) {
        (
            self.file_count as usize,
            self.chunk_count as usize,
            self.volume_count as usize,
        )
    }

    /// Fills the fast table in one sequential pass over the file, chunk
    /// and volume tables, 4 KiB per source read (no_std threads have small
    /// stacks). `Invalid` when a slice length differs from `fast_lens`.
    pub fn fill_fast(
        &self,
        hashes: &mut [u64],
        sizes: &mut [u64],
        chunks: &mut [u64],
        volumes: &mut [u64],
    ) -> Result<()> {
        let (files, chunk_n, volume_n) = self.fast_lens();
        if hashes.len() != files
            || sizes.len() != files
            || chunks.len() != chunk_n
            || volumes.len() != volume_n
        {
            return Err(Error::Invalid);
        }
        let mut buf = [0u8; 4096];
        let per = buf.len() / FILE_RECORD_SIZE;
        let records = hashes.chunks_mut(per).zip(sizes.chunks_mut(per));
        for (n, (hashes, sizes)) in records.enumerate() {
            let at = self.files_at + (n * per * FILE_RECORD_SIZE) as u64;
            let block = &mut buf[..hashes.len() * FILE_RECORD_SIZE];
            self.src.read_at(at, block)?;
            for (i, (h, size)) in hashes.iter_mut().zip(sizes.iter_mut()).enumerate() {
                *h = u64_at(block, i * FILE_RECORD_SIZE)?;
                *size = u64_at(block, i * FILE_RECORD_SIZE + 8)?;
            }
        }
        for (table, out) in [(self.chunks_at, chunks), (self.volumes_at, volumes)] {
            for (n, out) in out.chunks_mut(buf.len() / 8).enumerate() {
                let block = &mut buf[..out.len() * 8];
                self.src.read_at(table + (n * 4096) as u64, block)?;
                for (i, v) in out.iter_mut().enumerate() {
                    *v = u64_at(block, i * 8)?;
                }
            }
        }
        Ok(())
    }

    /// Makes lookups use `fast` (filled by `fill_fast` from this index).
    /// `Invalid` when its lengths do not match.
    pub fn with_fast(mut self, fast: Fast<'s>) -> Result<Self> {
        let lens = (fast.hashes.len(), fast.chunks.len(), fast.volumes.len());
        if lens != self.fast_lens() || fast.sizes.len() != lens.0 {
            return Err(Error::Invalid);
        }
        self.fast = Some(fast);
        Ok(self)
    }

    /// Whether `chunk` and `volume_size` read memory only.
    pub fn has_fast(&self) -> bool {
        self.fast.is_some()
    }

    fn raw_file(&self, id: u64) -> Result<[u8; FILE_RECORD_SIZE]> {
        if id >= self.file_count {
            return Err(Error::OutOfRange);
        }
        let mut r = [0u8; FILE_RECORD_SIZE];
        self.src
            .read_at(self.files_at + id * FILE_RECORD_SIZE as u64, &mut r)?;
        Ok(r)
    }

    fn parse_file(&self, r: &[u8]) -> Result<FileRecord> {
        let path_off = u64::from(u32_at(r, 20)?);
        let path_len = u16_at(r, 24)?;
        if path_off + u64::from(path_len) > self.strings_len {
            return Err(Error::Invalid);
        }
        let size = u64_at(r, 8)?;
        let chunk_count = size / CHUNK_SIZE + u64::from(size % CHUNK_SIZE != 0);
        Ok(FileRecord {
            path_at: self.strings_at + path_off,
            path_len,
            path_hash: u64_at(r, 0)?,
            logical_size: size,
            first_chunk: u32_at(r, 16)?,
            chunk_count: u32::try_from(chunk_count).map_err(|_| Error::Invalid)?,
            store_only: u16_at(r, 26)? & 1 != 0,
        })
    }

    pub fn file(&self, id: u64) -> Result<FileRecord> {
        self.parse_file(&self.raw_file(id)?)
    }

    /// File `id`'s logical size; with the fast table it reads memory only.
    pub fn logical_size(&self, id: u64) -> Result<u64> {
        match self.fast {
            Some(f) => f.sizes.get(id as usize).copied().ok_or(Error::OutOfRange),
            None => Ok(self.file(id)?.logical_size),
        }
    }

    /// Copies `rec`'s path into `buf`; `Invalid` when it does not fit.
    pub fn path<'b>(&self, rec: &FileRecord, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        src_bytes(self.src, rec.path_at, usize::from(rec.path_len), buf)
    }

    pub fn chunk(&self, id: u32) -> Result<ChunkRecord> {
        if id >= self.chunk_count {
            return Err(Error::OutOfRange);
        }
        let packed = match self.fast {
            Some(f) => f.chunks[id as usize],
            None => src_u64(
                self.src,
                self.chunks_at + u64::from(id) * CHUNK_RECORD_SIZE as u64,
            )?,
        };
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
        if id >= self.volume_count {
            return Err(Error::OutOfRange);
        }
        match self.fast {
            Some(f) => Ok(f.volumes[id as usize]),
            None => src_u64(
                self.src,
                self.volumes_at + u64::from(id) * VOLUME_RECORD_SIZE as u64,
            ),
        }
    }

    /// Zero-based file id in sorted (hash, path) order. The binary search
    /// compares hashes and reads a record's path only on an equal hash;
    /// with the fast table it searches the resident hashes.
    pub fn find(&self, path: &[u8]) -> Result<Option<u64>> {
        if !valid_path(path) {
            return Err(Error::Invalid);
        }
        if path.len() >= PATH_BUF {
            return Ok(None);
        }
        let hash = path_hash(path);
        let mut buf = [0u8; PATH_BUF];
        if let Some(f) = self.fast {
            // Equal hashes are in path order: stop at the first path past it.
            let mut id = f.hashes.partition_point(|&h| h < hash);
            while f.hashes.get(id) == Some(&hash) {
                match self.path(&self.file(id as u64)?, &mut buf)?.cmp(path) {
                    Ordering::Equal => return Ok(Some(id as u64)),
                    Ordering::Greater => break,
                    Ordering::Less => id += 1,
                }
            }
            return Ok(None);
        }
        let (mut low, mut high) = (0u64, self.file_count);
        while low < high {
            let mid = low + (high - low) / 2;
            let record = self.file(mid)?;
            let less = match record.path_hash.cmp(&hash) {
                Ordering::Equal => self.path(&record, &mut buf)? < path,
                o => o == Ordering::Less,
            };
            if less {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low >= self.file_count {
            return Ok(None);
        }
        let record = self.file(low)?;
        Ok((record.path_hash == hash && self.path(&record, &mut buf)? == path).then_some(low))
    }

    /// One pass over the records through the source. Two path buffers hold
    /// the current and the previous path for the order check.
    fn validate(&self) -> Result<()> {
        let (mut next_chunk, mut next_string, mut logical_total) = (0u32, 0u64, 0u64);
        let mut bufs = [[0u8; PATH_BUF]; 2];
        let mut previous: Option<(u64, usize)> = None;
        let (mut current_volume, mut next_offset) = (0u32, VOLUME_HEADER_SIZE as u64);
        let mut current_size = if self.volume_count > 0 {
            self.volume_size(0)?
        } else {
            0
        };
        for id in 0..self.file_count {
            let raw = self.raw_file(id)?;
            let file = self.parse_file(&raw)?;
            let [a, b] = &mut bufs;
            let (cur, prev) = if id & 1 == 0 { (a, &*b) } else { (b, &*a) };
            if usize::from(file.path_len) >= PATH_BUF {
                return Err(Error::Invalid);
            }
            let path = self.path(&file, cur)?;
            if u64::from(u32_at(&raw, 20)?) != next_string
                || u32_at(&raw, 28)? != 0
                || u16_at(&raw, 26)? & !1 != 0
                || !valid_path(path)
                || file.path_hash != path_hash(path)
                || file.first_chunk != next_chunk
                || previous.is_some_and(|(h, n)| (h, &prev[..n]) >= (file.path_hash, path))
            {
                return Err(Error::Invalid);
            }
            next_string += u64::from(file.path_len);
            next_chunk = next_chunk
                .checked_add(file.chunk_count)
                .ok_or(Error::Invalid)?;
            logical_total = logical_total
                .checked_add(file.logical_size)
                .ok_or(Error::Invalid)?;
            previous = Some((file.path_hash, path.len()));
            for n in 0..file.chunk_count {
                let chunk_id = file.first_chunk + n;
                let chunk = self.chunk(chunk_id)?;
                let decoded = (file.logical_size - u64::from(n) * CHUNK_SIZE).min(CHUNK_SIZE);
                if chunk.codec > 1
                    || u32::from(chunk.volume_id) >= self.volume_count
                    || (chunk.codec == 0 && u64::from(chunk.stored_size) != decoded)
                    || (chunk.codec == 1 && u64::from(chunk.stored_size) >= decoded)
                    || (file.store_only && chunk.codec != 0)
                {
                    return Err(Error::Invalid);
                }
                let volume = u32::from(chunk.volume_id);
                if volume != current_volume {
                    if volume != current_volume + 1 || next_offset != current_size {
                        return Err(Error::Invalid);
                    }
                    current_volume = volume;
                    current_size = self.volume_size(volume)?;
                    next_offset = VOLUME_HEADER_SIZE as u64;
                }
                if u64::from(chunk.offset) != next_offset {
                    return Err(Error::Invalid);
                }
                next_offset = next_offset
                    .checked_add(u64::from(chunk.stored_size))
                    .ok_or(Error::Invalid)?;
                if next_offset > current_size {
                    return Err(Error::Invalid);
                }
            }
        }
        if next_string != self.strings_len
            || next_chunk != self.chunk_count
            || logical_total != self.total_logical_bytes
        {
            return Err(Error::Invalid);
        }
        for volume in 0..self.volume_count {
            if !(VOLUME_HEADER_SIZE as u64..=VOLUME_LIMIT).contains(&self.volume_size(volume)?) {
                return Err(Error::Invalid);
            }
        }
        if self.volume_count > 0
            && (current_volume + 1 != self.volume_count
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

/// (files, chunks, volumes) declared by an index header, before `open`
/// checks them: lets the caller size its tables before the full pass.
pub fn header_counts(h: &[u8]) -> Result<(u64, u64, u32)> {
    if h.get(..8) != Some(&INDEX_MAGIC[..]) {
        return Err(Error::Invalid);
    }
    Ok((u64_at(h, 40)?, u64_at(h, 48)?, u32_at(h, 20)?))
}

/// Parses a 64-byte header, or the first 64 bytes of a complete volume, and
/// matches it to the checked index and its declared size for volume `id`.
pub fn volume_header<S: Source + ?Sized>(
    bytes: &[u8],
    index: &Index<'_, S>,
    id: u32,
) -> Result<VolumeHeader> {
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
    use crate::crc32;
    use core::cell::Cell;
    use std::vec::Vec;

    fn record(offset: u32, stored_size: u32, codec: u64) -> u64 {
        u64::from(offset) | (u64::from(stored_size - 1) << 44) | (codec << 62)
    }

    /// One file of a full raw chunk plus a 10-byte tail stored as 9 zstd bytes.
    fn image(shift: u8, tail_codec: u64) -> Vec<u8> {
        image_with(b"a.bin", shift, tail_codec)
    }

    fn image_with(path: &[u8], shift: u8, tail_codec: u64) -> Vec<u8> {
        let size = CHUNK_SIZE + 10;
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
    fn index_reads_256_kib_chunks_and_rejects_others() {
        let bytes = image(CHUNK_SHIFT, 1);
        let index = Index::open(&bytes[..]).unwrap();
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
        // A 64 KiB (shift 16) index fails cleanly.
        assert_eq!(Index::open(&image(16, 1)[..]).err(), Some(Error::Invalid));
        for codec in [2, 3] {
            assert_eq!(
                Index::open(&image(CHUNK_SHIFT, codec)[..]).err(),
                Some(Error::Invalid)
            );
        }
        let mut buf = [0u8; 32];
        assert_eq!(volume_name(7, &mut buf).unwrap(), "ampr_zstd-007.pak");
        assert_eq!(
            volume_name(MAX_VOLUMES as u32, &mut buf).err(),
            Some(Error::OutOfRange)
        );
    }

    /// A source that is not a slice: counts reads and can fail like a file.
    struct Counting {
        bytes: Vec<u8>,
        reads: Cell<usize>,
        fail: Cell<bool>,
    }

    impl Source for Counting {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            if self.fail.get() {
                return Err(Error::Io);
            }
            self.bytes[..].read_at(at, out)
        }
    }

    #[test]
    fn index_reads_through_a_non_slice_source() {
        let bytes = image(CHUNK_SHIFT, 1);
        let src = Counting {
            bytes: bytes.clone(),
            reads: Cell::new(0),
            fail: Cell::new(false),
        };
        let (paged, plain) = (Index::open(&src).unwrap(), Index::open(&bytes[..]).unwrap());
        assert!(src.reads.get() > 0);
        assert_eq!(paged.find(b"a.bin"), plain.find(b"a.bin"));
        assert_eq!(paged.find(b"a.bin"), Ok(Some(0)));
        assert_eq!(paged.find(b"b.bin"), Ok(None));
        let (a, b) = (paged.file(0).unwrap(), plain.file(0).unwrap());
        assert_eq!(a, b);
        let (mut x, mut y) = ([0u8; PATH_BUF], [0u8; PATH_BUF]);
        assert_eq!(paged.path(&a, &mut x), plain.path(&b, &mut y));
        assert_eq!(paged.path(&a, &mut x).unwrap(), b"a.bin");
        assert_eq!(paged.path(&a, &mut [0u8; 4]).err(), Some(Error::Invalid));
        assert_eq!(paged.chunk(1), plain.chunk(1));
        assert_eq!(paged.volume_size(0), plain.volume_size(0));
        // A path of PATH_BUF bytes or longer is refused (the PS5 path limit).
        let long = [b'a'; PATH_BUF];
        let ok = image_with(&long[..PATH_BUF - 1], CHUNK_SHIFT, 1);
        assert!(Index::open(&ok[..]).is_ok());
        let too_long = image_with(&long, CHUNK_SHIFT, 1);
        assert_eq!(Index::open(&too_long[..]).err(), Some(Error::Invalid));
        src.fail.set(true);
        assert_eq!(paged.file(0).err(), Some(Error::Io));
        assert_eq!(Index::open(&src).err(), Some(Error::Io));
    }

    /// `n` small raw files of one chunk each in one volume, records in
    /// (hash, path) order.
    fn multi(n: usize) -> Vec<u8> {
        let mut files: Vec<(u64, Vec<u8>)> = (0..n)
            .map(|i| std::format!("d{}/f{i}.bin", i % 5).into_bytes())
            .map(|p| (path_hash(&p), p))
            .collect();
        files.sort();
        let size = |i: usize| 10 + (i % 7) as u64;
        let (mut recs, mut chunks, mut strings) = (Vec::new(), Vec::new(), Vec::new());
        let mut offset = VOLUME_HEADER_SIZE as u64;
        for (i, (hash, path)) in files.iter().enumerate() {
            recs.extend_from_slice(&hash.to_le_bytes());
            recs.extend_from_slice(&size(i).to_le_bytes());
            recs.extend_from_slice(&(i as u32).to_le_bytes());
            recs.extend_from_slice(&(strings.len() as u32).to_le_bytes());
            recs.extend_from_slice(&(path.len() as u16).to_le_bytes());
            recs.extend_from_slice(&[0; 6]);
            chunks.extend_from_slice(&record(offset as u32, size(i) as u32, 0).to_le_bytes());
            offset += size(i);
            strings.extend_from_slice(path);
        }
        let mut out = std::vec![0u8; INDEX_HEADER_SIZE];
        let chunks_at = (INDEX_HEADER_SIZE + recs.len()) as u64;
        let volumes_at = chunks_at + chunks.len() as u64;
        out.extend_from_slice(&recs);
        out.extend_from_slice(&chunks);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&strings);
        let h = &mut out[..INDEX_HEADER_SIZE];
        h[..8].copy_from_slice(INDEX_MAGIC);
        h[8..12].copy_from_slice(&1u32.to_le_bytes());
        h[12..16].copy_from_slice(&(INDEX_HEADER_SIZE as u32).to_le_bytes());
        h[16] = CHUNK_SHIFT;
        h[17] = 5;
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        let total = offset - VOLUME_HEADER_SIZE as u64;
        for (at, value) in [
            (40, n as u64),
            (48, n as u64),
            (56, INDEX_HEADER_SIZE as u64),
            (64, chunks_at),
            (72, volumes_at),
            (80, volumes_at + 8),
            (88, strings.len() as u64),
            (96, total),
        ] {
            h[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let header_crc = crc32(&out[..INDEX_HEADER_SIZE]);
        let payload_crc = crc32(&out[INDEX_HEADER_SIZE..]);
        out[112..116].copy_from_slice(&payload_crc.to_le_bytes());
        out[116..120].copy_from_slice(&header_crc.to_le_bytes());
        out
    }

    #[test]
    fn fast_table_gives_the_same_answers_without_source_reads() {
        // 600 files: the pass crosses 4 KiB blocks of records and chunks.
        let n = 600;
        let bytes = multi(n);
        assert_eq!(header_counts(&bytes), Ok((n as u64, n as u64, 1)));
        let src = Counting {
            bytes: bytes.clone(),
            reads: Cell::new(0),
            fail: Cell::new(false),
        };
        let plain = Index::open(&bytes[..]).unwrap();
        let index = Index::open(&src).unwrap();
        let (f, c, v) = index.fast_lens();
        let (mut hashes, mut sizes, mut chunks, mut volumes) = (
            std::vec![0; f],
            std::vec![0; f],
            std::vec![0; c],
            std::vec![0; v],
        );
        assert_eq!(
            index.fill_fast(&mut hashes[1..], &mut sizes, &mut chunks, &mut volumes),
            Err(Error::Invalid)
        );
        assert_eq!(
            index.fill_fast(&mut hashes, &mut sizes[1..], &mut chunks, &mut volumes),
            Err(Error::Invalid)
        );
        index
            .fill_fast(&mut hashes, &mut sizes, &mut chunks, &mut volumes)
            .unwrap();
        let fast = Fast {
            hashes: &hashes,
            sizes: &sizes,
            chunks: &chunks,
            volumes: &volumes,
        };
        for short in [
            Fast {
                hashes: &hashes[1..],
                ..fast
            },
            Fast {
                sizes: &sizes[1..],
                ..fast
            },
        ] {
            assert!(Index::open(&src).unwrap().with_fast(short).is_err());
        }
        let index = index.with_fast(fast).unwrap();
        assert!(index.has_fast() && !plain.has_fast());
        src.reads.set(0);
        for id in 0..n as u32 {
            assert_eq!(index.chunk(id), plain.chunk(id));
        }
        assert_eq!(index.chunk(n as u32), plain.chunk(n as u32));
        assert_eq!(index.volume_size(0), plain.volume_size(0));
        assert_eq!(index.volume_size(1), plain.volume_size(1));
        for id in 0..n as u64 {
            let want = plain.file(id).unwrap().logical_size;
            assert_eq!(index.logical_size(id), Ok(want));
            assert_eq!(plain.logical_size(id), Ok(want));
        }
        assert_eq!(index.logical_size(n as u64), Err(Error::OutOfRange));
        // A path whose hash no record has: answered from memory.
        assert_eq!(index.find(b"none.bin"), Ok(None));
        assert_eq!(src.reads.get(), 0);
        let mut buf = [0u8; PATH_BUF];
        for id in 0..n as u64 {
            let path = plain
                .path(&plain.file(id).unwrap(), &mut buf)
                .unwrap()
                .to_vec();
            src.reads.set(0);
            assert_eq!(index.find(&path), Ok(Some(id)));
            // The record and the path that confirm it, nothing else.
            assert_eq!(src.reads.get(), 2);
            assert_eq!(plain.find(&path), Ok(Some(id)));
        }
        assert_eq!(index.find(b"d1/f0.bin"), plain.find(b"d1/f0.bin"));
    }
}
