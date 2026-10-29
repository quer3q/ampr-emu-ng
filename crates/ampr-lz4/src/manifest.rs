//! AMPRPAK4 byte-backed manifest reader and AMPRDAT3 header check.
use crate::{
    crc32, header_crc, i64_at, logical_path, pak_path_hash, range, safe_components, section,
    terminated_string, u16_at, u32_at, u64_at, Error, Result, CHUNK_LZ4, CHUNK_PAGE_ALIGNED,
    CHUNK_PAGE_CONTAINED, CHUNK_RAW, CHUNK_RECORD, CHUNK_STREAMING, DAT_HEADER, DAT_HEADER_CRC_AT,
    DAT_MAGIC, ENDIAN_MARKER, FILE_PACKED, FILE_RANDOM_ACCESS, FILE_RECORD, FILE_STORE_ONLY,
    FILE_STREAMING, PACK_IO_PAGE_LAYOUT, PACK_RECORD, PACK_STRIPED, PAK_HEADER, PAK_HEADER_CRC_AT,
    PAK_MAGIC, PAK_PAYLOAD_CRC_AT,
};

/// Raw 48-byte AMPRPAK4 file record (`AmprPackFileRecord`), not validated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileRecord {
    pub path_hash: u64,
    pub logical_size: u64,
    pub mtime: i64,
    pub first_chunk: u32,
    pub chunk_count: u32,
    pub path_offset: u32,
    pub path_length: u32,
    pub flags: u32,
    pub block_shift: u8,
    pub packing_class: u8,
    pub reserved: u16,
}

impl FileRecord {
    /// Decodes exactly `FILE_RECORD` bytes without checking any field.
    pub fn parse(r: &[u8]) -> Result<Self> {
        if r.len() != FILE_RECORD {
            return Err(Error::Invalid);
        }
        let geometry = u16_at(r, 44)?;
        Ok(Self {
            path_hash: u64_at(r, 0)?,
            logical_size: u64_at(r, 8)?,
            mtime: i64_at(r, 16)?,
            first_chunk: u32_at(r, 24)?,
            chunk_count: u32_at(r, 28)?,
            path_offset: u32_at(r, 32)?,
            path_length: u32_at(r, 36)?,
            flags: u32_at(r, 40)?,
            block_shift: geometry as u8,
            packing_class: (geometry >> 8) as u8,
            reserved: u16_at(r, 46)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct File<'a> {
    pub path: &'a [u8],
    pub logical_size: u64,
    pub mtime: i64,
    pub first_chunk: u32,
    pub chunk_count: u32,
    pub flags: u32,
    pub block_shift: u8,
    pub packing_class: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    pub offset: u64,
    pub pack_id: u16,
    pub stored_size: u32,
    pub codec: u8,
    pub flags: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct Pack<'a> {
    pub name: &'a [u8],
    pub payload_bytes: u64,
    pub file_size: u64,
    pub flags: u32,
    pub io_page_size: u32,
}

impl Pack<'_> {
    pub fn payload_offset(&self) -> u64 {
        self.file_size - self.payload_bytes
    }
}

pub struct Manifest<'a> {
    pub build_id: &'a [u8],
    files: &'a [u8],
    chunks: &'a [u8],
    packs: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Manifest<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        let m = Self::layout(bytes)?;
        for id in 0..m.pack_count() {
            m.pack(id)?;
        }
        for id in 0..m.file_count() {
            m.validate_file(id)?;
        }
        Ok(m)
    }

    /// Per-call view of bytes that already passed `open` and stay immutable:
    /// slices the sections at the header offsets with bounds checks only; no
    /// header field checks, no CRC and no per-record validation. Never panics.
    pub fn view_trusted(bytes: &'a [u8]) -> Result<Self> {
        let file_count = u64_at(bytes, 40)?;
        let chunk_count = u64_at(bytes, 48)?;
        let pack_count = u32_at(bytes, 56)?;
        if file_count > u32::MAX as u64
            || chunk_count > u32::MAX as u64
            || pack_count > u16::MAX as u32
        {
            return Err(Error::Invalid);
        }
        let len = |count: u64, size: usize| count.checked_mul(size as u64).ok_or(Error::Invalid);
        Ok(Self {
            build_id: range(bytes, 24, 16)?,
            files: section(bytes, u64_at(bytes, 72)?, len(file_count, FILE_RECORD)?)?,
            chunks: section(bytes, u64_at(bytes, 80)?, len(chunk_count, CHUNK_RECORD)?)?,
            packs: section(
                bytes,
                u64_at(bytes, 88)?,
                len(u64::from(pack_count), PACK_RECORD)?,
            )?,
            strings: section(bytes, u64_at(bytes, 96)?, u64_at(bytes, 104)?)?,
        })
    }

    fn layout(bytes: &'a [u8]) -> Result<Self> {
        if bytes.get(..8) != Some(PAK_MAGIC) {
            return Err(Error::Invalid);
        }
        range(bytes, 0, PAK_HEADER)?;
        if u32_at(bytes, 8)? != 4
            || u32_at(bytes, 12)? != PAK_HEADER as u32
            || u32_at(bytes, 16)? != 0
            || u32_at(bytes, 20)? != ENDIAN_MARKER
            || u32_at(bytes, 60)? != FILE_RECORD as u32
            || u32_at(bytes, 64)? != CHUNK_RECORD as u32
            || u32_at(bytes, 68)? != PACK_RECORD as u32
            || u64_at(bytes, 120)? != 0
        {
            return Err(Error::Invalid);
        }
        if header_crc(bytes, PAK_HEADER, PAK_HEADER_CRC_AT)? != u32_at(bytes, PAK_HEADER_CRC_AT)?
            || crc32(&bytes[PAK_HEADER..]) != u32_at(bytes, PAK_PAYLOAD_CRC_AT)?
        {
            return Err(Error::Checksum);
        }
        let file_count = u64_at(bytes, 40)?;
        let chunk_count = u64_at(bytes, 48)?;
        let pack_count = u32_at(bytes, 56)?;
        if file_count > u32::MAX as u64
            || chunk_count > u32::MAX as u64
            || pack_count > u16::MAX as u32
        {
            return Err(Error::Invalid);
        }
        let file_len = file_count
            .checked_mul(FILE_RECORD as u64)
            .ok_or(Error::Invalid)?;
        let chunk_len = chunk_count
            .checked_mul(CHUNK_RECORD as u64)
            .ok_or(Error::Invalid)?;
        let pack_len = u64::from(pack_count) * PACK_RECORD as u64;
        let files_at = PAK_HEADER as u64;
        let chunks_at = files_at.checked_add(file_len).ok_or(Error::Invalid)?;
        let packs_at = chunks_at.checked_add(chunk_len).ok_or(Error::Invalid)?;
        let strings_at = packs_at.checked_add(pack_len).ok_or(Error::Invalid)?;
        let strings_len = u64_at(bytes, 104)?;
        if u64_at(bytes, 72)? != files_at
            || u64_at(bytes, 80)? != chunks_at
            || u64_at(bytes, 88)? != packs_at
            || u64_at(bytes, 96)? != strings_at
            || strings_at.checked_add(strings_len) != Some(bytes.len() as u64)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            build_id: range(bytes, 24, 16)?,
            files: section(bytes, files_at, file_len)?,
            chunks: section(bytes, chunks_at, chunk_len)?,
            packs: section(bytes, packs_at, pack_len)?,
            strings: section(bytes, strings_at, strings_len)?,
        })
    }

    pub fn file_count(&self) -> u32 {
        (self.files.len() / FILE_RECORD) as u32
    }
    pub fn chunk_count(&self) -> u32 {
        (self.chunks.len() / CHUNK_RECORD) as u32
    }
    pub fn pack_count(&self) -> u32 {
        (self.packs.len() / PACK_RECORD) as u32
    }

    /// Returns the zero-based file record at `index`.
    pub fn file(&self, id: u32) -> Result<File<'a>> {
        let r = self.file_record(id)?;
        let path = self.string(r.path_offset, r.path_length)?;
        if !logical_path(path) || pak_path_hash(path) != r.path_hash || r.reserved != 0 {
            return Err(Error::Invalid);
        }
        Ok(File {
            path,
            logical_size: r.logical_size,
            mtime: r.mtime,
            first_chunk: r.first_chunk,
            chunk_count: r.chunk_count,
            flags: r.flags,
            block_shift: r.block_shift,
            packing_class: r.packing_class,
        })
    }

    /// Returns the raw, unvalidated zero-based file record at `id`.
    pub fn file_record(&self, id: u32) -> Result<FileRecord> {
        let at = id
            .checked_mul(FILE_RECORD as u32)
            .ok_or(Error::OutOfRange)? as usize;
        FileRecord::parse(range(self.files, at, FILE_RECORD)?)
    }

    /// NUL-terminated string-table entry without interior NULs.
    pub fn string(&self, off: u32, len: u32) -> Result<&'a [u8]> {
        terminated_string(self.strings, off, len)
    }

    pub fn chunk(&self, id: u32) -> Result<Chunk> {
        let c = self.chunk_record(id)?;
        if c.codec != CHUNK_RAW && c.codec != CHUNK_LZ4 || c.flags & !0x0f != 0 {
            return Err(Error::Invalid);
        }
        Ok(c)
    }

    /// Decodes a chunk record; only reserved descriptor bits 30..31 are checked.
    pub fn chunk_record(&self, id: u32) -> Result<Chunk> {
        let at = id
            .checked_mul(CHUNK_RECORD as u32)
            .ok_or(Error::OutOfRange)? as usize;
        let r = range(self.chunks, at, CHUNK_RECORD)?;
        let loc = u64_at(r, 0)?;
        let desc = u32_at(r, 8)?;
        if desc & 0xc000_0000 != 0 {
            return Err(Error::Invalid);
        }
        Ok(Chunk {
            offset: loc & ((1u64 << 48) - 1),
            pack_id: (loc >> 48) as u16,
            stored_size: (desc & 0x000f_ffff) + 1,
            codec: ((desc >> 20) & 3) as u8,
            flags: ((desc >> 22) & 0xff) as u8,
        })
    }

    pub fn pack(&self, id: u32) -> Result<Pack<'a>> {
        let at = id
            .checked_mul(PACK_RECORD as u32)
            .ok_or(Error::OutOfRange)? as usize;
        let r = range(self.packs, at, PACK_RECORD)?;
        let name = self.string(u32_at(r, 16)?, u32_at(r, 20)?)?;
        let p = Pack {
            name,
            payload_bytes: u64_at(r, 0)?,
            file_size: u64_at(r, 8)?,
            flags: u32_at(r, 24)?,
            io_page_size: u32_at(r, 28)?,
        };
        if !safe_components(name)
            || !p.io_page_size.is_power_of_two()
            || !(1 << 12..=1 << 20).contains(&p.io_page_size)
            || p.flags & !(PACK_STRIPED | PACK_IO_PAGE_LAYOUT) != 0
            || p.flags & PACK_IO_PAGE_LAYOUT == 0
            || p.file_size < DAT_HEADER as u64
            || p.payload_bytes > p.file_size
            || p.payload_offset() < DAT_HEADER as u64
            || p.payload_offset() % u64::from(p.io_page_size) != 0
            || p.file_size % u64::from(p.io_page_size) != 0
        {
            return Err(Error::Invalid);
        }
        Ok(p)
    }

    /// Raw name of pack record `id`: string-table bounds only, no pack checks.
    pub fn pack_name(&self, id: u32) -> Result<&'a [u8]> {
        let at = id
            .checked_mul(PACK_RECORD as u32)
            .ok_or(Error::OutOfRange)? as usize;
        let r = range(self.packs, at, PACK_RECORD)?;
        self.string(u32_at(r, 16)?, u32_at(r, 20)?)
    }

    fn validate_file(&self, id: u32) -> Result<()> {
        let f = self.file(id)?;
        if f.flags & !0x1f != 0 {
            return Err(Error::Invalid);
        }
        if f.flags & FILE_PACKED == 0 {
            if f.flags != 0
                || f.first_chunk != 0
                || f.chunk_count != 0
                || f.block_shift != 0
                || f.packing_class != 0
            {
                return Err(Error::Invalid);
            }
            return Ok(());
        }
        if !(14..=20).contains(&f.block_shift)
            || f.flags & FILE_STREAMING != 0 && f.flags & FILE_RANDOM_ACCESS != 0
            || u64::from(f.first_chunk) + u64::from(f.chunk_count) > u64::from(self.chunk_count())
        {
            return Err(Error::Invalid);
        }
        let block = 1u64 << f.block_shift;
        let expected = f.logical_size / block + u64::from(f.logical_size % block != 0);
        if u64::from(f.chunk_count) != expected {
            return Err(Error::Invalid);
        }
        for local in 0..f.chunk_count {
            let c = self.chunk(f.first_chunk + local)?;
            let p = self.pack(u32::from(c.pack_id))?;
            let raw = core::cmp::min(block, f.logical_size - u64::from(local) * block);
            let stored = u64::from(c.stored_size);
            let page = u64::from(p.io_page_size);
            let end = c.offset.checked_add(stored).ok_or(Error::Invalid)?;
            let contained = c.flags & CHUNK_PAGE_CONTAINED != 0;
            let aligned = c.flags & CHUNK_PAGE_ALIGNED != 0;
            let streaming = c.flags & CHUNK_STREAMING != 0;
            if stored > block
                || c.codec == CHUNK_RAW && stored != raw
                || f.flags & FILE_STORE_ONLY != 0 && c.codec != CHUNK_RAW
                || streaming != (f.flags & FILE_STREAMING != 0)
                || c.offset < p.payload_offset()
                || end > p.file_size
                || c.offset % 64 != 0
                || contained && (stored > page || c.offset / page != (end - 1) / page)
                || aligned && (c.offset % page != 0 || stored <= page && !contained)
                || !streaming
                    && ((stored <= page && !contained)
                        || (stored > page && !aligned)
                        || (c.codec == CHUNK_RAW && stored >= page && !aligned))
                || c.offset / page * page < p.payload_offset()
                || end.checked_add(page - 1).ok_or(Error::Invalid)? / page * page > p.file_size
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    /// Checks a volume header against a manifest pack record and actual volume size.
    pub fn check_volume_header(&self, h: &[u8], pack_id: u32, actual_size: u64) -> Result<()> {
        let p = self.pack(pack_id)?;
        check_volume_header(
            h,
            pack_id,
            self.build_id,
            p.flags,
            p.file_size,
            p.payload_bytes,
            p.io_page_size,
            actual_size,
        )?;
        Ok(())
    }
}

/// Check a separately read AMPRDAT3 header against an already validated pack.
/// Returns the byte range occupied by the payload.
pub fn check_volume_header(
    h: &[u8],
    pack_id: u32,
    build_id: &[u8],
    flags: u32,
    file_size: u64,
    payload_bytes: u64,
    io_page_size: u32,
    actual_size: u64,
) -> Result<(u64, u64)> {
    if h.get(..8) != Some(DAT_MAGIC) || build_id.len() != 16 {
        return Err(Error::Invalid);
    }
    range(h, 0, DAT_HEADER)?;
    if u32_at(h, 8)? != 3
        || u32_at(h, 12)? != DAT_HEADER as u32
        || u32_at(h, 16)? != pack_id
        || u32_at(h, 20)? != flags
        || flags & !(PACK_STRIPED | PACK_IO_PAGE_LAYOUT) != 0
        || &h[24..40] != build_id
        || u32_at(h, 60)? != 0
    {
        return Err(Error::Invalid);
    }
    if header_crc(h, DAT_HEADER, DAT_HEADER_CRC_AT)? != u32_at(h, DAT_HEADER_CRC_AT)? {
        return Err(Error::Checksum);
    }
    let off = u64_at(h, 40)?;
    let payload = u64_at(h, 48)?;
    let end = off.checked_add(payload).ok_or(Error::Invalid)?;
    if !io_page_size.is_power_of_two()
        || !(1 << 12..=1 << 20).contains(&io_page_size)
        || off < DAT_HEADER as u64
        || off % u64::from(io_page_size) != 0
        || file_size % u64::from(io_page_size) != 0
        || payload != payload_bytes
        || end != file_size
        || actual_size != file_size
    {
        return Err(Error::Invalid);
    }
    Ok((off, end))
}
