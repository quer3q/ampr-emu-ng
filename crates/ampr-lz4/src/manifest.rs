//! AMPRPAK4 manifest reader and AMPRDAT3 header check. The manifest reads
//! through a `Source`, so the runtime can page a large index instead of
//! holding it whole.
use crate::{
    header_crc, logical_path, pak_path_hash, range, safe_components, u16_at, u32_at, u64_at, Error,
    Result, CHUNK_LZ4, CHUNK_PAGE_ALIGNED, CHUNK_PAGE_CONTAINED, CHUNK_RAW, CHUNK_RECORD,
    CHUNK_STREAMING, DAT_HEADER, DAT_HEADER_CRC_AT, DAT_MAGIC, ENDIAN_MARKER, FILE_PACKED,
    FILE_RANDOM_ACCESS, FILE_RECORD, FILE_STORE_ONLY, FILE_STREAMING, PACK_IO_PAGE_LAYOUT,
    PACK_RECORD, PACK_STRIPED, PAK_HEADER, PAK_HEADER_CRC_AT, PAK_MAGIC, PAK_PAYLOAD_CRC_AT,
};
use ampr_format::overlay::folded_compare;
use ampr_format::source::{src_crc32, src_u32, src_u64, Source, PATH_BUF};

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
            mtime: crate::i64_at(r, 16)?,
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

/// A checked file record by value: the path stays in the source at
/// `path_at` (absolute offset) and is copied out with `Manifest::path`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct File {
    pub path_at: u64,
    pub path_len: u32,
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

/// A pack record by value; its name is copied out with `Manifest::pack_name`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pack {
    pub payload_bytes: u64,
    pub file_size: u64,
    pub flags: u32,
    pub io_page_size: u32,
}

impl Pack {
    pub fn payload_offset(&self) -> u64 {
        self.file_size - self.payload_bytes
    }
}

/// Reads records through `src` at absolute section offsets, so the same
/// reader serves a resident image and the runtime's index page cache; with
/// a fast table (`with_fast`) the records come from memory and only paths
/// are read through `src`.
pub struct Manifest<'s, S: Source + ?Sized = [u8]> {
    src: &'s S,
    /// The fast table (`fill_fast`): the file, chunk and pack record
    /// sections, `[files_at, strings_at)`, held in memory by the caller.
    fast: Option<&'s [u8]>,
    /// Records are in folded path order, ties allowed (checked by `open`;
    /// false for `view_trusted`).
    sorted: bool,
    pub build_id: [u8; 16],
    files_at: u64,
    file_count: u32,
    chunks_at: u64,
    chunk_count: u32,
    packs_at: u64,
    pack_count: u32,
    strings_at: u64,
    strings_len: u64,
}

// A copy reads the same source; `derive` would ask `S: Copy` of `[u8]`.
impl<S: Source + ?Sized> Clone for Manifest<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: Source + ?Sized> Copy for Manifest<'_, S> {}

/// `at` when `[at, at + len)` lies in the source: `Invalid` on overflow,
/// `Truncated` past the end, as a slice section was.
fn section(src: &(impl Source + ?Sized), at: u64, len: u64) -> Result<u64> {
    let end = at.checked_add(len).ok_or(Error::Invalid)?;
    if end > src.len() {
        return Err(Error::Truncated);
    }
    Ok(at)
}

/// Absolute offset of record `id` of `count` records of `size` bytes at
/// `base`: `OutOfRange` when the byte offset overflows u32, `Truncated`
/// past the section, as the slice reader returned.
fn record_at(base: u64, count: u32, id: u32, size: usize) -> Result<u64> {
    let off = id.checked_mul(size as u32).ok_or(Error::OutOfRange)?;
    if id >= count {
        return Err(Error::Truncated);
    }
    Ok(base + u64::from(off))
}

/// File, chunk and pack counts at header offsets 40, 48 and 56, checked
/// against the record index widths.
fn counts(src: &(impl Source + ?Sized)) -> Result<(u32, u32, u32)> {
    let file_count = src_u64(src, 40)?;
    let chunk_count = src_u64(src, 48)?;
    let pack_count = src_u32(src, 56)?;
    if file_count > u32::MAX as u64 || chunk_count > u32::MAX as u64 || pack_count > u16::MAX as u32
    {
        return Err(Error::Invalid);
    }
    Ok((file_count as u32, chunk_count as u32, pack_count))
}

/// (files, chunks, packs) declared by an AMPRPAK4 header, before `open`
/// checks the rest: lets the caller size its tables before the full pass.
pub fn header_counts(h: &[u8]) -> Result<(u32, u32, u32)> {
    if h.get(..8) != Some(&PAK_MAGIC[..]) {
        return Err(Error::Invalid);
    }
    counts(h)
}

impl<'s, S: Source + ?Sized> Manifest<'s, S> {
    /// Full validation: every pack and file record, each path read once.
    /// The same pass notes whether the records are in folded path order
    /// (`records_sorted`), comparing each path with the one before it.
    pub fn open(src: &'s S) -> Result<Self> {
        let mut m = Self::layout(src)?;
        for id in 0..m.pack_count() {
            m.pack(id)?;
        }
        let mut bufs = [[0u8; PATH_BUF]; 2];
        let (mut previous, mut sorted) = (None, true);
        for id in 0..m.file_count() {
            let [a, b] = &mut bufs;
            let (cur, prev) = if id & 1 == 0 { (a, &*b) } else { (b, &*a) };
            let len = m.validate_file(id, cur)?;
            if previous.is_some_and(|n: usize| folded_compare(&prev[..n], &cur[..len]).is_gt()) {
                sorted = false;
            }
            previous = Some(len);
        }
        m.sorted = sorted;
        Ok(m)
    }

    /// Whether `open` found the records in folded path order, ties allowed:
    /// then (folded path, id) order is plain id order.
    pub fn records_sorted(&self) -> bool {
        self.sorted
    }

    /// Per-call view of a source that already passed `open` and stays
    /// immutable: section offsets from the header with bounds checks only;
    /// no header field checks, no CRC and no per-record validation. Never
    /// panics.
    pub fn view_trusted(src: &'s S) -> Result<Self> {
        let (file_count, chunk_count, pack_count) = counts(src)?;
        let len = |count: u32, size: usize| u64::from(count) * size as u64;
        let mut build_id = [0u8; 16];
        src.read_at(24, &mut build_id)?;
        Ok(Self {
            src,
            fast: None,
            sorted: false,
            build_id,
            files_at: section(src, src_u64(src, 72)?, len(file_count, FILE_RECORD))?,
            file_count,
            chunks_at: section(src, src_u64(src, 80)?, len(chunk_count, CHUNK_RECORD))?,
            chunk_count,
            packs_at: section(src, src_u64(src, 88)?, len(pack_count, PACK_RECORD))?,
            pack_count,
            strings_at: section(src, src_u64(src, 96)?, src_u64(src, 104)?)?,
            strings_len: src_u64(src, 104)?,
        })
    }

    fn layout(src: &'s S) -> Result<Self> {
        let mut magic = [0u8; 8];
        if src.len() < 8 {
            return Err(Error::Invalid);
        }
        src.read_at(0, &mut magic)?;
        if &magic != PAK_MAGIC {
            return Err(Error::Invalid);
        }
        let mut h = [0u8; PAK_HEADER];
        src.read_at(0, &mut h)?;
        if u32_at(&h, 8)? != 4
            || u32_at(&h, 12)? != PAK_HEADER as u32
            || u32_at(&h, 16)? != 0
            || u32_at(&h, 20)? != ENDIAN_MARKER
            || u32_at(&h, 60)? != FILE_RECORD as u32
            || u32_at(&h, 64)? != CHUNK_RECORD as u32
            || u32_at(&h, 68)? != PACK_RECORD as u32
            || u64_at(&h, 120)? != 0
        {
            return Err(Error::Invalid);
        }
        if header_crc(&h, PAK_HEADER, PAK_HEADER_CRC_AT)? != u32_at(&h, PAK_HEADER_CRC_AT)?
            || src_crc32(src, PAK_HEADER as u64, src.len(), 0)? != u32_at(&h, PAK_PAYLOAD_CRC_AT)?
        {
            return Err(Error::Checksum);
        }
        let (file_count, chunk_count, pack_count) = counts(src)?;
        let file_len = u64::from(file_count) * FILE_RECORD as u64;
        let chunk_len = u64::from(chunk_count) * CHUNK_RECORD as u64;
        let pack_len = u64::from(pack_count) * PACK_RECORD as u64;
        let files_at = PAK_HEADER as u64;
        let chunks_at = files_at + file_len;
        let packs_at = chunks_at + chunk_len;
        let strings_at = packs_at + pack_len;
        let strings_len = u64_at(&h, 104)?;
        if u64_at(&h, 72)? != files_at
            || u64_at(&h, 80)? != chunks_at
            || u64_at(&h, 88)? != packs_at
            || u64_at(&h, 96)? != strings_at
            || strings_at.checked_add(strings_len) != Some(src.len())
        {
            return Err(Error::Invalid);
        }
        let mut build_id = [0u8; 16];
        build_id.copy_from_slice(range(&h, 24, 16)?);
        Ok(Self {
            src,
            fast: None,
            sorted: false,
            build_id,
            files_at,
            file_count,
            chunks_at,
            chunk_count,
            packs_at,
            pack_count,
            strings_at,
            strings_len,
        })
    }

    pub fn source(&self) -> &'s S {
        self.src
    }
    pub fn file_count(&self) -> u32 {
        self.file_count
    }
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }
    pub fn pack_count(&self) -> u32 {
        self.pack_count
    }

    // ---- fast table ----

    /// Bytes of the fast table: the file, chunk and pack record sections,
    /// which `layout` placed back to back from the header (48 B per file,
    /// 12 B per chunk, 32 B per pack). Paths stay in the source.
    pub fn fast_len(&self) -> usize {
        usize::try_from(self.strings_at.saturating_sub(self.files_at)).unwrap_or(usize::MAX)
    }

    /// Fills the fast table with one sequential pass over the record
    /// sections, 4 KiB per source read (no_std threads have small stacks).
    /// `Invalid` when `out` is not `fast_len` long or the sections are not
    /// back to back (a `view_trusted` header that `open` would refuse).
    pub fn fill_fast(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != self.fast_len() || !self.sections_contiguous() {
            return Err(Error::Invalid);
        }
        for (n, block) in out.chunks_mut(4096).enumerate() {
            self.src.read_at(self.files_at + (n * 4096) as u64, block)?;
        }
        Ok(())
    }

    /// Makes record reads (files, chunks, packs) use `fast`, filled by
    /// `fill_fast` from this manifest. `Invalid` when its length differs.
    pub fn with_fast(mut self, fast: &'s [u8]) -> Result<Self> {
        if fast.len() != self.fast_len() || !self.sections_contiguous() {
            return Err(Error::Invalid);
        }
        self.fast = Some(fast);
        Ok(self)
    }

    /// Whether file, chunk and pack records are read from memory only.
    pub fn has_fast(&self) -> bool {
        self.fast.is_some()
    }

    fn sections_contiguous(&self) -> bool {
        let len = |count: u32, size: usize| u64::from(count) * size as u64;
        self.chunks_at == self.files_at + len(self.file_count, FILE_RECORD)
            && self.packs_at == self.chunks_at + len(self.chunk_count, CHUNK_RECORD)
            && self.strings_at == self.packs_at + len(self.pack_count, PACK_RECORD)
    }

    /// Record bytes at absolute offset `at` (inside a record section, which
    /// `record_at` checked): from the fast table when there is one.
    fn read_record(&self, at: u64, out: &mut [u8]) -> Result<()> {
        match self.fast {
            Some(f) => {
                let from = (at - self.files_at) as usize;
                let bytes = f.get(from..from + out.len()).ok_or(Error::Truncated)?;
                out.copy_from_slice(bytes);
                Ok(())
            }
            None => self.src.read_at(at, out),
        }
    }

    /// The checked zero-based file record at `id`; reads its path once to
    /// check it against the record's hash.
    pub fn file(&self, id: u32) -> Result<File> {
        self.file_into(id, &mut [0u8; PATH_BUF])
    }

    /// `file` with the checked path left in `buf`.
    fn file_into(&self, id: u32, buf: &mut [u8; PATH_BUF]) -> Result<File> {
        let r = self.file_record(id)?;
        let path = self.string(r.path_offset, r.path_length, buf)?;
        if !logical_path(path) || pak_path_hash(path) != r.path_hash || r.reserved != 0 {
            return Err(Error::Invalid);
        }
        Ok(File {
            path_at: self.strings_at + u64::from(r.path_offset),
            path_len: r.path_length,
            logical_size: r.logical_size,
            mtime: r.mtime,
            first_chunk: r.first_chunk,
            chunk_count: r.chunk_count,
            flags: r.flags,
            block_shift: r.block_shift,
            packing_class: r.packing_class,
        })
    }

    /// Copies `f`'s path into `buf`; `Invalid` when it does not fit.
    pub fn path<'b>(&self, f: &File, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        ampr_format::source::src_bytes(self.src, f.path_at, f.path_len as usize, buf)
    }

    /// Returns the raw, unvalidated zero-based file record at `id`.
    pub fn file_record(&self, id: u32) -> Result<FileRecord> {
        FileRecord::parse(&self.file_record_raw(id)?)
    }

    /// The 48 bytes of file record `id`, for callers that keep the on-disk
    /// layout (the runtime's `AmprPackFileRecord`).
    pub fn file_record_raw(&self, id: u32) -> Result<[u8; FILE_RECORD]> {
        let at = record_at(self.files_at, self.file_count, id, FILE_RECORD)?;
        let mut r = [0u8; FILE_RECORD];
        self.read_record(at, &mut r)?;
        Ok(r)
    }

    /// NUL-terminated string-table entry without interior NULs, copied into
    /// `buf`. `Invalid` when `len` is `PATH_BUF` or more (the PS5 path
    /// limit; the packer never writes longer) or longer than `buf`.
    pub fn string<'b>(&self, off: u32, len: u32, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let end = u64::from(off) + u64::from(len);
        if len as usize >= PATH_BUF || end >= self.strings_len {
            return Err(Error::Invalid);
        }
        let out = buf.get_mut(..len as usize).ok_or(Error::Invalid)?;
        let mut nul = [0xffu8];
        self.src.read_at(self.strings_at + end, &mut nul)?;
        if nul[0] != 0 {
            return Err(Error::Invalid);
        }
        self.src.read_at(self.strings_at + u64::from(off), out)?;
        if out.contains(&0) {
            return Err(Error::Invalid);
        }
        Ok(out)
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
        let at = record_at(self.chunks_at, self.chunk_count, id, CHUNK_RECORD)?;
        let mut r = [0u8; CHUNK_RECORD];
        self.read_record(at, &mut r)?;
        let loc = u64_at(&r, 0)?;
        let desc = u32_at(&r, 8)?;
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

    /// Raw pack record `id`: payload bytes, file size, flags, I/O page
    /// size, name offset and length. No checks.
    fn pack_raw(&self, id: u32) -> Result<(Pack, u32, u32)> {
        let r = self.pack_record_raw(id)?;
        let p = Pack {
            payload_bytes: u64_at(&r, 0)?,
            file_size: u64_at(&r, 8)?,
            flags: u32_at(&r, 24)?,
            io_page_size: u32_at(&r, 28)?,
        };
        Ok((p, u32_at(&r, 16)?, u32_at(&r, 20)?))
    }

    /// The 32 bytes of pack record `id` (the runtime's `AmprPackDataRecord`).
    pub fn pack_record_raw(&self, id: u32) -> Result<[u8; PACK_RECORD]> {
        let at = record_at(self.packs_at, self.pack_count, id, PACK_RECORD)?;
        let mut r = [0u8; PACK_RECORD];
        self.read_record(at, &mut r)?;
        Ok(r)
    }

    /// The checked pack record `id`, its name included.
    pub fn pack(&self, id: u32) -> Result<Pack> {
        let (p, off, len) = self.pack_raw(id)?;
        let mut buf = [0u8; PATH_BUF];
        let name = self.string(off, len, &mut buf)?;
        if !safe_components(name) || !pack_fields_valid(&p) {
            return Err(Error::Invalid);
        }
        Ok(p)
    }

    /// Raw name of pack record `id` copied into `buf`: string-table bounds
    /// only, no pack checks.
    pub fn pack_name<'b>(&self, id: u32, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let (_, off, len) = self.pack_raw(id)?;
        self.string(off, len, buf)
    }

    /// Checks file record `id`; its path is left in `buf`, its length returned.
    fn validate_file(&self, id: u32, buf: &mut [u8; PATH_BUF]) -> Result<usize> {
        let f = self.file_into(id, buf)?;
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
            return Ok(f.path_len as usize);
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
        // The last pack is kept: a file's chunks mostly share one, and each
        // `pack` call reads its record and name through the source.
        let mut last: Option<(u16, Pack)> = None;
        for local in 0..f.chunk_count {
            let c = self.chunk(f.first_chunk + local)?;
            let p = match last {
                Some((id, p)) if id == c.pack_id => p,
                _ => {
                    let p = self.pack(u32::from(c.pack_id))?;
                    last = Some((c.pack_id, p));
                    p
                }
            };
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
        Ok(f.path_len as usize)
    }

    /// Checks a volume header against a manifest pack record and actual volume size.
    pub fn check_volume_header(&self, h: &[u8], pack_id: u32, actual_size: u64) -> Result<()> {
        let p = self.pack(pack_id)?;
        check_volume_header(
            h,
            pack_id,
            &self.build_id,
            p.flags,
            p.file_size,
            p.payload_bytes,
            p.io_page_size,
            actual_size,
        )?;
        Ok(())
    }
}

/// The numeric pack record checks of `Manifest::pack`.
fn pack_fields_valid(p: &Pack) -> bool {
    p.io_page_size.is_power_of_two()
        && (1 << 12..=1 << 20).contains(&p.io_page_size)
        && p.flags & !(PACK_STRIPED | PACK_IO_PAGE_LAYOUT) == 0
        && p.flags & PACK_IO_PAGE_LAYOUT != 0
        && p.file_size >= DAT_HEADER as u64
        && p.payload_bytes <= p.file_size
        && p.payload_offset() >= DAT_HEADER as u64
        && p.payload_offset() % u64::from(p.io_page_size) == 0
        && p.file_size % u64::from(p.io_page_size) == 0
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
