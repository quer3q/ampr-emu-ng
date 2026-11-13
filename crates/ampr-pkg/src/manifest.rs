//! AMPRPAK4 validation for pkg mode. Pack 0 is the .pkg itself, so its
//! chunks may be KRAKEN blocks, sit at any offset (blocks lie back to back
//! in the .pkg), and RAW and KRAKEN chunks skip the page-layout flag rules
//! (the runtime reads each chunk with an exact-size read). Packs 1 and up stay as
//! strict as `Manifest::open`.
use crate::{kraken_chunk_ok, split_kraken_location, CHUNK_KRAKEN, CHUNK_KRAKEN_FULL};
use ampr_format::source::{src_crc32, Source};
use ampr_lz4::manifest::{Chunk, Manifest};
use ampr_lz4::{
    header_crc, u32_at, u64_at, Error, Result, CHUNK_LZ4, CHUNK_PAGE_ALIGNED, CHUNK_PAGE_CONTAINED,
    CHUNK_RAW, CHUNK_RECORD, CHUNK_STREAMING, ENDIAN_MARKER, FILE_PACKED, FILE_RANDOM_ACCESS,
    FILE_RECORD, FILE_STORE_ONLY, FILE_STREAMING, PACK_RECORD, PAK_HEADER, PAK_HEADER_CRC_AT,
    PAK_MAGIC, PAK_PAYLOAD_CRC_AT,
};

/// `Manifest::open` with the pack 0 rules above, through any `Source`: a
/// resident image or the runtime's index page cache, so a pkg manifest too
/// large for the Index ledger is paged like an LZ4 one. The returned view is
/// `view_trusted`, so `records_sorted` is false.
pub fn open_pkg<S: Source + ?Sized>(src: &S) -> Result<Manifest<'_, S>> {
    check_header(src)?;
    let m = Manifest::view_trusted(src)?;
    for id in 0..m.pack_count() {
        m.pack(id)?;
    }
    for id in 0..m.file_count() {
        validate_file(&m, id)?;
    }
    Ok(m)
}

/// (offset, pack_id, kraken) of a chunk record. `chunk_record` splits the
/// location at bit 48; a KRAKEN location is offset (bits 0..39) | block
/// descriptor above it, pack 0 implied, so it is rebuilt and split again.
pub fn pkg_chunk(c: Chunk) -> (u64, u16, u32) {
    if c.codec != CHUNK_KRAKEN {
        return (c.offset, c.pack_id, 0);
    }
    let (offset, kraken) = split_kraken_location(c.offset | u64::from(c.pack_id) << 48);
    (offset, 0, kraken)
}

/// The header checks of `Manifest::open`, which keeps them private:
/// fields, both CRCs, and sections back to back up to the end.
fn check_header<S: Source + ?Sized>(src: &S) -> Result<()> {
    let len = src.len();
    if len < PAK_HEADER as u64 {
        return Err(Error::Invalid);
    }
    let mut h = [0u8; PAK_HEADER];
    src.read_at(0, &mut h)?;
    let bytes = &h[..];
    if &bytes[..8] != PAK_MAGIC {
        return Err(Error::Invalid);
    }
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
        || src_crc32(src, PAK_HEADER as u64, len, 0)? != u32_at(bytes, PAK_PAYLOAD_CRC_AT)?
    {
        return Err(Error::Checksum);
    }
    let after = |at: u64, count: u64, size: usize| {
        count
            .checked_mul(size as u64)
            .and_then(|len| at.checked_add(len))
            .ok_or(Error::Invalid)
    };
    let files_at = PAK_HEADER as u64;
    let chunks_at = after(files_at, u64_at(bytes, 40)?, FILE_RECORD)?;
    let packs_at = after(chunks_at, u64_at(bytes, 48)?, CHUNK_RECORD)?;
    let strings_at = after(packs_at, u64::from(u32_at(bytes, 56)?), PACK_RECORD)?;
    if u64_at(bytes, 72)? != files_at
        || u64_at(bytes, 80)? != chunks_at
        || u64_at(bytes, 88)? != packs_at
        || u64_at(bytes, 96)? != strings_at
        || strings_at.checked_add(u64_at(bytes, 104)?) != Some(len)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Upstream `validate_file`, loosened for pack 0 only.
fn validate_file<S: Source + ?Sized>(m: &Manifest<'_, S>, id: u32) -> Result<()> {
    let f = m.file(id)?;
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
        || u64::from(f.first_chunk) + u64::from(f.chunk_count) > u64::from(m.chunk_count())
    {
        return Err(Error::Invalid);
    }
    let block = 1u64 << f.block_shift;
    let expected = f.logical_size / block + u64::from(f.logical_size % block != 0);
    if u64::from(f.chunk_count) != expected {
        return Err(Error::Invalid);
    }
    // The last pack is kept, as in ampr-lz4: a file's chunks mostly share
    // one, and each `pack` call reads and checks its record and name.
    let mut last = None;
    for local in 0..f.chunk_count {
        let c = m.chunk_record(f.first_chunk + local)?;
        let kraken = c.codec == CHUNK_KRAKEN;
        let known = if kraken {
            0x0f | CHUNK_KRAKEN_FULL
        } else {
            0x0f
        };
        if c.codec != CHUNK_RAW && c.codec != CHUNK_LZ4 && !kraken || c.flags & !known != 0 {
            return Err(Error::Invalid);
        }
        let (offset, pack_id, desc) = pkg_chunk(c);
        let p = match last {
            Some((id, p)) if id == pack_id => p,
            _ => {
                let p = m.pack(u32::from(pack_id))?;
                last = Some((pack_id, p));
                p
            }
        };
        let raw = core::cmp::min(block, f.logical_size - u64::from(local) * block);
        let stored = u64::from(c.stored_size);
        let page = u64::from(p.io_page_size);
        let end = offset.checked_add(stored).ok_or(Error::Invalid)?;
        let contained = c.flags & CHUNK_PAGE_CONTAINED != 0;
        let aligned = c.flags & CHUNK_PAGE_ALIGNED != 0;
        let streaming = c.flags & CHUNK_STREAMING != 0;
        let loose = pack_id == 0;
        if stored > block
            || kraken && !kraken_chunk_ok(raw, stored, desc)
            || c.codec == CHUNK_RAW && stored != raw
            || f.flags & FILE_STORE_ONLY != 0 && c.codec != CHUNK_RAW
            || streaming != (f.flags & FILE_STREAMING != 0)
            || offset < p.payload_offset()
            || end > p.file_size
            || !loose && offset % 64 != 0
            || contained && (stored > page || offset / page != (end - 1) / page)
            || aligned && (offset % page != 0 || stored <= page && !contained)
            || !streaming
                && !(loose && (kraken || c.codec == CHUNK_RAW))
                && ((stored <= page && !contained)
                    || (stored > page && !aligned)
                    || (c.codec == CHUNK_RAW && stored >= page && !aligned))
            || offset / page * page < p.payload_offset()
            || end.checked_add(page - 1).ok_or(Error::Invalid)? / page * page > p.file_size
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
