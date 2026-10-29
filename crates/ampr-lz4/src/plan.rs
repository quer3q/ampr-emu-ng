//! Read planning over a mounted manifest: chunk views, page flags and read tasks.
use crate::manifest::{Chunk, FileRecord, Manifest};
use crate::{folded, pak_path_hash, FILE_PACKED};
pub use crate::{CoreError, CoreResult};

/// `AmprPackChunkView`: a chunk plus raw size derived from block geometry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkView {
    pub chunk: Chunk,
    pub raw_size: u32,
}

/// `AmprPackBlockReadTask`; `chunk_index` is the manifest-global chunk index.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadTask {
    pub chunk_index: u32,
    pub source_offset: u32,
    pub copy_length: u32,
    pub destination_offset: u32,
    pub chunk: ChunkView,
}

fn packed_geometry(f: &FileRecord) -> bool {
    f.flags & FILE_PACKED != 0 && (14..=20).contains(&f.block_shift)
}

fn request_valid(f: &FileRecord, offset: u64, length: u64) -> bool {
    packed_geometry(f)
        && length != 0
        && offset <= f.logical_size
        && length <= f.logical_size - offset
}

/// `ampr_pack_core_task_count`: zero for any rejected request.
pub fn task_count(f: &FileRecord, offset: u64, length: u64) -> usize {
    if !request_valid(f, offset, length) {
        return 0;
    }
    let first = offset >> f.block_shift;
    let last = (offset + length - 1) >> f.block_shift;
    usize::try_from(last - first + 1).unwrap_or(0)
}

impl Manifest<'_> {
    /// `ampr_pack_core_make_task`: task `index` of a read of `length` bytes at
    /// `offset` of `f`; see `task_count`.
    pub fn read_task(
        &self,
        f: &FileRecord,
        offset: u64,
        length: u64,
        index: usize,
    ) -> CoreResult<ReadTask> {
        if !request_valid(f, offset, length)
            || u64::from(f.first_chunk) + u64::from(f.chunk_count) > u64::from(self.chunk_count())
        {
            return Err(CoreError::InvalidArgument);
        }
        let block = 1u64 << f.block_shift;
        let first = offset >> f.block_shift;
        let end = offset + length;
        let count = ((end - 1) >> f.block_shift) - first + 1;
        let index = u64::try_from(index).map_err(|_| CoreError::OutOfRange)?;
        if index >= count || first + index >= u64::from(f.chunk_count) {
            return Err(CoreError::OutOfRange);
        }
        let local = first + index;
        let begin = local * block;
        let local = u32::try_from(local).map_err(|_| CoreError::OutOfRange)?;
        let chunk = self.chunk_in_range(f, local)?;
        let copy_begin = core::cmp::max(offset, begin);
        let copy_end = core::cmp::min(end, begin + u64::from(chunk.raw_size));
        let u32_of = |v: u64| u32::try_from(v).map_err(|_| CoreError::InvalidFormat);
        if copy_end <= copy_begin {
            return Err(CoreError::InvalidFormat);
        }
        Ok(ReadTask {
            chunk_index: f.first_chunk.wrapping_add(local),
            source_offset: u32_of(copy_begin - begin)?,
            copy_length: u32_of(copy_end - copy_begin)?,
            destination_offset: u32_of(copy_begin - offset)?,
            chunk,
        })
    }

    /// `ampr_pack_core_validate_logical_file` for one-based `file_id`. Checks
    /// size, request path hash and folded path equality against the record.
    pub fn validate_logical_file(
        &self,
        file_id: u32,
        path: &[u8],
        logical_size: u64,
    ) -> CoreResult<()> {
        let f = file_id
            .checked_sub(1)
            .filter(|&id| id < self.file_count())
            .and_then(|id| self.file_record(id).ok())
            .ok_or(CoreError::InvalidArgument)?;
        let stored = self
            .string(f.path_offset, f.path_length)
            .map_err(|_| CoreError::ChecksumMismatch)?;
        if f.logical_size != logical_size
            || f.path_hash != pak_path_hash(path)
            || stored.len() != path.len()
            || !stored
                .iter()
                .zip(path)
                .all(|(&a, &b)| folded(a) == folded(b))
        {
            return Err(CoreError::ChecksumMismatch);
        }
        Ok(())
    }

    // Caller has checked block shift and the chunk index range.
    fn chunk_in_range(&self, f: &FileRecord, local: u32) -> CoreResult<ChunkView> {
        let id = f
            .first_chunk
            .checked_add(local)
            .ok_or(CoreError::InvalidArgument)?;
        let chunk = self
            .chunk_record(id)
            .map_err(|_| CoreError::InvalidFormat)?;
        let block = 1u64 << f.block_shift;
        let begin = u64::from(local) * block;
        if begin >= f.logical_size {
            return Err(CoreError::InvalidFormat);
        }
        let raw = core::cmp::min(f.logical_size - begin, block);
        Ok(ChunkView {
            chunk,
            raw_size: u32::try_from(raw).map_err(|_| CoreError::InvalidFormat)?,
        })
    }
}
