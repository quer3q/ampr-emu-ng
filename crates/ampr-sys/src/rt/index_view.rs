//! Memory for the compiled index view: two `index_alloc` blocks from the
//! Index ledger (rt/index_memory.rs), carved into the column slices of
//! `ampr_format::view::Buffers`, each column at its type's alignment (the
//! 32-byte file rows at 32, so a row is in one cache line). The
//! resident block holds the columns `View` reads; the transient block holds
//! the ones only the `Builder` and the pack join read (`dir_of`, 4 B per
//! file, and `lz4_hash`, 8 B per file with LZ4 packs), and is given back
//! right after `Builder::finish`, because a ledger block cannot shrink.
//! The directory count is not known before the build, so `build` starts at
//! `files / 8 + 1024` directories and doubles on `Error::OutOfRange` while
//! the ledger has room; each retry reads the index again through its
//! source.

use super::index_memory::{index_alloc, index_free};
use super::stats;
use ampr_format::index::Index;
use ampr_format::source::Source;
use ampr_format::view::{self, Buffers, Builder, Dir, Packs, Row, Sizes};
use ampr_format::Error;
use core::ffi::c_void;
use core::mem::{align_of, size_of};

/// `collide` entries: `view::build` refuses an index with more ids whose
/// hash another file shares; 256 is far above what a 64-bit hash gives
/// real indexes.
pub(crate) const COLLIDE_MAX: usize = 256;

const TAG: &core::ffi::CStr = c"index.view";
const SCRATCH_TAG: &core::ffi::CStr = c"index.view.build";

// ---- layout ----

/// Byte offset of each column in its block and the two block sizes:
/// `bytes` for the resident block, `scratch` for the transient one
/// (`lz4_hash` and `dir_of`). The rows come first, at the block's page
/// start, then the 8-byte columns, so the 4-byte ones need no padding;
/// `place` aligns each anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub sizes: Sizes,
    pub packs: Packs,
    rows: usize,
    lz4_hash: usize,
    dirs: usize,
    chunk: usize,
    slots: usize,
    dir_slots: usize,
    collide: usize,
    dir_of: usize,
    pub bytes: usize,
    pub scratch: usize,
}

/// Offset of `count` elements of `T` at or past `*end`, aligned for `T`;
/// moves `*end` past them. None on overflow.
fn place<T>(end: &mut usize, count: usize) -> Option<usize> {
    let at = end.checked_next_multiple_of(align_of::<T>())?;
    *end = at.checked_add(count.checked_mul(size_of::<T>())?)?;
    Some(at)
}

/// The block for `files` files and `dir_cap` directories; None when
/// `view::sizes` refuses the counts or the bytes overflow.
pub(crate) fn layout(files: u32, dir_cap: u32, packs: Packs) -> Option<Layout> {
    let sizes = view::sizes(files, dir_cap)?;
    let n = files as usize;
    let (chunk, lz4) = sizes.pack_columns(packs);
    let (mut end, mut tmp) = (0, 0);
    Some(Layout {
        sizes,
        packs,
        rows: place::<Row>(&mut end, n)?,
        lz4_hash: place::<u64>(&mut tmp, lz4)?,
        dirs: place::<Dir>(&mut end, dir_cap as usize)?,
        chunk: place::<u32>(&mut end, chunk)?,
        slots: place::<u32>(&mut end, sizes.file_slots as usize)?,
        dir_slots: place::<u32>(&mut end, sizes.dir_slots as usize)?,
        collide: place::<u32>(&mut end, COLLIDE_MAX)?,
        dir_of: place::<u32>(&mut tmp, n)?,
        bytes: end,
        scratch: tmp,
    })
}

/// The first directory capacity tried for `files` files.
pub(crate) fn first_dir_cap(files: u32) -> u32 {
    files / 8 + 1024
}

// ---- block ----

/// The two Index ledger blocks of a view. It owns them: `free_scratch`
/// gives back the transient one, `free` both, and dropping it without
/// `free` leaks them in the ledger.
pub(crate) struct ViewMem {
    ptr: *mut u8,
    /// The transient block; null once `free_scratch` gave it back.
    scratch: *mut u8,
    layout: Layout,
}

// SAFETY: the blocks are plain memory owned by this value alone.
unsafe impl Send for ViewMem {}

/// `bytes` zeroed bytes from the Index ledger, or null when it refuses them
/// (the one-time index notice is sent there).
fn alloc_zeroed(bytes: usize, tag: &core::ffi::CStr) -> *mut u8 {
    // SAFETY: `tag` is a C string; the size and alignment are checked by
    // `index_alloc`.
    let ptr = unsafe { index_alloc(bytes, align_of::<Row>(), tag.as_ptr()) };
    if !ptr.is_null() {
        // SAFETY: `index_alloc` gave `bytes` writable bytes at `ptr`.
        unsafe { core::ptr::write_bytes(ptr, 0, bytes) };
    }
    ptr
}

impl ViewMem {
    /// Both blocks for `layout`, zeroed, so every column holds valid values
    /// before `view::build` writes it. None, with nothing taken, when the
    /// ledger refuses either.
    pub(crate) fn alloc(layout: Layout) -> Option<Self> {
        let ptr = alloc_zeroed(layout.bytes, TAG);
        if ptr.is_null() {
            return None;
        }
        let scratch = alloc_zeroed(layout.scratch, SCRATCH_TAG);
        if scratch.is_null() {
            // SAFETY: `ptr` came from `index_alloc` and has no user yet.
            unsafe { index_free(ptr.cast::<c_void>(), TAG.as_ptr()) };
            return None;
        }
        // The resident block counts in `index_view_bytes` until `free`;
        // a failed build try takes its count back with its block.
        stats::add(stats::Stat::IndexViewBytes, layout.bytes as u64);
        Some(Self {
            ptr,
            scratch,
            layout,
        })
    }

    #[cfg(test)]
    pub(crate) fn layout(&self) -> Layout {
        self.layout
    }

    /// Bytes of the resident block as asked of the ledger (it page-rounds
    /// them).
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.layout.bytes
    }

    /// Bytes of the transient block as asked of the ledger; 0 once
    /// `free_scratch` gave it back.
    #[cfg(test)]
    pub(crate) fn scratch_bytes(&self) -> usize {
        if self.scratch.is_null() {
            0
        } else {
            self.layout.scratch
        }
    }

    /// `len` elements of `T` at byte offset `at` of the block at `base`.
    ///
    /// # Safety
    /// As for `buffers`; `at` and `len` come from `self.layout` for the
    /// block at `base`.
    unsafe fn column<'a, T>(base: *mut u8, at: usize, len: usize) -> &'a mut [T] {
        // SAFETY: `layout` placed `len` aligned `T`s at `at` inside the
        // block (`at` may be its end when `len` is 0); the block is zeroed
        // and every column type is plain integers, valid at any bits.
        unsafe { core::slice::from_raw_parts_mut(base.add(at).cast::<T>(), len) }
    }

    /// The blocks carved into `Buffers`, lengths as `view::sizes` and
    /// `Sizes::pack_columns` give them.
    ///
    /// # Safety
    /// The blocks outlive `'a` (no `free` before; for `dir_of` and
    /// `lz4_hash`, no `free_scratch` before), `free_scratch` has not run,
    /// and no other `Buffers` of them, nor a `Builder` or `View` built from
    /// one, is live while these are written.
    pub(crate) unsafe fn buffers<'a>(&mut self) -> Buffers<'a> {
        let l = self.layout;
        let (p, t) = (self.ptr, self.scratch);
        let n = l.sizes.files as usize;
        let (chunk, lz4) = l.sizes.pack_columns(l.packs);
        // SAFETY: the caller's promise; the columns do not overlap.
        unsafe {
            Buffers {
                rows: Self::column(p, l.rows, n),
                chunk: Self::column(p, l.chunk, chunk),
                slots: Self::column(p, l.slots, l.sizes.file_slots as usize),
                dirs: Self::column(p, l.dirs, l.sizes.dir_cap as usize),
                dir_slots: Self::column(p, l.dir_slots, l.sizes.dir_slots as usize),
                collide: Self::column(p, l.collide, COLLIDE_MAX),
                dir_of: Self::column(t, l.dir_of, n),
                lz4_hash: Self::column(t, l.lz4_hash, lz4),
            }
        }
    }

    /// Gives the transient block back to the Index ledger; a no-op once
    /// done. A `View` reads none of its columns.
    ///
    /// # Safety
    /// No `Buffers` or `Builder` of the blocks is used afterwards.
    pub(crate) unsafe fn free_scratch(&mut self) {
        let t = core::mem::replace(&mut self.scratch, core::ptr::null_mut());
        if !t.is_null() {
            // SAFETY: `t` came from `index_alloc` and is freed once, here.
            unsafe { index_free(t.cast::<c_void>(), SCRATCH_TAG.as_ptr()) };
        }
    }

    /// Gives both blocks back to the Index ledger.
    ///
    /// # Safety
    /// No `Buffers`, `Builder` or `View` of the blocks is used afterwards.
    pub(crate) unsafe fn free(mut self) {
        // SAFETY: the caller's promise covers both blocks; `ptr` came from
        // `index_alloc` and is freed once, here.
        unsafe {
            self.free_scratch();
            index_free(self.ptr.cast::<c_void>(), TAG.as_ptr());
        }
        stats::sub(stats::Stat::IndexViewBytes, self.layout.bytes as u64);
    }
}

// ---- build ----

/// Why `build` gave no view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// The Index ledger refused the block (`LoadResult::Memory`).
    Memory,
    /// `view::build` refused the index.
    Format(Error),
}

/// Most directories `idx` can have: each one but `/app0` ends at a `/` of
/// some path, a distinct byte of the path blob.
fn dir_ceiling(path_bytes: u64) -> u32 {
    path_bytes.saturating_add(1).min(u64::from(u32::MAX >> 1)) as u32
}

/// Builds the view of `idx` into a `ViewMem`, starting at `first_dir_cap`
/// directories. On `Error::OutOfRange` it builds again at the count the
/// failed pass took (`view::build_sized`), so a title with more
/// directories reads its index twice, not once per doubling (four times
/// for one file per directory); it doubles only when no count came back
/// or the count did not hold, up to `dir_ceiling`. The blocks of a failed
/// try are freed before the next are asked. On
/// success the caller owns the blocks: it joins the packs into the
/// `Builder`, finishes it, calls `free_scratch`, and frees the `ViewMem`
/// after the last use of the view.
///
/// # Safety
/// The `Builder` and the `View` it finishes into are not used after the
/// returned `ViewMem` is freed.
pub(crate) unsafe fn build<'a, S: Source + ?Sized>(
    idx: &Index<'_, S>,
    packs: Packs,
) -> Result<(ViewMem, Builder<'a>), BuildError> {
    let files = idx.len();
    // `path_at` is a `u32` file offset; past 4 GiB `view::build` answers
    // `OutOfRange`, which must not read as a full directory table.
    if files == 0 || idx.source().len() > u64::from(u32::MAX) + 1 {
        return Err(BuildError::Format(if files == 0 {
            Error::Invalid
        } else {
            Error::OutOfRange
        }));
    }
    let ceiling = dir_ceiling(idx.layout().path_bytes);
    let mut dir_cap = first_dir_cap(files).min(ceiling);
    // The capacity before a jump to the failed pass's count: that count is
    // exact for a sorted index but only an upper bound for an unsorted one,
    // so a jump that does not fit falls back to doubling from here.
    let mut before_jump: Option<u32> = None;
    loop {
        let Some(mut mem) = layout(files, dir_cap, packs).and_then(ViewMem::alloc) else {
            match before_jump.take() {
                Some(prev) if prev < dir_cap => {
                    dir_cap = prev.saturating_mul(2).min(ceiling);
                    continue;
                }
                _ => return Err(BuildError::Memory),
            }
        };
        // SAFETY: the blocks live until the caller frees `mem`, and these
        // are their only buffers.
        let mut needed = 0;
        match view::build_sized(idx, unsafe { mem.buffers() }, &mut needed) {
            Ok(b) => return Ok((mem, b)),
            Err(e) => {
                // SAFETY: the failed build's buffers are gone with it.
                unsafe { mem.free() };
                if e != Error::OutOfRange || dir_cap >= ceiling {
                    return Err(BuildError::Format(e));
                }
            }
        }
        let doubled = dir_cap.saturating_mul(2);
        before_jump = (needed > doubled).then_some(dir_cap);
        dir_cap = if needed > dir_cap { needed } else { doubled }.min(ceiling);
    }
}

#[cfg(test)]
mod tests {
    use super::super::index::{fill_image, image_layout};
    use super::super::index_memory as im;
    use super::*;
    use ampr_format::view::Hit;
    use std::format;
    use std::vec::Vec;

    /// A sorted AMPRIDX3 image of `n` files, file `i` alone in directory
    /// `/app0/dNNNNN`, so the directories (`n` + 1) outgrow the first
    /// capacity once `n` is past about 1170.
    fn image(n: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let paths: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("/app0/d{i:05}/f.bin").into_bytes())
            .collect();
        let (mut records, mut blob) = (Vec::new(), Vec::new());
        for (i, p) in paths.iter().enumerate() {
            records.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&(i as u64).to_le_bytes());
            records.extend_from_slice(&0i64.to_le_bytes());
            blob.extend_from_slice(p);
            blob.push(0);
        }
        let l = image_layout(n, blob.len() as u64).unwrap();
        let mut img = std::vec![0u8; l.map_bytes];
        assert!(fill_image(&mut img, &l, &records, &blob));
        img.truncate(l.file_bytes);
        (img, paths)
    }

    #[test]
    fn columns_are_aligned_and_apart() {
        for packs in [Packs::None, Packs::Lz4, Packs::Zstd] {
            let l = layout(1000, 300, packs).unwrap();
            let (chunk, lz4) = l.sizes.pack_columns(packs);
            let n = 1000;
            let resident = [
                (l.rows, n * 32, 32),
                (l.dirs, 300 * size_of::<Dir>(), align_of::<Dir>()),
                (l.chunk, chunk * 4, 4),
                (l.slots, l.sizes.file_slots as usize * 4, 4),
                (l.dir_slots, l.sizes.dir_slots as usize * 4, 4),
                (l.collide, COLLIDE_MAX * 4, 4),
            ];
            let transient = [(l.lz4_hash, lz4 * 8, 8), (l.dir_of, n * 4, 4)];
            for (cols, bytes) in [(&resident[..], l.bytes), (&transient[..], l.scratch)] {
                let mut end = 0;
                for &(at, len, align) in cols {
                    assert_eq!(at % align, 0);
                    assert!(at >= end);
                    end = at + len;
                }
                assert_eq!(end, bytes);
            }
        }
        assert_eq!(layout(0, 300, Packs::None), None);
    }

    /// The sizes rt/index_memory.rs `INDEX_MEMORY_MAX` quotes for 300,000
    /// files at the first directory capacity, in KiB: the build's peak
    /// (both blocks), then the resident block alone after `finish`. The
    /// 32-byte file rows added 1,171 KiB (4 B per file) without packs and
    /// nothing with them.
    #[test]
    fn view_bytes_at_300k_files() {
        let kib = |packs| {
            let l = layout(300_000, first_dir_cap(300_000), packs).unwrap();
            ((l.bytes + l.scratch) >> 10, l.bytes >> 10)
        };
        assert_eq!(kib(Packs::None), (14_055, 12_883));
        assert_eq!(kib(Packs::Zstd), (15_227, 14_055));
        assert_eq!(kib(Packs::Lz4), (16_399, 12_883));
    }

    /// 3000 directories outgrow the first 1399: the failed pass counts
    /// 3001 (with `/app0`) and the second builds at exactly that, every path, directory and miss answers from the view in pool
    /// memory, and the free gives every byte back.
    #[test]
    fn a_view_builds_in_the_ledger_and_frees_to_zero() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000;
        let (img, paths) = image(n);
        let idx = Index::open(&img[..]).unwrap();
        let used = im::test_index_used();
        for packs in [Packs::None, Packs::Zstd] {
            let (mem, b) = unsafe { build(&idx, packs) }.unwrap();
            assert_eq!(mem.layout().sizes.dir_cap, n as u32 + 1);
            let scratch = mem.scratch_bytes().next_multiple_of(16 << 10);
            assert!(scratch > 0);
            assert!(im::test_index_used() >= used + mem.bytes() + scratch);
            let mut mem = mem;
            let v = b.finish();
            let before = im::test_index_used();
            unsafe { mem.free_scratch() };
            assert_eq!(im::test_index_used(), before - scratch);
            assert_eq!(v.files(), n as u32);
            assert_eq!(v.dir_count(), n as u32 + 1);
            // The rows start the block, so each is in one 64-byte line.
            assert_eq!((mem.ptr as usize + mem.layout().rows) % align_of::<Row>(), 0);
            for (i, p) in paths.iter().enumerate() {
                let id = i as u32 + 1;
                assert_eq!(v.lookup(&img[..], p).unwrap(), Hit::File(id));
                assert_eq!((v.size(id), v.mtime(id)), (i as u64, 0));
                assert!(!v.packed(id));
                let Hit::Dir(d) = v.lookup(&img[..], &p[..12]).unwrap() else {
                    panic!("no directory for {:?}", &p[..12]);
                };
                assert_eq!(v.dir(d).first_file, view::NONE);
            }
            assert_eq!(
                v.lookup(&img[..], b"/app0/d99999/f.bin").unwrap(),
                Hit::Miss
            );
            assert!(matches!(v.lookup(&img[..], b"/app0").unwrap(), Hit::Dir(_)));
            unsafe { mem.free() };
            assert_eq!(im::test_index_used(), used);
        }
    }

    /// With less Index room than the first block, the build is refused as
    /// `Memory` with the index notice and takes nothing; with room for the
    /// first block but not the doubled one, the first is given back too.
    #[test]
    fn no_room_is_memory_and_takes_nothing() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000;
        let (img, _) = image(n);
        let idx = Index::open(&img[..]).unwrap();
        let first = layout(n as u32, first_dir_cap(n as u32), Packs::None).unwrap();
        let used = im::test_index_used();
        let page = 16 << 10;
        for room in [first.bytes / 2, first.bytes.next_multiple_of(page)] {
            let fill = im::index_room() - room;
            let other = unsafe { im::index_alloc(fill, page, c"test.view.other".as_ptr()) };
            assert!(!other.is_null());
            im::test_take_index_notice();
            let r = unsafe { build(&idx, Packs::None) };
            assert_eq!(r.err(), Some(BuildError::Memory));
            assert!(im::test_take_index_notice());
            assert_eq!(im::test_index_used(), used + fill.next_multiple_of(page));
            unsafe { im::index_free(other.cast(), c"test.view.other.free".as_ptr()) };
            assert_eq!(im::test_index_used(), used);
        }
    }
}
