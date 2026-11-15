//! zstd mount state (pack format: docs/zstd-format.md):
//! the immutable `/app0/ampr_zstd.index` image, joined to the compiled
//! index view at mount. AMPRIDX3 stays the path and file-id authority; a
//! zstd record number is never an AMPR id.
//!
//! Public accessors. Each returns `None`/`0`/`false` until the mount is
//! ready (`LOAD_STATE == PACK_LOAD_READY`):
//! - `zstd_index() -> Option<&'static ZstdIndex>`: the mounted, fully
//!   validated zstd index, its chunk and volume tables resident in the
//!   Index ledger; it never reads its file after the mount.
//! - `zstd_extent(ampr_id) -> Option<ZstdExtent>`: first chunk, chunk
//!   count and logical size of a packed one-based AMPRIDX3 id, from the
//!   view (memory only); `None` = loose or unknown id.
//! - `zstd_volume_count() -> u32`, `zstd_volume_size(volume) -> Option<u64>`.
//! - `zstd_chunk_count() -> u32`: zstd chunk (= read task) records.
//!
//! Directory listings walk the published view for every pack format
//! (rt/pack/directories.rs); `zstd_name_hidden` (ampr_zstd.index and
//! mounted ampr_zstd-NNN.pak) backs `ampr_rust_overlay_service_name_hidden`
//! in overlay_ffi.rs.
//!
//! Mount lifecycle, called only from manifest.rs: `zstd_mount_fd`,
//! `zstd_mount_clear`, `zstd_mount_release`.
//!
//! Core tasks: `zstd_core_{task_count,make_task}` are the bodies of the
//! `ampr_pack_core_*` exports in rt/index.rs, their `file` argument a
//! `ZstdExtent`; `zstd_task_count`/`zstd_read_task` hold the task math.
//! An open checks no path: the join checked every packed id's size.
//!
//! The join runs in the index load: `ensure_ready_slow` (rt/index.rs)
//! hands its view `Builder` to the mount before it publishes the index,
//! so the mount reads no published AMPRIDX3 entry. `view_join::join_zstd`
//! sets each packed row's first chunk and links it into its directory;
//! reads, opens and maps take the view's chunk and size (`zstd_extent`),
//! and listings walk the view. Nothing is kept per zstd record. A packed
//! path whose logical size differs from AMPRIDX3 invalidates the mount
//! (`LOAD_STATE = PACK_LOAD_INVALID`).

use super::*;
use crate::rt::index_file::{FileSource, WINDOW};
use crate::rt::index_memory as im;
use ampr_format::source::Source;
use ampr_format::view::Builder;
use ampr_format::zstd::Index;
use core::sync::atomic::AtomicI32;

/// The mounted index, read through `ZSTD_FILE` during the mount only.
pub(crate) type ZstdIndex = Index<'static, ZstdFile>;

pub(crate) const AMPR_EMU_ZSTD_INDEX_PATH: &CStr = c"/app0/ampr_zstd.index";
// The index paths here spell the format crate's `INDEX_NAME`.
const _: () = assert!(
    ends_with(
        AMPR_EMU_ZSTD_INDEX_PATH.to_bytes(),
        ampr_format::zstd::INDEX_NAME.as_bytes()
    ) && ends_with(
        ZSTD_INDEX_LOGICAL_PATH,
        ampr_format::zstd::INDEX_NAME.as_bytes()
    )
);

const fn ends_with(path: &[u8], name: &[u8]) -> bool {
    if path.len() <= name.len() || path[path.len() - name.len() - 1] != b'/' {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if path[path.len() - name.len() + i] != name[i] {
            return false;
        }
        i += 1;
    }
    true
}
pub(crate) const ZSTD_INDEX_MIN_BYTES: usize = ampr_format::zstd::INDEX_HEADER_SIZE;
struct ZstdMount {
    /// The index, its chunk and volume tables at `tables`.
    index: Option<ZstdIndex>,
    /// The chunk and volume tables (8 B per chunk and per volume),
    /// `tables_bytes` of Index memory; null before a mount.
    tables: *mut u64,
    tables_bytes: usize,
}

impl ZstdMount {
    const EMPTY: Self = Self {
        index: None,
        tables: null_mut(),
        tables_bytes: 0,
    };
}

/// Written by the single manifest loader before `LOAD_STATE` turns ready;
/// read-only afterwards until shutdown.
static ZSTD_MOUNT: SyncCell<ZstdMount> = SyncCell::new(ZstdMount::EMPTY);

// ---- join ------------------------------------------------------

/// The zstd path of an AMPRIDX3 path: `/app0/<rel>` (`app0` case-folded, as
/// AMPRIDX3 stores it) gives `<rel>` with its case kept. The join test's
/// oracle; the runtime joins by hash and checks no path at open.
#[cfg(test)]
pub(crate) fn ampr_relative_path(path: &[u8]) -> Option<&[u8]> {
    (path.len() > 6
        && path[0] == b'/'
        && path[5] == b'/'
        && path[1..5].eq_ignore_ascii_case(b"app0"))
    .then(|| &path[6..])
}

// ---- mount lifecycle (manifest.rs) -------------------------------------------------

/// A pread that fills the whole slice at the offset (false on an error or
/// a short file).
pub(crate) type ReadAt = fn(u64, &mut [u8]) -> bool;

/// The index file as the mount reads it: through the two 64 KiB windows
/// of a `FileSource` (rt/index_file.rs) while the mount runs, so the CRC
/// pass, the chunk table fill and the join, all sequential, cost one
/// pread per 64 KiB block of each stream. The mounted index answers from
/// its chunk and volume tables and never reads the file again, so the
/// windows go back to the ledger and the fd is closed when the mount
/// ends; a read after that is `Io`. Written only by the single manifest
/// loader before `LOAD_STATE` turns ready.
pub(crate) struct ZstdFile(SyncCell<ZstdFileState>);

struct ZstdFileState {
    len: u64,
    reader: Option<FileSource<'static, ReadAt>>,
}

impl Source for ZstdFile {
    fn len(&self) -> u64 {
        // SAFETY: `len` is written only by the loader before the index
        // that reads it is published.
        unsafe { (*self.0.get()).len }
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
        // SAFETY: `reader` is set, used and cleared only by the loader
        // thread inside `zstd_mount_join`; after it nothing writes it.
        match unsafe { &(*self.0.get()).reader } {
            Some(r) => r.read_at(at, out),
            None => Err(ampr_format::Error::Io),
        }
    }
}

static ZSTD_FILE: ZstdFile = ZstdFile(SyncCell::new(ZstdFileState {
    len: 0,
    reader: None,
}));

/// The fd `read_mount` reads, set only while `zstd_mount_fd` runs.
static MOUNT_FD: AtomicI32 = AtomicI32::new(-1);

fn read_mount(at: u64, out: &mut [u8]) -> bool {
    let fd = MOUNT_FD.load(Ordering::Relaxed);
    unsafe { pread_exact(fd, out.as_mut_ptr().cast(), out.len(), at) }
}

/// Bytes of the chunk and volume tables: 8 B per chunk and per volume.
fn table_bytes(chunks: u64, volumes: u64) -> usize {
    let n = chunks.saturating_add(volumes).saturating_mul(8);
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// manifest.rs `load_manifest`: mounts the open index file `fd` of `len`
/// bytes (`zstd_mount_join`), then closes `fd`.
pub(crate) unsafe fn zstd_mount_fd(fd: c_int, len: u64, b: &mut Builder<'_>) -> bool {
    MOUNT_FD.store(fd, Ordering::Relaxed);
    let ok = unsafe { zstd_mount_join(len, read_mount, b) };
    MOUNT_FD.store(-1, Ordering::Relaxed);
    if let Some(close_fn) = unsafe { real_close() } {
        unsafe { close_fn(fd) };
    }
    ok
}

/// Mounts the `len`-byte index file `read` reads: the full `Index::open`
/// validation (its CRC pass included), the runtime caps, the chunk and
/// volume tables filled into one Index block, then the join to the view
/// `b` (`view_join::join_zstd` sets each packed row's first chunk and
/// links it for the listings). The header alone sizes the tables first,
/// so an index whose tables and windows do not fit the Index room is
/// refused with the index notice before the file is read. On failure the
/// caller releases what it took (`zstd_mount_release`), and rows already
/// joined stay linked in `b`: readers gate on `LOAD_STATE`, which the
/// caller sets invalid.
pub(crate) unsafe fn zstd_mount_join(len: u64, read: ReadAt, b: &mut Builder<'_>) -> bool {
    let mut head = [0u8; ampr_format::zstd::INDEX_HEADER_SIZE];
    if !read(0, &mut head) {
        return false;
    }
    let Ok((_, chunks, volumes)) = ampr_format::zstd::header_counts(&head) else {
        return false;
    };
    let needed = table_bytes(chunks, u64::from(volumes)).saturating_add(2 * WINDOW);
    if needed > im::index_room() {
        unsafe { im::index_refused(needed) };
        return false;
    }
    let tag = c"apr.zstd.index.windows";
    let windows = unsafe { im::index_alloc(2 * WINDOW, SCE_KERNEL_PAGE_SIZE, tag.as_ptr()) };
    if windows.is_null() {
        return false;
    }
    // SAFETY: the block holds two windows, apart, used only by the reader,
    // which is dropped before the block is freed.
    let (wa, wb) = unsafe {
        (
            &mut *windows.cast::<[u8; WINDOW]>(),
            &mut *windows.add(WINDOW).cast::<[u8; WINDOW]>(),
        )
    };
    let file = unsafe { &mut *ZSTD_FILE.0.get() };
    *file = ZstdFileState {
        len,
        reader: Some(FileSource::new(len, read, wa, wb)),
    };
    let ok = unsafe { mount_from_file(b) };
    file.reader = None;
    unsafe { im::index_free(windows.cast(), c"apr.zstd.index.windows.release".as_ptr()) };
    ok
}

/// `zstd_mount_join` once `ZSTD_FILE` reads the file: the index, its
/// tables and the join.
unsafe fn mount_from_file(b: &mut Builder<'_>) -> bool {
    let Ok(index) = Index::open(&ZSTD_FILE) else {
        return false;
    };
    if index.file_count() > AMPR_EMU_PACK_MAX_FILES
        || u64::from(index.chunk_count()) > AMPR_EMU_PACK_MAX_CHUNKS
        || index.volume_count() as usize > AMPR_EMU_PACK_MAX_PACKS
        || u64::from(b.files()) > AMPR_EMU_PACK_MAX_FILES
    {
        return false;
    }
    let mount = unsafe { &mut *ZSTD_MOUNT.get() };
    *mount = ZstdMount::EMPTY;
    let Some(index) = (unsafe { attach_chunks(index, mount) }) else {
        return false;
    };
    // A size mismatch or an unusable record is `Invalid`, a read error
    // `Io`: either way the mount fails.
    let joined = ampr_format::view_join::join_zstd(b, &index).is_ok();
    mount.index = Some(index);
    joined
}

/// The chunk and volume tables, in one Index allocation filled by one
/// pass over them: chunk records and volume sizes then read memory only,
/// which the read jobs and the fault handler need. None when the
/// allocation is refused or on a read error.
unsafe fn attach_chunks(index: ZstdIndex, mount: &mut ZstdMount) -> Option<ZstdIndex> {
    let (c, v) = index.chunk_lens();
    let bytes = table_bytes(c as u64, v as u64).max(8);
    let p = unsafe { im::index_alloc(bytes, 8, c"apr.zstd.chunks".as_ptr()) }.cast::<u64>();
    if p.is_null() {
        return None;
    }
    let all = unsafe { core::slice::from_raw_parts_mut(p, c + v) };
    let (chunks, volumes) = all.split_at_mut(c);
    if index.fill_chunks(chunks, volumes).is_err() {
        unsafe { im::index_free(p.cast(), c"apr.zstd.chunks.invalid".as_ptr()) };
        return None;
    }
    mount.tables = p;
    mount.tables_bytes = bytes;
    stats::add(stats::Stat::IndexViewBytes, bytes as u64);
    index.with_chunks(chunks, volumes).ok()
}

/// manifest.rs `clear_manifest_view`: drops the index borrow. The chunk
/// tables must already be freed (`zstd_mount_release`).
pub(crate) fn zstd_mount_clear() {
    unsafe { *ZSTD_MOUNT.get() = ZstdMount::EMPTY };
}

/// manifest.rs `release_manifest_storage` and a failed mount: frees the
/// chunk tables and clears the mount.
pub(crate) unsafe fn zstd_mount_release() {
    let mount = unsafe { &*ZSTD_MOUNT.get() };
    // The chunk tables go with the index that reads them.
    let (tables, tables_bytes) = (mount.tables, mount.tables_bytes);
    zstd_mount_clear();
    if !tables.is_null() {
        stats::sub(stats::Stat::IndexViewBytes, tables_bytes as u64);
        unsafe { im::index_free(tables.cast(), c"apr.zstd.chunks.release".as_ptr()) };
    }
}

// ---- accessors ----------------------------------------------------------------

/// The mount, once the manifest load is ready (immutable from then on:
/// `zstd_mount_join` wrote it before `LOAD_STATE` turned ready).
fn ready_mount() -> Option<&'static ZstdMount> {
    (LOAD_STATE.load(Ordering::Acquire) == PACK_LOAD_READY).then(|| unsafe { &*ZSTD_MOUNT.get() })
}

pub(crate) fn zstd_index() -> Option<&'static ZstdIndex> {
    ready_mount().and_then(|m| m.index.as_ref())
}

/// The extent of packed one-based AMPRIDX3 `ampr_id`: first chunk and
/// size from the published view, which the join set and checked against
/// the zstd record. Memory only (no lock, wait or pread), so the open
/// hooks, the read jobs and the decode-on-access signal handler may call
/// it. None before the mount is ready and for a loose or unknown id.
pub(crate) fn zstd_extent(ampr_id: u32) -> Option<ZstdExtent> {
    ready_mount()?;
    let view = super::super::index::published()?.view()?;
    ZstdExtent::of_view(&view, ampr_id)
}

pub(crate) fn zstd_volume_count() -> u32 {
    zstd_index().map_or(0, |i| i.volume_count())
}

/// Debug only: the metrics bench (readahead.rs `bench_volume_path`).
#[cfg(feature = "mem_report")]
pub(crate) fn zstd_volume_size(volume: u32) -> Option<u64> {
    zstd_index().and_then(|i| i.volume_size(volume).ok())
}

pub(crate) fn zstd_chunk_count() -> u32 {
    zstd_index().map_or(0, |i| i.chunk_count())
}

/// Chunk record `id` read from memory only: the chunk tables; never a
/// lock, wait or pread, so the decode-on-access signal handler may call it
/// (rt/pack/mmap_fault.rs). None for an unknown id.
pub(crate) fn zstd_chunk_resident(id: u32) -> Option<ampr_format::zstd::ChunkRecord> {
    let index = zstd_index()?;
    zstd_chunks_resident()
        .then(|| index.chunk(id).ok())
        .flatten()
}

/// Whether `zstd_chunk_resident` can answer: false before the mount is
/// ready (an index mounts only with its chunk tables).
pub(crate) fn zstd_chunks_resident() -> bool {
    zstd_index().is_some_and(|i| i.has_chunks())
}

// ---- service names ----------------------------------------------------------

use ampr_format::overlay::{self, LOGICAL_ROOT};
// The dirent types the pack runtime emits (mod.rs) are the overlay's.
const _: () = assert!(DT_DIR == overlay::DT_DIR && DT_REG == overlay::DT_REG);

/// Hidden from `/app0` listings, like the AMPRPAK4 index.
pub(crate) const ZSTD_INDEX_LOGICAL_PATH: &[u8] = b"/app0/ampr_zstd.index";

/// zstd pack service files hidden from listings: `/app0/ampr_zstd.index` and
/// the canonical name of each of the `volume_count` mounted volumes
/// (`/app0/ampr_zstd-000.pak`, ...), ASCII-folded like the other service names.
pub(crate) fn zstd_service_name_hidden(volume_count: u32, directory: &[u8], name: &[u8]) -> bool {
    if overlay::joined_matches(directory, name, ZSTD_INDEX_LOGICAL_PATH) {
        return true;
    }
    const PREFIX: &[u8] = ampr_format::zstd::VOLUME_PREFIX.as_bytes();
    const SUFFIX: &[u8] = ampr_format::zstd::VOLUME_SUFFIX.as_bytes();
    if name.len() < PREFIX.len() + 3 + SUFFIX.len()
        || name.len() > PREFIX.len() + 10 + SUFFIX.len()
        || !name[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
        || !name[name.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX)
    {
        return false;
    }
    // Canonical `volume_name` digits: the volume id, at least three digits,
    // no further leading zero (`ampr_zstd-000.pak`, ..., `ampr_zstd-1000.pak`).
    let digits = &name[PREFIX.len()..name.len() - SUFFIX.len()];
    if digits.len() > 3 && digits[0] == b'0' {
        return false;
    }
    let number = digits.iter().try_fold(0u64, |v, &d| {
        d.is_ascii_digit().then(|| v * 10 + u64::from(d - b'0'))
    });
    if !number.is_some_and(|id| id < u64::from(volume_count)) {
        return false;
    }
    let root = LOGICAL_ROOT.len();
    let len = root + 1 + name.len();
    let mut target = [0u8; 32];
    if len > target.len() {
        return false;
    }
    target[..root].copy_from_slice(LOGICAL_ROOT);
    target[root] = b'/';
    target[root + 1..len].copy_from_slice(name);
    overlay::joined_matches(directory, name, &target[..len])
}

/// `zstd_service_name_hidden` against the mounted index (no volumes are
/// hidden until the mount is ready).
pub(crate) fn zstd_name_hidden(directory: &[u8], name: &[u8]) -> bool {
    zstd_service_name_hidden(zstd_volume_count(), directory, name)
}

// ---- core tasks -------------------------------------------------------------
//
// zstd bodies of the `ampr_pack_core_*` exports in rt/index.rs (same ABI).
// Their `file` argument is `zstd_task_file(ampr_id)`; the `AmprPackCoreView`
// argument is ignored and the index comes from `zstd_index()`. A zstd
// chunk is the 8-byte record of `Index::chunk`, never an AMPRPAK4 record.

use ampr_format::zstd::CHUNK_SIZE as ZSTD_CHUNK_BYTES;
use ampr_format::CoreError;

/// What a read job needs of a packed file: its first chunk and logical
/// size from the view, and the chunk count the size gives (256 KiB each,
/// the last one shorter), so a task reads no index page. Passed by value
/// in `TaskFile::Zstd` (virtual_read.rs); the `file` pointer of the core
/// task calls points at that copy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ZstdExtent {
    pub logical_size: u64,
    pub first_chunk: u32,
    pub chunk_count: u32,
}

impl ZstdExtent {
    /// The extent of view file `id`; None when the join did not link it
    /// (loose, or not in the zstd index) or its chunk count overflows.
    pub(crate) fn of_view(view: &ampr_format::view::View<'_>, id: u32) -> Option<Self> {
        let first_chunk = view.chunk(id);
        if !view.packed(id) || first_chunk == ampr_format::view::NO_CHUNK {
            return None;
        }
        let logical_size = view.size(id);
        let chunk_count = u32::try_from(logical_size.div_ceil(ZSTD_CHUNK_BYTES)).ok()?;
        Some(Self {
            logical_size,
            first_chunk,
            chunk_count,
        })
    }
}

/// 18: 256 KiB chunks (`Index::open` rejects any other header chunk_shift).
const ZSTD_CHUNK_SHIFT: u32 = ampr_format::zstd::CHUNK_SHIFT as u32;
const _: () = assert!(ZSTD_CHUNK_SHIFT == 18 && 1u64 << ZSTD_CHUNK_SHIFT == ZSTD_CHUNK_BYTES);
/// Largest stored chunk: the 18-bit `stored_size - 1` field. The writer
/// stores a chunk raw when zstd is not smaller, so stored <= raw <= 256 KiB.
const ZSTD_MAX_STORED_BYTES: u32 = 1 << 18;
const _: () = assert!(
    ampr_codec::ZSTD_CODEC_RAW == AMPR_PACK_CHUNK_RAW
        && ampr_codec::ZSTD_MAX_CHUNK_SIZE as u64 == ZSTD_CHUNK_BYTES
        && ZSTD_MAX_STORED_BYTES as u64 == ZSTD_CHUNK_BYTES
);
// The shared read pipeline holds a whole 256 KiB chunk: the worker decoded
// scratch (worker.rs, also the warm-up scratch) is one max AMPRPAK4 block,
// and a chunk's stored bytes fit one I/O window (virtual_read.rs
// `prepare_exact_task_window`).
const _: () = {
    assert!(ZSTD_CHUNK_BYTES as usize <= PACK_MAX_BLOCK_BYTES);
    assert!(ZSTD_MAX_STORED_BYTES as usize <= PACK_PIPELINE_IO_BYTES);
};

fn request_valid(file: &ZstdExtent, offset: u64, length: u64) -> bool {
    length != 0 && offset <= file.logical_size && length <= file.logical_size - offset
}

/// Read tasks (256 KiB chunks touched) of `[offset, offset + length)` in
/// `file`; zero for a rejected request (empty, or past the end).
pub(crate) fn zstd_task_count(file: &ZstdExtent, offset: u64, length: u64) -> usize {
    if !request_valid(file, offset, length) {
        return 0;
    }
    let first = offset >> ZSTD_CHUNK_SHIFT;
    let last = (offset + length - 1) >> ZSTD_CHUNK_SHIFT;
    usize::try_from(last - first + 1).unwrap_or(0)
}

/// Task `task_index` of a read of `file`: chunk `first_chunk + local` with
/// its absolute volume offset, `raw_size = min(256 KiB, remaining bytes)`,
/// volume id in `pack_id`, codec 0 raw / 1 zstd, flags zero.
pub(crate) fn zstd_read_task<S: Source + ?Sized>(
    index: &Index<'_, S>,
    file: &ZstdExtent,
    offset: u64,
    length: u64,
    task_index: usize,
) -> Result<AmprPackBlockReadTask, CoreError> {
    if !request_valid(file, offset, length)
        || u64::from(file.first_chunk) + u64::from(file.chunk_count)
            > u64::from(index.chunk_count())
    {
        return Err(CoreError::InvalidArgument);
    }
    let first = offset >> ZSTD_CHUNK_SHIFT;
    let end = offset + length;
    let count = ((end - 1) >> ZSTD_CHUNK_SHIFT) - first + 1;
    let task = u64::try_from(task_index).map_err(|_| CoreError::OutOfRange)?;
    let local = first + task;
    if task >= count || local >= u64::from(file.chunk_count) {
        return Err(CoreError::OutOfRange);
    }
    // local < chunk_count and first_chunk + chunk_count <= index chunks.
    let chunk_index = file.first_chunk + local as u32;
    let record = index
        .chunk(chunk_index)
        .map_err(|_| CoreError::InvalidFormat)?;
    if record.codec > ampr_codec::ZSTD_CODEC_ZSTD {
        return Err(CoreError::InvalidFormat);
    }
    // local < ceil(size / 256 KiB), so begin < logical_size.
    let begin = local << ZSTD_CHUNK_SHIFT;
    let raw_size = (file.logical_size - begin).min(ZSTD_CHUNK_BYTES);
    let copy_begin = offset.max(begin);
    let copy_end = end.min(begin + raw_size);
    if copy_end <= copy_begin {
        return Err(CoreError::InvalidFormat);
    }
    Ok(AmprPackBlockReadTask {
        chunk_index,
        source_offset: (copy_begin - begin) as u32,
        copy_length: (copy_end - copy_begin) as u32,
        destination_offset: u32::try_from(copy_begin - offset)
            .map_err(|_| CoreError::InvalidFormat)?,
        chunk: AmprPackChunkView {
            offset: u64::from(record.offset),
            stored_size: record.stored_size,
            raw_size: raw_size as u32,
            pack_id: record.volume_id,
            codec: record.codec,
            flags: 0,
            kraken: 0,
        },
    })
}

/// The index and file extent behind a `TaskFile::Zstd` pointer
/// (virtual_read.rs), a `ZstdExtent` the caller keeps alive across the
/// call, as the LZ4 arm trusts its record copy. The extent came from the
/// view (`zstd_extent`); `zstd_read_task` still bounds its chunk span by
/// the index. None for a null pointer or before the mount is ready.
fn task_file(file: *const u8) -> Option<(&'static ZstdIndex, ZstdExtent)> {
    if file.is_null() {
        return None;
    }
    let extent = unsafe { file.cast::<ZstdExtent>().read_unaligned() };
    Some((zstd_index()?, extent))
}

/// zstd `ampr_pack_core_task_count`; zero for a rejected request.
pub(crate) fn zstd_core_task_count(file: *const u8, offset: u64, length: u64) -> usize {
    task_file(file).map_or(0, |(_, f)| zstd_task_count(&f, offset, length))
}

/// zstd `ampr_pack_core_make_task`; `*out` is zeroed on every error.
pub(crate) unsafe fn zstd_core_make_task(
    file: *const u8,
    offset: u64,
    length: u64,
    task_index: usize,
    out: *mut AmprPackBlockReadTask,
) -> c_int {
    if out.is_null() {
        return CoreError::InvalidArgument.code();
    }
    unsafe { out.write(AmprPackBlockReadTask::default()) };
    let task = task_file(file)
        .ok_or(CoreError::InvalidArgument)
        .and_then(|(index, f)| zstd_read_task(index, &f, offset, length, task_index));
    match task {
        Ok(t) => {
            unsafe { out.write(t) };
            AMPR_PACK_CORE_OK
        }
        Err(e) => e.code(),
    }
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ampr_format::zstd::{path_hash, CHUNK_SIZE, VOLUME_HEADER_SIZE};

    /// A raw-chunk AMPRZPK1 v1 image; volume 1 starts at chunk `split.1` of
    /// file `split.0`.
    fn build_index(files: &[(&str, u64)], split: (&str, u32)) -> Vec<u8> {
        build_index_with(files, split, |_, _| None)
    }

    /// As `build_index`; `zstd(path, chunk)` gives the stored size of a chunk
    /// recorded as zstd (codec 1; the payload itself is never read).
    fn build_index_with(
        files: &[(&str, u64)],
        split: (&str, u32),
        zstd: impl Fn(&str, u32) -> Option<u64>,
    ) -> Vec<u8> {
        let mut sorted = files.to_vec();
        sorted.sort_by(|a, b| {
            (path_hash(a.0.as_bytes()), a.0.as_bytes())
                .cmp(&(path_hash(b.0.as_bytes()), b.0.as_bytes()))
        });
        let (mut records, mut chunks, mut strings) = (Vec::new(), Vec::new(), Vec::new());
        let (mut volume, mut offset, mut volume_sizes) =
            (0u64, VOLUME_HEADER_SIZE as u64, Vec::new());
        let mut total = 0u64;
        for &(path, size) in &sorted {
            let count = size.div_ceil(CHUNK_SIZE);
            records.extend_from_slice(&path_hash(path.as_bytes()).to_le_bytes());
            records.extend_from_slice(&size.to_le_bytes());
            records.extend_from_slice(&((chunks.len() / 8) as u32).to_le_bytes());
            records.extend_from_slice(&(strings.len() as u32).to_le_bytes());
            records.extend_from_slice(&(path.len() as u16).to_le_bytes());
            records.extend_from_slice(&[0; 6]);
            strings.extend_from_slice(path.as_bytes());
            for n in 0..count {
                if (path, n as u32) == split {
                    volume_sizes.push(offset);
                    (volume, offset) = (volume + 1, VOLUME_HEADER_SIZE as u64);
                }
                let raw = (size - n * CHUNK_SIZE).min(CHUNK_SIZE);
                let (stored, codec) = zstd(path, n as u32).map_or((raw, 0u64), |s| (s, 1));
                let packed = offset | volume << 32 | (stored - 1) << 44 | codec << 62;
                chunks.extend_from_slice(&packed.to_le_bytes());
                offset += stored;
            }
            total += size;
        }
        volume_sizes.push(offset);
        let volumes: Vec<u8> = volume_sizes.iter().flat_map(|v| v.to_le_bytes()).collect();
        let chunks_off = 128 + records.len() as u64;
        let volumes_off = chunks_off + chunks.len() as u64;
        let strings_off = volumes_off + volumes.len() as u64;
        let mut h = vec![0u8; 128];
        h[..8].copy_from_slice(b"AMPRZPK1");
        h[8..12].copy_from_slice(&1u32.to_le_bytes());
        h[12..16].copy_from_slice(&128u32.to_le_bytes());
        (h[16], h[17]) = (ZSTD_CHUNK_SHIFT as u8, 5);
        h[20..24].copy_from_slice(&(volume_sizes.len() as u32).to_le_bytes());
        h[24..40].copy_from_slice(&[0xa5; 16]);
        let fields = [
            sorted.len() as u64,
            (chunks.len() / 8) as u64,
            128,
            chunks_off,
            volumes_off,
            strings_off,
            strings.len() as u64,
            total,
        ];
        for (i, value) in fields.iter().enumerate() {
            h[40 + i * 8..48 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        let payload = [records, chunks, volumes, strings].concat();
        let header_crc = ampr_format::crc32(&h);
        h[112..116].copy_from_slice(&ampr_format::crc32(&payload).to_le_bytes());
        h[116..120].copy_from_slice(&header_crc.to_le_bytes());
        [h, payload].concat()
    }

    const ZSTD_FILES: &[(&str, u64)] = &[
        ("data/a.bin", 10),
        ("Data/B.bin", 300_000),
        ("data/empty", 0),
        ("z/c.bin", 262_144),
    ];

    fn ampr_entries() -> Vec<(&'static [u8], u64)> {
        vec![
            (b"/app0/eboot.bin", 4096),      // 1: loose
            (b"/app0/data/a.bin", 10),       // 2
            (b"/APP0/Data/B.bin", 300_000),  // 3: spans volumes 0..1
            (b"/app0/data/empty", 0),        // 4: no chunks
            (b"/app0/Z/C.BIN", 262_144),     // 5: case differs, joined folded
            (b"/app0/ampr_zstd.index", 999), // 6: loose
            (b"/app0/\xff", 1),              // 7: not UTF-8, loose
            (b"/app0/data/c.bin", 5),        // 8: loose
        ]
    }

    /// The zstd record whose path is `rel` folded: the row the join must
    /// link (one per folded path in these images).
    fn fold_find(index: &Index<'_>, rel: &[u8]) -> Option<u64> {
        (0..index.file_count()).find(|&i| path_of(index, i as u32).eq_ignore_ascii_case(rel))
    }

    /// `view_join::join_zstd` of `index` into a fresh view of `entries`
    /// (the mount's join): its answer and each id's `View::chunk` once
    /// finished. The caller holds `POOL_TEST_LOCK`.
    fn joined<S: Source + ?Sized>(
        index: &Index<'_, S>,
        entries: &[(&'static [u8], u64)],
    ) -> (ampr_format::Result<u32>, Vec<u32>) {
        let mut idx = crate::rt::index::tests::zstd_builder(entries);
        let b = idx.compact.builder.as_mut().unwrap();
        let rc = ampr_format::view_join::join_zstd(b, index);
        idx.compact.finish();
        let view = idx.compact.view().unwrap();
        let chunks = (1..=entries.len() as u32)
            .map(|id| view.chunk(id))
            .collect();
        crate::rt::index::tests::drop_view(&mut idx);
        (rc, chunks)
    }

    #[test]
    fn path_helpers_strip_roots_and_hide_pack_files() {
        // relative path strips folded app0 root.
        assert_eq!(ampr_relative_path(b"/app0/a/B.bin"), Some(&b"a/B.bin"[..]));
        assert_eq!(ampr_relative_path(b"/APP0/x"), Some(&b"x"[..]));
        assert_eq!(ampr_relative_path(b"/app0/"), None);
        assert_eq!(ampr_relative_path(b"/app1/x"), None);
        assert_eq!(ampr_relative_path(b"app0/xy"), None);

        // hides zstd index and mounted volumes only.
        let hidden = |dir: &[u8], name: &[u8]| zstd_service_name_hidden(2, dir, name);
        for name in [
            &b"ampr_zstd.index"[..],
            b"AMPR_ZSTD.INDEX",
            b"ampr_zstd-000.pak",
            b"Ampr_Zstd-001.PAK",
        ] {
            assert!(hidden(b"/app0", name), "{:?}", name);
        }
        assert!(hidden(b"/app0/", b"ampr_zstd-000.pak"));
        // Unmounted, non-canonical, or outside /app0: still listed.
        for name in [
            &b"ampr_zstd-002.pak"[..],
            b"ampr_zstd-0.pak",
            b"ampr_zstd-01.pak",
            b"ampr_zstd-0001.pak",
            b"ampr_zstd-00x.pak",
            b"ampr_zstd-000.pa",
            b"ampr_zstdx.pak",
            b"game.index",
            b"data-01.pak",
            b"data.bin",
        ] {
            assert!(!hidden(b"/app0", name), "{:?}", name);
        }
        assert!(!hidden(b"/app0/sub", b"ampr_zstd-000.pak"));
        assert!(!hidden(b"/app0/sub", b"ampr_zstd.index"));
        assert!(!zstd_service_name_hidden(0, b"/app0", b"ampr_zstd-000.pak"));
        assert!(zstd_service_name_hidden(
            1001,
            b"/app0",
            b"ampr_zstd-1000.pak"
        ));
        assert!(!zstd_service_name_hidden(
            1000,
            b"/app0",
            b"ampr_zstd-1000.pak"
        ));
    }

    /// The mount's join: every packed id's `View::chunk` is the first
    /// chunk of the zstd record of its folded path, a loose id has
    /// `NO_CHUNK`, and a size mismatch invalidates the mount.
    #[test]
    fn the_join_gives_every_packed_id_its_first_chunk() {
        use ampr_format::view::NO_CHUNK;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = im::test_index_used();
        let image = build_index(ZSTD_FILES, ("Data/B.bin", 1));
        let index = Index::open(&image[..]).expect("test image validates");
        assert_eq!(index.volume_count(), 2);
        let entries = ampr_entries();
        let (rc, chunks) = joined(&index, &entries);
        assert_eq!(rc, Ok(4));
        for (n, &(path, size)) in entries.iter().enumerate() {
            let expected = ampr_relative_path(path).and_then(|rel| fold_find(&index, rel));
            match expected {
                None => assert_eq!(chunks[n], NO_CHUNK, "id {}", n + 1),
                Some(id) => {
                    let file = index.file(id).unwrap();
                    assert_eq!(chunks[n], file.first_chunk, "id {}", n + 1);
                    assert_eq!(file.logical_size, size);
                }
            }
        }
        for loose in [0, 5, 6, 7] {
            assert_eq!(chunks[loose], NO_CHUNK);
        }

        // A packed size mismatch invalidates; a loose path may have any size.
        let mut sized = ampr_entries();
        sized[2].1 = 299_999;
        assert_eq!(joined(&index, &sized).0, Err(ampr_format::Error::Invalid));
        let mut sized = ampr_entries();
        sized[0].1 = 1;
        assert_eq!(joined(&index, &sized).0, Ok(4));
        assert_eq!(im::test_index_used(), used);
    }

    /// `Data/B.bin` (300 000 bytes): chunk 0 raw in volume 0, chunk 1 zstd
    /// (1000 stored bytes) at the start of volume 1.
    fn task_image() -> Vec<u8> {
        build_index_with(ZSTD_FILES, ("Data/B.bin", 1), |path, n| {
            (path == "Data/B.bin" && n == 1).then_some(1000)
        })
    }

    /// File `id`'s path, copied out of the index.
    fn path_of(index: &Index<'_>, id: u32) -> Vec<u8> {
        let mut buf = [0u8; ampr_format::source::PATH_BUF];
        let f = index.file(u64::from(id)).unwrap();
        index.path(&f, &mut buf).unwrap().to_vec()
    }

    /// The extent the view gives `path` once `index` is joined to a view
    /// of every `ZSTD_FILES` path, as `zstd_extent` reads it at run time;
    /// it must equal the zstd record's. The caller holds `POOL_TEST_LOCK`.
    fn file(index: &Index<'_>, path: &str) -> ZstdExtent {
        let entries: Vec<(&'static [u8], u64)> = ZSTD_FILES
            .iter()
            .map(|&(p, size)| (&*format!("/app0/{p}").into_bytes().leak(), size))
            .collect();
        let at = ZSTD_FILES
            .iter()
            .position(|&(p, _)| p == path)
            .expect("test path");
        let mut idx = crate::rt::index::tests::zstd_builder(&entries);
        let b = idx.compact.builder.as_mut().unwrap();
        let joined = ampr_format::view_join::join_zstd(b, index);
        assert_eq!(joined, Ok(ZSTD_FILES.len() as u32));
        idx.compact.finish();
        let view = idx.compact.view().unwrap();
        let extent = ZstdExtent::of_view(&view, at as u32 + 1).expect("joined");
        crate::rt::index::tests::drop_view(&mut idx);
        assert_eq!(extent, record_extent(index, path), "{path}");
        extent
    }

    /// The extent the zstd record of `path` holds: the view's oracle.
    fn record_extent(index: &Index<'_>, path: &str) -> ZstdExtent {
        let rec = index
            .file(index.find(path.as_bytes()).unwrap().unwrap())
            .unwrap();
        ZstdExtent {
            logical_size: rec.logical_size,
            first_chunk: rec.first_chunk,
            chunk_count: rec.chunk_count,
        }
    }

    #[test]
    fn tasks_split_reads_into_fixed_256k_chunks() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = im::test_index_used();
        // tasks use fixed 256k chunks and carry volume and codec.
        let image = task_image();
        let index = Index::open(&image[..]).expect("test image validates");
        let f = file(&index, "Data/B.bin");
        assert_eq!((f.chunk_count, zstd_task_count(&f, 0, 300_000)), (2, 2));
        let t0 = zstd_read_task(&index, &f, 0, 300_000, 0).unwrap();
        let c0 = index.chunk(f.first_chunk).unwrap();
        assert_eq!(
            (
                t0.chunk_index,
                t0.source_offset,
                t0.copy_length,
                t0.destination_offset
            ),
            (f.first_chunk, 0, 262_144, 0)
        );
        let v = t0.chunk;
        assert_eq!(
            (
                v.offset,
                v.stored_size,
                v.raw_size,
                v.pack_id,
                v.codec,
                v.flags
            ),
            (u64::from(c0.offset), 262_144, 262_144, 0, 0, 0)
        );
        let t1 = zstd_read_task(&index, &f, 0, 300_000, 1).unwrap();
        assert_eq!(
            (
                t1.chunk_index,
                t1.source_offset,
                t1.copy_length,
                t1.destination_offset
            ),
            (f.first_chunk + 1, 0, 37_856, 262_144)
        );
        // The last chunk decodes to the remaining bytes; the volume header
        // occupies [0, 64), so the first chunk of volume 1 is at 64.
        let v = t1.chunk;
        assert_eq!(
            (
                v.offset,
                v.stored_size,
                v.raw_size,
                v.pack_id,
                v.codec,
                v.flags
            ),
            (VOLUME_HEADER_SIZE as u64, 1_000, 37_856, 1, 1, 0)
        );
        assert_eq!(
            zstd_read_task(&index, &f, 0, 300_000, 2).err(),
            Some(CoreError::OutOfRange)
        );

        // partial reads split at chunk boundaries.
        let image = task_image();
        let index = Index::open(&image[..]).unwrap();
        let f = file(&index, "Data/B.bin");
        assert_eq!(zstd_task_count(&f, 262_000, 1_000), 2);
        let t0 = zstd_read_task(&index, &f, 262_000, 1_000, 0).unwrap();
        let t1 = zstd_read_task(&index, &f, 262_000, 1_000, 1).unwrap();
        assert_eq!(
            (t0.source_offset, t0.copy_length, t0.destination_offset),
            (262_000, 144, 0)
        );
        assert_eq!(
            (t1.source_offset, t1.copy_length, t1.destination_offset),
            (0, 856, 144)
        );
        assert_eq!(zstd_task_count(&f, 10, 5), 1);
        assert_eq!(zstd_task_count(&f, 299_999, 1), 1);
        // Rejected: empty, past the end, or running over the end.
        for (offset, length) in [(0, 0), (300_000, 1), (299_999, 2), (u64::MAX, 1)] {
            assert_eq!(zstd_task_count(&f, offset, length), 0);
            assert_eq!(
                zstd_read_task(&index, &f, offset, length, 0).err(),
                Some(CoreError::InvalidArgument)
            );
        }
        let small = file(&index, "data/a.bin");
        let t = zstd_read_task(&index, &small, 0, 10, 0).unwrap();
        assert_eq!(
            (t.chunk.raw_size, t.copy_length, t.chunk.codec),
            (10, 10, 0)
        );
        let exact = file(&index, "z/c.bin");
        assert_eq!(zstd_task_count(&exact, 0, 262_144), 1);
        assert_eq!(
            zstd_read_task(&index, &exact, 0, 262_144, 0)
                .unwrap()
                .chunk
                .raw_size,
            262_144
        );

        // empty file has no tasks.
        let image = task_image();
        let index = Index::open(&image[..]).unwrap();
        let f = file(&index, "data/empty");
        assert_eq!(f.chunk_count, 0);
        assert_eq!(zstd_task_count(&f, 0, 0), 0);
        assert_eq!(zstd_task_count(&f, 0, 1), 0);
        assert!(zstd_read_task(&index, &f, 0, 1, 0).is_err());

        // The task exports take the extent by pointer and reject null; no
        // index is mounted in host tests, so a valid extent has no tasks.
        let extent = file(&index, "Data/B.bin");
        let file_ptr = (&extent as *const ZstdExtent).cast::<u8>();
        assert_eq!(zstd_core_task_count(null(), 0, 1), 0);
        assert_eq!(zstd_core_task_count(file_ptr, 0, 1), 0);
        let mut task = AmprPackBlockReadTask {
            chunk_index: 7,
            ..Default::default()
        };
        let rc = unsafe { zstd_core_make_task(null(), 0, 1, 0, &mut task) };
        assert_eq!((rc, task.chunk_index), (-1, 0));
        assert!(zstd_extent(3).is_none());
        assert_eq!(im::test_index_used(), used);
    }

    const TREE: &[(&str, u64)] = &[
        ("z/c.bin", 262_144),
        ("data/a.bin", 10),
        ("top.bin", 3),
        ("Data/B.bin", 300_000),
        ("data/sub/d.bin", 5),
        ("a b/x", 1),
        ("data/empty", 0),
    ];

    /// The children of `dir` (relative, folded) among the packed `TREE`
    /// paths, names folded: a name with anything below it is a directory.
    fn tree_children(dir: &str) -> std::collections::BTreeSet<(String, u8)> {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut kinds = std::collections::BTreeMap::new();
        for (path, _) in TREE {
            let path = path.to_ascii_lowercase();
            let Some(rest) = path.strip_prefix(&prefix) else {
                continue;
            };
            let (name, kind) = rest
                .split_once('/')
                .map_or((rest, DT_REG), |(n, _)| (n, DT_DIR));
            let k = kinds.entry(name.to_string()).or_insert(kind);
            if kind == DT_DIR {
                *k = DT_DIR;
            }
        }
        kinds.into_iter().collect()
    }

    /// A packed directory lists, from the view, the same children as a
    /// listing of the packed paths below it (names folded: the view spells
    /// a name as AMPRIDX3 stores it); a loose file is not listed, and a
    /// file, a miss or a directory of loose files only is no packed
    /// directory.
    #[test]
    fn a_view_listing_lists_the_packed_children() {
        use std::collections::BTreeSet;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = im::test_index_used();
        let image = build_index(TREE, ("Data/B.bin", 1));
        let index = Index::open(&image[..]).expect("test image validates");
        let loose = [
            "/app0/eboot.bin",
            "/app0/loose/only.bin",
            "/app0/data/c.bin",
            // A loose file of the same folded key as the packed `data`
            // directory: the directory still lists.
            "/app0/DATA",
        ];
        let paths: Vec<(Vec<u8>, u64)> = TREE
            .iter()
            .map(|&(p, n)| (format!("/app0/{p}").into_bytes(), n))
            .chain(loose.iter().map(|p| (p.as_bytes().to_vec(), 1)))
            .collect();
        let entries: Vec<(&[u8], u64)> = paths.iter().map(|(p, n)| (p.as_slice(), *n)).collect();
        let mut idx = crate::rt::index::tests::zstd_builder(&entries);
        let b = idx.compact.builder.as_mut().unwrap();
        assert_eq!(
            ampr_format::view_join::join_zstd(b, &index),
            Ok(TREE.len() as u32)
        );
        idx.compact.finish();
        let (view, src) = (idx.compact.view().unwrap(), &idx.compact.paths);
        let list = |dir: &[u8]| -> Option<BTreeSet<(String, u8)>> {
            let mut c = packed_dir_in(&view, src, dir).unwrap()?;
            let (mut out, mut names, mut name) = (BTreeSet::new(), BTreeSet::new(), [0u8; 256]);
            while let Some(child) = list_next_in(&view, src, c, &mut name).unwrap() {
                let len = usize::from(child.len);
                assert!(len > 0 && name[len] == 0);
                let text = String::from_utf8(name[..len].to_ascii_lowercase()).unwrap();
                assert!(names.insert(text.clone()), "{text} listed once");
                out.insert((text, child.kind));
                c = child.next;
            }
            assert_eq!(c, Cursor::Done);
            Some(out)
        };
        for (dir, rel) in [
            (&b"/app0"[..], ""),
            (b"/APP0/data", "data"),
            (b"/app0/Data", "data"),
            (b"/app0/DATA/sub", "data/sub"),
            (b"/app0/z", "z"),
            (b"/app0/a b", "a b"),
        ] {
            assert_eq!(list(dir), Some(tree_children(rel)), "{rel}");
        }
        for miss in [
            &b"/app0/top.bin"[..],
            b"/app0/dat",
            b"/app0/loose",
            b"/app0/data/sub/d.bin",
            b"/app0/eboot.bin",
        ] {
            assert_eq!(list(miss), None, "{:?}", miss);
        }
        // A path that cannot be read fails the entry with `Io` (the caller
        // keeps its cursor) instead of skipping it.
        struct Failing(u64);
        impl Source for Failing {
            fn len(&self) -> u64 {
                self.0
            }
            fn read_at(&self, _: u64, _: &mut [u8]) -> ampr_format::Result<()> {
                Err(ampr_format::Error::Io)
            }
        }
        let root = packed_dir_in(&view, src, b"/app0").unwrap().unwrap();
        let mut name = [0u8; 256];
        let failing = Failing(src.len());
        assert_eq!(
            list_next_in(&view, &failing, root, &mut name),
            Err(ampr_format::Error::Io)
        );
        assert!(list_next_in(&view, src, root, &mut name).unwrap().is_some());
        crate::rt::index::tests::drop_view(&mut idx);
        assert_eq!(im::test_index_used(), used);
    }

    // ---- mount (Index room, reads) ----

    /// The image `test_read` serves, and whether its reads fail. Set by a
    /// test that holds `POOL_TEST_LOCK`, so one mount reads it at a time.
    static TEST_IMAGE: std::sync::Mutex<&'static [u8]> = std::sync::Mutex::new(&[]);
    static TEST_FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static TEST_READS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn test_read(at: u64, out: &mut [u8]) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        TEST_READS.fetch_add(1, SeqCst);
        let image = *TEST_IMAGE.lock().unwrap();
        let at = at as usize;
        if TEST_FAIL.load(SeqCst) || at + out.len() > image.len() {
            return false;
        }
        out.copy_from_slice(&image[at..at + out.len()]);
        true
    }

    /// Mounts `image` through `zstd_mount_join` into `b`.
    unsafe fn mount_image(image: &'static [u8], b: &mut Builder<'_>) -> bool {
        *TEST_IMAGE.lock().unwrap() = image;
        unsafe { zstd_mount_join(image.len() as u64, test_read, b) }
    }

    /// A zstd index mounts only with its chunk and volume tables and the
    /// two read windows: with less Index room than they need, the mount
    /// is refused with the index notice before the file is read and takes
    /// nothing; with the room it mounts and joins every file, chunks and
    /// volume sizes come from memory, the windows go back, and the release
    /// gives every byte back.
    #[test]
    fn a_zstd_index_needs_room_for_its_chunk_tables() {
        use std::sync::atomic::Ordering::SeqCst;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000usize;
        let names: Vec<String> = (0..n).map(|i| format!("d{}/f{i}.bin", i % 7)).collect();
        let files: Vec<(&str, u64)> = names.iter().map(|p| (p.as_str(), 1)).collect();
        let image: &'static [u8] = build_index(&files, ("", u32::MAX)).leak();
        let paths: Vec<Vec<u8>> = names
            .iter()
            .map(|p| format!("/app0/{p}").into_bytes())
            .collect();
        let ampr: Vec<(&[u8], u64)> = paths.iter().map(|p| (p.as_slice(), 1)).collect();
        let used = im::test_index_used();
        let mut idx = crate::rt::index::tests::zstd_builder(&ampr);
        let tables = table_bytes(n as u64, 1);
        let page = SCE_KERNEL_PAGE_SIZE;
        TEST_FAIL.store(false, SeqCst);
        im::test_take_index_notice();
        unsafe {
            let b = idx.compact.builder.as_mut().unwrap();
            let before = im::test_index_used();
            // Leave a page less than the tables and windows need.
            let fill = im::index_room() - (tables + 2 * WINDOW).next_multiple_of(page) + page;
            let other = im::index_alloc(fill, page, c"test.other.tables".as_ptr());
            assert!(!other.is_null());
            TEST_READS.store(0, SeqCst);
            assert!(!mount_image(image, b));
            assert_eq!(TEST_READS.load(SeqCst), 1, "only the header is read");
            assert!(im::test_take_index_notice());
            assert!((*ZSTD_MOUNT.get()).index.is_none());
            im::index_free(other.cast(), c"test.other.tables.free".as_ptr());
            assert_eq!(im::test_index_used(), before);
            assert!(mount_image(image, b));
            assert!(!im::test_take_index_notice());
            let mount = &*ZSTD_MOUNT.get();
            assert_eq!(mount.tables_bytes, tables);
            assert_eq!(
                im::test_index_used(),
                before + tables.next_multiple_of(page)
            );
            let index = mount.index.as_ref().unwrap();
            assert!(index.has_chunks());
            let plain = Index::open(image).unwrap();
            for id in [0, n as u32 / 2, n as u32 - 1] {
                assert_eq!(index.chunk(id), plain.chunk(id));
            }
            assert_eq!(index.volume_size(0), plain.volume_size(0));
            zstd_mount_release();
            assert!((*ZSTD_MOUNT.get()).index.is_none());
            assert_eq!(im::test_index_used(), before);
        }
        crate::rt::index::tests::drop_view(&mut idx);
        assert_eq!(im::test_index_used(), used);
    }

    /// A read error of the zstd index is reported as `Io`, not as a bad
    /// record: the join stops with it, and works again once reads do.
    #[test]
    fn a_zstd_index_read_error_is_io_not_invalid() {
        use ampr_format::view::NO_CHUNK;
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        struct Flaky(&'static [u8], AtomicBool);
        impl Source for Flaky {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
                if self.1.load(SeqCst) {
                    return Err(ampr_format::Error::Io);
                }
                self.0.read_at(at, out)
            }
        }
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = (0..2000).map(|n| format!("dir/file-{n:05}.bin")).collect();
        let files: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), 1)).collect();
        let image: &'static [u8] = build_index(&files, (files[0].0, 0)).leak();
        let src = Flaky(image, AtomicBool::new(false));
        let index = Index::open(&src).unwrap();
        let first: &'static [u8] = format!("/app0/{}", names[0]).into_bytes().leak();
        src.1.store(true, SeqCst);
        assert_eq!(joined(&index, &[(first, 1)]).0, Err(ampr_format::Error::Io));
        src.1.store(false, SeqCst);
        let (rc, chunks) = joined(&index, &[(first, 1)]);
        assert!(rc == Ok(1) && chunks[0] != NO_CHUNK);
    }

    /// The mounted index reads no file: the reader is gone with the mount,
    /// so a record read is `Io`, while the task count and every task of a
    /// read job come from the chunk tables.
    #[test]
    fn zstd_read_tasks_read_no_index_file() {
        use std::sync::atomic::Ordering::SeqCst;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = (0..2000).map(|n| format!("dir/file-{n:05}.bin")).collect();
        let mut files: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), 1)).collect();
        files.push(("Data/B.bin", 300_000));
        let image = build_index_with(&files, ("Data/B.bin", 1), |path, n| {
            (path == "Data/B.bin" && n == 1).then_some(1000)
        });
        let image: &'static [u8] = image.leak();
        let paths: Vec<Vec<u8>> = files
            .iter()
            .map(|(p, _)| format!("/app0/{p}").into_bytes())
            .collect();
        let ampr: Vec<(&[u8], u64)> = paths
            .iter()
            .zip(&files)
            .map(|(p, f)| (p.as_slice(), f.1))
            .collect();
        let mut idx = crate::rt::index::tests::zstd_builder(&ampr);
        TEST_FAIL.store(false, SeqCst);
        let plain = Index::open(image).unwrap();
        let id = plain.find(b"Data/B.bin").unwrap().unwrap();
        let want = record_extent(&plain, "Data/B.bin");
        unsafe {
            assert!(mount_image(image, idx.compact.builder.as_mut().unwrap()));
            TEST_FAIL.store(true, SeqCst);
            TEST_READS.store(0, SeqCst);
            let index = (*ZSTD_MOUNT.get()).index.as_ref().unwrap();
            assert_eq!(index.file(id).err(), Some(ampr_format::Error::Io));
            assert_eq!(zstd_task_count(&want, 0, 300_000), 2);
            for task in 0..2 {
                let got = zstd_read_task(index, &want, 0, 300_000, task).unwrap();
                let w = zstd_read_task(&plain, &want, 0, 300_000, task).unwrap();
                assert_eq!(
                    (got.chunk_index, got.copy_length, got.destination_offset),
                    (w.chunk_index, w.copy_length, w.destination_offset)
                );
                let (g, w) = (got.chunk, w.chunk);
                assert_eq!(
                    (g.offset, g.stored_size, g.pack_id),
                    (w.offset, w.stored_size, w.pack_id)
                );
            }
            assert_eq!(TEST_READS.load(SeqCst), 0);
            TEST_FAIL.store(false, SeqCst);
            zstd_mount_release();
        }
        crate::rt::index::tests::drop_view(&mut idx);
    }
}
