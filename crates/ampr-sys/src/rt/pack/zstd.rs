//! zstd mount state (pack format: docs/zstd-format.md):
//! the immutable `/app0/ampr_zstd.index` image and its projection onto AMPRIDX3
//! ids. AMPRIDX3 stays the path and file-id authority; a zstd record number
//! is never an AMPR id.
//!
//! Public accessors (R5-R8 build on these). Each returns `None`/`0`/`false`
//! until the projection is ready (`zstd_projection_ready`):
//! - `zstd_index() -> Option<&'static Index<'static>>`: the mounted, fully
//!   validated zstd index (bytes live in `PackState::manifest_base`).
//! - `zstd_entry(ampr_id) -> Option<ZstdEntry>`: projection record of a
//!   one-based AMPRIDX3 id that is packed; `None` = loose or unknown id.
//! - `zstd_file_for_ampr_id(ampr_id) -> Option<u64>`: zero-based zstd file
//!   id for `Index::file`; `None` = loose or unknown id.
//! - `zstd_archive_id() -> Option<[u8; 16]>`: archive id every volume header
//!   must repeat.
//! - `zstd_volume_count() -> u32`, `zstd_volume_size(volume) -> Option<u64>`.
//! - `zstd_chunk_count() -> u32`: zstd chunk (= read task) records.
//! - `zstd_ampr_count() -> u32`: AMPRIDX3 ids projected (`ampr_id` 1..=n).
//! - `zstd_packed_count() -> u32`: AMPRIDX3 ids that map to a zstd file.
//! - `zstd_projection_ready() -> bool`.
//! - `ensure_zstd_projection() -> bool`: builds the projection once the
//!   AMPRIDX3 image is published; manifest.rs `ensure_manifest_ready` calls it, so a
//!   caller that saw `ensure_manifest_ready() == true` may use the accessors.
//!
//! - `zstd_task_file(ampr_id) -> *const u8`: the opaque `file` argument of
//!   `ampr_pack_core_task_count/make_task` in this build (null = loose).
//! - `try_zstd_projection() -> bool`: as `ensure_zstd_projection`, but
//!   never waits for another builder (hooks; slots.rs resident-ready check).
//!
//! R6 directory overlay: `zstd_packed_order() -> &[u32]` holds the distinct
//! zstd ids of the packed AMPRIDX3 ids sorted by the folded directory
//! comparator (built with the projection; zstd index order is hash order).
//! `zstd_directory_range`, `zstd_next_child`, `zstd_service_name_hidden`
//! (ampr_zstd.index and mounted ampr_zstd-NNN.pak) and `zstd_packed_file_matches`
//! back the `ampr_rust_overlay_*` exports in overlay_ffi.rs.
//!
//! Mount lifecycle, called only from manifest.rs: `zstd_mount_validate`,
//! `zstd_mount_clear`, `zstd_mount_release`.
//!
//! R5 core tasks: `zstd_core_{mount,validate_logical_file,task_count,
//! make_task}` are the bodies of the `ampr_pack_core_*` exports
//! in rt/index.rs; `zstd_task_count`/`zstd_read_task` hold the task math.
//!
//! Why the projection is deferred: the AMPRIDX3 loader calls
//! `ampr_pack_ensure_manifest_ready_safe` before it publishes the image, so
//! `load_manifest` cannot read AMPRIDX3 entries without deadlocking. The
//! first `ensure_manifest_ready` after publication builds it (CPU only, one
//! `Index::find` per AMPRIDX3 id); concurrent callers wait on `MANIFEST_CV`.
//! A packed path whose logical size differs from AMPRIDX3 invalidates the
//! mount (`LOAD_STATE = PACK_LOAD_INVALID`).

use super::*;
use ampr_format::zstd::Index;

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
/// `ZstdEntry::zstd_id` of a loose AMPRIDX3 id.
pub(crate) const ZSTD_FILE_NONE: u32 = u32::MAX;
/// `ZstdEntry` volume span of a loose or empty file.
pub(crate) const ZSTD_VOLUME_NONE: u16 = u16::MAX;

/// One projection record per one-based AMPRIDX3 id, at `[ampr_id - 1]`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ZstdEntry {
    /// Zero-based zstd file id, or `ZSTD_FILE_NONE` (loose).
    pub zstd_id: u32,
    /// First zstd chunk record of the file.
    pub first_chunk: u32,
    /// Chunks = read tasks of the whole file (256 KiB each, last one shorter).
    pub chunk_count: u32,
    /// Volume ids of the first and last chunk (a file may span volumes).
    pub first_volume: u16,
    pub last_volume: u16,
}
const _: () = assert!(size_of::<ZstdEntry>() == 16);

impl ZstdEntry {
    pub(crate) const LOOSE: Self = Self {
        zstd_id: ZSTD_FILE_NONE,
        first_chunk: 0,
        chunk_count: 0,
        first_volume: ZSTD_VOLUME_NONE,
        last_volume: ZSTD_VOLUME_NONE,
    };
    pub(crate) fn is_packed(&self) -> bool {
        self.zstd_id != ZSTD_FILE_NONE
    }
}

// ZSTD_PROJECTION values.
const PROJECTION_PENDING: u32 = 0;
const PROJECTION_BUILDING: u32 = 1;
const PROJECTION_READY: u32 = 2;
const PROJECTION_INVALID: u32 = 3;

struct ZstdMount {
    /// Borrows the pool allocation at `PackState::manifest_base`.
    index: Option<Index<'static>>,
    entries: *mut ZstdEntry,
    ampr_count: u32,
    packed_count: u32,
    /// Distinct zstd file ids of the packed AMPRIDX3 ids, in directory
    /// order (`zstd_sort_order`); null when `order_count == 0`.
    order: *mut u32,
    order_count: u32,
}

impl ZstdMount {
    const EMPTY: Self = Self {
        index: None,
        entries: null_mut(),
        ampr_count: 0,
        packed_count: 0,
        order: null_mut(),
        order_count: 0,
    };
}

/// Written by the single manifest loader (before `LOAD_STATE` turns ready)
/// and the single projection builder (before `ZSTD_PROJECTION` turns
/// ready); read-only afterwards until shutdown.
static ZSTD_MOUNT: SyncCell<ZstdMount> = SyncCell::new(ZstdMount::EMPTY);
static ZSTD_PROJECTION: AtomicU32 = AtomicU32::new(PROJECTION_PENDING);

// ---- pure projection logic ----------------------------------------------------

/// The zstd path of an AMPRIDX3 path: `/app0/<rel>` (`app0` case-folded, as
/// AMPRIDX3 stores it) gives `<rel>` with its case kept.
pub(crate) fn ampr_relative_path(path: &[u8]) -> Option<&[u8]> {
    (path.len() > 6
        && path[0] == b'/'
        && path[5] == b'/'
        && path[1..5].eq_ignore_ascii_case(b"app0"))
    .then(|| &path[6..])
}

/// Projection record of one AMPRIDX3 entry (`path`, logical `size`):
/// `ZstdEntry::LOOSE` when zstd has no such path (including paths zstd
/// cannot hold, e.g. non-UTF-8), `None` when the matched zstd file has a
/// different logical size or an unusable record (the mount is invalid).
pub(crate) fn project_entry(index: &Index<'_>, path: &[u8], size: u64) -> Option<ZstdEntry> {
    let Some(relative) = ampr_relative_path(path) else {
        return Some(ZstdEntry::LOOSE);
    };
    let Ok(Some(id)) = index.find(relative) else {
        return Some(ZstdEntry::LOOSE);
    };
    let file = index.file(id).ok()?;
    if file.logical_size != size {
        return None;
    }
    let zstd_id = u32::try_from(id).ok().filter(|&n| n != ZSTD_FILE_NONE)?;
    let (first_volume, last_volume) = if file.chunk_count == 0 {
        (ZSTD_VOLUME_NONE, ZSTD_VOLUME_NONE)
    } else {
        let last = file.first_chunk.checked_add(file.chunk_count - 1)?;
        (
            index.chunk(file.first_chunk).ok()?.volume_id,
            index.chunk(last).ok()?.volume_id,
        )
    };
    Some(ZstdEntry {
        zstd_id,
        first_chunk: file.first_chunk,
        chunk_count: file.chunk_count,
        first_volume,
        last_volume,
    })
}

/// Fills `out[n]` for AMPRIDX3 id `n + 1`; `entry(id)` yields that id's path
/// and logical size. Returns the packed-id count, or the first id that
/// invalidates the mount (no entry view, or a size mismatch).
pub(crate) fn project_ids<'p>(
    index: &Index<'_>,
    out: &mut [ZstdEntry],
    mut entry: impl FnMut(u32) -> Option<(&'p [u8], u64)>,
) -> Result<u32, u32> {
    let mut packed = 0u32;
    for (n, slot) in out.iter_mut().enumerate() {
        let id = u32::try_from(n + 1).map_err(|_| u32::MAX)?;
        let projected = entry(id).and_then(|(path, size)| project_entry(index, path, size));
        *slot = projected.ok_or(id)?;
        packed += u32::from(slot.is_packed());
    }
    Ok(packed)
}

// ---- mount lifecycle (manifest.rs) -------------------------------------------------

/// manifest.rs `validate_manifest_layout`: runs the full `Index::open` validation on
/// the loaded image and applies the runtime caps. On success the index
/// borrows `base` until `zstd_mount_clear`; the projection starts pending.
pub(crate) unsafe fn zstd_mount_validate(base: *mut c_void, bytes: usize) -> bool {
    if base.is_null() || bytes < ZSTD_INDEX_MIN_BYTES || bytes > isize::MAX as usize {
        return false;
    }
    // The pool allocation outlives the mount (freed by manifest.rs release only after
    // zstd_mount_clear drops this borrow).
    let image: &'static [u8] = unsafe { core::slice::from_raw_parts(base as *const u8, bytes) };
    let Ok(index) = Index::open(image) else {
        return false;
    };
    if index.file_count() > AMPR_EMU_PACK_MAX_FILES
        || u64::from(index.chunk_count()) > AMPR_EMU_PACK_MAX_CHUNKS
        || index.volume_count() as usize > AMPR_EMU_PACK_MAX_PACKS
    {
        return false;
    }
    let mount = unsafe { &mut *ZSTD_MOUNT.get() };
    *mount = ZstdMount::EMPTY;
    mount.index = Some(index);
    ZSTD_PROJECTION.store(PROJECTION_PENDING, Ordering::Release);
    true
}

/// manifest.rs `clear_manifest_view`: drops the index borrow and projection view.
/// The projection array must already be freed (`zstd_mount_release`).
pub(crate) fn zstd_mount_clear() {
    ZSTD_PROJECTION.store(PROJECTION_PENDING, Ordering::Release);
    unsafe { *ZSTD_MOUNT.get() = ZstdMount::EMPTY };
}

/// manifest.rs `release_manifest_storage`: frees the projection array and clears the
/// mount; manifest.rs then frees the index image itself.
pub(crate) unsafe fn zstd_mount_release() {
    let mount = unsafe { &mut *ZSTD_MOUNT.get() };
    if !mount.order.is_null() {
        unsafe {
            ampr_internal_amm_pool_free(
                mount.order as *mut c_void,
                c"apr.zstd.directory-index.release".as_ptr(),
            )
        };
        mount.order = null_mut();
    }
    if !mount.entries.is_null() {
        unsafe {
            ampr_internal_amm_pool_free(
                mount.entries as *mut c_void,
                c"apr.zstd.projection.release".as_ptr(),
            )
        };
        mount.entries = null_mut();
    }
    zstd_mount_clear();
}

// ---- projection build ---------------------------------------------------------

/// Builds the projection once, after the manifest is ready. Returns false
/// while AMPRIDX3 is unpublished (retry later), on stop, or when the mount
/// is invalid; concurrent callers wait for the single builder.
pub(crate) unsafe fn ensure_zstd_projection() -> bool {
    unsafe { zstd_projection_step(true) }
}

/// Nonblocking `ensure_zstd_projection` for hooks that may run under a
/// nonsleeping lock: builds inline (CPU only) when pending, but returns
/// false instead of waiting while another thread builds.
pub(crate) unsafe fn try_zstd_projection() -> bool {
    unsafe { zstd_projection_step(false) }
}

unsafe fn zstd_projection_step(wait: bool) -> bool {
    loop {
        match ZSTD_PROJECTION.load(Ordering::Acquire) {
            PROJECTION_READY => return true,
            PROJECTION_INVALID => return false,
            PROJECTION_BUILDING if !wait => return false,
            PROJECTION_BUILDING => {
                let mut lock = MANIFEST_MUTEX.lock();
                MANIFEST_CV.wait_until(&mut lock, || {
                    ZSTD_PROJECTION.load(Ordering::Acquire) != PROJECTION_BUILDING
                        || WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                });
                if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
                    return false;
                }
            }
            _ => {
                if WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                    || super::super::index::published().is_none()
                {
                    return false;
                }
                if ZSTD_PROJECTION
                    .compare_exchange(
                        PROJECTION_PENDING,
                        PROJECTION_BUILDING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                let built = unsafe { build_projection() };
                {
                    let _lock = MANIFEST_MUTEX.lock();
                    ZSTD_PROJECTION.store(
                        if built {
                            PROJECTION_READY
                        } else {
                            PROJECTION_INVALID
                        },
                        Ordering::Release,
                    );
                    if !built {
                        LOAD_STATE.store(PACK_LOAD_INVALID, Ordering::Release);
                    }
                }
                MANIFEST_CV.notify_all();
                return built;
            }
        }
    }
}

/// The sole builder (`ZSTD_PROJECTION == BUILDING`): one record per
/// published AMPRIDX3 id, in a pool allocation kept until shutdown.
unsafe fn build_projection() -> bool {
    let mount = unsafe { &mut *ZSTD_MOUNT.get() };
    let (Some(index), Some(count)) = (
        mount.index.as_ref(),
        super::super::index::published().map(|c| c.count),
    ) else {
        return false;
    };
    let Ok(ampr_count) = u32::try_from(count) else {
        return false;
    };
    if u64::from(ampr_count) > AMPR_EMU_PACK_MAX_FILES {
        return false;
    }
    let mut entries: *mut ZstdEntry = null_mut();
    if ampr_count != 0 {
        let bytes = count * size_of::<ZstdEntry>();
        let mut actual = 0usize;
        let memory = unsafe {
            ampr_internal_amm_pool_alloc(
                bytes,
                &mut actual,
                c"apr.zstd.projection".as_ptr(),
                true,
                align_of::<ZstdEntry>(),
            )
        };
        if memory.is_null() || actual < bytes {
            if !memory.is_null() {
                unsafe {
                    ampr_internal_amm_pool_free(memory, c"apr.zstd.projection.short".as_ptr())
                };
            }
            return false;
        }
        entries = memory as *mut ZstdEntry;
    }
    let out: &mut [ZstdEntry] = if entries.is_null() {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(entries, count) }
    };
    let result = project_ids(index, out, |id| {
        let mut view = FileEntryView {
            path: null(),
            path_length: 0,
            size: 0,
            mtime: 0,
        };
        if unsafe { ampr_index_get_entry_view(id, &mut view) } != 0 || view.path.is_null() {
            return None;
        }
        // The published AMPRIDX3 image is immutable for the module lifetime.
        let path: &'static [u8] =
            unsafe { core::slice::from_raw_parts(view.path.cast(), view.path_length as usize) };
        Some((path, view.size as u64))
    });
    let order = result
        .ok()
        .and_then(|packed| unsafe { build_order(index, out, packed) }.map(|o| (packed, o)));
    let Some((packed, (order, order_count))) = order else {
        if !entries.is_null() {
            unsafe {
                ampr_internal_amm_pool_free(
                    entries as *mut c_void,
                    c"apr.zstd.projection.invalid".as_ptr(),
                )
            };
        }
        return false;
    };
    mount.entries = entries;
    mount.ampr_count = ampr_count;
    mount.packed_count = packed;
    mount.order = order;
    mount.order_count = order_count;
    true
}

/// The directory order of the `packed` projected ids in `entries`: a pool
/// array of distinct zstd ids sorted by `zstd_sort_order` (null when no
/// id is packed). None on allocation failure.
unsafe fn build_order(
    index: &Index<'_>,
    entries: &[ZstdEntry],
    packed: u32,
) -> Option<(*mut u32, u32)> {
    if packed == 0 {
        return Some((null_mut(), 0));
    }
    let bytes = packed as usize * size_of::<u32>();
    let mut actual = 0usize;
    let memory = unsafe {
        ampr_internal_amm_pool_alloc(
            bytes,
            &mut actual,
            c"apr.zstd.directory-index".as_ptr(),
            true,
            align_of::<u32>(),
        )
    };
    if memory.is_null() || actual < bytes {
        if !memory.is_null() {
            unsafe {
                ampr_internal_amm_pool_free(memory, c"apr.zstd.directory-index.short".as_ptr())
            };
        }
        return None;
    }
    let order = unsafe { core::slice::from_raw_parts_mut(memory as *mut u32, packed as usize) };
    let ids = entries.iter().filter(|e| e.is_packed()).map(|e| e.zstd_id);
    for (slot, id) in order.iter_mut().zip(ids) {
        *slot = id;
    }
    let count = zstd_sort_order(index, order);
    Some((memory as *mut u32, count as u32))
}

// ---- accessors ----------------------------------------------------------------

pub(crate) fn zstd_projection_ready() -> bool {
    ZSTD_PROJECTION.load(Ordering::Acquire) == PROJECTION_READY
}

/// The mount, once the projection is ready (immutable from then on).
fn ready_mount() -> Option<&'static ZstdMount> {
    zstd_projection_ready().then(|| unsafe { &*ZSTD_MOUNT.get() })
}

pub(crate) fn zstd_index() -> Option<&'static Index<'static>> {
    ready_mount().and_then(|m| m.index.as_ref())
}

pub(crate) fn zstd_entry(ampr_id: u32) -> Option<ZstdEntry> {
    let mount = ready_mount()?;
    if ampr_id == 0 || ampr_id > mount.ampr_count || mount.entries.is_null() {
        return None;
    }
    let entry = unsafe { *mount.entries.add(ampr_id as usize - 1) };
    entry.is_packed().then_some(entry)
}

pub(crate) fn zstd_file_for_ampr_id(ampr_id: u32) -> Option<u64> {
    zstd_entry(ampr_id).map(|e| u64::from(e.zstd_id))
}

pub(crate) fn zstd_volume_count() -> u32 {
    zstd_index().map_or(0, |i| i.volume_count())
}

pub(crate) fn zstd_volume_size(volume: u32) -> Option<u64> {
    zstd_index().and_then(|i| i.volume_size(volume).ok())
}

pub(crate) fn zstd_chunk_count() -> u32 {
    zstd_index().map_or(0, |i| i.chunk_count())
}

pub(crate) fn zstd_ampr_count() -> u32 {
    ready_mount().map_or(0, |m| m.ampr_count)
}

/// Opaque `file` argument of the zstd `ampr_pack_core_task_count` and
/// `ampr_pack_core_make_task`: the address of the projection record of a
/// packed one-based AMPRIDX3 id. Null for a loose or unknown id.
pub(crate) fn zstd_task_file(ampr_id: u32) -> *const u8 {
    match (ready_mount(), zstd_entry(ampr_id)) {
        (Some(mount), Some(_)) => unsafe { mount.entries.add(ampr_id as usize - 1) as *const u8 },
        _ => null(),
    }
}

/// Directory order of the packed files (zstd ids); empty until ready.
pub(crate) fn zstd_packed_order() -> &'static [u32] {
    match ready_mount() {
        Some(m) if !m.order.is_null() && m.order_count != 0 => unsafe {
            core::slice::from_raw_parts(m.order, m.order_count as usize)
        },
        _ => &[],
    }
}

/// The packed record behind a `zstd_task_file` pointer; `None` for any
/// other pointer (outside the projection array, misaligned, or loose).
fn zstd_entry_at(file: *const u8) -> Option<ZstdEntry> {
    let mount = ready_mount()?;
    if mount.entries.is_null() {
        return None;
    }
    let at = (file as usize).checked_sub(mount.entries as usize)?;
    if at % size_of::<ZstdEntry>() != 0 {
        return None;
    }
    let slot = at / size_of::<ZstdEntry>();
    // slot < ampr_count <= u32::MAX, so slot + 1 fits.
    (slot < mount.ampr_count as usize)
        .then(|| zstd_entry(slot as u32 + 1))
        .flatten()
}

// ---- directory overlay (R6) ---------------------------------------------------
//
// zstd holds packed files only, in (path hash, path) order. Listings use the
// AMPRPAK4 directory order instead: ASCII-folded bytes of the logical path
// (`overlay::folded_compare`), then zstd id. Every logical path is
// `/app0/<zstd path>`, so ordering the relative paths orders the logical ones.

use ampr_format::overlay::{self, Child, LOGICAL_ROOT, PATH_MAX};
// The dirent types the pack runtime emits (mod.rs) are the overlay's.
const _: () = assert!(DT_DIR == overlay::DT_DIR && DT_REG == overlay::DT_REG);

/// Hidden from `/app0` listings, like the AMPRPAK4 index.
pub(crate) const ZSTD_INDEX_LOGICAL_PATH: &[u8] = b"/app0/ampr_zstd.index";

fn zstd_path<'a>(index: &Index<'a>, id: u32) -> Option<&'a [u8]> {
    index.file(u64::from(id)).ok().map(|f| f.path)
}

/// Sorts `order` (zstd ids) into directory order and drops repeated ids;
/// returns the length of the kept prefix. A record without a path sorts last.
pub(crate) fn zstd_sort_order(index: &Index<'_>, order: &mut [u32]) -> usize {
    order.sort_unstable_by(|&a, &b| zstd_order_compare(index, a, b));
    let mut kept = 0usize;
    for i in 0..order.len() {
        if kept == 0 || order[kept - 1] != order[i] {
            order[kept] = order[i];
            kept += 1;
        }
    }
    kept
}

/// Kept out of line: inlined, the sort's small-sort network grew to ~40 KB
/// of code for a sort that runs once, when the directory index is built.
#[inline(never)]
fn zstd_order_compare(index: &Index<'_>, a: u32, b: u32) -> core::cmp::Ordering {
    use core::cmp::Ordering as Cmp;
    match (zstd_path(index, a), zstd_path(index, b)) {
        (Some(x), Some(y)) => overlay::folded_compare(x, y).then(a.cmp(&b)),
        (Some(_), None) => Cmp::Less,
        (None, Some(_)) => Cmp::Greater,
        (None, None) => a.cmp(&b),
    }
}

/// The `/app0`-relative part of a normalized logical directory (`/app0` ->
/// empty, `/app0/a/b` -> `a/b`); None outside `/app0`.
pub(crate) fn zstd_relative_dir(directory: &[u8]) -> Option<&[u8]> {
    let root = LOGICAL_ROOT.len();
    if directory.len() < root || !directory[..root].eq_ignore_ascii_case(LOGICAL_ROOT) {
        return None;
    }
    match directory.get(root) {
        None => Some(&[]),
        Some(b'/') => Some(&directory[root + 1..]),
        _ => None,
    }
}

/// The `[begin, end)` span of `order` whose paths lie strictly below the
/// normalized logical `directory`; None when it has no packed descendant.
pub(crate) fn zstd_directory_range(
    index: &Index<'_>,
    order: &[u32],
    directory: &[u8],
) -> Option<(u32, u32)> {
    let relative = zstd_relative_dir(directory)?;
    let count = u32::try_from(order.len()).ok()?;
    if count == 0 || directory.len() >= PATH_MAX - 1 {
        return None;
    }
    if relative.is_empty() {
        return Some((0, count));
    }
    let mut buffer = [0u8; PATH_MAX];
    let n = relative.len() + 1;
    buffer[..relative.len()].copy_from_slice(relative);
    buffer[relative.len()] = b'/';
    overlay::prefix_range(order, &mut buffer[..n], |id| zstd_path(index, id))
}

/// `next_virtual_child` over zstd paths: the child at `order[cursor]` of
/// the normalized logical directory of `directory_len` bytes, merged with
/// the following entries of the same folded name (a directory if any of
/// them has descendants). `name` gets the NUL-terminated child name.
pub(crate) fn zstd_next_child(
    index: &Index<'_>,
    order: &[u32],
    range_end: u32,
    directory_len: usize,
    cursor: u32,
    name: &mut [u8],
) -> Option<Child> {
    let root = LOGICAL_ROOT.len();
    if directory_len < root {
        return None;
    }
    let dir_len = directory_len.saturating_sub(root + 1);
    overlay::next_child(order, range_end, dir_len, cursor, name, |id| {
        zstd_path(index, id)
    })
}

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
/// hidden until the projection is ready).
pub(crate) fn zstd_name_hidden(directory: &[u8], name: &[u8]) -> bool {
    zstd_service_name_hidden(zstd_volume_count(), directory, name)
}

/// Whether one-based AMPRIDX3 `ampr_id` is packed with logical size `size`.
pub(crate) fn zstd_packed_file_matches(ampr_id: u32, size: u64) -> bool {
    match (zstd_index(), zstd_entry(ampr_id)) {
        (Some(index), Some(entry)) => index
            .file(u64::from(entry.zstd_id))
            .is_ok_and(|f| f.logical_size == size),
        _ => false,
    }
}

// ---- core tasks and decode (R5) -----------------------------------------------
//
// zstd bodies of the `ampr_pack_core_*` exports in rt/index.rs (same ABI).
// Their `file` argument is `zstd_task_file(ampr_id)`; the `AmprPackCoreView`
// argument is ignored and the index comes from `zstd_index()`. A zstd
// chunk is the 8-byte record of `Index::chunk`, never an AMPRPAK4 record.

use ampr_format::zstd::{FileRecord as ZstdFileRecord, CHUNK_SIZE as ZSTD_CHUNK_BYTES};
use ampr_format::CoreError;

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
// scratch (worker.rs, also the warm-up scratch) is one max AMPRPAK4 block, a
// chunk's aligned backing window (virtual_read.rs make_pipeline_window_range) fits one
// staging window, and its pages fit the smallest mandatory group plan (page_plan.rs).
const _: () = {
    let page = ZSTD_IO_PAGE_SIZE as usize;
    let chunk_pages = (ZSTD_MAX_STORED_BYTES as usize).div_ceil(page) + 1;
    assert!(ZSTD_CHUNK_BYTES as usize <= PACK_MAX_BLOCK_BYTES);
    assert!(chunk_pages * page <= PACK_PIPELINE_IO_BYTES);
    assert!(chunk_pages <= PACK_MANDATORY_GROUP_MAX_REQUESTS);
};

fn request_valid(file: &ZstdFileRecord<'_>, offset: u64, length: u64) -> bool {
    length != 0 && offset <= file.logical_size && length <= file.logical_size - offset
}

/// Read tasks (256 KiB chunks touched) of `[offset, offset + length)` in
/// `file`; zero for a rejected request (empty, or past the end).
pub(crate) fn zstd_task_count(file: &ZstdFileRecord<'_>, offset: u64, length: u64) -> usize {
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
pub(crate) fn zstd_read_task(
    index: &Index<'_>,
    file: &ZstdFileRecord<'_>,
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
        },
    })
}

/// `ampr_pack_core_validate_logical_file` for a packed id: the zstd record
/// must hold the AMPRIDX3 path (relative, case kept) and logical size.
pub(crate) fn zstd_validate_logical(
    index: &Index<'_>,
    entry: &ZstdEntry,
    path: &[u8],
    logical_size: u64,
) -> Result<(), CoreError> {
    let file = index
        .file(u64::from(entry.zstd_id))
        .map_err(|_| CoreError::InvalidFormat)?;
    if file.logical_size != logical_size || ampr_relative_path(path) != Some(file.path) {
        return Err(CoreError::ChecksumMismatch);
    }
    Ok(())
}

/// A borrowed region; None for null or overflowing ranges.
unsafe fn region<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    (!p.is_null() && len <= isize::MAX as usize && (p as usize).checked_add(len).is_some())
        .then(|| unsafe { core::slice::from_raw_parts(p, len) })
}

/// The index and zstd file record behind a `zstd_task_file` pointer.
fn task_file(file: *const u8) -> Option<(&'static Index<'static>, ZstdFileRecord<'static>)> {
    let entry = zstd_entry_at(file)?;
    let index = zstd_index()?;
    let record = index.file(u64::from(entry.zstd_id)).ok()?;
    (record.first_chunk == entry.first_chunk && record.chunk_count == entry.chunk_count)
        .then_some((index, record))
}

/// zstd `ampr_pack_core_validate_logical_file`: `file_id` is a one-based
/// AMPRIDX3 id. A loose id has no zstd record to check and passes.
pub(crate) unsafe fn zstd_core_validate_logical_file(
    file_id: u32,
    path: *const c_char,
    path_len: usize,
    logical_size: u64,
) -> c_int {
    let (Some(index), Some(path)) = (zstd_index(), unsafe { region(path.cast(), path_len) }) else {
        return CoreError::InvalidArgument.code();
    };
    if file_id == 0 || file_id > zstd_ampr_count() {
        return CoreError::InvalidArgument.code();
    }
    match zstd_entry(file_id).map(|e| zstd_validate_logical(index, &e, path, logical_size)) {
        None | Some(Ok(())) => AMPR_PACK_CORE_OK,
        Some(Err(e)) => e.code(),
    }
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
            (b"/app0/data/A.BIN", 10),       // 5: case differs, loose
            (b"/app0/ampr_zstd.index", 999), // 6: loose
            (b"/app0/\xff", 1),              // 7: not UTF-8, loose
            (b"/app0/z/c.bin", 262_144),     // 8
        ]
    }

    fn project(
        index: &Index<'_>,
        entries: &[(&'static [u8], u64)],
    ) -> (Result<u32, u32>, Vec<ZstdEntry>) {
        let mut out = vec![ZstdEntry::LOOSE; entries.len()];
        let rc = project_ids(index, &mut out, |id| entries.get(id as usize - 1).copied());
        (rc, out)
    }

    #[test]
    fn relative_path_strips_folded_app0_root() {
        assert_eq!(ampr_relative_path(b"/app0/a/B.bin"), Some(&b"a/B.bin"[..]));
        assert_eq!(ampr_relative_path(b"/APP0/x"), Some(&b"x"[..]));
        assert_eq!(ampr_relative_path(b"/app0/"), None);
        assert_eq!(ampr_relative_path(b"/app1/x"), None);
        assert_eq!(ampr_relative_path(b"app0/xy"), None);
    }

    #[test]
    fn projects_every_ampr_id_onto_zstd_records() {
        let image = build_index(ZSTD_FILES, ("Data/B.bin", 1));
        let index = Index::open(&image).expect("test image validates");
        assert_eq!(index.volume_count(), 2);
        let entries = ampr_entries();
        let (rc, out) = project(&index, &entries);
        assert_eq!(rc, Ok(4));
        for (n, &(path, size)) in entries.iter().enumerate() {
            let expected = ampr_relative_path(path).and_then(|rel| index.find(rel).ok().flatten());
            match expected {
                None => assert_eq!(out[n], ZstdEntry::LOOSE, "id {}", n + 1),
                Some(id) => {
                    let file = index.file(id).unwrap();
                    assert_eq!(u64::from(out[n].zstd_id), id);
                    assert_eq!(file.logical_size, size);
                    assert_eq!(out[n].first_chunk, file.first_chunk);
                    assert_eq!(out[n].chunk_count, file.chunk_count);
                }
            }
        }
        for loose in [0, 4, 5, 6] {
            assert!(!out[loose].is_packed());
        }
        // Zero-based zstd ids follow hash order, not AMPRIDX3 order.
        let ids: Vec<u32> = [1, 2, 3, 7].iter().map(|&n| out[n].zstd_id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3]);
        assert_eq!(
            index.file(u64::from(out[2].zstd_id)).unwrap().path,
            b"Data/B.bin"
        );
        assert_eq!(
            (out[2].chunk_count, out[2].first_volume, out[2].last_volume),
            (2, 0, 1)
        );
        assert_eq!(
            (out[3].chunk_count, out[3].first_volume),
            (0, ZSTD_VOLUME_NONE)
        );
        assert_eq!(out[7].chunk_count, 1);
    }

    #[test]
    fn size_mismatch_or_missing_view_invalidates() {
        let image = build_index(ZSTD_FILES, ("Data/B.bin", 1));
        let index = Index::open(&image).unwrap();
        let mut entries = ampr_entries();
        entries[2].1 = 299_999;
        assert_eq!(project(&index, &entries).0, Err(3));
        // A loose path may have any size.
        let mut entries = ampr_entries();
        entries[0].1 = 1;
        assert_eq!(project(&index, &entries).0, Ok(4));
        let mut out = vec![ZstdEntry::LOOSE; 3];
        assert_eq!(
            project_ids(&index, &mut out, |id| (id != 2)
                .then_some((&b"/app0/x"[..], 0))),
            Err(2)
        );
        assert_eq!(project_ids(&index, &mut [], |_| None), Ok(0));
    }

    /// `Data/B.bin` (300 000 bytes): chunk 0 raw in volume 0, chunk 1 zstd
    /// (1000 stored bytes) at the start of volume 1.
    fn task_image() -> Vec<u8> {
        build_index_with(ZSTD_FILES, ("Data/B.bin", 1), |path, n| {
            (path == "Data/B.bin" && n == 1).then_some(1000)
        })
    }

    fn file<'a>(index: &Index<'a>, path: &str) -> ZstdFileRecord<'a> {
        let id = index.find(path.as_bytes()).unwrap().expect("path packed");
        index.file(id).unwrap()
    }

    #[test]
    fn tasks_use_fixed_256k_chunks_and_carry_volume_and_codec() {
        let image = task_image();
        let index = Index::open(&image).expect("test image validates");
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
    }

    #[test]
    fn partial_reads_split_at_chunk_boundaries() {
        let image = task_image();
        let index = Index::open(&image).unwrap();
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
    }

    #[test]
    fn empty_file_has_no_tasks() {
        let image = task_image();
        let index = Index::open(&image).unwrap();
        let f = file(&index, "data/empty");
        assert_eq!(f.chunk_count, 0);
        assert_eq!(zstd_task_count(&f, 0, 0), 0);
        assert_eq!(zstd_task_count(&f, 0, 1), 0);
        assert!(zstd_read_task(&index, &f, 0, 1, 0).is_err());
    }

    #[test]
    fn logical_file_matches_ampr_path_and_size() {
        let image = task_image();
        let index = Index::open(&image).unwrap();
        let entry = project_entry(&index, b"/APP0/Data/B.bin", 300_000).unwrap();
        assert!(entry.is_packed());
        assert_eq!(
            zstd_validate_logical(&index, &entry, b"/app0/Data/B.bin", 300_000),
            Ok(())
        );
        for (path, size) in [
            (&b"/app0/Data/B.bin"[..], 299_999),
            (b"/app0/data/b.bin", 300_000),
            (b"/app0/data/a.bin", 300_000),
        ] {
            assert_eq!(
                zstd_validate_logical(&index, &entry, path, size),
                Err(CoreError::ChecksumMismatch)
            );
        }
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

    fn tree_order(index: &Index<'_>) -> Vec<u32> {
        // Every id once in hash order, plus a repeat, as projection yields.
        let mut order: Vec<u32> = (0..index.file_count() as u32).collect();
        order.push(1);
        let kept = zstd_sort_order(index, &mut order);
        order.truncate(kept);
        order
    }

    fn children(index: &Index<'_>, order: &[u32], dir: &[u8]) -> Vec<(String, u8)> {
        let (begin, end) = zstd_directory_range(index, order, dir).expect("has packed files");
        let (mut out, mut cursor, mut name) = (Vec::new(), begin, [0u8; 256]);
        while let Some(c) = zstd_next_child(index, order, end, dir.len(), cursor, &mut name) {
            let text = String::from_utf8(name[..usize::from(c.len)].to_vec()).unwrap();
            assert_eq!(name[usize::from(c.len)], 0);
            out.push((text, c.kind));
            cursor = c.next;
        }
        assert_eq!(cursor, end, "listing consumes the whole range");
        out
    }

    #[test]
    fn directory_order_is_folded_path_order_not_hash_order() {
        let image = build_index(TREE, ("Data/B.bin", 1));
        let index = Index::open(&image).expect("test image validates");
        let order = tree_order(&index);
        let paths: Vec<&[u8]> = order
            .iter()
            .map(|&id| index.file(u64::from(id)).unwrap().path)
            .collect();
        let want: [&[u8]; 7] = [
            b"a b/x",
            b"data/a.bin",
            b"Data/B.bin",
            b"data/empty",
            b"data/sub/d.bin",
            b"top.bin",
            b"z/c.bin",
        ];
        assert_eq!(paths, want);
        assert_ne!(
            order,
            (0..7).collect::<Vec<u32>>(),
            "zstd ids are hash order"
        );

        assert_eq!(zstd_directory_range(&index, &order, b"/app0"), Some((0, 7)));
        assert_eq!(
            zstd_directory_range(&index, &order, b"/APP0/data"),
            Some((1, 5))
        );
        assert_eq!(
            zstd_directory_range(&index, &order, b"/app0/DATA/sub"),
            Some((4, 5))
        );
        for missing in [
            &b"/app0/top.bin"[..],
            b"/app0/dat",
            b"/app0/data/sub/d.bin",
            b"/app1",
            b"/app0x",
        ] {
            assert_eq!(zstd_directory_range(&index, &order, missing), None);
        }
        assert_eq!(zstd_directory_range(&index, &[], b"/app0"), None);

        let (d, r) = (DT_DIR, DT_REG);
        let s = |n: &str, k| (n.to_string(), k);
        assert_eq!(
            children(&index, &order, b"/app0"),
            [s("a b", d), s("data", d), s("top.bin", r), s("z", d)]
        );
        assert_eq!(
            children(&index, &order, b"/app0/Data"),
            [s("a.bin", r), s("B.bin", r), s("empty", r), s("sub", d)]
        );
        assert_eq!(children(&index, &order, b"/app0/data/sub"), [s("d.bin", r)]);
    }

    #[test]
    fn relative_dir_strips_logical_root() {
        assert_eq!(zstd_relative_dir(b"/app0"), Some(&b""[..]));
        assert_eq!(zstd_relative_dir(b"/APP0/a/B"), Some(&b"a/B"[..]));
        assert_eq!(zstd_relative_dir(b"/app0x"), None);
        assert_eq!(zstd_relative_dir(b"/app"), None);
    }

    #[test]
    fn hides_zstd_index_and_mounted_volumes_only() {
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

    #[test]
    fn task_exports_reject_foreign_file_pointers() {
        // No projection is mounted in host tests: every pointer is foreign.
        let record = [0u8; 48];
        assert!(zstd_task_file(1).is_null());
        assert_eq!(zstd_core_task_count(record.as_ptr(), 0, 1), 0);
        let mut task = AmprPackBlockReadTask {
            chunk_index: 7,
            ..Default::default()
        };
        let rc = unsafe { zstd_core_make_task(record.as_ptr(), 0, 1, 0, &mut task) };
        assert_eq!((rc, task.chunk_index), (-1, 0));
    }
}
