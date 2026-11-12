//! Manifest validation and loading, cache initialization, runtime profile
//! and decoded-cache hash table.

use super::*;
use crate::rt::index_memory::{
    self as im, cache_alloc, cache_room, index_room, lookup_alloc, lookup_free,
};
use crate::rt::index_pages::{self, IndexSource};

/// The mounted index image: AMPRZPK1 in zstd mode, else AMPRPAK4.
fn manifest_path() -> &'static CStr {
    if zstd_mode() {
        zstd::AMPR_EMU_ZSTD_INDEX_PATH
    } else {
        AMPR_EMU_PACK_INDEX_PATH
    }
}

fn manifest_min_bytes() -> usize {
    if zstd_mode() {
        zstd::ZSTD_INDEX_MIN_BYTES
    } else {
        size_of::<AmprPackIndexHeader>()
    }
}

/// AMPRPAK4 only: `ampr_pack_core_mount` runs the full Rust
/// `Manifest::open` validation through the mounted source, then the
/// runtime caps; a paged index also gets its fast table, without which
/// it is refused with the index notice. A zstd index is mounted by
/// `load_zstd_manifest`; its AMPRPAK4 view stays empty (`(*state).header`
/// null), so the AMPRPAK4 paths treat nothing as packed.
pub(crate) unsafe fn validate_manifest_layout(
    state: *mut PackState,
    src: &'static IndexSource,
) -> bool {
    let mut view = AmprPackCoreView::EMPTY;
    let mount_rc = unsafe { ampr_pack_core_mount(src, &mut view) };
    let header = view.header;
    if mount_rc != AMPR_PACK_CORE_OK
        || { header.file_count } > AMPR_EMU_PACK_MAX_FILES
        || { header.chunk_count } > AMPR_EMU_PACK_MAX_CHUNKS
        || { header.pack_count } as usize > AMPR_EMU_PACK_MAX_PACKS
    {
        return false;
    }
    if !src.is_resident() {
        let Some(m) = view.manifest.and_then(|m| unsafe { attach_lz4_fast(m) }) else {
            return false;
        };
        view.manifest = Some(m);
    }
    (*state).core_view = view;
    (*state).header = &raw const (*state).core_view.header;
    true
}

// ---- mounted index files ----

/// A pack index file as mounted: its source and the fd a paged source
/// reads its misses from (-1 for a resident one). Written only by the
/// single manifest loader before `LOAD_STATE` turns ready.
pub(crate) struct MountedSource(SyncCell<Option<(IndexSource, c_int)>>);

impl MountedSource {
    pub(crate) const fn new() -> Self {
        Self(SyncCell::new(None))
    }

    /// Whether the mounted file is read whole (no lock, no pread).
    pub(crate) unsafe fn is_resident(&self) -> bool {
        unsafe { &*self.0.get() }.is_some_and(|(s, _)| s.is_resident())
    }

    /// Gives the mounted file back (its memory or page registration) and
    /// closes its fd. Only for a source no published lookup holds: a
    /// failed mount, or a reload before the new file is mounted.
    pub(crate) unsafe fn drop_source(&self) {
        let Some((src, fd)) = (unsafe { &mut *self.0.get() }).take() else {
            return;
        };
        unsafe { src.release(c"apr.pack.index.release") };
        if fd >= 0 {
            if let Some(close_fn) = unsafe { real_close() } {
                unsafe { close_fn(fd) };
            }
        }
    }
}

/// The index file `fd` of `len` bytes as `slot`'s source, for both pack
/// formats: read whole into index memory when the file plus `derived` (the
/// derived tables the mount will build; a whole file needs no fast table)
/// fit the Index room left, else registered with the page cache (rt/index_pages.rs), which
/// keeps `fd` for its misses. A source mounted before (a reload) is
/// given back first, so the new file and length are the ones read. Takes
/// `fd`: closed unless kept. None when the page cache refused it.
pub(crate) unsafe fn mount_index_source(
    slot: &'static MountedSource,
    fd: c_int,
    len: u64,
    derived: usize,
) -> Option<&'static IndexSource> {
    unsafe { slot.drop_source() };
    let close = || {
        if let Some(close_fn) = unsafe { real_close() } {
            unsafe { close_fn(fd) };
        }
    };
    let fits = usize::try_from(len)
        .ok()
        .and_then(|n| n.checked_add(derived))
        .is_some_and(|n| n <= index_room());
    let resident = if fits {
        unsafe { index_pages::read_resident(fd, len, c"apr.pack.index") }
    } else {
        None
    };
    let mounted = match resident {
        Some(bytes) => {
            close();
            (IndexSource::Resident(bytes), -1)
        }
        None => match index_pages::register_file(fd, len) {
            Some(paged) => (IndexSource::Paged(paged), fd),
            None => {
                close();
                return None;
            }
        },
    };
    let cell = unsafe { &mut *slot.0.get() };
    Some(&cell.insert(mounted).0)
}

/// The mounted AMPRPAK4 index file (`mount_index_source`).
static LZ4_SOURCE: MountedSource = MountedSource::new();

/// The fast table of a paged AMPRPAK4 index and its `lookup_alloc` size;
/// null for a resident one. Written only by the single manifest loader.
static LZ4_FAST: SyncCell<(*mut u8, usize)> = SyncCell::new((null_mut(), 0));

/// Lookup bytes an AMPRPAK4 mount needs beside the file: the fast table
/// (the 48 B file, 12 B chunk and 32 B pack records) and the 4 B per file
/// of directory order.
fn lz4_lookup_bytes(files: u64, chunks: u64, packs: u64) -> (usize, usize) {
    let fast = files
        .saturating_mul(ampr_lz4::FILE_RECORD as u64)
        .saturating_add(chunks.saturating_mul(ampr_lz4::CHUNK_RECORD as u64))
        .saturating_add(packs.saturating_mul(ampr_lz4::PACK_RECORD as u64));
    let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    (size(fast), size(files.saturating_mul(4)))
}

/// The AMPRPAK4 index file `fd` of `len` bytes as the mount's source, read
/// whole when it fits the Index room with the directory order it still
/// needs (a whole file has no fast table), else paged. Takes `fd` (kept
/// for a paged source, else closed).
unsafe fn lz4_index_source(fd: c_int, len: u64) -> Option<&'static IndexSource> {
    let mut head = [0u8; ampr_lz4::PAK_HEADER];
    let derived = match index_pages::read_head(fd, &mut head)
        .then(|| ampr_lz4::manifest::header_counts(&head).ok())
        .flatten()
    {
        Some((files, chunks, packs)) => {
            lz4_lookup_bytes(u64::from(files), u64::from(chunks), u64::from(packs)).1
        }
        None => usize::MAX,
    };
    unsafe { mount_index_source(&LZ4_SOURCE, fd, len, derived) }
}

/// The fast table of a paged manifest, in one lookup allocation filled by
/// one pass over its record sections. None, with the index notice, when
/// it and the directory order still to come do not fit the lookup cap or
/// the Index room; None on a read error.
unsafe fn attach_lz4_fast(m: Lz4Manifest) -> Option<Lz4Manifest> {
    let bytes = m.fast_len();
    let needed = bytes.saturating_add(m.file_count() as usize * size_of::<u32>());
    if im::lookup_used().saturating_add(needed) > im::INDEX_LOOKUP_MAX || needed > index_room() {
        unsafe { index_pages::refuse(needed) };
        return None;
    }
    let size = bytes.max(8);
    let p = unsafe { lookup_alloc(size, 8, c"apr.pack.fast".as_ptr()) };
    if p.is_null() {
        return None;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(p, bytes) };
    if m.fill_fast(out).is_err() {
        unsafe { lookup_free(p.cast(), size, c"apr.pack.fast.invalid".as_ptr()) };
        return None;
    }
    let Ok(m) = m.with_fast(out) else {
        unsafe { lookup_free(p.cast(), size, c"apr.pack.fast.invalid".as_ptr()) };
        return None;
    };
    unsafe { *LZ4_FAST.get() = (p, size) };
    stats::add(stats::Stat::IndexFastBytes, size as u64);
    Some(m)
}

/// Frees the fast table; the view that read it is already cleared.
unsafe fn release_lz4_fast() {
    let (p, size) = core::mem::replace(unsafe { &mut *LZ4_FAST.get() }, (null_mut(), 0));
    if !p.is_null() {
        stats::sub(stats::Stat::IndexFastBytes, size as u64);
        unsafe { lookup_free(p.cast(), size, c"apr.pack.fast.release".as_ptr()) };
    }
}

/// The target from the pool under the cache cap, cut to what is left under
/// it (rt/index_memory.rs `cache_room`) but not below `min_bytes`. Freed by
/// `cache_free`.
unsafe fn cache_region(target: usize, min_bytes: usize, tag: &CStr) -> Option<(*mut u8, usize)> {
    let room = cache_room() & !(PACK_CACHE_PAGE_BYTES - 1);
    let bytes = align_up_size(target, PACK_CACHE_PAGE_BYTES).min(room);
    if bytes == 0 || bytes < target.min(min_bytes) {
        return None;
    }
    let memory = unsafe { cache_alloc(bytes, tag.as_ptr()) };
    (!memory.is_null()).then_some((memory, bytes))
}

/// AMPRPAK4 only: its `build_id` and path do not apply to a zstd mount.
pub(crate) unsafe fn load_runtime_profile(state: *mut PackState) -> bool {
    let (Some(open_fn), Some(fstat_fn), Some(close_fn)) =
        (unsafe { real_open() }, unsafe { real_fstat() }, unsafe {
            real_close()
        })
    else {
        return false;
    };
    let fd = unsafe {
        open_fn(
            AMPR_EMU_PACK_RUNTIME_PROFILE_PATH.as_ptr(),
            SCE_KERNEL_O_RDONLY,
            0 as c_int,
        )
    };
    if fd < 0 {
        let error = if fd == -1 {
            errno()
        } else {
            posix_errno_from_sce(fd)
        };
        return error == ENOENT;
    }
    let mut profile: AmprPackRuntimeProfile = unsafe { core::mem::zeroed() };
    let mut st: SceKernelStat = unsafe { core::mem::zeroed() };
    let size = size_of::<AmprPackRuntimeProfile>();
    let mut valid = unsafe { fstat_fn(fd, &mut st) } == 0
        && st.st_size == size as off_t
        && unsafe { pread_exact(fd, &mut profile as *mut _ as *mut c_void, size, 0) };
    let close_rc = unsafe { close_fn(fd) };
    let expected_crc = profile.crc32;
    profile.crc32 = 0;
    let (workers, reserve) = (profile.workers, profile.latency_reserve_workers);
    let (decoded, physical) = (profile.decoded_cache_bytes, profile.physical_cache_bytes);
    valid = valid
        && close_rc == 0
        && { profile.magic } == *b"AMPRCFG1"
        && { profile.version } == 1
        && { profile.size } as usize == size
        && { profile.reserved } == 0
        && { profile.build_id } == unsafe { (*(*state).header).build_id }
        && unsafe { ampr_pack_crc32(&profile as *const _ as *const c_void, size, 0) }
            == expected_crc
        && (1..=16).contains(&workers)
        && reserve < workers
        && decoded % PACK_CACHE_PAGE_BYTES as u64 == 0
        && physical % PACK_CACHE_PAGE_BYTES as u64 == 0;
    if !valid {
        return false;
    }
    // The format still carries a physical page cache size; there is no
    // such cache now, so its share goes to the decoded cache.
    let decoded = decoded.saturating_add(physical);
    (*state).decoded_cache_target_bytes =
        decoded.min(AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES) as usize;
    (*state).requested_workers = workers.min(AMPR_EMU_PACK_WORKER_CAPACITY as u32);
    (*state).latency_reserve_workers = reserve.min((*state).requested_workers - 1);
    true
}

/// Allocates the decoded cache, or leaves it off: a 0 target, or refused
/// under the cache cap.
unsafe fn initialize_decoded_cache(state: *mut PackState) {
    if (*state).decoded_cache_target_bytes == 0 || PACK_CACHE_MAX_PAGES == 0 {
        return;
    }
    let Some((memory, candidate)) = (unsafe {
        cache_region(
            (*state).decoded_cache_target_bytes,
            AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES as usize,
            c"apr.pack.decoded-cache",
        )
    }) else {
        return;
    };
    (*state).cache_base = memory;
    (*state).cache_bytes = candidate;
    (*state).cache_page_count = (candidate / PACK_CACHE_PAGE_BYTES) as u32;
    (*state).cache_page_bitmap.fill(0);
    (*state).cache_hash_heads.fill(0);
    (*state).cache_page_cursor = 0;
    (*state).cache_free_head = 0;
    for (i, entry) in (*state).cache_entries.iter_mut().enumerate() {
        *entry = CacheEntry::EMPTY;
        entry.free_next = if i + 1 < AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
    }
}

/// Carves the 64 MiB decoded cache from the pool at startup. No reserve is
/// held for the pipelines and workers: their windows and decode buffers
/// have their own Buffer ledger, and the Index, Cache and Buffer caps plus
/// the fixed sites fit the pool (rt/index_memory.rs), so a cache cannot
/// take their room. A refused cache stays off.
pub(crate) unsafe fn initialize_caches(state: *mut PackState) {
    unsafe {
        initialize_decoded_cache(state);
    }
}

pub(crate) unsafe fn clear_manifest_view(state: *mut PackState) {
    (*state).core_view = AmprPackCoreView::EMPTY;
    (*state).header = null();
    if zstd_mode() {
        zstd::zstd_mount_clear();
    }
}

pub(crate) unsafe fn release_manifest_storage(state: *mut PackState) {
    // Free the projection while the index image it was built from still exists.
    if zstd_mode() {
        unsafe { zstd::zstd_mount_release() };
    }
    if !(*state).packed_file_order.is_null() {
        unsafe {
            lookup_free(
                (*state).packed_file_order as *mut c_void,
                (*state).packed_file_count as usize * size_of::<u32>(),
                c"apr.pack.directory-index.release".as_ptr(),
            )
        };
        (*state).packed_file_order = null_mut();
    }
    (*state).packed_file_count = 0;
    // The index file stays mounted: hooks past the reader gate may still
    // read it; a failed mount or a reload gives it back. The fast table
    // goes with the view that reads it.
    clear_manifest_view(state);
    if !zstd_mode() {
        unsafe { release_lz4_fast() };
    }
}

pub(crate) unsafe fn load_manifest(state: *mut PackState, absent: *mut bool) -> bool {
    if !absent.is_null() {
        unsafe { *absent = false };
    }
    let (Some(open_fn), Some(close_fn), Some(fstat_fn), Some(_)) = (
        unsafe { real_open() },
        unsafe { real_close() },
        unsafe { real_fstat() },
        unsafe { real_pread() },
    ) else {
        return false;
    };
    let fd = unsafe { open_fn(manifest_path().as_ptr(), SCE_KERNEL_O_RDONLY, 0 as c_int) };
    if fd < 0 {
        let open_errno = if fd == -1 {
            errno()
        } else {
            posix_errno_from_sce(fd)
        };
        if !absent.is_null() && open_errno == ENOENT {
            unsafe { *absent = true };
        }
        return false;
    }
    let mut stat: SceKernelStat = unsafe { core::mem::zeroed() };
    let stat_rc = unsafe { fstat_fn(fd, &mut stat) };
    if stat_rc != 0
        || stat.st_size < manifest_min_bytes() as off_t
        || stat.st_size as u64 > AMPR_EMU_PACK_INDEX_MAX_BYTES
    {
        unsafe { close_fn(fd) };
        return false;
    }
    if zstd_mode() {
        return unsafe { load_zstd_manifest(state, fd, stat.st_size as u64) };
    }
    unsafe { load_lz4_manifest(state, fd, stat.st_size as u64) }
}

/// AMPRPAK4: the index file is mounted with `mount_index_source`, whole
/// when it fits with its tables, else paged with a resident fast table. A
/// failed mount gives the source back.
unsafe fn load_lz4_manifest(state: *mut PackState, fd: c_int, len: u64) -> bool {
    let Some(source) = (unsafe { lz4_index_source(fd, len) }) else {
        return false;
    };
    if !unsafe { validate_manifest_layout(state, source) } {
        clear_manifest_view(state);
        unsafe { LZ4_SOURCE.drop_source() };
        return false;
    }
    if !unsafe { load_runtime_profile(state) } || !unsafe { build_packed_file_order(state) } {
        unsafe { release_manifest_storage(state) };
        unsafe { LZ4_SOURCE.drop_source() };
        return false;
    }
    // The lookup tables are built: the page arena takes the room left.
    index_pages::grow_arena(0);
    unsafe { initialize_caches(state) };
    true
}

/// zstd: the index file is mounted with `mount_index_source`, whole when
/// it fits with its tables, else paged with a resident fast table. A
/// failed mount gives the source back. zstd keeps the cache defaults; its
/// directory order and AMPRIDX3 projection come later
/// (zstd::ensure_zstd_projection), which then grows the page arena.
unsafe fn load_zstd_manifest(state: *mut PackState, fd: c_int, len: u64) -> bool {
    let Some(source) = (unsafe { zstd::zstd_index_source(fd, len) }) else {
        return false;
    };
    if !unsafe { zstd::zstd_mount_validate(source) } {
        unsafe { zstd::zstd_mount_release() };
        clear_manifest_view(state);
        unsafe { zstd::zstd_source_drop() };
        return false;
    }
    unsafe { initialize_caches(state) };
    true
}

/// zstd: the mount also needs its AMPRIDX3 projection, built on the first
/// call after AMPRIDX3 is published (see zstd.rs).
pub(crate) unsafe fn ensure_manifest_ready() -> bool {
    unsafe { ensure_manifest_loaded() && (!zstd_mode() || zstd::ensure_zstd_projection()) }
}

pub(crate) unsafe fn ensure_manifest_loaded() -> bool {
    let state = unsafe { pack_state() };
    loop {
        if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
            return false;
        }
        let current = LOAD_STATE.load(Ordering::Acquire);
        if current == PACK_LOAD_READY {
            return true;
        }
        if current == PACK_LOAD_UNAVAILABLE || current == PACK_LOAD_INVALID {
            return false;
        }
        // Claimed under MANIFEST_MUTEX with the stop flag rechecked: shutdown
        // sets the flag and then waits for LOADING to end under the same
        // mutex, so a load either starts before that wait or not at all.
        let claimed = {
            let _lock = MANIFEST_MUTEX.lock();
            !WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                && LOAD_STATE
                    .compare_exchange(
                        PACK_LOAD_UNINITIALIZED,
                        PACK_LOAD_LOADING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
        };
        if claimed {
            let mut absent = false;
            let loaded = unsafe { load_manifest(state, &mut absent) };
            {
                let _lock = MANIFEST_MUTEX.lock();
                let next = if loaded {
                    PACK_LOAD_READY
                } else if absent {
                    PACK_LOAD_UNAVAILABLE
                } else {
                    PACK_LOAD_INVALID
                };
                LOAD_STATE.store(next, Ordering::Release);
            }
            MANIFEST_CV.notify_all();
            return loaded;
        }
        let mut lock = MANIFEST_MUTEX.lock();
        MANIFEST_CV.wait_until(&mut lock, || {
            LOAD_STATE.load(Ordering::Acquire) != PACK_LOAD_LOADING
                || WORKER_STOP_REQUESTED.load(Ordering::Acquire)
        });
    }
}

pub(crate) fn chunk_key_hash(chunk: &AmprPackChunkView) -> u64 {
    ampr_rust_cache_chunk_key_hash(
        chunk.offset,
        chunk.pack_id,
        chunk.stored_size,
        chunk.raw_size,
    )
}

pub(crate) fn cache_key_equal(
    entry: &CacheEntry,
    chunk: &AmprPackChunkView,
    key_hash: u64,
) -> bool {
    entry.state != CacheEntryState::Free
        && entry.key_hash == key_hash
        && entry.pack_id == chunk.pack_id
        && entry.physical_offset == chunk.offset
        && entry.stored_size == chunk.stored_size
        && entry.raw_size == chunk.raw_size
}

pub(crate) unsafe fn cache_find_locked(
    state: *mut PackState,
    chunk: &AmprPackChunkView,
    key_hash: u64,
) -> u32 {
    let bucket = ampr_format::cache::bucket_index(key_hash, AMPR_EMU_PACK_CACHE_HASH_BUCKETS);
    let mut link = (*state).cache_hash_heads[bucket];
    while link != 0 {
        let index = link - 1;
        if index as usize >= AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            break;
        }
        let entry = &(*state).cache_entries[index as usize];
        if cache_key_equal(entry, chunk, key_hash) {
            return index;
        }
        link = entry.hash_next_plus_one;
    }
    INVALID_INDEX
}

pub(crate) unsafe fn cache_hash_link_locked(state: *mut PackState, index: u32) {
    let entry = &mut (*state).cache_entries[index as usize];
    let bucket = ampr_format::cache::bucket_index(entry.key_hash, AMPR_EMU_PACK_CACHE_HASH_BUCKETS);
    entry.hash_next_plus_one = (*state).cache_hash_heads[bucket];
    (*state).cache_hash_heads[bucket] = index + 1;
}

pub(crate) unsafe fn cache_hash_unlink_locked(state: *mut PackState, index: u32) {
    let bucket = ampr_format::cache::bucket_index(
        (*state).cache_entries[index as usize].key_hash,
        AMPR_EMU_PACK_CACHE_HASH_BUCKETS,
    );
    let next = (*state).cache_entries[index as usize].hash_next_plus_one;
    // `prev` is None while the link is the bucket head.
    let mut prev: Option<usize> = None;
    let mut link = (*state).cache_hash_heads[bucket];
    while link != 0 {
        let current = link - 1;
        if current == index {
            match prev {
                None => (*state).cache_hash_heads[bucket] = next,
                Some(p) => (*state).cache_entries[p].hash_next_plus_one = next,
            }
            break;
        }
        if current as usize >= AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            break;
        }
        prev = Some(current as usize);
        link = (*state).cache_entries[current as usize].hash_next_plus_one;
    }
    (*state).cache_entries[index as usize].hash_next_plus_one = 0;
}

/// `bitmap_words(arr)`: the word count of a fixed bitmap array.
pub(crate) const fn bitmap_words<const N: usize>(_: &[u64; N]) -> usize {
    N
}

// Page-bitmap allocator (next-fit with cursor wrap): ampr_format::cache.
pub(crate) unsafe fn cache_mark_pages(state: *mut PackState, start: u32, count: u32, used: bool) {
    let words = bitmap_words(&(*state).cache_page_bitmap);
    unsafe {
        ampr_rust_cache_mark_pages(
            (*state).cache_page_bitmap.as_mut_ptr(),
            words,
            start,
            count,
            used,
        )
    };
}
