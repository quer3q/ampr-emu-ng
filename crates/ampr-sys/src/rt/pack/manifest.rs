//! Manifest validation and loading, cache initialization, runtime profile
//! and decoded-cache hash table.

use super::*;

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

/// zstd: `Index::open` plus runtime caps; the AMPRPAK4 view stays empty
/// (`(*state).header` null), so the AMPRPAK4 paths treat nothing as packed.
pub(crate) unsafe fn validate_manifest_layout(
    state: *mut PackState,
    base: *mut c_void,
    bytes: usize,
) -> bool {
    if zstd_mode() {
        unsafe { zstd::zstd_mount_validate(base, bytes) }
    } else {
        unsafe { validate_manifest_layout_lz4(state, base, bytes) }
    }
}

unsafe fn validate_manifest_layout_lz4(
    state: *mut PackState,
    base: *mut c_void,
    bytes: usize,
) -> bool {
    // ampr_pack_core_mount runs the full Rust Manifest::open validation.
    let mut view = AmprPackCoreView::EMPTY;
    let mount_rc = unsafe { ampr_pack_core_mount(base, bytes, &mut view) };
    let header = view.header as *const AmprPackIndexHeader;
    if mount_rc != AMPR_PACK_CORE_OK
        || header.is_null()
        || unsafe { (*header).file_count } > AMPR_EMU_PACK_MAX_FILES
        || unsafe { (*header).chunk_count } > AMPR_EMU_PACK_MAX_CHUNKS
        || unsafe { (*header).pack_count } as usize > AMPR_EMU_PACK_MAX_PACKS
    {
        return false;
    }
    (*state).header = header;
    (*state).files = view.files as *const AmprPackFileRecord;
    (*state).chunks = view.chunks as *const AmprPackChunkRecord;
    (*state).packs = view.packs as *const AmprPackDataRecord;
    (*state).strings = view.strings;
    (*state).strings_bytes = view.strings_size;
    (*state).core_view = view;
    true
}

/// Shared halving allocator of initialize_physical_cache/initialize_decoded_cache:
/// returns (memory, candidate) of the first candidate the pool fully satisfies.
unsafe fn alloc_cache_region(
    target: usize,
    min_bytes: usize,
    tag: &CStr,
    short_tag: &CStr,
) -> Option<(*mut u8, usize)> {
    let mut candidate = align_up_size(target, PACK_CACHE_PAGE_BYTES);
    let minimum = align_up_size(target.min(min_bytes), PACK_CACHE_PAGE_BYTES);
    while candidate != usize::MAX && candidate >= minimum && candidate != 0 {
        let mut actual = 0usize;
        let memory = unsafe {
            ampr_internal_amm_pool_alloc(
                candidate,
                &mut actual,
                tag.as_ptr(),
                false,
                PACK_CACHE_PAGE_BYTES,
            )
        };
        if !memory.is_null() && actual >= candidate {
            return Some((memory as *mut u8, candidate));
        }
        if !memory.is_null() {
            unsafe { ampr_internal_amm_pool_free(memory, short_tag.as_ptr()) };
        }
        candidate /= 2;
        candidate &= !(PACK_CACHE_PAGE_BYTES - 1);
    }
    None
}

pub(crate) unsafe fn initialize_physical_cache(state: *mut PackState) {
    if (*state).physical_cache_target_bytes == 0 || PACK_PHYSICAL_CACHE_MAX_PAGES == 0 {
        return;
    }
    let Some((memory, candidate)) = (unsafe {
        alloc_cache_region(
            (*state).physical_cache_target_bytes,
            AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES as usize,
            c"apr.pack.physical-page-cache",
            c"apr.pack.physical-page-cache.short",
        )
    }) else {
        return;
    };
    (*state).physical_cache_base = memory;
    (*state).physical_cache_bytes = candidate;
    (*state).physical_cache_page_count = (candidate / PACK_CACHE_PAGE_BYTES) as u32;
    (*state).physical_cache_page_bitmap.fill(0);
    (*state).physical_cache_hash_heads.fill(0);
    (*state).physical_cache_page_cursor = 0;
    (*state).physical_cache_free_head = 0;
    for (i, entry) in (*state).physical_cache_entries.iter_mut().enumerate() {
        *entry = PhysicalCacheEntry::EMPTY;
        entry.free_next = if i + 1 < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
    }
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
    (*state).decoded_cache_target_bytes =
        decoded.min(AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES) as usize;
    (*state).physical_cache_target_bytes =
        physical.min(AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES) as usize;
    (*state).requested_workers = workers.min(AMPR_EMU_PACK_WORKER_CAPACITY as u32);
    (*state).latency_reserve_workers = reserve.min((*state).requested_workers - 1);
    (*state).runtime_profile_loaded = true;
    true
}

pub(crate) unsafe fn runtime_cache_reserve_bytes(state: *const PackState) -> usize {
    let mut reserve = super::super::tune::reserve_bytes();
    let pipelines = super::super::tune::pipelines();
    if pipelines > (usize::MAX - reserve) / PACK_PIPELINE_IO_BYTES {
        return usize::MAX;
    }
    reserve += pipelines * PACK_PIPELINE_IO_BYTES;
    if (*state).requested_workers as usize > (usize::MAX - reserve) / PACK_MAX_BLOCK_BYTES {
        return usize::MAX;
    }
    reserve += (*state).requested_workers as usize * PACK_MAX_BLOCK_BYTES;
    align_up_size(reserve, PACK_CACHE_PAGE_BYTES)
}

pub(crate) unsafe fn initialize_decoded_cache(state: *mut PackState) {
    if (*state).decoded_cache_target_bytes == 0 || PACK_CACHE_MAX_PAGES == 0 {
        return;
    }
    let Some((memory, candidate)) = (unsafe {
        alloc_cache_region(
            (*state).decoded_cache_target_bytes,
            AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES as usize,
            c"apr.pack.decoded-cache",
            c"apr.pack.decoded-cache.short",
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

/// Holds a reserve for pipelines/workers while the caches are carved out, so
/// they cannot take the memory the runtime needs later.
pub(crate) unsafe fn initialize_caches(state: *mut PackState) {
    let reserve_bytes = runtime_cache_reserve_bytes(state);
    let mut reserve_actual = 0usize;
    let mut reserve: *mut c_void = null_mut();
    if reserve_bytes != 0 && reserve_bytes != usize::MAX {
        reserve = unsafe {
            ampr_internal_amm_pool_alloc(
                reserve_bytes,
                &mut reserve_actual,
                c"apr.pack.cache-reserve".as_ptr(),
                false,
                PACK_CACHE_PAGE_BYTES,
            )
        };
    }
    if reserve.is_null() || reserve_actual < reserve_bytes {
        if !reserve.is_null() {
            unsafe {
                ampr_internal_amm_pool_free(reserve, c"apr.pack.cache-reserve.short".as_ptr())
            };
        }
        return;
    }
    unsafe {
        initialize_physical_cache(state);
        initialize_decoded_cache(state);
        ampr_internal_amm_pool_free(reserve, c"apr.pack.cache-reserve.release".as_ptr());
    }
}

pub(crate) unsafe fn clear_manifest_view(state: *mut PackState) {
    (*state).manifest_base = null_mut();
    (*state).manifest_bytes = 0;
    (*state).core_view = AmprPackCoreView::EMPTY;
    (*state).header = null();
    (*state).files = null();
    (*state).chunks = null();
    (*state).packs = null();
    (*state).strings = null();
    (*state).strings_bytes = 0;
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
            ampr_internal_amm_pool_free(
                (*state).packed_file_order as *mut c_void,
                c"apr.pack.directory-index.release".as_ptr(),
            )
        };
        (*state).packed_file_order = null_mut();
    }
    (*state).packed_file_count = 0;
    let manifest = (*state).manifest_base;
    clear_manifest_view(state);
    if !manifest.is_null() {
        unsafe { ampr_internal_amm_pool_free(manifest, c"apr.pack.index.release".as_ptr()) };
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
    let bytes = stat.st_size as usize;
    let mut actual = 0usize;
    let memory = unsafe {
        ampr_internal_amm_pool_alloc(
            bytes,
            &mut actual,
            c"apr.pack.index".as_ptr(),
            true,
            core::mem::align_of::<AmprPackIndexHeader>(),
        )
    };
    if memory.is_null() || actual < bytes || !unsafe { pread_exact(fd, memory, bytes, 0) } {
        if !memory.is_null() {
            unsafe { ampr_internal_amm_pool_free(memory, c"apr.pack.index.fail".as_ptr()) };
        }
        unsafe { close_fn(fd) };
        return false;
    }
    unsafe { close_fn(fd) };

    if !unsafe { validate_manifest_layout(state, memory, bytes) } {
        unsafe { ampr_internal_amm_pool_free(memory, c"apr.pack.index.invalid".as_ptr()) };
        clear_manifest_view(state);
        return false;
    }
    (*state).manifest_base = memory;
    (*state).manifest_bytes = bytes;
    // zstd keeps the cache defaults; its directory order and AMPRIDX3
    // projection come later (zstd::ensure_zstd_projection, R6).
    if !zstd_mode()
        && (!unsafe { load_runtime_profile(state) } || !unsafe { build_packed_file_order(state) })
    {
        unsafe { release_manifest_storage(state) };
        return false;
    }
    unsafe { initialize_caches(state) };
    (*state).profile_decoded_bytes = (*state).cache_bytes;
    (*state).profile_physical_bytes = (*state).physical_cache_bytes;
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
        if LOAD_STATE
            .compare_exchange(
                PACK_LOAD_UNINITIALIZED,
                PACK_LOAD_LOADING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
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
    let bucket = (key_hash & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
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
    let bucket = (entry.key_hash & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
    entry.hash_next_plus_one = (*state).cache_hash_heads[bucket];
    (*state).cache_hash_heads[bucket] = index + 1;
}

pub(crate) unsafe fn cache_hash_unlink_locked(state: *mut PackState, index: u32) {
    let bucket = ((*state).cache_entries[index as usize].key_hash
        & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
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
