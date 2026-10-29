//! Physical-cache leases and invalidation, pack paths, data header
//! validation and pack fd acquisition.

use super::super::fd_cache::{
    ampr_index_fd_cache_mark_open_pressure, ampr_index_fd_cache_release_idle_percent,
    ampr_index_fd_cache_stats, ampr_index_fd_uncached_open_count,
};
use super::*;

pub(crate) unsafe fn physical_cache_acquire_locked(
    state: *mut PackState,
    pack_id: u16,
    offset: u64,
    size: u32,
    key_hash: u64,
) -> PhysicalCacheAcquireResult {
    let mut result = PhysicalCacheAcquireResult::EMPTY;
    let found = physical_cache_find_locked(state, pack_id, offset, size, key_hash);
    if found != INVALID_INDEX {
        let base = (*state).physical_cache_base;
        let entry = &mut (*state).physical_cache_entries[found as usize];
        match entry.state {
            PhysicalCacheEntryState::Loading => {
                result.kind = PhysicalCacheAcquireKind::Pending;
                return result;
            }
            PhysicalCacheEntryState::Ready => {
                entry.pin_count += 1;
                entry.referenced = true;
                result.kind = PhysicalCacheAcquireKind::Ready;
                result.lease.entry = found;
                result.lease.data = base.add(entry.page_start as usize * PACK_CACHE_PAGE_BYTES);
                return result;
            }
            PhysicalCacheEntryState::Failed => {
                result.kind = PhysicalCacheAcquireKind::Failed;
                result.lease.error = if entry.error != 0 {
                    entry.error
                } else {
                    SCE_KERNEL_ERROR_EIO
                };
                return result;
            }
            PhysicalCacheEntryState::Free => {}
        }
    }

    let page_count = ((size as usize + PACK_CACHE_PAGE_BYTES - 1) / PACK_CACHE_PAGE_BYTES) as u32;
    let mut page_start = physical_cache_find_page_run_locked(state, page_count);
    while (page_start == INVALID_INDEX || (*state).physical_cache_free_head == INVALID_INDEX)
        && physical_cache_evict_one_locked(state)
    {
        page_start = physical_cache_find_page_run_locked(state, page_count);
    }
    if page_start == INVALID_INDEX || (*state).physical_cache_free_head == INVALID_INDEX {
        return result;
    }

    let index = (*state).physical_cache_free_head;
    let entry = &mut (*state).physical_cache_entries[index as usize];
    (*state).physical_cache_free_head = entry.free_next;
    *entry = PhysicalCacheEntry {
        key_hash,
        physical_offset: offset,
        size,
        page_start,
        page_count,
        pin_count: 1,
        pack_id,
        state: PhysicalCacheEntryState::Loading,
        referenced: true,
        free_next: INVALID_INDEX,
        ..PhysicalCacheEntry::EMPTY
    };
    physical_cache_mark_pages(state, page_start, page_count, true);
    let page_end = page_start + page_count;
    (*state).physical_cache_page_cursor = if page_end == (*state).physical_cache_page_count {
        0
    } else {
        page_end
    };
    physical_cache_hash_link_locked(state, index);
    result.kind = PhysicalCacheAcquireKind::Load;
    result.lease.entry = index;
    result.lease.data = (*state)
        .physical_cache_base
        .add(page_start as usize * PACK_CACHE_PAGE_BYTES);
    result.lease.loader = true;
    result
}

pub(crate) unsafe fn physical_cache_acquire_batch(
    items: *const PhysicalCacheAcquireBatchItem,
    item_count: usize,
) -> usize {
    if items.is_null() || item_count == 0 {
        return 0;
    }
    let state = pack_state();
    let _lock = PHYSICAL_CACHE_MUTEX.lock();
    let mut processed = 0;
    while processed < item_count {
        let item = *items.add(processed);
        if item.result.is_null() {
            break;
        }
        *item.result = PhysicalCacheAcquireResult::EMPTY;
        if physical_cache_request_valid(state, item.offset, item.size) {
            *item.result = physical_cache_acquire_locked(
                state,
                item.pack_id,
                item.offset,
                item.size,
                physical_cache_key_hash(item.pack_id, item.offset, item.size),
            );
        }
        let kind = (*item.result).kind;
        if kind != PhysicalCacheAcquireKind::Ready && kind != PhysicalCacheAcquireKind::Load {
            return processed + 1;
        }
        processed += 1;
    }
    processed
}

/// Read extension (page_plan.rs): Load leases for consecutive `size` pages from
/// `offset` into `pages`, stopping at the first page already in the cache (any
/// state) or without a Load lease. Never waits. Returns the pages taken.
pub(crate) unsafe fn physical_cache_acquire_extension(
    pack_id: u16,
    offset: u64,
    size: u32,
    pages: &mut [PipelineMandatoryPage],
) -> usize {
    let state = pack_state();
    let _lock = PHYSICAL_CACHE_MUTEX.lock();
    let mut count = 0;
    while count < pages.len() {
        let page_offset = offset + count as u64 * size as u64;
        let key_hash = physical_cache_key_hash(pack_id, page_offset, size);
        if !physical_cache_request_valid(state, page_offset, size)
            || physical_cache_find_locked(state, pack_id, page_offset, size, key_hash)
                != INVALID_INDEX
        {
            break;
        }
        let acquired = physical_cache_acquire_locked(state, pack_id, page_offset, size, key_hash);
        if acquired.kind != PhysicalCacheAcquireKind::Load {
            break;
        }
        pages[count] = PipelineMandatoryPage {
            acquired,
            offset: page_offset,
            size,
            pack_id,
            extension: true,
            ..PipelineMandatoryPage::EMPTY
        };
        count += 1;
    }
    count
}

pub(crate) unsafe fn physical_cache_publish_batch(
    publications: *const PhysicalCachePublication,
    publication_count: usize,
) {
    if publications.is_null() || publication_count == 0 {
        return;
    }
    let state = pack_state();
    let mut published = false;
    let mut published_buckets = 0u64;
    {
        let _lock = PHYSICAL_CACHE_MUTEX.lock();
        for i in 0..publication_count {
            let publication = *publications.add(i);
            let lease = publication.lease;
            if lease.is_null()
                || (*lease).entry == INVALID_INDEX
                || (*lease).entry as usize >= AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP
            {
                continue;
            }
            let index = (*lease).entry;
            let entry = &mut (*state).physical_cache_entries[index as usize];
            if entry.state != PhysicalCacheEntryState::Loading || entry.pin_count == 0 {
                continue;
            }
            if publication.error == 0 {
                entry.state = PhysicalCacheEntryState::Ready;
                entry.error = 0;
            } else if cache_error_is_transient(publication.error) && entry.pin_count == 1 {
                let wait_bucket = cache_wait_bucket(entry.key_hash);
                physical_cache_release_entry_locked(state, index);
                *lease = PhysicalCacheLease::EMPTY;
                published_buckets |= 1u64 << wait_bucket;
                published = true;
                continue;
            } else {
                entry.state = PhysicalCacheEntryState::Failed;
                entry.error = publication.error;
            }
            published_buckets |= 1u64 << cache_wait_bucket(entry.key_hash);
            published = true;
        }
    }
    if !published {
        return;
    }
    for bucket in 0..PACK_CACHE_WAIT_BUCKET_COUNT {
        if published_buckets & (1u64 << bucket) != 0 {
            PHYSICAL_CACHE_PUBLICATION_EPOCH[bucket].fetch_add(1, Ordering::Release);
        }
    }
}

pub(crate) unsafe fn physical_cache_release_locked(
    state: *mut PackState,
    lease: &mut PhysicalCacheLease,
) {
    if lease.entry == INVALID_INDEX {
        return;
    }
    if (lease.entry as usize) < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP {
        let entry = &mut (*state).physical_cache_entries[lease.entry as usize];
        if entry.pin_count != 0 {
            entry.pin_count -= 1;
        }
        if entry.pin_count == 0
            && entry.state == PhysicalCacheEntryState::Failed
            && cache_error_is_transient(entry.error)
        {
            physical_cache_release_entry_locked(state, lease.entry);
        }
    }
    *lease = PhysicalCacheLease::EMPTY;
}

pub(crate) unsafe fn physical_cache_release_batch(
    leases: *const *mut PhysicalCacheLease,
    lease_count: usize,
) {
    if leases.is_null() || lease_count == 0 {
        return;
    }
    let state = pack_state();
    let _lock = PHYSICAL_CACHE_MUTEX.lock();
    for i in 0..lease_count {
        let lease = *leases.add(i);
        if !lease.is_null() {
            physical_cache_release_locked(state, &mut *lease);
        }
    }
}

pub(crate) unsafe fn physical_cache_invalidate(pack_id: u16, offset: u64, size: u32) {
    if size == 0 {
        return;
    }
    let state = pack_state();
    let key_hash = physical_cache_key_hash(pack_id, offset, size);
    let _lock = PHYSICAL_CACHE_MUTEX.lock();
    let found = physical_cache_find_locked(state, pack_id, offset, size, key_hash);
    if found == INVALID_INDEX {
        return;
    }
    let entry = &mut (*state).physical_cache_entries[found as usize];
    if entry.pin_count == 0 && entry.state != PhysicalCacheEntryState::Loading {
        physical_cache_release_entry_locked(state, found);
    } else if entry.state == PhysicalCacheEntryState::Ready {
        entry.state = PhysicalCacheEntryState::Failed;
        entry.error = SCE_KERNEL_ERROR_EIO;
    }
}

// ---- mounted volume geometry (AMPRPAK4 records, or the zstd index) -----------

/// Physical page size of every zstd volume: zstd has no per-volume I/O page
/// record, so cache I/O uses the cache page. Chunks start at any byte (the
/// first at 64, after the header), so page reads align down to page 0.
pub(crate) const ZSTD_IO_PAGE_SIZE: u32 = PACK_CACHE_PAGE_BYTES as u32;
const _: () = assert!(
    ZSTD_IO_PAGE_SIZE.is_power_of_two()
        && ZSTD_IO_PAGE_SIZE >= 1 << AMPR_PACK_IO_PAGE_SHIFT_MIN
        && ZSTD_IO_PAGE_SIZE <= 1 << AMPR_PACK_IO_PAGE_SHIFT_MAX
);

/// True once the volume records are mounted: the AMPRPAK4 header and pack
/// table, or the zstd index (its projection ready).
pub(crate) unsafe fn pack_mount_ready(state: *const PackState) -> bool {
    if zstd_mode() {
        zstd::zstd_index().is_some()
    } else {
        !(*state).header.is_null() && !(*state).packs.is_null()
    }
}

/// Mounted pack volumes (0 while unmounted): AMPRPAK4 `pack_count`, or the
/// zstd volume count once its projection is ready.
pub(crate) unsafe fn pack_volume_count(state: *const PackState) -> u32 {
    if zstd_mode() {
        zstd::zstd_volume_count()
    } else if (*state).header.is_null() {
        0
    } else {
        unsafe { (*(*state).header).pack_count }
    }
}

/// Mounted chunk records (0 while unmounted).
pub(crate) unsafe fn pack_chunk_count(state: *const PackState) -> u64 {
    if zstd_mode() {
        u64::from(zstd::zstd_chunk_count())
    } else if (*state).header.is_null() {
        0
    } else {
        unsafe { (*(*state).header).chunk_count }
    }
}

/// Physical I/O page size of volume `pack_id`, or None when it is not mounted.
pub(crate) unsafe fn pack_io_page_size(state: *const PackState, pack_id: u16) -> Option<u32> {
    if u32::from(pack_id) >= unsafe { pack_volume_count(state) } {
        return None;
    }
    if zstd_mode() {
        Some(ZSTD_IO_PAGE_SIZE)
    } else if (*state).packs.is_null() {
        None
    } else {
        Some(unsafe { (*(*state).packs.add(pack_id as usize)).io_page_size })
    }
}

/// zstd: a backing read of `[offset, offset + nbyte)` may end past the end of
/// volume `pack_id`, because its last page is aligned up (payload_end). A
/// read that stopped exactly at the volume end is complete: zero the tail of
/// `buf` and report `nbyte`. Any other result is left for the caller to check.
pub(crate) unsafe fn zstd_complete_eof_read(
    pack_id: u16,
    offset: u64,
    nbyte: usize,
    buf: *mut u8,
    return_value: &mut i64,
) {
    let Some(volume_size) = zstd::zstd_volume_size(u32::from(pack_id)) else {
        return;
    };
    let read = *return_value;
    if buf.is_null() || read < 0 || read as u64 >= nbyte as u64 || offset >= volume_size {
        return;
    }
    if offset.checked_add(read as u64) != Some(volume_size) {
        return;
    }
    unsafe { core::ptr::write_bytes(buf.add(read as usize), 0, nbyte - read as usize) };
    *return_value = nbyte as i64;
}

pub(crate) unsafe fn build_pack_path(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    if zstd_mode() {
        unsafe { build_pack_path_zstd(state, pack_id, output, output_size) }
    } else {
        unsafe { build_pack_path_lz4(state, pack_id, output, output_size) }
    }
}

unsafe fn build_pack_path_zstd(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    let mut name_buffer = [0u8; 32];
    if output.is_null() || u32::from(pack_id) >= unsafe { pack_volume_count(state) } {
        return false;
    }
    let Ok(name) = ampr_format::zstd::volume_name(u32::from(pack_id), &mut name_buffer) else {
        return false;
    };
    let name = name.as_bytes();
    let root = AMPR_EMU_PACK_ROOT_PATH.to_bytes();
    let needs_slash = !root.is_empty() && root[root.len() - 1] != b'/';
    let prefix_length = root.len() + needs_slash as usize;
    if prefix_length + name.len() + 1 > output_size {
        return false;
    }
    let out = output as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(root.as_ptr(), out, root.len());
        if needs_slash {
            *out.add(root.len()) = b'/';
        }
        core::ptr::copy_nonoverlapping(name.as_ptr(), out.add(prefix_length), name.len());
        *out.add(prefix_length + name.len()) = 0;
    }
    true
}

unsafe fn build_pack_path_lz4(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    if output.is_null()
        || output_size == 0
        || (*state).header.is_null()
        || pack_id as u32 >= { (*(*state).header).pack_count }
    {
        return false;
    }
    let record = *(*state).packs.add(pack_id as usize);
    let name = manifest_string(state, record.name_offset, record.name_length);
    let root = AMPR_EMU_PACK_ROOT_PATH.to_bytes();
    let needs_slash = !root.is_empty() && root[root.len() - 1] != b'/';
    let prefix_length = root.len() + needs_slash as usize;
    let name_length = record.name_length as usize;
    if name.is_null() || prefix_length + name_length + 1 > output_size {
        return false;
    }
    let out = output as *mut u8;
    core::ptr::copy_nonoverlapping(root.as_ptr(), out, root.len());
    if needs_slash {
        *out.add(root.len()) = b'/';
    }
    core::ptr::copy_nonoverlapping(name as *const u8, out.add(prefix_length), name_length);
    *out.add(prefix_length + name_length) = 0;
    true
}

/// zstd: checks the 64-byte AMPRZDT1 header against the mounted index and
/// the actual size (`file_size`, from fstat) against `Index::volume_size`.
/// Chunk offsets are absolute and the first chunk starts at 64, inside page
/// 0, so the page-granular I/O range is `[0, volume size aligned up)`; a read
/// of the last page stops at the volume end (`zstd_complete_eof_read`).
pub(crate) unsafe fn validate_data_header(
    state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    if zstd_mode() {
        unsafe {
            validate_data_header_zstd(state, pack_id, fd, file_size, payload_begin, payload_end)
        }
    } else {
        unsafe {
            validate_data_header_lz4(state, pack_id, fd, file_size, payload_begin, payload_end)
        }
    }
}

unsafe fn validate_data_header_zstd(
    _state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    use ampr_format::zstd::VOLUME_HEADER_SIZE;
    let Some(index) = zstd::zstd_index() else {
        return false;
    };
    let volume = u32::from(pack_id);
    let Ok(volume_size) = index.volume_size(volume) else {
        return false;
    };
    let mut page_end = 0u64;
    if payload_begin.is_null()
        || payload_end.is_null()
        || file_size != volume_size
        || !unsafe { align_up_u64(volume_size, u64::from(ZSTD_IO_PAGE_SIZE), &mut page_end) }
    {
        return false;
    }
    let mut header = [0u8; VOLUME_HEADER_SIZE];
    stats::add(stats::Stat::PackDiskReads, 1);
    stats::add(stats::Stat::PackDiskBytes, VOLUME_HEADER_SIZE as u64);
    if !unsafe { pread_exact(fd, header.as_mut_ptr() as *mut c_void, header.len(), 0) } {
        return false;
    }
    if ampr_format::zstd::volume_header(&header, index, volume).is_err() {
        return false;
    }
    unsafe {
        *payload_begin = 0;
        *payload_end = page_end;
    }
    true
}

unsafe fn validate_data_header_lz4(
    state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    let mut header = MaybeUninit::<AmprPackDataHeader>::zeroed();
    stats::add(stats::Stat::PackDiskReads, 1);
    stats::add(
        stats::Stat::PackDiskBytes,
        size_of::<AmprPackDataHeader>() as u64,
    );
    if !pread_exact(
        fd,
        header.as_mut_ptr() as *mut c_void,
        size_of::<AmprPackDataHeader>(),
        0,
    ) {
        return false;
    }
    let record = *(*state).packs.add(pack_id as usize);
    ampr_rust_volume_header_validate(
        header.as_ptr() as *const u8,
        core::ptr::addr_of!((*(*state).header).build_id) as *const u8,
        pack_id as u32,
        record.flags,
        record.file_size,
        record.payload_bytes,
        record.io_page_size,
        file_size,
        payload_begin,
        payload_end,
    ) != 0
}

/// `open_only` (read-ahead, readahead.rs): use only an already-open handle; return
/// EAGAIN instead of evicting another handle or opening this one.
pub(crate) unsafe fn acquire_pack_fd(pack_id: u16, open_only: bool) -> c_int {
    let state = pack_state();
    let mut path = [0 as c_char; SCE_KERNEL_PATH_MAX];
    let (Some(open_fn), Some(_), Some(fstat_fn)) = (real_open(), real_close(), real_fstat()) else {
        return SCE_KERNEL_ERROR_EIO;
    };
    let id = pack_id as usize;
    let mut victim_fd = -1;
    {
        let _lock = PACK_M.lock();
        // AMPRPAK4 pack count, or the zstd volume count.
        let pack_count = pack_volume_count(state);
        if pack_id as u32 >= pack_count {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        if (*state).pack_handles[id].fd >= 0 {
            if (*state).pack_handles[id].pins == u32::MAX {
                return SCE_KERNEL_ERROR_EBUSY;
            }
            (*state).pack_handles[id].pins += 1;
            (*state).pack_handles[id].last_use = (*state).tick;
            (*state).tick += 1;
            return (*state).pack_handles[id].fd;
        }
        if open_only || (*state).pack_handles[id].opening {
            return SCE_KERNEL_ERROR_EAGAIN;
        }
        if !build_pack_path(state, pack_id, path.as_mut_ptr(), path.len()) {
            return SCE_KERNEL_ERROR_ENAMETOOLONG;
        }
        if (*state).open_pack_count + (*state).opening_pack_count >= AMPR_EMU_PACK_OPEN_PACK_FD_CAP
        {
            let mut victim = INVALID_INDEX;
            let mut oldest = u64::MAX;
            for i in 0..pack_count {
                let c = &(*state).pack_handles[i as usize];
                if c.fd >= 0 && c.pins == 0 && !c.opening && c.last_use < oldest {
                    victim = i;
                    oldest = c.last_use;
                }
            }
            if victim == INVALID_INDEX {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            victim_fd = (*state).pack_handles[victim as usize].fd;
            (*state).pack_handles[victim as usize] = PackHandle::EMPTY;
            if (*state).open_pack_count == 0 {
                abort();
            }
            (*state).open_pack_count -= 1;
        }
        (*state).pack_handles[id].opening = true;
        (*state).opening_pack_count += 1;
    }

    if victim_fd >= 0 {
        close_physical_pack_fd(victim_fd);
    }
    if !ampr_index_fd_cache_release_open_fd_budget_headroom(1) {
        let _lock = PACK_M.lock();
        if !(*state).pack_handles[id].opening || (*state).opening_pack_count == 0 {
            abort();
        }
        (*state).pack_handles[id].opening = false;
        (*state).opening_pack_count -= 1;
        return SCE_KERNEL_ERROR_EAGAIN;
    }
    let mut fd = open_fn(path.as_ptr(), SCE_KERNEL_O_RDONLY | O_NONBLOCK, 0 as c_int);
    // A signal is not fd pressure: retry the open a few times instead of parking.
    let mut eintr_retries = 0;
    while fd == -1 && errno() == EINTR && eintr_retries < 3 {
        fd = open_fn(path.as_ptr(), SCE_KERNEL_O_RDONLY | O_NONBLOCK, 0 as c_int);
        eintr_retries += 1;
    }
    // libc open/fstat return -1 with errno.
    let mut result = if fd == -1 {
        let err = errno();
        if posix_errno_is_fd_open_pressure(err) {
            let observed = ampr_index_fd_cache_stats()
                .open
                .saturating_add(ampr_index_fd_uncached_open_count());
            ampr_index_fd_cache_mark_open_pressure(observed);
            ampr_index_fd_cache_release_idle_percent(100);
            SCE_KERNEL_ERROR_EAGAIN
        } else {
            sce_errno_from_posix(err)
        }
    } else {
        fd
    };
    if fd >= 0 {
        ampr_index_fd_pack_note_open();
    }
    let mut stat: SceKernelStat = core::mem::zeroed();
    let stat_rc = if fd >= 0 {
        let rc = fstat_fn(fd, &mut stat);
        if rc == -1 {
            sce_errno_from_posix(errno())
        } else {
            rc
        }
    } else {
        fd
    };
    let mut payload_begin = 0u64;
    let mut payload_end = 0u64;
    if fd >= 0
        && (stat_rc != 0
            || stat.st_size < 0
            || !validate_data_header(
                state,
                pack_id,
                fd,
                stat.st_size as u64,
                &mut payload_begin,
                &mut payload_end,
            ))
    {
        close_physical_pack_fd(fd);
        fd = -1;
        result = if stat_rc != 0 {
            stat_rc
        } else {
            SCE_KERNEL_ERROR_EIO
        };
    }
    let wake_workers;
    {
        let _lock = PACK_M.lock();
        if !(*state).pack_handles[id].opening || (*state).opening_pack_count == 0 {
            abort();
        }
        (*state).pack_handles[id].opening = false;
        (*state).opening_pack_count -= 1;
        if fd >= 0 {
            let tick = (*state).tick;
            (*state).tick += 1;
            let handle = &mut (*state).pack_handles[id];
            handle.fd = fd;
            handle.pins = 1;
            handle.last_use = tick;
            handle.payload_begin = payload_begin;
            handle.payload_end = payload_end;
            (*state).open_pack_count += 1;
        }
        // Any finished attempt except a pressure EAGAIN releases `opening`: wake its waiters.
        if fd >= 0 || result != SCE_KERNEL_ERROR_EAGAIN {
            PACK_FD_PROGRESS_EPOCH.fetch_add(1, Ordering::Release);
        }
        wake_workers = wake_fd_waiters_locked(state);
    }
    if wake_workers {
        QUEUE_CV.notify_all();
    }
    result
}
