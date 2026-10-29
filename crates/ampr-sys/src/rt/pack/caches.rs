//! Decoded-cache admission, acquire/publish/release and physical-cache
//! hash table, page runs and eviction.

use super::*;

pub(crate) unsafe fn cache_find_page_run_locked(state: *mut PackState, count: u32) -> u32 {
    let words = bitmap_words(&(*state).cache_page_bitmap);
    unsafe {
        ampr_rust_cache_find_page_run(
            (*state).cache_page_bitmap.as_ptr(),
            words,
            (*state).cache_page_count,
            (*state).cache_page_cursor,
            count,
        )
    }
}

pub(crate) unsafe fn cache_release_entry_locked(state: *mut PackState, index: u32) {
    cache_hash_unlink_locked(state, index);
    let (start, count) = {
        let e = &(*state).cache_entries[index as usize];
        (e.page_start, e.page_count)
    };
    if count != 0 {
        cache_mark_pages(state, start, count, false);
    }
    let entry = &mut (*state).cache_entries[index as usize];
    *entry = CacheEntry::EMPTY;
    entry.state = CacheEntryState::Free;
    entry.free_next = (*state).cache_free_head;
    (*state).cache_free_head = index;
}

pub(crate) unsafe fn cache_evict_one_locked(state: *mut PackState) -> bool {
    for _ in 0..AMPR_EMU_PACK_CACHE_ENTRY_CAP as u32 * 2 {
        let index = (*state).cache_clock % AMPR_EMU_PACK_CACHE_ENTRY_CAP as u32;
        (*state).cache_clock = (*state).cache_clock.wrapping_add(1);
        let entry = &mut (*state).cache_entries[index as usize];
        if entry.state == CacheEntryState::Free
            || entry.pin_count != 0
            || entry.state == CacheEntryState::Loading
        {
            continue;
        }
        if entry.referenced {
            entry.referenced = false;
            continue;
        }
        cache_release_entry_locked(state, index);
        return true;
    }
    false
}

pub(crate) unsafe fn cache_should_admit_locked(
    state: *mut PackState,
    chunk: &AmprPackChunkView,
    file_flags: u32,
    key_hash: u64,
) -> bool {
    if file_flags & AMPR_PACK_FILE_STREAMING != 0 || chunk.flags & AMPR_PACK_CHUNK_STREAMING != 0 {
        return false;
    }
    if file_flags & AMPR_PACK_FILE_HOT != 0 || chunk.flags & AMPR_PACK_CHUNK_SHARED != 0 {
        return true;
    }
    let touch =
        &mut (*state).touches[(key_hash & (AMPR_EMU_PACK_TOUCH_TABLE_SIZE as u64 - 1)) as usize];
    if touch.key_hash != key_hash {
        touch.key_hash = key_hash;
        touch.count = 1;
        return false;
    }
    if touch.count < 3 {
        touch.count += 1;
    }
    touch.count >= 2
}

/// `wait_for_loader = false` returns Pending on a Loading entry instead of
/// blocking. `force_admit` (read-ahead, readahead.rs) skips
/// the admission policy, so a missing chunk always gets a Load lease if room.
pub(crate) unsafe fn cache_acquire(
    chunk: &AmprPackChunkView,
    file_flags: u32,
    wait_for_loader: bool,
    force_admit: bool,
) -> CacheAcquireResult {
    let state = unsafe { pack_state() };
    let mut result = CacheAcquireResult::EMPTY;
    if (*state).cache_base.is_null() || (*state).cache_page_count == 0 {
        return result;
    }
    let key_hash = chunk_key_hash(chunk);
    let mut lock = CACHE_MUTEX.lock();
    loop {
        let found = cache_find_locked(state, chunk, key_hash);
        if found != INVALID_INDEX {
            let entry = &mut (*state).cache_entries[found as usize];
            match entry.state {
                CacheEntryState::Loading => {
                    if !wait_for_loader {
                        // While Loading, error marks a waiter; publication replaces it.
                        entry.error = 1;
                        result.kind = CacheAcquireKind::Pending;
                        return result;
                    }
                    CACHE_CVS[(key_hash & (PACK_CACHE_WAIT_BUCKET_COUNT as u64 - 1)) as usize]
                        .wait(&mut lock);
                    continue;
                }
                CacheEntryState::Ready => {
                    entry.pin_count += 1;
                    entry.referenced = true;
                    result.kind = CacheAcquireKind::Ready;
                    result.lease.entry = found;
                    result.lease.data = unsafe {
                        (*state)
                            .cache_base
                            .add(entry.page_start as usize * PACK_CACHE_PAGE_BYTES)
                    };
                    return result;
                }
                CacheEntryState::Failed => {
                    result.kind = CacheAcquireKind::Failed;
                    result.lease.error = if entry.error != 0 {
                        entry.error
                    } else {
                        SCE_KERNEL_ERROR_EIO
                    };
                    return result;
                }
                CacheEntryState::Free => {}
            }
        }

        if !force_admit && !cache_should_admit_locked(state, chunk, file_flags, key_hash) {
            return result;
        }
        let page_count =
            ((chunk.raw_size as usize + PACK_CACHE_PAGE_BYTES - 1) / PACK_CACHE_PAGE_BYTES) as u32;
        let mut page_start = cache_find_page_run_locked(state, page_count);
        while (page_start == INVALID_INDEX || (*state).cache_free_head == INVALID_INDEX)
            && cache_evict_one_locked(state)
        {
            page_start = cache_find_page_run_locked(state, page_count);
        }
        if page_start == INVALID_INDEX || (*state).cache_free_head == INVALID_INDEX {
            return result;
        }
        let index = (*state).cache_free_head;
        let entry = &mut (*state).cache_entries[index as usize];
        (*state).cache_free_head = entry.free_next;
        *entry = CacheEntry {
            key_hash,
            physical_offset: chunk.offset,
            stored_size: chunk.stored_size,
            raw_size: chunk.raw_size,
            page_start,
            page_count,
            pin_count: 1,
            pack_id: chunk.pack_id,
            state: CacheEntryState::Loading,
            referenced: true,
            free_next: INVALID_INDEX,
            ..CacheEntry::EMPTY
        };
        cache_mark_pages(state, page_start, page_count, true);
        let page_end = page_start + page_count;
        (*state).cache_page_cursor = if page_end == (*state).cache_page_count {
            0
        } else {
            page_end
        };
        cache_hash_link_locked(state, index);
        result.kind = CacheAcquireKind::Load;
        result.lease.entry = index;
        result.lease.data = unsafe {
            (*state)
                .cache_base
                .add(page_start as usize * PACK_CACHE_PAGE_BYTES)
        };
        result.lease.loader = true;
        return result;
    }
}

pub(crate) fn cache_error_is_transient(error: c_int) -> bool {
    error == SCE_KERNEL_ERROR_EAGAIN
        || error == SCE_KERNEL_ERROR_EMFILE
        || error == SCE_KERNEL_ERROR_ENFILE
        || error == SCE_KERNEL_ERROR_ENOMEM
        || error == SCE_KERNEL_ERROR_EINTR
        || error == SCE_KERNEL_ERROR_ECANCELED
}

pub(crate) unsafe fn cache_publish(lease: &mut CacheLease, error: c_int) -> bool {
    if lease.entry == INVALID_INDEX {
        return false;
    }
    let state = unsafe { pack_state() };
    let wait_bucket;
    let waited;
    {
        let _lock = CACHE_MUTEX.lock();
        if lease.entry as usize >= AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            return false;
        }
        let entry = &mut (*state).cache_entries[lease.entry as usize];
        if entry.state != CacheEntryState::Loading || entry.pin_count == 0 {
            return false;
        }
        wait_bucket = (entry.key_hash & (PACK_CACHE_WAIT_BUCKET_COUNT as u64 - 1)) as usize;
        waited = entry.error != 0;
        if error == 0 {
            entry.state = CacheEntryState::Ready;
            entry.error = 0;
        } else if cache_error_is_transient(error) && entry.pin_count == 1 {
            // Pending readers do not pin loading entries; drop a transient
            // loader failure before waking them so none sees Failed.
            cache_release_entry_locked(state, lease.entry);
            *lease = CacheLease::EMPTY;
        } else {
            entry.state = CacheEntryState::Failed;
            entry.error = error;
        }
    }
    DECODED_CACHE_PUBLICATION_EPOCH[wait_bucket].fetch_add(1, Ordering::Release);
    CACHE_CVS[wait_bucket].notify_all();
    waited
}

pub(crate) unsafe fn cache_release(lease: &mut CacheLease) {
    if lease.entry == INVALID_INDEX {
        return;
    }
    let state = unsafe { pack_state() };
    let _lock = CACHE_MUTEX.lock();
    if (lease.entry as usize) < AMPR_EMU_PACK_CACHE_ENTRY_CAP {
        let entry = &mut (*state).cache_entries[lease.entry as usize];
        if entry.pin_count != 0 {
            entry.pin_count -= 1;
        }
        if entry.pin_count == 0
            && entry.state == CacheEntryState::Failed
            && cache_error_is_transient(entry.error)
        {
            cache_release_entry_locked(state, lease.entry);
        }
    }
    *lease = CacheLease::EMPTY;
}

pub(crate) unsafe fn cache_try_pin_ready(chunk: &AmprPackChunkView, out: *mut CacheLease) -> bool {
    if out.is_null() {
        return false;
    }
    let out = unsafe { &mut *out };
    *out = CacheLease::EMPTY;
    let state = unsafe { pack_state() };
    if (*state).cache_base.is_null() || (*state).cache_page_count == 0 {
        return false;
    }
    let key_hash = chunk_key_hash(chunk);
    let _lock = CACHE_MUTEX.lock();
    let found = cache_find_locked(state, chunk, key_hash);
    if found == INVALID_INDEX {
        return false;
    }
    let entry = &mut (*state).cache_entries[found as usize];
    if entry.state != CacheEntryState::Ready {
        return false;
    }
    entry.pin_count += 1;
    entry.referenced = true;
    out.entry = found;
    out.data = unsafe {
        (*state)
            .cache_base
            .add(entry.page_start as usize * PACK_CACHE_PAGE_BYTES)
    };
    true
}

pub(crate) fn physical_cache_key_hash(pack_id: u16, offset: u64, size: u32) -> u64 {
    ampr_rust_physical_cache_key_hash(pack_id, offset, size)
}

// ampr_format::cache::WAIT_BUCKETS sizes the epoch and condvar arrays.
const _: () = assert!(PACK_CACHE_WAIT_BUCKET_COUNT == 64);
pub(crate) fn cache_wait_bucket(key_hash: u64) -> u32 {
    ampr_rust_cache_wait_bucket(key_hash)
}

/// The epochs are statics; `state` is unused.
pub(crate) unsafe fn cache_wait_epoch(
    _state: *const PackState,
    domain: CacheWaitDomain,
    bucket: u32,
) -> u64 {
    if bucket as usize >= PACK_CACHE_WAIT_BUCKET_COUNT {
        return 0;
    }
    let epochs = if domain == CacheWaitDomain::Physical {
        &PHYSICAL_CACHE_PUBLICATION_EPOCH
    } else {
        &DECODED_CACHE_PUBLICATION_EPOCH
    };
    epochs[bucket as usize].load(Ordering::Acquire)
}

/// Reads the epoch statics directly: `pipeline` usually lives inside
/// PackState, so no second access path to it is needed here.
pub(crate) unsafe fn prepare_cache_wait(
    pipeline: &mut ReadPipelineContext,
    domain: CacheWaitDomain,
    key_hash: u64,
) {
    pipeline.cache_wait_domain = domain;
    pipeline.cache_wait_bucket = cache_wait_bucket(key_hash) as u16;
    let epochs = if domain == CacheWaitDomain::Physical {
        &PHYSICAL_CACHE_PUBLICATION_EPOCH
    } else {
        &DECODED_CACHE_PUBLICATION_EPOCH
    };
    pipeline.cache_wait_epoch = epochs
        .get(pipeline.cache_wait_bucket as usize)
        .map_or(0, |e| e.load(Ordering::Acquire));
}

pub(crate) fn physical_cache_key_equal(
    entry: &PhysicalCacheEntry,
    pack_id: u16,
    offset: u64,
    size: u32,
    key_hash: u64,
) -> bool {
    entry.state != PhysicalCacheEntryState::Free
        && entry.key_hash == key_hash
        && entry.pack_id == pack_id
        && entry.physical_offset == offset
        && entry.size == size
}

pub(crate) unsafe fn physical_cache_find_locked(
    state: *mut PackState,
    pack_id: u16,
    offset: u64,
    size: u32,
    key_hash: u64,
) -> u32 {
    let bucket = (key_hash & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
    let mut link = (*state).physical_cache_hash_heads[bucket];
    while link != 0 {
        let index = link - 1;
        if index as usize >= AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP {
            break;
        }
        let entry = &(*state).physical_cache_entries[index as usize];
        if physical_cache_key_equal(entry, pack_id, offset, size, key_hash) {
            return index;
        }
        link = entry.hash_next_plus_one;
    }
    INVALID_INDEX
}

pub(crate) unsafe fn physical_cache_hash_link_locked(state: *mut PackState, index: u32) {
    let entry = &mut (*state).physical_cache_entries[index as usize];
    let bucket = (entry.key_hash & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
    entry.hash_next_plus_one = (*state).physical_cache_hash_heads[bucket];
    (*state).physical_cache_hash_heads[bucket] = index + 1;
}

pub(crate) unsafe fn physical_cache_hash_unlink_locked(state: *mut PackState, index: u32) {
    let i = index as usize;
    let bucket = ((*state).physical_cache_entries[i].key_hash
        & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS as u64 - 1)) as usize;
    let next = (*state).physical_cache_entries[i].hash_next_plus_one;
    // `prev` is None while the link is the bucket head.
    let mut prev: Option<usize> = None;
    let mut link = (*state).physical_cache_hash_heads[bucket];
    while link != 0 {
        let current = link - 1;
        if current == index {
            match prev {
                None => (*state).physical_cache_hash_heads[bucket] = next,
                Some(p) => (*state).physical_cache_entries[p].hash_next_plus_one = next,
            }
            break;
        }
        if current as usize >= AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP {
            break;
        }
        prev = Some(current as usize);
        link = (*state).physical_cache_entries[current as usize].hash_next_plus_one;
    }
    (*state).physical_cache_entries[i].hash_next_plus_one = 0;
}

pub(crate) unsafe fn physical_cache_mark_pages(
    state: *mut PackState,
    start: u32,
    count: u32,
    used: bool,
) {
    let words = bitmap_words(&(*state).physical_cache_page_bitmap);
    unsafe {
        ampr_rust_cache_mark_pages(
            (*state).physical_cache_page_bitmap.as_mut_ptr(),
            words,
            start,
            count,
            used,
        )
    };
}

pub(crate) unsafe fn physical_cache_find_page_run_locked(state: *mut PackState, count: u32) -> u32 {
    let words = bitmap_words(&(*state).physical_cache_page_bitmap);
    unsafe {
        ampr_rust_cache_find_page_run(
            (*state).physical_cache_page_bitmap.as_ptr(),
            words,
            (*state).physical_cache_page_count,
            (*state).physical_cache_page_cursor,
            count,
        )
    }
}

pub(crate) unsafe fn physical_cache_release_entry_locked(state: *mut PackState, index: u32) {
    physical_cache_hash_unlink_locked(state, index);
    let (start, count) = {
        let e = &(*state).physical_cache_entries[index as usize];
        (e.page_start, e.page_count)
    };
    if count != 0 {
        physical_cache_mark_pages(state, start, count, false);
    }
    let entry = &mut (*state).physical_cache_entries[index as usize];
    *entry = PhysicalCacheEntry::EMPTY;
    entry.state = PhysicalCacheEntryState::Free;
    entry.free_next = (*state).physical_cache_free_head;
    (*state).physical_cache_free_head = index;
}

pub(crate) unsafe fn physical_cache_evict_one_locked(state: *mut PackState) -> bool {
    for _ in 0..AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP as u32 * 2 {
        let index = (*state).physical_cache_clock % AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP as u32;
        (*state).physical_cache_clock = (*state).physical_cache_clock.wrapping_add(1);
        let entry = &mut (*state).physical_cache_entries[index as usize];
        if entry.state == PhysicalCacheEntryState::Free
            || entry.pin_count != 0
            || entry.state == PhysicalCacheEntryState::Loading
        {
            continue;
        }
        if entry.referenced {
            entry.referenced = false;
            continue;
        }
        physical_cache_release_entry_locked(state, index);
        return true;
    }
    false
}

pub(crate) unsafe fn physical_cache_request_valid(
    state: *const PackState,
    offset: u64,
    size: u32,
) -> bool {
    !(*state).physical_cache_base.is_null()
        && (*state).physical_cache_page_count != 0
        && size != 0
        && size <= 1u32 << AMPR_PACK_IO_PAGE_SHIFT_MAX
        && offset & (size as u64 - 1) == 0
}
