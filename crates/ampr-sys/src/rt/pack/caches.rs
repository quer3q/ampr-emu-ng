//! Decoded-cache admission, acquire/publish/release, page runs and
//! eviction.

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
    if (*state).cache_entries[index as usize].protected {
        cache_unprotect_locked(state, index);
    }
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

// ---- protected segment ----
//
// One reference bit cannot tell a chunk hit 500 times from one hit twice: a
// level load that admits more than the cache holds turns the hand twice and
// evicts everything, menus and UI included. An entry hit
// `tune::cache_protect_hits` times while cached turns protected, and the
// hand skips protected entries while they hold at most
// `tune::cache_protect_pct` of the cache. Same memory, same CACHE_MUTEX.

/// Bytes an entry holds: its whole pages.
fn cache_entry_bytes(entry: &CacheEntry) -> usize {
    entry.page_count as usize * PACK_CACHE_PAGE_BYTES
}

/// Most bytes protected entries keep before the hand demotes them. None
/// with `cache_protect_hits` 0, so entries protected before a live change
/// to 0 are demoted as the hand meets them and the cache turns plain clock.
unsafe fn cache_protected_share(state: *mut PackState) -> usize {
    if super::super::tune::cache_protect_hits() == 0 {
        return 0;
    }
    (*state).cache_page_count as usize * PACK_CACHE_PAGE_BYTES
        * super::super::tune::cache_protect_pct() as usize
        / 100
}

/// Counts a hit on a Ready entry; the `cache_protect_hits`-th one makes it
/// protected (0 protects nothing).
pub(crate) unsafe fn cache_note_hit_locked(state: *mut PackState, index: u32) {
    let limit = super::super::tune::cache_protect_hits();
    let entry = &mut (*state).cache_entries[index as usize];
    entry.referenced = true;
    entry.hits = entry.hits.saturating_add(1);
    if limit == 0 || entry.protected || (entry.hits as u32) < limit {
        return;
    }
    entry.protected = true;
    let bytes = cache_entry_bytes(entry);
    (*state).cache_protected_bytes += bytes;
    stats::add(stats::Stat::CachePromotions, 1);
    stats::add(stats::Stat::CacheProtectedBytes, bytes as u64);
}

/// Takes `index` out of the protected segment (demotion or release).
unsafe fn cache_unprotect_locked(state: *mut PackState, index: u32) {
    let entry = &mut (*state).cache_entries[index as usize];
    entry.protected = false;
    entry.hits = 0;
    let bytes = cache_entry_bytes(entry);
    (*state).cache_protected_bytes = (*state).cache_protected_bytes.saturating_sub(bytes);
    stats::sub(stats::Stat::CacheProtectedBytes, bytes as u64);
}

/// The hand walks only the indices below the high-water mark (at most the
/// live entry count, about 540 for 256 KiB zstd chunks in the 135 MiB cache)
/// instead of all 8192 slots, and wraps at it, so it visits the live entries
/// in the same order as a full-range hand would.
///
/// Protected entries are skipped while the protected bytes are within
/// their share; above it the hand treats them as a clock does, but the
/// first unreferenced one it meets is demoted to probation with its bit
/// set, so it gets one more sweep. Three turns cover a demoted entry's bit
/// clear and eviction. A turn that meets only protected entries within
/// their share evicts the first one it skipped, so a load never fails for
/// lack of room while an entry could go.
pub(crate) unsafe fn cache_evict_one_locked(state: *mut PackState) -> bool {
    let limit = (*state)
        .cache_entry_high_water
        .min(AMPR_EMU_PACK_CACHE_ENTRY_CAP as u32);
    let share = cache_protected_share(state);
    let mut fallback = INVALID_INDEX;
    let mut since_probation = 0u32;
    for _ in 0..limit * 3 {
        let index = if (*state).cache_clock < limit {
            (*state).cache_clock
        } else {
            0
        };
        (*state).cache_clock = index + 1;
        let entry = &mut (*state).cache_entries[index as usize];
        if entry.state == CacheEntryState::Free
            || entry.pin_count != 0
            || entry.state == CacheEntryState::Loading
        {
            continue;
        }
        if entry.protected && (*state).cache_protected_bytes <= share {
            if fallback == INVALID_INDEX {
                fallback = index;
            }
            since_probation += 1;
            if since_probation >= limit {
                break;
            }
            continue;
        }
        since_probation = 0;
        if entry.referenced {
            entry.referenced = false;
            continue;
        }
        if entry.protected {
            cache_unprotect_locked(state, index);
            (*state).cache_entries[index as usize].referenced = true;
            stats::add(stats::Stat::CacheDemotions, 1);
            continue;
        }
        cache_release_entry_locked(state, index);
        return true;
    }
    if fallback != INVALID_INDEX {
        cache_release_entry_locked(state, fallback);
        return true;
    }
    false
}

/// A Failed entry gives its error only to a reader that waited on its load
/// (`waiter`); that error is returned. Any other reader drops the entry and
/// gets 0, so one disk error does not fail every later read of the chunk
/// until eviction: an unpinned entry is freed, a pinned one leaves the hash
/// and turns transient, so its last release frees it.
pub(crate) unsafe fn cache_take_failed_locked(
    state: *mut PackState,
    index: u32,
    waiter: bool,
) -> c_int {
    let entry = &mut (*state).cache_entries[index as usize];
    if waiter {
        return if entry.error != 0 {
            entry.error
        } else {
            SCE_KERNEL_ERROR_EIO
        };
    }
    if entry.pin_count == 0 {
        cache_release_entry_locked(state, index);
    } else {
        entry.error = SCE_KERNEL_ERROR_EAGAIN;
        cache_hash_unlink_locked(state, index);
    }
    0
}

/// A read of part of a chunk is admitted on its first touch: small
/// sequential reads over one chunk would otherwise read the disk and decode
/// it once per read until the second touch. A full-chunk read (`full_chunk`)
/// decodes straight into the game buffer, so it is admitted on its second
/// touch, as before.
pub(crate) unsafe fn cache_should_admit_locked(
    state: *mut PackState,
    chunk: &AmprPackChunkView,
    file_flags: u32,
    key_hash: u64,
    full_chunk: bool,
) -> bool {
    if file_flags & AMPR_PACK_FILE_STREAMING != 0 || chunk.flags & AMPR_PACK_CHUNK_STREAMING != 0 {
        return false;
    }
    if file_flags & AMPR_PACK_FILE_HOT != 0
        || chunk.flags & AMPR_PACK_CHUNK_SHARED != 0
        || !full_chunk
    {
        return true;
    }
    let touch = &mut (*state).touches
        [ampr_format::cache::bucket_index(key_hash, AMPR_EMU_PACK_TOUCH_TABLE_SIZE)];
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
/// blocking. `waiter`: the caller got Pending for this chunk last time and
/// was woken by a publication, so a Failed entry is its loader's answer (see
/// cache_take_failed_locked). `full_chunk`: the read copies the whole chunk
/// (see cache_should_admit_locked).
pub(crate) unsafe fn cache_acquire(
    chunk: &AmprPackChunkView,
    file_flags: u32,
    full_chunk: bool,
    wait_for_loader: bool,
    mut waiter: bool,
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
                    CACHE_CVS[cache_wait_bucket(key_hash) as usize].wait(&mut lock);
                    waiter = true;
                    continue;
                }
                CacheEntryState::Ready => {
                    entry.pin_count += 1;
                    let page_start = entry.page_start;
                    cache_note_hit_locked(state, found);
                    result.kind = CacheAcquireKind::Ready;
                    result.lease.entry = found;
                    result.lease.data = unsafe {
                        (*state)
                            .cache_base
                            .add(page_start as usize * PACK_CACHE_PAGE_BYTES)
                    };
                    return result;
                }
                CacheEntryState::Failed => {
                    let error = cache_take_failed_locked(state, found, waiter);
                    if error != 0 {
                        result.kind = CacheAcquireKind::Failed;
                        result.lease.error = error;
                        return result;
                    }
                }
                CacheEntryState::Free => {}
            }
        }

        if !cache_should_admit_locked(state, chunk, file_flags, key_hash, full_chunk) {
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
        if index >= (*state).cache_entry_high_water {
            (*state).cache_entry_high_water = index + 1;
        }
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

/// True when the decoded cache holds `chunk` (Ready or Loading), without
/// taking a lease. An exact read (virtual_read.rs) ends its run of adjacent
/// chunks there instead of reading bytes the cache already has.
pub(crate) unsafe fn cache_holds_chunk(chunk: &AmprPackChunkView) -> bool {
    unsafe {
        let state = pack_state();
        if (*state).cache_base.is_null() || (*state).cache_page_count == 0 {
            return false;
        }
        let key_hash = chunk_key_hash(chunk);
        let _lock = CACHE_MUTEX.lock();
        let found = cache_find_locked(state, chunk, key_hash);
        found != INVALID_INDEX
            && matches!(
                (*state).cache_entries[found as usize].state,
                CacheEntryState::Ready | CacheEntryState::Loading
            )
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
        wait_bucket = cache_wait_bucket(entry.key_hash) as usize;
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

// ampr_format::cache::WAIT_BUCKETS sizes the epoch and condvar arrays.
const _: () = assert!(PACK_CACHE_WAIT_BUCKET_COUNT == 64);
pub(crate) fn cache_wait_bucket(key_hash: u64) -> u32 {
    ampr_rust_cache_wait_bucket(key_hash)
}

/// The publication epoch of a cache wait bucket (a static, so no state).
pub(crate) fn cache_wait_epoch(bucket: u32) -> u64 {
    DECODED_CACHE_PUBLICATION_EPOCH
        .get(bucket as usize)
        .map_or(0, |e| e.load(Ordering::Acquire))
}

/// Reads the epoch statics directly: `pipeline` usually lives inside
/// PackState, so no second access path to it is needed here.
pub(crate) unsafe fn prepare_cache_wait(pipeline: &mut ReadPipelineContext, key_hash: u64) {
    pipeline.cache_wait_bucket = cache_wait_bucket(key_hash) as u16;
    pipeline.cache_wait_epoch = cache_wait_epoch(pipeline.cache_wait_bucket as u32);
}

#[cfg(test)]
mod decoded_cache_tests {
    use super::*;
    use std::alloc::{alloc_zeroed, Layout};

    /// A zeroed PackState (leaked) with `live` Ready decoded entries at
    /// indices 0.., one page each. The `_locked` paths run without
    /// CACHE_MUTEX: the host has no scePthreadMutex*.
    fn cache_state(live: u32) -> *mut PackState {
        unsafe {
            let state = alloc_zeroed(Layout::new::<PackState>()) as *mut PackState;
            assert!(!state.is_null());
            (*state).cache_page_count = 64;
            (*state).cache_free_head = INVALID_INDEX;
            for i in 0..live {
                let entry = &mut (*state).cache_entries[i as usize];
                *entry = CacheEntry::EMPTY;
                entry.key_hash = 0x1000 + i as u64;
                entry.page_start = i;
                entry.page_count = 1;
                entry.state = CacheEntryState::Ready;
                cache_mark_pages(state, i, 1, true);
                cache_hash_link_locked(state, i);
            }
            (*state).cache_entry_high_water = live;
            state
        }
    }

    /// Whether `index` is on the hash chain of `key_hash`.
    fn linked(state: *mut PackState, key_hash: u64, index: u32) -> bool {
        let bucket = ampr_format::cache::bucket_index(key_hash, AMPR_EMU_PACK_CACHE_HASH_BUCKETS);
        let mut link = unsafe { (*state).cache_hash_heads[bucket] };
        while link != 0 {
            if link - 1 == index {
                return true;
            }
            link = unsafe { (*state).cache_entries[(link - 1) as usize].hash_next_plus_one };
        }
        false
    }

    #[test]
    fn clock_wraps_at_high_water_in_full_range_order() {
        let state = cache_state(4);
        unsafe {
            (*state).cache_entries[1].referenced = true;
            let mut order = Vec::new();
            for _ in 0..4 {
                let before: Vec<_> =
                    (0..4).map(|i| (*state).cache_entries[i].state).collect();
                assert!(cache_evict_one_locked(state));
                let freed = (0..4)
                    .find(|&i| {
                        before[i] != CacheEntryState::Free
                            && (*state).cache_entries[i].state == CacheEntryState::Free
                    })
                    .unwrap();
                order.push(freed);
                // The hand never leaves the live range.
                assert!((*state).cache_clock <= 4);
            }
            // Entry 1 loses its reference bit on the first pass and goes last,
            // as with a hand over all 8192 slots.
            assert_eq!(order, [0, 2, 3, 1]);
            assert!(!cache_evict_one_locked(state));
        }
    }

    /// The release hit count (the debug knob defaults to it; no test
    /// changes the cache knobs).
    const CACHE_PROTECT_HITS_TEST: u32 = super::super::super::tune::CACHE_PROTECT_HITS_DEFAULT;

    /// A partial-chunk read is admitted on its first touch; a full-chunk
    /// read on its second; a streaming chunk never.
    #[test]
    fn partial_reads_admit_on_first_touch() {
        let state = cache_state(0);
        let chunk = AmprPackChunkView::default();
        unsafe {
            assert!(cache_should_admit_locked(state, &chunk, 0, 0x77, false));
            assert!(!cache_should_admit_locked(state, &chunk, 0, 0x78, true));
            assert!(cache_should_admit_locked(state, &chunk, 0, 0x78, true));
            let streaming = AmprPackChunkView {
                flags: AMPR_PACK_CHUNK_STREAMING as u8,
                ..chunk
            };
            assert!(!cache_should_admit_locked(state, &streaming, 0, 0x79, false));
        }
    }

    /// Admits a Ready one-page entry for `key_hash` as cache_acquire's
    /// miss path does: evict until a page and an entry are free.
    fn insert_ready(state: *mut PackState, key_hash: u64) -> u32 {
        unsafe {
            let mut page = cache_find_page_run_locked(state, 1);
            while (page == INVALID_INDEX || (*state).cache_free_head == INVALID_INDEX)
                && cache_evict_one_locked(state)
            {
                page = cache_find_page_run_locked(state, 1);
            }
            assert!(page != INVALID_INDEX && (*state).cache_free_head != INVALID_INDEX);
            let index = (*state).cache_free_head;
            let entry = &mut (*state).cache_entries[index as usize];
            (*state).cache_free_head = entry.free_next;
            *entry = CacheEntry::EMPTY;
            entry.key_hash = key_hash;
            entry.page_start = page;
            entry.page_count = 1;
            entry.state = CacheEntryState::Ready;
            entry.referenced = true;
            cache_mark_pages(state, page, 1, true);
            cache_hash_link_locked(state, index);
            index
        }
    }

    /// A level load that streams 16 cache sizes of new chunks through the
    /// cache while the game re-reads 8 hot chunks now and then: the hot
    /// chunks turn protected and stay cached; with the plain clock the
    /// stream evicts them between re-reads.
    #[test]
    fn hot_set_survives_a_scan_past_the_cache_size() {
        let state = cache_state(64);
        let hot: Vec<(u64, u32)> = (0..8u32).map(|i| (0x1000 + i as u64, i)).collect();
        unsafe {
            for &(_, index) in &hot {
                for _ in 0..CACHE_PROTECT_HITS_TEST {
                    cache_note_hit_locked(state, index);
                }
                assert!((*state).cache_entries[index as usize].protected);
            }
            assert_eq!((*state).cache_protected_bytes, 8 * PACK_CACHE_PAGE_BYTES);
            for n in 0..64 * 16u64 {
                insert_ready(state, 0x10_0000 + n);
                if n % 128 == 0 {
                    for &(key, index) in &hot {
                        assert!(linked(state, key, index), "hot chunk {key:#x} evicted");
                        cache_note_hit_locked(state, index);
                    }
                }
            }
            for &(key, index) in &hot {
                assert!(linked(state, key, index), "hot chunk {key:#x} evicted");
            }
            // The cold first fill is gone.
            assert!(!linked(state, 0x1000 + 63, 63));
        }
    }

    /// Above the share the hand demotes protected entries to probation (bit
    /// set, hits cleared) and then evicts them like any other entry.
    #[test]
    fn protected_entries_above_the_share_are_demoted() {
        let state = cache_state(64);
        unsafe {
            for index in 0..40 {
                for _ in 0..CACHE_PROTECT_HITS_TEST {
                    cache_note_hit_locked(state, index);
                }
            }
            // 40 of 64 pages protected, above the 50% share.
            assert_eq!((*state).cache_protected_bytes, 40 * PACK_CACHE_PAGE_BYTES);
            for _ in 0..64 {
                assert!(cache_evict_one_locked(state));
            }
            assert_eq!((*state).cache_protected_bytes, 0);
            assert!(!cache_evict_one_locked(state));
        }
    }

    /// A sweep that meets only protected entries within their share still
    /// evicts one, so a load never fails for lack of room.
    #[test]
    fn only_protected_entries_still_evict_one() {
        let state = cache_state(16);
        unsafe {
            (*state).cache_page_count = 64;
            for index in 0..16 {
                for _ in 0..CACHE_PROTECT_HITS_TEST {
                    cache_note_hit_locked(state, index);
                }
            }
            assert!(cache_evict_one_locked(state));
            assert_eq!((*state).cache_protected_bytes, 15 * PACK_CACHE_PAGE_BYTES);
        }
    }

    #[test]
    fn failed_entry_errors_only_its_waiters() {
        let state = cache_state(2);
        unsafe {
            let entry = &mut (*state).cache_entries[0];
            entry.state = CacheEntryState::Failed;
            entry.error = SCE_KERNEL_ERROR_EIO;
            // A reader that parked on the load gets the loader's error and
            // the entry stays for the other waiters.
            assert_eq!(cache_take_failed_locked(state, 0, true), SCE_KERNEL_ERROR_EIO);
            assert!((*state).cache_entries[0].state == CacheEntryState::Failed);
            assert!(linked(state, 0x1000, 0));
            // A later reader drops it, so it loads the chunk again.
            assert_eq!(cache_take_failed_locked(state, 0, false), 0);
            assert!((*state).cache_entries[0].state == CacheEntryState::Free);
            assert_eq!((*state).cache_free_head, 0);
            assert!(!linked(state, 0x1000, 0));
        }
    }

    #[test]
    fn pinned_failed_entry_leaves_hash_and_turns_transient() {
        let state = cache_state(1);
        unsafe {
            let entry = &mut (*state).cache_entries[0];
            entry.state = CacheEntryState::Failed;
            entry.error = SCE_KERNEL_ERROR_EIO;
            entry.pin_count = 1;
            assert_eq!(cache_take_failed_locked(state, 0, false), 0);
            let entry = &(*state).cache_entries[0];
            // The holder keeps its pages; cache_release frees it at pin 0.
            assert!(entry.state == CacheEntryState::Failed);
            assert!(cache_error_is_transient(entry.error));
            assert!(!linked(state, 0x1000, 0));
        }
    }
}
