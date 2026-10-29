//! C ABI for pure cache bookkeeping (`src/ampr_emu_pack.cpp` decoded and
//! physical caches). C++ owns the bitmaps and holds the cache lock.

use ampr_format::cache;

pub fn ampr_rust_cache_chunk_key_hash(
    offset: u64,
    pack_id: u16,
    stored_size: u32,
    raw_size: u32,
) -> u64 {
    cache::chunk_key_hash(offset, pack_id, stored_size, raw_size)
}

pub fn ampr_rust_physical_cache_key_hash(pack_id: u16, offset: u64, size: u32) -> u64 {
    cache::physical_key_hash(pack_id, offset, size)
}

pub fn ampr_rust_cache_wait_bucket(key_hash: u64) -> u32 {
    cache::wait_bucket(key_hash)
}

fn words_ok(bitmap: *const u64, words: usize) -> bool {
    !bitmap.is_null()
        && (bitmap as usize) % 8 == 0
        && words <= isize::MAX as usize / 8
        && (bitmap as usize).checked_add(words * 8).is_some()
}

/// Returns `u32::MAX` when no run fits or the bitmap is invalid.
///
/// # Safety
/// `bitmap` points to `words` initialized u64 values not written concurrently.
pub unsafe fn ampr_rust_cache_find_page_run(
    bitmap: *const u64,
    words: usize,
    page_count: u32,
    cursor: u32,
    count: u32,
) -> u32 {
    if !words_ok(bitmap, words) {
        return cache::INVALID;
    }
    let bitmap = unsafe { core::slice::from_raw_parts(bitmap, words) };
    cache::find_run_next_fit(bitmap, page_count, cursor, count)
}

/// # Safety
/// `bitmap` points to `words` writable u64 values with no other live access.
pub unsafe fn ampr_rust_cache_mark_pages(
    bitmap: *mut u64,
    words: usize,
    start: u32,
    count: u32,
    used: bool,
) {
    if !words_ok(bitmap, words) {
        return;
    }
    let bitmap = unsafe { core::slice::from_raw_parts_mut(bitmap, words) };
    cache::mark_pages(bitmap, start, count, used);
}
