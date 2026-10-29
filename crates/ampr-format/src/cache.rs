//! Pure decoded/physical pack cache bookkeeping:
//! key hashes, wait buckets and the page-bitmap allocator. Bit `p` of the
//! bitmap is `bitmap[p / 64] >> (p % 64) & 1`; a set bit is a used page.
//! Pages beyond the bitmap count as used and are never marked.

/// Invalid index sentinel.
pub const INVALID: u32 = u32::MAX;
/// Number of cache wait buckets (power of two).
pub const WAIT_BUCKETS: u32 = 64;

/// splitmix64 finalizer.
pub fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Decoded-cache key hash of a chunk; low bit forced on.
pub fn chunk_key_hash(offset: u64, pack_id: u16, stored_size: u32, raw_size: u32) -> u64 {
    let value = offset
        ^ (u64::from(pack_id) << 48)
        ^ (u64::from(stored_size) << 16)
        ^ (u64::from(raw_size) << 32);
    mix64(value) | 1
}

/// Physical-cache key hash of a pack byte range; low bit forced on.
pub fn physical_key_hash(pack_id: u16, offset: u64, size: u32) -> u64 {
    mix64(offset ^ (u64::from(pack_id) << 48) ^ (u64::from(size) << 17)) | 1
}

/// Wait bucket of a key hash.
pub fn wait_bucket(key_hash: u64) -> u32 {
    (key_hash & u64::from(WAIT_BUCKETS - 1)) as u32
}

/// First free run of `count` pages starting
/// in `[begin, end)`, or `INVALID`. Pages beyond the bitmap count as used.
/// Consumes whole free/used stretches of a word at once.
pub fn find_run_range(bitmap: &[u64], begin: u32, end: u32, count: u32) -> u32 {
    if count == 0 {
        return INVALID;
    }
    let mut run_start = begin;
    let mut run_length = 0u32;
    let mut page = begin;
    while page < end {
        // Pages past the bitmap are used, so no later run can complete.
        let Some(&word) = bitmap.get((page / 64) as usize) else {
            return INVALID;
        };
        let bit = page & 63;
        let span = (64 - bit).min(end - page);
        let mask = if span == 64 { !0 } else { (1u64 << span) - 1 };
        let used = (word >> bit) & mask;
        let free = used.trailing_zeros().min(span);
        if free > 0 {
            if run_length == 0 {
                run_start = page;
            }
            if free >= count - run_length {
                return run_start;
            }
            run_length += free;
            page += free;
        } else {
            run_length = 0;
            page += (!used & mask).trailing_zeros().min(span);
        }
    }
    INVALID
}

/// Next-fit search: scan `[cursor, page_count)`, then wrap
/// to `[0, min(cursor + count - 1, page_count))` so a run spanning the cursor
/// stays eligible.
pub fn find_run_next_fit(bitmap: &[u64], page_count: u32, cursor: u32, count: u32) -> u32 {
    if count == 0 || count > page_count {
        return INVALID;
    }
    let cursor = if cursor >= page_count { 0 } else { cursor };
    let found = find_run_range(bitmap, cursor, page_count, count);
    if found != INVALID || cursor == 0 {
        return found;
    }
    let wrap_end = u64::from(cursor) + u64::from(count) - 1;
    let wrap_end = if wrap_end < u64::from(page_count) {
        wrap_end as u32
    } else {
        page_count
    };
    find_run_range(bitmap, 0, wrap_end, count)
}

/// Sets or clears `[start, start + count)`. A range whose u32 end wraps
/// is empty; pages beyond the bitmap are skipped. Whole words at a time.
pub fn mark_pages(bitmap: &mut [u64], start: u32, count: u32, used: bool) {
    let end = start.wrapping_add(count);
    if end <= start {
        return;
    }
    let limit = (bitmap.len() as u64).saturating_mul(64);
    let end = u64::from(end).min(limit);
    let mut page = u64::from(start);
    while page < end {
        let bit = page & 63;
        let span = (64 - bit).min(end - page);
        let mask = if span == 64 {
            !0
        } else {
            ((1u64 << span) - 1) << bit
        };
        let word = &mut bitmap[(page / 64) as usize];
        if used {
            *word |= mask;
        } else {
            *word &= !mask;
        }
        page += span;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_fit_scans_from_cursor_then_wraps_across_it() {
        let mut bitmap = [0u64; 2];
        mark_pages(&mut bitmap, 0, 128, true);
        mark_pages(&mut bitmap, 62, 4, false);
        assert_eq!(bitmap, [0x3fff_ffff_ffff_ffff, !0x3]);
        // Run 62..66 spans the cursor at 64: the suffix scan fails, the wrap
        // scan reaches up to cursor + count - 1 = 67 and finds it.
        assert_eq!(find_run_next_fit(&bitmap, 100, 64, 4), 62);
        assert_eq!(find_run_next_fit(&bitmap, 100, 64, 5), INVALID);
        assert_eq!(find_run_next_fit(&bitmap, 100, 63, 3), 63);
        assert_eq!(find_run_next_fit(&bitmap, 100, 500, 2), 62);
        assert_eq!(find_run_next_fit(&bitmap, 64, 0, 2), 62);
        assert_eq!(physical_key_hash(1, 2, 3) & 1, 1);
        assert_eq!(mix64(1), 0x5692_161d_100b_05e5);
    }

    /// Whether `page` is used; pages beyond the bitmap count as used.
    fn page_used(bitmap: &[u64], page: u32) -> bool {
        bitmap
            .get((page / 64) as usize)
            .map_or(true, |word| word & (1u64 << (page & 63)) != 0)
    }

    /// The former bit-by-bit scan.
    fn reference_range(bitmap: &[u64], begin: u32, end: u32, count: u32) -> u32 {
        let (mut run_start, mut run_length) = (begin, 0u32);
        for page in begin..end {
            if page_used(bitmap, page) {
                run_length = 0;
            } else {
                if run_length == 0 {
                    run_start = page;
                }
                run_length += 1;
                if run_length == count {
                    return run_start;
                }
            }
        }
        INVALID
    }

    #[test]
    fn word_skipping_scan_matches_bit_by_bit_reference() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut patterns = [[0u64; 4]; 16];
        patterns[1] = [!0u64; 4];
        patterns[2] = [0xaaaa_aaaa_aaaa_aaaa; 4];
        patterns[3] = [!0, 0, 0x8000_0000_0000_0001, !1];
        for p in &mut patterns[4..] {
            for w in p.iter_mut() {
                seed = mix64(seed);
                // Mix sparse, dense and full words.
                *w = match seed % 4 {
                    0 => 0,
                    1 => !0,
                    2 => seed & mix64(seed),
                    _ => seed | mix64(seed),
                };
            }
        }
        for bitmap in &patterns {
            for begin in [0u32, 1, 5, 63, 64, 65, 130] {
                for end in [0u32, 3, 64, 100, 128, 191, 256, 300] {
                    for count in [0u32, 1, 2, 3, 7, 63, 64, 65, 129, 256] {
                        assert_eq!(
                            find_run_range(bitmap, begin, end, count),
                            reference_range(bitmap, begin, end, count),
                            "{bitmap:x?} {begin} {end} {count}"
                        );
                    }
                }
            }
            for cursor in [0u32, 1, 64, 77, 200, 255] {
                for count in [1u32, 2, 5, 64, 100] {
                    let fit = find_run_next_fit(bitmap, 256, cursor, count);
                    let want = match reference_range(bitmap, cursor, 256, count) {
                        INVALID if cursor != 0 => {
                            reference_range(bitmap, 0, (cursor + count - 1).min(256), count)
                        }
                        found => found,
                    };
                    assert_eq!(fit, want, "{bitmap:x?} {cursor} {count}");
                }
            }
        }
    }
    /// The former bit-by-bit `mark_pages`.
    fn reference_mark(bitmap: &mut [u64], start: u32, count: u32, used: bool) {
        for page in start..start.wrapping_add(count) {
            let Some(word) = bitmap.get_mut((page / 64) as usize) else {
                return;
            };
            let mask = 1u64 << (page & 63);
            if used {
                *word |= mask;
            } else {
                *word &= !mask;
            }
        }
    }

    #[test]
    fn word_mask_mark_matches_bit_by_bit_reference() {
        let starts = [
            0u32, 1, 31, 62, 63, 64, 65, 127, 128, 129, 191, 200, 255, 256, 300,
        ];
        let counts = [
            0u32, 1, 2, 63, 64, 65, 66, 127, 128, 129, 192, 255, 256, 257, 1000,
        ];
        let wraps = [
            (u32::MAX, 1u32),
            (u32::MAX, 2),
            (u32::MAX - 63, 200),
            (1, u32::MAX),
            (0, u32::MAX),
            (5, u32::MAX - 5),
        ];
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..8 {
            let mut base = [0u64; 4];
            for w in base.iter_mut() {
                seed = mix64(seed);
                *w = seed;
            }
            for used in [false, true] {
                let pairs = starts
                    .iter()
                    .flat_map(|&s| counts.iter().map(move |&c| (s, c)))
                    .chain(wraps);
                for (start, count) in pairs {
                    let (mut got, mut want) = (base, base);
                    mark_pages(&mut got, start, count, used);
                    reference_mark(&mut want, start, count, used);
                    assert_eq!(got, want, "{base:x?} {start} {count} {used}");
                }
            }
        }
    }
}
