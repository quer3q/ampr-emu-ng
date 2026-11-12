//! Run coalescing of adjacent byte ranges: one disk read that covers a
//! chunk and the chunks right after it.

/// End of one disk read that covers a chunk at `begin` of `stored` bytes and
/// the chunks after it, each given as (offset, stored). A later chunk joins
/// while it starts at or after the current end, the gap is at most
/// `gap_max`, and the whole read stays within `cap`. Returns the end and how
/// many chunks joined, or None when the first chunk alone is empty or does
/// not fit. The caller ends the iterator to stop early (e.g. on a chunk
/// already cached).
pub fn exact_run_end(
    begin: u64,
    stored: u64,
    cap: u64,
    gap_max: u64,
    next: impl Iterator<Item = (u64, u64)>,
) -> Option<(u64, u32)> {
    let mut end = begin.checked_add(stored)?;
    if stored == 0 || end - begin > cap {
        return None;
    }
    let mut extra = 0u32;
    for (offset, size) in next {
        if offset < end || offset - end > gap_max || size == 0 {
            break;
        }
        match offset.checked_add(size) {
            Some(new_end) if new_end - begin <= cap => end = new_end,
            _ => break,
        }
        extra += 1;
    }
    Some((end, extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(begin: u64, stored: u64, next: &[(u64, u64)]) -> Option<(u64, u32)> {
        exact_run_end(begin, stored, 1000, 16, next.iter().copied())
    }

    #[test]
    fn exact_run_first_chunk() {
        assert_eq!(run(100, 50, &[]), Some((150, 0)));
        assert_eq!(run(100, 0, &[]), None);
        assert_eq!(run(100, 1000, &[]), Some((1100, 0)));
        assert_eq!(run(100, 1001, &[]), None);
        assert_eq!(run(u64::MAX - 1, 2, &[]), None);
    }

    #[test]
    fn exact_run_extends_over_near_chunks() {
        // Back to back, then a 16-byte gap.
        assert_eq!(run(0, 100, &[(100, 100), (216, 50)]), Some((266, 2)));
        // Stops at the first chunk that fails, even if a later one fits.
        assert_eq!(run(0, 100, &[(117, 10), (100, 10)]), Some((100, 0)));
        assert_eq!(run(0, 100, &[(99, 10)]), Some((100, 0)));
        assert_eq!(run(0, 100, &[(100, 0), (100, 10)]), Some((100, 0)));
        // The cap bounds the whole read, gap included.
        assert_eq!(run(0, 100, &[(100, 900), (1000, 1)]), Some((1000, 1)));
        assert_eq!(run(0, 100, &[(110, 891)]), Some((100, 0)));
    }

    #[test]
    fn exact_run_overflow_and_lazy_stop() {
        let big = exact_run_end(0, 10, u64::MAX, u64::MAX, [(u64::MAX - 1, 5)].into_iter());
        assert_eq!(big, Some((10, 0)));
        // The caller ends the run by ending the iterator; later items are
        // never pulled.
        let mut pulled = 0;
        let items = [(10u64, 10u64), (20, 10), (30, 10)];
        let it = items
            .iter()
            .copied()
            .take_while(|&(o, _)| o < 30)
            .inspect(|_| pulled += 1);
        assert_eq!(exact_run_end(0, 10, 1000, 0, it), Some((30, 2)));
        assert_eq!(pulled, 2);
    }
}
