//! zstd: one game read that spans several 256 KiB chunks is split into
//! contiguous, chunk-aligned child jobs so idle pack workers decode its
//! chunks in parallel.
//!
//! The caller sees one request: a virtual AIO group id whose children are the
//! child jobs (aio.rs sceKernelAioSubmitReadCommandsMultiple). Each child writes
//! its own result into the group (`SplitGroup::results`); when the last child
//! completes (worker.rs complete_virtual_job, PACK_M held) the caller's result is
//! written once from `aggregate_split`.

use super::*;
use core::sync::atomic::AtomicI64;

/// Children of one split read: at most one per decode worker.
pub(crate) const SPLIT_MAX_CHILDREN: usize = AMPR_EMU_PACK_WORKER_CAPACITY;
/// A read splits only while this many virtual AIO slots stay free for the
/// rest of its batch and for other callers.
pub(crate) const SPLIT_MIN_FREE_SLOTS: usize = AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS / 4;
/// 256 KiB zstd chunks at fixed logical offsets (rt/pack/zstd.rs).
const SPLIT_CHUNK_SHIFT: u32 = ampr_format::zstd::CHUNK_SHIFT as u32;
const _: () = assert!(
    1u64 << SPLIT_CHUNK_SHIFT == ampr_format::zstd::CHUNK_SIZE
        && AMPR_EMU_PACK_WORKERS as usize <= SPLIT_MAX_CHILDREN
        && SPLIT_MAX_CHILDREN <= SCE_KERNEL_AIO_REQUEST_NUM_MAX
);

/// One child of a split read: `[delta, delta + nbyte)` of the parent request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SplitRange {
    pub delta: u64,
    pub nbyte: u64,
}
impl SplitRange {
    pub(crate) const EMPTY: Self = Self { delta: 0, nbyte: 0 };
}

/// Chunks of `1 << shift` bytes that `[offset, offset + length)` touches
/// (0 for an empty range).
pub(crate) fn split_chunk_span(offset: u64, length: u64, shift: u32) -> u64 {
    if length == 0 {
        return 0;
    }
    ((offset + length - 1) >> shift) - (offset >> shift) + 1
}

/// Splits the (EOF-clamped) read `[offset, offset + length)` into at most
/// `max_children` contiguous children whose inner boundaries fall on chunk
/// starts, chunks spread as evenly as possible (earlier children take the
/// remainder). Returns the child count; below 2 means "do not split".
pub(crate) fn plan_split(
    offset: u64,
    length: u64,
    shift: u32,
    max_children: usize,
    out: &mut [SplitRange; SPLIT_MAX_CHILDREN],
) -> usize {
    let chunks = split_chunk_span(offset, length, shift);
    let n = (chunks.min(max_children.min(SPLIT_MAX_CHILDREN) as u64)) as usize;
    if n < 2 || offset.checked_add(length).is_none() {
        return if n == 0 { 0 } else { 1 };
    }
    let first = offset >> shift;
    let (base, extra) = (chunks / n as u64, chunks % n as u64);
    let mut task = 0u64;
    let mut start = 0u64;
    for (k, range) in out.iter_mut().enumerate().take(n) {
        task += base + u64::from((k as u64) < extra);
        let end = if k + 1 == n {
            length
        } else {
            ((first + task) << shift) - offset
        };
        *range = SplitRange {
            delta: start,
            nbyte: end - start,
        };
        start = end;
    }
    n
}

/// (return_value, state) of a split read from its children's results in plan
/// order (`nbytes[k]` = bytes child k asked for): the total when every child
/// read all its bytes; else the bytes up to the first short child (its own
/// bytes included) or before the first failed child, or that child's error
/// when it is the first. ABORTED when any child aborted, else COMPLETED.
pub(crate) fn aggregate_split(results: &[SceKernelAioResult], nbytes: &[u64]) -> (i64, c_int) {
    let aborted = results.iter().any(|r| {
        (r.state as c_int & !SCE_KERNEL_AIO_STATE_NOTIFIED) == SCE_KERNEL_AIO_STATE_ABORTED
    });
    let state = if aborted {
        SCE_KERNEL_AIO_STATE_ABORTED
    } else {
        SCE_KERNEL_AIO_STATE_COMPLETED
    };
    let mut done = 0i64;
    for (k, (r, &want)) in results.iter().zip(nbytes).enumerate() {
        let rv = r.return_value;
        if rv < 0 {
            return (if k == 0 { rv } else { done }, state);
        }
        done += rv;
        if (rv as u64) < want {
            break;
        }
    }
    (done, state)
}

/// Split-read state of a virtual AIO group (`VirtualAioGroupSlot::split`);
/// `count == 0` for a plain group. All-zero is EMPTY (groups live in zeroed
/// PackState storage). PACK_M guards it; children write `results` through
/// their request's result pointer.
#[derive(Clone, Copy)]
pub(crate) struct SplitGroup {
    /// The caller's result, written once by the last child (may be null).
    pub result: *mut SceKernelAioResult,
    pub count: u16,
    /// Children not yet completed.
    pub pending: u16,
    pub nbytes: [u64; SPLIT_MAX_CHILDREN],
    pub results: [SceKernelAioResult; SPLIT_MAX_CHILDREN],
}
impl SplitGroup {
    pub(crate) const EMPTY: Self = Self {
        result: null_mut(),
        count: 0,
        pending: 0,
        nbytes: [0; SPLIT_MAX_CHILDREN],
        results: [SceKernelAioResult::EMPTY; SPLIT_MAX_CHILDREN],
    };
}

unsafe fn free_virtual_aio_count_locked(state: *const PackState) -> usize {
    (*state)
        .virtual_aio
        .iter()
        .filter(|slot| slot.phase == VirtualAioPhase::Free)
        .count()
}

/// Splits the just-prepared virtual job `first` (Reserved; request, file,
/// priority, origin and work class set) of a read of zstd file `file_ptr`
/// (`file_size` bytes) into chunk-aligned children, when it spans at least
/// two chunks and `reserve` slots stay free besides the children. Child 0 is
/// `first`; `children[..n]` gets every child's slot. Returns (group index, n),
/// or None with nothing changed. PACK_M held.
pub(crate) unsafe fn split_virtual_read_locked(
    state: *mut PackState,
    first: u32,
    file_ptr: *const u8,
    file_size: u64,
    reserve: usize,
    children: &mut [u32; SPLIT_MAX_CHILDREN],
) -> Option<(u32, usize)> {
    let req = (*state).virtual_aio[first as usize].request;
    if req.result.is_null() || req.buf.is_null() {
        return None;
    }
    let length = clamp_read(req.offset, req.nbyte, file_size).ok()?;
    let offset = req.offset as u64;
    let mut ranges = [SplitRange::EMPTY; SPLIT_MAX_CHILDREN];
    let n = plan_split(
        offset,
        length,
        SPLIT_CHUNK_SHIFT,
        // The worker count in use (debug builds: the `workers` knob).
        super::super::tune::workers() as usize,
        &mut ranges,
    );
    if n < 2 {
        return None;
    }
    // The core's task count must agree with the chunk plan.
    let tasks = unsafe { ampr_pack_core_task_count(file_ptr, offset, length) };
    if tasks as u64 != split_chunk_span(offset, length, SPLIT_CHUNK_SHIFT) {
        return None;
    }
    if free_virtual_aio_count_locked(state) < (n - 1) + reserve {
        return None;
    }
    let group_index = allocate_virtual_aio_group_locked(state);
    if group_index == INVALID_INDEX {
        return None;
    }
    children[0] = first;
    for k in 1..n {
        let index = allocate_virtual_aio_locked(state);
        if index == INVALID_INDEX {
            for &child in &children[1..k] {
                free_virtual_aio_locked(state, child);
            }
            free_virtual_aio_group_locked(state, group_index);
            return None;
        }
        children[k] = index;
    }

    let parent = &(*state).virtual_aio[first as usize];
    let (file_id, priority, work_class) = (parent.file_id, parent.priority, parent.work_class);
    let group = &mut (*state).virtual_aio_groups[group_index as usize];
    group.split = SplitGroup {
        result: req.result,
        count: n as u16,
        pending: n as u16,
        ..SplitGroup::EMPTY
    };
    group.child_count = n as u16;
    let results = group.split.results.as_mut_ptr();
    for k in 0..n {
        let range = ranges[k];
        group.split.nbytes[k] = range.nbyte;
        let child = &mut (*state).virtual_aio[children[k] as usize];
        child.request = SceKernelAioRWRequest {
            offset: req.offset + range.delta as off_t,
            nbyte: range.nbyte as usize,
            buf: (req.buf as *mut u8)
                .wrapping_add(range.delta as usize)
                .cast(),
            result: unsafe { results.add(k) },
            fd: req.fd,
        };
        child.file_id = file_id;
        child.priority = priority;
        child.work_class = work_class;
        child.cancel_requested.store(false, Ordering::Relaxed);
        child.split_group = group_index;
        group.children[k] = encode_virtual_aio(children[k], child.generation);
    }
    Some((group_index, n))
}

/// The id the caller gets for a job at a request position whose split group
/// is `group_index` (INVALID_INDEX: not split, keep `direct`). PACK_M held.
pub(crate) unsafe fn split_caller_id(
    state: *const PackState,
    group_index: u32,
    direct: SceKernelAioSubmitId,
) -> SceKernelAioSubmitId {
    if group_index == INVALID_INDEX {
        return direct;
    }
    encode_virtual_aio_group(
        group_index,
        (*state).virtual_aio_groups[group_index as usize].generation,
    )
}

/// Frees the split groups a failed submit made (their children are freed by
/// the caller). PACK_M held.
pub(crate) unsafe fn free_split_groups_locked(state: *mut PackState, groups: &[u32]) {
    for &group_index in groups {
        if group_index != INVALID_INDEX {
            free_virtual_aio_group_locked(state, group_index);
        }
    }
}

/// One child of split group `group_index` completed (its result is written):
/// the last one writes the caller's result. PACK_M held.
pub(crate) unsafe fn finish_split_child_locked(state: *mut PackState, group_index: u32) {
    let Some(group) = (*state).virtual_aio_groups.get_mut(group_index as usize) else {
        return;
    };
    let split = &mut group.split;
    if !group.active || split.count == 0 || split.pending == 0 {
        return;
    }
    split.pending -= 1;
    if split.pending != 0 || split.result.is_null() {
        return;
    }
    // Children write their results under PACK_M too (complete_virtual_job).
    let n = split.count as usize;
    let results = split.results;
    let (return_value, completion) = aggregate_split(&results[..n], &split.nbytes[..n]);
    let result = split.result;
    unsafe {
        AtomicI64::from_ptr(&raw mut (*result).return_value).store(return_value, Ordering::Relaxed);
        AtomicU32::from_ptr(&raw mut (*result).state).store(completion as u32, Ordering::Release);
    }
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SHIFT: u32 = SPLIT_CHUNK_SHIFT;
    const C: u64 = 1 << SHIFT;

    fn plan(offset: u64, length: u64, max: usize) -> alloc::vec::Vec<SplitRange> {
        let mut out = [SplitRange::EMPTY; SPLIT_MAX_CHILDREN];
        let n = plan_split(offset, length, SHIFT, max, &mut out);
        out[..n].to_vec()
    }

    /// Children cover `[0, length)` in order, every inner boundary is a chunk
    /// start, and no child is empty.
    fn check_cover(offset: u64, length: u64, ranges: &[SplitRange]) {
        let mut at = 0;
        for (k, r) in ranges.iter().enumerate() {
            assert_eq!(r.delta, at, "child {k} starts where the previous ended");
            assert!(r.nbyte != 0, "child {k} is empty");
            if k != 0 {
                assert_eq!((offset + r.delta) % C, 0, "child {k} starts on a chunk");
            }
            at += r.nbyte;
        }
        assert_eq!(at, length, "children cover the request exactly");
    }

    #[test]
    fn plan_covers_request_on_chunk_boundaries() {
        // ~250 KB read from the end of a chunk: 2 chunks -> 2 children.
        let (offset, length) = (C - 4096, 250_000);
        let r = plan(offset, length, 4);
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[0],
            SplitRange {
                delta: 0,
                nbyte: 4096
            }
        );
        check_cover(offset, length, &r);
        // Three chunks, unaligned both ends.
        let (offset, length) = (5 * C + 123, 2 * C + 1000);
        let r = plan(offset, length, 4);
        assert_eq!(r.len(), 3);
        check_cover(offset, length, &r);
        // Aligned 8-chunk read: 4 children of 2 chunks each.
        let r = plan(0, 8 * C, 4);
        assert_eq!(r.len(), 4);
        assert!(r.iter().all(|c| c.nbyte == 2 * C));
        check_cover(0, 8 * C, &r);
    }

    #[test]
    fn plan_caps_child_count_and_spreads_chunks() {
        // 5 chunks over 4 children: 2, 1, 1, 1 chunks.
        let r = plan(0, 5 * C, 4);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].nbyte, 2 * C);
        assert!(r[1..].iter().all(|c| c.nbyte == C));
        check_cover(0, 5 * C, &r);
        // Never more than SPLIT_MAX_CHILDREN, whatever the caller asks.
        let r = plan(7, 100 * C, usize::MAX);
        assert_eq!(r.len(), SPLIT_MAX_CHILDREN);
        check_cover(7, 100 * C, &r);
        // A cap of 1 never splits.
        assert_eq!(plan(0, 4 * C, 1).len(), 1);
    }

    #[test]
    fn plan_does_not_split_one_chunk_or_empty_reads() {
        assert_eq!(plan(0, C, 4).len(), 1);
        assert_eq!(plan(C + 10, C - 10, 4).len(), 1);
        assert_eq!(plan(3 * C, 1, 4).len(), 1);
        assert_eq!(plan(3 * C, 0, 4).len(), 0);
        assert_eq!(split_chunk_span(C - 1, 2, SHIFT), 2);
        assert_eq!(split_chunk_span(C, C, SHIFT), 1);
    }

    #[test]
    fn plan_of_eof_clamped_read() {
        // File of 2.5 chunks; a 4 MiB read from 1 KiB clamps to the file end.
        let size = 2 * C + C / 2;
        let length = clamp_read(1024, 4 << 20, size).unwrap();
        assert_eq!(length, size - 1024);
        let r = plan(1024, length, 4);
        assert_eq!(r.len(), 3);
        assert_eq!(
            r[2],
            SplitRange {
                delta: 2 * C - 1024,
                nbyte: C / 2
            }
        );
        check_cover(1024, length, &r);
        // Clamped into the last chunk: no split; at EOF: nothing to read.
        let length = clamp_read((2 * C + 1) as off_t, 1 << 20, size).unwrap();
        assert_eq!(plan(2 * C + 1, length, 4).len(), 1);
        assert_eq!(clamp_read(size as off_t, 10, size).unwrap(), 0);
    }

    fn res(return_value: i64, state: c_int) -> SceKernelAioResult {
        SceKernelAioResult {
            return_value,
            state: state as u32,
        }
    }

    const OK: c_int = SCE_KERNEL_AIO_STATE_COMPLETED;
    const AB: c_int = SCE_KERNEL_AIO_STATE_ABORTED;

    #[test]
    fn aggregate_totals_and_partial_reads() {
        let want = [100, 200, 300];
        assert_eq!(
            aggregate_split(&[res(100, OK), res(200, OK), res(300, OK)], &want),
            (600, OK)
        );
        // A later child failed: the bytes before it.
        let eio = SCE_KERNEL_ERROR_EIO as i64;
        assert_eq!(
            aggregate_split(&[res(100, OK), res(eio, OK), res(300, OK)], &want),
            (100, OK)
        );
        // The first child failed: its error.
        assert_eq!(
            aggregate_split(&[res(eio, OK), res(200, OK), res(300, OK)], &want),
            (eio, OK)
        );
        // A short child ends the read after its own bytes.
        assert_eq!(
            aggregate_split(&[res(100, OK), res(50, OK), res(300, OK)], &want),
            (150, OK)
        );
    }

    #[test]
    fn aggregate_reports_abort() {
        let want = [100, 200];
        let canceled = SCE_KERNEL_ERROR_ECANCELED as i64;
        assert_eq!(
            aggregate_split(&[res(canceled, AB), res(canceled, AB)], &want),
            (canceled, AB)
        );
        assert_eq!(
            aggregate_split(&[res(100, OK), res(canceled, AB)], &want),
            (100, AB)
        );
        // A NOTIFIED bit on a child state does not hide the abort.
        let notified = AB | SCE_KERNEL_AIO_STATE_NOTIFIED;
        assert_eq!(
            aggregate_split(&[res(100, OK), res(200, notified)], &want).1,
            AB
        );
    }
}
