//! The game's loose-file APR reads (real fds, not pack virtual fds) through
//! the pread pool (pread_pool.rs) instead of kernel AIO. Measured on the
//! console (a game, internal SSD, debug build, kernel AIO): 24,096
//! loose reads of ~508 KB took 2.5 ms each with 0.79 in flight on average
//! (apr_read_ns 61.0 s over 77.7 s uptime), 158 MB/s overall, 250 MB/s peak.
//! Kernel AIO on this FS serves 1-2 requests at a time; 32 parallel preads
//! reached 1.6-2.0 GB/s (mod.rs, 2026-10-25 bench).
//!
//! Only a read's first submit is routed, at the end-of-pass flush
//! (`route_loose_reads_to_pread`, called from flush.rs). The read is accounted
//! exactly as a kernel accept would (chain sequence, offsets), but owns no
//! kernel id, so no poll path sees it. A pool result that is not the full
//! length (EFAULT from a GPU-only buffer, any other error, a short read) puts
//! the same ActiveRead into the deferred state that kernel AIO's own EFAULT
//! retry uses (capacity.rs), so the read is resubmitted to kernel AIO and its
//! final bytes, error and short-read handling are kernel AIO's. Destinations
//! that faulted are remembered and later reads into them skip the pool.
//!
//! A read longer than `loose_pread_part_kib` (64 KiB release) is queued as
//! parallel part tasks into the same destination, all or none; their results
//! fold (`LoosePartResult`) into what one pread of the range returns, and
//! the read finishes when the last part is in. Unmeasured: the hypothesis
//! is that the FS serves a ~510 KB pread as sequential 64 KiB I/Os (2.50 ms
//! per read, pread_pending_max <= 6 on 16-32 threads, console 2026-10).

use super::*;
use crate::rt::stats::{self, Stat};

// ---- GPU-only destination regions ----

/// log2 of the region size: 2 MiB, the direct memory page size.
pub(crate) const LOOSE_GPU_REGION_SHIFT: u32 = 21;
/// ponytail: 32 regions, 64 MiB of GPU-only read targets. Past that the oldest
/// entry is replaced (FIFO), and a read into an evicted region pays one more
/// failed pread (a disk read thrown away) before it is remembered again.
pub(crate) const LOOSE_GPU_REGION_CAPACITY: usize = 32;
/// An entry expires 1 s after its last EFAULT (`time_counter_now`, ns): an
/// EFAULT can be transient (an AMM remap in flight), and a CPU-accessible
/// region must not stay on kernel AIO for the module lifetime. A region that
/// is GPU-only pays one failed pread per second, then is remembered again.
pub(crate) const LOOSE_GPU_REGION_TTL_NS: u64 = 1_000_000_000;

/// Destinations where a pool pread returned EFAULT, with the time of that
/// EFAULT. Reactor thread only; all-zero is the empty table (init_members
/// zeroes the reactor).
#[derive(Clone, Copy)]
pub(crate) struct LooseGpuRegions {
    regions: [usize; LOOSE_GPU_REGION_CAPACITY],
    stamps: [u64; LOOSE_GPU_REGION_CAPACITY],
    len: u32,
    next: u32,
}

impl LooseGpuRegions {
    #[cfg(test)]
    const fn new() -> Self {
        Self {
            regions: [0; LOOSE_GPU_REGION_CAPACITY],
            stamps: [0; LOOSE_GPU_REGION_CAPACITY],
            len: 0,
            next: 0,
        }
    }

    /// First and last region index of `[buf, buf + len)`; None for an empty,
    /// wrapping or more-than-capacity range (such a read is not routed).
    fn span(buf: usize, len: u64) -> Option<(usize, usize)> {
        let len = usize::try_from(len).ok()?;
        if len == 0 {
            return None;
        }
        let end = buf.checked_add(len - 1)?;
        let first = buf >> LOOSE_GPU_REGION_SHIFT;
        let last = end >> LOOSE_GPU_REGION_SHIFT;
        (last - first < LOOSE_GPU_REGION_CAPACITY).then_some((first, last))
    }

    fn find(&self, region: usize) -> Option<usize> {
        self.regions[..self.len as usize]
            .iter()
            .position(|&r| r == region)
    }

    fn contains(&self, region: usize, now: u64) -> bool {
        self.find(region)
            .is_some_and(|i| now.saturating_sub(self.stamps[i]) < LOOSE_GPU_REGION_TTL_NS)
    }

    /// True when the range touches a region that faulted in the last TTL.
    pub(crate) fn overlaps(&self, buf: usize, len: u64, now: u64) -> bool {
        match Self::span(buf, len) {
            Some((first, last)) => (first..=last).any(|r| self.contains(r, now)),
            None => false,
        }
    }

    /// Remembers every region of the range at `now`; the fault address is
    /// unknown. A region already in the table (expired or not) is refreshed.
    pub(crate) fn insert(&mut self, buf: usize, len: u64, now: u64) {
        let Some((first, last)) = Self::span(buf, len) else {
            return;
        };
        for region in first..=last {
            if let Some(i) = self.find(region) {
                self.stamps[i] = now;
                continue;
            }
            self.stamps[self.next as usize] = now;
            self.regions[self.next as usize] = region;
            self.next = (self.next + 1) % LOOSE_GPU_REGION_CAPACITY as u32;
            if (self.len as usize) < LOOSE_GPU_REGION_CAPACITY {
                self.len += 1;
            }
        }
    }
}

// ---- routing and fallback decisions ----

/// What a finished pool read means for the ActiveRead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LoosePreadOutcome {
    /// Full length read: complete it as a kernel COMPLETED result.
    Done,
    /// EFAULT: remember the destination, resubmit to kernel AIO.
    Efault,
    /// Any other error or a short read: resubmit to kernel AIO, which
    /// produces the final result (the read is repeated, rare).
    Retry,
}

pub(crate) const fn loose_pread_outcome(returnValue: i64, length: u64) -> LoosePreadOutcome {
    if returnValue >= 0 && returnValue as u64 == length {
        LoosePreadOutcome::Done
    } else if returnValue == SCE_KERNEL_ERROR_EFAULT as i64 {
        LoosePreadOutcome::Efault
    } else {
        LoosePreadOutcome::Retry
    }
}

// ---- split reads ----

/// Smallest part a split read uses; smaller knob values are raised to it.
pub(crate) const LOOSE_PREAD_PART_MIN_BYTES: u64 = 16 * 1024;
/// Part sizes are rounded down to this (the page size).
pub(crate) const LOOSE_PREAD_PART_ALIGN_BYTES: u64 = 4 * 1024;

/// Part size in bytes for a `loose_pread_part_kib` value: 0 means no split;
/// otherwise rounded down to a 4 KiB multiple, at least 16 KiB.
pub(crate) const fn loose_pread_part_bytes(kib: u32) -> u64 {
    if kib == 0 {
        return 0;
    }
    let bytes = kib as u64 * 1024 / LOOSE_PREAD_PART_ALIGN_BYTES * LOOSE_PREAD_PART_ALIGN_BYTES;
    if bytes < LOOSE_PREAD_PART_MIN_BYTES {
        LOOSE_PREAD_PART_MIN_BYTES
    } else {
        bytes
    }
}

/// Number of pool tasks for a read of `length` bytes with part size `part`
/// (0 = no split) when `room` loose tasks are free: ceil(length / part),
/// or 1 (unsplit) when that does not fit `room` or one pool group, or the
/// read is not longer than one part. Never a partial split.
pub(crate) fn loose_pread_part_count(length: u64, part: u64, room: u32) -> u32 {
    if part == 0 || length <= part {
        return 1;
    }
    let parts = length.div_ceil(part);
    if parts > room as u64 || parts > kAprExternalAioGroupMaxRequests as u64 {
        1
    } else {
        parts as u32
    }
}

/// Byte offset (relative to the read's start) and length of part `index`
/// of `parts` (from loose_pread_part_count) for a read of `length` bytes:
/// `index * part`, the last part takes the rest; one part is the whole read.
pub(crate) fn loose_pread_part_range(length: u64, part: u64, parts: u32, index: u32) -> (u64, u64) {
    if parts <= 1 {
        return (0, length);
    }
    let start = (index as u64 * part).min(length);
    (start, (length - start).min(part))
}

/// Results of a loose read's part tasks, folded as they finish (any order)
/// into the value one pread of the whole range returns, mirroring the
/// worker loop (pread_pool.rs): parts in offset order, full parts add up,
/// and the first part (lowest index) that is short or failed ends the read:
/// its bytes or its error is the result, later parts count nothing. EFAULT
/// in any part is kept apart, since it decides the GPU region table.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct LoosePartResult {
    /// The whole-read result so far (the full length until a part stops it).
    pub(crate) total: i64,
    /// Part tasks not finished yet.
    pub(crate) left: u8,
    /// Index of the part that stopped the read; `parts` when none did.
    pub(crate) stop: u8,
    pub(crate) efault: bool,
}

impl LoosePartResult {
    pub(crate) fn new(length: u64, parts: u32) -> Self {
        Self {
            total: length as i64,
            left: parts as u8,
            stop: parts as u8,
            efault: false,
        }
    }

    /// Part `index` at `start` (relative) of `len` bytes returned `value`.
    pub(crate) fn add(&mut self, index: u32, start: u64, len: u64, value: i64) {
        if self.left == 0 {
            abort();
        }
        self.left -= 1;
        if value == SCE_KERNEL_ERROR_EFAULT as i64 {
            self.efault = true;
        }
        let full = value >= 0 && value as u64 == len;
        if !full && index < self.stop as u32 {
            self.stop = index as u8;
            self.total = if value >= 0 {
                (start + (value as u64).min(len)) as i64
            } else {
                value
            };
        }
    }

    pub(crate) fn done(&self) -> bool {
        self.left == 0
    }

    pub(crate) fn outcome(&self, length: u64) -> LoosePreadOutcome {
        if self.efault {
            LoosePreadOutcome::Efault
        } else {
            loose_pread_outcome(self.total, length)
        }
    }
}

/// A finished part task, copied out of its PreadTask before it is retired.
#[derive(Clone, Copy)]
pub(crate) struct LoosePartDone {
    pub(crate) index: u32,
    /// File offset and length of the part.
    pub(crate) offset: off_t,
    pub(crate) len: u64,
    pub(crate) value: i64,
}

/// Why a staged read is or is not handed to the pool (`Pool` only when it is
/// a first submit to a real fd and the target is not a known GPU-only region).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LoosePreadRoute {
    Pool,
    /// A resubmit, a virtual (pack) fd or an unroutable range.
    Aio,
    /// The destination faulted before (counted as loose_pread_skipped).
    KnownGpu,
}

pub(crate) fn loose_pread_route(
    firstSubmit: bool,
    realFd: bool,
    regions: &LooseGpuRegions,
    buf: usize,
    len: u64,
    now: u64,
) -> LoosePreadRoute {
    if !firstSubmit || !realFd || LooseGpuRegions::span(buf, len).is_none() {
        LoosePreadRoute::Aio
    } else if regions.overlaps(buf, len, now) {
        LoosePreadRoute::KnownGpu
    } else {
        LoosePreadRoute::Pool
    }
}

// ---- reactor ----

impl AprAioReactor {
    /// Takes staged first submits of loose reads out of `batch` into the pread
    /// pool; the rest, and any the pool has no task or thread for, stay in
    /// order for the kernel multiple-submit. Reactor thread only, from
    /// flush_aio_submit_round before flush_aio_priority_submits.
    pub(crate) fn route_loose_reads_to_pread(&mut self, batch: &mut AioSubmitBatch) -> bool {
        if batch.count == 0 || !crate::rt::tune::loose_pread() {
            return false;
        }
        let mut kept = 0usize;
        let mut routed = false;
        for index in 0..batch.count {
            let item = batch.items[index];
            if !item.isExternal && self.try_queue_loose_pread(&item.active, batch.aioPriority) {
                routed = true;
                continue;
            }
            if kept != index {
                batch.requests[kept] = batch.requests[index];
                batch.ids[kept] = batch.ids[index];
                batch.items[kept] = item;
            }
            kept += 1;
        }
        batch.count = kept;
        routed
    }

    fn try_queue_loose_pread(&mut self, item: &ActiveReadRef, priority: c_int) -> bool {
        let ap = self
            .activeReads
            .active_at_slot_2(item.slot, item.generation);
        if ap.is_null() {
            abort();
        }
        let active = unsafe { &mut *ap };
        if !active.awaitingBatchSubmit || active.aioId >= 0 || active.preadQueued {
            abort();
        }
        if active.job.is_null()
            || active.chain.is_null()
            || active.aioPrio != priority
            || active.request.nbyte as u64 != active.desc.length
        {
            return false;
        }
        let route = loose_pread_route(
            !active.submitAccounted && !active.awaitingResubmit,
            active.nativeCapacityCharged && active.request.fd >= 0,
            &self.looseGpuRegions,
            active.request.buf as usize,
            active.desc.length,
            time_counter_now(),
        );
        match route {
            LoosePreadRoute::Aio => return false,
            LoosePreadRoute::KnownGpu => {
                stats::add(Stat::LoosePreadSkipped, 1);
                return false;
            }
            LoosePreadRoute::Pool => {}
        }
        // Loose tasks (queued + running) stay below the thread count, so
        // AMPR_EMU_APR_LOOSE_PREAD_PACK_RESERVE threads always serve pack tasks:
        // workers pick strictly by priority, and a high-priority loose stream
        // could otherwise hold every thread while a pack read stays queued.
        // Workers start on the first queued task; start them here so the
        // first loose read sees the real thread count and can split. With
        // <= AMPR_EMU_APR_LOOSE_PREAD_PACK_RESERVE threads (only the debug
        // `pread_threads` knob allows it) the reserve cannot be kept: the
        // cap floors at 1 loose task.
        if !self.ensure_pread_workers() {
            return false;
        }
        let looseCap = (self
            .preadThreadCount
            .saturating_sub(AMPR_EMU_APR_LOOSE_PREAD_PACK_RESERVE))
        .max(1)
        .min(AMPR_EMU_APR_LOOSE_PREAD_TASKS_MAX as usize) as u32;
        if self.preadLooseCount >= looseCap {
            return false;
        }
        // Split into parts when every part fits the cap and the free tasks;
        // otherwise one unsplit task, never a partial split.
        let length = active.desc.length;
        let part = loose_pread_part_bytes(crate::rt::tune::loose_pread_part_kib());
        let mut parts = loose_pread_part_count(length, part, looseCap - self.preadLooseCount);
        let mut rc = self.queue_loose_parts(active, item, priority, part, parts);
        if rc == SCE_KERNEL_ERROR_EAGAIN && parts > 1 {
            parts = 1;
            rc = self.queue_loose_parts(active, item, priority, part, parts);
        }
        if rc != 0 {
            return false;
        }
        if parts > 1 {
            stats::add(Stat::LoosePreadSplitReads, 1);
            stats::add(Stat::LoosePreadParts, parts as u64);
        }
        self.preadLooseCount += parts;
        self.preadLooseReadCount += 1;
        active.loosePart = LoosePartResult::new(length, parts);
        active.awaitingBatchSubmit = false;
        active.preadQueued = true;
        Self::account_active_read_accept(active, time_counter_now(), true);
        active.statSubmitNs = stats::now();
        if active.statSubmitNs != 0 {
            stats::max(
                Stat::AprInflightMax,
                (self.submittedActiveReadCount
                    + self.externalAioSubmittedCount.load(Ordering::Acquire)
                    + self.preadLooseReadCount) as u64,
            );
        }
        true
    }

    /// Queues `parts` tasks for the read, part k at `offset + k * part` into
    /// `buf + k * part`, all into the same game destination. The tasks get
    /// a null `request.result` and report through PreadTask.returnValue, so
    /// no pool thread writes the ActiveRead.
    fn queue_loose_parts(
        &mut self,
        active: &ActiveRead,
        item: &ActiveReadRef,
        priority: c_int,
        part: u64,
        parts: u32,
    ) -> c_int {
        let mut requests = [SceKernelAioRWRequest::default(); kAprExternalAioGroupMaxRequests];
        let length = active.desc.length;
        for index in 0..parts {
            let (start, len) = loose_pread_part_range(length, part, parts, index);
            let request = &mut requests[index as usize];
            *request = active.request;
            request.offset += start as off_t;
            request.nbyte = len as usize;
            request.buf = unsafe { active.request.buf.cast::<u8>().add(start as usize).cast() };
            request.result = null_mut();
        }
        self.queue_pread_tasks(
            &requests[..parts as usize],
            item.slot,
            item.generation,
            priority,
            true,
        )
    }

    /// One part task of a loose read is done (drain_pread_completions). Its
    /// result is folded in; once all parts are in, a full read completes as
    /// a kernel COMPLETED result would (poll path in progress.rs) and
    /// anything else goes back to kernel AIO as a whole.
    pub(crate) fn finish_loose_pread(&mut self, target: ActiveReadRef, part: LoosePartDone) {
        let it = self.activeReads.iterator_from_slot(target.slot);
        if it.index_ == kInvalid {
            abort();
        }
        let active = unsafe { it.get() };
        if active.listGeneration != target.generation
            || !active.preadQueued
            || active.aioId >= 0
            || active.awaitingBatchSubmit
            || active.awaitingResubmit
        {
            abort();
        }
        let Some(start) = part
            .offset
            .checked_sub(active.request.offset)
            .and_then(|s| u64::try_from(s).ok())
        else {
            abort();
        };
        if part.value == SCE_KERNEL_ERROR_EFAULT as i64 {
            // Only the faulted part's range; the fault address is unknown.
            self.looseGpuRegions.insert(
                active.request.buf as usize + start as usize,
                part.len,
                time_counter_now(),
            );
        }
        active
            .loosePart
            .add(part.index, start, part.len, part.value);
        if !active.loosePart.done() {
            return;
        }
        if self.preadLooseReadCount == 0 {
            abort();
        }
        self.preadLooseReadCount -= 1;
        active.preadQueued = false;
        let length = active.desc.length;
        let outcome = active.loosePart.outcome(length);
        match outcome {
            LoosePreadOutcome::Done => {
                active.result.returnValue = active.loosePart.total;
                active.result.state = SCE_KERNEL_AIO_STATE_COMPLETED as u32;
                stats::add(Stat::LoosePreadReads, 1);
                stats::add(Stat::LoosePreadBytes, length);
                if active.statSubmitNs != 0 {
                    let latencyNs = stats::since(active.statSubmitNs);
                    active.statSubmitNs = 0;
                    stats::add(Stat::AprReads, 1);
                    stats::add(Stat::AprReadBytes, length);
                    stats::add(Stat::AprReadNs, latencyNs);
                    stats::max(Stat::AprReadNsMax, latencyNs);
                }
                let mut finishedJob = active.job;
                // rc 0 and a full length: never a retry or a delete failure.
                if self.finish_active_read_after_delete(it, SCE_KERNEL_AIO_STATE_COMPLETED, 0) {
                    abort();
                }
                let _ = self.erase_active_read(it);
                if !finishedJob.is_null() && !self.activeReads.empty() {
                    self.reset_completion_frontier_active_aio_poll_for_job(
                        unsafe { &mut *finishedJob },
                        time_counter_now(),
                    );
                }
                self.maybe_release_reactor_job(&mut finishedJob);
            }
            outcome => {
                if outcome == LoosePreadOutcome::Efault {
                    stats::add(Stat::LoosePreadEfault, 1);
                } else {
                    stats::add(Stat::LoosePreadRetry, 1);
                }
                self.defer_loose_pread_to_aio(active);
            }
        }
    }

    /// Same deferred state as kernel AIO's EFAULT retry (capacity.rs), with no
    /// delay; resubmit_deferred_active_reads stages it for kernel AIO and
    /// accept_aio_submit_item does not account it a second time. Its
    /// apr_read_ns then runs from the kernel submit.
    fn defer_loose_pread_to_aio(&mut self, active: &mut ActiveRead) {
        if !active.submitAccounted || self.deferredActiveReadCount >= kMaxActiveReads {
            abort();
        }
        self.deferredActiveReadCount += 1;
        active.awaitingResubmit = true;
        active.retryNotBeforeNs = 0;
        active.submitTimeNs = 0;
        active.statSubmitNs = 0;
        active.result = SceKernelAioResult::default();
        active.request.result = &mut active.result;
    }
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    const MIB2: usize = 1 << LOOSE_GPU_REGION_SHIFT;
    /// A fixed `time_counter_now` for tests that do not exercise expiry.
    const T: u64 = 5;
    const READ: u64 = 0x7f000; // 508 KB, the measured loose read size
    const BUF: usize = 0x2_0000_0000;

    #[test]
    fn gpu_regions_cover_whole_2mib_regions_of_routable_ranges() {
        let mut t = LooseGpuRegions::new();
        assert!(!t.overlaps(BUF, READ, T), "empty table");
        t.insert(BUF + 0x1000, READ, T);
        assert!(t.overlaps(BUF, 1, T));
        assert!(t.overlaps(BUF + MIB2 - 1, 1, T));
        assert!(!t.overlaps(BUF + MIB2, READ, T));
        assert!(!t.overlaps(BUF - 0x1000, 0x1000, T));
        assert!(t.overlaps(BUF - 0x1000, 0x1001, T));
        // A read straddling a boundary marks both regions, each once.
        let mut s = LooseGpuRegions::new();
        s.insert(BUF + MIB2 - 0x1000, READ, T);
        assert!(s.overlaps(BUF, 1, T) && s.overlaps(BUF + MIB2, 1, T));
        assert_eq!(s.len, 2);
        s.insert(BUF, 1, T);
        assert_eq!(s.len, 2, "a known region is not added twice");
        // Empty, wrapping and more-than-capacity ranges are not tracked.
        let mut u = LooseGpuRegions::new();
        u.insert(0x1000, 0, T);
        u.insert(usize::MAX - 10, 100, T);
        let tooLong = (LOOSE_GPU_REGION_CAPACITY as u64 + 1) << LOOSE_GPU_REGION_SHIFT;
        u.insert(0, tooLong, T);
        assert_eq!(u.len, 0);
    }

    #[test]
    fn gpu_regions_expire_refresh_and_evict_oldest() {
        let mut t = LooseGpuRegions::new();
        let at = 1_000u64;
        t.insert(BUF, READ, at);
        assert!(t.overlaps(BUF, 1, at + LOOSE_GPU_REGION_TTL_NS - 1));
        let expired = at + LOOSE_GPU_REGION_TTL_NS;
        assert!(!t.overlaps(BUF, 1, expired), "expired");
        assert_eq!(
            loose_pread_route(true, true, &t, BUF, READ, expired),
            LoosePreadRoute::Pool,
            "a transient EFAULT is retried"
        );
        // A new EFAULT refreshes the expired entry instead of adding one.
        let later = at + 3 * LOOSE_GPU_REGION_TTL_NS;
        t.insert(BUF, READ, later);
        assert_eq!(t.len, 1);
        assert!(t.overlaps(BUF, 1, later + 1));
        // A full table replaces its oldest entry.
        let mut f = LooseGpuRegions::new();
        let base = 0x4_0000_0000usize;
        for i in 0..=LOOSE_GPU_REGION_CAPACITY {
            f.insert(base + i * MIB2, 1, T);
        }
        assert_eq!(f.len as usize, LOOSE_GPU_REGION_CAPACITY);
        assert!(!f.overlaps(base, 1, T), "first region evicted");
        assert!((1..=LOOSE_GPU_REGION_CAPACITY).all(|i| f.overlaps(base + i * MIB2, 1, T)));
    }

    #[test]
    fn outcome_is_done_only_for_the_full_length() {
        let efault = sce_errno_from_posix(EFAULT) as i64;
        let eio = SCE_KERNEL_ERROR_EIO as i64;
        assert_eq!(
            loose_pread_outcome(READ as i64, READ),
            LoosePreadOutcome::Done
        );
        assert_eq!(loose_pread_outcome(efault, READ), LoosePreadOutcome::Efault);
        for rc in [eio, 0, READ as i64 - 1, READ as i64 + 1] {
            assert_eq!(
                loose_pread_outcome(rc, READ),
                LoosePreadOutcome::Retry,
                "{rc}"
            );
        }
    }

    #[test]
    fn route_needs_first_submit_real_fd_and_no_known_gpu_region() {
        let mut t = LooseGpuRegions::new();
        let route = |t: &LooseGpuRegions, first, real, buf, len| {
            loose_pread_route(first, real, t, buf, len, T)
        };
        assert_eq!(route(&t, true, true, BUF, READ), LoosePreadRoute::Pool);
        assert_eq!(route(&t, false, true, BUF, READ), LoosePreadRoute::Aio);
        assert_eq!(route(&t, true, false, BUF, READ), LoosePreadRoute::Aio);
        assert_eq!(route(&t, true, true, BUF, 0), LoosePreadRoute::Aio);
        t.insert(BUF, READ, T);
        assert_eq!(
            route(&t, true, true, BUF + 0x80000, READ),
            LoosePreadRoute::KnownGpu
        );
        assert_eq!(
            route(&t, true, true, BUF + MIB2, READ),
            LoosePreadRoute::Pool
        );
    }

    // ---- split reads ----

    const PART: u64 = 64 * 1024;

    /// Folds per-part pread results, in reverse order (parts finish in any
    /// order), the way finish_loose_pread does.
    fn fold(length: u64, part: u64, values: &[i64]) -> LoosePartResult {
        let parts = values.len() as u32;
        let mut r = LoosePartResult::new(length, parts);
        for index in (0..parts).rev() {
            let (start, len) = loose_pread_part_range(length, part, parts, index);
            r.add(index, start, len, values[index as usize]);
        }
        assert!(r.done());
        r
    }

    /// Full results for the 8 parts of READ.
    fn full_parts() -> [i64; 8] {
        core::array::from_fn(|k| loose_pread_part_range(READ, PART, 8, k as u32).1 as i64)
    }

    #[test]
    fn part_size_count_and_ranges_cover_the_read_exactly() {
        for (kib, bytes) in [
            (0, 0),
            (1, 16 << 10),
            (16, 16 << 10),
            (18, 16 << 10),
            (66, PART),
        ] {
            assert_eq!(loose_pread_part_bytes(kib), bytes, "{kib} KiB");
        }
        assert_eq!(loose_pread_part_bytes(4096), 4 << 20);
        assert_eq!(loose_pread_part_count(READ, PART, 8), 8);
        assert_eq!(loose_pread_part_count(READ, PART, 7), 1, "no partial split");
        assert_eq!(loose_pread_part_count(READ, 0, 32), 1, "knob 0");
        assert_eq!(loose_pread_part_count(PART, PART, 32), 1);
        assert_eq!(loose_pread_part_count(PART + 1, PART, 32), 2);
        let tooMany = (kAprExternalAioGroupMaxRequests as u64 + 1) * 16 * 1024;
        assert_eq!(loose_pread_part_count(tooMany, 16 * 1024, 64), 1);
        assert_eq!(loose_pread_part_range(READ, PART, 1, 0), (0, READ));
        // Parts are contiguous from 0, the last one takes the rest.
        let mut next = 0;
        for k in 0..8 {
            let (start, len) = loose_pread_part_range(READ, PART, 8, k);
            assert_eq!((start, len.min(PART)), (next, len));
            next = start + len;
        }
        assert_eq!(next, READ);
        assert_eq!(loose_pread_part_range(PART + 1, PART, 2, 1), (PART, 1));
    }

    #[test]
    fn parts_fold_to_one_pread_up_to_the_first_short_part() {
        let r = fold(READ, PART, &full_parts());
        assert_eq!(
            (r.total, r.outcome(READ)),
            (READ as i64, LoosePreadOutcome::Done)
        );
        assert_eq!(
            fold(READ, PART, &[READ as i64]).outcome(READ),
            LoosePreadOutcome::Done
        );
        // EOF mid part: later parts count nothing, even a full one.
        let mut v = full_parts();
        v[3] = 1000;
        v[4] = 0;
        v[5] = PART as i64;
        let r = fold(READ, PART, &v);
        assert_eq!(
            (r.total, r.outcome(READ)),
            ((3 * PART + 1000) as i64, LoosePreadOutcome::Retry)
        );
        // EOF on a part boundary.
        let mut v = full_parts();
        v[3..].fill(0);
        assert_eq!(fold(READ, PART, &v).total, (3 * PART) as i64);
    }

    #[test]
    fn part_errors_end_the_read_and_efault_sends_it_to_aio() {
        let eio = SCE_KERNEL_ERROR_EIO as i64;
        let mut v = full_parts();
        v[2] = eio;
        v[5] = 10;
        let r = fold(READ, PART, &v);
        assert_eq!((r.total, r.outcome(READ)), (eio, LoosePreadOutcome::Retry));
        // A short part before the error ends the read first.
        v[1] = 10;
        assert_eq!(fold(READ, PART, &v).total, (PART + 10) as i64);
        // EFAULT in any part wins, also after an earlier EOF.
        let mut v = full_parts();
        v[6] = sce_errno_from_posix(EFAULT) as i64;
        assert_eq!(
            fold(READ, PART, &v).outcome(READ),
            LoosePreadOutcome::Efault
        );
        v[0] = 0;
        assert_eq!(
            fold(READ, PART, &v).outcome(READ),
            LoosePreadOutcome::Efault
        );
    }
}
