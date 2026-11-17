//! Job progress loop, deferred read resubmission and AIO poll batch execution.

use super::*;
use crate::rt::stats::{self, Stat};

impl AprAioReactor {
    pub(crate) fn progress_all_jobs(&mut self) -> bool {
        let mut progressed = false;
        let mut admission = AioAdmissionContext::default();
        self.begin_aio_submit_round();
        let mut laneHeads: [JobPtr; PRIO_N] = [null_mut(); PRIO_N];
        let mut laneDemandMask: u8 = 0;
        {
            let _lk = self.m.lock();
            for lane in 0..PRIO_N {
                laneHeads[lane] = self.activePriorityHeads[lane];
                if !laneHeads[lane].is_null() {
                    laneDemandMask |= (1u32 << lane) as u8;
                }
            }
        }
        admission.laneDemandMask = laneDemandMask;
        progressed |= self.stage_external_aio_submits(&mut admission, true);

        // Every pass restarts at the highest APR priority; FIFO order inside a
        // lane is preserved and each lane has a bounded read-chunk quantum.
        for lane in 0..PRIO_N {
            Self::begin_aio_admission_lane(&mut admission);
            self.clear_cursor_read_wait_hint(lane);
            let mut priorReadFencePending = false;
            let mut priorNativeBatchPending = false;
            let mut readIssueBudget = ReadIssueBudget {
                requestsLeft: crate::rt::tune::read_chunk_quantum(),
                bytesLeft: crate::rt::tune::read_pass_bytes(),
                held: false,
            };
            let mut job = laneHeads[lane];
            while !job.is_null() {
                if self.native_batch_wait_pending(lane as u32) {
                    if unsafe { !(*job).priorityNext.load(Ordering::Acquire).is_null() } {
                        note_lane_block(LaneBlock::Wait);
                    }
                    break;
                }
                let next = unsafe { (*job).priorityNext.load(Ordering::Acquire) };
                progressed |= self.progress_job(
                    &mut job,
                    priorReadFencePending,
                    priorNativeBatchPending,
                    &mut readIssueBudget,
                    &mut admission,
                );
                // A synchronously released/failed head is a pass boundary; a
                // blocked or partially admitted head keeps the lane.
                if job.is_null() {
                    break;
                }
                let j = unsafe { &mut *job };
                let nativeSubmitted = j.nativeSubmitted.load(Ordering::Acquire);
                if j.sourceOffset != j.sourceBytes {
                    if !next.is_null() {
                        Self::note_lane_successor_blocked(j);
                    }
                    break;
                } else if !Self::job_allows_priority_successor(j, nativeSubmitted) {
                    if !next.is_null() {
                        note_lane_block(LaneBlock::Other);
                    }
                    break;
                }
                // The successor's EOPs wait while any earlier job still reads.
                priorReadFencePending |= Self::job_has_outstanding_reads(j);
                priorNativeBatchPending |=
                    nativeSubmitted && j.nativeMicroEngine == NativeMicroEngine::AprBatch;
                job = next;
            }
            if readIssueBudget.held {
                stats::add(Stat::ReadBudgetHeld, 1);
            }
            if !self.seal_open_native_apr_batch_group(lane as u32) {
                abort();
            }
        }
        Self::begin_aio_admission_lane(&mut admission);
        progressed |= self.stage_external_aio_submits(&mut admission, false);
        progressed |= self.flush_aio_submit_round(&mut admission);
        #[cfg(debug_assertions)]
        if admission.initialized
            && admission.snapshot.activeCount
                != self
                    .collect_aio_admission_snapshot(time_counter_now())
                    .activeCount
        {
            abort();
        }
        progressed
    }

    pub(crate) fn resubmit_deferred_active_reads(&mut self) -> bool {
        if self.deferredActiveReadCount == 0 {
            return false;
        }
        self.begin_aio_submit_round();
        let mut progressed = false;
        let nowNs = time_counter_now();
        let mut it = self.activeReads.begin();
        while it.index_ != kInvalid {
            let active = unsafe { it.get() };
            if !active.awaitingResubmit {
                it.inc();
                continue;
            }
            let mut job = active.job;
            let chain = active.chain;
            if job.is_null()
                || chain.is_null()
                || Self::job_failed(unsafe { &*job })
            {
                if !chain.is_null() {
                    unsafe { (*chain).allIssued = true };
                }
                apr_release_aio_read_desc(&mut active.desc);
                Self::decrement_active_read_count(job);
                Self::decrement_read_chain_active(chain, active.readCreditBytes);
                let next = self.erase_active_read(it);
                self.maybe_finish_read_chain(chain);
                self.maybe_release_reactor_job(&mut job);
                it = next;
                progressed = true;
                continue;
            }
            if active.retryNotBeforeNs != 0 && nowNs < active.retryNotBeforeNs {
                it.inc();
                continue;
            }
            active.result = SceKernelAioResult::default();
            active.request.result = &mut active.result;
            self.stage_aio_submit(active, true);
            it.inc();
        }
        progressed |= self.flush_aio_submit_round(null_mut());
        progressed
    }
}

impl AprAioReactor {
    pub(crate) fn has_submitted_active_reads(&self) -> bool {
        self.submittedActiveReadCount != 0
            || self.externalAioSubmittedCount.load(Ordering::Acquire) != 0
    }

    pub(crate) fn next_deferred_active_retry_wait_ns(&self, nowNs: u64) -> u64 {
        let idle = Self::active_lane_idle_sleep_ns() as u64;
        if self.deferredActiveReadCount == 0
            && self.externalAioDeferredCount.load(Ordering::Acquire) == 0
        {
            return idle;
        }
        let mut best: u64 = 0;
        let mut it = self.activeReads.begin_const();
        while it.index_ != kInvalid {
            let active = unsafe { &*it.ptr() };
            it.inc();
            if !active.awaitingResubmit {
                continue;
            }
            if active.retryNotBeforeNs == 0 || active.retryNotBeforeNs <= nowNs {
                return 1;
            }
            let waitNs = active.retryNotBeforeNs - nowNs;
            if best == 0 || waitNs < best {
                best = waitNs;
            }
        }
        for external in &self.externalAioReads {
            if !external.published.load(Ordering::Acquire)
                || external.state != ExternalAioState::Deferred
            {
                continue;
            }
            if external.retryNotBeforeNs == 0 || external.retryNotBeforeNs <= nowNs {
                return 1;
            }
            let waitNs = external.retryNotBeforeNs - nowNs;
            if best == 0 || waitNs < best {
                best = waitNs;
            }
        }
        if best != 0 {
            best
        } else {
            idle
        }
    }

    pub(crate) fn stage_active_aio_poll(&mut self, batch: &mut AioPollBatch, it: ActiveReadIt) {
        if it.index_ == kInvalid || batch.count >= kAioPollBatchLimit {
            abort();
        }
        let active = unsafe { it.get() };
        if !Self::active_read_is_submitted(active) {
            abort();
        }
        #[cfg(debug_assertions)]
        if batch.ids[..batch.count].contains(&active.aioId) {
            abort();
        }
        let item = batch.count;
        batch.count += 1;
        batch.items[item].active = ActiveReadRef {
            slot: active.listSlot,
            generation: active.listGeneration,
        };
        batch.items[item].isExternal = false;
        batch.ids[item] = active.aioId;
        batch.states[item] = i32::MIN;
        active.hotPollQueued = false;
        self.remove_poll_deadline(active);
    }

    pub(crate) fn next_external_aio_poll_backoff_ns(&self, external: &ExternalAioRead) -> u32 {
        let maxBackoffNs = match external.ioClass {
            AprExternalAioClass::Latency => AMPR_EMU_APR_EXTERNAL_AIO_POLL_LATENCY_BACKOFF_MAX_NS,
            AprExternalAioClass::Balanced => AMPR_EMU_APR_EXTERNAL_AIO_POLL_BALANCED_BACKOFF_MAX_NS,
            AprExternalAioClass::Bulk => AMPR_EMU_APR_EXTERNAL_AIO_POLL_BULK_BACKOFF_MAX_NS,
        };
        let mut backoffNs = external.pollBackoffNs;
        if backoffNs == 0 {
            backoffNs = self.external_aio_initial_poll_delay_ns(external);
        } else if backoffNs < maxBackoffNs {
            backoffNs = if backoffNs <= maxBackoffNs / 2 {
                backoffNs * 2
            } else {
                maxBackoffNs
            };
        }
        backoffNs.min(maxBackoffNs)
    }

    pub(crate) fn schedule_next_external_aio_poll(
        &self,
        external: &mut ExternalAioRead,
        nowNs: u64,
    ) {
        external.pollBackoffNs = self.next_external_aio_poll_backoff_ns(external);
        external.nextPollTimeNs = nowNs + external.pollBackoffNs as u64;
    }

    pub(crate) fn stage_external_aio_poll(&mut self, batch: &mut AioPollBatch, slotIndex: u32) {
        if slotIndex >= kExternalAioCapacity {
            abort();
        }
        let external = &self.externalAioReads[slotIndex as usize];
        if !external.published.load(Ordering::Acquire)
            || external.state != ExternalAioState::Submitted
            || external.remainingCount == 0
        {
            abort();
        }
        let id = external.aioId;
        if id < 0 {
            return;
        }
        if batch.count >= kAioPollBatchLimit {
            abort();
        }
        #[cfg(debug_assertions)]
        if batch.ids[..batch.count].contains(&id) {
            abort();
        }
        let item = batch.count;
        batch.count += 1;
        batch.items[item].external = ExternalAioRef {
            slot: slotIndex,
            generation: external.generation,
        };
        batch.items[item].isExternal = true;
        batch.ids[item] = id;
        batch.states[item] = i32::MIN;
    }

    pub(crate) fn record_aio_delete_failure(
        retries: &mut u32,
        firstFailureNs: &mut u64,
        nowNs: u64,
    ) -> bool {
        if *retries != u32::MAX {
            *retries += 1;
        }
        if *firstFailureNs == 0 {
            *firstFailureNs = nowNs;
        }
        let ageNs = nowNs.saturating_sub(*firstFailureNs);
        (*firstFailureNs != 0 && ageNs >= AMPR_EMU_APR_AIO_DELETE_TIMEOUT_NS)
            || (nowNs == 0 && *retries >= AMPR_EMU_APR_AIO_DELETE_RETRY_LIMIT)
    }

    pub(crate) fn handle_external_delete_failure(
        &self,
        external: &mut ExternalAioRead,
        nowNs: u64,
        _rc: c_int,
    ) {
        // A failed delete does not retire the ID; the kernel may still own the
        // buffer, so a timed-out delete is fatal.
        if Self::record_aio_delete_failure(
            &mut external.deleteRetries,
            &mut external.deleteFirstFailureNs,
            nowNs,
        ) {
            abort();
        }
    }
}

impl AprAioReactor {
    /// Live external slot for a batch item, or abort when stale.
    fn poll_batch_external(&mut self, batch: &AioPollBatch, item: usize) -> *mut ExternalAioRead {
        let external = self.external_aio_at(&batch.items[item].external);
        if external.is_null() {
            abort();
        }
        let e = unsafe { &*external };
        if e.state != ExternalAioState::Submitted || e.aioId != batch.ids[item] {
            abort();
        }
        external
    }

    pub(crate) fn execute_active_aio_poll_batch(
        &mut self,
        batch: &mut AioPollBatch,
        pollNow: u64,
    ) -> AioObservationResult {
        if batch.count == 0 {
            return AioObservationResult::default();
        }
        let pollRc = unsafe {
            sceKernelAioPollRequests(
                batch.ids.as_mut_ptr(),
                batch.count as c_int,
                batch.states.as_mut_ptr(),
            )
        };
        let pollEndNs = pollNow;
        if pollRc != 0 {
            abort();
        }
        let statPollNs = stats::now();

        let mut terminalItems = [0usize; kAioPollBatchLimit];
        let mut deleteIds: [SceKernelAioSubmitId; kAioPollBatchLimit] = [0; kAioPollBatchLimit];
        let mut deleteResults = [0 as c_int; kAioPollBatchLimit];
        let mut terminalCount = 0usize;
        for item in 0..batch.count {
            let external = if batch.items[item].isExternal {
                self.poll_batch_external(batch, item)
            } else {
                null_mut()
            };
            let r = batch.items[item].active;
            let active = self.activeReads.active_at_slot_2(r.slot, r.generation);
            if external.is_null()
                && (active.is_null()
                    || !Self::active_read_is_submitted(unsafe { &*active })
                    || unsafe { (*active).aioId } != batch.ids[item])
            {
                abort();
            }
            let mut state = batch.states[item];
            if state == i32::MIN {
                abort();
            }
            if state < 0 {
                // Invalid ID in states[]: publish its poll error and retire the
                // ID through the common delete batch.
                if !active.is_null() && unsafe { !(*active).job.is_null() } {
                    let a = unsafe { &*active };
                    self.set_command_error(
                        unsafe { &mut *a.job },
                        c"aio-poll".as_ptr(),
                        apr_backend_read_error_to_apr(apr_aio_api_rc_to_sce(state)),
                        a.desc.errorOff,
                        0,
                    );
                }
                state = SCE_KERNEL_AIO_STATE_ABORTED;
                batch.states[item] = state;
            }
            let finalState = state & !SCE_KERNEL_AIO_STATE_NOTIFIED;
            let terminal = finalState == SCE_KERNEL_AIO_STATE_COMPLETED
                || finalState == SCE_KERNEL_AIO_STATE_ABORTED;
            if statPollNs != 0 {
                Self::stat_observe_poll(external, active, terminal, statPollNs);
            }
            if terminal {
                terminalItems[terminalCount] = item;
                deleteIds[terminalCount] = batch.ids[item];
                deleteResults[terminalCount] = i32::MIN;
                terminalCount += 1;
            } else if !external.is_null() {
                let e = unsafe { &mut *external };
                if e.nextPollTimeNs <= pollEndNs {
                    self.schedule_next_external_aio_poll(e, pollEndNs);
                }
            } else {
                self.schedule_next_active_read_poll(unsafe { &mut *active }, pollEndNs);
            }
        }

        if terminalCount == 0 {
            batch.count = 0;
            return AioObservationResult {
                polled: true,
                completed: false,
            };
        }

        let deleteRc = unsafe {
            sceKernelAioDeleteRequests(
                deleteIds.as_mut_ptr(),
                terminalCount as c_int,
                deleteResults.as_mut_ptr(),
            )
        };
        if deleteRc != 0 {
            abort();
        }
        for &r in &deleteResults[..terminalCount] {
            crate::rt::stats::add(
                if r == 0 {
                    crate::rt::stats::Stat::AioIdsDeleted
                } else {
                    crate::rt::stats::Stat::AioDeleteFailed
                },
                1,
            );
        }

        let mut completedAny = false;
        for terminal in 0..terminalCount {
            if deleteResults[terminal] == i32::MIN {
                abort();
            }
            let item = terminalItems[terminal];
            let batchItem = batch.items[item];
            if batchItem.isExternal {
                let e = unsafe { &mut *self.poll_batch_external(batch, item) };
                let deleteSceRc = apr_aio_api_rc_to_sce(deleteResults[terminal]);
                if deleteSceRc != 0 {
                    self.handle_external_delete_failure(e, pollEndNs, deleteSceRc);
                    if e.nextPollTimeNs <= pollEndNs {
                        self.schedule_next_external_aio_poll(e, pollEndNs);
                    }
                    continue;
                }
                if e.remainingCount == 0 {
                    abort();
                }
                e.aioId = -1;
                e.remainingCount -= 1;
                if self.externalAioSubmittedCount.load(Ordering::Acquire) == 0 {
                    abort();
                }
                self.externalAioSubmittedCount
                    .fetch_sub(1, Ordering::Release);
                if batch.states[item] & !SCE_KERNEL_AIO_STATE_NOTIFIED
                    != SCE_KERNEL_AIO_STATE_COMPLETED
                {
                    e.completionState = batch.states[item];
                }
                completedAny = true;
                if e.remainingCount != 0 {
                    continue;
                }
                if self.externalAioLiveCount.load(Ordering::Acquire) == 0 {
                    abort();
                }
                self.externalAioLiveCount.fetch_sub(1, Ordering::Release);
                let completionState = e.completionState;
                self.notify_external_aio(e, AprExternalAioEvent::Completed, completionState, false);
                Self::release_external_aio_slot(e);
                continue;
            }
            let activeItem = batchItem.active;
            let it = self.activeReads.iterator_from_slot(activeItem.slot);
            if it.index_ == kInvalid
                || unsafe { it.get() }.listGeneration != activeItem.generation
                || unsafe { it.get() }.aioId != batch.ids[item]
            {
                abort();
            }
            let mut finishedJob = unsafe { it.get() }.job;
            if !self.finish_active_read_after_delete(
                it,
                batch.states[item],
                deleteResults[terminal],
            ) {
                let _ = self.erase_active_read(it);
                if !finishedJob.is_null() && !self.activeReads.empty() {
                    self.reset_completion_frontier_active_aio_poll_for_job(
                        unsafe { &mut *finishedJob },
                        pollEndNs,
                    );
                }
                self.maybe_release_reactor_job(&mut finishedJob);
                completedAny = true;
            } else if !unsafe { it.get() }.awaitingResubmit {
                self.schedule_next_active_read_poll(unsafe { it.get() }, pollEndNs);
            }
        }
        batch.count = 0;
        AioObservationResult {
            polled: true,
            completed: completedAny,
        }
    }
}

impl AprAioReactor {
    /// mem_report: one poll of one kernel AIO request. A "done" poll records
    /// submit->observed latency, polls since submit, and the gap since the last
    /// "not done" poll (0 when done on the first poll). `statSubmitNs` is cleared
    /// so a re-poll after a failed delete is not counted twice.
    fn stat_observe_poll(
        external: *mut ExternalAioRead,
        active: *mut ActiveRead,
        terminal: bool,
        nowNs: u64,
    ) {
        let (submitNs, lastPollNs, polls, bytes, ext) =
            if let Some(e) = unsafe { external.as_mut() } {
                let bytes = e.request.nbyte as u64;
                (
                    &mut e.statSubmitNs,
                    &mut e.statLastPollNs,
                    &mut e.statPolls,
                    bytes,
                    true,
                )
            } else if let Some(a) = unsafe { active.as_mut() } {
                let bytes = a.request.nbyte as u64;
                (
                    &mut a.statSubmitNs,
                    &mut a.statLastPollNs,
                    &mut a.statPolls,
                    bytes,
                    false,
                )
            } else {
                return;
            };
        *polls = polls.saturating_add(1);
        if !terminal {
            *lastPollNs = nowNs;
            return;
        }
        if *submitNs == 0 {
            return;
        }
        let latencyNs = nowNs.saturating_sub(*submitNs);
        let detectNs = if *lastPollNs != 0 {
            nowNs.saturating_sub(*lastPollNs)
        } else {
            0
        };
        let pollCount = *polls as u64;
        *submitNs = 0;
        if ext {
            stats::add(Stat::ExtReads, 1);
            stats::add(Stat::ExtReadNs, latencyNs);
            stats::max(Stat::ExtReadNsMax, latencyNs);
            stats::add(Stat::ExtPolls, pollCount);
            stats::add(Stat::ExtDetectNs, detectNs);
        } else {
            stats::add(Stat::AprReads, 1);
            stats::add(Stat::AprReadBytes, bytes);
            stats::add(Stat::AprReadNs, latencyNs);
            stats::max(Stat::AprReadNsMax, latencyNs);
            stats::add(Stat::AprPolls, pollCount);
            stats::add(Stat::AprDetectNs, detectNs);
        }
    }
}

// ---- lane block diagnostics ----

/// A command that only tells the game the job's earlier work is done: the
/// at-completion forms of WriteAddress, WriteCounter, WriteKernelEventQueue
/// and the WriteAddressFrom{TimeCounter,Counter,CounterPair} writes (the
/// `_04_00` exports decode to the same op types). It ends job_notify_ns
/// (native.rs) and classifies a parked head (lane_block_kind).
pub(crate) fn lane_completion_signals(op: &Op) -> bool {
    match op.op_type {
        WRITE_ADDRESS
        | WRITE_EQUEUE
        | WRITE_COUNTER
        | WRITE_ADDRESS_FROM_TIME_COUNTER
        | WRITE_ADDRESS_FROM_COUNTER
        | WRITE_ADDRESS_FROM_COUNTER_PAIR => !AprAioReactor::software_op_is_sop(op),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaneBlock {
    Fence,
    Wait,
    Other,
}

/// Why a head with source left stops its lane: `cursorOp` is the decoded
/// command parked at its source cursor (None if not cached), `fencePending`
/// whether its own reads or a deferred native EOP are still outstanding.
pub(crate) fn lane_block_kind(cursorOp: Option<&Op>, fencePending: bool) -> LaneBlock {
    match cursorOp {
        Some(op) if matches!(op.op_type, WAIT_ON_ADDRESS | WAIT_ON_COUNTER) => LaneBlock::Wait,
        Some(op) if fencePending && lane_completion_signals(op) => LaneBlock::Fence,
        _ => LaneBlock::Other,
    }
}

pub(crate) fn note_lane_block(kind: LaneBlock) {
    let s = match kind {
        LaneBlock::Fence => Stat::LaneSuccessorBlockedFence,
        LaneBlock::Wait => Stat::LaneSuccessorBlockedWait,
        LaneBlock::Other => Stat::LaneSuccessorBlockedOther,
    };
    stats::add(s, 1);
}

impl AprAioReactor {
    /// The decoded command parked at the job's source cursor, if cached.
    fn lane_cursor_op(j: &JobState) -> Option<&Op> {
        (j.decodedOpCacheBytes != 0 && j.decodedOpCache.buf_offset_bytes == j.sourceOffset)
            .then_some(&j.decodedOpCache)
    }

    /// mem_report: the head before `succ` is being released. If `succ`'s
    /// reads are all done and it is parked on a completion command, it was
    /// held by lane order since its last read finished: job_order_wait_ns.
    /// Its job_notify_ns span keeps running (statReadDoneNs is not taken).
    pub(crate) fn note_successor_order_wait(succ: &JobState) {
        #[cfg(feature = "mem_report")]
        let start = succ.statReadDoneNs;
        #[cfg(not(feature = "mem_report"))]
        let start = 0u64;
        if start != 0
            && !Self::job_failed(succ)
            && !Self::job_has_outstanding_reads(succ)
            && Self::lane_cursor_op(succ).is_some_and(lane_completion_signals)
        {
            stats::add(Stat::JobOrderWaits, 1);
            stats::add(Stat::JobOrderWaitNs, stats::since(start));
        }
    }

    /// Records why the lane loop stops before `j`'s queued successor.
    pub(crate) fn note_lane_successor_blocked(j: &JobState) {
        if !crate::rt::tune::ON {
            return;
        }
        let fencePending =
            j.completedReadSeq < j.latestSubmittedReadSeq || j.nativeBatchReleasePending;
        note_lane_block(lane_block_kind(Self::lane_cursor_op(j), fencePending));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn op(op_type: OpType) -> Op {
        Op {
            op_type,
            ..Op::default()
        }
    }
    fn write(op_type: OpType, sop: bool) -> Op {
        let mut o = op(op_type);
        o.ptra = 0x1000;
        o.u64a = 7;
        o.u64b = 0x2000;
        o.u32b = 3;
        match op_type {
            WRITE_ADDRESS | WRITE_EQUEUE => o.u8a = sop as u8,
            WRITE_COUNTER => {
                o.u8b = 1;
                o.u32c = sop as u32;
            }
            _ => o.u8b = sop as u8,
        }
        o
    }
    const WRITES: [OpType; 6] = [
        WRITE_ADDRESS,
        WRITE_EQUEUE,
        WRITE_COUNTER,
        WRITE_ADDRESS_FROM_TIME_COUNTER,
        WRITE_ADDRESS_FROM_COUNTER,
        WRITE_ADDRESS_FROM_COUNTER_PAIR,
    ];
    fn nop() -> Op {
        let mut o = op(NOP);
        o.u32a = 1;
        o
    }
    fn read_file() -> Op {
        let mut o = op(APR_READ_FILE);
        o.u32a = 1;
        o.ptra = 0x10000;
        o.u64a = 4096;
        o
    }
    fn wait_address() -> Op {
        let mut o = op(WAIT_ON_ADDRESS);
        o.ptra = 0x1000;
        o.u64a = 1;
        o
    }

    #[test]
    fn completion_signals_are_eop_writes_also_after_decode() {
        for t in WRITES {
            assert!(lane_completion_signals(&write(t, false)), "{t}");
            assert!(!lane_completion_signals(&write(t, true)), "sop {t}");
        }
        for t in [
            NOP,
            MARKER_POP,
            APR_READ_FILE,
            APR_READ_GATHER_SCATTER,
            APR_RESET_GATHER_SCATTER,
            APR_MAP_BEGIN,
            APR_MAP_END,
            WAIT_ON_ADDRESS,
            WAIT_ON_COUNTER,
            AMM_MAP,
        ] {
            assert!(!lane_completion_signals(&op(t)), "{t}");
        }
        // Packed and decoded again, every op keeps its class.
        let mut ops: Vec<Op> = WRITES.iter().map(|&t| write(t, false)).collect();
        ops.extend(WRITES.iter().map(|&t| write(t, true)));
        ops.extend([nop(), op(MARKER_POP), read_file(), wait_address()]);
        let (mut buf, mut offs) = (Vec::new(), Vec::new());
        for o in &ops {
            offs.push(buf.len() as u32);
            let (w, n) = o.encode_words().unwrap();
            for x in &w[..n] {
                buf.extend_from_slice(&x.to_ne_bytes());
            }
        }
        for (o, &off) in ops.iter().zip(&offs) {
            let (mut d, mut n, mut e) = (Op::default(), 0u32, 0u32);
            let rc = unsafe {
                ampr_decode_apr_packed_op(
                    buf.as_ptr().cast(),
                    buf.len() as u32,
                    off,
                    &mut d,
                    &mut n,
                    &mut e,
                )
            };
            assert_eq!(rc, 0, "{}", o.op_type);
            assert_eq!(d.op_type, o.op_type);
            assert_eq!(lane_completion_signals(&d), lane_completion_signals(o), "{}", o.op_type);
        }
    }

    #[test]
    fn block_kind_follows_the_parked_command() {
        let eop = write(WRITE_ADDRESS, false);
        assert_eq!(lane_block_kind(Some(&eop), true), LaneBlock::Fence);
        assert_eq!(lane_block_kind(Some(&eop), false), LaneBlock::Other);
        assert_eq!(lane_block_kind(Some(&wait_address()), false), LaneBlock::Wait);
        assert_eq!(lane_block_kind(Some(&op(WAIT_ON_COUNTER)), true), LaneBlock::Wait);
        assert_eq!(lane_block_kind(Some(&read_file()), true), LaneBlock::Other);
        assert_eq!(lane_block_kind(Some(&nop()), true), LaneBlock::Other);
        assert_eq!(lane_block_kind(None, true), LaneBlock::Other);
    }
}
