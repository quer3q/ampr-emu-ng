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
            let mut speculativeCommandUsed = false;
            let mut readIssueBudget = ReadIssueBudget {
                requestsLeft: AMPR_EMU_APR_READ_CHUNK_QUANTUM,
                bytesLeft: AMPR_EMU_APR_READ_PASS_MAX_BYTES,
            };
            let mut job = laneHeads[lane];
            while !job.is_null() {
                if self.native_batch_wait_pending(lane as u32) {
                    break;
                }
                let next = unsafe { (*job).priorityNext.load(Ordering::Acquire) };
                progressed |= self.progress_job(
                    &mut job,
                    priorReadFencePending,
                    priorNativeBatchPending,
                    &mut speculativeCommandUsed,
                    &mut readIssueBudget,
                    &mut admission,
                );
                // A synchronously released/failed head is a pass boundary; a
                // blocked or partially admitted head keeps the lane.
                if job.is_null() {
                    break;
                }
                let j = unsafe { &*job };
                if j.sourceOffset != j.sourceBytes {
                    break;
                }
                let nativeSubmitted = j.nativeSubmitted.load(Ordering::Acquire);
                if !Self::job_allows_priority_successor(j, nativeSubmitted) {
                    break;
                }
                priorReadFencePending |= Self::job_has_outstanding_reads(j);
                priorNativeBatchPending |=
                    nativeSubmitted && j.nativeMicroEngine == NativeMicroEngine::AprBatch;
                job = next;
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
                || Self::cross_eop_suffix_is_canceled(unsafe { &*job }, active.desc.errorOff)
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
        for requestIndex in 0..external.requestCount {
            let id = external.aioIds[requestIndex as usize];
            if id < 0 {
                continue;
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
            batch.items[item].externalRequestIndex = requestIndex;
            batch.ids[item] = id;
            batch.states[item] = i32::MIN;
        }
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
        requestIndex: u32,
        nowNs: u64,
        _rc: c_int,
    ) {
        let i = requestIndex as usize;
        // A failed delete does not retire the ID; the kernel may still own the
        // buffer, so a timed-out delete is fatal.
        if Self::record_aio_delete_failure(
            &mut external.deleteRetries[i],
            &mut external.deleteFirstFailureNs[i],
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
        let requestIndex = batch.items[item].externalRequestIndex;
        if external.is_null() {
            abort();
        }
        let e = unsafe { &*external };
        if e.state != ExternalAioState::Submitted
            || requestIndex >= e.requestCount
            || e.aioIds[requestIndex as usize] != batch.ids[item]
        {
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
                    self.set_or_defer_read_command_error(
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
                Self::stat_observe_poll(
                    external,
                    active,
                    batch.items[item].externalRequestIndex,
                    terminal,
                    statPollNs,
                );
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

        let mut completedAny = false;
        for terminal in 0..terminalCount {
            if deleteResults[terminal] == i32::MIN {
                abort();
            }
            let item = terminalItems[terminal];
            let batchItem = batch.items[item];
            if batchItem.isExternal {
                let e = unsafe { &mut *self.poll_batch_external(batch, item) };
                let requestIndex = batchItem.externalRequestIndex;
                let deleteSceRc = apr_aio_api_rc_to_sce(deleteResults[terminal]);
                if deleteSceRc != 0 {
                    self.handle_external_delete_failure(e, requestIndex, pollEndNs, deleteSceRc);
                    if e.nextPollTimeNs <= pollEndNs {
                        self.schedule_next_external_aio_poll(e, pollEndNs);
                    }
                    continue;
                }
                if e.remainingCount == 0 {
                    abort();
                }
                e.aioIds[requestIndex as usize] = -1;
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
        requestIndex: u32,
        terminal: bool,
        nowNs: u64,
    ) {
        let (submitNs, lastPollNs, polls, bytes, ext) =
            if let Some(e) = unsafe { external.as_mut() } {
                let i = requestIndex as usize;
                if i >= kAprExternalAioGroupMaxRequests {
                    return;
                }
                let bytes = e.requests[i].nbyte as u64;
                (
                    &mut e.statSubmitNs[i],
                    &mut e.statLastPollNs[i],
                    &mut e.statPolls[i],
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
