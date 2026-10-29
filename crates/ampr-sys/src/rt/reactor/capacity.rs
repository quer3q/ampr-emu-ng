//! Capacity probe polling, post-delete active read completion and native batch progress.

use super::*;

impl AprAioReactor {
    pub(crate) fn next_capacity_probe_active_read(&mut self) -> ActiveReadIt {
        let mut afterCursor: Option<u32> = None;
        let mut wrapped: Option<u32> = None;
        let end = self.activeReads.end();
        let mut it = self.activeReads.begin();
        while it != end {
            let active = unsafe { it.get() };
            it.inc();
            if !Self::active_read_is_submitted(active) {
                continue;
            }
            let slot = active.listSlot;
            if wrapped.is_none_or(|w| slot < w) {
                wrapped = Some(slot);
            }
            if slot > self.capacityPollCursorSlot && afterCursor.is_none_or(|a| slot < a) {
                afterCursor = Some(slot);
            }
        }
        let Some(selected) = afterCursor.or(wrapped) else {
            self.capacityPollCursorSlot = u32::MAX;
            return self.activeReads.end();
        };
        self.capacityPollCursorSlot = selected;
        self.activeReads.iterator_from_slot(selected)
    }

    pub(crate) fn poll_active_aio_reads_for_capacity(&mut self, now: u64) -> AioObservationResult {
        if !self.capacityPollRequested
            || self.submittedActiveReadCount == 0
            || (self.nextCapacityPollNs != 0 && now < self.nextCapacityPollNs)
        {
            return AioObservationResult::default();
        }
        let mut batch = AioPollBatch::default();
        let itemLimit = (self.submittedActiveReadCount as usize).min(kAioCapacityPollBatchLimit);
        while batch.count < itemLimit {
            let it = self.next_capacity_probe_active_read();
            if it == self.activeReads.end() {
                break;
            }
            self.stage_active_aio_poll(&mut batch, it);
        }
        let result = self.execute_active_aio_poll_batch(&mut batch, now);
        if result.polled {
            self.nextCapacityPollNs =
                time_counter_now() + AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS;
        }
        result
    }

    pub(crate) fn poll_active_aio_reads_once(&mut self) -> AioObservationResult {
        let observationNow = time_counter_now();
        let mut batch = AioPollBatch::default();
        while batch.count < kAioPollBatchLimit {
            let hotIt = self.pop_hot_active_read_poll();
            if hotIt == self.activeReads.end() {
                break;
            }
            self.stage_active_aio_poll(&mut batch, hotIt);
        }
        let mut slotIndex = 0u32;
        while slotIndex < kExternalAioCapacity && batch.count < kAioPollBatchLimit {
            let external = &self.externalAioReads[slotIndex as usize];
            if external.published.load(Ordering::Acquire)
                && external.state == ExternalAioState::Submitted
                && !external.preadBacked
                && (external.nextPollTimeNs == 0 || external.nextPollTimeNs <= observationNow)
            {
                self.stage_external_aio_poll(&mut batch, slotIndex);
            }
            slotIndex += 1;
        }
        // A pack job finished: its game read is likely done, so do not wait for deadlines.
        let dueNow = if self.externalProgressPollAll.swap(false, Ordering::AcqRel) {
            u64::MAX
        } else {
            observationNow
        };
        while batch.count < kAioPollBatchLimit && !self.activeReads.empty() {
            let dueIt = self.first_due_active_read(dueNow);
            if dueIt == self.activeReads.end() {
                break;
            }
            self.stage_active_aio_poll(&mut batch, dueIt);
        }
        self.execute_active_aio_poll_batch(&mut batch, observationNow)
    }
}

impl AprAioReactor {
    pub(crate) fn finish_active_read_after_delete(
        &mut self,
        it: ActiveReadIt,
        state: c_int,
        deleteResult: c_int,
    ) -> bool {
        let active = unsafe { &mut *it.ptr() };
        let job = active.job;
        let chain = active.chain;
        let finalState = state & !SCE_KERNEL_AIO_STATE_NOTIFIED;
        let errorOff = active.desc.errorOff;
        let finishTimeNs = time_counter_now();
        let completeAgeMs = Self::active_read_age_ms(active, finishTimeNs);
        self.note_aio_age_ms(completeAgeMs);

        let mut rc = 0;
        if finalState == SCE_KERNEL_AIO_STATE_ABORTED {
            rc = SCE_KERNEL_ERROR_ECANCELED;
        } else if finalState != SCE_KERNEL_AIO_STATE_COMPLETED {
            rc = SCE_KERNEL_ERROR_EIO;
        } else if active.result.returnValue < 0 {
            rc = apr_aio_result_to_sce(active.result.returnValue);
        }
        let shortRead = finalState == SCE_KERNEL_AIO_STATE_COMPLETED
            && active.result.returnValue >= 0
            && active.result.returnValue as u64 != active.desc.length;

        if apr_aio_api_rc_to_sce(deleteResult) != 0 {
            let timedOut = Self::record_aio_delete_failure(
                &mut active.aioDeleteRetries,
                &mut active.aioDeleteFirstFailureNs,
                finishTimeNs,
            );
            if timedOut {
                abort();
            }
            return true;
        }
        if job.is_null() || chain.is_null() {
            apr_release_aio_read_desc(&mut active.desc);
            Self::decrement_active_read_count(job);
            Self::decrement_read_chain_active(chain, active.readCreditBytes);
            self.maybe_finish_read_chain(chain);
            return false;
        }
        let jobRef = unsafe { &mut *job };
        let completionEfault = rc == SCE_KERNEL_ERROR_EFAULT;
        let completionRetryable = apr_aio_completion_sce_rc_is_retryable(rc);
        let nextCompletionRetry = if completionEfault || active.aioCompletionRetries == u32::MAX {
            active.aioCompletionRetries
        } else {
            active.aioCompletionRetries + 1
        };

        if rc == 0 {
            self.note_slow_aio_completion(finishTimeNs, completeAgeMs);
        }
        if rc == 0 && shortRead {
            self.set_or_defer_read_command_error(
                jobRef,
                c"aio-short-read".as_ptr(),
                SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET,
                errorOff,
                0,
            );
        }

        let efaultRetryLimitReached = completionEfault
            && active.ammEfaultRetries as u64 >= AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT as u64;
        let completionRetryLimitReached = completionRetryable
            && active.aioCompletionRetries as u64 >= AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT as u64;

        if rc != 0
            && !Self::job_failed(jobRef)
            && !Self::cross_eop_suffix_is_canceled(jobRef, errorOff)
            && (completionEfault || completionRetryable)
            && !efaultRetryLimitReached
            && !completionRetryLimitReached
        {
            let retryDelayNs = if completionEfault {
                AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_DELAY_NS
            } else {
                AMPR_EMU_APR_AIO_COMPLETION_RETRY_DELAY_NS
            };
            if completionEfault {
                self.note_efault_retry_event();
                if active.ammEfaultRetries != u32::MAX {
                    active.ammEfaultRetries += 1;
                }
            }
            active.aioCompletionRetries = nextCompletionRetry;
            self.mark_active_read_deferred(active);
            active.retryNotBeforeNs = finishTimeNs + retryDelayNs;
            active.submitTimeNs = 0;
            active.result = SceKernelAioResult::default();
            active.request.result = &mut active.result;
            active.hotPollQueued = false;
            self.remove_poll_deadline(active);
            // Keep the same ActiveRead slot, fd borrow, chain reference and
            // sequence. The worker resubmits it directly after retryAt.
            return true;
        }

        if rc != 0 && !Self::job_failed(jobRef) && completionRetryLimitReached {
            self.set_or_defer_read_command_error(
                jobRef,
                c"aio-completion-retry-limit".as_ptr(),
                apr_backend_read_error_to_apr(rc),
                errorOff,
                0,
            );
        }
        if rc != 0 && !Self::job_failed(jobRef) && efaultRetryLimitReached {
            self.note_efault_retry_limit_event();
            self.set_or_defer_read_command_error(
                jobRef,
                c"aio-efault-retry-limit".as_ptr(),
                apr_backend_read_error_to_apr(rc),
                errorOff,
                0,
            );
        }
        if rc != 0 && !Self::job_failed(jobRef) && !completionEfault && !completionRetryable {
            self.set_or_defer_read_command_error(
                jobRef,
                c"aio-completion-nonretryable".as_ptr(),
                apr_backend_read_error_to_apr(rc),
                errorOff,
                0,
            );
        }

        Self::decrement_active_read_count(job);
        Self::decrement_read_chain_active(chain, active.readCreditBytes);
        self.maybe_finish_read_chain(chain);
        apr_release_aio_read_desc(&mut active.desc);
        false
    }

    pub(crate) fn note_reactor_progress(&mut self, _progressed: bool) {}
}

impl AprAioReactor {
    pub(crate) fn refresh_native_batch_progress_snapshots(&mut self) {
        for laneIndex in 0..kPriorityCount as u32 {
            let lane = &mut self.nativeBatchLanes[laneIndex as usize];
            if lane.activeBuffer < 0 {
                continue;
            }
            let bufferIndex = lane.activeBuffer as u32;
            let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
            if slot.is_null()
                || lane.buffers[bufferIndex as usize].phase != NativeBatchPhase::Active
            {
                abort();
            }
            Self::sample_native_batch_progress(laneIndex, bufferIndex, lane, slot);
        }
    }

    pub(crate) fn progress_native_batches(&mut self) -> bool {
        let mut progressed = false;
        for laneIndex in 0..kPriorityCount as u32 {
            let li = laneIndex as usize;
            if self.nativeBatchLanes[li].activeBuffer < 0 {
                continue;
            }
            let bufferIndex = self.nativeBatchLanes[li].activeBuffer as u32;
            let bi = bufferIndex as usize;
            let slot = apr_native_batch_slot(li, bi);
            let state = self.nativeBatchLanes[li].buffers[bi];
            if slot.is_null() || state.phase != NativeBatchPhase::Active {
                abort();
            }
            if state.nextGroup == 0
                || state.nextGroup > kAprNativeBatchGroupCount
                || state.openGroupPackets != 0
                || state.packetCount == 0
                || state.packetCount > kAprNativeBatchPacketCount
            {
                abort();
            }
            // A partially populated backing buffer is parked on the next false
            // group gate; only a fully released buffer can become rollover-ready.
            if state.nextGroup != kAprNativeBatchGroupCount {
                continue;
            }

            let expectedProgress = apr_native_batch_token(kAprNativeBatchGroupCount - 1);
            if Self::native_batch_token_reached(state.observedProgress, expectedProgress) {
                // The final checkpoint is the last command in the buffer: wait
                // only retires the submit id and cannot block on a gate.
                let mut waitRcRaw: c_int = 0;
                let waitDispatchRc =
                    unsafe { apr_native_wait_dispatch(state.submitId, &mut waitRcRaw) };
                let waitRc = if waitDispatchRc != 0 {
                    waitDispatchRc
                } else {
                    apr_libkernel_rc_to_sce(waitRcRaw)
                };
                if waitRc != 0 || self.native_batch_result(slot) != 0 {
                    abort();
                }
                let lane = &mut self.nativeBatchLanes[li];
                let s = &mut lane.buffers[bi];
                s.submitId = 0;
                s.submitTimeNs = 0;
                s.lastReleaseTimeNs = 0;
                s.phase = NativeBatchPhase::Free;
                lane.activeBuffer = -1;
                progressed = true;

                let fillingIndex = bufferIndex ^ 1;
                let filling = lane.buffers[fillingIndex as usize];
                if filling.phase == NativeBatchPhase::Filling
                    && (filling.nextGroup == 0
                        || filling.openGroupPackets != 0
                        || !self.submit_native_batch_buffer(laneIndex, fillingIndex))
                {
                    abort();
                }
                continue;
            }

            let now = time_counter_now();
            let ageNs = if state.lastReleaseTimeNs != 0 && now >= state.lastReleaseTimeNs {
                now - state.lastReleaseTimeNs
            } else {
                0
            };
            if ageNs < kNativeCompletionTimeoutNs {
                continue;
            }
            let observedProgress = Self::sample_native_batch_progress(
                laneIndex,
                bufferIndex,
                &mut self.nativeBatchLanes[li],
                slot,
            );
            if Self::native_batch_token_reached(observedProgress, expectedProgress) {
                continue;
            }
            // Fatal without checkpoint, or rollover timeout: both abort.
            abort();
        }
        progressed
    }
}
