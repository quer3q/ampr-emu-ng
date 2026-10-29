//! Poll backoff scheduling, reactor wake, read credits, job errors/results and read chains.

use super::*;

impl AprAioReactor {
    pub(crate) fn initial_active_read_poll_delay_ns(&self, active: &ActiveRead) -> u32 {
        if self.active_read_can_gate_publish(active) {
            return AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS;
        }
        self.initial_background_read_poll_delay_ns(active)
    }

    pub(crate) fn arm_active_read_poll_after_submit(&mut self, active: &mut ActiveRead, now: u64) {
        if self.active_read_needs_immediate_submit_poll(active) {
            self.reset_and_queue_hot_active_read_poll(active, now);
            return;
        }
        let oldDeadlineNs = active.nextPollTimeNs;
        let initialDelayNs = self.initial_background_read_poll_delay_ns(active);
        active.pollBackoffNs = initialDelayNs;
        active.nextPollTimeNs = now + initialDelayNs as u64;
        self.update_poll_deadline(active, oldDeadlineNs);
    }

    pub(crate) fn next_active_read_poll_backoff_ns(&self, active: &ActiveRead, now: u64) -> u32 {
        let maxBackoffNs = self.active_read_max_poll_backoff_ns(active, now);
        let mut backoffNs = active.pollBackoffNs;
        if backoffNs == 0 {
            backoffNs = self.initial_active_read_poll_delay_ns(active);
        } else if backoffNs < maxBackoffNs {
            backoffNs = if backoffNs <= maxBackoffNs / 2 {
                backoffNs * 2
            } else {
                maxBackoffNs
            };
        }
        backoffNs.min(maxBackoffNs)
    }

    pub(crate) fn schedule_next_active_read_poll(&mut self, active: &mut ActiveRead, now: u64) {
        let oldDeadlineNs = active.nextPollTimeNs;
        let backoffNs = self.next_active_read_poll_backoff_ns(active, now);
        active.pollBackoffNs = backoffNs;
        active.nextPollTimeNs = now + backoffNs as u64;
        self.update_poll_deadline(active, oldDeadlineNs);
    }

    pub(crate) fn next_aio_poll_wait_ns(&self, now: u64) -> u64 {
        let mut deadlineNs = self.active_poll_deadline_ns();
        for external in &self.externalAioReads {
            if !external.published.load(Ordering::Acquire)
                || external.state != ExternalAioState::Submitted
                || external.preadBacked
            {
                continue;
            }
            if external.nextPollTimeNs == 0 || external.nextPollTimeNs <= now {
                return 0;
            }
            if deadlineNs == 0 || external.nextPollTimeNs < deadlineNs {
                deadlineNs = external.nextPollTimeNs;
            }
        }
        if deadlineNs != 0 && deadlineNs > now {
            deadlineNs - now
        } else {
            0
        }
    }

    pub(crate) fn wait_for_reactor_wake(&self, observedEpoch: u64, timeoutNs: u64) {
        if timeoutNs == 0 {
            return;
        }
        let mut lk = self.m.lock();
        if self.stop || self.reactorWakeEpoch.load(Ordering::Acquire) != observedEpoch {
            return;
        }
        if timeoutNs == u64::MAX {
            self.reactorCv.wait(&mut lk);
        } else {
            self.reactorCv
                .wait_for_us(&mut lk, timeoutNs.div_ceil(1000));
        }
    }

    pub(crate) fn increment_active_read_count(job: JobPtr) {
        let Some(job) = (unsafe { job.as_mut() }) else {
            return;
        };
        if job.activeReadCount == u32::MAX {
            abort();
        }
        job.activeReadCount += 1;
    }

    pub(crate) fn decrement_active_read_count(job: JobPtr) {
        let Some(job) = (unsafe { job.as_mut() }) else {
            return;
        };
        if job.activeReadCount == 0 {
            abort();
        }
        job.activeReadCount -= 1;
    }

    pub(crate) const fn read_credit_bytes(requestBytes: u64) -> u64 {
        let granule = AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES;
        if requestBytes == 0 {
            return 0;
        }
        let remainder = requestBytes & (granule - 1);
        if remainder == 0 {
            requestBytes
        } else {
            requestBytes + (granule - remainder)
        }
    }

    pub(crate) fn increment_read_chain_active(chain: *mut ReadChain, bytes: u64) {
        let Some(chain) = (unsafe { chain.as_mut() }) else {
            return;
        };
        if chain.activeCount == u32::MAX || chain.activeBytes > u64::MAX - bytes {
            abort();
        }
        chain.activeCount += 1;
        chain.activeBytes += bytes;
    }

    pub(crate) fn decrement_read_chain_active(chain: *mut ReadChain, bytes: u64) {
        let Some(chain) = (unsafe { chain.as_mut() }) else {
            return;
        };
        if chain.activeCount == 0 || chain.activeBytes < bytes {
            abort();
        }
        chain.activeCount -= 1;
        chain.activeBytes -= bytes;
    }

    pub(crate) fn abandon_unsubmitted_read_chain(&mut self, slot: &mut *mut ReadChain) {
        let chain = *slot;
        *slot = null_mut();
        if !self.read_chain_is_live(chain) {
            return;
        }
        unsafe { (*chain).allIssued = true };
        self.maybe_finish_read_chain(chain);
    }

    pub(crate) fn abandon_job_cursor_read_chains(&mut self, job: &mut JobState) {
        self.abandon_unsubmitted_read_chain(&mut job.cursorReadChain);
    }

    pub(crate) fn set_fail(
        &mut self,
        job: &mut JobState,
        _reason: *const c_char,
        rc: c_int,
        errorOffset: u32,
        _backendRc: c_int,
    ) {
        if job.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        job.result.rc = if rc != 0 { rc } else { SCE_KERNEL_ERROR_EIO };
        job.result.errorOffset = errorOffset;
        self.clear_cursor_read_wait_hint(job.prioIndex as usize);
        Self::finish_job_processing(job);
        self.abandon_job_cursor_read_chains(job);
    }
}

impl AprAioReactor {
    pub(crate) fn set_command_error(
        &mut self,
        job: &mut JobState,
        reason: *const c_char,
        rc: c_int,
        errorOffset: u32,
        backendRc: c_int,
    ) {
        if Self::job_failed(job) || job.hasCommandError {
            return;
        }
        job.hasCommandError = true;
        self.set_fail(job, reason, rc, errorOffset, backendRc);
    }

    pub(crate) fn set_or_defer_read_command_error(
        &mut self,
        job: &mut JobState,
        reason: *const c_char,
        rc: c_int,
        errorOffset: u32,
        backendRc: c_int,
    ) -> bool {
        self.set_command_error(job, reason, rc, errorOffset, backendRc);
        false
    }

    pub(crate) fn publish_deferred_cross_eop_error(&mut self, _job: &mut JobState) -> bool {
        false
    }

    pub(crate) fn cross_eop_suffix_is_canceled(_job: &JobState, _sourceOffset: u32) -> bool {
        false
    }

    pub(crate) fn publish_job_result(&self, job: &mut JobState) {
        if job.aprRes.is_null() {
            return;
        }
        let failed = Self::job_failed(job);
        let result = if failed { job.result.rc } else { 0 };
        let errorOffset = if failed { job.result.errorOffset } else { 0 };
        unsafe {
            ptr::write_volatile(addr_of_mut!((*job.aprRes).result), result);
            ptr::write_volatile(addr_of_mut!((*job.aprRes).error_offset), errorOffset);
        }
        fence(Ordering::SeqCst);
    }

    pub(crate) fn read_completion_word_index(seq: u64) -> usize {
        (((seq - 1) % kReadCompletionRingBits) / 64) as usize
    }

    pub(crate) fn read_completion_word_mask(seq: u64) -> u64 {
        1u64 << (((seq - 1) % kReadCompletionRingBits) & 63)
    }

    pub(crate) fn mark_seq_complete(&mut self, job: &mut JobState, seq: u64) {
        let nextSeq = job.completedReadSeq + 1;
        if seq < nextSeq {
            return;
        }
        if seq == nextSeq {
            job.completedReadSeq = seq;
            loop {
                let nextCompleted = job.completedReadSeq + 1;
                let wordIndex = Self::read_completion_word_index(nextCompleted);
                let mask = Self::read_completion_word_mask(nextCompleted);
                if job.completedOutOfOrderWords[wordIndex] & mask == 0 {
                    break;
                }
                job.completedOutOfOrderWords[wordIndex] &= !mask;
                job.completedReadSeq += 1;
            }
        } else {
            if seq - job.completedReadSeq > kReadCompletionRingBits {
                let off = job.sourceOffset;
                self.set_command_error(
                    job,
                    c"read-completion-window".as_ptr(),
                    SCE_KERNEL_ERROR_EBUSY,
                    off,
                    0,
                );
                return;
            }
            job.completedOutOfOrderWords[Self::read_completion_word_index(seq)] |=
                Self::read_completion_word_mask(seq);
        }
    }

    pub(crate) fn read_chain_next_desc(chain: &ReadChain) -> AprAioReadDesc {
        let mut desc = chain.ownerDesc;
        desc.fd = -1;
        desc.cachePinned = false;
        desc.borrowedFd = false;
        desc.buffer = chain.nextBuffer;
        desc.offset = chain.nextOffset;
        desc.length = chain.remaining.min(kSoftwareReadChunkMax);
        desc
    }

    pub(crate) fn borrow_read_chain_fd(chain: &mut ReadChain, desc: &mut AprAioReadDesc) {
        desc.fd = chain.ownerDesc.fd;
        desc.bypassFdCache = chain.ownerDesc.bypassFdCache;
        desc.closeAfter = chain.ownerDesc.closeAfter;
        desc.closeAfterPhysical = chain.ownerDesc.closeAfterPhysical;
        desc.cachePinned = chain.ownerDesc.cachePinned;
        desc.borrowedFd = desc.fd >= 0;
    }

    pub(crate) fn maybe_finish_read_chain(&mut self, chain: *mut ReadChain) {
        // A repeated finish attempt on a retired chain is a no-op.
        if !self.read_chain_is_live(chain) {
            return;
        }
        let c = unsafe { &mut *chain };
        if c.activeCount != 0 || c.activeBytes != 0 {
            return;
        }
        let job = c.job;
        let jobLive = !job.is_null() && !Self::job_failed(unsafe { &*job });
        if jobLive && !c.allIssued {
            return;
        }
        let seq = c.seq;
        apr_release_aio_read_desc(&mut c.ownerDesc);
        if jobLive && seq != 0 {
            self.mark_seq_complete(unsafe { &mut *job }, seq);
        }
        self.release_read_chain_storage(chain);
    }
}

impl AprAioReactor {
    pub(crate) fn clear_cursor_read_wait_hint(&mut self, priority: usize) {
        if priority < kPriorityCount as usize {
            self.cursorReadWaitHints[priority] = CursorReadWaitHint::default();
        }
    }

    pub(crate) fn set_cursor_read_wait_hint(&mut self, priority: usize) {
        if priority < kPriorityCount as usize {
            self.cursorReadWaitHints[priority] = CursorReadWaitHint { valid: true };
        }
    }

    pub(crate) fn effective_read_class(
        &self,
        _job: *const JobState,
        desc: &AprAioReadDesc,
    ) -> AmprLooseReadClass {
        desc.readClass
    }

    pub(crate) fn latency_read_waiting_at_equal_or_higher_priority(&self, _priority: u8) -> bool {
        false
    }

    pub(crate) fn read_group_for_priority(priority: u8) -> A53ReadGroup {
        match priority {
            0 => A53ReadGroup::Urgent,
            1..=3 => A53ReadGroup::High,
            _ => A53ReadGroup::Normal,
        }
    }

    pub(crate) fn read_group_index(group: A53ReadGroup) -> usize {
        group as usize
    }
}
