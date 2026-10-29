//! Effective read limits, fd pressure, admission context and active read poll gating.

use super::*;

const fn nonzero_or_one(v: u32) -> u32 {
    if v != 0 {
        v
    } else {
        1
    }
}

impl AprAioReactor {
    pub(crate) fn aio_effective_read_limit(
        &self,
        now: u64,
        snapshot: &AioAdmissionSnapshot,
    ) -> u32 {
        let baseLimit = Self::aio_active_read_limit();
        let level = self.aioAgeThrottleLevel;
        let capped = if level == AioAgeThrottleLevel::Emergency {
            Some(nonzero_or_one(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT))
        } else if level == AioAgeThrottleLevel::Severe {
            Some(nonzero_or_one(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT))
        } else if level == AioAgeThrottleLevel::Medium || self.slow_aio_cooldown_active(now) {
            Some(nonzero_or_one(AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT))
        } else {
            None
        };
        if let Some(l) = capped {
            return l.min(baseLimit);
        }
        if self.aio_small_read_boost_eligible(now, snapshot) {
            return Self::aio_small_read_limit();
        }
        baseLimit
    }

    pub(crate) fn begin_aio_admission_lane(context: &mut AioAdmissionContext) {
        context.laneNowValid = false;
        context.current = false;
    }

    pub(crate) fn aio_admission_lane_now(context: &mut AioAdmissionContext) -> u64 {
        if !context.laneNowValid {
            context.laneNowNs = time_counter_now();
            context.laneNowValid = true;
        }
        context.laneNowNs
    }

    pub(crate) fn prepare_aio_admission_context(
        &mut self,
        context: &mut AioAdmissionContext,
        now: u64,
    ) {
        if context.current {
            return;
        }
        if !context.initialized {
            context.snapshot = self.collect_aio_admission_snapshot(now);
            context.initialized = true;
        } else {
            Self::refresh_aio_snapshot_age(&mut context.snapshot, now);
        }
        self.update_aio_age_throttle(now, &context.snapshot);
        context.effectiveLimit = self.aio_effective_read_limit(now, &context.snapshot);
        context.fdPressure = self.fd_pressure_active(now);
        context.directFdCap = apr_adaptive_direct_fd_cap(
            &ampr_index_fd_pressure_current_caps(),
            Self::aio_direct_read_limit(context.effectiveLimit),
            context.fdPressure,
        );
        context.current = true;
    }

    pub(crate) fn apply_fd_pressure_event(&self, now: u64) {
        const kFdPressureCooldownNs: u64 = AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS * 1_000_000;
        let until = now + kFdPressureCooldownNs;
        if until > self.fdPressureUntilNs.get() {
            self.fdPressureUntilNs.set(until);
        }
        let cap = ampr_index_fd_pressure_current_caps().cache_cap;
        ampr_index_fd_cache_set_effective_cap(cap);
        self.fdCachePressureCapApplied.set(true);
        ampr_index_fd_cache_release_open_fd_headroom(0, cap);
    }

    pub(crate) fn sync_fd_cache_open_pressure(&self, now: u64) {
        let generation = ampr_index_fd_cache_open_pressure_generation();
        if generation == self.fdCacheOpenPressureSeen.get() {
            return;
        }
        self.fdCacheOpenPressureSeen.set(generation);
        self.apply_fd_pressure_event(now);
    }

    pub(crate) fn fd_pressure_active(&self, now: u64) -> bool {
        self.sync_fd_cache_open_pressure(now);
        let until = self.fdPressureUntilNs.get();
        if until == 0 {
            return false;
        }
        if now < until {
            return true;
        }
        self.fdPressureUntilNs.set(0);
        if self.fdCachePressureCapApplied.get() {
            ampr_index_fd_open_budget_set_effective_cap(kFdOpenBudgetBaseCap);
            ampr_index_fd_cache_set_effective_cap(AMPR_EMU_FD_CACHE_CAP);
            self.fdCachePressureCapApplied.set(false);
        }
        false
    }

    pub(crate) fn fd_budget_available_for_read(
        &self,
        rd: &AprAioReadDesc,
        directFdCap: usize,
    ) -> bool {
        // Cache hits and cached-open headroom are decided atomically by
        // ampr_index_acquire_cached_fd under the fd-cache lock.
        if rd.fd >= 0 || !rd.bypassFdCache {
            return true;
        }
        let caps = ampr_index_fd_pressure_current_caps();
        let directOpen = ampr_index_fd_direct_open_count();
        if directFdCap != 0 && directOpen + 1 > directFdCap {
            return false;
        }
        let reserve = (1 + AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE).min(caps.fd_budget);
        unsafe {
            ampr_index_fd_common_open_budget_headroom_available(
                reserve,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        }
    }

    pub(crate) fn active_read_age_ns(active: &ActiveRead, now: u64) -> u64 {
        if active.submitTimeNs != 0 && now >= active.submitTimeNs {
            now - active.submitTimeNs
        } else {
            0
        }
    }
}

impl AprAioReactor {
    // Force an immediate observation only when an already-submitted read has
    // just become publication-gating. Fresh submissions use a delayed first
    // poll so millisecond-scale AIO is not queried every few microseconds.
    pub(crate) fn reset_active_read_poll_backoff(&mut self, active: &mut ActiveRead, now: u64) {
        let oldDeadlineNs = active.nextPollTimeNs;
        active.nextPollTimeNs = now;
        active.pollBackoffNs = 0;
        self.update_poll_deadline(active, oldDeadlineNs);
    }

    pub(crate) fn queue_hot_active_read_poll(&mut self, active: &mut ActiveRead) {
        if active.hotPollQueued
            || active.listSlot == u32::MAX
            || self.hotPollQueueCount >= kHotPollQueueCapacity
        {
            return;
        }
        self.hotPollQueue[self.hotPollQueueTail as usize] = ActiveReadRef {
            slot: active.listSlot,
            generation: active.listGeneration,
        };
        self.hotPollQueueTail = (self.hotPollQueueTail + 1) % kHotPollQueueCapacity;
        self.hotPollQueueCount += 1;
        active.hotPollQueued = true;
    }

    /// Deferred and not-yet-submitted reads own no SDK AIO id; their submit
    /// path arms the poll and promotes them then if still publication-gating.
    pub(crate) fn reset_and_queue_hot_active_read_poll(
        &mut self,
        active: &mut ActiveRead,
        now: u64,
    ) {
        if !Self::active_read_is_submitted(active) {
            return;
        }
        self.reset_active_read_poll_backoff(active, now);
        self.queue_hot_active_read_poll(active);
    }

    pub(crate) fn pop_hot_active_read_poll(&mut self) -> ActiveReadIt {
        while self.hotPollQueueCount != 0 {
            let entry = self.hotPollQueue[self.hotPollQueueHead as usize];
            self.hotPollQueueHead = (self.hotPollQueueHead + 1) % kHotPollQueueCapacity;
            self.hotPollQueueCount -= 1;
            let ap = self
                .activeReads
                .active_at_slot_2(entry.slot, entry.generation);
            if ap.is_null() || unsafe { !(*ap).hotPollQueued } {
                continue;
            }
            let active = unsafe { &mut *ap };
            active.hotPollQueued = false;
            // A queued read may have left the submitted state (e.g. a bounded
            // resubmit); drop the stale entry and its old deadline.
            if !Self::active_read_is_submitted(active) {
                self.remove_poll_deadline(active);
                continue;
            }
            return self.activeReads.iterator_from_slot(entry.slot);
        }
        self.activeReads.end()
    }

    pub(crate) fn active_read_is_completion_frontier(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        !job.is_null()
            && unsafe { !Self::job_failed(&*job) && active.seq == (*job).completedReadSeq + 1 }
    }

    pub(crate) fn active_read_is_latest_submitted_tail(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        !job.is_null()
            && unsafe {
                !Self::job_failed(&*job)
                    && (*job).latestSubmittedReadSeq != 0
                    && active.seq == (*job).latestSubmittedReadSeq
            }
    }

    pub(crate) fn active_read_is_native_release_gate(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        !job.is_null()
            && unsafe {
                !Self::job_failed(&*job)
                    && (*job).nativeBatchReleasePending
                    && (*job).nativeBatchReleaseReadSequence != 0
                    && active.seq == (*job).nativeBatchReleaseReadSequence
            }
    }

    /// Staged-EOP class: only reads that can unblock the currently closed
    /// native gate (owner job bounded by the captured EOP read sequence, or
    /// earlier FIFO jobs that reached the end of their source).
    pub(crate) fn active_read_is_staged_eop_gate(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        if job.is_null() {
            return false;
        }
        let job = unsafe { &*job };
        if Self::job_failed(job) || job.prioIndex >= kPriorityCount {
            return false;
        }
        let lane = &self.nativeBatchLanes[job.prioIndex as usize];
        if lane.deferredReleaseSequence == 0 {
            return false;
        }
        if job.id == lane.deferredReleaseJobId {
            return job.nativeBatchReleasePending
                && job.nativeBatchReleaseReadSequence != 0
                && active.seq <= job.nativeBatchReleaseReadSequence
                && (self.active_read_is_completion_frontier(active)
                    || self.active_read_is_native_release_gate(active));
        }
        if job.sourceOffset == job.sourceBytes {
            return self.active_read_can_gate_publish(active);
        }
        false
    }

    pub(crate) fn active_read_can_gate_publish(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        if job.is_null() || unsafe { Self::job_failed(&*job) } {
            return false;
        }
        let mode = unsafe { (*job).submitMode };
        mode == AprSubmitMode::kSubmitAndGetResult
            || self.active_read_is_completion_frontier(active)
            || self.active_read_is_latest_submitted_tail(active)
            || self.active_read_is_native_release_gate(active)
    }

    /// Deliberately ignores latestSubmittedReadSeq: every fresh read is the
    /// provisional tail, which would make the whole workload immediate-poll.
    pub(crate) fn active_read_needs_immediate_submit_poll(&self, active: &ActiveRead) -> bool {
        let job = active.job;
        if job.is_null() || unsafe { Self::job_failed(&*job) } {
            return false;
        }
        let mode = unsafe { (*job).submitMode };
        mode == AprSubmitMode::kSubmitAndGetResult
            || self.active_read_is_completion_frontier(active)
            || self.active_read_is_native_release_gate(active)
    }

    pub(crate) fn active_lane_idle_sleep_ns() -> u32 {
        AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS as u32
    }
}

impl AprAioReactor {
    pub(crate) fn reset_completion_frontier_active_aio_poll_for_job(
        &mut self,
        job: &mut JobState,
        now: u64,
    ) {
        let jp: JobPtr = job;
        let targetSeq = job.completedReadSeq + 1;
        let mut slot = job.activeReadHead;
        let mut chainBroken = false;
        let mut scanned = 0u32;
        while slot != u32::MAX && scanned < kMaxActiveReads {
            let ap = self.activeReads.active_at_slot(slot);
            if ap.is_null() || unsafe { (*ap).job } != jp {
                chainBroken = true;
                break;
            }
            let active = unsafe { &mut *ap };
            let nextSlot = active.jobNextSlot;
            if active.seq == targetSeq {
                self.reset_and_queue_hot_active_read_poll(active, now);
                return;
            }
            slot = nextSlot;
            scanned += 1;
        }
        if !chainBroken && slot == u32::MAX {
            return;
        }
        let mut it = self.activeReads.begin();
        let end = self.activeReads.end();
        while it != end {
            let active = unsafe { it.get() };
            if active.job == jp && active.seq == targetSeq {
                self.reset_and_queue_hot_active_read_poll(active, now);
                return;
            }
            it.inc();
        }
    }

    pub(crate) fn reset_publish_gating_active_aio_poll_backoff_for_lane(
        &mut self,
        laneIndex: u32,
        now: u64,
    ) {
        if laneIndex >= kPriorityCount as u32 {
            return;
        }
        let mut it = self.activeReads.begin();
        let end = self.activeReads.end();
        while it != end {
            let active = unsafe { it.get() };
            if !active.job.is_null()
                && unsafe { (*active.job).prioIndex } as u32 == laneIndex
                && self.active_read_is_staged_eop_gate(active)
            {
                self.reset_and_queue_hot_active_read_poll(active, now);
            }
            it.inc();
        }
    }

    pub(crate) fn active_read_max_poll_backoff_ns(&self, active: &ActiveRead, now: u64) -> u32 {
        // Explicit native release/EOP gates stay on the tightest policy.
        if self.active_read_is_staged_eop_gate(active)
            || self.active_read_is_native_release_gate(active)
        {
            return AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS;
        }
        if self.active_read_can_gate_publish(active) {
            // SubmitAndGetResult callers wait synchronously: never relax by age.
            if !active.job.is_null()
                && unsafe { (*active.job).submitMode } == AprSubmitMode::kSubmitAndGetResult
            {
                return AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS;
            }
            // Still publication-critical; only the syscall cadence relaxes
            // once the SDK AIO is clearly outside the normal window.
            let ageNs = Self::active_read_age_ns(active, now);
            if ageNs >= AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS {
                return AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS;
            }
            if ageNs >= AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS {
                return AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS;
            }
            return AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS;
        }
        if self.submittedActiveReadCount >= kAioPollPressureThreshold {
            return AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS;
        }
        if Self::active_read_age_ns(active, now) >= AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS {
            return AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS;
        }
        AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS
    }

    /// Background first-poll delay: 250/250/250/400 us for <=16/64/256/>256 KiB.
    pub(crate) fn initial_background_read_poll_delay_ns(&self, active: &ActiveRead) -> u32 {
        let mut delayNs = AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS as u64;
        let len = active.desc.length;
        if len > 0x4000 {
            delayNs *= 2;
        }
        if len > 0x10000 {
            delayNs *= 2;
        }
        if len > 0x40000 {
            delayNs *= 2;
        }
        delayNs = delayNs.max(AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS as u64);
        let capNs = if self.submittedActiveReadCount >= kAioPollPressureThreshold {
            AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS
        } else {
            AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS
        };
        delayNs.min(capNs as u64) as u32
    }
}
