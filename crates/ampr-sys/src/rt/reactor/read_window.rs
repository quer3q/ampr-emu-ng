//! Read group targets, adaptive read window, staged admission and AIO submit rounds.

use super::*;

impl DirectReadSubmitOutcome {
    pub(crate) fn has_error(&self) -> bool {
        !self.errorReason.is_null()
    }
}

impl AprAioReactor {
    pub(crate) fn group_has_waiting_cursor(&self, group: A53ReadGroup) -> bool {
        (0..kPriorityCount).any(|p| {
            self.cursorReadWaitHints[p as usize].valid && Self::read_group_for_priority(p) == group
        })
    }

    pub(crate) fn scaled_group_target(limit: u32, numerator: u32) -> u32 {
        (limit.wrapping_mul(numerator).wrapping_add(16)) / 32
    }

    pub(crate) fn read_group_targets(
        &self,
        limit: u32,
        active: &A53ReadGroupCounts,
    ) -> A53ReadGroupCounts {
        let mut targets = A53ReadGroupCounts::default();
        if limit == 0 {
            return targets;
        }
        let u = Self::read_group_index(A53ReadGroup::Urgent);
        let h = Self::read_group_index(A53ReadGroup::High);
        let n = Self::read_group_index(A53ReadGroup::Normal);
        let urgentDemand =
            active.values[u] != 0 || self.group_has_waiting_cursor(A53ReadGroup::Urgent);
        if !urgentDemand {
            let mut high = Self::scaled_group_target(limit, 20);
            high = if limit > 1 {
                high.min(limit - 1).max(1)
            } else {
                limit
            };
            targets.values[h] = high;
            targets.values[n] = limit - high;
            return targets;
        }
        let mut urgent = Self::scaled_group_target(limit, 4);
        let mut high = Self::scaled_group_target(limit, 18);
        if limit >= 3 {
            urgent = urgent.max(1);
            high = high.max(1);
            if urgent + high >= limit {
                high = limit - urgent - 1;
            }
            targets.values[u] = urgent;
            targets.values[h] = high;
            targets.values[n] = limit - urgent - high;
        } else {
            targets.values[u] = 1;
            targets.values[h] = if limit > 1 { 1 } else { 0 };
            targets.values[n] = 0;
        }
        targets
    }

    pub(crate) fn group_soft_target_available(
        &self,
        priority: u8,
        effectiveLimit: u32,
        snapshot: &AioAdmissionSnapshot,
    ) -> bool {
        if !AMPR_EMU_APR_GROUP_SOFT_TARGETS || effectiveLimit <= 1 {
            return true;
        }
        let active = A53ReadGroupCounts {
            values: snapshot.groupActive,
        };
        let targets = self.read_group_targets(effectiveLimit, &active);
        let requestedIndex = Self::read_group_index(Self::read_group_for_priority(priority));
        if active.values[requestedIndex] < targets.values[requestedIndex] {
            return true;
        }
        // Stop borrowing once another group has a cursor waiting below its target.
        for (index, group) in [
            A53ReadGroup::Urgent,
            A53ReadGroup::High,
            A53ReadGroup::Normal,
        ]
        .into_iter()
        .enumerate()
        {
            if index == requestedIndex
                || targets.values[index] == 0
                || active.values[index] >= targets.values[index]
            {
                continue;
            }
            if self.group_has_waiting_cursor(group) {
                return false;
            }
        }
        true
    }

    pub(crate) const fn adaptive_read_hard_chunk_limit() -> u32 {
        AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS
    }

    pub(crate) fn another_priority_has_waiting_read(
        &self,
        priority: u8,
        laneDemandMask: u8,
    ) -> bool {
        (0..kPriorityCount).any(|other| {
            other != priority
                && laneDemandMask & (1u8 << other) != 0
                && self.cursorReadWaitHints[other as usize].valid
        })
    }

    pub(crate) fn adaptive_read_window(
        &self,
        priority: u8,
        readClass: AmprLooseReadClass,
        context: &AioAdmissionContext,
    ) -> AdaptiveReadWindow {
        let pressure = context.fdPressure
            || self.aioAgeThrottleLevel != AioAgeThrottleLevel::Normal
            || self.slow_aio_cooldown_active(context.laneNowNs)
            || context.effectiveLimit < Self::aio_active_read_limit();
        let latencyDemand = self.latency_read_waiting_at_equal_or_higher_priority(priority);
        let mut window = AdaptiveReadWindow::default();
        let mut constrained = pressure || readClass == AmprLooseReadClass::Latency;
        let mut shared = false;
        if pressure {
            window.mode = AdaptiveReadWindowMode::Pressure;
        } else if readClass == AmprLooseReadClass::Latency || latencyDemand {
            window.mode = AdaptiveReadWindowMode::Contended;
        } else if self.another_priority_has_waiting_read(priority, context.laneDemandMask) {
            window.mode = AdaptiveReadWindowMode::Contended;
            constrained = true;
        } else {
            let mut otherLaneMask = context.laneDemandMask;
            if priority < kPriorityCount {
                otherLaneMask &= !(1u8 << priority);
            }
            let aged =
                context.snapshot.oldestSubmittedAgeMs > AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS;
            shared = otherLaneMask != 0 || aged || latencyDemand;
            window.mode = if shared {
                AdaptiveReadWindowMode::Shared
            } else {
                AdaptiveReadWindowMode::Exclusive
            };
        }
        window.chunks = ampr_loose_chain_chunk_limit(
            readClass,
            latencyDemand,
            constrained,
            shared,
            Self::adaptive_read_hard_chunk_limit(),
        );
        window.bytes = (window.chunks as u64 * Self::read_credit_bytes(kSoftwareReadChunkMax))
            .min(AMPR_EMU_APR_PER_READ_ACTIVE_BYTES);
        window
    }

    pub(crate) fn note_adaptive_read_window_staged(&mut self, _mode: AdaptiveReadWindowMode) {}

    pub(crate) fn note_adaptive_read_window_blocked(&mut self, _mode: AdaptiveReadWindowMode) {}
}

impl AprAioReactor {
    pub(crate) fn reserve_staged_aio_admission(
        &mut self,
        context: &mut AioAdmissionContext,
        active: &ActiveRead,
        stageTimeNs: u64,
    ) {
        if !context.initialized || !context.current {
            abort();
        }
        if !active.nativeCapacityCharged {
            return;
        }
        context.snapshot.activeCount += 1;
        let classIndex = active.desc.readClass as usize;
        if classIndex < AmprLooseReadClass::Count as usize {
            context.snapshot.classActive[classIndex] += 1;
        }
        if Self::aio_desc_is_small_for_boost(&active.desc) {
            context.snapshot.smallCount += 1;
        }
        if !active.job.is_null() {
            let prio = unsafe { (*active.job).prioIndex };
            if prio < kPriorityCount {
                context.snapshot.groupActive
                    [Self::read_group_index(Self::read_group_for_priority(prio))] += 1;
            }
        }
        if stageTimeNs != 0
            && (context.snapshot.oldestSubmittedTimeNs == 0
                || stageTimeNs < context.snapshot.oldestSubmittedTimeNs)
        {
            context.snapshot.oldestSubmittedTimeNs = stageTimeNs;
        }
        context.laneNowNs = stageTimeNs;
        context.laneNowValid = true;
        Self::refresh_aio_snapshot_age(&mut context.snapshot, stageTimeNs);
        self.update_aio_age_throttle(stageTimeNs, &context.snapshot);
        context.effectiveLimit = self.aio_effective_read_limit(stageTimeNs, &context.snapshot);
    }

    pub(crate) fn direct_read_admission_available(
        &mut self,
        priority: u8,
        readClass: AmprLooseReadClass,
        ownerDesc: &AprAioReadDesc,
        sliceDesc: &AprAioReadDesc,
        nowNs: u64,
        context: &mut AioAdmissionContext,
    ) -> bool {
        self.prepare_aio_admission_context(context, nowNs);
        let limit =
            self.aio_direct_read_admission_limit(priority, readClass, sliceDesc, nowNs, context);
        let activeCount = context.snapshot.activeCount;
        // Virtual pack parents still occupy ActiveRead storage; keep storage
        // admission independent from the native-capacity snapshot.
        if self.activeReads.size() >= kMaxActiveReads as usize || activeCount >= limit as usize {
            // Completed-but-unpolled slots stay unavailable; the next pass may
            // run a bounded capacity probe.
            self.passReadBlockedOnAioCapacity = true;
            return false;
        }
        if !self.group_soft_target_available(priority, limit, &context.snapshot) {
            return false;
        }
        // Slots above the normal window are exclusively for small SDK reads.
        if activeCount >= Self::aio_active_read_limit() as usize
            && !Self::aio_desc_is_small_for_boost(sliceDesc)
        {
            return false;
        }
        if !self.fd_budget_available_for_read(ownerDesc, context.directFdCap) {
            self.passReadBlockedOnFdBudget = true;
            return false;
        }
        true
    }

    pub(crate) fn aio_submit_batch_index(aioPriority: c_int) -> usize {
        match aioPriority {
            SCE_KERNEL_AIO_PRIORITY_HIGH => 0,
            SCE_KERNEL_AIO_PRIORITY_MID => 1,
            SCE_KERNEL_AIO_PRIORITY_LOW => 2,
            _ => abort(),
        }
    }

    pub(crate) fn begin_aio_submit_round(&mut self) {
        let round = &mut self.aioSubmitRound;
        if round.groupedExternal.iter().any(|b| b.count != 0)
            || round.batches.iter().any(|b| b.count != 0)
        {
            abort();
        }
        let prios = [
            SCE_KERNEL_AIO_PRIORITY_HIGH,
            SCE_KERNEL_AIO_PRIORITY_MID,
            SCE_KERNEL_AIO_PRIORITY_LOW,
        ];
        for (i, p) in prios.into_iter().enumerate() {
            round.batches[i].aioPriority = p;
            round.groupedExternal[i].aioPriority = p;
        }
    }

    pub(crate) fn stage_aio_submit(&mut self, active: &mut ActiveRead, resubmit: bool) {
        let batch = &mut self.aioSubmitRound.batches[Self::aio_submit_batch_index(active.aioPrio)];
        if batch.count >= SCE_KERNEL_AIO_REQUEST_NUM_MAX
            || active.aioId >= 0
            || active.awaitingBatchSubmit
            || resubmit != active.awaitingResubmit
        {
            abort();
        }
        let item = batch.count;
        batch.count += 1;
        batch.requests[item] = active.request;
        batch.ids[item] = -1;
        batch.items[item].active = ActiveReadRef {
            slot: active.listSlot,
            generation: active.listGeneration,
        };
        batch.items[item].isExternal = false;
        active.awaitingBatchSubmit = true;
    }

    pub(crate) fn external_aio_group_index(priority: c_int) -> usize {
        match priority {
            SCE_KERNEL_AIO_PRIORITY_HIGH => 0,
            SCE_KERNEL_AIO_PRIORITY_MID => 1,
            _ => 2,
        }
    }

    /// Null when the ref is stale or the slot is free.
    pub(crate) fn external_aio_at(&mut self, r: &ExternalAioRef) -> *mut ExternalAioRead {
        if r.slot >= kExternalAioCapacity {
            return null_mut();
        }
        let slot = &mut self.externalAioReads[r.slot as usize];
        if slot.published.load(Ordering::Acquire)
            && slot.state != ExternalAioState::Free
            && slot.generation == r.generation
        {
            slot
        } else {
            null_mut()
        }
    }

    pub(crate) fn release_external_aio_slot(external: &mut ExternalAioRead) {
        let generation = external.generation;
        for i in 0..kAprExternalAioGroupMaxRequests {
            external.requests[i] = SceKernelAioRWRequest::default();
            external.deleteRetries[i] = 0;
            external.deleteFirstFailureNs[i] = 0;
            external.aioIds[i] = -1;
        }
        external.context = null_mut();
        external.callback = None;
        external.submitTimeNs = 0;
        external.retryNotBeforeNs = 0;
        external.nextPollTimeNs = 0;
        external.pollBackoffNs = 0;
        external.requestCount = 0;
        external.remainingCount = 0;
        external.totalBytes = 0;
        external.completionState = SCE_KERNEL_AIO_STATE_COMPLETED;
        external.aioPriority = SCE_KERNEL_AIO_PRIORITY_MID;
        external.grouped = false;
        external.preadBacked = false;
        external.state = ExternalAioState::Free;
        external.generation = generation;
        external.published.store(false, Ordering::Release);
    }
}
