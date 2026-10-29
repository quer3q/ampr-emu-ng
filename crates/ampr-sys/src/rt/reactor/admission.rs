//! External AIO admission/staging, submit-id checks and accepting submitted AIO items.

use super::*;

impl AprAioReactor {
    pub(crate) fn reserve_external_aio_admission(
        &mut self,
        admission: &mut AioAdmissionContext,
        external: &ExternalAioRead,
        nowNs: u64,
    ) {
        let n = external.requestCount;
        admission.snapshot.activeCount += n as usize;
        if Self::external_aio_is_small_for_boost(external) {
            admission.snapshot.smallCount += n as usize;
        }
        admission.snapshot.groupActive[Self::external_aio_group_index(external.aioPriority)] += n;
        admission.laneNowNs = nowNs;
        admission.laneNowValid = true;
        Self::refresh_aio_snapshot_age(&mut admission.snapshot, nowNs);
        self.update_aio_age_throttle(nowNs, &admission.snapshot);
        admission.effectiveLimit = self.aio_effective_read_limit(nowNs, &admission.snapshot);
    }

    pub(crate) fn rollback_external_aio_admission(
        &self,
        admission: &mut AioAdmissionContext,
        external: &ExternalAioRead,
    ) {
        let group = Self::external_aio_group_index(external.aioPriority);
        let n = external.requestCount;
        let s = &mut admission.snapshot;
        if s.activeCount < n as usize || s.groupActive[group] < n {
            abort();
        }
        s.activeCount -= n as usize;
        if Self::external_aio_is_small_for_boost(external) {
            if s.smallCount < n as usize {
                abort();
            }
            s.smallCount -= n as usize;
        }
        s.groupActive[group] -= n;
    }

    pub(crate) fn stage_external_aio_submits(
        &mut self,
        admission: &mut AioAdmissionContext,
        preserveLaneShare: bool,
    ) -> bool {
        let mut staged = false;
        let nowNs = time_counter_now();
        self.prepare_aio_admission_context(admission, nowNs);
        let mut priority = SCE_KERNEL_AIO_PRIORITY_HIGH;
        while priority >= SCE_KERNEL_AIO_PRIORITY_LOW {
            let bi = Self::aio_submit_batch_index(priority);
            for slotIndex in 0..kExternalAioCapacity {
                // Raw pointer: `external` lives in `self` while `self` methods run.
                let external =
                    unsafe { &mut *addr_of_mut!(self.externalAioReads[slotIndex as usize]) };
                if !external.published.load(Ordering::Acquire) {
                    continue;
                }
                let deferred = external.state == ExternalAioState::Deferred;
                if (external.state != ExternalAioState::Pending && !deferred)
                    || external.aioPriority != priority
                    || (deferred
                        && external.retryNotBeforeNs != 0
                        && nowNs < external.retryNotBeforeNs)
                {
                    continue;
                }
                // Pread pool (pread_pool.rs): no kernel AIO admission, ids or polling.
                if external.preadBacked {
                    let n = external.requestCount as usize;
                    let requests =
                        unsafe { core::slice::from_raw_parts(external.requests.as_ptr(), n) };
                    let rc = self.queue_pread_requests(
                        requests,
                        slotIndex,
                        external.generation,
                        priority,
                    );
                    if rc == SCE_KERNEL_ERROR_EAGAIN {
                        continue;
                    }
                    if rc != 0 {
                        self.externalAioLiveCount.fetch_sub(1, Ordering::Release);
                        self.notify_external_aio(
                            external,
                            AprExternalAioEvent::SubmitFailed,
                            rc,
                            false,
                        );
                        Self::release_external_aio_slot(external);
                    } else {
                        external.state = ExternalAioState::Submitted;
                        external.remainingCount = external.requestCount;
                        external.submitTimeNs = nowNs;
                        self.notify_external_aio(
                            external,
                            AprExternalAioEvent::Submitted,
                            0,
                            false,
                        );
                    }
                    staged = true;
                    continue;
                }
                if (!external.grouped
                    && self.aioSubmitRound.batches[bi].count >= SCE_KERNEL_AIO_REQUEST_NUM_MAX)
                    || (external.grouped
                        && self.aioSubmitRound.groupedExternal[bi].count
                            >= kAprExternalAioCapacity as usize)
                {
                    continue;
                }
                let n = external.requestCount as usize;
                if !deferred {
                    let mut admissionLimit = admission.effectiveLimit as usize;
                    if !Self::external_aio_is_small_for_boost(external)
                        && admissionLimit > Self::aio_active_read_limit() as usize
                    {
                        admissionLimit = Self::aio_active_read_limit() as usize;
                    }
                    if n > admissionLimit || admission.snapshot.activeCount > admissionLimit - n {
                        self.passReadBlockedOnAioCapacity = true;
                        continue;
                    }
                }
                if !deferred && preserveLaneShare && admission.laneDemandMask != 0 {
                    let prepassLimit = (admission.effectiveLimit as usize * 3 + 3) / 4;
                    if n > prepassLimit || admission.snapshot.activeCount > prepassLimit - n {
                        continue;
                    }
                }
                let itemRef = AioItemRef {
                    external: ExternalAioRef {
                        slot: slotIndex,
                        generation: external.generation,
                    },
                    isExternal: true,
                    externalWasDeferred: deferred,
                    ..Default::default()
                };
                if external.grouped {
                    let g = &mut self.aioSubmitRound.groupedExternal[bi];
                    g.items[g.count] = itemRef;
                    g.count += 1;
                } else {
                    let b = &mut self.aioSubmitRound.batches[bi];
                    let item = b.count;
                    b.count += 1;
                    b.requests[item] = external.requests[0];
                    b.ids[item] = -1;
                    b.items[item] = itemRef;
                }
                external.state = ExternalAioState::AwaitingBatchSubmit;
                if !deferred {
                    self.reserve_external_aio_admission(admission, external, nowNs);
                }
                staged = true;
            }
            priority -= 1;
        }
        staged
    }
}

impl AprAioReactor {
    pub(crate) fn rollback_staged_aio_admission(
        &self,
        admission: &mut AioAdmissionContext,
        active: &ActiveRead,
    ) {
        if !active.nativeCapacityCharged {
            return;
        }
        let s = &mut admission.snapshot;
        if !admission.initialized || s.activeCount == 0 {
            abort();
        }
        s.activeCount -= 1;
        let classIndex = active.desc.readClass as usize;
        if classIndex < AmprLooseReadClass::Count as usize {
            if s.classActive[classIndex] == 0 {
                abort();
            }
            s.classActive[classIndex] -= 1;
        }
        if Self::aio_desc_is_small_for_boost(&active.desc) {
            if s.smallCount == 0 {
                abort();
            }
            s.smallCount -= 1;
        }
        if !active.job.is_null() {
            let prio = unsafe { (*active.job).prioIndex };
            if prio < kPriorityCount {
                let groupIndex = Self::read_group_index(Self::read_group_for_priority(prio));
                if s.groupActive[groupIndex] == 0 {
                    abort();
                }
                s.groupActive[groupIndex] -= 1;
            }
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn aio_submit_id_is_live_unique(&self, id: SceKernelAioSubmitId) -> bool {
        if id < 0 {
            return false;
        }
        let mut it = self.activeReads.begin_const();
        let end = self.activeReads.end_const();
        while it != end {
            let active = unsafe { it.get() };
            if Self::active_read_is_submitted(active) && active.aioId == id {
                return false;
            }
            it.inc();
        }
        for external in &self.externalAioReads {
            if external.published.load(Ordering::Acquire)
                && external.state == ExternalAioState::Submitted
                && external.aioIds[..external.requestCount as usize].contains(&id)
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn detach_staged_read_chain(&self, job: JobPtr, chain: *mut ReadChain) {
        if job.is_null() || chain.is_null() {
            return;
        }
        unsafe {
            if (*job).cursorReadChain == chain {
                (*job).cursorReadChain = null_mut();
            }
        }
    }

    pub(crate) fn reserve_read_chain_sequence(job: &mut JobState, chain: &mut ReadChain) {
        if chain.seq != 0 {
            return;
        }
        chain.seq = job.nextReadSeq;
        job.nextReadSeq += 1;
        job.latestSubmittedReadSeq = chain.seq;
    }

    pub(crate) fn external_aio_initial_poll_delay_ns(&self, external: &ExternalAioRead) -> u32 {
        match external.ioClass {
            AprExternalAioClass::Latency => AMPR_EMU_APR_EXTERNAL_AIO_POLL_LATENCY_INITIAL_NS,
            AprExternalAioClass::Balanced => AMPR_EMU_APR_EXTERNAL_AIO_POLL_BALANCED_INITIAL_NS,
            AprExternalAioClass::Bulk => AMPR_EMU_APR_EXTERNAL_AIO_POLL_BULK_INITIAL_NS,
        }
    }

    /// Default `firstExternalInSubmitBatch = false`.
    pub(crate) fn notify_external_aio(
        &self,
        external: &mut ExternalAioRead,
        event: AprExternalAioEvent,
        value: c_int,
        firstExternalInSubmitBatch: bool,
    ) {
        if let Some(callback) = external.callback {
            let n = AprExternalAioNotification {
                event,
                value,
                firstExternalInSubmitBatch,
            };
            unsafe { callback(external.context, &n) };
        }
    }
}

impl AprAioReactor {
    fn take_external_deferred(&self, wasDeferred: bool) {
        if wasDeferred {
            if self.externalAioDeferredCount.load(Ordering::Acquire) == 0 {
                abort();
            }
            self.externalAioDeferredCount
                .fetch_sub(1, Ordering::Release);
        }
    }

    fn arm_external_submitted(
        &self,
        external: &mut ExternalAioRead,
        submitTimeNs: u64,
        submitted: u32,
    ) {
        external.submitTimeNs = submitTimeNs;
        external.retryNotBeforeNs = 0;
        external.pollBackoffNs = self.external_aio_initial_poll_delay_ns(external);
        external.nextPollTimeNs = submitTimeNs + external.pollBackoffNs as u64;
        external.state = ExternalAioState::Submitted;
        self.externalAioSubmittedCount
            .fetch_add(submitted, Ordering::Release);
    }

    pub(crate) fn accept_external_aio_submit(
        &mut self,
        item: &AioItemRef,
        aioId: SceKernelAioSubmitId,
        submitTimeNs: u64,
        firstExternalInSubmitBatch: bool,
    ) {
        let external = self.external_aio_at(&item.external);
        if external.is_null()
            || unsafe { (*external).state } != ExternalAioState::AwaitingBatchSubmit
            || aioId < 0
        {
            abort();
        }
        let external = unsafe { &mut *external };
        self.take_external_deferred(item.externalWasDeferred);
        external.aioIds[0] = aioId;
        external.remainingCount = 1;
        self.arm_external_submitted(external, submitTimeNs, 1);
        self.notify_external_aio(
            external,
            AprExternalAioEvent::Submitted,
            0,
            firstExternalInSubmitBatch,
        );
    }

    pub(crate) fn accept_external_aio_group(
        &mut self,
        item: &AioItemRef,
        submitTimeNs: u64,
        firstExternalInSubmitBatch: bool,
    ) {
        let external = self.external_aio_at(&item.external);
        if external.is_null() {
            abort();
        }
        let external = unsafe { &mut *external };
        if !external.grouped
            || external.state != ExternalAioState::AwaitingBatchSubmit
            || external.requestCount < 2
        {
            abort();
        }
        self.take_external_deferred(item.externalWasDeferred);
        external.remainingCount = external.requestCount;
        self.arm_external_submitted(external, submitTimeNs, external.requestCount);
        self.notify_external_aio(
            external,
            AprExternalAioEvent::Submitted,
            0,
            firstExternalInSubmitBatch,
        );
    }

    pub(crate) fn reject_external_aio_submit(
        &mut self,
        item: &AioItemRef,
        submitSceRc: c_int,
        submitTimeNs: u64,
        admission: *mut AioAdmissionContext,
    ) {
        let external = self.external_aio_at(&item.external);
        if external.is_null()
            || unsafe { (*external).state } != ExternalAioState::AwaitingBatchSubmit
        {
            abort();
        }
        let external = unsafe { &mut *external };
        if apr_aio_submit_sce_rc_is_deferred(submitSceRc) {
            external.state = ExternalAioState::Deferred;
            external.retryNotBeforeNs = submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
            if !item.externalWasDeferred {
                self.externalAioDeferredCount
                    .fetch_add(1, Ordering::Release);
            }
            self.notify_external_aio(
                external,
                AprExternalAioEvent::SubmitDeferred,
                submitSceRc,
                false,
            );
            return;
        }
        if !item.externalWasDeferred {
            if admission.is_null() {
                abort();
            }
            self.rollback_external_aio_admission(unsafe { &mut *admission }, external);
        } else {
            self.take_external_deferred(true);
        }
        if self.externalAioLiveCount.load(Ordering::Acquire) == 0 {
            abort();
        }
        self.externalAioLiveCount.fetch_sub(1, Ordering::Release);
        self.notify_external_aio(
            external,
            AprExternalAioEvent::SubmitFailed,
            submitSceRc,
            false,
        );
        Self::release_external_aio_slot(external);
    }

    pub(crate) fn accept_aio_submit_item(
        &mut self,
        item: &ActiveReadRef,
        aioId: SceKernelAioSubmitId,
        submitTimeNs: u64,
    ) {
        let active = self
            .activeReads
            .active_at_slot_2(item.slot, item.generation);
        if active.is_null() {
            abort();
        }
        let active = unsafe { &mut *active };
        if active.job.is_null()
            || active.chain.is_null()
            || active.aioPrio < SCE_KERNEL_AIO_PRIORITY_LOW
            || active.aioPrio > SCE_KERNEL_AIO_PRIORITY_HIGH
        {
            abort();
        }
        let job = unsafe { &mut *active.job };
        let chain = unsafe { &mut *active.chain };
        if active.submitAccounted && !active.awaitingResubmit {
            abort();
        }
        let accountSubmit = !active.submitAccounted;
        self.mark_active_read_submitted(active, aioId);
        active.submitTimeNs = submitTimeNs;
        active.retryNotBeforeNs = 0;
        if accountSubmit {
            chain.retryNotBeforeNs = 0;
        }
        active.aioDeleteRetries = 0;
        active.aioDeleteFirstFailureNs = 0;
        if accountSubmit {
            Self::reserve_read_chain_sequence(job, chain);
        }
        if active.seq != chain.seq {
            abort();
        }
        if accountSubmit {
            let issuedLength = active.desc.length;
            if issuedLength == 0 || issuedLength > chain.remaining {
                abort();
            }
            chain.remaining -= issuedLength;
            chain.nextBuffer =
                (chain.nextBuffer as usize).wrapping_add(issuedLength as usize) as *mut c_void;
            chain.nextOffset += issuedLength;
            active.submitAccounted = true;
        }
        self.arm_active_read_poll_after_submit(active, submitTimeNs);
    }
}
