//! Rejecting AIO submits, flushing priority submit batches and read chain slice submission.

use super::*;
use crate::rt::stats::{self, Stat};

const fn outcome(
    result: DirectReadSubmitResult,
    errorReason: *const c_char,
    errorRc: c_int,
    errorOffset: u32,
    backendRc: c_int,
) -> DirectReadSubmitOutcome {
    DirectReadSubmitOutcome {
        result,
        errorReason,
        errorRc,
        errorOffset,
        backendRc,
    }
}
const PENDING: DirectReadSubmitOutcome = outcome(DirectReadSubmitResult::Pending, null(), 0, 0, 0);

impl AprAioReactor {
    pub(crate) fn reject_aio_submit_item(
        &mut self,
        item: &ActiveReadRef,
        submitSceRc: c_int,
        submitTimeNs: u64,
        admission: *mut AioAdmissionContext,
    ) {
        let active = self
            .activeReads
            .active_at_slot_2(item.slot, item.generation);
        if active.is_null() || unsafe { (*active).job.is_null() || (*active).chain.is_null() } {
            abort();
        }
        let active = unsafe { &mut *active };
        let mut job = active.job;
        let chain = active.chain;
        let errorOff = active.desc.errorOff;

        if active.awaitingResubmit {
            if !active.awaitingBatchSubmit {
                abort();
            }
            active.awaitingBatchSubmit = false;
            if apr_aio_submit_sce_rc_is_deferred(submitSceRc) {
                active.retryNotBeforeNs = submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                return;
            }
            self.detach_staged_read_chain(job, chain);
            unsafe { (*chain).allIssued = true };
            self.set_or_defer_read_command_error(
                unsafe { &mut *job },
                c"aio-resubmit".as_ptr(),
                apr_backend_read_error_to_apr(submitSceRc),
                errorOff,
                0,
            );
            apr_release_aio_read_desc(&mut active.desc);
            Self::decrement_active_read_count(job);
            Self::decrement_read_chain_active(chain, active.readCreditBytes);
            let it = self.activeReads.iterator_from_slot(item.slot);
            self.erase_active_read(it);
            self.maybe_finish_read_chain(chain);
            self.maybe_release_reactor_job(&mut job);
            return;
        }

        if !active.awaitingBatchSubmit || active.awaitingResubmit || admission.is_null() {
            abort();
        }
        if apr_aio_submit_sce_rc_is_deferred(submitSceRc) {
            self.mark_staged_read_deferred(active);
            active.retryNotBeforeNs = submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
            // Keep the chain parked until this first request receives an id.
            unsafe { (*chain).retryNotBeforeNs = kReadChainAwaitingInitialSubmit };
            return;
        }

        active.awaitingBatchSubmit = false;
        self.rollback_staged_aio_admission(unsafe { &mut *admission }, active);
        apr_release_aio_read_desc(&mut active.desc);
        Self::decrement_active_read_count(job);
        Self::decrement_read_chain_active(chain, active.readCreditBytes);
        let it = self.activeReads.iterator_from_slot(item.slot);
        self.erase_active_read(it);
        self.detach_staged_read_chain(job, chain);
        unsafe { (*chain).allIssued = true };
        self.maybe_finish_read_chain(chain);
        if !Self::job_failed(unsafe { &*job }) {
            self.set_or_defer_read_command_error(
                unsafe { &mut *job },
                c"aio-submit".as_ptr(),
                apr_backend_read_error_to_apr(submitSceRc),
                errorOff,
                0,
            );
        }
        self.maybe_release_reactor_job(&mut job);
    }

    fn flush_group_external(&mut self, item: &AioItemRef) -> &'static mut ExternalAioRead {
        let external = self.external_aio_at(&item.external);
        if external.is_null() {
            abort();
        }
        let external = unsafe { &mut *external };
        if !external.grouped || external.state != ExternalAioState::AwaitingBatchSubmit {
            abort();
        }
        external
    }

    pub(crate) fn flush_aio_priority_submits(
        &mut self,
        batch: &mut AioSubmitBatch,
        grouped: &mut ExternalAioGroupBatch,
        admission: *mut AioAdmissionContext,
    ) -> bool {
        let stagedItemCount = batch.count;
        let stagedGroupCount = grouped.count;
        batch.count = 0;
        grouped.count = 0;
        if stagedItemCount == 0 && stagedGroupCount == 0 {
            return false;
        }
        if batch.aioPriority != grouped.aioPriority
            || stagedItemCount > SCE_KERNEL_AIO_REQUEST_NUM_MAX
            || stagedGroupCount > kExternalAioCapacity as usize
        {
            abort();
        }

        let mut groupRequestOffsets = [0u32; kExternalAioCapacity as usize];
        let mut progressedAny = false;
        let mut stagedItem = 0usize;
        let mut stagedGroup = 0usize;
        while stagedItem < stagedItemCount || stagedGroup < stagedGroupCount {
            let firstItem = stagedItem;
            let firstGroup = stagedGroup;
            let mut requestCount = 0usize;
            while stagedItem < stagedItemCount && requestCount < kAioCombinedSubmitRequestLimit {
                batch.requests[requestCount] = batch.requests[stagedItem];
                batch.ids[requestCount] = -1;
                requestCount += 1;
                stagedItem += 1;
            }

            let mut groupCount = 0usize;
            while stagedGroup < stagedGroupCount {
                let external = self.flush_group_external(&grouped.items[stagedGroup]);
                let n = external.requestCount as usize;
                if n < 2 || n > kAioCombinedSubmitRequestLimit {
                    abort();
                }
                if n > kAioCombinedSubmitRequestLimit - requestCount {
                    break;
                }
                groupRequestOffsets[groupCount] = requestCount as u32;
                for r in 0..n {
                    batch.requests[requestCount] = external.requests[r];
                    batch.ids[requestCount] = -1;
                    requestCount += 1;
                }
                groupCount += 1;
                stagedGroup += 1;
            }
            if requestCount == 0 {
                abort();
            }

            let statSubmitNs = stats::now();
            let submitRc = unsafe {
                sceKernelAioSubmitReadCommandsMultiple(
                    batch.requests.as_mut_ptr(),
                    requestCount as c_int,
                    batch.aioPriority,
                    batch.ids.as_mut_ptr(),
                )
            };
            let submitTimeNs = time_counter_now();
            let submitSceRc = apr_aio_api_rc_to_sce(submitRc);
            self.note_aio_submit_result(submitSceRc, requestCount);

            let ids = &batch.ids[..requestCount];
            for (i, &id) in ids.iter().enumerate() {
                // Uniqueness walk is a debug-only invariant check.
                let bad = if submitRc == 0 {
                    #[cfg(debug_assertions)]
                    let bad = !self.aio_submit_id_is_live_unique(id) || ids[..i].contains(&id);
                    #[cfg(not(debug_assertions))]
                    let bad = {
                        let _ = i;
                        false
                    };
                    bad
                } else {
                    id >= 0
                };
                if bad {
                    abort();
                }
            }

            let deferred = apr_aio_submit_sce_rc_is_deferred(submitSceRc);
            let mut acceptedExternalInBatch = false;
            for itemIndex in firstItem..stagedItem {
                let id = batch.ids[itemIndex - firstItem];
                let item = batch.items[itemIndex];
                if submitRc == 0 {
                    if item.isExternal {
                        self.accept_external_aio_submit(
                            &item,
                            id,
                            submitTimeNs,
                            !acceptedExternalInBatch,
                        );
                        acceptedExternalInBatch = true;
                        self.stat_arm_external_submit(&item, statSubmitNs);
                    } else {
                        self.accept_aio_submit_item(&item.active, id, submitTimeNs);
                        self.stat_arm_active_submit(&item.active, statSubmitNs);
                    }
                    progressedAny = true;
                } else {
                    if item.isExternal {
                        self.reject_external_aio_submit(
                            &item,
                            submitSceRc,
                            submitTimeNs,
                            admission,
                        );
                    } else {
                        self.reject_aio_submit_item(
                            &item.active,
                            submitSceRc,
                            submitTimeNs,
                            admission,
                        );
                    }
                    progressedAny |= !deferred;
                }
            }

            for groupIndex in 0..groupCount {
                let item = grouped.items[firstGroup + groupIndex];
                let external = self.flush_group_external(&item);
                let requestOffset = groupRequestOffsets[groupIndex] as usize;
                let requestEnd = if groupIndex + 1 < groupCount {
                    groupRequestOffsets[groupIndex + 1] as usize
                } else {
                    requestCount
                };
                if requestEnd < requestOffset
                    || external.requestCount as usize != requestEnd - requestOffset
                {
                    abort();
                }
                if submitRc == 0 {
                    let n = external.requestCount as usize;
                    external.aioIds[..n].copy_from_slice(&batch.ids[requestOffset..requestEnd]);
                    self.accept_external_aio_group(&item, submitTimeNs, !acceptedExternalInBatch);
                    acceptedExternalInBatch = true;
                    progressedAny = true;
                    Self::stat_arm_external_requests(external, statSubmitNs);
                } else {
                    self.reject_external_aio_submit(&item, submitSceRc, submitTimeNs, admission);
                    progressedAny |= !deferred;
                }
            }
            if submitRc == 0 && statSubmitNs != 0 {
                stats::max(
                    Stat::AprInflightMax,
                    (self.submittedActiveReadCount
                        + self.externalAioSubmittedCount.load(Ordering::Acquire))
                        as u64,
                );
            }
        }
        progressedAny
    }

    pub(crate) fn flush_aio_submit_round(&mut self, admission: *mut AioAdmissionContext) -> bool {
        let r = &self.aioSubmitRound;
        if !(0..3).any(|i| r.batches[i].count != 0 || r.groupedExternal[i].count != 0) {
            return false;
        }
        self.ensure_aio_initialized();
        let mut progressedAny = false;
        for i in 0..3 {
            // Batches live in `self`; the flush callees never touch `aioSubmitRound`.
            let batch = unsafe { &mut *addr_of_mut!(self.aioSubmitRound.batches[i]) };
            let grouped = unsafe { &mut *addr_of_mut!(self.aioSubmitRound.groupedExternal[i]) };
            progressedAny |= self.flush_aio_priority_submits(batch, grouped, admission);
        }
        progressedAny
    }

    pub(crate) fn submit_read_chain_slice(
        &mut self,
        job: &mut JobPtr,
        chain: &mut ReadChain,
        issueBudget: &mut ReadIssueBudget,
        admission: &mut AioAdmissionContext,
    ) -> DirectReadSubmitOutcome {
        let failed = outcome(DirectReadSubmitResult::Failed, null(), 0, 0, 0);
        if job.is_null() || chain.job != *job || chain.remaining == 0 {
            return failed;
        }
        let jobRef = unsafe { &mut **job };
        if Self::job_failed(jobRef) {
            return failed;
        }

        let mut sliceDesc = Self::read_chain_next_desc(chain);
        let sliceCreditBytes = Self::read_credit_bytes(sliceDesc.length);
        if sliceCreditBytes == 0 {
            return outcome(
                DirectReadSubmitResult::Failed,
                c"aio-read-credit-zero".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                sliceDesc.errorOff,
                0,
            );
        }
        if !issueBudget.can_admit(sliceCreditBytes) {
            return PENDING;
        }
        let nowNs = Self::aio_admission_lane_now(admission);
        if chain.retryNotBeforeNs != 0 {
            if nowNs < chain.retryNotBeforeNs {
                return PENDING;
            }
            chain.retryNotBeforeNs = 0;
        }
        self.prepare_aio_admission_context(admission, nowNs);
        let readClass = self.effective_read_class(*job, &chain.ownerDesc);
        let readWindow = self.adaptive_read_window(jobRef.prioIndex, readClass, admission);
        // Count and charged bytes are separate adaptive credits; I/O length is unchanged.
        if chain.activeCount >= readWindow.chunks
            || sliceCreditBytes > readWindow.bytes
            || chain.activeBytes > readWindow.bytes - sliceCreditBytes
        {
            self.note_adaptive_read_window_blocked(readWindow.mode);
            return PENDING;
        }
        if !self.direct_read_admission_available(
            jobRef.prioIndex,
            readClass,
            &chain.ownerDesc,
            &sliceDesc,
            nowNs,
            admission,
        ) {
            return PENDING;
        }

        if chain.ownerDesc.fd < 0 {
            let mut acquireRc: c_int = 0;
            let mut acquireErrorOff = chain.ownerDesc.errorOff;
            let acquired = apr_acquire_aio_read_desc(
                jobRef.id,
                &mut chain.ownerDesc,
                !admission.fdPressure,
                admission.directFdCap,
                &mut acquireRc,
                &mut acquireErrorOff,
            );
            if !acquired {
                if apr_fd_acquire_sce_rc_is_deferred(acquireRc) {
                    let failureNowNs = time_counter_now();
                    if acquireRc == SCE_KERNEL_ERROR_EMFILE {
                        self.note_emfile_event();
                    }
                    // Only a real open EAGAIN/EMFILE/ENFILE publishes fd pressure.
                    if self.fd_pressure_active(failureNowNs) {
                        admission.current = false;
                    }
                    chain.retryNotBeforeNs = failureNowNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                    return PENDING;
                }
                chain.allIssued = true;
                let reason = if apr_backend_read_error_is_missing_path(acquireRc) {
                    c"indexed-path-missing"
                } else {
                    c"aio-acquire-fd"
                };
                return outcome(
                    DirectReadSubmitResult::Failed,
                    reason.as_ptr(),
                    apr_backend_read_error_to_apr(acquireRc),
                    acquireErrorOff,
                    acquireRc,
                );
            }
            // Rebuild after acquiring the chain-owned fd; the slice borrows it.
            sliceDesc = Self::read_chain_next_desc(chain);
        }

        Self::borrow_read_chain_fd(chain, &mut sliceDesc);
        let seqCandidate = if chain.seq != 0 {
            chain.seq
        } else {
            jobRef.nextReadSeq
        };
        let activeIt = self.activeReads.push_back(ActiveRead::default());
        self.note_active_read_peak(self.activeReads.size());
        let active = unsafe { activeIt.get() };
        let chainPtr: *mut ReadChain = chain;
        active.job = *job;
        active.desc = sliceDesc;
        active.chain = chainPtr;
        active.seq = seqCandidate;
        active.commandIndex = chain.commandIndex;
        active.readCreditBytes = sliceCreditBytes;
        active.result = SceKernelAioResult::default();
        active.request = SceKernelAioRWRequest::default();
        self.link_active_read_to_job(active, jobRef);
        Self::increment_active_read_count(*job);
        Self::increment_read_chain_active(chainPtr, active.readCreditBytes);
        active.request.offset = active.desc.offset as off_t;
        active.request.nbyte = active.desc.length as usize;
        active.request.buf = active.desc.buffer;
        active.request.result = &mut active.result;
        active.request.fd = active.desc.fd;
        active.nativeCapacityCharged = !unsafe { ampr_pack_is_virtual_fd(active.request.fd) };

        active.aioPrio = apr_aio_priority_from_apr(jobRef.prioIndex);
        issueBudget.consume(active.readCreditBytes);
        self.stage_aio_submit(active, false);
        // Park the chain until the end-of-pass multiple-submit accepts this
        // exact slice, so no duplicate request is staged from the same range.
        chain.retryNotBeforeNs = kReadChainAwaitingInitialSubmit;
        self.note_adaptive_read_window_staged(readWindow.mode);
        // Reserve in the pass-local admission snapshot with the real lane time.
        self.reserve_staged_aio_admission(admission, active, nowNs);
        outcome(DirectReadSubmitResult::Staged, null(), 0, 0, 0)
    }
}

// mem_report counters: start the per-request clocks at the kernel submit.
// `ns` is 0 in normal builds, so these return before touching anything.
impl AprAioReactor {
    fn stat_arm_active_submit(&mut self, item: &ActiveReadRef, ns: u64) {
        if ns == 0 {
            return;
        }
        let active = self
            .activeReads
            .active_at_slot_2(item.slot, item.generation);
        if let Some(a) = unsafe { active.as_mut() } {
            a.statSubmitNs = ns;
            a.statLastPollNs = 0;
            a.statPolls = 0;
        }
    }

    fn stat_arm_external_submit(&mut self, item: &AioItemRef, ns: u64) {
        if ns == 0 {
            return;
        }
        if let Some(e) = unsafe { self.external_aio_at(&item.external).as_mut() } {
            Self::stat_arm_external_requests(e, ns);
        }
    }

    fn stat_arm_external_requests(external: &mut ExternalAioRead, ns: u64) {
        if ns == 0 {
            return;
        }
        let n = (external.requestCount as usize).min(kAprExternalAioGroupMaxRequests);
        external.statSubmitNs[..n].fill(ns);
        external.statLastPollNs[..n].fill(0);
        external.statPolls[..n].fill(0);
    }
}
