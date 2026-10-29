//! Native micro completion, job release, the worker loop, construction and the C ABI.

use super::*;

/// Locks `m` without tying the guard to the `&self` borrow
fn lock_detached(m: &Mutex) -> MutexGuard<'static> {
    unsafe { (*(m as *const Mutex)).lock() }
}

impl AprAioReactor {
    pub(crate) fn retire_native_apr_micro_submit(
        &self,
        job: &mut JobState,
        slot: *mut AprNativeMicroSlot,
    ) -> c_int {
        if job.nativeMicroEngine != NativeMicroEngine::Apr || job.nativeMicroSubmitId == 0 {
            abort();
        }
        let mut waitRcRaw: c_int = 0;
        let waitDispatchRc =
            unsafe { apr_native_wait_dispatch(job.nativeMicroSubmitId, &mut waitRcRaw) };
        let waitRc = if waitDispatchRc != 0 {
            waitDispatchRc
        } else {
            apr_libkernel_rc_to_sce(waitRcRaw)
        };
        if waitRc != 0 {
            abort();
        }
        job.nativeMicroSubmitId = 0;
        unsafe { AtomicI32::from_ptr(addr_of_mut!((*slot).result.result)).load(Ordering::Acquire) }
    }

    fn clear_native_batch_submit(job: &mut JobState) -> bool {
        job.nativeSubmitted.store(false, Ordering::Release);
        job.nativeBatchSequence = 0;
        job.nativeSubmitTimeNs = 0;
        job.nativeMicroEngine = NativeMicroEngine::None;
        true
    }

    pub(crate) fn native_micro_completion_observed(&mut self, job: &mut JobState) -> bool {
        if !job.nativeSubmitted.load(Ordering::Acquire) {
            return true;
        }

        if job.nativeMicroEngine == NativeMicroEngine::AprBatch {
            if job.prioIndex >= kPriorityCount || job.nativeBatchSequence == 0 {
                abort();
            }
            let prio = job.prioIndex as usize;
            let lane = &mut self.nativeBatchLanes[prio];
            if Self::native_batch_sequence_reached(lane.completedSequence, job.nativeBatchSequence)
            {
                return Self::clear_native_batch_submit(job);
            }
            if lane.activeBuffer < 0 {
                return false;
            }
            let bufferIndex = lane.activeBuffer as u32;
            let state = lane.buffers[bufferIndex as usize];
            let targetIsActive = state.firstSequence != 0
                && Self::native_batch_sequence_reached(
                    job.nativeBatchSequence,
                    state.firstSequence,
                )
                && Self::native_batch_sequence_reached(state.lastSequence, job.nativeBatchSequence);
            if !targetIsActive {
                return false;
            }
            let now = time_counter_now();
            let checkBase =
                if job.nativeSubmitTimeNs != 0 && job.nativeSubmitTimeNs >= state.submitTimeNs {
                    job.nativeSubmitTimeNs
                } else {
                    state.submitTimeNs
                };
            let ageNs = if checkBase != 0 && now >= checkBase {
                now - checkBase
            } else {
                0
            };
            if ageNs < kNativeCompletionTimeoutNs {
                return false;
            }
            let slot = apr_native_batch_slot(prio, bufferIndex as usize);
            if slot.is_null() {
                abort();
            }
            Self::sample_native_batch_progress(prio as u32, bufferIndex, lane, slot);
            if Self::native_batch_sequence_reached(lane.completedSequence, job.nativeBatchSequence)
            {
                return Self::clear_native_batch_submit(job);
            }
            // Checkpoint timeout: fatal whether or not the batch reported an error.
            abort();
        }

        let aprMicro = job.nativeMicroEngine == NativeMicroEngine::Apr;
        let microSlot = if aprMicro {
            apr_native_micro_slot(job.poolSlot as usize)
        } else {
            null_mut()
        };
        if aprMicro && (microSlot.is_null() || job.nativeMicroSubmitId == 0) {
            abort();
        }
        let loadCompletion =
            |p: *mut u64| unsafe { AtomicU64::from_ptr(p).load(Ordering::Acquire) };
        let mut completionValue = if job.nativeCompletionAddress.is_null() {
            0
        } else {
            loadCompletion(job.nativeCompletionAddress)
        };
        let now = time_counter_now();
        let ageNs = if job.nativeSubmitTimeNs != 0 && now >= job.nativeSubmitTimeNs {
            now - job.nativeSubmitTimeNs
        } else {
            0
        };
        if completionValue == 0
            && ageNs >= kNativeCompletionTimeoutNs
            && !job.nativeCompletionAddress.is_null()
        {
            completionValue = loadCompletion(job.nativeCompletionAddress);
        }
        let timedOut = completionValue == 0 && ageNs >= kNativeCompletionTimeoutNs;
        let mut aprTerminalError = false;
        if aprMicro && completionValue == 0 {
            let earlyResult = unsafe {
                AtomicI32::from_ptr(addr_of_mut!((*microSlot).result.result))
                    .load(Ordering::Acquire)
            };
            if earlyResult != kAprNativeMicroResultPending && earlyResult != 0 {
                let result = self.retire_native_apr_micro_submit(job, microSlot);
                let rc = if result != 0 { result } else { earlyResult };
                let off = job.nativeSourceOffset;
                self.set_fail(job, c"native-apr-micro-result".as_ptr(), rc, off, 0);
                aprTerminalError = true;
            }
        }
        if completionValue == 0 && !timedOut && !aprTerminalError {
            return false;
        }
        let off = job.nativeSourceOffset;
        if timedOut && !aprTerminalError {
            if aprMicro {
                abort();
            }
            self.set_fail(
                job,
                c"native-completion-timeout".as_ptr(),
                SCE_KERNEL_ERROR_ETIMEDOUT,
                off,
                0,
            );
        } else if !aprTerminalError
            && !Self::job_failed(job)
            && completionValue != kAprNativeMicroCompletionDone
        {
            self.set_fail(
                job,
                c"native-completion-write".as_ptr(),
                SCE_KERNEL_ERROR_EIO,
                off,
                0,
            );
        }
        if aprMicro && !aprTerminalError {
            let result = self.retire_native_apr_micro_submit(job, microSlot);
            if result != 0 {
                self.set_fail(job, c"native-apr-micro-result".as_ptr(), result, off, 0);
            }
        }
        job.nativeSubmitted.store(false, Ordering::Release);
        job.nativeSubmitTimeNs = 0;
        job.nativeMicroEngine = NativeMicroEngine::None;
        true
    }

    pub(crate) fn maybe_release_reactor_job(&mut self, job: &mut JobPtr) {
        let j = *job;
        if j.is_null() {
            return;
        }
        let jr = unsafe { &mut *j };
        if jr.nativeSubmitted.load(Ordering::Acquire) && !self.native_micro_completion_observed(jr)
        {
            return;
        }
        if Self::job_has_outstanding_reads(jr) {
            return;
        }
        if !Self::job_failed(jr) && !Self::job_processing_complete(jr) {
            return;
        }
        {
            let _lk = lock_detached(&self.m);
            if jr.prioIndex >= kPriorityCount
                || self.activePriorityHeads[jr.prioIndex as usize] != j
            {
                return;
            }
            self.erase_active_job_locked(j);
        }
        jr.nativeCompletionAddress = null_mut();
        jr.nativeCommandBuffer = null_mut();
        self.publish_job_result(jr);
        if jr.syntheticWaitPublished {
            self.publish_synthetic_wait_completion(jr);
        } else {
            let _lk = lock_detached(&self.m);
            self.release_unpublished_synthetic_wait_slot_locked(jr);
        }
        self.release_job_state(j);
        *job = null_mut();
    }

    pub(crate) fn worker(&mut self) {
        self.configure_worker_thread();
        // WAIT_ON_ADDRESS has no wake source: poll with exponential backoff.
        let mut waitOnAddressBackoffNs = AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS;
        loop {
            let shuttingDown = self.shutdownRequested.load(Ordering::Acquire);
            let waitIfIdle = !shuttingDown
                && !self.has_active_lanes_locked()
                && self.activeReads.empty()
                && self.externalAioLiveCount.load(Ordering::Acquire) == 0;
            self.maybe_release_stale_fds(waitIfIdle);
            self.drain_incoming(waitIfIdle);
            self.workerObservedWakeEpoch = self.reactorWakeEpoch.load(Ordering::Acquire);
            {
                let _lk = lock_detached(&self.m);
                if self.stop {
                    return;
                }
            }

            // Pread pool completions (pread_pool.rs); a later completion bumps the
            // epoch observed above, so the wait below returns at once.
            let mut progressed = self.drain_pread_completions();
            if shuttingDown && !self.prepare_native_batches_for_shutdown() {
                abort();
            }

            // Phase 1: AIO observation (hot/deadline-due requests; never sleeps).
            if self.has_submitted_active_reads() {
                let normal = self.poll_active_aio_reads_once();
                progressed |= normal.completed;
                let mut aioPolledThisPass = normal.polled;
                if self.capacityPollRequested && !aioPolledThisPass {
                    let capacity = self.poll_active_aio_reads_for_capacity(time_counter_now());
                    progressed |= capacity.completed;
                    aioPolledThisPass = capacity.polled;
                }
                if aioPolledThisPass {
                    self.nextCapacityPollNs =
                        time_counter_now() + AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS;
                }
            } else {
                self.capacityPollCursorSlot = u32::MAX;
            }

            progressed |= self.resubmit_deferred_active_reads();
            self.refresh_native_batch_progress_snapshots();
            progressed |= self.progress_native_batches();

            // Phase 2: exactly one fair cursor pass.
            self.passWaitOnAddressPending = false;
            self.passReadBlockedOnAioCapacity = false;
            self.passReadBlockedOnFdBudget = false;
            self.passLocalEqueueBackpressure = false;
            progressed |= self.progress_all_jobs();
            self.capacityPollRequested = self.passReadBlockedOnAioCapacity;

            if shuttingDown && self.native_batches_idle() {
                let _lk = lock_detached(&self.m);
                self.stop = true;
                return;
            }

            if progressed {
                waitOnAddressBackoffNs = AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS;
                self.note_reactor_progress(true);
                continue;
            }
            self.note_reactor_progress(false);

            // Phase 3: one unified wait domain.
            let mut passNativeMicroPending = false;
            let mut nativeSubmitRetryAtNs = 0;
            {
                let _lk = lock_detached(&self.m);
                for lane in 0..PRIO_N {
                    let mut job = self.activePriorityHeads[lane];
                    while !job.is_null() {
                        let j = unsafe { &*job };
                        let nativeSubmitted = j.nativeSubmitted.load(Ordering::Acquire);
                        if nativeSubmitted && j.nativeMicroEngine != NativeMicroEngine::AprBatch {
                            passNativeMicroPending = true;
                        }
                        if j.nativeSubmitRetryAtNs != 0 {
                            passNativeMicroPending = true;
                            if nativeSubmitRetryAtNs == 0
                                || j.nativeSubmitRetryAtNs < nativeSubmitRetryAtNs
                            {
                                nativeSubmitRetryAtNs = j.nativeSubmitRetryAtNs;
                            }
                        }
                        if !Self::job_allows_priority_successor(j, nativeSubmitted) {
                            break;
                        }
                        job = j.priorityNext.load(Ordering::Acquire);
                    }
                }
            }
            let nowNs = time_counter_now();
            let mut waitNs: u64 = 0;
            let mut retryImmediately = false;
            let mut consider_wait = |candidateNs: u64| {
                if candidateNs == 0 {
                    retryImmediately = true;
                } else if waitNs == 0 || candidateNs < waitNs {
                    waitNs = candidateNs;
                }
            };

            if self.passWaitOnAddressPending {
                consider_wait(waitOnAddressBackoffNs);
                waitOnAddressBackoffNs =
                    (waitOnAddressBackoffNs * 2).min(WAIT_ON_ADDRESS_BACKOFF_MAX_NS);
            } else {
                waitOnAddressBackoffNs = AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS;
            }
            if self.passReadBlockedOnFdBudget {
                consider_wait(FD_BUDGET_RETRY_WAIT_NS);
            }
            if self.has_submitted_active_reads() {
                consider_wait(self.next_aio_poll_wait_ns(nowNs));
            }
            if nativeSubmitRetryAtNs != 0 {
                consider_wait(if nativeSubmitRetryAtNs <= nowNs {
                    0
                } else {
                    nativeSubmitRetryAtNs - nowNs
                });
            }
            // The capacity probe only polls APR reads; externals are covered by the AIO poll above.
            if self.capacityPollRequested && self.submittedActiveReadCount != 0 {
                let readyNs = self.nextCapacityPollNs;
                consider_wait(if readyNs == 0 || readyNs <= nowNs {
                    0
                } else {
                    readyNs - nowNs
                });
            }
            if self.deferredActiveReadCount != 0
                || self.externalAioDeferredCount.load(Ordering::Acquire) != 0
            {
                consider_wait(self.next_deferred_active_retry_wait_ns(nowNs));
            }
            let localEqueueOnlyWait = self.passLocalEqueueBackpressure
                && self.submittedActiveReadCount == 0
                && self.deferredActiveReadCount == 0
                && self.externalAioLiveCount.load(Ordering::Acquire) == 0
                && !self.native_batch_work_pending()
                && !passNativeMicroPending;
            if localEqueueOnlyWait {
                // Sleep on the reactor epoch; only a hooked wait/queue delete frees pending nodes.
                // Bounded: notify_external_progress bumps the epoch without `m` (it can be
                // reached with `m` held), so its signal can land before this wait starts.
                consider_wait(LOCAL_EQUEUE_BACKPRESSURE_WAIT_NS);
            } else if !self.passWaitOnAddressPending && self.has_active_lanes_locked() {
                // A no-progress pass reaches here. Lanes stalled only behind in-flight
                // AIO are woken by the AIO poll / capacity / deferred deadlines above;
                // native batches have no deadline and keep the idle poll. The 1 ms
                // bound covers wake signals that race the epoch check unlocked.
                if self.has_submitted_active_reads()
                    && !self.native_batch_work_pending()
                    && !passNativeMicroPending
                {
                    consider_wait(LOCAL_EQUEUE_BACKPRESSURE_WAIT_NS);
                } else if !self.passReadBlockedOnFdBudget
                    || self.native_batch_work_pending()
                    || passNativeMicroPending
                {
                    consider_wait(Self::active_lane_idle_sleep_ns() as u64);
                }
            }

            if retryImmediately {
                continue;
            }
            // No candidate applied (e.g. an external group blocked on capacity): never
            // hot-spin; every submit bumps the epoch, so this bound adds no wake latency.
            if waitNs == 0 {
                waitNs = LOCAL_EQUEUE_BACKPRESSURE_WAIT_NS;
            }
            self.wait_for_reactor_wake(self.workerObservedWakeEpoch, waitNs);
        }
    }
}

/// Upper bound for the local-equeue backpressure sleep.
const LOCAL_EQUEUE_BACKPRESSURE_WAIT_NS: u64 = 1_000_000;
const FD_BUDGET_RETRY_WAIT_NS: u64 = 250_000;
/// Cap for the WAIT_ON_ADDRESS poll backoff (starts at the 10 us lane idle sleep).
const WAIT_ON_ADDRESS_BACKOFF_MAX_NS: u64 = 200_000;

impl AprAioReactor {
    /// `AprAioReactor::AprAioReactor()` (placement into `this`).
    pub(crate) unsafe fn construct(this: *mut Self) {
        unsafe { Self::init_members(this) };
        let r = unsafe { &mut *this };
        for (slot, s) in r.jobStateSlots.iter_mut().enumerate() {
            s.nextFree = if slot as u32 + 1 < kJobStatePoolCapacity {
                slot as u32 + 1
            } else {
                u32::MAX
            };
        }
        r.jobStateFreeHead = if kJobStatePoolCapacity != 0 {
            0
        } else {
            u32::MAX
        };
        r.jobStateFreeCount
            .store(kJobStatePoolCapacity, Ordering::Relaxed);
        for (slot, s) in r.syntheticDoneSlots.iter_mut().enumerate() {
            s.next = if slot as u32 + 1 < kSyntheticDoneCapacity {
                slot as u32 + 1
            } else {
                u32::MAX
            };
        }
        r.syntheticDoneFreeHead = if kSyntheticDoneCapacity != 0 {
            0
        } else {
            u32::MAX
        };
        for s in r.syntheticLowerSlots.iter_mut() {
            s.generation = 1;
        }
        for (slot, s) in r.readChainSlots.iter_mut().enumerate() {
            s.nextFree = if slot as u32 + 1 < kReadChainPoolCapacity {
                slot as u32 + 1
            } else {
                u32::MAX
            };
        }
        r.readChainFreeHead = if kReadChainPoolCapacity != 0 {
            0
        } else {
            u32::MAX
        };
    }
}

/// `apr_aio_reactor()`: lazily constructs the singleton in static storage.
pub(crate) fn apr_aio_reactor() -> &'static mut AprAioReactor {
    let p = g_apr_aio_reactor.load(Ordering::Acquire);
    if !p.is_null() {
        return unsafe { &mut *p };
    }
    if g_apr_aio_reactor_init
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let p = unsafe { (*g_apr_aio_reactor_storage.get()).as_mut_ptr() };
        unsafe { AprAioReactor::construct(p) };
        g_apr_aio_reactor.store(p, Ordering::Release);
        g_apr_aio_reactor_init.store(2, Ordering::Release);
        return unsafe { &mut *p };
    }
    let mut spins = 0u32;
    while g_apr_aio_reactor_init.load(Ordering::Acquire) != 2 {
        ampr_spin_pause_or_yield(&mut spins);
    }
    unsafe { &mut *g_apr_aio_reactor.load(Ordering::Acquire) }
}

// Public reactor and external AIO broker API.

pub unsafe fn apr_reactor_shutdown() -> c_int {
    let reactor = g_apr_aio_reactor.load(Ordering::Acquire);
    if reactor.is_null() {
        0
    } else {
        unsafe { (*reactor).shutdown() }
    }
}

pub unsafe fn apr_reactor_submit_external_aio_read(
    request: *const SceKernelAioRWRequest,
    priority: c_int,
    ioClass: AprExternalAioClass,
    context: *mut c_void,
    callback: AprExternalAioCallback,
) -> c_int {
    apr_aio_reactor().submit_external_aio_read(
        unsafe { &*request },
        priority,
        ioClass,
        context,
        callback,
    )
}

pub unsafe fn apr_reactor_submit_external_aio_read_group(
    requests: *const SceKernelAioRWRequest,
    requestCount: usize,
    priority: c_int,
    ioClass: AprExternalAioClass,
    context: *mut c_void,
    callback: AprExternalAioCallback,
) -> c_int {
    apr_aio_reactor().submit_external_aio_read_group(
        requests,
        requestCount,
        priority,
        ioClass,
        context,
        callback,
    )
}

pub unsafe fn apr_reactor_notify_external_progress() {
    let reactor = g_apr_aio_reactor.load(Ordering::Acquire);
    if !reactor.is_null() {
        unsafe { (*reactor).notify_external_progress() };
    }
}

pub unsafe fn apr_reactor_wait_synthetic_submit_id(
    id: SceAprSubmitId,
    outHandled: *mut bool,
) -> c_int {
    apr_aio_reactor().wait_synthetic_submit_id(id, outHandled)
}

pub unsafe fn apr_reactor_submit(j: *const Job, outSubmitId: *mut SceAprSubmitId) -> c_int {
    apr_aio_reactor().submit(unsafe { &*j }, outSubmitId)
}
