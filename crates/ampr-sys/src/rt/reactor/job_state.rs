//! Synthetic wait completion, job progress predicates and native batch/micro pool setup.

use super::*;

/// Detaches the guard lifetime from `self` so `&mut self` helpers can run under `m`.
fn unbound_mutex<'a>(m: &Mutex) -> &'a Mutex {
    unsafe { &*(m as *const Mutex) }
}

/// `PackedOpLayout::bytes` (field is private in command_buffer.rs; repr(C), first u32).
fn packed_layout_bytes(l: &PackedOpLayout) -> u32 {
    unsafe { *(l as *const PackedOpLayout as *const u32) }
}

impl AprAioReactor {
    pub(crate) fn release_synthetic_lower_slot_locked(&mut self, job: &mut JobState) {
        if job.syntheticLowerSlot >= kSyntheticLowerSlotCapacity {
            return;
        }
        let lower = &mut self.syntheticLowerSlots[job.syntheticLowerSlot as usize];
        if lower.active && lower.generation == job.syntheticLowerGeneration {
            let generationMax =
                kSyntheticSubmitIdGenerationMask >> kSyntheticSubmitIdGenerationShift;
            lower.active = false;
            let mut nextGeneration = lower.generation.wrapping_add(1);
            if nextGeneration == 0 || nextGeneration > generationMax {
                nextGeneration = 1;
                lower.generationWrapped = true;
            }
            lower.generation = nextGeneration;
            self.syntheticLowerSlotAvailableCv.notify_one();
        }
        job.syntheticLowerSlot = u32::MAX;
        job.syntheticLowerGeneration = 0;
    }

    pub(crate) fn release_unpublished_synthetic_wait_slot_locked(&mut self, job: &mut JobState) {
        if job.syntheticWaitPublished {
            return;
        }
        self.release_synthetic_lower_slot_locked(job);
        if job.syntheticWaitSlot < kSyntheticRequestCapacity {
            let request = &mut self.syntheticWaitSlots[job.syntheticWaitSlot as usize];
            if request.active {
                *request = SyntheticWaitSlot::default();
                self.syntheticRequestAvailableCv.notify_one();
            }
        }
        job.syntheticSubmitId = 0;
        job.syntheticWaitSlot = u32::MAX;
    }

    pub(crate) fn publish_synthetic_wait_completion(&mut self, job: &mut JobState) {
        if !job.syntheticWaitPublished || job.syntheticWaitSlot >= kSyntheticRequestCapacity {
            return;
        }
        let mut notifyWaiter = false;
        let mut notifyRequestAvailable = false;
        let laneIndex = job.prioIndex as usize;
        {
            let _lk = unbound_mutex(&self.m).lock();
            let slot = job.syntheticWaitSlot as usize;
            let request = self.syntheticWaitSlots[slot];
            if request.active && request.submitId == job.syntheticSubmitId {
                // Native command errors stay in SceAprResultBuffer when the caller
                // requested one; infrastructure failures and result-less submits
                // stay observable through the synthetic wait itself.
                let result =
                    if Self::job_failed(job) && (!job.hasCommandError || job.aprRes.is_null()) {
                        job.result.rc
                    } else {
                        0
                    };
                self.syntheticWaitSlots[slot].result = result;
                if request.waiterClaimed {
                    self.syntheticWaitSlots[slot].done = true;
                    notifyWaiter = true;
                } else {
                    let _evictedId =
                        self.retain_synthetic_done_result_locked(request.submitId, result);
                    self.syntheticWaitSlots[slot] = SyntheticWaitSlot::default();
                    job.syntheticWaitSlot = u32::MAX;
                    notifyRequestAvailable = true;
                }
            }
            // Completion always releases the lower descriptor immediately.
            self.release_synthetic_lower_slot_locked(job);
        }
        if notifyWaiter && laneIndex < PRIO_N {
            self.syntheticWaitCvs[laneIndex].notify_all();
        }
        if notifyRequestAvailable {
            self.syntheticRequestAvailableCv.notify_one();
        }
    }

    pub(crate) fn job_processing_complete(job: &JobState) -> bool {
        job.processingComplete
    }

    pub(crate) fn job_failed(job: &JobState) -> bool {
        job.failed.load(Ordering::Acquire)
    }

    pub(crate) fn job_has_outstanding_reads(job: &JobState) -> bool {
        let physicalReads = job.activeReadCount != 0 || !job.cursorReadChain.is_null();
        // A failed job is kept alive only for physical SDK AIO/read-chain owners.
        if Self::job_failed(job) {
            return physicalReads;
        }
        physicalReads || job.latestSubmittedReadSeq != job.completedReadSeq
    }

    pub(crate) fn clear_decoded_op(job: &mut JobState) {
        job.decodedOpCacheBytes = 0;
    }

    pub(crate) fn cache_decoded_op(job: &mut JobState, op: &Op, opBytes: u32) {
        if !ptr::eq(op, &job.decodedOpCache) {
            job.decodedOpCache = *op;
        }
        job.decodedOpCacheBytes = opBytes;
    }

    pub(crate) fn advance_job_source_commands(job: &mut JobState, opBytes: u32, commandCount: u32) {
        if commandCount == 0
            || job.sourceOffset > job.sourceBytes
            || opBytes > job.sourceBytes - job.sourceOffset
            || job.sourceCommandIndex > u32::MAX - commandCount
        {
            abort();
        }
        job.sourceOffset += opBytes;
        job.sourceCommandIndex += commandCount;
        Self::clear_decoded_op(job);
    }

    pub(crate) fn advance_job_source(job: &mut JobState, opBytes: u32) {
        Self::advance_job_source_commands(job, opBytes, 1);
    }

    pub(crate) fn job_allows_priority_successor(job: &JobState, nativeSubmitted: bool) -> bool {
        if Self::job_failed(job) || job.sourceOffset != job.sourceBytes {
            return false;
        }
        if nativeSubmitted && job.nativeMicroEngine != NativeMicroEngine::AprBatch {
            return false;
        }
        Self::job_has_outstanding_reads(job) || Self::job_processing_complete(job)
    }

    pub(crate) fn finish_job_processing(job: &mut JobState) {
        Self::clear_decoded_op(job);
        job.processingComplete = true;
    }

    pub(crate) fn initialize_native_batch_pool_storage(&mut self) -> bool {
        for words in 1..=kAprNativeBatchPaddingHeaderCount {
            let mut encodedNop = [0u8; 20];
            let mut nopView = cb_view();
            nopView.buffer = encodedNop.as_mut_ptr().cast();
            nopView.bufsize = encodedNop.len() as u32;
            let nop = Op {
                op_type: NOP,
                u32a: words,
                ..Op::default()
            };
            if unsafe { ampr_strict_write_op(&mut nopView, 0, &nop, words * 4) } != 0 {
                return false;
            }
            self.nativeBatchPaddingHeaders[(words - 1) as usize] =
                u32::from_ne_bytes([encodedNop[0], encodedNop[1], encodedNop[2], encodedNop[3]]);
        }

        for lane in 0..kPriorityCount as usize {
            for bufferIndex in 0..kAprNativeBatchBufferCountPerLane as usize {
                let slotPtr = apr_native_batch_slot(lane, bufferIndex);
                if slotPtr.is_null() {
                    return false;
                }
                unsafe { ptr::write_bytes(slotPtr, 0, 1) };
                let releasePtr = unsafe { apr_native_batch_release_ptr(slotPtr) };
                let progressPtr = unsafe { apr_native_batch_progress_ptr(slotPtr) };
                let slot = unsafe { &mut *slotPtr };
                let mut payloadView = cb_view();
                payloadView.buffer = slot.defaultPayload.as_mut_ptr().cast();
                payloadView.bufsize = slot.defaultPayload.len() as u32;

                let nop4 = Op {
                    op_type: NOP,
                    u32a: 1,
                    ..Op::default()
                };
                let nop20 = Op { u32a: 5, ..nop4 };
                let mut payloadRc = 0;
                for packet in 0..kAprNativeBatchPacketsPerGroup {
                    let payloadOffset = packet * kAprNativeBatchPayloadSlotBytes;
                    unsafe {
                        payloadRc |=
                            ampr_strict_write_op(&mut payloadView, payloadOffset, &nop4, 4);
                        payloadRc |=
                            ampr_strict_write_op(&mut payloadView, payloadOffset + 4, &nop20, 20);
                    }
                }
                if payloadRc != 0 {
                    return false;
                }
                for group in 0..kAprNativeBatchGroupCount {
                    let groupOffset = group * kAprNativeBatchGroupBytes;
                    let payloadAt = (groupOffset + kAprNativeBatchGateBytes) as usize;
                    slot.commands
                        [payloadAt..payloadAt + kAprNativeBatchPayloadRegionBytes as usize]
                        .copy_from_slice(&slot.defaultPayload);
                    let gate = Op {
                        op_type: WAIT_ON_ADDRESS,
                        ptra: releasePtr as u64,
                        u64a: apr_native_batch_token(group),
                        u32a: WaitCompare::kGreaterThanOrEqualWrapped as u32,
                        u32c: WaitFlush::kEnable as u32,
                        ..Op::default()
                    };
                    let mut commandsView = cb_view();
                    commandsView.buffer = slot.commands.as_mut_ptr().cast();
                    commandsView.bufsize = slot.commands.len() as u32;
                    let gateRc = unsafe {
                        ampr_strict_write_op(
                            &mut commandsView,
                            groupOffset,
                            &gate,
                            kAprNativeBatchGateBytes,
                        )
                    };
                    let checkpoint = Op {
                        op_type: WRITE_ADDRESS,
                        ptra: progressPtr as u64,
                        u64a: apr_native_batch_token(group),
                        u8a: 0,
                        ..Op::default()
                    };
                    let checkpointRc = unsafe {
                        ampr_strict_write_op(
                            &mut commandsView,
                            groupOffset
                                + kAprNativeBatchGateBytes
                                + kAprNativeBatchPayloadRegionBytes,
                            &checkpoint,
                            kAprNativeBatchCheckpointBytes,
                        )
                    };
                    if gateRc != 0 || checkpointRc != 0 {
                        return false;
                    }
                }
                slot.result.result = kAprNativeBatchResultPending;
            }
        }
        true
    }

    fn native_pool_init_failed(&mut self) -> bool {
        let _lock = SpinLock::from_atomic(unbound_atomic(&self.nativeExecutionPoolLock)).lock();
        self.nativeExecutionPoolInitAttempted = false;
        false
    }

    pub(crate) fn ensure_native_execution_pool(&mut self) -> bool {
        loop {
            let mut shouldInit = false;
            {
                let _lock =
                    SpinLock::from_atomic(unbound_atomic(&self.nativeExecutionPoolLock)).lock();
                if self.nativeExecutionPoolReady {
                    return true;
                }
                if !self.nativeExecutionPoolInitAttempted {
                    self.nativeExecutionPoolInitAttempted = true;
                    shouldInit = true;
                }
            }
            if shouldInit {
                break;
            }
            let ts = SceKernelTimespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            unsafe { sceKernelNanosleep(&ts, null_mut()) };
        }

        if !self.initialize_native_batch_pool_storage() {
            return self.native_pool_init_failed();
        }

        // Publish all CPU-side initialization before device access is enabled.
        fence(Ordering::SeqCst);

        let kNativeMicroProt = SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL;
        let microProtectRc = unsafe {
            ampr_real_sceKernelMprotect(
                g_apr_native_micro_pool.get() as *const c_void,
                kAprNativeMicroPoolBytes,
                kNativeMicroProt,
            )
        };
        if microProtectRc != 0 {
            return self.native_pool_init_failed();
        }
        let batchProtectRc = unsafe {
            ampr_real_sceKernelMprotect(
                g_apr_native_batch_pool.get() as *const c_void,
                kAprNativeBatchPoolBytes,
                kNativeMicroProt,
            )
        };
        if batchProtectRc != 0 {
            return self.native_pool_init_failed();
        }

        {
            let _lock = SpinLock::from_atomic(unbound_atomic(&self.nativeExecutionPoolLock)).lock();
            self.nativeExecutionPoolReady = true;
        }
        true
    }

    pub(crate) fn ensure_native_micro_slot(
        &mut self,
        job: &mut JobState,
        errorOffset: u32,
    ) -> bool {
        if !self.ensure_native_execution_pool() {
            self.set_fail(
                job,
                c"native-micro-pool".as_ptr(),
                SCE_KERNEL_ERROR_ENOMEM,
                errorOffset,
                0,
            );
            return false;
        }
        let slotIndex = job.poolSlot;
        let slotPtr = apr_native_micro_slot(slotIndex as usize);
        if slotPtr.is_null() || slotIndex >= kJobStatePoolCapacity {
            self.set_fail(
                job,
                c"native-micro-slot".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                errorOffset,
                0,
            );
            return false;
        }
        let slot = unsafe { &mut *slotPtr };
        if !self.nativeMicroTemplateReady[slotIndex as usize] {
            let completion = Op {
                op_type: WRITE_ADDRESS,
                ptra: addr_of_mut!(slot.completion) as u64,
                u64a: kAprNativeMicroCompletionDone,
                u8a: 0,
                ..Op::default()
            };
            let mut completionLayout = PackedOpLayout::default();
            let layoutRc = unsafe { ampr_op_layout_checked(&completion, &mut completionLayout) };
            if layoutRc != 0
                || packed_layout_bytes(&completionLayout) != kAprNativeMicroCompletionBytes
            {
                let rc = if layoutRc != 0 {
                    layoutRc
                } else {
                    SCE_KERNEL_ERROR_EINVAL
                };
                self.set_fail(job, c"native-micro-template".as_ptr(), rc, errorOffset, 0);
                return false;
            }
            let mut view = cb_view();
            view.buffer = slot.completionTemplate.as_mut_ptr().cast();
            view.bufsize = kAprNativeMicroCompletionBytes;
            let writeRc =
                unsafe { ampr_write_op_with_layout(&mut view, 0, &completion, &completionLayout) };
            if writeRc != 0 {
                self.set_fail(
                    job,
                    c"native-micro-template".as_ptr(),
                    writeRc,
                    errorOffset,
                    0,
                );
                return false;
            }
            self.nativeMicroTemplateReady[slotIndex as usize] = true;
        }
        job.nativeCommandBuffer = slot.commands.as_mut_ptr().cast();
        job.nativeCompletionAddress = addr_of_mut!(slot.completion);
        true
    }
}

fn unbound_atomic<'a>(a: &AtomicU32) -> &'a AtomicU32 {
    unsafe { &*(a as *const AtomicU32) }
}

/// Empty `SceAmprCommandBuffer` view.
fn cb_view() -> SceAmprCommandBuffer {
    SceAmprCommandBuffer {
        r#type: 0,
        offset: 0,
        num: 0,
        bufsize: 0,
        buffer: null_mut(),
    }
}

// ---- debug job timing (stats.rs job_*) ----
// Every helper compiles to nothing in release builds (no fields, no clock call).

use crate::rt::stats::{self, Stat};

impl JobState {
    /// Submit accepted (submit.rs): starts job_first_issue_ns.
    #[inline(always)]
    pub(crate) fn stat_accepted(&mut self) {
        #[cfg(feature = "mem_report")]
        {
            self.statAcceptNs = crate::rt::stats::now();
        }
    }

    /// A read slice was accepted by kernel AIO or the pread pool
    /// (admission.rs account_active_read_accept); the first one per job ends
    /// job_first_issue_ns.
    #[inline(always)]
    pub(crate) fn stat_read_issued(&mut self) {
        #[cfg(feature = "mem_report")]
        let start = core::mem::take(&mut self.statAcceptNs);
        #[cfg(not(feature = "mem_report"))]
        let start = 0;
        stats::span(
            start,
            Stat::JobFirstIssues,
            Stat::JobFirstIssueNs,
            Stat::JobFirstIssueNsMax,
        );
    }

    /// The reactor saw one of the job's read chains complete
    /// (backoff.rs mark_seq_complete): starts or restarts job_notify_ns.
    #[inline(always)]
    pub(crate) fn stat_read_done(&mut self) {
        #[cfg(feature = "mem_report")]
        {
            self.statReadDoneNs = crate::rt::stats::now();
        }
    }

    /// The job told the game something after its reads (native.rs fence-clear
    /// command or deferred EOP release, worker.rs result publish): ends
    /// job_notify_ns if a read completed since the last notify.
    #[inline(always)]
    pub(crate) fn stat_notified(&mut self) {
        #[cfg(feature = "mem_report")]
        let start = core::mem::take(&mut self.statReadDoneNs);
        #[cfg(not(feature = "mem_report"))]
        let start = 0;
        stats::span(
            start,
            Stat::JobNotifies,
            Stat::JobNotifyNs,
            Stat::JobNotifyNsMax,
        );
    }
}

// ---- debug gather/scatter retry check (stats.rs gs_retry_*) ----
// Upstream failure class: a retry re-resolved a gather/scatter read from the
// per-lane cursor after another job had advanced it, and read another file.
// The same shape is here: one GatherScatterState per
// priority lane (mod.rs gatherScatterStates), and native.rs
// progress_software_read_command re-resolves from it whenever no retained read
// chain matches. Debug builds compare each re-resolution with the first one.

/// The first lane-cursor resolution of one gather/scatter command of a job.
#[cfg(any(test, feature = "mem_report"))]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct GsPrepRecord {
    /// Source offset + 1 of the command (0: nothing recorded).
    pub(crate) mark: u32,
    pub(crate) commandIndex: u32,
    pub(crate) fileId: u32,
    pub(crate) offset: u64,
    /// A mismatch of this command was already logged (counted every time).
    pub(crate) logged: bool,
}

/// What `GsPrepRecord::check` found.
#[cfg(any(test, feature = "mem_report"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum GsCheck {
    /// First resolution of this command: recorded, nothing to compare.
    Prepared,
    /// A re-resolution with the recorded file id and offset.
    Match,
    /// A re-resolution with another file id or offset; `first` is true once
    /// per command, for the log entry.
    Mismatch { first: bool },
}

#[cfg(any(test, feature = "mem_report"))]
impl GsPrepRecord {
    /// Records or compares one resolution of the command at `bufOffset`
    /// (`commandIndex` in the job's command order). A command other than the
    /// recorded one starts a new record. `bufOffset` is below the job's u32
    /// `sourceBytes`, so `bufOffset + 1` does not wrap.
    pub(crate) fn check(
        &mut self,
        commandIndex: u32,
        bufOffset: u32,
        fileId: u32,
        offset: u64,
    ) -> GsCheck {
        let mark = bufOffset.wrapping_add(1);
        if self.mark != mark || self.commandIndex != commandIndex {
            *self = Self {
                mark,
                commandIndex,
                fileId,
                offset,
                logged: false,
            };
            return GsCheck::Prepared;
        }
        if self.fileId == fileId && self.offset == offset {
            return GsCheck::Match;
        }
        let first = !self.logged;
        self.logged = true;
        GsCheck::Mismatch { first }
    }
}

impl JobState {
    /// A gather/scatter read at the cursor resolved from the lane cursor
    /// (native.rs progress_software_read_command) to `fileId`/`offset`. The
    /// first resolution of a command is its prepare record; a later one is a
    /// retry and counts gs_retry_checks, and gs_retry_mismatches plus a 'G'
    /// event when it differs. Never fails the read: the check only reports.
    #[inline(always)]
    pub(crate) fn stat_gs_resolved(&mut self, bufOffset: u32, fileId: u32, offset: u64) {
        #[cfg(feature = "mem_report")]
        let (retry, mismatch) = {
            let prep = (self.gsPrep.fileId, self.gsPrep.offset);
            let commandIndex = self.sourceCommandIndex;
            match self.gsPrep.check(commandIndex, bufOffset, fileId, offset) {
                GsCheck::Prepared => (false, false),
                GsCheck::Match => (true, false),
                GsCheck::Mismatch { first } => {
                    if first {
                        stats::gs_retry_mismatch(
                            SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE as i64,
                            prep,
                            (fileId, offset),
                        );
                    }
                    (true, true)
                }
            }
        };
        #[cfg(not(feature = "mem_report"))]
        let (retry, mismatch) = {
            let _ = (bufOffset, fileId, offset);
            (false, false)
        };
        if retry {
            stats::add(Stat::GsRetryChecks, 1);
        }
        if mismatch {
            stats::add(Stat::GsRetryMismatches, 1);
        }
    }
}

#[cfg(test)]
mod gs_retry_tests {
    use super::*;

    fn read_op(op_type: OpType, fileId: u32, buffer: u64, length: u64, offset: u64) -> Op {
        Op {
            op_type,
            u32a: fileId,
            ptra: buffer,
            u64a: length,
            u64b: offset,
            ..Op::default()
        }
    }

    fn resolve(gs: &GatherScatterState, op: &Op) -> SoftwareRead {
        let mut read = SoftwareRead {
            fileId: 0,
            buffer: null_mut(),
            length: 0,
            offset: 0,
        };
        assert_eq!(AprAioReactor::resolve_software_read(gs, op, &mut read), 0);
        read
    }

    /// Two jobs on one lane cursor, job A's scatter read prepared and then
    /// retried (not issued, so the lane cursor did not advance for it), the
    /// way native.rs progress_software_read_command re-resolves it when no
    /// read chain is retained.
    #[test]
    fn retry_of_prepared_scatter_read_on_shared_lane() {
        let mut lane = GatherScatterState::default();
        // Job A: an explicit file read (fid 7) sets the lane cursor.
        let a0 = read_op(APR_READ_FILE, 7, 0x10000, 0x100, 0x1000);
        let r = resolve(&lane, &a0);
        AprAioReactor::update_software_gs_cursor(&mut lane, &r);

        // Job A, command 1: a scatter read takes fid and offset from the lane.
        let mut a = GsPrepRecord::default();
        let a1 = read_op(APR_READ_SCATTER, 0, 0x20000, 0x200, 0);
        let prep = resolve(&lane, &a1);
        assert_eq!((prep.fileId, prep.offset), (7, 0x1100));
        let c = a.check(1, 0x40, prep.fileId, prep.offset);
        assert_eq!(c, GsCheck::Prepared);

        // Forced retry with the lane untouched: the prepared fid is read.
        let retry = resolve(&lane, &a1);
        assert_eq!(retry.fileId, prep.fileId);
        assert_eq!(a.check(1, 0x40, retry.fileId, retry.offset), GsCheck::Match);

        // Job B advances the same lane (cross-EOP read-ahead or lane overlap,
        // both off in release): the retry now resolves to B's file.
        let b0 = read_op(APR_READ_FILE, 9, 0x30000, 0x40, 0x5000);
        let r = resolve(&lane, &b0);
        AprAioReactor::update_software_gs_cursor(&mut lane, &r);
        let retry = resolve(&lane, &a1);
        assert_eq!((retry.fileId, retry.offset), (9, 0x5040));
        let c = a.check(1, 0x40, retry.fileId, retry.offset);
        assert_eq!(c, GsCheck::Mismatch { first: true });
        let c = a.check(1, 0x40, retry.fileId, retry.offset);
        assert_eq!(c, GsCheck::Mismatch { first: false });
        assert_eq!((a.fileId, a.offset), (7, 0x1100));

        // Job A's next command starts a new record.
        assert_eq!(a.check(2, 0x80, 9, 0x5040), GsCheck::Prepared);
    }
}
