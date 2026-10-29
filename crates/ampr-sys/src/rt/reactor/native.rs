//! Native batch append, native micro submit/retry and per-job command progress.

use super::*;

impl AprAioReactor {
    pub(crate) fn native_batches_idle(&self) -> bool {
        if !self.nativeExecutionPoolReady {
            return true;
        }
        self.nativeBatchLanes.iter().all(|lane| {
            lane.activeBuffer < 0
                && lane
                    .buffers
                    .iter()
                    .all(|s| s.phase == NativeBatchPhase::Free)
        })
    }

    /// True while any lane has issued groups not yet completed (this covers a
    /// blocking wait, which is cleared lazily), a deferred EOP release or an
    /// unsealed open group. A parked, fully completed Active buffer is not
    /// pending work (unlike `native_batches_idle`).
    pub(crate) fn native_batch_work_pending(&self) -> bool {
        if !self.nativeExecutionPoolReady {
            return false;
        }
        self.nativeBatchLanes.iter().any(|lane| {
            lane.deferredReleaseSequence != 0
                || !Self::native_batch_sequence_reached(lane.completedSequence, lane.issuedSequence)
                || lane
                    .buffers
                    .iter()
                    .any(|s| s.phase != NativeBatchPhase::Free && s.openGroupPackets != 0)
        })
    }

    /// Defaults: `deferRelease = false`, `releaseReadSequence = 0`.
    pub(crate) fn append_native_apr_batch(
        &mut self,
        job: &mut JobState,
        op: &Op,
        packedSource: *const c_void,
        packedBytes: u32,
        deferRelease: bool,
        releaseReadSequence: u64,
    ) -> bool {
        if !self.ensure_native_execution_pool() {
            self.set_fail(
                job,
                c"native-batch-pool".as_ptr(),
                SCE_KERNEL_ERROR_ENOMEM,
                op.buf_offset_bytes,
                0,
            );
            return false;
        }
        if packedSource.is_null() || packedBytes < 4 || packedBytes > 20 || packedBytes & 3 != 0 {
            self.set_fail(
                job,
                c"native-batch-command-size".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                op.buf_offset_bytes,
                0,
            );
            return false;
        }

        let li = job.prioIndex as usize;
        let lane: *mut NativeBatchLane = &mut self.nativeBatchLanes[li];
        unsafe {
            if deferRelease {
                if !Self::software_op_is_native_apr_eop(op) || (*lane).deferredReleaseSequence != 0
                {
                    abort();
                }
                // Release the open SOP group before dedicating a gated group
                // to the completion packet.
                if !self.seal_open_native_apr_batch_group(li as u32) {
                    return false;
                }
            }
            let mut bufferIndex = (*lane).activeBuffer as i32;
            if bufferIndex >= 0 {
                let active = &(*lane).buffers[bufferIndex as usize];
                if active.phase != NativeBatchPhase::Active
                    || active.nextGroup >= kAprNativeBatchGroupCount
                {
                    bufferIndex = -1;
                }
            }
            if bufferIndex < 0 {
                if let Some(c) = (*lane).buffers.iter().position(|s| {
                    s.phase == NativeBatchPhase::Filling && s.nextGroup < kAprNativeBatchGroupCount
                }) {
                    bufferIndex = c as i32;
                }
            }
            if bufferIndex < 0 {
                if let Some(c) = (*lane)
                    .buffers
                    .iter()
                    .position(|s| s.phase == NativeBatchPhase::Free)
                {
                    self.reset_native_batch_buffer(
                        li as u32,
                        c as u32,
                        job.nativeSubmitType as u32,
                    );
                    bufferIndex = c as i32;
                }
            }
            if bufferIndex < 0 {
                return false;
            }
            let bi = bufferIndex as usize;

            let state: *mut NativeBatchState = &mut (*lane).buffers[bi];
            if (*state).nativeSubmitType != job.nativeSubmitType as u32 {
                abort();
            }
            let slot = apr_native_batch_slot(li, bi);
            if slot.is_null()
                || (*state).nextGroup >= kAprNativeBatchGroupCount
                || (*state).openGroupPackets >= kAprNativeBatchPacketsPerGroup
                || (deferRelease && (*state).openGroupPackets != 0)
            {
                return false;
            }

            let groupIndex = (*state).nextGroup;
            let packetIndex = (*state).openGroupPackets;
            let groupOffset = groupIndex * kAprNativeBatchGroupBytes;
            let payloadOffset = groupOffset
                + kAprNativeBatchGateBytes
                + packetIndex * kAprNativeBatchPayloadSlotBytes;
            let paddingBytes = kAprNativeBatchPayloadSlotBytes - packedBytes;
            let dst = (addr_of_mut!((*slot).commands) as *mut u8).add(payloadOffset as usize);
            ptr::copy_nonoverlapping(packedSource as *const u8, dst, packedBytes as usize);
            let paddingHeaderIndex = (paddingBytes / 4 - 1) as usize;
            let hdr = self.nativeBatchPaddingHeaders[paddingHeaderIndex];
            ptr::copy_nonoverlapping(addr_of!(hdr) as *const u8, dst.add(packedBytes as usize), 4);

            (*state).openGroupPackets += 1;
            (*state).packetCount += 1;
            let groupSequence = (*lane).issuedSequence.wrapping_add(1);
            if groupSequence == 0 {
                abort();
            }
            if op.op_type == WAIT_ON_COUNTER {
                (*lane).blockingWaitSequence = groupSequence;
            }

            job.nativeMicroEngine = NativeMicroEngine::AprBatch;
            job.nativeBatchSequence = groupSequence;
            job.nativeCompletionAddress = null_mut();
            job.nativeCommandBuffer = null_mut();
            job.nativeSubmitBytes = packedBytes;
            job.nativeSubmitFirstType = op.op_type;
            job.nativeSourceOffset = op.buf_offset_bytes;
            job.nativeSourceType = op.op_type;
            job.nativeSubmitTimeNs = if (*state).phase == NativeBatchPhase::Active {
                time_counter_now()
            } else {
                0
            };
            job.nativeSubmitted.store(true, Ordering::Release);

            let mustSeal = (*state).openGroupPackets == kAprNativeBatchPacketsPerGroup
                || op.op_type == WAIT_ON_COUNTER
                || deferRelease;
            if mustSeal && !self.seal_native_apr_batch_group(li as u32, bi as u32, !deferRelease) {
                abort();
            }
            if deferRelease {
                (*lane).deferredReleaseSequence = groupSequence;
                (*lane).deferredReleaseJobId = job.id;
                (*lane).deferredReleaseBufferIndex = bi as u32;
                (*lane).deferredReleaseGroupIndex = groupIndex;
                job.nativeBatchReleasePending = true;
                job.nativeBatchReleaseReadSequence = releaseReadSequence;
                self.reset_publish_gating_active_aio_poll_backoff_for_lane(
                    li as u32,
                    time_counter_now(),
                );
            }
        }
        true
    }
}

impl AprAioReactor {
    pub(crate) fn prepare_native_micro_pair(
        &mut self,
        job: &mut JobState,
        firstOp: &Op,
        packedSource: *const c_void,
        packedBytes: u32,
        encodeFirst: bool,
    ) -> bool {
        let off = firstOp.buf_offset_bytes;
        if !self.ensure_native_micro_slot(job, off) {
            return false;
        }
        let slot = apr_native_micro_slot(job.poolSlot as usize);
        let cmds = if slot.is_null() {
            null_mut()
        } else {
            unsafe { addr_of_mut!((*slot).commands) as *mut u8 }
        };
        if slot.is_null()
            || job.nativeCommandBuffer.is_null()
            || job.nativeCommandBuffer != cmds as *mut c_void
        {
            self.set_fail(
                job,
                c"native-micro-slot".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                off,
                0,
            );
            return false;
        }
        const CAP: u32 = kAprNativeMicroCommandCapacity;

        let mut firstBytes = packedBytes;
        let (a, b, c, ua, ub) = (
            firstOp.u64a,
            firstOp.u64b,
            firstOp.u64c,
            firstOp.u32a as u64,
            firstOp.u32b as u64,
        );
        let write = |dst: *mut c_void, out: *mut u64| -> c_int {
            match firstOp.op_type {
                AMM_MAP => unsafe { ammWriteMapCommand2(dst, a, b, ub, ua, 0, out) },
                AMM_MAP_DIRECT => unsafe { ammWriteMapDirectCommand(dst, a, b, c, ub, ua, out) },
                _ => SCE_KERNEL_ERROR_EINVAL,
            }
        };
        if encodeFirst {
            let mut measuredBytes: u64 = 0;
            let sizeRc = write(null_mut(), &mut measuredBytes);
            if sizeRc != 0 || measuredBytes == 0 || measuredBytes > u32::MAX as u64 {
                let rc = if sizeRc != 0 {
                    sizeRc
                } else {
                    SCE_KERNEL_ERROR_EINVAL
                };
                self.set_fail(job, c"native-micro-size".as_ptr(), rc, off, 0);
                return false;
            }
            firstBytes = measuredBytes as u32;
            if firstBytes > CAP {
                self.set_fail(
                    job,
                    c"native-micro-size".as_ptr(),
                    SCE_KERNEL_ERROR_EBUSY,
                    off,
                    0,
                );
                return false;
            }
            let writeRc = write(cmds as *mut c_void, null_mut());
            if writeRc != 0 {
                self.set_fail(job, c"native-micro-encode".as_ptr(), writeRc, off, 0);
                return false;
            }
        } else {
            if packedSource.is_null() || firstBytes == 0 || firstBytes > CAP {
                self.set_fail(
                    job,
                    c"native-micro-copy".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    off,
                    0,
                );
                return false;
            }
            unsafe {
                ptr::copy_nonoverlapping(packedSource as *const u8, cmds, firstBytes as usize)
            };
        }

        if firstBytes < 4
            || firstBytes > 20
            || firstBytes & 3 != 0
            || firstBytes > CAP - kAprNativeMicroCompletionBytes
        {
            self.set_fail(
                job,
                c"native-micro-template".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                off,
                0,
            );
            return false;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                addr_of!((*slot).completionTemplate) as *const u8,
                cmds.add(firstBytes as usize),
                kAprNativeMicroCompletionBytes as usize,
            );
            ptr::write_volatile(addr_of_mut!((*slot).completion), 0);
            fence(Ordering::SeqCst);
            job.nativeCompletionAddress = addr_of_mut!((*slot).completion);
        }
        job.nativeSubmitBytes = firstBytes + kAprNativeMicroCompletionBytes;
        job.nativeSubmitFirstType = firstOp.op_type;
        job.nativeSourceOffset = off;
        job.nativeSourceType = firstOp.op_type;
        job.nativeSubmitTimeNs = 0;
        true
    }

    pub(crate) fn submit_native_micro(
        &mut self,
        job: &mut JobState,
        engine: NativeMicroEngine,
    ) -> bool {
        job.nativeMicroEngine = engine;
        let mut submitted = false;
        if engine == NativeMicroEngine::Amm {
            let submitRc = unsafe {
                ammTrySubmitCommandBufferLeaf(
                    job.nativeCommandBuffer as u64,
                    job.nativeSubmitBytes,
                    kAprNativeMicroAmmPriority,
                )
            };
            if submitRc == kAmmSubmitRetryRc {
                // No native ownership yet; keep the prepared packet and cursor.
                job.nativeSubmitRetryAtNs = time_counter_now() + 200_000;
                return false;
            }
            job.nativeSubmitRetryAtNs = 0;
            if submitRc == 0 {
                submitted = true;
            } else {
                let off = job.nativeSourceOffset;
                self.set_fail(job, c"native-amm-submit".as_ptr(), submitRc, off, 0);
            }
        } else if engine == NativeMicroEngine::Apr {
            let slot = apr_native_micro_slot(job.poolSlot as usize);
            if slot.is_null() || job.nativeMicroSubmitId != 0 {
                abort();
            }
            let mut cb = NativeAprCommandBufferView::default();
            cb.m_commandBuffer.r#type = job.nativeSubmitType;
            cb.m_commandBuffer.offset = job.nativeSubmitBytes;
            cb.m_commandBuffer.num = 2;
            cb.m_commandBuffer.bufsize = kAprNativeMicroCommandCapacity;
            let mut submitRcRaw: c_int = 0;
            let mut submitId: SceAprSubmitId = 0;
            let dispatchRc = unsafe {
                cb.m_commandBuffer.buffer = addr_of_mut!((*slot).commands) as *mut c_void;
                (*slot).result.error_offset = 0;
                AtomicI32::from_ptr(addr_of_mut!((*slot).result.result))
                    .store(kAprNativeMicroResultPending, Ordering::Relaxed);
                fence(Ordering::SeqCst);
                apr_native_submit_dispatch(
                    &mut cb,
                    job.prioIndex as u32,
                    AprSubmitMode::kSubmitAndGetResult,
                    addr_of_mut!((*slot).result),
                    &mut submitId,
                    &mut submitRcRaw,
                )
            };
            let submitRc = if dispatchRc != 0 {
                dispatchRc
            } else {
                apr_libkernel_rc_to_sce(submitRcRaw)
            };
            if submitRc == 0 && submitId != 0 {
                job.nativeMicroSubmitId = submitId;
                submitted = true;
            } else {
                let rc = if submitRc != 0 {
                    submitRc
                } else {
                    SCE_KERNEL_ERROR_EIO
                };
                let off = job.nativeSourceOffset;
                self.set_fail(job, c"native-apr-micro-submit".as_ptr(), rc, off, 0);
            }
        }
        if !submitted {
            if Self::job_failed(job) {
                job.result.errorOffset = job.nativeSourceOffset;
            }
            job.nativeMicroEngine = NativeMicroEngine::None;
            return false;
        }
        job.nativeSubmitTimeNs = time_counter_now();
        job.nativeSubmitted.store(true, Ordering::Release);
        true
    }

    pub(crate) fn retry_native_amm_micro(&mut self, job: &mut JobState) -> bool {
        if time_counter_now() < job.nativeSubmitRetryAtNs {
            return false;
        }
        if !self.submit_native_micro(job, NativeMicroEngine::Amm) {
            return false;
        }
        if job.nativeRetryMapBegin {
            job.mapActive = true;
        }
        Self::advance_job_source(job, job.nativeRetrySourceBytes);
        job.nativeRetrySourceBytes = 0;
        job.nativeRetryMapBegin = false;
        true
    }
}

/// `*job` as `&mut JobState` (JobPtr is a raw pointer).
macro_rules! j {
    ($job:expr) => {
        unsafe { &mut **$job }
    };
}

impl AprAioReactor {
    pub(crate) fn progress_job(
        &mut self,
        job: &mut JobPtr,
        priorReadFencePending: bool,
        priorNativeBatchPending: bool,
        _speculativeCommandUsed: &mut bool,
        readIssueBudget: &mut ReadIssueBudget,
        admission: &mut AioAdmissionContext,
    ) -> bool {
        if job.is_null() {
            return false;
        }
        let mut progressed = false;
        let sourceOffsetAtEntry = j!(job).sourceOffset;

        if j!(job).nativeSubmitted.load(Ordering::Acquire) {
            if !self.native_micro_completion_observed(j!(job)) {
                if j!(job).nativeMicroEngine != NativeMicroEngine::AprBatch {
                    return false;
                }
            } else {
                progressed = true;
            }
        }
        if self.publish_deferred_cross_eop_error(j!(job)) {
            progressed = true;
        }
        if j!(job).nativeBatchReleasePending {
            let jb = j!(job);
            if Self::job_failed(jb) {
                if !self.release_deferred_native_eop(jb, true) {
                    abort();
                }
                progressed = true;
            } else if !priorReadFencePending
                && (jb.nativeBatchReleaseReadSequence == 0
                    || jb.completedReadSeq >= jb.nativeBatchReleaseReadSequence)
            {
                if jb.sourceOffset != jb.nativeSourceOffset
                    || jb.decodedOpCacheBytes != jb.nativeSubmitBytes
                    || jb.decodedOpCache.buf_offset_bytes != jb.nativeSourceOffset
                    || jb.decodedOpCache.op_type != jb.nativeSourceType
                    || !Self::software_op_is_native_apr_eop(&jb.decodedOpCache)
                    || jb.nativeSubmitBytes == 0
                {
                    abort();
                }
                let completedOpBytes = jb.nativeSubmitBytes;
                if !self.release_deferred_native_eop(jb, false) {
                    abort();
                }
                Self::advance_job_source(jb, completedOpBytes);
                progressed = true;
            } else {
                return progressed;
            }
        }
        if Self::job_failed(j!(job)) {
            j!(job).nativeSubmitRetryAtNs = 0;
            self.maybe_release_reactor_job(job);
            return progressed;
        }
        if j!(job).nativeSubmitRetryAtNs != 0 {
            return self.retry_native_amm_micro(j!(job)) || progressed;
        }
        if j!(job).sourceOffset != sourceOffsetAtEntry {
            // Releasing a deferred EOP consumed this lane's one cursor command
            // for the current reactor cycle.
            self.maybe_release_reactor_job(job);
            return true;
        }
        let gs: *mut GatherScatterState = &mut self.gatherScatterStates[j!(job).prioIndex as usize];
        if self.progress_job_commands(
            job,
            gs,
            priorReadFencePending,
            priorNativeBatchPending,
            readIssueBudget,
            admission,
        ) {
            progressed = true;
        }

        let jb = j!(job);
        if !Self::job_failed(jb)
            && jb.sourceOffset == jb.sourceBytes
            && (!jb.nativeSubmitted.load(Ordering::Acquire)
                || jb.nativeMicroEngine == NativeMicroEngine::AprBatch)
            && !Self::job_processing_complete(jb)
        {
            if jb.sourceCommandIndex != jb.commandCount {
                let off = jb.sourceOffset;
                self.set_fail(
                    jb,
                    c"software-command-count".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    off,
                    0,
                );
            } else {
                Self::finish_job_processing(jb);
            }
            progressed = true;
        }

        self.maybe_release_reactor_job(job);
        progressed
    }

    /// The `while (job->sourceOffset < job->sourceBytes)` loop of `progress_job`;
    /// returns whether it progressed.
    fn progress_job_commands(
        &mut self,
        job: &mut JobPtr,
        gs: *mut GatherScatterState,
        priorReadFencePending: bool,
        priorNativeBatchPending: bool,
        readIssueBudget: &mut ReadIssueBudget,
        admission: &mut AioAdmissionContext,
    ) -> bool {
        let gs = unsafe { &mut *gs };
        let mut progressed = false;
        let mut continueReadGrouping = false;
        let mut continueWithAdjacentEqueue = false;
        while j!(job).sourceOffset < j!(job).sourceBytes {
            if self.publish_deferred_cross_eop_error(j!(job)) {
                progressed = true;
                break;
            }
            if self.native_batch_wait_pending(j!(job).prioIndex as u32) {
                break;
            }
            let jb = j!(job);
            let mut opBytes: u32 = 0;
            // `op` is a copy of the cached decode or a fresh decode.
            let Some(op) = self.decode_job_command(jb, &mut opBytes) else {
                break;
            };
            let op = &op;

            if AMPR_EMU_APR_LOCAL_EQUEUE && continueWithAdjacentEqueue {
                continueWithAdjacentEqueue = false;
                if op.op_type != WRITE_EQUEUE {
                    Self::cache_decoded_op(jb, op, opBytes);
                    break;
                }
            }

            // After consecutive reads end, the cursor stays parked on the boundary.
            if continueReadGrouping && !cb_op_is_apr_read(op.op_type) {
                Self::cache_decoded_op(jb, op, opBytes);
                break;
            }
            continueReadGrouping = false;

            let flow = if cb_op_is_apr_read(op.op_type) {
                self.progress_software_read_command(
                    job,
                    gs,
                    op,
                    opBytes,
                    readIssueBudget,
                    admission,
                    &mut progressed,
                )
            } else if op.op_type == APR_RESET_GATHER_SCATTER {
                Self::reset_software_gs_cursor(gs);
                Self::advance_job_source(jb, opBytes);
                progressed = true;
                CommandFlow::Stop
            } else if Self::software_op_is_marker_or_nop(op.op_type) {
                Self::advance_job_source(jb, opBytes);
                progressed = true;
                CommandFlow::Stop
            } else {
                self.progress_native_or_address_command(
                    jb,
                    op,
                    opBytes,
                    priorReadFencePending,
                    priorNativeBatchPending,
                    readIssueBudget,
                    &mut progressed,
                )
            };
            match flow {
                CommandFlow::Stop => break,
                CommandFlow::GroupReads => continueReadGrouping = true,
                CommandFlow::AdjacentEqueue => continueWithAdjacentEqueue = true,
            }
        }
        progressed
    }
}

/// How `progress_job_commands` goes on after one command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandFlow {
    /// Leave the command loop.
    Stop,
    /// Decode the next command; only another APR read may follow.
    GroupReads,
    /// Decode the next command; only an adjacent local equeue write may follow.
    AdjacentEqueue,
}

/// True while the read quantum still has a request and a credit granule left.
#[inline]
fn read_budget_open(b: &ReadIssueBudget) -> bool {
    b.requestsLeft != 0 && b.bytesLeft >= AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES
}

impl AprAioReactor {
    /// The command at the job's source cursor: the cached decode while it is
    /// still at the cursor, else a fresh decode. None after a decode error
    /// (recorded on the job).
    #[inline]
    fn decode_job_command(&mut self, jb: &mut JobState, opBytes: &mut u32) -> Option<Op> {
        let remainingBytes = jb.sourceBytes - jb.sourceOffset;
        if jb.decodedOpCacheBytes != 0
            && jb.decodedOpCache.buf_offset_bytes == jb.sourceOffset
            && jb.decodedOpCacheBytes <= remainingBytes
        {
            *opBytes = jb.decodedOpCacheBytes;
            return Some(jb.decodedOpCache);
        }
        Self::clear_decoded_op(jb);
        let mut decodedOp = Op::default();
        let mut errorOffset = jb.sourceOffset;
        let decodeRc = unsafe {
            ampr_decode_apr_packed_op(
                jb.sourceBuffer as *const c_void,
                jb.sourceBytes,
                jb.sourceOffset,
                &mut decodedOp,
                opBytes,
                &mut errorOffset,
            )
        };
        if decodeRc != 0 || *opBytes == 0 || *opBytes > remainingBytes {
            let rc = if decodeRc != 0 {
                decodeRc
            } else {
                SCE_KERNEL_ERROR_EINVAL
            };
            self.set_command_error(jb, c"software-decode".as_ptr(), rc, errorOffset, 0);
            return None;
        }
        decodedOp.buf_offset_bytes = jb.sourceOffset;
        Some(decodedOp)
    }

    /// One APR read command: resolves (or retries the chain-owned) read,
    /// coalesces the adjacent reads and issues them.
    #[allow(clippy::too_many_arguments)]
    fn progress_software_read_command(
        &mut self,
        job: &mut JobPtr,
        gs: &mut GatherScatterState,
        op: &Op,
        opBytes: u32,
        readIssueBudget: &mut ReadIssueBudget,
        admission: &mut AioAdmissionContext,
        progressed: &mut bool,
    ) -> CommandFlow {
        let jb = j!(job);
        let mut read = SoftwareRead::default();
        let chain = jb.cursorReadChain;
        let retainedChainAtCursor = self.read_chain_is_live(chain)
            && unsafe {
                (*chain).job == *job
                    && (*chain).commandIndex == jb.sourceCommandIndex as usize
                    && (*chain).ownerDesc.errorOff == op.buf_offset_bytes
            };
        let mut readRc = 0;
        if retainedChainAtCursor {
            // Retry the descriptor already owned by the chain.
            let d = unsafe { &(*chain).ownerDesc };
            read.fileId = d.fileId;
            read.buffer = d.buffer;
            read.length = d.length;
            read.offset = d.offset;
        } else {
            readRc = Self::resolve_software_read(gs, op, &mut read);
        }
        if readRc != 0 {
            self.set_command_error(
                jb,
                c"software-read-state".as_ptr(),
                readRc,
                op.buf_offset_bytes,
                0,
            );
            return CommandFlow::Stop;
        }
        let coalesced = Self::coalesce_adjacent_reads(jb, gs, op, opBytes, &read);
        let commandIndex = jb.sourceCommandIndex as usize;
        let mut logicalIssued = false;
        if !self.issue_software_read(
            job,
            gs,
            &coalesced.read,
            coalesced.sourceBytes,
            op.buf_offset_bytes,
            commandIndex,
            admission,
            true,
            false,
            &mut logicalIssued,
            readIssueBudget,
            coalesced.commandCount,
            &coalesced.finalGs,
            coalesced.gatherScatterCommandCount,
            null_mut(),
        ) {
            let jb = j!(job);
            if !Self::job_failed(jb) {
                Self::cache_decoded_op(jb, op, opBytes);
            }
            return CommandFlow::Stop;
        }
        *progressed = true;
        // Consecutive APR reads share the remaining request/byte quantum.
        if logicalIssued && read_budget_open(readIssueBudget) {
            return CommandFlow::GroupReads;
        }
        CommandFlow::Stop
    }

    /// Any command other than an APR read, gather-scatter reset or marker:
    /// gated by the read fence and pending native batches, then run as a map
    /// end, software address op, local equeue write or native micro op.
    #[allow(clippy::too_many_arguments)]
    fn progress_native_or_address_command(
        &mut self,
        jb: &mut JobState,
        op: &Op,
        opBytes: u32,
        priorReadFencePending: bool,
        priorNativeBatchPending: bool,
        readIssueBudget: &ReadIssueBudget,
        progressed: &mut bool,
    ) -> CommandFlow {
        // SOPs overlap the AIO reactor; EOPs and map transitions stay behind
        // the software read fence.
        let nativeBatchPending = jb.nativeSubmitted.load(Ordering::Acquire)
            && jb.nativeMicroEngine == NativeMicroEngine::AprBatch;
        let completionReadSequence = jb.latestSubmittedReadSeq;
        let readFencePending =
            priorReadFencePending || jb.completedReadSeq < completionReadSequence;
        let packedSource =
            unsafe { jb.sourceBuffer.add(jb.sourceOffset as usize) } as *const c_void;
        if readFencePending && Self::software_op_is_native_apr_eop(op) {
            if !self.append_native_apr_batch(
                jb,
                op,
                packedSource,
                opBytes,
                true,
                completionReadSequence,
            ) {
                if !Self::job_failed(jb) {
                    Self::cache_decoded_op(jb, op, opBytes);
                }
                return CommandFlow::Stop;
            }
            Self::cache_decoded_op(jb, op, opBytes);
            *progressed = true;
            return CommandFlow::Stop;
        }
        if readFencePending && !Self::software_op_is_sop(op) {
            Self::cache_decoded_op(jb, op, opBytes);
            return CommandFlow::Stop;
        }
        if (priorNativeBatchPending || nativeBatchPending)
            && ((!Self::software_op_is_sop(op)
                && !Self::software_op_uses_native_apr_batch(op.op_type))
                || op.op_type == WRITE_EQUEUE)
        {
            Self::cache_decoded_op(jb, op, opBytes);
            return CommandFlow::Stop;
        }
        if op.op_type == APR_MAP_END {
            if !jb.mapActive {
                self.set_command_error(
                    jb,
                    c"software-map-end-state".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    op.buf_offset_bytes,
                    0,
                );
                return CommandFlow::Stop;
            }
            jb.mapActive = false;
            Self::advance_job_source(jb, opBytes);
            *progressed = true;
            return CommandFlow::Stop;
        }
        if let Some(flow) =
            self.progress_software_address_command(jb, op, opBytes, readIssueBudget, progressed)
        {
            return flow;
        }
        if AMPR_EMU_APR_LOCAL_EQUEUE && op.op_type == WRITE_EQUEUE {
            self.progress_local_equeue_command(jb, op, opBytes, packedSource, progressed);
            return CommandFlow::Stop;
        }
        self.progress_native_micro_command(jb, op, opBytes, packedSource, progressed);
        CommandFlow::Stop
    }

    /// Runs `op` as a software address op. None when it is not one; otherwise
    /// how the command loop goes on.
    fn progress_software_address_command(
        &mut self,
        jb: &mut JobState,
        op: &Op,
        opBytes: u32,
        readIssueBudget: &ReadIssueBudget,
        progressed: &mut bool,
    ) -> Option<CommandFlow> {
        let mut softwareAddressHandled = false;
        let mut softwareAddressComplete = false;
        if !self.try_execute_software_address_op(
            jb,
            op,
            &mut softwareAddressHandled,
            &mut softwareAddressComplete,
        ) {
            return Some(CommandFlow::Stop);
        }
        if !softwareAddressHandled {
            return None;
        }
        if !softwareAddressComplete {
            if op.op_type == WAIT_ON_ADDRESS {
                // A sync primitive, not an AIO dependency.
                self.passWaitOnAddressPending = true;
            }
            Self::cache_decoded_op(jb, op, opBytes);
            return Some(CommandFlow::Stop);
        }
        Self::advance_job_source(jb, opBytes);
        *progressed = true;
        if op.op_type == WAIT_ON_ADDRESS && read_budget_open(readIssueBudget) {
            // Reads right behind a satisfied wait may use the remaining quantum.
            return Some(CommandFlow::GroupReads);
        }
        if AMPR_EMU_APR_LOCAL_EQUEUE
            && op.op_type == WRITE_ADDRESS
            && jb.sourceOffset < jb.sourceBytes
        {
            // Decode the one permitted adjacent local-equeue candidate.
            return Some(CommandFlow::AdjacentEqueue);
        }
        Some(CommandFlow::Stop)
    }

    /// A local equeue write: published here, deferred on backpressure or
    /// handed to the native APR batch unchanged.
    fn progress_local_equeue_command(
        &mut self,
        jb: &mut JobState,
        op: &Op,
        opBytes: u32,
        packedSource: *const c_void,
        progressed: &mut bool,
    ) {
        let publish = unsafe {
            apr_equeue_try_publish(op.u64b as usize as SceKernelEqueue, op.u32b as i32, op.u64a)
        };
        match publish {
            AprEqueuePublishResult::Published => {
                Self::advance_job_source(jb, opBytes);
                *progressed = true;
            }
            AprEqueuePublishResult::Backpressure => {
                self.passLocalEqueueBackpressure = true;
                Self::cache_decoded_op(jb, op, opBytes);
            }
            AprEqueuePublishResult::NativeFallback => {
                // Unchanged native APR packet.
                if !self.append_native_apr_batch(jb, op, packedSource, opBytes, false, 0) {
                    if !Self::job_failed(jb) {
                        Self::cache_decoded_op(jb, op, opBytes);
                    }
                    return;
                }
                Self::advance_job_source(jb, opBytes);
                *progressed = true;
            }
        }
    }

    /// A command owned by a native micro engine: map begins and AMM ops go to
    /// the AMM engine, the rest join the native APR batch.
    fn progress_native_micro_command(
        &mut self,
        jb: &mut JobState,
        op: &Op,
        opBytes: u32,
        packedSource: *const c_void,
        progressed: &mut bool,
    ) {
        let mapBegin = op.op_type == APR_MAP_BEGIN || op.op_type == APR_MAP_DIRECT_BEGIN;
        let mut nativeOp = *op;
        let mut engine = NativeMicroEngine::None;
        let mut encodeFirst = false;
        if mapBegin {
            if jb.mapActive {
                self.set_command_error(
                    jb,
                    c"software-map-begin-state".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    op.buf_offset_bytes,
                    0,
                );
                return;
            }
            nativeOp = Op {
                buf_offset_bytes: op.buf_offset_bytes,
                u64a: op.u64a,
                u64b: op.u64b,
                ..Op::default()
            };
            if op.op_type == APR_MAP_BEGIN {
                nativeOp.op_type = AMM_MAP;
                nativeOp.u32a = op.u32a;
                nativeOp.u32b = op.u32b;
            } else {
                nativeOp.op_type = AMM_MAP_DIRECT;
                nativeOp.u64c = op.u64c;
                nativeOp.u32a = op.u32b;
                nativeOp.u32b = op.u32a;
            }
            engine = NativeMicroEngine::Amm;
            encodeFirst = true;
        } else if Self::software_op_uses_amm(op.op_type) {
            engine = NativeMicroEngine::Amm;
        }

        if engine == NativeMicroEngine::None {
            if !Self::software_op_uses_native_apr_batch(op.op_type) {
                self.set_command_error(
                    jb,
                    c"software-native-owner".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    op.buf_offset_bytes,
                    0,
                );
                return;
            }
            if !self.append_native_apr_batch(jb, op, packedSource, opBytes, false, 0) {
                if !Self::job_failed(jb) {
                    Self::cache_decoded_op(jb, op, opBytes);
                }
                return;
            }
            Self::advance_job_source(jb, opBytes);
            *progressed = true;
            return;
        }
        if !self.prepare_native_micro_pair(jb, &nativeOp, packedSource, opBytes, encodeFirst) {
            return;
        }
        if !self.submit_native_micro(jb, engine) {
            if jb.nativeSubmitRetryAtNs != 0 {
                jb.nativeRetrySourceBytes = opBytes;
                jb.nativeRetryMapBegin = mapBegin;
            }
            return;
        }
        if mapBegin {
            jb.mapActive = true;
        }
        Self::advance_job_source(jb, opBytes);
        *progressed = true;
    }
}
