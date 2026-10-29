//! Software op classification, address ops, gather/scatter cursors and software reads.

use super::*;

impl AprAioReactor {
    pub(crate) fn software_op_is_marker_or_nop(t: OpType) -> bool {
        matches!(t, NOP | MARKER_SET | MARKER_PUSH | MARKER_POP)
    }

    pub(crate) fn software_op_is_sop(op: &Op) -> bool {
        match op.op_type {
            WAIT_ON_ADDRESS | WAIT_ON_COUNTER => true,
            WRITE_ADDRESS | WRITE_EQUEUE => op.u8a != 0,
            WRITE_COUNTER => op.u32c != 0,
            WRITE_ADDRESS_FROM_TIME_COUNTER
            | WRITE_ADDRESS_FROM_COUNTER
            | WRITE_ADDRESS_FROM_COUNTER_PAIR => op.u8b != 0,
            _ => false,
        }
    }

    pub(crate) fn software_op_uses_amm(t: OpType) -> bool {
        matches!(
            t,
            AMM_MAP
                | AMM_MAP_DIRECT
                | AMM_UNMAP
                | AMM_REMAP
                | AMM_MULTI_MAP
                | AMM_MODIFY_PROTECT
                | AMM_MODIFY_MTYPE_PROTECT
                | AMM_MAP_AS_PRT
                | AMM_ALLOC_PA_FOR_PRT
                | AMM_REMAP_INTO_PRT
                | AMM_UNMAP_TO_PRT
        )
    }

    pub(crate) fn software_op_uses_native_apr_batch(t: OpType) -> bool {
        match t {
            WAIT_ON_COUNTER
            | WRITE_COUNTER
            | WRITE_ADDRESS_FROM_TIME_COUNTER
            | WRITE_ADDRESS_FROM_COUNTER
            | WRITE_ADDRESS_FROM_COUNTER_PAIR => true,
            WRITE_EQUEUE => !AMPR_EMU_APR_LOCAL_EQUEUE,
            _ => false,
        }
    }

    pub(crate) fn software_op_is_native_apr_eop(op: &Op) -> bool {
        Self::software_op_uses_native_apr_batch(op.op_type) && !Self::software_op_is_sop(op)
    }

    pub(crate) fn software_wait_compare(observed: u64, reference: u64, compare: u32) -> bool {
        const S: u64 = 1 << 63;
        match compare {
            0 => observed == reference,
            1 => observed > reference,
            2 => observed < reference,
            3 => observed != reference,
            4 => observed.wrapping_sub(reference) <= i64::MAX as u64,
            5 => (observed ^ S) > (reference ^ S),
            6 => (observed ^ S) < (reference ^ S),
            _ => false,
        }
    }

    pub(crate) fn try_execute_software_address_op(
        &mut self,
        job: &mut JobState,
        op: &Op,
        outHandled: *mut bool,
        outComplete: *mut bool,
    ) -> bool {
        if outHandled.is_null() || outComplete.is_null() {
            return false;
        }
        unsafe {
            *outHandled = false;
            *outComplete = false;
        }
        if op.op_type != WRITE_ADDRESS && op.op_type != WAIT_ON_ADDRESS {
            return true;
        }
        let wait = op.op_type == WAIT_ON_ADDRESS;
        let addr = op.ptra as usize;
        if addr == 0 || addr & 7 != 0 {
            let (reason, rc) = if wait {
                (
                    c"software-wait-address-invalid",
                    SCE_AMPR_ERROR_APR_INVALIDWAITONADDRESSADDRESS,
                )
            } else {
                (
                    c"software-write-address-invalid",
                    SCE_AMPR_ERROR_APR_INVALIDWRITEADDRESSSOURCE,
                )
            };
            self.set_command_error(job, reason.as_ptr(), rc, op.buf_offset_bytes, 0);
            unsafe { *outHandled = true };
            return false;
        }
        if wait && op.u32a > 6 {
            self.set_command_error(
                job,
                c"software-wait-compare-invalid".as_ptr(),
                SCE_AMPR_ERROR_APR_INVALIDCOMMANDDATAFORMAT,
                op.buf_offset_bytes,
                0,
            );
            unsafe { *outHandled = true };
            return false;
        }
        let address = unsafe { AtomicU64::from_ptr(addr as *mut u64) };
        unsafe { *outHandled = true };
        if !wait {
            address.store(op.u64a, Ordering::Release);
            unsafe { *outComplete = true };
            return true;
        }
        let observed = address.load(Ordering::Acquire);
        unsafe { *outComplete = Self::software_wait_compare(observed, op.u64a, op.u32a) };
        true
    }
}

impl AprAioReactor {
    pub(crate) fn loose_gs_state_view(state: &GatherScatterState) -> AmprLooseGsState {
        AmprLooseGsState {
            nextOffset: state.nextOffset,
            nextBuffer: state.nextBuffer as usize,
            fileId: state.fileId,
        }
    }

    pub(crate) fn gather_scatter_state_from_view(state: &AmprLooseGsState) -> GatherScatterState {
        GatherScatterState {
            nextOffset: state.nextOffset,
            nextBuffer: state.nextBuffer as *mut c_void,
            fileId: state.fileId,
        }
    }

    pub(crate) fn loose_gs_command_from_op(op: &Op, out: *mut AmprLooseGsCommand) -> bool {
        if out.is_null() {
            return false;
        }
        let kind = match op.op_type {
            APR_READ_FILE => AmprLooseGsReadKind::File,
            APR_READ_GATHER => AmprLooseGsReadKind::Gather,
            APR_READ_SCATTER => AmprLooseGsReadKind::Scatter,
            APR_READ_GATHER_SCATTER => AmprLooseGsReadKind::GatherScatter,
            _ => return false,
        };
        let command = AmprLooseGsCommand {
            kind,
            fileId: op.u32a,
            buffer: op.ptra as usize,
            length: op.u64a,
            offset: op.u64b,
        };
        unsafe { *out = command };
        true
    }

    pub(crate) fn software_read_op_is_stateful(op: &Op) -> bool {
        matches!(
            op.op_type,
            APR_READ_GATHER | APR_READ_SCATTER | APR_READ_GATHER_SCATTER
        )
    }

    pub(crate) fn resolve_software_read(
        gs: &GatherScatterState,
        op: &Op,
        out: *mut SoftwareRead,
    ) -> c_int {
        if out.is_null() {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut command = AmprLooseGsCommand::default();
        if !Self::loose_gs_command_from_op(op, &mut command) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let resolved = ampr_loose_gs_resolve(&Self::loose_gs_state_view(gs), &command);
        if !resolved.valid {
            return if Self::software_read_op_is_stateful(op) {
                SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE
            } else {
                SCE_KERNEL_ERROR_EINVAL
            };
        }
        unsafe {
            *out = SoftwareRead {
                fileId: resolved.fileId,
                buffer: resolved.buffer as *mut c_void,
                length: resolved.length,
                offset: resolved.offset,
            };
        }
        0
    }

    pub(crate) fn update_software_gs_cursor(gs: &mut GatherScatterState, read: &SoftwareRead) {
        let resolved = AmprLooseGsResolvedRead {
            fileId: read.fileId,
            buffer: read.buffer as usize,
            length: read.length,
            offset: read.offset,
            valid: read.fileId != 0 && !read.buffer.is_null() && read.length != 0,
        };
        *gs = Self::gather_scatter_state_from_view(&ampr_loose_gs_advance(
            &resolved,
            kSoftwareReadOffsetMaxExclusive,
        ));
    }

    pub(crate) fn reset_software_gs_cursor(gs: &mut GatherScatterState) {
        *gs = GatherScatterState::default();
    }
}

impl AprAioReactor {
    pub(crate) fn coalesce_adjacent_reads(
        job: &JobState,
        initialGs: &GatherScatterState,
        firstOp: &Op,
        firstOpBytes: u32,
        firstRead: &SoftwareRead,
    ) -> CoalescedSoftwareRead {
        let mut result = CoalescedSoftwareRead {
            read: *firstRead,
            finalGs: *initialGs,
            ..Default::default()
        };
        Self::update_software_gs_cursor(&mut result.finalGs, firstRead);
        result.sourceBytes = firstOpBytes;
        result.commandCount = 1;
        result.gatherScatterCommandCount = Self::software_read_op_is_stateful(firstOp) as u32;

        // A retained cursor chain owns the descriptor and GS result chosen on
        // the first attempt; never rebuild it from `initialGs`.
        let chain = job.cursorReadChain;
        if chain.is_null() {
            return result;
        }
        let chain = unsafe { &*chain };
        if chain.commandIndex != job.sourceCommandIndex as usize
            || chain.ownerDesc.errorOff != firstOp.buf_offset_bytes
            || chain.ownerDesc.coalescedCommandCount == 0
            || !chain.hasPendingFinalGs
        {
            return result;
        }
        let retainedCommandCount = chain.ownerDesc.coalescedCommandCount as u32;
        let mut retainedSourceBytes = firstOpBytes;
        let mut cursor = job.sourceOffset.wrapping_add(firstOpBytes);
        let mut valid = firstOpBytes != 0;
        let mut index = 1u32;
        while valid && index < retainedCommandCount {
            let mut op = Op::default();
            let mut opBytes = 0u32;
            let mut errorOffset = cursor;
            let rc = unsafe {
                ampr_decode_apr_packed_op(
                    job.sourceBuffer.cast(),
                    job.sourceBytes,
                    cursor,
                    &mut op,
                    &mut opBytes,
                    &mut errorOffset,
                )
            };
            valid = rc == 0
                && opBytes != 0
                && opBytes <= job.sourceBytes.wrapping_sub(cursor)
                && cb_op_is_apr_read(op.op_type)
                && retainedSourceBytes <= u32::MAX - opBytes;
            if valid {
                retainedSourceBytes += opBytes;
                cursor = cursor.wrapping_add(opBytes);
            }
            index += 1;
        }
        if valid {
            let d = &chain.ownerDesc;
            result.read = SoftwareRead {
                fileId: d.fileId,
                buffer: d.buffer,
                length: d.length,
                offset: d.offset,
            };
            result.finalGs = chain.pendingFinalGs;
            result.sourceBytes = retainedSourceBytes;
            result.commandCount = retainedCommandCount;
            result.gatherScatterCommandCount = chain.gatherScatterCommandCount as u32;
        }
        result
    }
}

impl AprAioReactor {
    /// Defaults: advanceSource=true, deferValidationError=false,
    /// outLogicalIssued/issueBudget/finalGs/outSubmitResult=null,
    /// sourceCommandCount=1, sourceGatherScatterCount=0.
    pub(crate) fn issue_software_read(
        &mut self,
        job: &mut JobPtr,
        gs: &mut GatherScatterState,
        read: &SoftwareRead,
        opBytes: u32,
        opOffset: u32,
        commandIndex: usize,
        admission: &mut AioAdmissionContext,
        advanceSource: bool,
        deferValidationError: bool,
        outLogicalIssued: *mut bool,
        issueBudget: *mut ReadIssueBudget,
        sourceCommandCount: u32,
        finalGs: *const GatherScatterState,
        sourceGatherScatterCount: u32,
        outSubmitResult: *mut DirectReadSubmitResult,
    ) -> bool {
        unsafe {
            if !outLogicalIssued.is_null() {
                *outLogicalIssued = false;
            }
            if !outSubmitResult.is_null() {
                *outSubmitResult = DirectReadSubmitResult::Failed;
            }
        }
        let j: *mut JobState = *job;
        if j.is_null()
            || sourceCommandCount == 0
            || sourceCommandCount > u8::MAX as u32
            || sourceGatherScatterCount > sourceCommandCount
            || sourceGatherScatterCount > u8::MAX as u32
        {
            return false;
        }
        if !issueBudget.is_null()
            && unsafe { (*issueBudget).requestsLeft == 0 || (*issueBudget).bytesLeft == 0 }
        {
            return false;
        }
        let effectiveRead = *read;
        if !self.validate_software_read(j, &effectiveRead, opOffset, deferValidationError) {
            return false;
        }

        let mut requestedFinalGs = *gs;
        if !finalGs.is_null() {
            requestedFinalGs = unsafe { *finalGs };
        } else {
            Self::update_software_gs_cursor(&mut requestedFinalGs, &effectiveRead);
        }

        let chainSlot: *mut *mut ReadChain = unsafe { addr_of_mut!((*j).cursorReadChain) };
        let mut chain = unsafe { *chainSlot };
        if chain.is_null() {
            chain = self.open_cursor_read_chain(
                j,
                &effectiveRead,
                opOffset,
                commandIndex,
                sourceCommandCount,
                sourceGatherScatterCount,
                &requestedFinalGs,
                deferValidationError,
            );
            if chain.is_null() {
                return false;
            }
            unsafe { *chainSlot = chain };
        } else {
            let chainLive = self.read_chain_is_live(chain);
            let c = unsafe { &*chain };
            if !chainLive
                || c.job != j
                || c.commandIndex != commandIndex
                || c.ownerDesc.errorOff != opOffset
                || c.ownerDesc.coalescedCommandCount as u32 != sourceCommandCount
                || c.gatherScatterCommandCount as u32 != sourceGatherScatterCount
                || !c.hasPendingFinalGs
            {
                abort();
            }
            // GS drift on a Pending retry: keep the retained transactional GS.
        }

        if advanceSource {
            self.set_cursor_read_wait_hint(unsafe { (*j).prioIndex } as usize);
        }

        let mut singleRequestBudget = ReadIssueBudget {
            requestsLeft: 1,
            bytesLeft: kSoftwareReadChunkMax,
        };
        let budget: &mut ReadIssueBudget = if issueBudget.is_null() {
            &mut singleRequestBudget
        } else {
            unsafe { &mut *issueBudget }
        };
        let outcome = self.submit_read_chain_slice(job, unsafe { &mut *chain }, budget, admission);
        if !outSubmitResult.is_null() {
            unsafe { *outSubmitResult = outcome.result };
        }
        if outcome.result == DirectReadSubmitResult::Staged {
            return self.finish_staged_read_chain(
                j,
                gs,
                chain,
                chainSlot,
                opBytes,
                sourceCommandCount,
                advanceSource,
                outLogicalIssued,
            );
        }
        if outcome.result == DirectReadSubmitResult::Pending {
            return false;
        }

        if advanceSource {
            self.clear_cursor_read_wait_hint(unsafe { (*j).prioIndex } as usize);
        }
        // Detach cursor ownership before publishing an error (set_fail may
        // return the chain to the pool); do not touch `chain` after finish.
        unsafe { (*chain).allIssued = true };
        unsafe { *chainSlot = null_mut() };
        self.maybe_finish_read_chain(chain);

        if outcome.has_error() && !Self::job_failed(unsafe { &*j }) {
            self.set_or_defer_read_command_error(
                unsafe { &mut *j },
                outcome.errorReason,
                outcome.errorRc,
                outcome.errorOffset,
                outcome.backendRc,
            );
        }
        false
    }
}

impl AprAioReactor {
    /// Rejects an empty or oversized read and one outside the user VA or
    /// file offset range, recording the error unless it is deferred.
    #[inline]
    fn validate_software_read(
        &mut self,
        j: *mut JobState,
        effectiveRead: &SoftwareRead,
        opOffset: u32,
        deferValidationError: bool,
    ) -> bool {
        if effectiveRead.length == 0 || effectiveRead.length > kSoftwareReadLengthMax {
            if !deferValidationError {
                self.set_command_error(
                    unsafe { &mut *j },
                    c"software-read-length".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    opOffset,
                    0,
                );
            }
            return false;
        }
        let readBuffer = effectiveRead.buffer as u64;
        if readBuffer > kSoftwareReadUserVaMax
            || effectiveRead.length > kSoftwareReadUserVaMax - readBuffer
            || effectiveRead.offset >= kSoftwareReadOffsetMaxExclusive
        {
            if !deferValidationError {
                self.set_command_error(
                    unsafe { &mut *j },
                    c"software-read-range".as_ptr(),
                    SCE_KERNEL_ERROR_EINVAL,
                    opOffset,
                    0,
                );
            }
            return false;
        }
        true
    }

    /// A new read chain owning the logical read at the job's cursor. Null
    /// when the completion window is full, the descriptor cannot be prepared
    /// (error recorded unless deferred) or no chain is free.
    #[allow(clippy::too_many_arguments)]
    fn open_cursor_read_chain(
        &mut self,
        j: *mut JobState,
        effectiveRead: &SoftwareRead,
        opOffset: u32,
        commandIndex: usize,
        sourceCommandCount: u32,
        sourceGatherScatterCount: u32,
        requestedFinalGs: &GatherScatterState,
        deferValidationError: bool,
    ) -> *mut ReadChain {
        if unsafe {
            apr_read_completion_window_exhausted(
                (*j).latestSubmittedReadSeq,
                (*j).completedReadSeq,
                kReadCompletionRingBits,
            )
        } {
            return null_mut();
        }
        let mut logicalRead = AprAioReadDesc::default();
        let mut prepareRc: c_int = 0;
        if !apr_prepare_aio_read_desc(
            unsafe { (*j).id },
            effectiveRead.fileId,
            effectiveRead.buffer,
            effectiveRead.length,
            effectiveRead.offset,
            opOffset,
            &mut logicalRead,
            &mut prepareRc,
        ) {
            if !deferValidationError {
                self.set_command_error(
                    unsafe { &mut *j },
                    c"software-read-prepare".as_ptr(),
                    prepareRc,
                    opOffset,
                    0,
                );
            }
            return null_mut();
        }
        logicalRead.coalescedCommandCount = sourceCommandCount as u8;
        apr_update_read_desc_fd_policy(&mut logicalRead, false);

        let chain = self.allocate_read_chain();
        if chain.is_null() {
            return null_mut();
        }
        let c = unsafe { &mut *chain };
        c.job = j;
        c.ownerDesc = logicalRead;
        c.nextBuffer = c.ownerDesc.buffer;
        c.nextOffset = c.ownerDesc.offset;
        c.remaining = c.ownerDesc.length;
        c.commandIndex = commandIndex;
        c.pendingFinalGs = *requestedFinalGs;
        c.gatherScatterCommandCount = sourceGatherScatterCount as u8;
        c.hasPendingFinalGs = true;
        chain
    }

    /// A chain slice staged its final quantum: the chain is fully issued, so
    /// the cursor detaches from it, takes its final GS and may advance.
    /// False while more than one chunk remains.
    #[allow(clippy::too_many_arguments)]
    fn finish_staged_read_chain(
        &mut self,
        j: *mut JobState,
        gs: &mut GatherScatterState,
        chain: *mut ReadChain,
        chainSlot: *mut *mut ReadChain,
        opBytes: u32,
        sourceCommandCount: u32,
        advanceSource: bool,
        outLogicalIssued: *mut bool,
    ) -> bool {
        let c = unsafe { &mut *chain };
        if c.remaining > kSoftwareReadChunkMax {
            return false;
        }
        // The final source quantum is now an ActiveRead that owns the
        // initial-submit retry, so the cursor may advance.
        if c.activeCount == 0 || (c.seq == 0 && c.activeCount != 1) {
            abort();
        }
        Self::reserve_read_chain_sequence(unsafe { &mut *j }, c);
        c.allIssued = true;
        unsafe { *chainSlot = null_mut() };
        if !c.hasPendingFinalGs {
            abort();
        }
        *gs = c.pendingFinalGs;
        if advanceSource {
            self.clear_cursor_read_wait_hint(unsafe { (*j).prioIndex } as usize);
            Self::advance_job_source_commands(unsafe { &mut *j }, opBytes, sourceCommandCount);
        }
        if !outLogicalIssued.is_null() {
            unsafe { *outLogicalIssued = true };
        }
        self.maybe_finish_read_chain(chain);
        true
    }
}
