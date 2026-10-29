//! Native APR batch buffers: reset, submit, progress sampling, sealing and deferred EOPs.
//! `reset_software_gs_cursor` is already defined in software.rs.

use super::*;

unsafe fn store_u64(p: *mut u64, v: u64, o: Ordering) {
    unsafe { AtomicU64::from_ptr(p).store(v, o) }
}

unsafe fn slot_result(slot: *mut AprNativeBatchSlot) -> &'static AtomicI32 {
    unsafe { AtomicI32::from_ptr(addr_of_mut!((*slot).result.result)) }
}

/// Copy `len` default-payload bytes (from `src_off`) into `commands[dst_off..]`.
unsafe fn copy_default_payload(
    slot: *mut AprNativeBatchSlot,
    dst_off: u32,
    src_off: u32,
    len: u32,
) {
    unsafe {
        ptr::copy_nonoverlapping(
            (addr_of!((*slot).defaultPayload) as *const u8).add(src_off as usize),
            (addr_of_mut!((*slot).commands) as *mut u8).add(dst_off as usize),
            len as usize,
        )
    }
}

impl AprAioReactor {
    pub(crate) fn native_batch_token_reached(observed: u64, target: u64) -> bool {
        observed.wrapping_sub(target) <= i64::MAX as u64
    }

    pub(crate) fn native_batch_result(&self, slot: *mut AprNativeBatchSlot) -> c_int {
        unsafe { slot_result(slot).load(Ordering::Acquire) }
    }

    pub(crate) fn reset_native_batch_buffer(
        &mut self,
        laneIndex: u32,
        bufferIndex: u32,
        nativeSubmitType: u32,
    ) {
        let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
        let state = &mut self.nativeBatchLanes[laneIndex as usize].buffers[bufferIndex as usize];
        if slot.is_null() || state.phase != NativeBatchPhase::Free {
            abort();
        }
        unsafe {
            store_u64(apr_native_batch_release_ptr(slot), 0, Ordering::Relaxed);
            store_u64(apr_native_batch_progress_ptr(slot), 0, Ordering::Relaxed);
            (*slot).result.error_offset = 0;
            slot_result(slot).store(kAprNativeBatchResultPending, Ordering::Relaxed);
        }
        state.generation = state.generation.wrapping_add(1);
        if state.generation == 0 {
            state.generation = 1;
        }
        state.nextGroup = 0;
        state.openGroupPackets = 0;
        state.packetCount = 0;
        state.nativeSubmitType = nativeSubmitType;
        state.observedProgress = 0;
        state.firstSequence = 0;
        state.lastSequence = 0;
        state.submitTimeNs = 0;
        state.lastReleaseTimeNs = 0;
        state.submitId = 0;
        state.phase = NativeBatchPhase::Filling;
    }

    pub(crate) fn has_live_synthetic_waits_locked(&self) -> bool {
        self.syntheticWaitSlots.iter().any(|s| s.active)
    }

    pub(crate) fn submit_native_batch_buffer(&mut self, laneIndex: u32, bufferIndex: u32) -> bool {
        let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
        let lane = &mut self.nativeBatchLanes[laneIndex as usize];
        let state = &mut lane.buffers[bufferIndex as usize];
        if slot.is_null()
            || state.phase != NativeBatchPhase::Filling
            || state.nextGroup == 0
            || state.openGroupPackets != 0
            || lane.activeBuffer >= 0
        {
            return false;
        }

        let mut cb = NativeAprCommandBufferView::default();
        cb.m_commandBuffer.r#type = state.nativeSubmitType as i32;
        cb.m_commandBuffer.offset = kAprNativeBatchExecutableBytes;
        cb.m_commandBuffer.num = kAprNativeBatchCommandCount as i32;
        cb.m_commandBuffer.bufsize = kAprNativeBatchSubmitBytes;
        unsafe {
            cb.m_commandBuffer.buffer = addr_of_mut!((*slot).commands) as *mut c_void;
            (*slot).result.error_offset = 0;
            slot_result(slot).store(kAprNativeBatchResultPending, Ordering::Relaxed);
        }
        fence(Ordering::SeqCst);

        let mut submitRcRaw: c_int = 0;
        let mut submitId: SceAprSubmitId = 0;
        let dispatchRc = unsafe {
            apr_native_submit_dispatch(
                &mut cb,
                laneIndex,
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
        if submitRc != 0 {
            return false;
        }
        state.submitId = submitId;
        state.submitTimeNs = time_counter_now();
        if state.lastReleaseTimeNs < state.submitTimeNs {
            state.lastReleaseTimeNs = state.submitTimeNs;
        }
        state.phase = NativeBatchPhase::Active;
        lane.activeBuffer = bufferIndex as i8;
        true
    }

    pub(crate) fn native_batch_sequence_reached(completed: u64, target: u64) -> bool {
        completed.wrapping_sub(target) <= i64::MAX as u64
    }

    /// Takes the lane and addresses the buffer state as
    /// `lane.buffers[bufferIndex]` (no aliasing &mut).
    pub(crate) fn sample_native_batch_progress(
        _laneIndex: u32,
        bufferIndex: u32,
        lane: &mut NativeBatchLane,
        slot: *mut AprNativeBatchSlot,
    ) -> u64 {
        let observed = unsafe {
            AtomicU64::from_ptr(apr_native_batch_progress_ptr(slot)).load(Ordering::Acquire)
        };
        let state = &mut lane.buffers[bufferIndex as usize];
        state.observedProgress = observed;
        if observed == 0 {
            return observed;
        }
        if state.firstSequence == 0 || observed <= kAprNativeBatchTokenBase {
            abort();
        }
        let completedGroupCount = observed - kAprNativeBatchTokenBase;
        if completedGroupCount > state.nextGroup as u64 {
            abort();
        }
        let completedSequence = state
            .firstSequence
            .wrapping_add(completedGroupCount)
            .wrapping_sub(1);
        if Self::native_batch_sequence_reached(completedSequence, lane.completedSequence) {
            lane.completedSequence = completedSequence;
        }
        observed
    }

    pub(crate) fn native_batch_wait_pending(&mut self, laneIndex: u32) -> bool {
        if laneIndex >= kPriorityCount as u32 {
            return false;
        }
        let lane = &mut self.nativeBatchLanes[laneIndex as usize];
        if lane.blockingWaitSequence == 0 {
            return false;
        }
        if Self::native_batch_sequence_reached(lane.completedSequence, lane.blockingWaitSequence) {
            lane.blockingWaitSequence = 0;
            return false;
        }
        if lane.activeBuffer >= 0 {
            let bufferIndex = lane.activeBuffer as u32;
            let state = &lane.buffers[bufferIndex as usize];
            let waitIsActive = state.phase == NativeBatchPhase::Active
                && state.firstSequence != 0
                && Self::native_batch_sequence_reached(
                    lane.blockingWaitSequence,
                    state.firstSequence,
                )
                && Self::native_batch_sequence_reached(
                    state.lastSequence,
                    lane.blockingWaitSequence,
                );
            if waitIsActive {
                let now = time_counter_now();
                let checkBase = state.lastReleaseTimeNs.max(state.submitTimeNs);
                let ageNs = if checkBase != 0 && now >= checkBase {
                    now - checkBase
                } else {
                    0
                };
                if ageNs >= kNativeCompletionTimeoutNs {
                    let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
                    if slot.is_null() {
                        abort();
                    }
                    Self::sample_native_batch_progress(laneIndex, bufferIndex, lane, slot);
                    if Self::native_batch_sequence_reached(
                        lane.completedSequence,
                        lane.blockingWaitSequence,
                    ) {
                        lane.blockingWaitSequence = 0;
                        return false;
                    }
                    abort();
                }
            }
        }
        true
    }

    /// Default `releaseGroup = true`.
    pub(crate) fn seal_native_apr_batch_group(
        &mut self,
        laneIndex: u32,
        bufferIndex: u32,
        releaseGroup: bool,
    ) -> bool {
        let lane = &mut self.nativeBatchLanes[laneIndex as usize];
        let state = &mut lane.buffers[bufferIndex as usize];
        if state.openGroupPackets == 0 {
            return true;
        }
        if state.nextGroup >= kAprNativeBatchGroupCount
            || state.openGroupPackets > kAprNativeBatchPacketsPerGroup
        {
            return false;
        }
        let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
        if slot.is_null() {
            return false;
        }
        let groupIndex = state.nextGroup;
        let unusedPacketCount = kAprNativeBatchPacketsPerGroup - state.openGroupPackets;
        if unusedPacketCount != 0 {
            let usedPayloadBytes = state.openGroupPackets * kAprNativeBatchPayloadSlotBytes;
            unsafe {
                copy_default_payload(
                    slot,
                    groupIndex * kAprNativeBatchGroupBytes
                        + kAprNativeBatchGateBytes
                        + usedPayloadBytes,
                    usedPayloadBytes,
                    unusedPacketCount * kAprNativeBatchPayloadSlotBytes,
                )
            };
        }
        let token = apr_native_batch_token(groupIndex);
        let groupSequence = lane.issuedSequence.wrapping_add(1);
        if groupSequence == 0 {
            return false;
        }
        lane.issuedSequence = groupSequence;
        if state.nextGroup == 0 {
            state.firstSequence = groupSequence;
        }
        state.lastSequence = groupSequence;
        state.nextGroup += 1;
        state.openGroupPackets = 0;
        if releaseGroup {
            state.lastReleaseTimeNs = time_counter_now();
            fence(Ordering::SeqCst);
            unsafe { store_u64(apr_native_batch_release_ptr(slot), token, Ordering::Release) };
        }
        if state.phase == NativeBatchPhase::Filling
            && lane.activeBuffer < 0
            && !self.submit_native_batch_buffer(laneIndex, bufferIndex)
        {
            return false;
        }
        true
    }

    pub(crate) fn seal_open_native_apr_batch_group(&mut self, laneIndex: u32) -> bool {
        for bufferIndex in 0..kAprNativeBatchBufferCountPerLane {
            if self.nativeBatchLanes[laneIndex as usize].buffers[bufferIndex as usize]
                .openGroupPackets
                != 0
            {
                return self.seal_native_apr_batch_group(laneIndex, bufferIndex, true);
            }
        }
        true
    }

    pub(crate) fn release_deferred_native_eop(
        &mut self,
        job: &mut JobState,
        cancelPacket: bool,
    ) -> bool {
        if !job.nativeBatchReleasePending || job.prioIndex >= kPriorityCount {
            return false;
        }
        let lane = &mut self.nativeBatchLanes[job.prioIndex as usize];
        if lane.deferredReleaseSequence == 0
            || lane.deferredReleaseSequence != job.nativeBatchSequence
            || lane.deferredReleaseJobId != job.id
            || lane.deferredReleaseBufferIndex >= kAprNativeBatchBufferCountPerLane
        {
            abort();
        }
        let bufferIndex = lane.deferredReleaseBufferIndex;
        let groupIndex = lane.deferredReleaseGroupIndex;
        let deferredSequence = lane.deferredReleaseSequence;
        let state = &mut lane.buffers[bufferIndex as usize];
        let slot = apr_native_batch_slot(job.prioIndex as usize, bufferIndex as usize);
        if slot.is_null()
            || state.phase == NativeBatchPhase::Free
            || groupIndex >= state.nextGroup
            || groupIndex >= kAprNativeBatchGroupCount
            || state.firstSequence.wrapping_add(groupIndex as u64) != deferredSequence
        {
            abort();
        }
        if cancelPacket {
            unsafe {
                copy_default_payload(
                    slot,
                    groupIndex * kAprNativeBatchGroupBytes + kAprNativeBatchGateBytes,
                    0,
                    kAprNativeBatchPayloadRegionBytes,
                )
            };
        }
        let token = apr_native_batch_token(groupIndex);
        let releaseTimeNs = time_counter_now();
        state.lastReleaseTimeNs = releaseTimeNs;
        job.nativeSubmitTimeNs = releaseTimeNs;
        fence(Ordering::SeqCst);
        unsafe { store_u64(apr_native_batch_release_ptr(slot), token, Ordering::Release) };
        lane.deferredReleaseSequence = 0;
        lane.deferredReleaseJobId = 0;
        lane.deferredReleaseBufferIndex = 0;
        lane.deferredReleaseGroupIndex = 0;
        job.nativeBatchReleasePending = false;
        job.nativeBatchReleaseReadSequence = 0;
        true
    }

    pub(crate) fn prepare_native_batches_for_shutdown(&mut self) -> bool {
        if !self.nativeExecutionPoolReady {
            return true;
        }
        for laneIndex in 0..kPriorityCount as u32 {
            if self.nativeBatchLanes[laneIndex as usize].deferredReleaseSequence != 0 {
                continue;
            }
            if !self.seal_open_native_apr_batch_group(laneIndex) {
                return false;
            }
            for bufferIndex in 0..kAprNativeBatchBufferCountPerLane {
                let lane = &mut self.nativeBatchLanes[laneIndex as usize];
                let state = &mut lane.buffers[bufferIndex as usize];
                if state.phase == NativeBatchPhase::Free {
                    continue;
                }
                if state.nextGroup == 0 {
                    if state.packetCount != 0 {
                        return false;
                    }
                    state.phase = NativeBatchPhase::Free;
                    continue;
                }
                if state.nextGroup > kAprNativeBatchGroupCount || state.openGroupPackets != 0 {
                    return false;
                }
                let slot = apr_native_batch_slot(laneIndex as usize, bufferIndex as usize);
                if slot.is_null() {
                    return false;
                }
                if state.nextGroup < kAprNativeBatchGroupCount {
                    for group in state.nextGroup..kAprNativeBatchGroupCount {
                        unsafe {
                            copy_default_payload(
                                slot,
                                group * kAprNativeBatchGroupBytes + kAprNativeBatchGateBytes,
                                0,
                                kAprNativeBatchPayloadRegionBytes,
                            )
                        };
                        let sequence = lane.issuedSequence.wrapping_add(1);
                        if sequence == 0 {
                            return false;
                        }
                        lane.issuedSequence = sequence;
                        state.lastSequence = sequence;
                    }
                    state.nextGroup = kAprNativeBatchGroupCount;
                    state.lastReleaseTimeNs = time_counter_now();
                    fence(Ordering::SeqCst);
                    unsafe {
                        store_u64(
                            apr_native_batch_release_ptr(slot),
                            apr_native_batch_token(kAprNativeBatchGroupCount - 1),
                            Ordering::Release,
                        )
                    };
                }
                if state.phase == NativeBatchPhase::Filling
                    && lane.activeBuffer < 0
                    && !self.submit_native_batch_buffer(laneIndex, bufferIndex)
                {
                    return false;
                }
            }
        }
        true
    }
}
