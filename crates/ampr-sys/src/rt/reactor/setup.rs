//! AIO parameters, worker thread setup, active job tracking and synthetic submit-id slots.

use super::*;

const _: () = {
    assert!(AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE > 0);
    assert!(AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE <= SCE_KERNEL_AIO_SCHED_WINDOW_MAX);
    assert!(AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT > 0);
    assert!(AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT <= SCE_KERNEL_AIO_DELAYED_COUNT_MAX);
};

const kSyntheticGenerationMax: u32 =
    kSyntheticSubmitIdGenerationMask >> kSyntheticSubmitIdGenerationShift;
const _: () = assert!(kSyntheticGenerationMax > kSyntheticRequestCapacity + kSyntheticDoneCapacity);

impl AprAioReactor {
    pub(crate) fn initialize_aio_parameters(&mut self) -> c_int {
        let mut param = SceKernelAioParam::default();
        unsafe { sceKernelAioInitializeParam(&mut param) };
        let setParam = |sched: &mut SceKernelAioSchedulingParam| unsafe {
            sceKernelAioSetParam(
                sched,
                AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE,
                AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT,
                SCE_KERNEL_AIO_DISABLE_SPLIT,
                SCE_KERNEL_AIO_SPLIT_SIZE_DEFAULT,
                SCE_KERNEL_AIO_SPLIT_CHUNK_SIZE_DEFAULT,
            )
        };
        let lowRc = setParam(&mut param.low);
        let midRc = setParam(&mut param.mid);
        let highRc = setParam(&mut param.high);
        if lowRc != 0 || midRc != 0 || highRc != 0 {
            return if lowRc != 0 {
                lowRc
            } else if midRc != 0 {
                midRc
            } else {
                highRc
            };
        }
        unsafe { sceKernelAioInitialize(&mut param) }
    }

    /// Only fed the dropped `aioSubmitEagainCount` counter.
    pub(crate) fn note_aio_submit_result(&self, _sceRc: c_int, _requestCount: usize) {}

    pub(crate) fn configure_worker_thread(&self) {
        unsafe {
            let this = scePthreadSelf();
            let _ = scePthreadRename(this, c"ampr_apr_reactor".as_ptr());
            if AMPR_EMU_APR_REACTOR_THREAD_PRIORITY != 0 {
                let mut oldPrio: c_int = -1;
                let getRc = scePthreadGetprio(this, &mut oldPrio);
                let clampedPrio = AMPR_EMU_APR_REACTOR_THREAD_PRIORITY
                    .clamp(SCE_KERNEL_PRIO_FIFO_HIGHEST, SCE_KERNEL_PRIO_FIFO_LOWEST);
                let targetPrio = if getRc == 0
                    && (SCE_KERNEL_PRIO_FIFO_HIGHEST..=SCE_KERNEL_PRIO_FIFO_LOWEST)
                        .contains(&oldPrio)
                    && oldPrio < clampedPrio
                {
                    oldPrio
                } else {
                    clampedPrio
                };
                if getRc != 0 || oldPrio != targetPrio {
                    let _ = scePthreadSetprio(this, targetPrio);
                }
                let mut newPrio: c_int = -1;
                let _ = scePthreadGetprio(this, &mut newPrio);
            }
            if AMPR_EMU_APR_REACTOR_THREAD_AFFINITY != 0 {
                let _ = scePthreadSetaffinity(
                    this,
                    AMPR_EMU_APR_REACTOR_THREAD_AFFINITY as SceKernelCpumask,
                );
            }
        }
    }

    pub(crate) fn has_active_lanes_locked(&self) -> bool {
        self.activeJobCountAtomic.load(Ordering::Relaxed) != 0
    }

    pub(crate) fn add_active_job_locked(&mut self, job: *mut JobState) -> bool {
        let Some(j) = (unsafe { job.as_mut() }) else {
            return false;
        };
        if j.activeListed || j.prioIndex >= kPriorityCount {
            return false;
        }
        j.activePrev = self.activeJobTail;
        j.activeNext = null_mut();
        if let Some(tail) = unsafe { self.activeJobTail.as_mut() } {
            tail.activeNext = job;
        } else {
            self.activeJobHead = job;
        }
        self.activeJobTail = job;
        let p = j.prioIndex as usize;
        let priorityTail = self.activePriorityTails[p];
        j.priorityPrev = priorityTail;
        j.priorityNext.store(null_mut(), Ordering::Relaxed);
        if let Some(tail) = unsafe { priorityTail.as_ref() } {
            tail.priorityNext.store(job, Ordering::Release);
        } else {
            self.activePriorityHeads[p] = job;
        }
        self.activePriorityTails[p] = job;
        j.activeListed = true;
        self.activeJobCountAtomic.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub(crate) fn erase_active_job_locked(&mut self, job: *mut JobState) -> bool {
        let Some(j) = (unsafe { job.as_mut() }) else {
            return false;
        };
        if j.activeListed {
            if let Some(prev) = unsafe { j.activePrev.as_mut() } {
                prev.activeNext = j.activeNext;
            } else {
                self.activeJobHead = j.activeNext;
            }
            if let Some(next) = unsafe { j.activeNext.as_mut() } {
                next.activePrev = j.activePrev;
            } else {
                self.activeJobTail = j.activePrev;
            }
            let p = j.prioIndex as usize;
            let priorityNext = j.priorityNext.load(Ordering::Acquire);
            if let Some(prev) = unsafe { j.priorityPrev.as_ref() } {
                prev.priorityNext.store(priorityNext, Ordering::Release);
            } else {
                self.activePriorityHeads[p] = priorityNext;
            }
            if let Some(next) = unsafe { priorityNext.as_mut() } {
                next.priorityPrev = j.priorityPrev;
            } else {
                self.activePriorityTails[p] = j.priorityPrev;
            }
        }
        let wasListed = j.activeListed;
        j.activeListed = false;
        j.activePrev = null_mut();
        j.activeNext = null_mut();
        j.priorityPrev = null_mut();
        j.priorityNext.store(null_mut(), Ordering::Relaxed);
        if wasListed {
            self.activeJobCountAtomic.fetch_sub(1, Ordering::Relaxed);
        }
        wasListed
    }

    pub(crate) fn make_synthetic_submit_id(slot: u32, generation: u32) -> SceAprSubmitId {
        (kSyntheticSubmitIdTag
            | ((generation << kSyntheticSubmitIdGenerationShift)
                & kSyntheticSubmitIdGenerationMask)
            | (slot & kSyntheticSubmitIdSlotMask)) as SceAprSubmitId
    }

    pub(crate) fn decode_synthetic_submit_id(
        id: SceAprSubmitId,
        outSlot: *mut u32,
        outGeneration: *mut u32,
    ) -> bool {
        let raw = id as u32;
        if (raw & kSyntheticSubmitIdTagMask) != kSyntheticSubmitIdTag {
            return false;
        }
        let slot = raw & kSyntheticSubmitIdSlotMask;
        let generation =
            (raw & kSyntheticSubmitIdGenerationMask) >> kSyntheticSubmitIdGenerationShift;
        if slot >= kSyntheticLowerSlotCapacity || generation == 0 {
            return false;
        }
        unsafe {
            if !outSlot.is_null() {
                *outSlot = slot;
            }
            if !outGeneration.is_null() {
                *outGeneration = generation;
            }
        }
        true
    }

    fn synthetic_lower_slot_of(id: SceAprSubmitId) -> Option<usize> {
        let mut slot: u32 = 0;
        Self::decode_synthetic_submit_id(id, &mut slot, null_mut()).then_some(slot as usize)
    }

    pub(crate) fn find_synthetic_done_slot_locked(&self, id: SceAprSubmitId) -> u32 {
        if let Some(lower) = Self::synthetic_lower_slot_of(id) {
            let hint = self.syntheticLowerSlots[lower].doneSlotHint.wrapping_sub(1);
            if hint < kSyntheticDoneCapacity {
                let done = &self.syntheticDoneSlots[hint as usize];
                if done.active && done.submitId == id {
                    return hint;
                }
            }
        }
        let mut slot = self.syntheticDoneHead;
        while slot < kSyntheticDoneCapacity {
            let done = &self.syntheticDoneSlots[slot as usize];
            if done.active && done.submitId == id {
                return slot;
            }
            slot = done.next;
        }
        u32::MAX
    }

    pub(crate) fn take_synthetic_done_result_locked(
        &mut self,
        id: SceAprSubmitId,
        outResult: *mut c_int,
    ) -> bool {
        let slot = self.find_synthetic_done_slot_locked(id);
        if slot >= kSyntheticDoneCapacity {
            return false;
        }
        let SyntheticDoneSlot {
            result, next, prev, ..
        } = self.syntheticDoneSlots[slot as usize];
        if !outResult.is_null() {
            unsafe { *outResult = result };
        }
        if prev < kSyntheticDoneCapacity {
            self.syntheticDoneSlots[prev as usize].next = next;
        } else {
            self.syntheticDoneHead = next;
        }
        if next < kSyntheticDoneCapacity {
            self.syntheticDoneSlots[next as usize].prev = prev;
        } else {
            self.syntheticDoneTail = prev;
        }
        if let Some(lower) = Self::synthetic_lower_slot_of(id) {
            let lower = &mut self.syntheticLowerSlots[lower];
            if lower.doneSlotHint == slot + 1 {
                lower.doneSlotHint = 0;
            }
        }
        let done = &mut self.syntheticDoneSlots[slot as usize];
        *done = SyntheticDoneSlot::default();
        done.next = self.syntheticDoneFreeHead;
        self.syntheticDoneFreeHead = slot;
        true
    }

    pub(crate) fn retain_synthetic_done_result_locked(
        &mut self,
        id: SceAprSubmitId,
        result: c_int,
    ) -> SceAprSubmitId {
        let slot;
        let mut evictedId: SceAprSubmitId = 0;
        if self.syntheticDoneFreeHead < kSyntheticDoneCapacity {
            slot = self.syntheticDoneFreeHead;
            self.syntheticDoneFreeHead = self.syntheticDoneSlots[slot as usize].next;
        } else {
            slot = self.syntheticDoneHead;
            if slot >= kSyntheticDoneCapacity {
                abort();
            }
            let oldest = self.syntheticDoneSlots[slot as usize];
            evictedId = oldest.submitId;
            self.syntheticDoneHead = oldest.next;
            if self.syntheticDoneHead < kSyntheticDoneCapacity {
                self.syntheticDoneSlots[self.syntheticDoneHead as usize].prev = u32::MAX;
            } else {
                self.syntheticDoneTail = u32::MAX;
            }
        }
        let tail = self.syntheticDoneTail;
        self.syntheticDoneSlots[slot as usize] = SyntheticDoneSlot {
            submitId: id,
            result,
            next: u32::MAX,
            prev: tail,
            active: true,
        };
        if tail < kSyntheticDoneCapacity {
            self.syntheticDoneSlots[tail as usize].next = slot;
        } else {
            self.syntheticDoneHead = slot;
        }
        self.syntheticDoneTail = slot;
        if let Some(lower) = Self::synthetic_lower_slot_of(id) {
            self.syntheticLowerSlots[lower].doneSlotHint = slot + 1;
        }
        evictedId
    }

    pub(crate) fn synthetic_submit_id_owned_locked(&self, id: SceAprSubmitId) -> bool {
        if id == 0 {
            return false;
        }
        if self.find_synthetic_wait_slot_locked(id) < kSyntheticRequestCapacity {
            return true;
        }
        self.find_synthetic_done_slot_locked(id) < kSyntheticDoneCapacity
    }

    pub(crate) fn find_synthetic_wait_slot_locked(&self, id: SceAprSubmitId) -> u32 {
        if let Some(lower) = Self::synthetic_lower_slot_of(id) {
            let hint = self.syntheticLowerSlots[lower].waitSlotHint.wrapping_sub(1);
            if hint < kSyntheticRequestCapacity {
                let request = &self.syntheticWaitSlots[hint as usize];
                if request.active && request.submitId == id {
                    return hint;
                }
            }
        }
        self.syntheticWaitSlots
            .iter()
            .position(|r| r.active && r.submitId == id)
            .map_or(u32::MAX, |s| s as u32)
    }

    pub(crate) fn reserve_synthetic_wait_slot_locked(&mut self, job: &mut JobState) -> bool {
        if job.syntheticWaitSlot < kSyntheticRequestCapacity {
            return true;
        }
        for attempt in 0..kSyntheticRequestCapacity {
            let slot = (self.syntheticWaitAllocCursor + attempt) % kSyntheticRequestCapacity;
            let request = &mut self.syntheticWaitSlots[slot as usize];
            if request.active {
                continue;
            }
            *request = SyntheticWaitSlot::default();
            request.ownerJob = job;
            request.prioIndex = job.prioIndex;
            request.active = true;
            job.syntheticWaitSlot = slot;
            self.syntheticWaitAllocCursor = (slot + 1) % kSyntheticRequestCapacity;
            return true;
        }
        false
    }

    pub(crate) fn allocate_synthetic_lower_slot_locked(
        &mut self,
        job: &mut JobState,
        outId: *mut SceAprSubmitId,
    ) -> bool {
        if outId.is_null() || job.syntheticWaitSlot >= kSyntheticRequestCapacity {
            return false;
        }
        let generationMax = kSyntheticGenerationMax;
        for attempt in 0..kSyntheticLowerSlotCapacity {
            let slot = (self.syntheticLowerAllocCursor + attempt) % kSyntheticLowerSlotCapacity;
            let lower = self.syntheticLowerSlots[slot as usize];
            if lower.active {
                continue;
            }
            let mut generation = lower.generation;
            if generation == 0 || generation > generationMax {
                generation = 1;
            }
            let mut id = Self::make_synthetic_submit_id(slot, generation);
            // After a generation wrap, skip any encoded id that is still owned.
            if lower.generationWrapped {
                id = 0;
                for _ in 0..generationMax {
                    let candidate = Self::make_synthetic_submit_id(slot, generation);
                    if !self.synthetic_submit_id_owned_locked(candidate) {
                        id = candidate;
                        break;
                    }
                    generation += 1;
                    if generation == 0 || generation > generationMax {
                        generation = 1;
                    }
                }
                if id == 0 {
                    continue;
                }
            }
            let lower = &mut self.syntheticLowerSlots[slot as usize];
            lower.generation = generation;
            lower.active = true;
            lower.waitSlotHint = job.syntheticWaitSlot + 1;
            job.syntheticLowerSlot = slot;
            job.syntheticLowerGeneration = generation;
            job.syntheticSubmitId = id;
            let request = &mut self.syntheticWaitSlots[job.syntheticWaitSlot as usize];
            request.submitId = id;
            request.result = 0;
            request.done = false;
            request.waiterClaimed = false;
            self.syntheticLowerAllocCursor = (slot + 1) % kSyntheticLowerSlotCapacity;
            unsafe { *outId = id };
            return true;
        }
        false
    }
}
