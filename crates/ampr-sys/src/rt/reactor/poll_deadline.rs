//! Poll-deadline heap, active read submit/defer/link bookkeeping, worker start and AIO init.

use super::*;

impl AprAioReactor {
    pub(crate) fn poll_deadline_less(lhs: *const ActiveRead, rhs: *const ActiveRead) -> bool {
        let (l, r) = unsafe { (&*lhs, &*rhs) };
        if l.nextPollTimeNs != r.nextPollTimeNs {
            return l.nextPollTimeNs < r.nextPollTimeNs;
        }
        l.listSlot < r.listSlot
    }

    pub(crate) fn swap_poll_deadlines(&mut self, lhsIndex: u32, rhsIndex: u32) {
        if lhsIndex == rhsIndex {
            return;
        }
        let heap = &mut self.activePollDeadlineHeap;
        let lhs = heap[lhsIndex as usize];
        let rhs = heap[rhsIndex as usize];
        heap[lhsIndex as usize] = rhs;
        heap[rhsIndex as usize] = lhs;
        unsafe {
            (*rhs).pollDeadlineHeapIndex = lhsIndex;
            (*lhs).pollDeadlineHeapIndex = rhsIndex;
        }
    }

    pub(crate) fn sift_poll_deadline_up(&mut self, mut index: u32) {
        while index != 0 {
            let parent = (index - 1) / 2;
            let heap = &self.activePollDeadlineHeap;
            if !Self::poll_deadline_less(heap[index as usize], heap[parent as usize]) {
                break;
            }
            self.swap_poll_deadlines(index, parent);
            index = parent;
        }
    }

    pub(crate) fn sift_poll_deadline_down(&mut self, mut index: u32) {
        loop {
            let left = index * 2 + 1;
            if left >= self.activePollDeadlineHeapSize {
                return;
            }
            let right = left + 1;
            let heap = &self.activePollDeadlineHeap;
            let mut smallest = left;
            if right < self.activePollDeadlineHeapSize
                && Self::poll_deadline_less(heap[right as usize], heap[left as usize])
            {
                smallest = right;
            }
            if !Self::poll_deadline_less(heap[smallest as usize], heap[index as usize]) {
                return;
            }
            self.swap_poll_deadlines(index, smallest);
            index = smallest;
        }
    }

    pub(crate) fn update_poll_deadline(&mut self, active: &mut ActiveRead, oldDeadlineNs: u64) {
        let ap: *mut ActiveRead = active;
        if active.pollDeadlineHeapIndex == u32::MAX {
            if active.listSlot >= kMaxActiveReads
                || self.activePollDeadlineHeapSize >= kMaxActiveReads
            {
                abort();
            }
            let index = self.activePollDeadlineHeapSize;
            self.activePollDeadlineHeapSize += 1;
            self.activePollDeadlineHeap[index as usize] = ap;
            active.pollDeadlineHeapIndex = index;
            self.sift_poll_deadline_up(index);
            return;
        }
        let index = active.pollDeadlineHeapIndex;
        if index >= self.activePollDeadlineHeapSize
            || self.activePollDeadlineHeap[index as usize] != ap
        {
            abort();
        }
        if active.nextPollTimeNs < oldDeadlineNs {
            self.sift_poll_deadline_up(index);
        } else if active.nextPollTimeNs > oldDeadlineNs {
            self.sift_poll_deadline_down(index);
        }
    }

    pub(crate) fn remove_poll_deadline(&mut self, active: &mut ActiveRead) {
        let ap: *mut ActiveRead = active;
        let index = active.pollDeadlineHeapIndex;
        if index == u32::MAX {
            return;
        }
        if index >= self.activePollDeadlineHeapSize
            || self.activePollDeadlineHeap[index as usize] != ap
        {
            abort();
        }
        self.activePollDeadlineHeapSize -= 1;
        let lastIndex = self.activePollDeadlineHeapSize;
        active.pollDeadlineHeapIndex = u32::MAX;
        if index == lastIndex {
            self.activePollDeadlineHeap[index as usize] = null_mut();
            return;
        }
        let replacement = self.activePollDeadlineHeap[lastIndex as usize];
        if replacement.is_null() {
            abort();
        }
        self.activePollDeadlineHeap[index as usize] = replacement;
        self.activePollDeadlineHeap[lastIndex as usize] = null_mut();
        unsafe { (*replacement).pollDeadlineHeapIndex = index };
        if index != 0
            && Self::poll_deadline_less(
                replacement,
                self.activePollDeadlineHeap[((index - 1) / 2) as usize],
            )
        {
            self.sift_poll_deadline_up(index);
        } else {
            self.sift_poll_deadline_down(index);
        }
    }

    pub(crate) fn first_poll_deadline_read(&self) -> *mut ActiveRead {
        if self.activePollDeadlineHeapSize == 0 {
            return null_mut();
        }
        let active = self.activePollDeadlineHeap[0];
        if active.is_null() || unsafe { (*active).pollDeadlineHeapIndex } != 0 {
            abort();
        }
        active
    }

    pub(crate) fn active_poll_deadline_ns(&self) -> u64 {
        let active = self.first_poll_deadline_read();
        if active.is_null() {
            0
        } else {
            unsafe { (*active).nextPollTimeNs }
        }
    }

    pub(crate) fn first_due_active_read(&mut self, now: u64) -> ActiveReadIt {
        let active = self.first_poll_deadline_read();
        if active.is_null()
            || unsafe { (*active).nextPollTimeNs != 0 && now < (*active).nextPollTimeNs }
        {
            return self.activeReads.end();
        }
        let it = self
            .activeReads
            .iterator_from_slot(unsafe { (*active).listSlot });
        if it == self.activeReads.end() || it.ptr() != active {
            abort();
        }
        it
    }
}

impl AprAioReactor {
    pub(crate) fn active_read_is_submitted(active: &ActiveRead) -> bool {
        !active.awaitingBatchSubmit && !active.awaitingResubmit && active.aioId >= 0
    }

    pub(crate) fn mark_active_read_submitted(
        &mut self,
        active: &mut ActiveRead,
        aioId: SceKernelAioSubmitId,
    ) {
        if aioId < 0
            || Self::active_read_is_submitted(active)
            || !active.awaitingBatchSubmit
            || active.aioId >= 0
        {
            abort();
        }
        active.awaitingBatchSubmit = false;
        if active.awaitingResubmit {
            if self.deferredActiveReadCount == 0 {
                abort();
            }
            self.deferredActiveReadCount -= 1;
        }
        if self.submittedActiveReadCount >= kMaxActiveReads {
            abort();
        }
        self.submittedActiveReadCount += 1;
        active.aioId = aioId;
        active.awaitingResubmit = false;
    }

    pub(crate) fn mark_active_read_deferred(&mut self, active: &mut ActiveRead) {
        if !Self::active_read_is_submitted(active)
            || self.submittedActiveReadCount == 0
            || self.deferredActiveReadCount >= kMaxActiveReads
            || !active.submitAccounted
        {
            abort();
        }
        self.submittedActiveReadCount -= 1;
        self.deferredActiveReadCount += 1;
        active.aioId = -1;
        active.awaitingResubmit = true;
    }

    pub(crate) fn mark_staged_read_deferred(&mut self, active: &mut ActiveRead) {
        if active.aioId >= 0
            || !active.awaitingBatchSubmit
            || active.awaitingResubmit
            || active.submitAccounted
            || self.deferredActiveReadCount >= kMaxActiveReads
        {
            abort();
        }
        active.awaitingBatchSubmit = false;
        active.awaitingResubmit = true;
        self.deferredActiveReadCount += 1;
    }

    pub(crate) fn erase_active_read(&mut self, it: ActiveReadIt) -> ActiveReadIt {
        if it == self.activeReads.end() {
            return self.activeReads.end();
        }
        let a = unsafe { it.get() };
        if Self::active_read_is_submitted(a) {
            if self.submittedActiveReadCount == 0 {
                abort();
            }
            self.submittedActiveReadCount -= 1;
        } else if a.awaitingResubmit {
            if a.aioId >= 0 || a.awaitingBatchSubmit || self.deferredActiveReadCount == 0 {
                abort();
            }
            self.deferredActiveReadCount -= 1;
        } else if a.awaitingBatchSubmit {
            if a.aioId >= 0 {
                abort();
            }
        } else if a.aioId >= 0 {
            abort();
        }
        self.remove_poll_deadline(a);
        self.unlink_active_read_from_job(a);
        self.activeReads.erase(it)
    }

    pub(crate) fn link_active_read_to_job(&mut self, active: &mut ActiveRead, job: &mut JobState) {
        let slot = active.listSlot;
        if slot == u32::MAX {
            return;
        }
        let jp: JobPtr = job;
        active.job = jp;
        active.jobPrevSlot = job.activeReadTail;
        active.jobNextSlot = u32::MAX;
        if job.activeReadTail != u32::MAX {
            let tail = self.activeReads.active_at_slot(job.activeReadTail);
            if !tail.is_null() && unsafe { (*tail).job } == jp {
                unsafe { (*tail).jobNextSlot = slot };
            } else {
                active.jobPrevSlot = u32::MAX;
                job.activeReadHead = slot;
            }
        } else {
            job.activeReadHead = slot;
        }
        job.activeReadTail = slot;
    }

    pub(crate) fn unlink_active_read_from_job(&mut self, active: &mut ActiveRead) {
        let job = active.job;
        if !job.is_null() {
            let slot = active.listSlot;
            let prevSlot = active.jobPrevSlot;
            let nextSlot = active.jobNextSlot;
            unsafe {
                if (*job).activeReadHead == slot {
                    (*job).activeReadHead = nextSlot;
                }
                if (*job).activeReadTail == slot {
                    (*job).activeReadTail = prevSlot;
                }
                if prevSlot != u32::MAX {
                    let prev = self.activeReads.active_at_slot(prevSlot);
                    if !prev.is_null() && (*prev).job == job {
                        (*prev).jobNextSlot = nextSlot;
                    }
                }
                if nextSlot != u32::MAX {
                    let next = self.activeReads.active_at_slot(nextSlot);
                    if !next.is_null() && (*next).job == job {
                        (*next).jobPrevSlot = prevSlot;
                    }
                }
            }
        }
        active.hotPollQueued = false;
        active.jobPrevSlot = u32::MAX;
        active.jobNextSlot = u32::MAX;
    }
}

impl AprAioReactor {
    pub(crate) unsafe extern "C" fn worker_entry(arg: *mut c_void) -> *mut c_void {
        let this = arg as *mut Self;
        if !this.is_null() {
            unsafe { (*this).worker() };
        }
        null_mut()
    }

    pub(crate) fn notify_all_wait_domains(&self) {
        self.reactorCv.notify_all();
        self.jobStateAvailableCv.notify_all();
        self.syntheticRequestAvailableCv.notify_all();
        self.syntheticLowerSlotAvailableCv.notify_all();
        for cv in &self.syntheticWaitCvs {
            cv.notify_all();
        }
    }

    /// Thread creation is retryable; failure is intentionally non-sticky.
    pub(crate) fn start_worker(&mut self) -> bool {
        if self.started.load(Ordering::Acquire) {
            return true;
        }
        let this: *mut Self = self;
        // Serialize submitters with shutdown, but not under `m` across create.
        let _lifecycle = unsafe { (*this).workerLifecycleMutex.lock() };
        if self.started.load(Ordering::Acquire) {
            return true;
        }
        {
            let _lk = unsafe { (*this).m.lock() };
            if self.stop || self.shutdownRequested.load(Ordering::Acquire) {
                return false;
            }
        }
        let mut thread: ScePthread = null_mut();
        let createRc = unsafe {
            scePthreadCreate(
                &mut thread,
                null(),
                Self::worker_entry,
                this.cast(),
                b"ampr_apr_reactor\0".as_ptr().cast(),
            )
        };
        if createRc == 0 {
            self.workerThread = thread;
            self.started.store(true, Ordering::Release);
            return true;
        }
        false
    }

    pub(crate) const fn aio_active_read_limit() -> u32 {
        kBaseActiveReads
    }

    pub(crate) const fn aio_small_read_limit() -> u32 {
        kSmallReadActiveReads
    }

    pub(crate) const fn aio_direct_read_limit(effectiveLimit: u32) -> u32 {
        apr_direct_read_aio_limit(effectiveLimit, Self::aio_active_read_limit())
    }

    pub(crate) fn ensure_aio_initialized(&mut self) {
        loop {
            let state = self.aioInitState.load(Ordering::Acquire);
            if state == kAioInitReady || state == kAioInitExternalBusy {
                return;
            }
            if self
                .aioInitState
                .compare_exchange(
                    kAioInitUninitialized,
                    kAioInitInitializing,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
            let mut spins = 0u32;
            while self.aioInitState.load(Ordering::Acquire) == kAioInitInitializing {
                ampr_spin_pause_or_yield(&mut spins);
            }
        }
        let initRc = self.initialize_aio_parameters();
        let next = if initRc == 0 {
            kAioInitReady
        } else if initRc == SCE_KERNEL_ERROR_EBUSY {
            kAioInitExternalBusy
        } else {
            kAioInitUninitialized
        };
        self.aioInitState.store(next, Ordering::Release);
    }
}
