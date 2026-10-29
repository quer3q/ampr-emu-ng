//! Read chain and job state pools, and the `ActiveReadList` slot list.

use super::*;

impl AprAioReactor {
    pub(crate) fn allocate_read_chain(&mut self) -> *mut ReadChain {
        let slotIndex = self.readChainFreeHead;
        if slotIndex >= kReadChainPoolCapacity {
            return null_mut();
        }
        let slot = &mut self.readChainSlots[slotIndex as usize];
        self.readChainFreeHead = slot.nextFree;
        slot.nextFree = u32::MAX;
        slot.active = true;
        slot.value = ReadChain::default();
        slot.value.poolSlot = slotIndex;
        if self.liveReadChainCount == u32::MAX {
            abort();
        }
        self.liveReadChainCount += 1;
        &mut slot.value
    }

    pub(crate) fn release_read_chain_storage(&mut self, chain: *mut ReadChain) {
        if chain.is_null() || unsafe { (*chain).poolSlot } >= kReadChainPoolCapacity {
            return;
        }
        let slotIndex = unsafe { (*chain).poolSlot };
        let slot = &mut self.readChainSlots[slotIndex as usize];
        if !slot.active || !ptr::eq(&slot.value, chain) {
            abort();
        }
        slot.value = ReadChain::default();
        slot.active = false;
        slot.nextFree = self.readChainFreeHead;
        self.readChainFreeHead = slotIndex;
        if self.liveReadChainCount == 0 {
            abort();
        }
        self.liveReadChainCount -= 1;
    }

    pub(crate) fn read_chain_is_live(&self, chain: *const ReadChain) -> bool {
        if chain.is_null() || unsafe { (*chain).poolSlot } >= kReadChainPoolCapacity {
            return false;
        }
        let slot = &self.readChainSlots[unsafe { (*chain).poolSlot } as usize];
        slot.active && ptr::eq(&slot.value, chain)
    }

    pub(crate) fn release_job_state(&mut self, job: *mut JobState) {
        if job.is_null() {
            return;
        }
        let slotIndex = unsafe { (*job).poolSlot };
        if slotIndex >= kJobStatePoolCapacity {
            return;
        }
        unsafe {
            if (*job).activeReadCount != 0 || !(*job).cursorReadChain.is_null() {
                abort();
            }
        }
        {
            let _lock = SpinLock::from_atomic(&self.jobStatePoolLock).lock();
            let slot = &mut self.jobStateSlots[slotIndex as usize];
            if !slot.active || slot.job() != job {
                return;
            }
            unsafe { ptr::drop_in_place(job) };
            slot.active = false;
            slot.nextFree = self.jobStateFreeHead;
            self.jobStateFreeHead = slotIndex;
            // Publish the count while the freelist lock still hides this slot.
            self.jobStateFreeCount.fetch_add(1, Ordering::Release);
        }
        // Notify under the mutex only when a waiter can sleep on this pool.
        if self.jobStateWaiterCount.load(Ordering::Acquire) != 0 {
            let _availabilityLock = self.m.lock();
            self.jobStateAvailableCv.notify_one();
        }
    }

    pub(crate) fn allocate_job_state(&mut self) -> JobPtr {
        let _lock = SpinLock::from_atomic(&self.jobStatePoolLock).lock();
        let slotIndex = self.jobStateFreeHead;
        if slotIndex < kJobStatePoolCapacity {
            let slot = &mut self.jobStateSlots[slotIndex as usize];
            self.jobStateFreeHead = slot.nextFree;
            slot.nextFree = u32::MAX;
            slot.active = true;
            let job = slot.job();
            unsafe {
                JobState::init_in_place(job);
                (*job).poolSlot = slotIndex;
            }
            self.jobStateFreeCount.fetch_sub(1, Ordering::Release);
            return job;
        }
        null_mut()
    }
}

impl ActiveReadList {
    pub(crate) fn empty(&self) -> bool {
        self.count_ == 0
    }
    pub(crate) fn size(&self) -> usize {
        self.count_
    }

    pub(crate) fn begin(&mut self) -> ActiveReadIt {
        ActiveReadIt {
            owner_: self,
            index_: self.head_,
        }
    }
    pub(crate) fn end(&mut self) -> ActiveReadIt {
        ActiveReadIt {
            owner_: self,
            index_: kInvalid,
        }
    }
    pub(crate) fn begin_const(&self) -> const_iterator {
        ActiveReadIt {
            owner_: self as *const Self as *mut Self,
            index_: self.head_,
        }
    }
    pub(crate) fn end_const(&self) -> const_iterator {
        ActiveReadIt {
            owner_: self as *const Self as *mut Self,
            index_: kInvalid,
        }
    }
    pub(crate) fn iterator_from_slot(&mut self, slot: u32) -> ActiveReadIt {
        if slot >= kMaxActiveReads || !self.slots_[slot as usize].active {
            return self.end();
        }
        ActiveReadIt {
            owner_: self,
            index_: slot,
        }
    }
    pub(crate) fn active_at_slot(&mut self, slot: u32) -> *mut ActiveRead {
        if slot >= kMaxActiveReads || !self.slots_[slot as usize].active {
            return null_mut();
        }
        &mut self.slots_[slot as usize].value
    }
    pub(crate) fn active_at_slot_2(&mut self, slot: u32, generation: u32) -> *mut ActiveRead {
        if slot >= kMaxActiveReads
            || !self.slots_[slot as usize].active
            || self.slots_[slot as usize].generation != generation
        {
            return null_mut();
        }
        &mut self.slots_[slot as usize].value
    }

    pub(crate) fn push_back(&mut self, value: ActiveRead) -> ActiveReadIt {
        let slot = (0..kMaxActiveReads)
            .map(|n| (self.freeCursor_ + n) % kMaxActiveReads)
            .find(|&i| !self.slots_[i as usize].active)
            .unwrap_or_else(|| abort());
        self.freeCursor_ = (slot + 1) % kMaxActiveReads;
        let tail = self.tail_;
        let node = &mut self.slots_[slot as usize];
        node.generation = if node.generation == u32::MAX {
            1
        } else {
            node.generation + 1
        };
        node.value = value;
        node.value.listSlot = slot;
        node.value.listGeneration = node.generation;
        node.prev = tail;
        node.next = kInvalid;
        node.active = true;
        if tail != kInvalid {
            self.slots_[tail as usize].next = slot;
        } else {
            self.head_ = slot;
        }
        self.tail_ = slot;
        self.count_ += 1;
        ActiveReadIt {
            owner_: self,
            index_: slot,
        }
    }

    pub(crate) fn erase(&mut self, it: ActiveReadIt) -> ActiveReadIt {
        if !ptr::eq(it.owner_, self)
            || it.index_ == kInvalid
            || !self.slots_[it.index_ as usize].active
        {
            return self.end();
        }
        let index = it.index_ as usize;
        let next = self.slots_[index].next;
        let prev = self.slots_[index].prev;
        if prev != kInvalid {
            self.slots_[prev as usize].next = next;
        } else {
            self.head_ = next;
        }
        if next != kInvalid {
            self.slots_[next as usize].prev = prev;
        } else {
            self.tail_ = prev;
        }
        let s = &mut self.slots_[index];
        s.value = ActiveRead::default();
        s.prev = kInvalid;
        s.next = kInvalid;
        s.active = false;
        // generation is kept.
        self.count_ -= 1;
        self.freeCursor_ = index as u32;
        ActiveReadIt {
            owner_: self,
            index_: next,
        }
    }
}
