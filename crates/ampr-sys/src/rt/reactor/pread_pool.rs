//! Blocking pread pool for the pack's physical reads (external AIO groups).
//! Kernel AIO on BFS serves 1-2 requests at a time; a pool of threads each
//! blocked in pread keeps many in flight. Pack reads land in the internal
//! pool (CPU memory), so a CPU pread can fill them; the game's APR reads stay
//! on kernel AIO because their buffers may be GPU-only (EFAULT from pread).
//! Ported from test-crate-readwrite (image bypass), external path only.

use super::*;
use crate::rt::stats::{self, Stat};

impl AprAioReactor {
    unsafe extern "C" fn pread_worker_entry(arg: *mut c_void) -> *mut c_void {
        // Reactor priority, above the decode workers: a finished read is handed
        // on and the next one issued before decode work runs; the threads
        // spend nearly all their time blocked in pread. Workers' affinity.
        unsafe {
            let this = scePthreadSelf();
            let _ = scePthreadSetprio(this, AMPR_EMU_APR_REACTOR_THREAD_PRIORITY);
            if crate::rt::pack::AMPR_EMU_PACK_WORKER_AFFINITY != 0 {
                let _ = scePthreadSetaffinity(
                    this,
                    crate::rt::pack::AMPR_EMU_PACK_WORKER_AFFINITY as SceKernelCpumask,
                );
            }
        }
        if !arg.is_null() {
            unsafe { Self::pread_worker(arg.cast()) };
        }
        null_mut()
    }

    /// Takes the highest-priority, oldest queued task, preads it in up to
    /// AMPR_EMU_PACK_PREAD_MAX_BYTES pieces, publishes the result and wakes
    /// the reactor (under `m`, so the epoch change cannot race its wait).
    unsafe fn pread_worker(this: *mut Self) {
        let mutex = unsafe { &*addr_of!((*this).preadMutex) };
        let cv = unsafe { &*addr_of!((*this).preadCv) };
        loop {
            let (slot, request, queuedNs) = {
                let mut guard = mutex.lock();
                loop {
                    let mut found: Option<usize> = None;
                    for index in 0..AMPR_EMU_PACK_PREAD_TASKS {
                        let task = unsafe { &*addr_of!((*this).preadTasks[index]) };
                        if task.state.load(Ordering::Acquire) != PREAD_QUEUED {
                            continue;
                        }
                        if found.is_none_or(|best| {
                            let prior = unsafe { &*addr_of!((*this).preadTasks[best]) };
                            task.priority > prior.priority
                                || (task.priority == prior.priority
                                    && task.sequence < prior.sequence)
                        }) {
                            found = Some(index);
                        }
                    }
                    if let Some(slot) = found {
                        let task = unsafe { &*addr_of!((*this).preadTasks[slot]) };
                        task.state.store(PREAD_RUNNING, Ordering::Release);
                        break (slot, task.request, task.statQueuedNs);
                    }
                    if unsafe { (*this).preadStop } {
                        return;
                    }
                    cv.wait(&mut guard);
                }
            };
            let readStartNs = stats::now();
            let queueNs = readStartNs.saturating_sub(queuedNs);
            stats::add(Stat::PreadQueueNs, queueNs);
            stats::max(Stat::PreadQueueNsMax, queueNs);
            let (result, bytesRead) = match unsafe { crate::rt::pack::real_pread() } {
                Some(pread) => {
                    let mut done = 0usize;
                    let mut error = 0i64;
                    while done < request.nbyte {
                        let Some(offset) = off_t::try_from(done)
                            .ok()
                            .and_then(|n| request.offset.checked_add(n))
                        else {
                            error = SCE_KERNEL_ERROR_EINVAL as i64;
                            break;
                        };
                        let rc = unsafe {
                            pread(
                                request.fd,
                                request.buf.cast::<u8>().add(done).cast(),
                                (request.nbyte - done)
                                    .min(crate::rt::pack::AMPR_EMU_PACK_PREAD_MAX_BYTES as usize),
                                offset,
                            )
                        };
                        if rc == 0 {
                            break;
                        }
                        if rc < 0 {
                            let e = if rc == -1 { errno() } else { 0 };
                            if e == EINTR {
                                continue;
                            }
                            error = if rc == -1 {
                                sce_errno_from_posix(e) as i64
                            } else {
                                rc as i64
                            };
                            break;
                        }
                        done += rc as usize;
                    }
                    (if error != 0 { error } else { done as i64 }, done as u64)
                }
                None => (SCE_KERNEL_ERROR_EIO as i64, 0),
            };
            let readNs = stats::since(readStartNs);
            stats::add(Stat::PreadReads, 1);
            stats::add(Stat::PreadBytes, bytesRead);
            stats::add(Stat::PreadReadNs, readNs);
            stats::max(Stat::PreadReadNsMax, readNs);
            unsafe {
                (*request.result).returnValue = result;
                (*request.result).state = SCE_KERNEL_AIO_STATE_COMPLETED as u32;
            }
            unsafe {
                (*addr_of!((*this).preadTasks[slot]))
                    .state
                    .store(PREAD_DONE, Ordering::Release)
            };
            let _wakeGuard = unsafe { (&*addr_of!((*this).m)).lock() };
            unsafe { (*addr_of!((*this).reactorWakeEpoch)).fetch_add(1, Ordering::Release) };
            unsafe { (&*addr_of!((*this).reactorCv)).notify_one() };
        }
    }

    fn ensure_pread_workers(&mut self) -> bool {
        if self.preadThreadCount != 0 {
            return true;
        }
        let count = crate::rt::tune::pread_threads().min(AMPR_EMU_PACK_PREAD_WORKERS);
        while self.preadThreadCount < count {
            let mut thread: ScePthread = null_mut();
            let rc = unsafe {
                scePthreadCreate(
                    &mut thread,
                    null(),
                    Self::pread_worker_entry,
                    (self as *mut Self).cast(),
                    c"ampr_pack_pread".as_ptr(),
                )
            };
            if rc != 0 {
                break;
            }
            self.preadThreads[self.preadThreadCount] = thread;
            self.preadThreadCount += 1;
        }
        self.preadThreadCount != 0
    }

    /// Queues all requests of external group `targetSlot` together, so the
    /// pack keeps one Submitted/Completed callback pair. EAGAIN when fewer
    /// free tasks than requests (the group stays Pending). Reactor thread only.
    pub(crate) fn queue_pread_requests(
        &mut self,
        requests: &[SceKernelAioRWRequest],
        targetSlot: u32,
        targetGeneration: u32,
        priority: c_int,
    ) -> c_int {
        if requests.is_empty() || requests.len() > kAprExternalAioGroupMaxRequests {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        if !self.ensure_pread_workers() {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        let _guard = unsafe { (&*addr_of!(self.preadMutex)).lock() };
        let mut slots = [0usize; kAprExternalAioGroupMaxRequests];
        let mut found = 0usize;
        for (index, task) in self.preadTasks.iter().enumerate() {
            if task.state.load(Ordering::Acquire) == PREAD_FREE {
                slots[found] = index;
                found += 1;
                if found == requests.len() {
                    break;
                }
            }
        }
        if found != requests.len() {
            return SCE_KERNEL_ERROR_EAGAIN;
        }
        for (requestIndex, request) in requests.iter().enumerate() {
            let task = &mut self.preadTasks[slots[requestIndex]];
            task.request = *request;
            task.targetSlot = targetSlot;
            task.targetGeneration = targetGeneration;
            task.requestIndex = requestIndex as u32;
            task.priority = priority;
            task.sequence = self.preadNextSequence;
            self.preadNextSequence = self.preadNextSequence.wrapping_add(1);
            task.statQueuedNs = stats::now();
            task.state.store(PREAD_QUEUED, Ordering::Release);
        }
        self.preadPendingCount += requests.len() as u32;
        stats::max(Stat::PreadPendingMax, self.preadPendingCount as u64);
        self.preadCv.notify_all();
        0
    }

    /// Retires finished tasks; the last one of a group completes it.
    /// Reactor thread only.
    pub(crate) fn drain_pread_completions(&mut self) -> bool {
        if self.preadPendingCount == 0 {
            return false;
        }
        let mut progressed = false;
        for slot in 0..AMPR_EMU_PACK_PREAD_TASKS {
            if self.preadTasks[slot].state.load(Ordering::Acquire) != PREAD_DONE {
                continue;
            }
            let task = &self.preadTasks[slot];
            let reference = ExternalAioRef {
                slot: task.targetSlot,
                generation: task.targetGeneration,
            };
            let requestIndex = task.requestIndex;
            let queuedNs = task.statQueuedNs;
            if queuedNs != 0 {
                let latencyNs = stats::since(queuedNs);
                stats::add(Stat::ExtReads, 1);
                stats::add(Stat::ExtReadNs, latencyNs);
                stats::max(Stat::ExtReadNsMax, latencyNs);
            }
            let e = self.external_aio_at(&reference);
            if e.is_null()
                || unsafe { (*e).state != ExternalAioState::Submitted || !(*e).preadBacked }
            {
                abort();
            }
            let e = unsafe { &mut *e };
            if requestIndex >= e.requestCount || e.remainingCount == 0 {
                abort();
            }
            e.remainingCount -= 1;
            if e.remainingCount == 0 {
                if self.externalAioLiveCount.load(Ordering::Acquire) == 0 {
                    abort();
                }
                self.externalAioLiveCount.fetch_sub(1, Ordering::Release);
                let completionState = e.completionState;
                self.notify_external_aio(e, AprExternalAioEvent::Completed, completionState, false);
                Self::release_external_aio_slot(e);
            }
            self.preadTasks[slot]
                .state
                .store(PREAD_FREE, Ordering::Release);
            if self.preadPendingCount == 0 {
                abort();
            }
            self.preadPendingCount -= 1;
            progressed = true;
        }
        progressed
    }

    /// Joins the pool threads (reactor shutdown, after the worker loop ends).
    pub(crate) fn stop_pread_workers(&mut self) -> c_int {
        {
            let _guard = unsafe { (&*addr_of!(self.preadMutex)).lock() };
            self.preadStop = true;
            self.preadCv.notify_all();
        }
        for index in 0..self.preadThreadCount {
            if unsafe { scePthreadJoin(self.preadThreads[index], null_mut()) } != 0 {
                return SCE_KERNEL_ERROR_EIO;
            }
            self.preadThreads[index] = null_mut();
        }
        self.preadThreadCount = 0;
        0
    }
}
