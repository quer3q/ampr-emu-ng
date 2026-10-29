//! External AIO read submission, native AIO readiness, `shutdown` and `ReadIssueBudget`.

use super::*;

/// Detached borrow of a reactor mutex, so a held guard does not freeze `self`.
fn detached<'a>(m: &Mutex) -> &'a Mutex {
    unsafe { &*(m as *const Mutex) }
}

impl AprAioReactor {
    pub(crate) fn submit_external_aio_read(
        &mut self,
        request: &SceKernelAioRWRequest,
        priority: c_int,
        ioClass: AprExternalAioClass,
        context: *mut c_void,
        callback: AprExternalAioCallback,
    ) -> c_int {
        self.submit_external_aio_read_impl(request, 1, false, priority, ioClass, context, callback)
    }

    pub(crate) fn submit_external_aio_read_group(
        &mut self,
        requests: *const SceKernelAioRWRequest,
        requestCount: usize,
        priority: c_int,
        ioClass: AprExternalAioClass,
        context: *mut c_void,
        callback: AprExternalAioCallback,
    ) -> c_int {
        self.submit_external_aio_read_impl(
            requests,
            requestCount,
            true,
            priority,
            ioClass,
            context,
            callback,
        )
    }

    pub(crate) fn submit_external_aio_read_impl(
        &mut self,
        requests: *const SceKernelAioRWRequest,
        requestCount: usize,
        grouped: bool,
        priority: c_int,
        ioClass: AprExternalAioClass,
        context: *mut c_void,
        callback: AprExternalAioCallback,
    ) -> c_int {
        if requests.is_null()
            || callback.is_none()
            || requestCount == 0
            || requestCount > kAprExternalAioGroupMaxRequests
            || (grouped && requestCount < 2)
            || !(SCE_KERNEL_AIO_PRIORITY_LOW..=SCE_KERNEL_AIO_PRIORITY_HIGH).contains(&priority)
        {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let reqs = unsafe { core::slice::from_raw_parts(requests, requestCount) };
        let mut totalBytes: u64 = 0;
        for r in reqs {
            let n = r.nbyte as u64;
            if r.result.is_null() || r.fd < 0 || n == 0 || totalBytes > u64::MAX - n {
                return SCE_KERNEL_ERROR_EINVAL;
            }
            totalBytes += n;
        }
        if !self.start_worker() {
            return SCE_KERNEL_ERROR_ENOMEM;
        }

        let _lk = detached(&self.m).lock();
        if self.stop || self.shutdownRequested.load(Ordering::Acquire) {
            return SCE_KERNEL_ERROR_ECANCELED;
        }
        for slotIndex in 0..kExternalAioCapacity as usize {
            let slot = &mut self.externalAioReads[slotIndex];
            if slot.published.load(Ordering::Acquire) {
                continue;
            }
            let mut generation = slot.generation.wrapping_add(1);
            if generation == 0 {
                generation = 1;
            }
            slot.requests = [SceKernelAioRWRequest::default(); kAprExternalAioGroupMaxRequests];
            slot.aioIds = [-1; kAprExternalAioGroupMaxRequests];
            slot.submitTimeNs = 0;
            slot.retryNotBeforeNs = 0;
            slot.nextPollTimeNs = 0;
            slot.pollBackoffNs = 0;
            slot.requests[..requestCount].copy_from_slice(reqs);
            slot.requestCount = requestCount as u32;
            slot.remainingCount = 0;
            slot.totalBytes = totalBytes;
            slot.completionState = SCE_KERNEL_AIO_STATE_COMPLETED;
            slot.grouped = grouped;
            // Only the pack submits externals, into pool memory: pread-safe (pread_pool.rs).
            slot.preadBacked = crate::rt::tune::pread();
            slot.context = context;
            slot.callback = callback;
            slot.generation = generation;
            slot.aioPriority = priority;
            slot.ioClass = ioClass;
            slot.state = ExternalAioState::Pending;
            self.externalAioLiveCount.fetch_add(1, Ordering::Release);
            slot.published.store(true, Ordering::Release);
            self.reactorWakeEpoch.fetch_add(1, Ordering::Release);
            self.reactorCv.notify_one();
            return 0;
        }
        SCE_KERNEL_ERROR_EAGAIN
    }

    pub(crate) fn notify_external_progress(&self) {
        self.externalProgressPollAll.store(true, Ordering::Release);
        self.reactorWakeEpoch.fetch_add(1, Ordering::Release);
        self.reactorCv.notify_one();
    }

    pub(crate) fn shutdown(&mut self) -> c_int {
        // Serialize with worker creation (scePthreadCreate in flight).
        let _lifecycle = detached(&self.workerLifecycleMutex).lock();
        let thread = {
            let _lk = detached(&self.m).lock();
            if !self.started.load(Ordering::Acquire) {
                self.stop = true;
                self.shutdownRequested.store(true, Ordering::SeqCst);
                return 0;
            }
            if self.has_active_lanes_locked()
                || self.has_live_synthetic_waits_locked()
                || self.externalAioLiveCount.load(Ordering::Acquire) != 0
            {
                return SCE_KERNEL_ERROR_EBUSY;
            }
            self.shutdownRequested.store(true, Ordering::Release);
            self.reactorWakeEpoch.fetch_add(1, Ordering::Release);
            self.workerThread
        };
        self.notify_all_wait_domains();
        if unsafe { scePthreadJoin(thread, null_mut()) } != 0 {
            return SCE_KERNEL_ERROR_EIO;
        }
        self.started.store(false, Ordering::Release);
        self.stop_pread_workers()
    }
}

impl ReadIssueBudget {
    pub(crate) fn can_admit(&self, bytes: u64) -> bool {
        self.requestsLeft != 0 && bytes != 0 && bytes <= self.bytesLeft
    }

    pub(crate) fn consume(&mut self, bytes: u64) {
        if self.requestsLeft == 0 || bytes == 0 || bytes > self.bytesLeft {
            abort();
        }
        self.requestsLeft -= 1;
        self.bytesLeft -= bytes;
    }
}
