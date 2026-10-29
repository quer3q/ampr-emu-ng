//! Direct-read fd policy, read descriptor acquire/release, `submit` and synthetic submit-id waits.

use super::*;

pub(crate) const fn apr_direct_read_aio_limit(effectiveLimit: u32, baseLimit: u32) -> u32 {
    if effectiveLimit == 0 || baseLimit == 0 {
        return 0;
    }
    // Direct one-shot reads keep at most half of the base AIO window.
    let directShare = baseLimit / 2 + baseLimit % 2;
    if effectiveLimit < directShare {
        effectiveLimit
    } else {
        directShare
    }
}

const _: () = assert!(apr_direct_read_aio_limit(64, 32) == 16);
const _: () = assert!(apr_direct_read_aio_limit(16, 32) == 16);
const _: () = assert!(apr_direct_read_aio_limit(8, 32) == 8);
const _: () = assert!(apr_direct_read_aio_limit(1, 1) == 1);

pub(crate) fn apr_adaptive_direct_fd_cap(
    caps: &AmprIndexFdPressureCaps,
    aioLimit: u32,
    fdPressure: bool,
) -> usize {
    let budget = caps.fd_budget;
    if budget == 0 || aioLimit == 0 {
        return 0;
    }
    let reserve = AMPR_EMU_FD_DIRECT_CAP_RESERVE;
    let mut cap = if budget > reserve {
        budget - reserve
    } else {
        1
    };
    cap = cap.min(aioLimit as usize);
    if fdPressure {
        let pressureShare = ((budget * AMPR_EMU_FD_DIRECT_CAP_PRESSURE_PERCENT) / 100).max(1);
        cap = cap.min(pressureShare);
    }
    cap
}

pub(crate) fn apr_update_read_desc_fd_policy(rd: &mut AprAioReadDesc, promoteFullFile: bool) {
    if !rd.fileMetadataValid {
        return;
    }
    rd.bypassFdCache =
        apr_read_is_single_quantum_full_file(rd.offset, rd.length, rd.fileSize as u64)
            && !promoteFullFile;
}

pub(crate) fn apr_read_desc_entry(rd: &AprAioReadDesc, out: *mut FileEntryView) -> bool {
    if out.is_null() {
        return false;
    }
    if rd.fileMetadataValid {
        let o = unsafe { &mut *out };
        o.path = rd.filePath;
        o.path_length = rd.filePathLength;
        o.size = rd.fileSize;
        o.mtime = 0;
        return !rd.filePath.is_null();
    }
    unsafe { ampr_index_get_entry_view(rd.fileId, out) == 0 }
}

pub(crate) fn apr_acquire_aio_read_desc(
    jobId: u64,
    rd: &mut AprAioReadDesc,
    allowNewFd: bool,
    directOpenCap: usize,
    outRc: *mut c_int,
    outErrorOffset: *mut u32,
) -> bool {
    let set_rc = |rc: c_int| {
        if !outRc.is_null() {
            unsafe { *outRc = rc };
        }
    };
    set_rc(0);
    if !outErrorOffset.is_null() {
        unsafe { *outErrorOffset = rd.errorOff };
    }
    if rd.fd >= 0 {
        return true;
    }

    if rd.bypassFdCache {
        let mut directEntry: FileEntryView = unsafe { core::mem::zeroed() };
        let haveDirectEntry = apr_read_desc_entry(rd, &mut directEntry);
        if !haveDirectEntry {
            set_rc(apr_file_id_lookup_error(rd.fileId));
            return false;
        }
        // A packed direct read uses a synthetic descriptor; resolve it before
        // applying physical direct-FD caps.
        let mut packedHandled = false;
        let packedFd = unsafe {
            ampr_pack_try_open_indexed(
                rd.fileId,
                &directEntry,
                kAprAioOpenFlags,
                0,
                &mut packedHandled,
            )
        };
        if packedHandled {
            if packedFd < 0 {
                set_rc(packedFd);
                return false;
            }
            rd.fd = packedFd;
            rd.closeAfter = true;
            rd.closeAfterPhysical = false;
            return true;
        }
        let fdCaps = ampr_index_fd_pressure_current_caps();
        let directOpen = ampr_index_fd_direct_open_count();
        if directOpenCap != 0 && directOpen + 1 > directOpenCap {
            set_rc(SCE_KERNEL_ERROR_EAGAIN);
            return false;
        }
        let requestedReserve = 1 + AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE;
        let openReserve = requestedReserve.min(fdCaps.fd_budget);
        if !allowNewFd
            && !unsafe {
                ampr_index_fd_common_open_budget_headroom_available(
                    openReserve,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            }
        {
            set_rc(SCE_KERNEL_ERROR_EAGAIN);
            return false;
        }
        // Only reclaim cache entries when the reserve would exceed the budget.
        let observedOpen = ampr_index_fd_cache_stats().open + ampr_index_fd_uncached_open_count();
        let hasBudgetHeadroom =
            observedOpen <= fdCaps.fd_budget && openReserve <= fdCaps.fd_budget - observedOpen;
        if !hasBudgetHeadroom && !ampr_index_fd_cache_release_open_fd_budget_headroom(openReserve) {
            set_rc(SCE_KERNEL_ERROR_EAGAIN);
            return false;
        }
        let mut fd = unsafe { ampr_real_posix_open(directEntry.path, kAprAioOpenFlags, 0) };
        if fd == -1 {
            fd = ampr_sce_errno_from_posix(errno());
        }
        let openErrno = if fd < 0 {
            ampr_posix_errno_from_sce(fd)
        } else {
            0
        };
        let openPressure = fd < 0 && ampr_posix_errno_is_fd_open_pressure(openErrno);
        if openPressure {
            let observedOpen =
                ampr_index_fd_cache_stats().open + ampr_index_fd_uncached_open_count();
            ampr_index_fd_cache_mark_open_pressure(observedOpen);
            ampr_index_fd_cache_release_idle_percent(
                AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT,
            );
        }
        if fd < 0 {
            set_rc(ampr_sce_errno_from_posix(openErrno));
            return false;
        }
        rd.fd = fd;
        rd.closeAfter = true;
        rd.closeAfterPhysical = true;
        ampr_index_fd_direct_note_open();
        return true;
    }

    let mut cachedEntry: FileEntryView = unsafe { core::mem::zeroed() };
    if !apr_read_desc_entry(rd, &mut cachedEntry) {
        set_rc(apr_file_id_lookup_error(rd.fileId));
        return false;
    }
    // Cache acquisition tries packed files before enforcing the physical FD budget.
    let fd = unsafe {
        ampr_index_acquire_cached_fd(jobId, rd.fileId, &cachedEntry, kAprAioOpenFlags, 0, true)
    };
    if fd < 0 {
        set_rc(ampr_sce_errno_from_posix(-fd));
        return false;
    }
    rd.fd = fd;
    rd.cachePinned = true;
    true
}

pub(crate) fn apr_release_aio_read_desc(rd: &mut AprAioReadDesc) {
    if rd.fd < 0 {
        return;
    }
    if rd.borrowedFd {
        rd.fd = -1;
        rd.cachePinned = false;
        rd.borrowedFd = false;
        return;
    }
    if rd.closeAfter {
        unsafe { sceKernelClose(rd.fd) };
        if rd.closeAfterPhysical {
            ampr_index_fd_direct_note_close();
        }
        rd.fd = -1;
        rd.closeAfterPhysical = false;
        return;
    }
    if rd.cachePinned {
        ampr_index_release_cached_fd_pin(rd.fileId);
        rd.cachePinned = false;
    }
    rd.fd = -1;
}

/// Detached borrow of the reactor mutex, so a held guard does not freeze `self`.
fn reactor_mutex<'a>(m: &Mutex) -> &'a Mutex {
    unsafe { &*(m as *const Mutex) }
}

impl AprAioReactor {
    fn stopping(&self) -> bool {
        self.stop || self.shutdownRequested.load(Ordering::Acquire)
    }

    pub(crate) fn submit(&mut self, j: &Job, outSubmitId: *mut SceAprSubmitId) -> c_int {
        if !outSubmitId.is_null() {
            unsafe { *outSubmitId = 0 };
        }

        let job: JobPtr = loop {
            let job = self.allocate_job_state();
            if !job.is_null() {
                break job;
            }
            let mut lk = reactor_mutex(&self.m).lock();
            if self.stopping() {
                return SCE_KERNEL_ERROR_ECANCELED;
            }
            self.jobStateWaiterCount.fetch_add(1, Ordering::Release);
            self.jobStateAvailableCv.wait_until(&mut lk, || {
                self.stopping() || self.jobStateFreeCount.load(Ordering::Acquire) != 0
            });
            self.jobStateWaiterCount.fetch_sub(1, Ordering::Release);
            if self.stopping() {
                return SCE_KERNEL_ERROR_ECANCELED;
            }
        };

        let js = unsafe { &mut *job };
        js.id = j.id;
        js.commandCount = j.sourceCommandCount;
        js.nativePrio = j.nativePrio;
        js.prioIndex = apr_scheduler_priority_lane(j.nativePrio);
        js.submitMode = j.submitMode;
        js.aprRes = j.aprRes;
        if j.sourceBuffer.is_null() || j.sourceBytes == 0 || j.sourceCommandCount == 0 {
            self.set_fail(
                js,
                c"software-source-state".as_ptr(),
                SCE_KERNEL_ERROR_EINVAL,
                0,
                0,
            );
            let rc = js.result.rc;
            self.release_job_state(job);
            return rc;
        }
        js.sourceBuffer = j.sourceBuffer.cast();
        js.sourceBytes = j.sourceBytes;
        js.nativeSubmitType = j.nativeSubmitType;
        if !self.start_worker() {
            self.release_job_state(job);
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        {
            let mut lk = reactor_mutex(&self.m).lock();
            if self.stopping() {
                drop(lk);
                self.release_job_state(job);
                return SCE_KERNEL_ERROR_ECANCELED;
            }
            let mut syntheticId: SceAprSubmitId = 0;
            if !outSubmitId.is_null() {
                // Only live work holds a request slot; completed results move
                // to the bounded exact-id history.
                while !self.reserve_synthetic_wait_slot_locked(js) {
                    if self.stopping() {
                        self.release_unpublished_synthetic_wait_slot_locked(js);
                        drop(lk);
                        self.release_job_state(job);
                        return SCE_KERNEL_ERROR_ECANCELED;
                    }
                    self.syntheticRequestAvailableCv.wait(&mut lk);
                }
                // The lower submit-id descriptor is released on completion.
                while !self.allocate_synthetic_lower_slot_locked(js, &mut syntheticId) {
                    if self.stopping() {
                        self.release_unpublished_synthetic_wait_slot_locked(js);
                        drop(lk);
                        self.release_job_state(job);
                        return SCE_KERNEL_ERROR_ECANCELED;
                    }
                    self.syntheticLowerSlotAvailableCv.wait(&mut lk);
                }
            }
            if !self.add_active_job_locked(job) {
                self.release_unpublished_synthetic_wait_slot_locked(js);
                drop(lk);
                self.release_job_state(job);
                return SCE_KERNEL_ERROR_ENOMEM;
            }
            if !outSubmitId.is_null() {
                js.syntheticWaitPublished = true;
                unsafe { *outSubmitId = js.syntheticSubmitId };
            }
            self.reactorWakeEpoch.fetch_add(1, Ordering::Release);
            drop(lk);
        }
        self.reactorCv.notify_one();
        0
    }

    pub(crate) fn wait_synthetic_submit_id(
        &mut self,
        id: SceAprSubmitId,
        outHandled: *mut bool,
    ) -> c_int {
        let set_handled = |v: bool| {
            if !outHandled.is_null() {
                unsafe { *outHandled = v };
            }
        };
        set_handled(false);
        let mut lowerSlot: u32 = 0;
        let mut generation: u32 = 0;
        if !Self::decode_synthetic_submit_id(id, &mut lowerSlot, &mut generation) {
            return 0;
        }

        let mut lk = reactor_mutex(&self.m).lock();
        // A completed id has released its lower slot and moved to the done ring:
        // take it there first, before the wait-slot hint misses into a full scan.
        let lower = self.syntheticLowerSlots[lowerSlot as usize];
        let mut completedResult: c_int = 0;
        if !(lower.active && lower.generation == generation)
            && self.take_synthetic_done_result_locked(id, &mut completedResult)
        {
            set_handled(true);
            return completedResult;
        }
        let requestSlot = self.find_synthetic_wait_slot_locked(id);
        if requestSlot >= kSyntheticRequestCapacity {
            // A tag-shaped native APR/AMM id is not ours.
            return 0;
        }
        set_handled(true);
        let slot = requestSlot as usize;
        let waitSlot = &mut self.syntheticWaitSlots[slot];
        if waitSlot.waiterClaimed {
            return SCE_KERNEL_ERROR_EBUSY;
        }
        waitSlot.waiterClaimed = true;
        if !waitSlot.ownerJob.is_null() {
            unsafe {
                (*waitSlot.ownerJob)
                    .schedulingWaiterClaimed
                    .store(true, Ordering::Release)
            };
        }
        let laneIndex = waitSlot.prioIndex as usize;
        self.reactorWakeEpoch.fetch_add(1, Ordering::Release);
        self.reactorCv.notify_one();
        self.syntheticWaitCvs[laneIndex].wait_until(&mut lk, || {
            let current = &self.syntheticWaitSlots[slot];
            !current.active || current.submitId != id || current.done
        });
        let completed = &mut self.syntheticWaitSlots[slot];
        if !completed.active || completed.submitId != id {
            return SCE_KERNEL_ERROR_ESRCH;
        }
        let rc = completed.result;
        *completed = SyntheticWaitSlot::default();
        drop(lk);
        // The waiter owned the live record until now.
        self.syntheticRequestAvailableCv.notify_one();
        rc
    }
}
