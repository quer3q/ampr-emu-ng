//! Idle wait, stale fd release, incoming drain and AIO admission snapshot/throttling.

use super::*;

impl AprAioReactor {
    pub(crate) fn idle_wait_timeout_ns() -> u64 {
        if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS == 0 {
            0
        } else if AMPR_EMU_FD_CACHE_IDLE_SCAN_NS != 0 {
            AMPR_EMU_FD_CACHE_IDLE_SCAN_NS
        } else {
            AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS
        }
    }

    pub(crate) fn maybe_release_stale_fds(&mut self, beforeIdleWait: bool) {
        if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS == 0 {
            return;
        }
        if !beforeIdleWait {
            self.fdCacheMaintenanceBusyLoops += 1;
            if self.fdCacheMaintenanceBusyLoops < kFdCacheMaintenanceBusyStride {
                return;
            }
        }
        self.fdCacheMaintenanceBusyLoops = 0;
        let nowNs = time_counter_now();
        if nowNs == 0 {
            return;
        }
        let deadline = nowNs.saturating_add(kFdCacheMaintenanceIntervalNs);
        if self.nextFdCacheMaintenanceNs == 0 {
            self.nextFdCacheMaintenanceNs = deadline;
            return;
        }
        if nowNs < self.nextFdCacheMaintenanceNs {
            return;
        }
        ampr_index_fd_cache_release_stale(nowNs);
        self.nextFdCacheMaintenanceNs = deadline;
    }

    pub(crate) fn drain_incoming(&mut self, waitIfIdle: bool) {
        let mut lk = self.m.lock();
        if waitIfIdle
            && !self.stop
            && !self.shutdownRequested.load(Ordering::Acquire)
            && !self.has_active_lanes_locked()
            && self.activeReads.empty()
            // Re-check under `m`: an external submit may have landed after worker() looked.
            && self.externalAioLiveCount.load(Ordering::Acquire) == 0
        {
            let idleWaitNs = Self::idle_wait_timeout_ns();
            if idleWaitNs != 0 {
                self.reactorCv.wait_for_us(&mut lk, idleWaitNs / 1000);
            } else {
                self.reactorCv.wait_until(&mut lk, || {
                    self.stop
                        || self.shutdownRequested.load(Ordering::Acquire)
                        || self.has_active_lanes_locked()
                        || !self.activeReads.empty()
                        || self.externalAioLiveCount.load(Ordering::Acquire) != 0
                });
            }
        }
    }

    pub(crate) fn active_read_age_ms(active: &ActiveRead, now: u64) -> u64 {
        if active.submitTimeNs != 0 && now >= active.submitTimeNs {
            (now - active.submitTimeNs) / 1_000_000
        } else {
            0
        }
    }

    pub(crate) fn note_active_read_peak(&mut self, _total: usize) {}
    pub(crate) fn note_aio_age_ms(&mut self, _ageMs: u64) {}
    pub(crate) fn note_emfile_event(&mut self) {}
    pub(crate) fn note_efault_retry_event(&mut self) {}
    pub(crate) fn note_efault_retry_limit_event(&mut self) {}

    pub(crate) fn refresh_aio_snapshot_age(snapshot: &mut AioAdmissionSnapshot, now: u64) {
        snapshot.oldestSubmittedAgeMs =
            if snapshot.oldestSubmittedTimeNs != 0 && now >= snapshot.oldestSubmittedTimeNs {
                (now - snapshot.oldestSubmittedTimeNs) / 1_000_000
            } else {
                0
            };
    }
}

impl AprAioReactor {
    pub(crate) fn external_aio_is_small_for_boost(external: &ExternalAioRead) -> bool {
        if AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES == 0 || external.requestCount == 0 {
            return false;
        }
        external.requests[..external.requestCount as usize]
            .iter()
            .all(|r| {
                let bytes = r.nbyte as u64;
                bytes != 0 && bytes <= AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES
            })
    }

    pub(crate) fn external_aio_admission_count(external: &ExternalAioRead) -> u32 {
        if external.state == ExternalAioState::Submitted {
            external.remainingCount
        } else {
            external.requestCount
        }
    }

    pub(crate) fn collect_aio_admission_snapshot(&self, now: u64) -> AioAdmissionSnapshot {
        let mut snapshot = AioAdmissionSnapshot::default();
        let mut it = self.activeReads.begin_const();
        let end = self.activeReads.end_const();
        while it != end {
            let active = unsafe { &*it.ptr() };
            it.inc();
            if !active.nativeCapacityCharged {
                continue;
            }
            snapshot.activeCount += 1;
            let classIndex = active.desc.readClass as usize;
            if classIndex < AmprLooseReadClass::Count as usize {
                snapshot.classActive[classIndex] += 1;
            }
            if Self::aio_desc_is_small_for_boost(&active.desc) {
                snapshot.smallCount += 1;
            }
            if !active.awaitingResubmit
                && active.aioId >= 0
                && active.submitTimeNs != 0
                && (snapshot.oldestSubmittedTimeNs == 0
                    || active.submitTimeNs < snapshot.oldestSubmittedTimeNs)
            {
                snapshot.oldestSubmittedTimeNs = active.submitTimeNs;
            }
            if !active.job.is_null() {
                let priority = unsafe { (*active.job).prioIndex };
                if priority < kPriorityCount {
                    let group = if priority == 0 {
                        0
                    } else if priority <= 3 {
                        1
                    } else {
                        2
                    };
                    snapshot.groupActive[group] += 1;
                }
            }
        }
        for external in self.externalAioReads.iter() {
            if !external.published.load(Ordering::Acquire)
                || external.state == ExternalAioState::Free
                || external.state == ExternalAioState::Pending
                || external.preadBacked
            {
                continue;
            }
            let commandCount = Self::external_aio_admission_count(external);
            snapshot.activeCount += commandCount as usize;
            if Self::external_aio_is_small_for_boost(external) {
                snapshot.smallCount += commandCount as usize;
            }
            snapshot.groupActive[Self::external_aio_group_index(external.aioPriority)] +=
                commandCount;
            if external.state == ExternalAioState::Submitted
                && external.submitTimeNs != 0
                && (snapshot.oldestSubmittedTimeNs == 0
                    || external.submitTimeNs < snapshot.oldestSubmittedTimeNs)
            {
                snapshot.oldestSubmittedTimeNs = external.submitTimeNs;
            }
        }
        Self::refresh_aio_snapshot_age(&mut snapshot, now);
        snapshot
    }

    pub(crate) fn slow_aio_cooldown_active(&self, now: u64) -> bool {
        AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS != 0
            && self.slowAioCooldownUntilNs != 0
            && now < self.slowAioCooldownUntilNs
    }

    pub(crate) fn aio_small_read_boost_recovery_cooldown_active(&self, now: u64) -> bool {
        AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS != 0
            && self.aioSmallReadBoostBlockedUntilNs != 0
            && now < self.aioSmallReadBoostBlockedUntilNs
    }

    pub(crate) fn arm_aio_small_read_boost_recovery_cooldown(&mut self, now: u64) {
        if AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS == 0 {
            return;
        }
        let until =
            now.wrapping_add(AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS * 1_000_000);
        if until > self.aioSmallReadBoostBlockedUntilNs {
            self.aioSmallReadBoostBlockedUntilNs = until;
        }
    }

    pub(crate) fn note_slow_aio_completion(&mut self, now: u64, ageMs: u64) {
        if AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS == 0
            || AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS == 0
            || ageMs < AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS
        {
            return;
        }
        let until = now.wrapping_add(AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS * 1_000_000);
        if until > self.slowAioCooldownUntilNs {
            self.slowAioCooldownUntilNs = until;
        }
    }

    pub(crate) fn aio_desc_is_small_for_boost(desc: &AprAioReadDesc) -> bool {
        AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES != 0
            && desc.length != 0
            && desc.length <= AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES
    }
}

impl AprAioReactor {
    pub(crate) fn aio_small_read_boost_eligible(
        &self,
        now: u64,
        snapshot: &AioAdmissionSnapshot,
    ) -> bool {
        if Self::aio_small_read_limit() <= Self::aio_active_read_limit()
            || AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES == 0
            || snapshot.activeCount < Self::aio_active_read_limit() as usize
        {
            return false;
        }
        if self.aioAgeThrottleLevel != AioAgeThrottleLevel::Normal
            || self.slow_aio_cooldown_active(now)
            || self.aio_small_read_boost_recovery_cooldown_active(now)
        {
            return false;
        }
        if snapshot.oldestSubmittedAgeMs > AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS {
            return false;
        }
        snapshot.smallCount * 100
            >= snapshot.activeCount * AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT as usize
    }

    pub(crate) fn aio_direct_read_admission_limit(
        &self,
        priority: u8,
        readClass: AmprLooseReadClass,
        sliceDesc: &AprAioReadDesc,
        now: u64,
        context: &AioAdmissionContext,
    ) -> u32 {
        let currentLimit = context.effectiveLimit;
        if AMPR_EMU_APR_AIO_LATENCY_ESCAPE_SLOTS == 0 {
            return currentLimit;
        }
        let baseLimit = Self::aio_active_read_limit();
        if currentLimit != baseLimit
            || priority > 3
            || readClass != AmprLooseReadClass::Latency
            || !Self::aio_desc_is_small_for_boost(sliceDesc)
            || context.fdPressure
            || self.aioAgeThrottleLevel != AioAgeThrottleLevel::Normal
            || self.slow_aio_cooldown_active(now)
            || self.aio_small_read_boost_recovery_cooldown_active(now)
            || context.snapshot.oldestSubmittedAgeMs > AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS
        {
            return currentLimit;
        }
        let availableExtra = Self::aio_small_read_limit().saturating_sub(baseLimit);
        baseLimit + AMPR_EMU_APR_AIO_LATENCY_ESCAPE_SLOTS.min(availableExtra)
    }

    pub(crate) fn update_aio_age_throttle(&mut self, now: u64, snapshot: &AioAdmissionSnapshot) {
        use AioAgeThrottleLevel::*;
        let previousLevel = self.aioAgeThrottleLevel;
        if snapshot.activeCount == 0 {
            self.aioAgeThrottleLevel = Normal;
            if previousLevel != Normal {
                self.arm_aio_small_read_boost_recovery_cooldown(now);
            }
            return;
        }
        let age = snapshot.oldestSubmittedAgeMs;
        let reached = |limit: u64| limit != 0 && age >= limit;
        let emergency = reached(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS);
        let severe = reached(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS);
        let medium = reached(AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS);
        let level = &mut self.aioAgeThrottleLevel;
        match *level {
            Normal => {
                if emergency {
                    *level = Emergency;
                } else if severe {
                    *level = Severe;
                } else if medium {
                    *level = Medium;
                }
            }
            Medium => {
                if emergency {
                    *level = Emergency;
                } else if severe {
                    *level = Severe;
                } else if age <= AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS {
                    *level = Normal;
                }
            }
            Severe => {
                if emergency {
                    *level = Emergency;
                } else if age <= AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS {
                    *level = Medium;
                }
            }
            Emergency => {
                if age <= AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS {
                    *level = Severe;
                }
            }
        }
        // Throttle already disables boost; delay only the return to the
        // expanded small-read window after the queue has recovered.
        if previousLevel != Normal && self.aioAgeThrottleLevel == Normal {
            self.arm_aio_small_read_boost_recovery_cooldown(now);
        }
    }
}
