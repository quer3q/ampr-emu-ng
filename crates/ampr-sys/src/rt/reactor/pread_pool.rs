//! Blocking pread pool for the pack's physical reads (external AIO groups).
//! Kernel AIO on BFS serves 1-2 requests at a time; a pool of threads each
//! blocked in pread keeps many in flight. Pack reads land in the internal
//! pool (CPU memory), so a CPU pread can fill them. The game's loose APR
//! reads also come here (loose_pread.rs); their buffers may be GPU-only
//! (EFAULT from pread), so a failed one falls back to kernel AIO.
//! Ported from test-crate-readwrite (image bypass), external path.

use super::*;
use crate::rt::stats::{self, Stat};

// ---- pool size ----
//
// The pool keeps PREAD_MIN_THREADS threads and grows by one thread per
// queued task no idle thread takes, up to its ceiling (tune::pread_threads,
// 16) and the thread budget (rt/thread_hooks.rs). A thread idle for
// PREAD_IDLE_EXIT_US exits, down to the minimum. A game thread creation that
// fails with EAGAIN makes the pool give threads back, down to none (reads
// then go to kernel AIO), and the budget keeps it from growing back. A title
// saw its own scePthreadCreate fail with EAGAIN after 94 creations while 32
// pool threads were live.

/// Stack of a pool thread: it only loops on pread (pread_worker), so 32 KiB,
/// not libkernel's 64 KiB default. Stacks are the game's flexible memory,
/// which a title can use up (32 threads with 64 KiB stacks took 3 MiB).
const PREAD_STACK_BYTES: usize = 32 * 1024;
/// Threads the pool starts with and keeps while the game has room.
pub(crate) const PREAD_MIN_THREADS: u32 = 1;
/// A thread with no task for this long exits (down to the minimum).
const PREAD_IDLE_EXIT_US: u64 = 2_000_000;
/// How long a yielding game thread waits for pool threads to exit; a busy
/// thread exits after its current pread (~0.5 ms average, 15 ms max on a
/// zstd title, debug /metrics).
const PREAD_YIELD_WAIT_US: u64 = 50_000;

/// Next sleep of an idle pool thread. When the idle period is over but the
/// thread may not exit (the last one, PREAD_MIN_THREADS), a full new period
/// is waited: the old `remaining` was 0 and floored to 1 us, so the thread
/// re-scanned the empty table thousands of times a second while idle.
fn idle_wait_us(idle_ns: u64, may_exit: bool) -> u64 {
    let period = PREAD_IDLE_EXIT_US * 1000;
    let left = if idle_ns >= period && !may_exit {
        period
    } else {
        period.saturating_sub(idle_ns)
    };
    left.div_ceil(1000).max(1)
}

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
            let a = unsafe { *(arg as *const PreadThreadArg) };
            unsafe { Self::pread_worker(a.reactor, a.slot) };
        }
        null_mut()
    }

    /// Takes the highest-priority, oldest queued task, preads it in up to
    /// AMPR_EMU_PACK_PREAD_MAX_BYTES pieces, publishes the result and wakes
    /// the reactor (under `m`, so the epoch change cannot race its wait).
    /// Leaves its loop (slot EXITED, under preadMutex) on stop, on an exit
    /// asked by pread_pool_yield, or after PREAD_IDLE_EXIT_US idle, the last
    /// two only above PREAD_MIN_THREADS.
    unsafe fn pread_worker(this: *mut Self, thread_slot: usize) {
        let mutex = unsafe { &*addr_of!((*this).preadMutex) };
        let cv = unsafe { &*addr_of!((*this).preadCv) };
        // Under preadMutex: this thread leaves the live set.
        let exit = |this: *mut Self| unsafe {
            (*this).preadThreadCount -= 1;
            (*this).preadSlots[thread_slot] = PREAD_SLOT_EXITED;
            (&*addr_of!((*this).preadExitCv)).notify_all();
            // Wake the reactor to join it (not under `m`: no lock order with
            // preadMutex; a missed wake only defers the join to the next pass).
            (*addr_of!((*this).preadReapPending)).store(true, Ordering::Release);
            (*addr_of!((*this).reactorWakeEpoch)).fetch_add(1, Ordering::Release);
            (&*addr_of!((*this).reactorCv)).notify_one();
        };
        loop {
            let (slot, request, queuedNs) = {
                let mut guard = mutex.lock();
                let mut woken = false;
                // Idle time from when this thread last found a task, not
                // from its last wake-up (`pread_wake_all` wakes them all).
                let mut idle_since = time_counter_now();
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
                    if woken {
                        stats::add(Stat::PreadWakeups, 1);
                        if found.is_none() {
                            stats::add(Stat::PreadWakeupsIdle, 1);
                        }
                    }
                    // Exits: an idle thread above PREAD_MIN_THREADS, or one
                    // given back to the game (preadExitRequests, down to
                    // none). The last thread leaves only with no task
                    // queued, so no queued read is stranded.
                    let live = unsafe { (*this).preadThreadCount };
                    let may_exit = live > PREAD_MIN_THREADS as usize;
                    let may_yield = live > 1 || found.is_none();
                    if may_yield && unsafe { (*this).preadExitRequests } != 0 {
                        unsafe { (*this).preadExitRequests -= 1 };
                        exit(this);
                        drop(guard);
                        return;
                    }
                    if let Some(slot) = found {
                        let task = unsafe { &*addr_of!((*this).preadTasks[slot]) };
                        task.state.store(PREAD_RUNNING, Ordering::Release);
                        break (slot, task.request, task.statQueuedNs);
                    }
                    let idle_ns = time_counter_now().saturating_sub(idle_since);
                    let idle_timeout = idle_ns >= PREAD_IDLE_EXIT_US * 1000;
                    if unsafe { (*this).preadStop } || (idle_timeout && may_exit) {
                        if idle_timeout {
                            stats::add(Stat::PreadThreadsRetired, 1);
                        }
                        exit(this);
                        drop(guard);
                        return;
                    }
                    // The last thread may not exit (PREAD_MIN_THREADS), so a
                    // timeout that could not retire it starts a new idle
                    // period. Without this reset the remaining wait stayed at
                    // its 1 us floor and the thread woke thousands of times a
                    // second while the game was idle. A fixed-build run of a
                    // zstd title (261 s, debug /metrics) reported
                    // pread_wakeups_idle 147, 0.6 per second.
                    if idle_timeout {
                        idle_since = time_counter_now();
                    }
                    unsafe { (*this).preadIdle += 1 };
                    let left_us = idle_wait_us(idle_ns, may_exit);
                    let _ = cv.wait_for_us(&mut guard, left_us);
                    unsafe { (*this).preadIdle -= 1 };
                    woken = true;
                }
            };
            let readStartNs = stats::now();
            let queueNs = readStartNs.saturating_sub(queuedNs);
            stats::add(Stat::PreadQueueNs, queueNs);
            stats::max(Stat::PreadQueueNsMax, queueNs);
            let (result, bytesRead) = match unsafe { crate::rt::pack::real_pread() } {
                Some(pread) => pread_parts(
                    request.nbyte,
                    request.offset,
                    crate::rt::pack::AMPR_EMU_PACK_PREAD_MAX_BYTES as usize,
                    |done, len, offset| unsafe {
                        pread(request.fd, request.buf.cast::<u8>().add(done).cast(), len, offset)
                    },
                    errno,
                ),
                None => (SCE_KERNEL_ERROR_EIO as i64, 0),
            };
            let readNs = stats::since(readStartNs);
            stats::add(Stat::PreadReads, 1);
            stats::add(Stat::PreadBytes, bytesRead);
            stats::add(Stat::PreadReadNs, readNs);
            stats::max(Stat::PreadReadNsMax, readNs);
            if !request.result.is_null() {
                unsafe {
                    (*request.result).returnValue = result;
                    (*request.result).state = SCE_KERNEL_AIO_STATE_COMPLETED as u32;
                }
            }
            // The task is RUNNING, so only this thread touches it until DONE.
            let task = unsafe { addr_of_mut!((*this).preadTasks[slot]) };
            unsafe {
                (*task).returnValue = result;
                (*task).state.store(PREAD_DONE, Ordering::Release)
            };
            let _wakeGuard = unsafe { (&*addr_of!((*this).m)).lock() };
            unsafe { (*addr_of!((*this).reactorWakeEpoch)).fetch_add(1, Ordering::Release) };
            unsafe { (&*addr_of!((*this).reactorCv)).notify_one() };
        }
    }

    /// Starts the pool (PREAD_MIN_THREADS threads) on first use. Reactor
    /// thread only; true when at least one thread is live.
    pub(super) fn ensure_pread_workers(&mut self) -> bool {
        let started = {
            let _g = self.preadMutex.lock();
            if self.preadCeiling == 0 {
                self.preadCeiling = crate::rt::tune::pread_threads()
                    .min(AMPR_EMU_PACK_PREAD_WORKERS)
                    .max(1) as u32;
            }
            self.preadThreadCount
        };
        if started != 0 {
            return true;
        }
        for _ in 0..PREAD_MIN_THREADS.min(self.preadCeiling) {
            if !self.spawn_pread_thread() {
                break;
            }
        }
        let _g = self.preadMutex.lock();
        self.preadThreadCount != 0
    }

    /// Adds one pool thread; false when at the ceiling or the creation
    /// failed (the ceiling then drops to the live count). Reactor thread only.
    fn spawn_pread_thread(&mut self) -> bool {
        self.reap_pread_threads();
        let slot = {
            let _g = self.preadMutex.lock();
            if self.preadThreadCount >= self.preadCeiling as usize {
                return false;
            }
            let Some(slot) = self.preadSlots.iter().position(|&s| s == PREAD_SLOT_EMPTY) else {
                return false;
            };
            // The runtime-wide thread budget (rt/thread_hooks.rs); the first
            // thread is exempt unless the pool gave its last one away.
            let first = self.preadThreadCount == 0 && !self.preadGaveLast;
            if !crate::rt::thread_hooks::reserve(first) {
                return false;
            }
            self.preadSlots[slot] = PREAD_SLOT_LIVE;
            self.preadThreadCount += 1;
            slot
        };
        self.preadArgs[slot] = PreadThreadArg {
            reactor: self as *mut Self,
            slot,
        };
        let mut thread: ScePthread = null_mut();
        let arg = addr_of_mut!(self.preadArgs[slot]).cast();
        let rc = unsafe {
            crate::rt::thread_hooks::create_counted(
                (&mut thread as *mut ScePthread).cast(),
                Self::pread_worker_entry,
                arg,
                c"ampr_pack_pread".as_ptr(),
                PREAD_STACK_BYTES,
            )
        };
        let _g = self.preadMutex.lock();
        if rc != 0 {
            self.preadSlots[slot] = PREAD_SLOT_EMPTY;
            self.preadThreadCount -= 1;
            // A yield may have counted this slot; drop requests no live
            // thread can meet, or make_room would wait on them forever. The
            // budget, cut by the failed creation, limits growth.
            self.preadExitRequests = self.preadExitRequests.min(self.preadThreadCount as u32);
            stats::add(Stat::PreadThreadCreateFailed, 1);
            return false;
        }
        self.preadThreads[slot] = thread;
        // It may have left already (a yield asked it to): reap it now.
        if self.preadSlots[slot] == PREAD_SLOT_EXITED {
            self.preadReapPending.store(true, Ordering::Release);
        }
        stats::add(Stat::PreadThreadsStarted, 1);
        stats::max(Stat::PreadThreadsMax, self.preadThreadCount as u64);
        true
    }

    /// Joins every EXITED pool thread (any thread may call it).
    pub(crate) fn reap_pread_threads(&self) {
        loop {
            let (slot, thread) = {
                let this = self as *const Self as *mut Self;
                let _g = self.preadMutex.lock();
                // A slot whose handle is not published yet waits: its creator
                // flags a reap once it is (spawn_pread_thread).
                let Some(slot) = (0..self.preadSlots.len()).find(|&i| {
                    self.preadSlots[i] == PREAD_SLOT_EXITED && !self.preadThreads[i].is_null()
                }) else {
                    return;
                };
                unsafe { (*this).preadSlots[slot] = PREAD_SLOT_JOINING };
                (slot, self.preadThreads[slot])
            };
            let _ = unsafe { scePthreadJoin(thread, null_mut()) };
            let this = self as *const Self as *mut Self;
            let _g = self.preadMutex.lock();
            unsafe {
                (*this).preadThreads[slot] = null_mut();
                (*this).preadSlots[slot] = PREAD_SLOT_EMPTY;
            }
        }
    }

    /// Asks up to `want` pool threads to exit, down to none (reads then go
    /// to kernel AIO until the budget lets a thread back), waits up to
    /// PREAD_YIELD_WAIT_US for them and joins them. Returns how many exited.
    /// Called from a game thread whose creation failed.
    pub(crate) fn yield_pread_threads(&self, want: u32) -> u32 {
        let this = self as *const Self as *mut Self;
        let target = {
            let mut g = self.preadMutex.lock();
            let live = self.preadThreadCount as u32;
            // Exits other yields already asked for are not given twice.
            let give = want.min(live.saturating_sub(self.preadExitRequests));
            if give == 0 {
                return 0;
            }
            // No ceiling change: the thread budget (rt/thread_hooks.rs)
            // keeps the pool from growing back.
            unsafe { (*this).preadExitRequests += give };
            let target = live - self.preadExitRequests;
            if target == 0 {
                unsafe { (*this).preadGaveLast = true };
            }
            self.preadCv.notify_all();
            let deadline = time_counter_now() + PREAD_YIELD_WAIT_US * 1000;
            while (self.preadThreadCount as u32) > target {
                let now = time_counter_now();
                if now >= deadline {
                    break;
                }
                let _ = self
                    .preadExitCv
                    .wait_for_us(&mut g, (deadline - now).div_ceil(1000));
            }
            (live, target)
        };
        self.reap_pread_threads();
        let live = {
            let _g = self.preadMutex.lock();
            self.preadThreadCount as u32
        };
        let released = target.0.saturating_sub(live);
        stats::add(Stat::PreadThreadsYielded, released as u64);
        released
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
        self.queue_pread_tasks(requests, targetSlot, targetGeneration, priority, false)
    }

    /// `queue_pread_requests` for either target kind; a loose read
    /// (loose_pread.rs) queues its part requests (one when unsplit) aimed at
    /// its ActiveRead slot, all or none; `requestIndex` is the part index.
    pub(crate) fn queue_pread_tasks(
        &mut self,
        requests: &[SceKernelAioRWRequest],
        targetSlot: u32,
        targetGeneration: u32,
        priority: c_int,
        looseRead: bool,
    ) -> c_int {
        if requests.is_empty() || requests.len() > kAprExternalAioGroupMaxRequests {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        if !self.ensure_pread_workers() {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        let _guard = unsafe { (&*addr_of!(self.preadMutex)).lock() };
        // No thread (all given to the game, or none could start): callers go
        // to kernel AIO. Checked under preadMutex, and the last thread leaves
        // only with no task queued (pread_worker), so no accepted read is
        // left without a thread.
        if self.preadThreadCount == 0 {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
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
            task.looseRead = looseRead;
            task.priority = priority;
            task.sequence = self.preadNextSequence;
            self.preadNextSequence = self.preadNextSequence.wrapping_add(1);
            task.statQueuedNs = stats::now();
            task.state.store(PREAD_QUEUED, Ordering::Release);
        }
        self.preadPendingCount += requests.len() as u32;
        stats::max(Stat::PreadPendingMax, self.preadPendingCount as u64);
        // One thread per task, not all of them: the threads run at the
        // highest priority (256) on the game's cores, and with 32 threads and
        // at most 4-5 tasks queued (debug /metrics) a broadcast woke ~27
        // threads per submit for nothing. A busy thread rescans before it
        // waits, so a signal that finds no sleeper loses no task.
        if crate::rt::tune::pread_wake_all() {
            self.preadCv.notify_all();
        } else {
            for _ in requests {
                self.preadCv.notify_one();
            }
        }
        // One new thread per task no idle thread takes, at once, up to the
        // ceiling (spawn_pread_thread stops there).
        let grow = requests.len().saturating_sub(self.preadIdle as usize);
        drop(_guard);
        for _ in 0..grow {
            if !self.spawn_pread_thread() {
                break;
            }
        }
        0
    }

    /// Retires finished tasks; the last one of a group completes it.
    /// Reactor thread only.
    pub(crate) fn drain_pread_completions(&mut self) -> bool {
        if self.preadReapPending.swap(false, Ordering::AcqRel) {
            self.reap_pread_threads();
        }
        if self.preadPendingCount == 0 {
            return false;
        }
        let mut progressed = false;
        for slot in 0..AMPR_EMU_PACK_PREAD_TASKS {
            if self.preadTasks[slot].state.load(Ordering::Acquire) != PREAD_DONE {
                continue;
            }
            let task = &self.preadTasks[slot];
            if task.looseRead {
                let target = ActiveReadRef {
                    slot: task.targetSlot,
                    generation: task.targetGeneration,
                };
                let part = LoosePartDone {
                    index: task.requestIndex,
                    offset: task.request.offset,
                    len: task.request.nbyte as u64,
                    value: task.returnValue,
                };
                self.retire_pread_task(slot);
                if self.preadLooseCount == 0 {
                    abort();
                }
                self.preadLooseCount -= 1;
                self.finish_loose_pread(target, part);
                progressed = true;
                continue;
            }
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
            self.retire_pread_task(slot);
            progressed = true;
        }
        progressed
    }

    fn retire_pread_task(&mut self, slot: usize) {
        self.preadTasks[slot]
            .state
            .store(PREAD_FREE, Ordering::Release);
        if self.preadPendingCount == 0 {
            abort();
        }
        self.preadPendingCount -= 1;
    }

    /// Stops and joins the pool threads (reactor shutdown, after the worker
    /// loop ends). Threads exit on preadStop; a yielding game thread may
    /// join some of them meanwhile.
    pub(crate) fn stop_pread_workers(&mut self) -> c_int {
        {
            let mut g = self.preadMutex.lock();
            self.preadStop = true;
            self.preadCv.notify_all();
            while self.preadThreadCount != 0 {
                let _ = self.preadExitCv.wait_for_us(&mut g, 100_000);
            }
        }
        self.reap_pread_threads();
        loop {
            let busy = {
                let _g = self.preadMutex.lock();
                self.preadSlots.iter().any(|&s| s != PREAD_SLOT_EMPTY)
            };
            if !busy {
                break;
            }
            // A game thread is still joining one: wait for it.
            let mut spins = 0u32;
            ampr_spin_pause_or_yield(&mut spins);
        }
        0
    }
}

// ---- pread loop ----

/// One pool task's pread loop over `read(done, len, offset) -> rc` (libc
/// pread semantics: -1 with `errno()`), in pieces of at most `max_request`
/// bytes. Returns (result, bytes read): result is the byte count, or an SCE
/// error. A short read continues at the new offset and EOF (0) ends the
/// read short. EINTR retries up to `PREAD_EINTR_RETRIES` (16) times in a
/// row, the bound the pack loader's `pread_loop` (pack/state.rs) and the
/// index reader (rt/index.rs) use; past it the part fails with
/// SCE_KERNEL_ERROR_EINTR, so a kernel returning EINTR forever no longer
/// pins a pool thread. Progress resets the count.
pub(super) fn pread_parts(
    nbyte: usize,
    offset: off_t,
    max_request: usize,
    mut read: impl FnMut(usize, usize, off_t) -> ssize_t,
    errno: impl Fn() -> c_int,
) -> (i64, u64) {
    let mut done = 0usize;
    let mut interrupted = 0u32;
    let mut error = 0i64;
    while done < nbyte {
        let Some(at) = off_t::try_from(done)
            .ok()
            .and_then(|n| offset.checked_add(n))
        else {
            error = SCE_KERNEL_ERROR_EINVAL as i64;
            break;
        };
        let rc = read(done, (nbyte - done).min(max_request.max(1)), at);
        if rc == 0 {
            break;
        }
        if rc < 0 {
            let e = if rc == -1 { errno() } else { 0 };
            if e == EINTR && interrupted < crate::rt::pack::PREAD_EINTR_RETRIES {
                interrupted += 1;
                continue;
            }
            error = if rc == -1 {
                sce_errno_from_posix(e) as i64
            } else {
                rc as i64
            };
            break;
        }
        interrupted = 0;
        done += rc as usize;
    }
    (if error != 0 { error } else { done as i64 }, done as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rt::pack::PREAD_EINTR_RETRIES;

    /// Runs `pread_parts` over a script of results (Some(n): n bytes;
    /// None: -1 with EINTR); past the script every call is EIO.
    fn run(nbyte: usize, script: &[Option<isize>]) -> (i64, u64, usize) {
        let calls = core::cell::Cell::new(0usize);
        let last = core::cell::Cell::new(0);
        let (result, read) = pread_parts(
            nbyte,
            0,
            4,
            |_, len, _| {
                let i = calls.get();
                calls.set(i + 1);
                match script.get(i) {
                    Some(Some(n)) => (*n).min(len as isize),
                    Some(None) => {
                        last.set(EINTR);
                        -1
                    }
                    None => {
                        last.set(EINTR + 1);
                        -1
                    }
                }
            },
            || last.get(),
        );
        (result, read, calls.get())
    }

    #[test]
    fn eintr_is_bounded_and_reset_by_progress() {
        let bound = PREAD_EINTR_RETRIES as usize;
        // Endless EINTR: bound retries, then the part fails with EINTR.
        let endless = vec![None; bound + 8];
        let (rc, read, calls) = run(8, &endless);
        assert_eq!(rc, SCE_KERNEL_ERROR_EINTR as i64);
        assert_eq!((read, calls), (0, bound + 1));
        // `bound` EINTRs, progress, `bound` again: the count resets.
        let mut script = vec![None; bound];
        script.push(Some(4));
        script.extend(vec![None; bound]);
        script.push(Some(4));
        assert_eq!(run(8, &script), (8, 8, 2 * bound + 2));
        // A short read continues; EOF ends short; other errors fail.
        assert_eq!(run(7, &[Some(3), Some(4)]).0, 7);
        assert_eq!(run(8, &[Some(3), Some(0)]).0, 3);
        assert_eq!(run(8, &[Some(3)]).0, SCE_KERNEL_ERROR_EIO as i64);
        // Each call resumes where the last short read ended, capped per request.
        let mut seen = Vec::new();
        let mut reads = [3, 2, 4, 1].into_iter();
        let rc = pread_parts(
            10,
            100,
            4,
            |done, len, at| {
                seen.push((done, len, at));
                reads.next().unwrap()
            },
            || 0,
        );
        assert_eq!(rc, (10, 10));
        assert_eq!(seen, [(0, 4, 100), (3, 4, 103), (5, 4, 105), (9, 1, 109)]);
    }

    #[test]
    fn a_thread_that_cannot_exit_waits_a_full_idle_period() {
        let period_us = PREAD_IDLE_EXIT_US;
        // Before the timeout the remaining time is what is left.
        assert_eq!(idle_wait_us(0, false), period_us);
        assert_eq!(idle_wait_us(period_us * 1000 / 2, false), period_us / 2);
        // Past it, the last thread sleeps another whole period instead of
        // spinning on the 1 us floor.
        assert_eq!(idle_wait_us(period_us * 1000, false), period_us);
        assert_eq!(idle_wait_us(period_us * 1000 * 3, false), period_us);
    }
}
