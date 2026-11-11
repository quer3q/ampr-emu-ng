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
// queued task (not yet taken; running tasks hold their own thread) beyond
// the idle and spinning threads, up to its ceiling (tune::pread_threads, 6)
// and the thread budget (rt/thread_hooks.rs). A thread that finishes a task
// exits after RETIRE_STREAK such finishes in a row with more live than one
// above the load target (thread_hooks::LoadGroup). A game thread creation
// that fails with EAGAIN makes the pool give threads back, down to none
// (reads then go to kernel AIO); under the pressure that follows it grows
// only a first thread and retires to the target, down to none. A title
// saw its own scePthreadCreate fail with EAGAIN after 94 creations while 32
// pool threads were live.

/// Stack of a pool thread: it only loops on pread (pread_worker), so 32 KiB,
/// not libkernel's 64 KiB default. Stacks are the game's flexible memory,
/// which a title can use up (32 threads with 64 KiB stacks took 3 MiB).
const PREAD_STACK_BYTES: usize = 32 * 1024;
/// Threads the pool starts with and keeps while the game has room.
pub(crate) const PREAD_MIN_THREADS: u32 = 1;
/// A pool thread spinning for its next task (spin_for_task), at most one:
/// SPIN_NONE, SPIN_OPEN (no submit counted on it yet) or SPIN_CLAIMED (one
/// submit sent one wake fewer for it). Claimed and cleared under preadMutex.
/// The reactor is a single instance (g_apr_aio_reactor), so one word serves.
static PREAD_SPINNING: AtomicU32 = AtomicU32::new(SPIN_NONE);
const SPIN_NONE: u32 = 0;
const SPIN_OPEN: u32 = 1;
const SPIN_CLAIMED: u32 = 2;
/// How long a yielding game thread waits for pool threads to exit; a busy
/// thread exits after its current pread (~0.5 ms average, 15 ms max on a
/// zstd title, debug /metrics).
#[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
const PREAD_YIELD_WAIT_US: u64 = 50_000;

/// Busy pool thread samples and the load target (rt/thread_hooks.rs), under
/// preadMutex; the reactor is a single instance, so one static serves.
static PREAD_LOAD: crate::rt::thread_hooks::LoadGroup = crate::rt::thread_hooks::LoadGroup::new(0);

/// Debug /metrics: the read pool's load counters (LoadGroup::metrics).
#[cfg(feature = "mem_report")]
pub(crate) fn pread_pool_load() -> [u64; 5] {
    PREAD_LOAD.metrics()
}

// ---- yield to a failed game creation (rt/thread_hooks.rs make_room) ----

/// The reactor, when it has started.
fn reactor() -> Option<&'static AprAioReactor> {
    let reactor = g_apr_aio_reactor.load(Ordering::Acquire);
    (!reactor.is_null()).then(|| unsafe { &*reactor })
}

/// Live pool threads.
pub(crate) fn pread_pool_live() -> u32 {
    reactor().map_or(0, |r| {
        let _g = r.preadMutex.lock();
        r.preadThreadCount as u32
    })
}

/// AprAioReactor::ask_pread_exits; 0 before the reactor starts.
pub(crate) fn pread_pool_ask(want: u32) -> u32 {
    reactor().map_or(0, |r| r.ask_pread_exits(want))
}

/// AprAioReactor::reap_yielded_pread_threads; 0 before the reactor starts.
pub(crate) fn pread_pool_reap(before: u32) -> u32 {
    reactor().map_or(0, |r| r.reap_yielded_pread_threads(before))
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
    /// asked by ask_pread_exits, or after a task when the pool is above its
    /// load target. After a task it may spin for the next one
    /// (spin_for_task) before it parks.
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
        // This thread holds PREAD_SPINNING (spin_for_task); cleared under
        // preadMutex before the scan, so the one submit that claimed it and
        // sent one wake fewer is met by that scan.
        let mut spinner = false;
        // A task just finished: sampled, and the next scan decides whether
        // this thread stays.
        let mut finished = false;
        loop {
            let (slot, request, queuedNs) = {
                let mut guard = mutex.lock();
                if core::mem::take(&mut spinner) {
                    PREAD_SPINNING.store(SPIN_NONE, Ordering::Release);
                }
                if finished {
                    PREAD_LOAD.end();
                }
                let mut woken = false;
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
                    // Exits: one given back to the game (preadExitRequests,
                    // down to none), or one above the load target after a
                    // task. The last thread leaves only with no task
                    // queued, so no queued read is stranded.
                    let live = unsafe { (*this).preadThreadCount };
                    let may_yield = live > 1 || found.is_none();
                    if may_yield && unsafe { (*this).preadExitRequests } != 0 {
                        unsafe { (*this).preadExitRequests -= 1 };
                        exit(this);
                        // The wake that brought this thread may have been for
                        // the task it leaves: pass it on to a parked thread.
                        if found.is_some() {
                            cv.notify_one();
                        }
                        drop(guard);
                        return;
                    }
                    let ceiling = unsafe { (*this).preadCeiling };
                    if core::mem::take(&mut finished)
                        && !unsafe { (*this).preadStop }
                        && PREAD_LOAD.retire_due(live as u32, ceiling, found.is_some())
                    {
                        exit(this);
                        if found.is_some() {
                            cv.notify_one();
                        }
                        drop(guard);
                        return;
                    }
                    if let Some(slot) = found {
                        let task = unsafe { &*addr_of!((*this).preadTasks[slot]) };
                        task.state.store(PREAD_RUNNING, Ordering::Release);
                        PREAD_LOAD.begin();
                        break (slot, task.request, task.statQueuedNs);
                    }
                    if unsafe { (*this).preadStop } {
                        exit(this);
                        drop(guard);
                        return;
                    }
                    unsafe { (*this).preadIdle += 1 };
                    cv.wait(&mut guard);
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
            {
                let _wakeGuard = unsafe { (&*addr_of!((*this).m)).lock() };
                unsafe { (*addr_of!((*this).reactorWakeEpoch)).fetch_add(1, Ordering::Release) };
                unsafe { (&*addr_of!((*this).reactorCv)).notify_one() };
            }
            spinner = unsafe { Self::spin_for_task(this, slot) };
            finished = true;
        }
    }

    /// After a task, waits up to tune::spin_us for the next one with
    /// preadMutex released, so a task queued meanwhile is taken without a
    /// cv wake-up. Only one thread spins (PREAD_SPINNING), and only while
    /// another task is in flight (queued, running, or done and not yet
    /// retired): a lone read's next request comes after the reactor and the
    /// game have handled it, past any spin window. Returns true when this
    /// thread holds PREAD_SPINNING; the caller clears it under preadMutex.
    /// With spin_us 0 it does nothing.
    unsafe fn spin_for_task(this: *mut Self, own: usize) -> bool {
        let spin_us = crate::rt::tune::spin_us() as u64;
        if spin_us == 0 {
            return false;
        }
        let busy = (0..AMPR_EMU_PACK_PREAD_TASKS).any(|index| {
            index != own
                && unsafe { &*addr_of!((*this).preadTasks[index]) }
                    .state
                    .load(Ordering::Acquire)
                    != PREAD_FREE
        });
        if !busy
            || PREAD_SPINNING
                .compare_exchange(SPIN_NONE, SPIN_OPEN, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return false;
        }
        let deadline = time_counter_now() + spin_us * 1000;
        loop {
            let queued = (0..AMPR_EMU_PACK_PREAD_TASKS).any(|index| {
                unsafe { &*addr_of!((*this).preadTasks[index]) }
                    .state
                    .load(Ordering::Acquire)
                    == PREAD_QUEUED
            });
            if queued || time_counter_now() >= deadline {
                return true;
            }
            core::hint::spin_loop();
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
            if self.preadThreadCount >= self.preadCeiling as usize
                || !PREAD_LOAD.may_grow(self.preadThreadCount as u32)
            {
                return false;
            }
            let Some(slot) = self.preadSlots.iter().position(|&s| s == PREAD_SLOT_EMPTY) else {
                return false;
            };
            // The runtime-wide thread budget (rt/thread_hooks.rs); the first
            // thread is exempt unless the pool gave its last one away while
            // the pressure that asked for it lasts. After it, the flag is
            // dropped, or the pool would need budget room for good.
            if self.preadGaveLast && !crate::rt::thread_hooks::pressure() {
                self.preadGaveLast = false;
            }
            let first = self.preadThreadCount == 0 && !self.preadGaveLast;
            if !crate::rt::thread_hooks::reserve(first) {
                return false;
            }
            self.preadSlots[slot] = PREAD_SLOT_LIVE;
            self.preadThreadCount += 1;
            PREAD_LOAD.started(self.preadThreadCount as u32);
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
    /// to kernel AIO until the budget lets a thread back), and wakes them.
    /// Returns how many it asked. Called from a game thread whose creation
    /// failed, which then waits and calls `reap_yielded_pread_threads`.
    pub(crate) fn ask_pread_exits(&self, want: u32) -> u32 {
        let this = self as *const Self as *mut Self;
        let _g = self.preadMutex.lock();
        PREAD_LOAD.asked();
        let live = self.preadThreadCount as u32;
        // Exits other yields already asked for are not given twice.
        let give = crate::rt::thread_hooks::exits_to_ask(want, live, 0, self.preadExitRequests);
        if give == 0 {
            return 0;
        }
        // No ceiling change: the thread budget (rt/thread_hooks.rs) keeps
        // the pool from growing back.
        unsafe { (*this).preadExitRequests += give };
        if live == self.preadExitRequests {
            unsafe { (*this).preadGaveLast = true };
        }
        self.preadCv.notify_all();
        give
    }

    /// Joins the pool threads that left since `before` were live and
    /// counts them.
    pub(crate) fn reap_yielded_pread_threads(&self, before: u32) -> u32 {
        self.reap_pread_threads();
        let _g = self.preadMutex.lock();
        let released = before.saturating_sub(self.preadThreadCount as u32);
        stats::add(Stat::PreadThreadsYielded, released as u64);
        PREAD_LOAD.yielded(released);
        released
    }

    /// `ask_pread_exits`, up to PREAD_YIELD_WAIT_US for the threads to
    /// exit, then `reap_yielded_pread_threads`. Returns how many exited.
    #[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
    pub(crate) fn yield_pread_threads(&self, want: u32) -> u32 {
        let before = {
            let _g = self.preadMutex.lock();
            self.preadThreadCount as u32
        };
        if self.ask_pread_exits(want) == 0 {
            return 0;
        }
        {
            let mut g = self.preadMutex.lock();
            let deadline = time_counter_now() + PREAD_YIELD_WAIT_US * 1000;
            while self.preadExitRequests != 0 {
                let now = time_counter_now();
                if now >= deadline {
                    break;
                }
                let _ = self
                    .preadExitCv
                    .wait_for_us(&mut g, (deadline - now).div_ceil(1000));
            }
        }
        self.reap_yielded_pread_threads(before)
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
        // waits, so a signal that finds no sleeper loses no task. An open
        // spinner (spin_for_task) is claimed for one task and that task's
        // wake is not sent: the spinner rescans under preadMutex before it
        // can park or exit, and passes the wake on if it leaves instead. A
        // claimed spinner is not counted again, so every other task gets
        // its own notify_one.
        let spinner = PREAD_SPINNING
            .compare_exchange(SPIN_OPEN, SPIN_CLAIMED, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        if crate::rt::tune::pread_wake_all() {
            self.preadCv.notify_all();
        } else {
            for _ in 0..requests.len() - spinner as usize {
                self.preadCv.notify_one();
            }
        }
        // One new thread per queued task (not yet taken, from any submit)
        // beyond the idle threads and a spinner (claimed by this submit or
        // an earlier one; it takes one task at its rescan), at once, up to
        // the ceiling (spawn_pread_thread stops there). Running tasks hold
        // their own thread and do not count; a thread that finishes one
        // rescans before it waits.
        let queued = self
            .preadTasks
            .iter()
            .filter(|task| task.state.load(Ordering::Acquire) == PREAD_QUEUED)
            .count();
        let spinning = PREAD_SPINNING.load(Ordering::Acquire) != SPIN_NONE;
        let grow = queued.saturating_sub(self.preadIdle as usize + spinning as usize);
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
}
