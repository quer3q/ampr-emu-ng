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
// and the thread budget (rt/thread_hooks.rs). A started thread stays. A
// game thread creation that fails with EAGAIN makes the pool give threads
// back, down to none (reads then go to kernel AIO); under the pressure that
// follows (thread_hooks::LoadGroup) it grows only a first thread, and a
// thread that finishes a task leaves above one with work, none without. A title
// saw its own scePthreadCreate fail with EAGAIN after 94 creations while 32
// pool threads were live.

/// Stack of a pool thread, from the pool's stack block (rt/thread_stack.rs):
/// 64 KiB, libkernel's default. Besides its preads, a pool thread completes
/// pack jobs, and that can reap a decode worker (scePthreadJoin) and start
/// one (scePthreadCreate) inside libkernel, which a 32 KiB stack with a
/// no-access guard below it had no measured room for.
const PREAD_STACK_BYTES: usize = 64 * 1024;
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

/// The pool's pressure state and counters (rt/thread_hooks.rs), under
/// preadMutex; the reactor is a single instance, so one static serves.
static PREAD_LOAD: crate::rt::thread_hooks::LoadGroup = crate::rt::thread_hooks::LoadGroup::new(0);

/// Debug /metrics: the read pool's load counters (LoadGroup::metrics).
#[cfg(feature = "mem_report")]
pub(crate) fn pread_pool_load() -> [u64; 3] {
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

/// AprAioReactor::queue_pack_pread; ENOMEM before the reactor starts.
pub(crate) fn pread_pool_queue_pack(
    request: &SceKernelAioRWRequest,
    priority: c_int,
    callback: PackPreadCallback,
    context: *mut c_void,
) -> Result<usize, c_int> {
    reactor().map_or(Err(SCE_KERNEL_ERROR_ENOMEM), |r| {
        r.queue_pack_pread(request, priority, callback, context)
    })
}

/// Starts up to `n` pool threads, the count queue_pack_pread asked for.
/// The caller holds no runtime lock (PACK_M, preadMutex, `m`).
pub(crate) fn pread_pool_grow(n: usize) {
    if let Some(r) = reactor() {
        r.grow_pread_threads(n);
    }
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
    /// asked by ask_pread_exits, or after a task under pressure when the
    /// pool is above its target. After a task it may spin for the next one
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
        // A task just finished: the next scan decides whether this thread
        // stays.
        let mut finished = false;
        loop {
            let (slot, request, queuedNs, packCallback, packContext) = {
                let mut guard = mutex.lock();
                if core::mem::take(&mut spinner) {
                    PREAD_SPINNING.store(SPIN_NONE, Ordering::Release);
                }
                let mut woken = false;
                loop {
                    let mut found: Option<usize> = None;
                    // No queued task (an idle wake, an exit request): no scan.
                    let scan = match unsafe { &*addr_of!((*this).preadQueuedCount) }
                        .load(Ordering::Acquire)
                    {
                        0 => 0,
                        _ => AMPR_EMU_PACK_PREAD_TASKS,
                    };
                    for index in 0..scan {
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
                    // down to none), or one above the pressure target after
                    // a task. The last thread leaves only with no task
                    // queued, so no queued read is stranded.
                    // Threads still being created do not count: one whose
                    // creation fails leaves no thread for a queued task.
                    let may_yield = unsafe { (*this).started() } > 1 || found.is_none();
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
                        && PREAD_LOAD.retire_due(
                            unsafe { (*this).started() } as u32,
                            ceiling,
                            found.is_some(),
                        )
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
                        unsafe { &*addr_of!((*this).preadQueuedCount) }
                            .fetch_sub(1, Ordering::AcqRel);
                        break (
                            slot,
                            task.request,
                            task.statQueuedNs,
                            task.packCallback,
                            task.packContext,
                        );
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
            if let Some(callback) = packCallback {
                unsafe { Self::finish_pack_task(task, queuedNs, callback, packContext) };
                spinner = unsafe { Self::spin_for_task(this, slot) };
                finished = true;
                continue;
            }
            // Read before DONE: the reactor may retire the task right after.
            let (looseRead, target, generation) =
                unsafe { ((*task).looseRead, (*task).targetSlot, (*task).targetGeneration) };
            unsafe {
                (*task).returnValue = result;
                (*task).state.store(PREAD_DONE, Ordering::Release)
            };
            // A loose part wakes the reactor only when it is the read's last:
            // the reactor finishes a read when all its parts are in, and an
            // earlier part's wake made it run a whole pass for nothing (12
            // passes for a read of 6 parts).
            let wake = !looseRead
                || unsafe { &*addr_of!((*this).preadLoosePartsLeft) }
                    .get(target as usize)
                    .is_none_or(|word| loose_part_finished(word, generation));
            if wake {
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
            let queued = unsafe { &*addr_of!((*this).preadQueuedCount) }.load(Ordering::Acquire) != 0;
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

    /// Adds one pool thread; false when at the ceiling, stopping, or the
    /// creation failed (the thread budget, cut by the failure, then limits
    /// growth; the ceiling stays). The
    /// reactor thread (loose reads), or a pack worker holding no lock
    /// (pread_pool_grow):
    /// the slot is claimed under preadMutex, so two callers never share one.
    pub(crate) fn spawn_pread_thread(&self) -> bool {
        let this = self as *const Self as *mut Self;
        self.reap_pread_threads();
        let slot = {
            let _g = self.preadMutex.lock();
            if self.preadStop
                || self.preadThreadCount >= self.preadCeiling as usize
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
                unsafe { (*this).preadGaveLast = false };
            }
            let first = self.preadThreadCount == 0 && !self.preadGaveLast;
            if !crate::rt::thread_hooks::reserve(first) {
                return false;
            }
            unsafe {
                (*this).preadSlots[slot] = PREAD_SLOT_LIVE;
                (*this).preadThreadCount += 1;
                (*this).preadStarting += 1;
                // The slot is this caller's until its handle is published.
                (*this).preadArgs[slot] = PreadThreadArg {
                    reactor: this,
                    slot,
                };
            }
            PREAD_LOAD.started(self.preadThreadCount as u32);
            slot
        };
        let mut thread: ScePthread = null_mut();
        let arg = unsafe { addr_of_mut!((*this).preadArgs[slot]) }.cast();
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
        unsafe { (*this).preadStarting -= 1 };
        if rc != 0 {
            unsafe {
                (*this).preadSlots[slot] = PREAD_SLOT_EMPTY;
                (*this).preadThreadCount -= 1;
                // A yield may have counted this slot; drop requests no live
                // thread can meet, or make_room would wait on them forever.
                // The budget, cut by the failed creation, limits growth.
                (*this).preadExitRequests =
                    self.preadExitRequests.min(self.preadThreadCount as u32);
            }
            stats::add(Stat::PreadThreadCreateFailed, 1);
            return false;
        }
        unsafe { (*this).preadThreads[slot] = thread };
        // It may have left already (a yield or a stop asked it to): reap it.
        if self.preadSlots[slot] == PREAD_SLOT_EXITED {
            self.preadReapPending.store(true, Ordering::Release);
        }
        stats::add(Stat::PreadThreadsStarted, 1);
        stats::max(Stat::PreadThreadsMax, self.preadThreadCount as u64);
        true
    }

    /// Joins every EXITED pool thread (any thread may call it).
    /// A failed join empties the slot all the same and is counted (debug
    /// `thread_join_failed`): the handle no longer names a joinable thread,
    /// and libkernel reuses handles, so a retry could join or wait on an
    /// unrelated thread. Its pool stack stays reserved (rt/thread_stack.rs
    /// frees a stack only after a join that succeeded); none was ever seen.
    pub(crate) fn reap_pread_threads(&self) {
        loop {
            let (slot, thread) = {
                let this = self as *const Self as *mut Self;
                let _g = self.preadMutex.lock();
                // A slot whose handle is not published yet waits: its creator
                // flags a reap once it is (spawn_pread_thread).
                let Some(slot) = (0..self.preadSlots.len()).find(|&i| {
                    self.preadSlots[i] == PREAD_SLOT_EXITED
                        && !self.preadThreads[i].is_null()
                }) else {
                    return;
                };
                unsafe { (*this).preadSlots[slot] = PREAD_SLOT_JOINING };
                (slot, self.preadThreads[slot])
            };
            let rc = unsafe { scePthreadJoin(thread, null_mut()) };
            let this = self as *const Self as *mut Self;
            let _g = self.preadMutex.lock();
            if rc != 0 {
                stats::add(Stat::ThreadJoinFailed, 1);
            }
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
            // Pool threads lower the count through a raw pointer while this
            // thread waits; through `&self` the compiler may assume it never
            // changes and read it once (clippy while_immutable_condition),
            // so each pass reads it again.
            while unsafe { addr_of!(self.preadExitRequests).read_volatile() } != 0 {
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

    /// Queues external read `targetSlot`'s request for a pool thread (the
    /// pack keeps one Submitted/Completed callback pair). EAGAIN with no
    /// free task (the read stays Pending), ENOMEM with no live thread.
    /// Reactor thread only.
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
        let guard = unsafe { (&*addr_of!(self.preadMutex)).lock() };
        // No thread (all given to the game, or none could start): callers go
        // to kernel AIO. Checked under preadMutex, and the last thread leaves
        // only with no task queued (pread_worker), so no accepted read is
        // left without a thread. A thread still being created does not
        // count: its creation may fail with the read queued.
        if self.started() == 0 {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        let queued = self.queue_tasks_locked(requests, targetSlot, targetGeneration, priority, false);
        drop(guard);
        match queued {
            Ok(grow) => {
                self.grow_pread_threads(grow);
                0
            }
            Err(rc) => rc,
        }
    }

    /// Under preadMutex (the caller checked `started`): queues `requests`
    /// for one target into free tasks, all or none (EAGAIN when fewer are
    /// free), and wakes threads for them. A loose read (loose_pread.rs)
    /// queues its parts aimed at its ActiveRead slot; `requestIndex` is the
    /// part index. Ok: how many threads to start (grow_pread_threads, after
    /// the caller drops preadMutex).
    pub(super) fn queue_tasks_locked(
        &mut self,
        requests: &[SceKernelAioRWRequest],
        targetSlot: u32,
        targetGeneration: u32,
        priority: c_int,
        looseRead: bool,
    ) -> Result<usize, c_int> {
        let count = requests.len();
        if count == 0 || count > kAprExternalAioGroupMaxRequests {
            return Err(SCE_KERNEL_ERROR_EINVAL);
        }
        let mut slots = [0usize; kAprExternalAioGroupMaxRequests];
        let tasks = &self.preadTasks;
        let found = take_free_tasks(
            AMPR_EMU_PACK_PREAD_TASKS,
            self.preadFreeHint as usize,
            &mut slots[..count],
            |index| tasks[index].state.load(Ordering::Acquire) == PREAD_FREE,
        );
        if found != count {
            return Err(SCE_KERNEL_ERROR_EAGAIN);
        }
        if looseRead {
            // Set before any part is QUEUED: a thread reads it only after it
            // took a part under preadMutex.
            let Some(word) = self.preadLoosePartsLeft.get(targetSlot as usize) else {
                abort();
            };
            word.store(loose_parts_word(targetGeneration, count as u32), Ordering::Release);
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
            task.packCallback = None;
            task.packContext = null_mut();
            task.state.store(PREAD_QUEUED, Ordering::Release);
        }
        self.preadFreeHint = ((slots[count - 1] + 1) % AMPR_EMU_PACK_PREAD_TASKS) as u32;
        self.preadPendingCount += count as u32;
        stats::max(Stat::PreadPendingMax, self.preadPendingCount as u64);
        self.preadQueuedCount.fetch_add(count as u32, Ordering::AcqRel);
        Ok(self.wake_pread_threads_locked(count))
    }

    /// Starts up to `n` pool threads with no runtime lock held. On the
    /// reactor thread: when every pool thread is busy, it is the only thread
    /// that can start one, and deferring to a pool thread left the queue
    /// behind one slow pread.
    pub(super) fn grow_pread_threads(&self, n: usize) {
        for _ in 0..n {
            if !self.spawn_pread_thread() {
                break;
            }
        }
    }

    /// Under preadMutex, after `tasks` tasks were queued: wakes a thread per
    /// task and returns how many threads to start for the queued tasks no
    /// thread can take.
    fn wake_pread_threads_locked(&self, tasks: usize) -> usize {
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
            for _ in 0..tasks - spinner as usize {
                self.preadCv.notify_one();
            }
        }
        // One new thread per queued task (not yet taken, from any submit)
        // beyond the idle threads and a spinner (claimed by this submit or
        // an earlier one; it takes one task at its rescan), at once, up to
        // the ceiling (spawn_pread_thread stops there). Running tasks hold
        // their own thread and do not count; a thread that finishes one
        // rescans before it waits.
        let queued = self.preadQueuedCount.load(Ordering::Acquire) as usize;
        let spinning = PREAD_SPINNING.load(Ordering::Acquire) != SPIN_NONE;
        queued.saturating_sub(self.preadIdle as usize + spinning as usize)
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
                // Progress only when the read is finished: an earlier part
                // changes nothing the rest of the pass acts on.
                progressed |= self.finish_loose_pread(target, part);
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
            // Exiting threads lower the count through a raw pointer: read it
            // again each pass, as in yield_pread_threads.
            while unsafe { addr_of!(self.preadThreadCount).read_volatile() } != 0 {
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
            // A game thread is still joining one, or a pack worker has not
            // published the handle of one it started (pread_pool_grow):
            // wait, and join what is ready.
            self.reap_pread_threads();
            let mut spins = 0u32;
            ampr_spin_pause_or_yield(&mut spins);
        }
        0
    }
}

// ---- pack tasks: no reactor hop ----
//
// A pack worker queues its window read here itself (pack/worker.rs
// `submit_pipeline_io_locked`), and the pool thread that runs it calls the
// pack's completion, which requeues the job. That removes two reactor hops
// per missed chunk (reactor -> pool thread, reactor -> worker); before, a
// pack job took 1.54 ms against 0.81 ms of disk read on one title
// (Makefile), the rest queueing and hops. A refused queue (no free task, no
// live thread, stopping) goes through the reactor as before
// (submit_external_aio_read), which also starts the pool on first use and
// falls back to kernel AIO when it has no thread.
//
// Lock order: PACK_M -> preadMutex, and PACK_M -> `m` (the reactor path).
// The worker queues holding PACK_M. Nothing takes PACK_M with preadMutex or
// `m` held: the pool thread calls the pack completion holding no lock, and
// takes `m` only after it drops preadMutex (as the reactor never takes
// preadMutex under `m`), so the order has no cycle. Threads are created
// with none of these held: the worker starts the pool threads this queue
// asks for after it drops PACK_M (pread_pool_grow), never the reactor.

/// The pack's completion for a pack task: `(context, notification)`.
pub(crate) type PackPreadCallback =
    unsafe extern "C" fn(context: *mut c_void, notification: *const AprExternalAioNotification);

impl AprAioReactor {
    /// Queues one pack read for a pool thread. Ok: how many pool threads to
    /// start for it (pread_pool_grow, after the caller drops its locks).
    /// Err: ENOMEM with no live thread or the pool stopping, EAGAIN with no
    /// free task. Any thread; the caller may hold PACK_M (lock order above).
    pub(crate) fn queue_pack_pread(
        &self,
        request: &SceKernelAioRWRequest,
        priority: c_int,
        callback: PackPreadCallback,
        context: *mut c_void,
    ) -> Result<usize, c_int> {
        let this = self as *const Self as *mut Self;
        let _g = self.preadMutex.lock();
        // Only a thread whose creation returned: one still being created
        // may fail and take its count back with this task queued.
        if self.preadStop || self.started() == 0 {
            return Err(SCE_KERNEL_ERROR_ENOMEM);
        }
        let mut slot = [0usize; 1];
        let tasks = &self.preadTasks;
        if take_free_tasks(
            AMPR_EMU_PACK_PREAD_TASKS,
            self.preadFreeHint as usize,
            &mut slot,
            |index| tasks[index].state.load(Ordering::Acquire) == PREAD_FREE,
        ) == 0
        {
            return Err(SCE_KERNEL_ERROR_EAGAIN);
        }
        let index = slot[0];
        unsafe {
            (*this).preadFreeHint = ((index + 1) % AMPR_EMU_PACK_PREAD_TASKS) as u32;
            let task = &mut (*this).preadTasks[index];
            task.request = *request;
            task.targetSlot = u32::MAX;
            task.targetGeneration = 0;
            task.requestIndex = 0;
            task.looseRead = false;
            task.priority = priority;
            task.sequence = (*this).preadNextSequence;
            (*this).preadNextSequence = (*this).preadNextSequence.wrapping_add(1);
            task.statQueuedNs = stats::now();
            task.packCallback = Some(callback);
            task.packContext = context;
            task.state.store(PREAD_QUEUED, Ordering::Release);
        }
        self.preadQueuedCount.fetch_add(1, Ordering::AcqRel);
        if crate::rt::tune::ON {
            // Pack tasks are not in preadPendingCount (the reactor never
            // retires them): count the table instead.
            let busy = self
                .preadTasks
                .iter()
                .filter(|task| task.state.load(Ordering::Acquire) != PREAD_FREE)
                .count();
            stats::max(Stat::PreadPendingMax, busy as u64);
        }
        Ok(self.wake_pread_threads_locked(1))
    }

    /// Live pool threads whose creation returned, under preadMutex.
    pub(crate) fn started(&self) -> usize {
        self.preadThreadCount.saturating_sub(self.preadStarting)
    }

    /// A pack task's pread is done (its result is in `request.result`):
    /// frees the task, then calls the pack completion with no lock held.
    /// The task is freed first, so the job it requeues can queue its next
    /// read at once; nothing in the task is read after the store.
    unsafe fn finish_pack_task(
        task: *mut PreadTask,
        queuedNs: u64,
        callback: unsafe extern "C" fn(*mut c_void, *const AprExternalAioNotification),
        context: *mut c_void,
    ) {
        if queuedNs != 0 {
            let latencyNs = stats::since(queuedNs);
            stats::add(Stat::ExtReads, 1);
            stats::add(Stat::ExtReadNs, latencyNs);
            stats::max(Stat::ExtReadNsMax, latencyNs);
        }
        unsafe { (*task).state.store(PREAD_FREE, Ordering::Release) };
        let n = AprExternalAioNotification {
            event: AprExternalAioEvent::Completed,
            value: SCE_KERNEL_AIO_STATE_COMPLETED,
            firstExternalInSubmitBatch: false,
        };
        unsafe { callback(context, &n) };
    }
}

// ---- task table ----

/// Collects up to `out.len()` indexes of free tasks (`free`) into `out`,
/// scanning the `n` tasks cyclically from `hint`, and returns how many it
/// found. The hint is one past the last task queued: tasks are taken in
/// that order and freed in about that order, so the scan meets free tasks
/// first instead of walking every busy one from index 0.
pub(super) fn take_free_tasks(
    n: usize,
    hint: usize,
    out: &mut [usize],
    free: impl Fn(usize) -> bool,
) -> usize {
    let mut found = 0;
    for k in 0..n {
        if found == out.len() {
            break;
        }
        let index = (hint + k) % n;
        if free(index) {
            out[found] = index;
            found += 1;
        }
    }
    found
}

/// The parts-left word of a loose read queued at `generation` (its
/// ActiveRead listGeneration, never 0) with `parts` part tasks.
pub(super) const fn loose_parts_word(generation: u32, parts: u32) -> u64 {
    ((generation as u64) << 32) | parts as u64
}

/// A part task of the loose read at `generation` is DONE (stored before
/// this call, so the last part's count proves every part is visible as
/// DONE): counts it off `word` and returns true when it was the last part,
/// whose thread then wakes the reactor. Another generation in the word
/// means the reactor already retired every part (any pass drains DONE
/// tasks) and the slot holds a newer read: nothing to count, no wake
/// needed. A count already 0 (not expected) wakes, as a wake is harmless.
pub(super) fn loose_part_finished(word: &AtomicU64, generation: u32) -> bool {
    let mut current = word.load(Ordering::Acquire);
    loop {
        if (current >> 32) as u32 != generation {
            return false;
        }
        let left = current as u32;
        if left == 0 {
            return true;
        }
        match word.compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return left == 1,
            Err(now) => current = now,
        }
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
    fn free_task_scan_starts_at_the_hint_and_wraps() {
        let free = [true, false, true, false, false, true];
        let mut out = [0usize; 3];
        assert_eq!(take_free_tasks(6, 3, &mut out, |i| free[i]), 3);
        assert_eq!(out, [5, 0, 2]);
        let mut two = [0usize; 2];
        assert_eq!(take_free_tasks(6, 1, &mut two, |i| free[i]), 2);
        assert_eq!(two, [2, 5]);
        // Too few free: the count found, so the caller refuses all.
        let mut four = [0usize; 4];
        assert_eq!(take_free_tasks(6, 0, &mut four, |i| free[i]), 3);
        assert_eq!(take_free_tasks(6, 4, &mut four, |_| false), 0);
    }

    #[test]
    fn only_the_last_loose_part_wakes() {
        let word = AtomicU64::new(loose_parts_word(7, 3));
        assert!(!loose_part_finished(&word, 7));
        assert!(!loose_part_finished(&word, 7));
        assert!(loose_part_finished(&word, 7), "third of three");
        // A read that was retired and its slot reused by a newer read: an
        // old part's thread neither counts nor wakes.
        word.store(loose_parts_word(8, 2), Ordering::Relaxed);
        assert!(!loose_part_finished(&word, 7));
        assert_eq!(word.load(Ordering::Relaxed), loose_parts_word(8, 2));
        // A late part of a retired read whose slot was not reused: the
        // count is spent, so it wakes once more, which is harmless.
        let spent = AtomicU64::new(loose_parts_word(9, 0));
        assert!(loose_part_finished(&spent, 9));
        let one = AtomicU64::new(loose_parts_word(u32::MAX, 1));
        assert!(loose_part_finished(&one, u32::MAX), "an unsplit read");
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
