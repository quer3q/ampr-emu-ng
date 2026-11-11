//! Virtual fd read/seek entry points, backing AIO completion and shutdown.

use super::*;
use core::ptr::addr_of_mut;
use core::sync::atomic::AtomicU8;

pub unsafe fn ampr_pack_try_getdents_fd(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    handled: *mut bool,
) -> c_int {
    unsafe { ampr_pack_try_directory_read_fd(fd, buffer, size, null_mut(), false, handled) }
}

pub unsafe fn ampr_pack_try_getdirentries_fd(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
    handled: *mut bool,
) -> c_int {
    unsafe { ampr_pack_try_directory_read_fd(fd, buffer, size, basep, true, handled) }
}

unsafe fn clear_handled(handled: *mut bool) {
    if !handled.is_null() {
        unsafe { *handled = false };
    }
}

// ---- ordinary virtual fd reads -----------------------------------------------
//
// read/pread/readv/preadv of a virtual pack fd submit one virtual AIO
// request per iovec segment (aio.rs) and wait for them (aio_wait.rs), so chunks are
// read and decoded only on the pack workers, each with its own decoder. The
// caller sleeps on AIO_CV like a game's own sceKernelAioWaitRequests. pread*
// leave the slot cursor alone; read* and lseek hold the slot's
// VIRTUAL_FD_MUTEXES entry (close takes it too) while they use and move the
// cursor. Results are byte counts or SCE error codes; the posix_* hooks
// convert those to -1/errno.

/// FreeBSD `UIO_MAXIOV`.
pub(crate) const VIRTUAL_READ_IOV_MAX: usize = 1024;
const SEEK_END: c_int = 2;
/// FreeBSD `EISDIR` (no SCE constant in sys.rs).
const EISDIR_POSIX: c_int = 21;

/// Byte total of a readv/preadv vector: EINVAL past `UIO_MAXIOV` or above
/// `SSIZE_MAX`, EFAULT for a null base with a nonzero length.
pub(crate) fn iov_total(iov: &[SceKernelIovec]) -> Result<usize, c_int> {
    if iov.len() > VIRTUAL_READ_IOV_MAX {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    let mut total = 0usize;
    for v in iov {
        total = total
            .checked_add(v.iov_len)
            .filter(|&t| t <= isize::MAX as usize)
            .ok_or(SCE_KERNEL_ERROR_EINVAL)?;
    }
    if iov.iter().any(|v| v.iov_base.is_null() && v.iov_len != 0) {
        return Err(SCE_KERNEL_ERROR_EFAULT);
    }
    Ok(total)
}

/// The caller's vector as a slice: EINVAL for a negative or too large count,
/// EFAULT for a null array with a nonzero count.
pub(crate) unsafe fn iov_slice<'a>(
    iov: *const SceKernelIovec,
    iovcnt: c_int,
) -> Result<&'a [SceKernelIovec], c_int> {
    if iovcnt < 0 || iovcnt as usize > VIRTUAL_READ_IOV_MAX {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    if iovcnt == 0 {
        return Ok(&[]);
    }
    if iov.is_null() {
        return Err(SCE_KERNEL_ERROR_EFAULT);
    }
    Ok(unsafe { core::slice::from_raw_parts(iov, iovcnt as usize) })
}

/// Bytes a read of `want` at `offset` returns from a file of `size` bytes:
/// zero at or past EOF and for `want == 0`; EINVAL for a negative offset.
pub(crate) fn clamp_read(offset: off_t, want: usize, size: u64) -> Result<u64, c_int> {
    if offset < 0 {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    let offset = offset as u64;
    Ok(if offset >= size {
        0
    } else {
        (want as u64).min(size - offset)
    })
}

/// New cursor of an lseek: EINVAL for an unknown `whence`, a negative
/// result, or one past `off_t::MAX` (there is no SCE EOVERFLOW constant).
/// Seeking past EOF is allowed; a read there returns 0.
pub(crate) fn seek_target(
    cursor: u64,
    size: u64,
    offset: off_t,
    whence: c_int,
) -> Result<u64, c_int> {
    let base = match whence {
        SEEK_SET => 0i128,
        SEEK_CUR => cursor as i128,
        SEEK_END => size as i128,
        _ => return Err(SCE_KERNEL_ERROR_EINVAL),
    };
    let target = base + offset as i128;
    if target < 0 || target > off_t::MAX as i128 {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    Ok(target as u64)
}

/// One read request per non-empty segment of `vector` for its bytes
/// `[done, length)`, at most `out.len()` of them: (file offset = `offset` +
/// vector position, buffer, bytes). Returns the number written.
pub(crate) fn plan_segment_reads(
    vector: &[SceKernelIovec],
    offset: u64,
    length: u64,
    done: u64,
    out: &mut [(u64, *mut u8, usize)],
) -> usize {
    let (mut count, mut at, mut start) = (0usize, done, 0u64);
    for v in vector {
        let end = start + v.iov_len as u64;
        if count == out.len() || at >= length {
            break;
        }
        if v.iov_len != 0 && at < end {
            let skip = at - start;
            let n = (end - at).min(length - at);
            out[count] = (
                offset + at,
                (v.iov_base as *mut u8).wrapping_add(skip as usize),
                n as usize,
            );
            count += 1;
            at += n;
        }
        start = end;
    }
    count
}

/// Gap between submit retries while the virtual AIO table is full.
const SUBMIT_RETRY_USECS: u32 = 100;
/// A full virtual AIO table (EAGAIN) is retried while pack jobs keep
/// completing (`aio_completion_epoch` moves); the read fails with EAGAIN
/// only after this long with no completion at all. The old fixed budget
/// (2000 retries, ~0.2 s) failed a blocking read whose slots were only held
/// by slow reads: one 1 MiB read from a USB disk can take longer than that,
/// and a sleeping USB HDD takes seconds to spin up.
const SUBMIT_IDLE_LIMIT_USECS: u64 = 10_000_000;
/// Absolute cap from the first EAGAIN, even while completions keep moving:
/// other readers can keep the table full forever, and a blocking read must
/// still fail (EAGAIN, as before) instead of hanging the caller. 30 s covers
/// the multi-second USB HDD spin-up above with room to spare.
const SUBMIT_TOTAL_LIMIT_USECS: u64 = 30_000_000;

/// Retry policy of `read_on_workers` for a full virtual AIO table.
pub(crate) struct SubmitBackoff {
    epoch: u64,
    first: u64,
    idle_since: u64,
    /// Idle retries; bounds the wait when the clock is unavailable (now = 0).
    idle_retries: u64,
    /// All retries; bounds the total wait when the clock is unavailable.
    total_retries: u64,
}

impl SubmitBackoff {
    pub(crate) fn new(now: u64, epoch: u64) -> Self {
        Self {
            epoch,
            first: now,
            idle_since: now,
            idle_retries: 0,
            total_retries: 0,
        }
    }

    /// True to retry the submit at `now` with completion epoch `epoch`.
    pub(crate) fn retry(&mut self, now: u64, epoch: u64) -> bool {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.idle_since = now;
            self.idle_retries = 0;
        }
        self.idle_retries += 1;
        self.total_retries += 1;
        elapsed_usecs(self.idle_since, now) < SUBMIT_IDLE_LIMIT_USECS
            && self.idle_retries <= SUBMIT_IDLE_LIMIT_USECS / SUBMIT_RETRY_USECS as u64
            && elapsed_usecs(self.first, now) < SUBMIT_TOTAL_LIMIT_USECS
            && self.total_retries <= SUBMIT_TOTAL_LIMIT_USECS / SUBMIT_RETRY_USECS as u64
    }
}

unsafe fn completion_epoch() -> u64 {
    let state = unsafe { pack_state() };
    let _lock = PACK_M.lock();
    unsafe { (*state).aio_completion_epoch }
}

/// Reads `[offset, offset + length)` (already clamped to EOF, nonzero) of
/// virtual fd `fd` into `vector` on the pack workers: batches of one AIO
/// request per segment, submitted and waited for here, so chunks decode only
/// on workers (each owns one decoder). Returns `length`, the bytes before the
/// first short or failed request (a partial read), or that error when nothing
/// was read.
unsafe fn read_on_workers(
    fd: c_int,
    vector: &[SceKernelIovec],
    offset: u64,
    length: u64,
) -> ssize_t {
    const N: usize = SCE_KERNEL_AIO_REQUEST_NUM_MAX;
    let mut done = 0u64;
    while done < length {
        let mut plan = [(0u64, null_mut::<u8>(), 0usize); N];
        let count = plan_segment_reads(vector, offset, length, done, &mut plan);
        if count == 0 {
            break;
        }
        let mut results = [SceKernelAioResult {
            return_value: 0,
            state: 0,
        }; N];
        let mut requests = [SceKernelAioRWRequest::EMPTY; N];
        for i in 0..count {
            let (at, buf, nbyte) = plan[i];
            requests[i] = SceKernelAioRWRequest {
                offset: at as off_t,
                nbyte,
                buf: buf.cast(),
                result: unsafe { results.as_mut_ptr().add(i) },
                fd,
            };
        }
        let mut ids = [0 as SceKernelAioSubmitId; N];
        let mut backoff: Option<SubmitBackoff> = None;
        let rc = loop {
            let rc = unsafe {
                sceKernelAioSubmitReadCommandsMultiple(
                    requests.as_mut_ptr(),
                    count as c_int,
                    SCE_KERNEL_AIO_PRIORITY_HIGH,
                    ids.as_mut_ptr(),
                )
            };
            if rc != SCE_KERNEL_ERROR_EAGAIN {
                break rc;
            }
            let (now, epoch) = (pack_monotonic_usecs(), unsafe { completion_epoch() });
            let retry = backoff
                .get_or_insert_with(|| SubmitBackoff::new(now, epoch))
                .retry(now, epoch);
            if !retry {
                break rc;
            }
            unsafe { sceKernelUsleep(SUBMIT_RETRY_USECS) };
        };
        if rc != 0 {
            return if done != 0 {
                done as ssize_t
            } else {
                rc as ssize_t
            };
        }
        let mut states = [0 as c_int; N];
        let wait_rc = unsafe {
            sceKernelAioWaitRequests(
                ids.as_mut_ptr(),
                count as c_int,
                states.as_mut_ptr(),
                SCE_KERNEL_AIO_WAIT_AND,
                null_mut(),
            )
        };
        if wait_rc != 0 {
            // An untimed wait on our own virtual ids cannot fail; returning
            // would leave workers writing into this frame's `results`.
            abort();
        }
        let mut deleted = [0 as c_int; N];
        let _ = unsafe {
            sceKernelAioDeleteRequests(ids.as_mut_ptr(), count as c_int, deleted.as_mut_ptr())
        };
        for i in 0..count {
            let rv = results[i].return_value;
            if rv < 0 {
                return if done != 0 {
                    done as ssize_t
                } else {
                    rv as ssize_t
                };
            }
            done += rv as u64;
            if (rv as u64) < plan[i].2 as u64 {
                return done as ssize_t;
            }
        }
    }
    match done {
        0 => SCE_KERNEL_ERROR_EIO as ssize_t,
        n => n as ssize_t,
    }
}

// ---- read threads ----------------------------------------------------------

/// `read_on_workers` runs here, not on the caller's thread: its frames hold
/// AIO arrays sized for 128 requests (read_on_workers 12,024 B,
/// sceKernelAioSubmitReadCommandsMultiple 13,528 B, publish_virtual_jobs
/// 6,600 B in the debug PRX), ~32 KB that a small game thread does not have.
/// A game's video I/O thread read a packed file and faulted on the guard
/// page in publish_virtual_jobs. The thread stacks (at most READ_THREADS x
/// READ_STACK = 4 x 128 KiB = 512 KiB) are libkernel memory, outside the
/// internal pool. Every virtual-fd read pays one handoff; smaller AIO
/// arrays (smaller batches, more submits) would let the caller's thread
/// read inline, if the handoff shows in read latency.
const READ_THREADS: usize = 4;
/// 128 KiB: read_on_workers needs ~32 KB (above). The stacks come from the
/// game's flexible memory, which a title can use up (flex_free_bytes 0 of
/// 312 MiB, debug /metrics).
const READ_STACK: usize = 128 * 1024;
const READ_QUEUE: usize = 64;

/// One read handed to a read thread; lives on the waiting caller's stack.
struct ReadCall {
    fd: c_int,
    vector: *const SceKernelIovec,
    count: usize,
    offset: u64,
    length: u64,
    rc: ssize_t,
    done: bool,
    /// Index into READ_DONE_CVS of the condvar its caller waits on.
    cv: usize,
}

/// FIFO of `N` queued items: read threads take the oldest call, so a queued
/// read cannot starve behind later ones (a first-free-slot scan took the
/// lowest slot, which later calls could refill every time). `head` and
/// `tail` count pops and pushes; the slot is the count mod `N`.
struct Fifo<T: Copy, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    tail: usize,
}

impl<T: Copy, const N: usize> Fifo<T, N> {
    const fn new() -> Self {
        Self {
            slots: [None; N],
            head: 0,
            tail: 0,
        }
    }
    /// Appends `item`; false (and nothing changes) when `N` are queued.
    fn push(&mut self, item: T) -> bool {
        if self.tail.wrapping_sub(self.head) == N {
            return false;
        }
        self.slots[self.tail % N] = Some(item);
        self.tail = self.tail.wrapping_add(1);
        true
    }
    /// Removes and returns the oldest item.
    fn pop(&mut self) -> Option<T> {
        if self.head == self.tail {
            return None;
        }
        let item = self.slots[self.head % N].take();
        self.head = self.head.wrapping_add(1);
        item
    }
}

static READ_M: Mutex = Mutex::new();
/// Read threads wait here for a call, an exit request or shutdown. Callers
/// waiting for queue space have their own condvar, so neither side wakes
/// the other (one shared condvar woke both on every push and pop).
static READ_WORK_CV: Condvar = Condvar::new();
/// Callers wait here while READ_QUEUE calls are queued.
static READ_SPACE_CV: Condvar = Condvar::new();
/// Callers waiting on READ_SPACE_CV, under READ_M: a pop signals only then.
static READ_SPACE_WAITERS: SyncCell<u32> = SyncCell::new(0);
/// Condvars callers wait on for their call to finish, handed out round
/// robin (READ_DONE_NEXT). One shared condvar with notify_all woke every
/// waiting caller per finished read, up to READ_QUEUE + READ_THREADS = 68,
/// and all but one slept again. Two callers share one only while a call
/// waits through 64 newer ones; the notify_all on it covers that case.
/// Each pthread cond is created on first use, then kept (64 in all).
const READ_DONE_CV_COUNT: usize = 64;
static READ_DONE_CVS: [Condvar; READ_DONE_CV_COUNT] = {
    const CV: Condvar = Condvar::new();
    [CV; READ_DONE_CV_COUNT]
};
static READ_DONE_NEXT: AtomicU32 = AtomicU32::new(0);
/// Calls queued for the read threads, oldest first, under READ_M.
static READ_CALLS: SyncCell<Fifo<*mut ReadCall, READ_QUEUE>> = SyncCell::new(Fifo::new());
/// Length of READ_CALLS, changed under READ_M; a spinning read thread polls
/// it without the lock.
static READ_QUEUED: AtomicU32 = AtomicU32::new(0);
/// A failed first read thread start is tried again from this time (ns,
/// monotonic) on; reads run inline meanwhile. One try per 100 ms keeps a
/// game out of thread creation on every read while it has no room.
static READ_START_RETRY_NS: AtomicU64 = AtomicU64::new(0);
const READ_START_RETRY_GAP_NS: u64 = 100_000_000;
static READ_THREADS_UP: AtomicU32 = AtomicU32::new(0);
/// Set under READ_M by `stop_read_threads`; a read thread exits once it sees
/// it with an empty queue.
static READ_STOP: AtomicBool = AtomicBool::new(false);
/// Started read threads, joined by `stop_read_threads` before module_stop
/// returns, so none is left in the PRX's code after an unload.
static READ_HANDLES: SyncCell<[ScePthread; READ_THREADS]> =
    SyncCell::new([null_mut(); READ_THREADS]);

// ---- read thread count ----
// One read thread at first; another starts when a call is queued and none
// waits, up to READ_THREADS and the thread budget (rt/thread_hooks.rs). A
// thread that finishes a call leaves when more are live than the load target
// (thread_hooks::LoadGroup), never the last in normal mode. Under pressure,
// or when a game short of threads asks (`read_threads_ask`), they leave
// down to one while calls are queued and to none without; the next call
// starts one again, which pressure mode then keeps, or reads inline when it
// cannot.

/// Busy read thread samples and the load target (rt/thread_hooks.rs).
static READ_LOAD: super::super::thread_hooks::LoadGroup =
    super::super::thread_hooks::LoadGroup::new(0);
const READ_SLOT_EMPTY: u8 = 0;
const READ_SLOT_LIVE: u8 = 1;
const READ_SLOT_EXITED: u8 = 2;
/// Per slot state, idle threads and exits asked, all under READ_M.
static READ_SLOTS: SyncCell<[u8; READ_THREADS]> = SyncCell::new([READ_SLOT_EMPTY; READ_THREADS]);
static READ_IDLE: AtomicU32 = AtomicU32::new(0);
static READ_EXIT_REQUESTS: AtomicU32 = AtomicU32::new(0);
/// A read thread left: the next read thread through READ_M joins it (a
/// spawn and `read_threads_reap` join too), so its slot is free at once (as
/// WORKER_REAP_PENDING, worker.rs).
static READ_REAP_PENDING: AtomicBool = AtomicBool::new(false);

// ---- spin before park ----
// With tune::spin_us() > 0, a read thread that finished a call polls
// READ_QUEUED for that long before it parks, so a read that follows soon
// skips a condvar sleep and wake. At most one thread spins. READ_SPIN
// changes only under READ_M: a caller that queues a call while it is
// SPIN_WAITING claims the spinner (SPIN_CLAIMED) instead of signalling. The
// spinner clears it under READ_M and pops in the same hold, so a claimed
// call is never left without a thread to take it.
const SPIN_NONE: u8 = 0;
const SPIN_WAITING: u8 = 1;
const SPIN_CLAIMED: u8 = 2;
static READ_SPIN: AtomicU8 = AtomicU8::new(SPIN_NONE);

/// Polls READ_QUEUED for up to `us` with the lock released; the clock is
/// read every 32 pauses, not on each.
fn spin_for_call(us: u32) {
    let start = super::super::sys::monotonic_ns();
    let limit = us as u64 * 1000;
    let mut n = 0u32;
    while READ_QUEUED.load(Ordering::Acquire) == 0 && !READ_STOP.load(Ordering::Relaxed) {
        core::hint::spin_loop();
        n = n.wrapping_add(1);
        if n % 32 == 0 {
            let now = super::super::sys::monotonic_ns();
            if start == 0 || now == 0 || now.saturating_sub(start) >= limit {
                return;
            }
        }
    }
}

unsafe extern "C" fn read_thread(arg: *mut c_void) -> *mut c_void {
    let slot = arg as usize;
    // Under READ_M: this thread leaves the live set.
    let leave = || {
        READ_THREADS_UP.fetch_sub(1, Ordering::Release);
        unsafe { (*READ_SLOTS.get())[slot] = READ_SLOT_EXITED };
        READ_REAP_PENDING.store(true, Ordering::Release);
        // Yield, load retirement, shutdown: every idle thread rechecks, so a
        // call queued for this one is taken.
        READ_WORK_CV.notify_all();
    };
    let mut g = READ_M.lock();
    loop {
        let call = {
            loop {
                if READ_REAP_PENDING.swap(false, Ordering::AcqRel) {
                    unsafe { reap_read_threads_locked() };
                }
                // The last thread leaves only with no call queued.
                let others = READ_THREADS_UP.load(Ordering::Relaxed) > 1
                    || READ_QUEUED.load(Ordering::Relaxed) == 0;
                if others && READ_EXIT_REQUESTS.load(Ordering::Relaxed) != 0 {
                    READ_EXIT_REQUESTS.fetch_sub(1, Ordering::Relaxed);
                    leave();
                    return null_mut();
                }
                if let Some(call) = unsafe { (*READ_CALLS.get()).pop() } {
                    READ_QUEUED.fetch_sub(1, Ordering::Release);
                    // One slot freed: one caller waiting on a full queue
                    // can push.
                    if unsafe { *READ_SPACE_WAITERS.get() } != 0 {
                        READ_SPACE_CV.notify_one();
                    }
                    READ_LOAD.begin();
                    break call;
                }
                if READ_STOP.load(Ordering::Acquire) {
                    leave();
                    return null_mut();
                }
                READ_IDLE.fetch_add(1, Ordering::Relaxed);
                READ_WORK_CV.wait(&mut g);
                READ_IDLE.fetch_sub(1, Ordering::Relaxed);
            }
        };
        drop(g);
        let rc = unsafe {
            let c = &*call;
            read_on_workers(c.fd, core::slice::from_raw_parts(c.vector, c.count), c.offset, c.length)
        };
        g = READ_M.lock();
        READ_LOAD.end();
        // Under READ_M: the caller cannot see `done` and leave (freeing
        // `call`) before this thread unlocks, after the notify.
        let cv = unsafe { (*call).cv };
        unsafe { ((*call).rc, (*call).done) = (rc, true) };
        READ_DONE_CVS[cv].notify_all();
        // Above the load target: leave (`leave` wakes the others for any
        // queued call; under pressure one stays while calls are queued),
        // meeting an exit asked of the group if any.
        if READ_LOAD.retire_due(
            READ_THREADS_UP.load(Ordering::Relaxed),
            READ_THREADS as u32,
            READ_QUEUED.load(Ordering::Relaxed) != 0,
        ) {
            let _ = super::super::thread_hooks::take_exit_request(&READ_EXIT_REQUESTS);
            leave();
            return null_mut();
        }
        let spin = super::super::tune::spin_us();
        if spin != 0
            && READ_QUEUED.load(Ordering::Relaxed) == 0
            && READ_SPIN.load(Ordering::Relaxed) == SPIN_NONE
        {
            READ_SPIN.store(SPIN_WAITING, Ordering::Relaxed);
            drop(g);
            spin_for_call(spin);
            g = READ_M.lock();
            // Cleared and followed by a pop in this hold (see READ_SPIN).
            READ_SPIN.store(SPIN_NONE, Ordering::Relaxed);
        }
    }
}

/// Under READ_M: joins threads that left (they hold no lock any more) and
/// frees their slots.
unsafe fn reap_read_threads_locked() {
    // `stop_read_threads` joins every thread itself; READ_STOP is set under
    // READ_M, so no reap is in progress after it.
    if READ_STOP.load(Ordering::Acquire) {
        return;
    }
    let slots = unsafe { &mut *READ_SLOTS.get() };
    let handles = unsafe { &mut *READ_HANDLES.get() };
    for i in 0..READ_THREADS {
        if slots[i] == READ_SLOT_EXITED {
            let _ = unsafe { scePthreadJoin(handles[i], null_mut()) };
            handles[i] = null_mut();
            slots[i] = READ_SLOT_EMPTY;
        }
    }
}

/// Under READ_M: starts one read thread with a READ_STACK stack in a free
/// slot; false when all are taken or the creation failed.
unsafe fn spawn_read_thread_locked() -> bool {
    unsafe { reap_read_threads_locked() };
    let slots = unsafe { &mut *READ_SLOTS.get() };
    let Some(slot) = slots.iter().position(|&s| s == READ_SLOT_EMPTY) else {
        return false;
    };
    // The runtime-wide thread budget (rt/thread_hooks.rs).
    if !super::super::thread_hooks::reserve(READ_THREADS_UP.load(Ordering::Relaxed) == 0) {
        return false;
    }
    let mut thread: ScePthread = null_mut();
    let rc = unsafe {
        super::super::thread_hooks::create_counted(
            (&mut thread as *mut ScePthread).cast(),
            read_thread,
            slot as *mut c_void,
            c"ampr_fd_read".as_ptr(),
            READ_STACK,
        )
    };
    if rc != 0 {
        return false;
    }
    unsafe { (*READ_HANDLES.get())[slot] = thread };
    slots[slot] = READ_SLOT_LIVE;
    READ_LOAD.started(READ_THREADS_UP.fetch_add(1, Ordering::Release) + 1);
    true
}

/// Starts the first read thread; false when none is running. A failed start
/// (no thread budget, or the game used up its threads) is tried again on a
/// later read, at most once per READ_START_RETRY_GAP_NS; a once flag never
/// retried, so every read stayed inline for the rest of the run. No read
/// thread starts after `stop_read_threads`.
unsafe fn start_read_threads() -> bool {
    if READ_THREADS_UP.load(Ordering::Acquire) != 0 {
        return true;
    }
    if READ_STOP.load(Ordering::Acquire) {
        return false;
    }
    let now = super::super::sys::monotonic_ns();
    if now < READ_START_RETRY_NS.load(Ordering::Relaxed) {
        return false;
    }
    let _g = READ_M.lock();
    if READ_THREADS_UP.load(Ordering::Relaxed) == 0
        && !READ_STOP.load(Ordering::Acquire)
        && !unsafe { spawn_read_thread_locked() }
    {
        READ_START_RETRY_NS.store(now.saturating_add(READ_START_RETRY_GAP_NS), Ordering::Relaxed);
    }
    READ_THREADS_UP.load(Ordering::Relaxed) != 0
}

/// Read thread exits asked (`read_threads_ask`) not yet done; none after
/// `stop_read_threads`, which joins every thread without meeting them.
pub(crate) fn read_threads_pending_exits() -> u32 {
    if READ_STOP.load(Ordering::Acquire) {
        return 0;
    }
    READ_EXIT_REQUESTS.load(Ordering::Relaxed)
}

/// Live read threads (make_room counts what a yield gave from it).
pub(crate) fn read_threads_live() -> u32 {
    READ_THREADS_UP.load(Ordering::Acquire)
}

/// Asks up to `want` read threads to leave (the last only with no call
/// queued) and wakes them. Returns how many it asked. Called from a game
/// thread whose creation failed (rt/thread_hooks.rs `make_room`), which
/// then waits and calls `read_threads_reap`.
pub(crate) unsafe fn read_threads_ask(want: u32) -> u32 {
    let _g = READ_M.lock();
    READ_LOAD.asked();
    // Exits other yields already asked for are not given twice.
    let give = super::super::thread_hooks::exits_to_ask(
        want,
        READ_THREADS_UP.load(Ordering::Relaxed),
        (READ_QUEUED.load(Ordering::Relaxed) != 0) as u32,
        READ_EXIT_REQUESTS.load(Ordering::Relaxed),
    );
    if give != 0 {
        READ_EXIT_REQUESTS.fetch_add(give, Ordering::Relaxed);
        READ_WORK_CV.notify_all();
    }
    give
}

/// Joins the read threads that left since `before` were live and counts
/// them.
pub(crate) unsafe fn read_threads_reap(before: u32) -> u32 {
    let _g = READ_M.lock();
    unsafe { reap_read_threads_locked() };
    let released = before.saturating_sub(READ_THREADS_UP.load(Ordering::Relaxed));
    READ_LOAD.yielded(released);
    released
}

/// Debug /metrics: live read threads and the group's load counters.
#[cfg(feature = "mem_report")]
pub(crate) fn read_threads_load() -> (u32, [u64; 5]) {
    let _g = READ_M.lock();
    (READ_THREADS_UP.load(Ordering::Relaxed), READ_LOAD.metrics())
}

/// `read_on_workers` on a read thread; inline when no read thread started.
/// Shutdown, after pack submissions drained (each virtual read holds one
/// while it waits for its read thread, so the queue is empty): wakes the
/// read threads and joins them; a read after this runs inline
/// (`start_read_threads` checks READ_STOP).
unsafe fn stop_read_threads() {
    // No early return on READ_THREADS_UP == 0: threads that left but were
    // not reaped still hold handles to join here.
    {
        let _g = READ_M.lock();
        READ_STOP.store(true, Ordering::Release);
        READ_WORK_CV.notify_all();
        READ_SPACE_CV.notify_all();
    }
    for thread in unsafe { (*READ_HANDLES.get()).iter_mut() } {
        if !thread.is_null() {
            let _ = unsafe { scePthreadJoin(*thread, null_mut()) };
            *thread = null_mut();
        }
    }
    unsafe { *READ_SLOTS.get() = [READ_SLOT_EMPTY; READ_THREADS] };
    READ_THREADS_UP.store(0, Ordering::Release);
}

unsafe fn read_on_read_thread(
    fd: c_int,
    vector: &[SceKernelIovec],
    offset: u64,
    length: u64,
) -> ssize_t {
    // No read thread (its first creation failed and the retry is not due,
    // or after shutdown): read inline. An error instead would fail every packed read,
    // also on the large-stack threads that read fine inline; only a
    // small-stack caller is at risk, as before the read threads existed.
    if !unsafe { start_read_threads() } {
        return unsafe { read_on_workers(fd, vector, offset, length) };
    }
    let mut call = ReadCall {
        fd,
        vector: vector.as_ptr(),
        count: vector.len(),
        offset,
        length,
        rc: 0,
        done: false,
        cv: READ_DONE_NEXT.fetch_add(1, Ordering::Relaxed) as usize % READ_DONE_CV_COUNT,
    };
    let p: *mut ReadCall = &mut call;
    let mut g = READ_M.lock();
    loop {
        // Every thread may have left since start_read_threads looked, or
        // while this call waited for space (load or pressure); a call
        // queued with none live and none startable would wait forever, so
        // it reads inline then (after shutdown, and within
        // READ_START_RETRY_GAP_NS of a failed start, without trying).
        if READ_THREADS_UP.load(Ordering::Relaxed) == 0 {
            let now = super::super::sys::monotonic_ns();
            let due = !READ_STOP.load(Ordering::Acquire)
                && now >= READ_START_RETRY_NS.load(Ordering::Relaxed);
            if !(due && unsafe { spawn_read_thread_locked() }) {
                if due {
                    READ_START_RETRY_NS
                        .store(now.saturating_add(READ_START_RETRY_GAP_NS), Ordering::Relaxed);
                }
                drop(g);
                return unsafe { read_on_workers(fd, vector, offset, length) };
            }
        }
        if unsafe { (*READ_CALLS.get()).push(p) } {
            READ_QUEUED.fetch_add(1, Ordering::Release);
            break;
        }
        // Full: READ_QUEUE calls wait for a read thread.
        unsafe { *READ_SPACE_WAITERS.get() += 1 };
        READ_SPACE_CV.wait(&mut g);
        unsafe { *READ_SPACE_WAITERS.get() -= 1 };
    }
    if READ_SPIN.load(Ordering::Relaxed) == SPIN_WAITING {
        // The spinner takes it (see READ_SPIN): no signal, no new thread.
        READ_SPIN.store(SPIN_CLAIMED, Ordering::Relaxed);
    } else {
        // No thread waits for it: one more, up to READ_THREADS.
        let up = READ_THREADS_UP.load(Ordering::Relaxed);
        if READ_IDLE.load(Ordering::Relaxed) == 0
            && up < READ_THREADS as u32
            && READ_LOAD.may_grow(up)
        {
            let _ = unsafe { spawn_read_thread_locked() };
        }
        // One call queued: one idle thread can take it. A woken thread that
        // leaves instead (exit request) wakes all of them (`leave`).
        READ_WORK_CV.notify_one();
    }
    // `done` is written under READ_M by the read thread.
    READ_DONE_CVS[call.cv].wait_until(&mut g, || unsafe {
        core::ptr::read_volatile(&(*p).done)
    });
    drop(g);
    call.rc
}

/// Logical size of the packed file behind a virtual fd slot.
unsafe fn virtual_file_size(state: *const PackState, file_id: u32) -> Option<u64> {
    unsafe { packed_read_file(state, file_id) }.map(|(_, size, _)| size)
}

/// The slot `index` while it still holds `fd`, under PACK_M.
unsafe fn virtual_fd_snapshot(
    state: *const PackState,
    fd: c_int,
    index: u32,
) -> Option<VirtualFdSlot> {
    let _lock = PACK_M.lock();
    let slot = (*state).virtual_fds[index as usize];
    slot.holds(fd).then_some(slot)
}

/// Classifies `fd` for a read: Some(slot) for a virtual pack fd; None with
/// `*handled` false for any physical fd (the caller runs the real function)
/// or true with `*rc` set for a virtual directory fd.
unsafe fn virtual_read_target(fd: c_int, handled: *mut bool, rc: &mut ssize_t) -> Option<u32> {
    unsafe { clear_handled(handled) };
    *rc = SCE_KERNEL_ERROR_EBADF as ssize_t;
    if let Some(index) = decode_virtual_fd(fd) {
        if !handled.is_null() {
            unsafe { *handled = true };
        }
        return Some(index);
    }
    if unsafe { decode_virtual_directory_fd(fd, null_mut(), null_mut()) } {
        if !handled.is_null() {
            unsafe { *handled = true };
        }
        if unsafe { ampr_pack_is_virtual_directory_fd(fd) } {
            *rc = sce_errno(EISDIR_POSIX) as ssize_t;
        }
    }
    None
}

/// The read of `slot`'s file at `offset` into the caller's vector.
unsafe fn read_slot_at(
    state: *const PackState,
    fd: c_int,
    slot: &VirtualFdSlot,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    offset: off_t,
) -> ssize_t {
    let (vector, total) =
        match unsafe { iov_slice(iov, iovcnt) }.and_then(|v| Ok((v, iov_total(v)?))) {
            Ok(v) => v,
            Err(e) => return e as ssize_t,
        };
    let Some(size) = (unsafe { virtual_file_size(state, slot.file_id) }) else {
        return SCE_KERNEL_ERROR_EIO as ssize_t;
    };
    let length = match clamp_read(offset, total, size) {
        Ok(0) => return 0,
        Ok(n) => n,
        Err(e) => return e as ssize_t,
    };
    unsafe { read_on_read_thread(fd, vector, offset as u64, length) }
}

/// pread/preadv: the slot cursor is neither read nor moved, so concurrent
/// positional reads of one fd run in parallel. The PackSubmission keeps
/// shutdown from freeing the caches and volume fds under the read.
unsafe fn virtual_pread(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    offset: off_t,
    handled: *mut bool,
) -> ssize_t {
    let mut rc = 0;
    let Some(index) = (unsafe { virtual_read_target(fd, handled, &mut rc) }) else {
        return rc;
    };
    let state = unsafe { pack_state() };
    let submission = PackSubmission::new(state);
    if !submission.admitted() {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    }
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, fd, index) }) else {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    };
    unsafe { read_slot_at(state, fd, &slot, iov, iovcnt, offset) }
}

/// read/readv: the slot's descriptor mutex serializes the cursor with other
/// read/lseek/close calls on the fd for the whole read, so concurrent reads
/// never return the same bytes.
unsafe fn virtual_read(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    handled: *mut bool,
) -> ssize_t {
    let mut rc = 0;
    let Some(index) = (unsafe { virtual_read_target(fd, handled, &mut rc) }) else {
        return rc;
    };
    let state = unsafe { pack_state() };
    if unsafe { virtual_fd_snapshot(state, fd, index) }.is_none() {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    }
    let _descriptor = VIRTUAL_FD_MUTEXES[index as usize].lock();
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    }
    let submission = PackSubmission::new(state);
    if !submission.admitted() {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    }
    // Close needs the descriptor mutex, so this slot stays this fd's until
    // the guard drops; re-check in case it closed before we took it.
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, fd, index) }) else {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    };
    let cursor = slot.cursor;
    let offset = if cursor > off_t::MAX as u64 {
        -1
    } else {
        cursor as off_t
    };
    let n = unsafe { read_slot_at(state, fd, &slot, iov, iovcnt, offset) };
    if n > 0 {
        let _lock = PACK_M.lock();
        let s = &mut (*state).virtual_fds[index as usize];
        if s.holds(fd) {
            s.cursor = cursor + n as u64;
        }
    }
    n
}

pub unsafe fn ampr_pack_try_pread_fd(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
    offset: off_t,
    handled: *mut bool,
) -> ssize_t {
    let iov = SceKernelIovec {
        iov_base: buffer,
        iov_len: size,
    };
    unsafe { virtual_pread(fd, &iov, 1, offset, handled) }
}

pub unsafe fn ampr_pack_try_preadv_fd(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    offset: off_t,
    handled: *mut bool,
) -> ssize_t {
    unsafe { virtual_pread(fd, iov, iovcnt, offset, handled) }
}

pub unsafe fn ampr_pack_try_read_fd(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
    handled: *mut bool,
) -> ssize_t {
    let iov = SceKernelIovec {
        iov_base: buffer,
        iov_len: size,
    };
    unsafe { virtual_read(fd, &iov, 1, handled) }
}

pub unsafe fn ampr_pack_try_readv_fd(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    handled: *mut bool,
) -> ssize_t {
    unsafe { virtual_read(fd, iov, iovcnt, handled) }
}

// ---- read hooks (rt/hook.rs ids read..sceKernelPreadv) ------------------------
//
// Shared by both builds: a physical fd fails the virtual-fd decode (a tag
// test, no lock, no pack state) and goes straight to the original, so with
// no virtual fds open the hooks behave like the unhooked functions. The
// posix forms return -1 with errno (as aio.rs's close/fstat/lseek); the sce
// forms return the SCE code unchanged.

/// libc result of a handled read: the count, or -1 with the SCE code's errno.
pub(crate) fn posix_count_from_pack(rc: ssize_t) -> ssize_t {
    if rc >= 0 {
        return rc;
    }
    set_errno(posix_errno_from_sce(rc as c_int));
    -1
}

pub(crate) fn posix_read_missing() -> ssize_t {
    set_errno(EIO);
    -1
}

fn sce_read_missing() -> ssize_t {
    SCE_KERNEL_ERROR_EIO as ssize_t
}

pub unsafe extern "C" fn posix_read_emul(fd: c_int, buffer: *mut c_void, size: usize) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_read_fd(fd, buffer, size, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { real_read() }.map_or_else(posix_read_missing, |f| unsafe { f(fd, buffer, size) })
}

pub unsafe extern "C" fn posix_pread_emul(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
    offset: off_t,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_pread_fd(fd, buffer, size, offset, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { real_pread() }.map_or_else(posix_read_missing, |f| unsafe {
        f(fd, buffer, size, offset)
    })
}

pub unsafe extern "C" fn posix_readv_emul(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_readv_fd(fd, iov, iovcnt, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { real_readv() }.map_or_else(posix_read_missing, |f| unsafe { f(fd, iov, iovcnt) })
}

pub unsafe extern "C" fn posix_preadv_emul(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    offset: off_t,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_preadv_fd(fd, iov, iovcnt, offset, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { real_preadv() }.map_or_else(posix_read_missing, |f| unsafe {
        f(fd, iov, iovcnt, offset)
    })
}

pub unsafe extern "C" fn sceKernelRead_emul(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_read_fd(fd, buffer, size, &mut handled) };
    if handled {
        return rc;
    }
    unsafe { real_sce_read() }.map_or_else(sce_read_missing, |f| unsafe { f(fd, buffer, size) })
}

pub unsafe extern "C" fn sceKernelPread_emul(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
    offset: off_t,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_pread_fd(fd, buffer, size, offset, &mut handled) };
    if handled {
        return rc;
    }
    unsafe { real_sce_pread() }
        .map_or_else(sce_read_missing, |f| unsafe { f(fd, buffer, size, offset) })
}

pub unsafe extern "C" fn sceKernelReadv_emul(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_readv_fd(fd, iov, iovcnt, &mut handled) };
    if handled {
        return rc;
    }
    unsafe { real_sce_readv() }.map_or_else(sce_read_missing, |f| unsafe { f(fd, iov, iovcnt) })
}

pub unsafe extern "C" fn sceKernelPreadv_emul(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
    offset: off_t,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_preadv_fd(fd, iov, iovcnt, offset, &mut handled) };
    if handled {
        return rc;
    }
    unsafe { real_sce_preadv() }
        .map_or_else(sce_read_missing, |f| unsafe { f(fd, iov, iovcnt, offset) })
}

pub unsafe fn ampr_pack_try_lseek_fd(
    fd: c_int,
    offset: off_t,
    whence: c_int,
    handled: *mut bool,
) -> off_t {
    unsafe { clear_handled(handled) };
    if let Some(index) = decode_virtual_fd(fd) {
        if !handled.is_null() {
            unsafe { *handled = true };
        }
        return unsafe { lseek_virtual_fd(fd, index, offset, whence) };
    }
    // Decode before pack_state(), as in ampr_pack_try_close_fd: a physical
    // fd never creates or waits on the pack state.
    let mut index = 0u32;
    let mut generation = 0u16;
    if !unsafe { decode_virtual_directory_fd(fd, &mut index, &mut generation) } {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let state = unsafe { pack_state() };
    if !handled.is_null() {
        unsafe { *handled = true };
    }
    if whence != SEEK_SET || offset != 0 {
        return SCE_KERNEL_ERROR_EINVAL as off_t;
    }
    let _lock = DIRECTORY_MUTEXES[index as usize].lock();
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let slot = &mut (*state).virtual_directories[index as usize];
    if !slot.active || slot.generation != generation {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    if slot.real_fd >= 0 {
        match unsafe { real_lseek() } {
            Some(f) if unsafe { f(slot.real_fd, 0, SEEK_SET) } >= 0 => {}
            _ => return SCE_KERNEL_ERROR_EIO as off_t,
        }
    }
    slot.real_exhausted = false;
    slot.directory_offset = 0;
    slot.dot_emitted = false;
    slot.dot_dot_emitted = false;
    slot.virtual_cursor = slot.range_begin;
    slot.physical_hash_count = 0;
    slot.physical_hash_overflow = false;
    0
}

/// lseek of a virtual pack fd: moves the slot cursor under the descriptor
/// mutex that read/readv hold for their whole read.
unsafe fn lseek_virtual_fd(fd: c_int, index: u32, offset: off_t, whence: c_int) -> off_t {
    let state = unsafe { pack_state() };
    if unsafe { virtual_fd_snapshot(state, fd, index) }.is_none() {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let _descriptor = VIRTUAL_FD_MUTEXES[index as usize].lock();
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, fd, index) }) else {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    };
    // SEEK_END needs the size; SEEK_SET/SEEK_CUR do not touch the mount.
    let size = if whence == SEEK_END {
        match unsafe { virtual_file_size(state, slot.file_id) } {
            Some(size) => size,
            None => return SCE_KERNEL_ERROR_EIO as off_t,
        }
    } else {
        0
    };
    let target = match seek_target(slot.cursor, size, offset, whence) {
        Ok(t) => t,
        Err(e) => return e as off_t,
    };
    let _lock = PACK_M.lock();
    let s = &mut (*state).virtual_fds[index as usize];
    if !s.holds(fd) {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    s.cursor = target;
    target as off_t
}

pub unsafe fn ampr_pack_is_virtual_fd(fd: c_int) -> bool {
    let Some(slot) = decode_virtual_fd(fd) else {
        return false;
    };
    let state = unsafe { pack_state() };
    let _lock = PACK_M.lock();
    (*state).virtual_fds[slot as usize].holds(fd)
}

/// One-based AMPRIDX3 file id behind an open virtual pack fd; None for any
/// other fd. rt/pack/mmap.rs keys its disk cache by it; debug probes
/// (rt/probe.rs) map it to the file's path.
pub(crate) unsafe fn virtual_fd_file_id(fd: c_int) -> Option<u32> {
    let slot = decode_virtual_fd(fd)?;
    let state = unsafe { pack_state() };
    let _lock = PACK_M.lock();
    let s = unsafe { &(*state).virtual_fds[slot as usize] };
    s.holds(fd).then_some(s.file_id)
}

pub(crate) fn native_pack_priority(priority: u8) -> c_int {
    match priority {
        0 => SCE_KERNEL_AIO_PRIORITY_LOW,
        1 => SCE_KERNEL_AIO_PRIORITY_MID,
        _ => SCE_KERNEL_AIO_PRIORITY_HIGH,
    }
}

pub(crate) fn native_pack_io_class(
    work_class: PackWorkClass,
    physical_bytes: usize,
) -> AprExternalAioClass {
    if work_class == PackWorkClass::Bulk {
        return AprExternalAioClass::Bulk;
    }
    if work_class == PackWorkClass::Latency
        && physical_bytes as u64 <= AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES
    {
        return AprExternalAioClass::Latency;
    }
    AprExternalAioClass::Balanced
}

/// `AprExternalAioCallback` for pack backing reads; `context` is the pipeline.
pub(crate) unsafe extern "C" fn complete_pack_backing_aio_adapter(
    context: *mut c_void,
    notification: *const reactor::AprExternalAioNotification,
) {
    // The pack and reactor notification layouts are identical.
    unsafe { complete_pack_backing_aio(context, notification.cast()) };
}

const _: () = {
    assert!(
        size_of::<reactor::AprExternalAioNotification>() == size_of::<AprExternalAioNotification>()
    );
    assert!(
        offset_of!(reactor::AprExternalAioNotification, value)
            == offset_of!(AprExternalAioNotification, value)
    );
    assert!(
        offset_of!(
            reactor::AprExternalAioNotification,
            firstExternalInSubmitBatch
        ) == offset_of!(AprExternalAioNotification, first_external_in_submit_batch)
    );
};

pub(crate) unsafe extern "C" fn complete_pack_backing_aio(
    context: *mut c_void,
    notification: *const AprExternalAioNotification,
) {
    let pipeline = context as *mut ReadPipelineContext;
    if pipeline.is_null() {
        return;
    }
    let n = unsafe { *notification };
    let state = unsafe { pack_state() };
    let submitted = unsafe { AtomicBool::from_ptr(addr_of_mut!((*pipeline).native_submitted)) };
    if n.event == AprExternalAioEvent::Submitted {
        submitted.store(true, Ordering::Release);
        return;
    }
    let mut queue_worker = false;
    let mut notify_one = false;
    {
        let _lock = PACK_M.lock();
        let p = unsafe { &mut *pipeline };
        let owner = p.owner;
        if !p.active
            || !p.native_accepted
            || owner == INVALID_INDEX
            || owner as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS
        {
            abort();
        }
        match n.event {
            AprExternalAioEvent::Submitted => abort(),
            AprExternalAioEvent::SubmitDeferred => {
                (*state).virtual_aio[owner as usize].phase = VirtualAioPhase::IoQueued;
            }
            AprExternalAioEvent::SubmitFailed => {
                disk_inflight_release(p);
                p.native_accepted = false;
                p.native_io_error = n.value;
                p.native_completion_ready = true;
                queue_push_locked(state, owner, pack_telemetry_usecs());
                queue_worker = true;
            }
            AprExternalAioEvent::Completed => {
                if !submitted.load(Ordering::Acquire) {
                    abort();
                }
                disk_inflight_release(p);
                let base = if n.value < 0 {
                    n.value
                } else {
                    n.value & !SCE_KERNEL_AIO_STATE_NOTIFIED
                };
                p.native_accepted = false;
                p.native_io_error = if base == SCE_KERNEL_AIO_STATE_COMPLETED {
                    0
                } else if base < 0 {
                    base
                } else {
                    SCE_KERNEL_ERROR_ECANCELED
                };
                p.native_completion_ready = true;
                queue_push_locked(state, owner, 0);
                queue_worker = true;
            }
        }
        if queue_worker {
            notify_one = effective_latency_reserve_locked(state) == 0;
        }
    }
    if queue_worker {
        if notify_one {
            QUEUE_CV.notify_one();
        } else {
            QUEUE_CV.notify_all();
        }
    }
}

pub unsafe fn ampr_pack_shutdown() -> c_int {
    let mut init_state = g_pack_state_init.load(Ordering::Acquire);
    if init_state == 0 {
        return 0;
    }
    let mut spins = 0u32;
    while init_state == 1 {
        spin_pause_or_yield(&mut spins);
        init_state = g_pack_state_init.load(Ordering::Acquire);
    }
    let sp = g_pack_state.load(Ordering::Acquire);
    if sp.is_null() {
        return 0;
    }
    let state = sp;

    // Close the manifest gate before anything else: from here on opens,
    // stats and probes act as if no manifest were loaded, and the open path
    // rechecks the gate under PACK_M, so no new virtual fd is allocated
    // during the drain below.
    MANIFEST_READERS.close();
    {
        let mut g = PACK_M.lock();
        (*state).submissions_closed = true;
        SUBMIT_CV.wait_until(
            &mut g,
            || unsafe { core::ptr::read_volatile(addr_of_mut!((*sp).active_submissions)) } == 0,
        );
    }
    unsafe { stop_read_threads() };
    unsafe { super::mmap::close_cache() };
    {
        let _g = MANIFEST_MUTEX.lock();
        WORKER_STOP_REQUESTED.store(true, Ordering::Release);
    }
    MANIFEST_CV.notify_all();
    for m in VIRTUAL_FD_MUTEXES.iter().chain(DIRECTORY_MUTEXES.iter()) {
        drop(m.lock());
    }
    {
        let mut g = MANIFEST_MUTEX.lock();
        MANIFEST_CV.wait_until(&mut g, || {
            LOAD_STATE.load(Ordering::Acquire) != PACK_LOAD_LOADING
        });
    }

    cancel_virtual_jobs(state);

    let drain_start = pack_monotonic_usecs();
    loop {
        let has_native = {
            let _g = PACK_M.lock();
            (*state).pipeline_active_count != 0
                || (&(*state).pipelines)[..(*state).pipeline_capacity as usize]
                    .iter()
                    .any(|p| p.native_accepted)
        };
        if !has_native {
            break;
        }
        if elapsed_usecs(drain_start, pack_monotonic_usecs()) >= 10_000_000 {
            return SCE_KERNEL_ERROR_ETIMEDOUT;
        }
        unsafe { sceKernelUsleep(100) };
    }

    // A reap under PACK_M started before the stop flag finishes first; after
    // it none starts (worker.rs `reap_workers_locked`).
    drop(PACK_M.lock());
    let mut join_error = 0;
    for worker in (*state).workers.iter_mut() {
        if !worker.started {
            continue;
        }
        let rc = unsafe { scePthreadJoin(worker.thread, null_mut()) };
        if rc != 0 {
            if join_error == 0 {
                join_error = rc;
            }
            continue;
        }
        worker.started = false;
        if (*state).workers_started != 0 {
            (*state).workers_started -= 1;
        }
        PROFILE_STARTED_WORKERS.store((*state).workers_started, Ordering::Release);
    }
    if join_error != 0 {
        return join_error;
    }

    close_pack_and_directory_fds(state);

    free_worker_and_cache_memory(state);
    {
        let _g = MANIFEST_MUTEX.lock();
        LOAD_STATE.store(PACK_LOAD_UNAVAILABLE, Ordering::Release);
    }
    // The hook threads' lock-free manifest readers hold a ManifestReader
    // (rt/pack/mod.rs). The gate closed at the top, so this waits only for
    // readers already inside; no lock is held, so none of them can block on
    // this thread.
    let mut spins = 0u32;
    MANIFEST_READERS.wait_drained(|| {
        spin_pause_or_yield(&mut spins);
        true
    });
    unsafe { release_manifest_storage(state) };
    MANIFEST_CV.notify_all();
    0
}

/// Shutdown: cancels every live virtual job, completes the queued and
/// reserved ones as aborted, requeues the parked ones and wakes everyone.
unsafe fn cancel_virtual_jobs(state: *mut PackState) {
    let _g = PACK_M.lock();
    for index in 0..AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32 {
        let aio = &(*state).virtual_aio[index as usize];
        let phase = aio.phase;
        if phase != VirtualAioPhase::Free && phase != VirtualAioPhase::Done {
            aio.cancel_requested.store(true, Ordering::Release);
        }
        match phase {
            VirtualAioPhase::Queued => {
                if aio.pipeline_index == INVALID_INDEX && queue_remove_locked(state, index) {
                    unsafe {
                        complete_virtual_job(
                            state,
                            index,
                            SCE_KERNEL_ERROR_ECANCELED as i64,
                            SCE_KERNEL_AIO_STATE_ABORTED,
                        )
                    };
                }
            }
            VirtualAioPhase::Reserved => unsafe {
                complete_virtual_job(
                    state,
                    index,
                    SCE_KERNEL_ERROR_ECANCELED as i64,
                    SCE_KERNEL_AIO_STATE_ABORTED,
                )
            },
            VirtualAioPhase::WaitingCache => queue_cache_waiter_locked(state, index, 0),
            VirtualAioPhase::WaitingFd => queue_fd_waiter_locked(state, index, 0),
            _ => {}
        }
    }
    QUEUE_CV.notify_all();
    for cv in CACHE_CVS.iter() {
        cv.notify_all();
    }
}

/// Shutdown: resets the pack handles, virtual jobs, virtual fds and virtual
/// directories, then closes their real descriptors outside the locks.
unsafe fn close_pack_and_directory_fds(state: *mut PackState) {
    let mut pack_fds = [0 as c_int; AMPR_EMU_PACK_MAX_PACKS];
    let mut pack_fd_count = 0usize;
    {
        let _g = PACK_M.lock();
        for handle in (*state).pack_handles.iter_mut() {
            if handle.fd >= 0 {
                pack_fds[pack_fd_count] = handle.fd;
                pack_fd_count += 1;
            }
            *handle = PackHandle::EMPTY;
        }
        (*state).open_pack_count = 0;
        (*state).opening_pack_count = 0;
        for i in 0..AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32 {
            free_virtual_aio_locked(state, i);
            free_virtual_aio_group_locked(state, i);
        }
        for (fd, live) in (*state).virtual_fds.iter_mut().zip(&VIRTUAL_FD_LIVE) {
            *fd = VirtualFdSlot::EMPTY;
            live.store(false, Ordering::Release);
        }
    }
    for &fd in &pack_fds[..pack_fd_count] {
        unsafe { close_physical_pack_fd(fd) };
    }

    let mut directory_fds = [0 as c_int; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS];
    let mut directory_fd_count = 0usize;
    {
        let _table = DIRECTORY_TABLE_MUTEX.lock();
        for i in 0..AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS {
            let _dir = DIRECTORY_MUTEXES[i].lock();
            let directory = addr_of_mut!((*state).virtual_directories[i]);
            unsafe {
                if (*directory).real_fd >= 0 {
                    directory_fds[directory_fd_count] = (*directory).real_fd;
                    directory_fd_count += 1;
                }
                let generation = (*directory).generation;
                directory.write(VirtualDirectorySlot::EMPTY);
                (*directory).generation = generation;
            }
        }
    }
    if let Some(close_fn) = unsafe { real_close() } {
        for &fd in &directory_fds[..directory_fd_count] {
            unsafe { close_fn(fd) };
        }
    }
}

/// Shutdown: frees the worker scratch and decoders, the pipeline io windows
/// and both caches.
unsafe fn free_worker_and_cache_memory(state: *mut PackState) {
    for worker in (*state).workers.iter_mut() {
        if !worker.decoded_scratch.is_null() {
            unsafe {
                crate::rt::index_memory::buffer_free(
                    worker.decoded_scratch as *mut c_void,
                    c"apr.pack.worker.decoded.shutdown".as_ptr(),
                )
            };
        }
        unsafe { release_worker_decoder(worker) };
        *worker = WorkerContext::EMPTY;
    }
    for i in 0..AMPR_EMU_PACK_PIPELINE_SLOTS {
        let pipeline = addr_of_mut!((*state).pipelines[i]);
        unsafe {
            if !(*pipeline).io_scratch.is_null() {
                crate::rt::index_memory::buffer_free(
                    (*pipeline).io_scratch as *mut c_void,
                    c"apr.pack.pipeline.io-window.shutdown".as_ptr(),
                );
            }
            pipeline.write(ReadPipelineContext::EMPTY);
        }
    }
    (*state).pipeline_free_head = INVALID_INDEX;
    (*state).pipeline_capacity = 0;
    (*state).cache_waiter_count = 0;
    if !(*state).cache_base.is_null() {
        unsafe {
            crate::rt::index_memory::cache_free(
                (*state).cache_base as *mut c_void,
                c"apr.pack.decoded-cache.shutdown".as_ptr(),
            )
        };
        (*state).cache_base = null_mut();
        (*state).cache_bytes = 0;
        (*state).cache_page_count = 0;
        (*state).cache_page_cursor = 0;
    }
    if !(*state).physical_cache_base.is_null() {
        unsafe {
            crate::rt::index_memory::cache_free(
                (*state).physical_cache_base as *mut c_void,
                c"apr.pack.physical-cache.shutdown".as_ptr(),
            )
        };
        (*state).physical_cache_base = null_mut();
        (*state).physical_cache_bytes = 0;
        (*state).physical_cache_page_count = 0;
        (*state).physical_cache_page_cursor = 0;
    }
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn iov(buf: &mut [u8]) -> SceKernelIovec {
        SceKernelIovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        }
    }

    const NULL_IOV: SceKernelIovec = SceKernelIovec {
        iov_base: core::ptr::null_mut(),
        iov_len: 0,
    };

    #[test]
    fn iov_vectors_are_validated() {
        // iov total sums and rejects bad vectors.
        let (mut a, mut b) = ([0u8; 3], [0u8; 5]);
        assert_eq!(iov_total(&[iov(&mut a), NULL_IOV, iov(&mut b)]), Ok(8));
        assert_eq!(iov_total(&[]), Ok(0));
        let big = SceKernelIovec {
            iov_base: a.as_mut_ptr().cast(),
            iov_len: isize::MAX as usize,
        };
        assert_eq!(iov_total(&[big]), Ok(isize::MAX as usize));
        assert_eq!(iov_total(&[big, iov(&mut b)]), Err(SCE_KERNEL_ERROR_EINVAL));
        let null_with_len = SceKernelIovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 1,
        };
        assert_eq!(iov_total(&[null_with_len]), Err(SCE_KERNEL_ERROR_EFAULT));
        let many = [NULL_IOV; VIRTUAL_READ_IOV_MAX + 1];
        assert_eq!(iov_total(&many), Err(SCE_KERNEL_ERROR_EINVAL));
        assert_eq!(iov_total(&many[..VIRTUAL_READ_IOV_MAX]), Ok(0));

        // iov slice checks count and array.
        let mut a = [0u8; 2];
        let v = [iov(&mut a)];
        unsafe {
            assert_eq!(iov_slice(v.as_ptr(), 1).map(|s| s.len()), Ok(1));
            assert_eq!(iov_slice(core::ptr::null(), 0).map(|s| s.len()), Ok(0));
            let err = |r: Result<&[SceKernelIovec], c_int>| r.err();
            assert_eq!(
                err(iov_slice(core::ptr::null(), 1)),
                Some(SCE_KERNEL_ERROR_EFAULT)
            );
            assert_eq!(
                err(iov_slice(v.as_ptr(), -1)),
                Some(SCE_KERNEL_ERROR_EINVAL)
            );
            assert_eq!(
                err(iov_slice(v.as_ptr(), VIRTUAL_READ_IOV_MAX as c_int + 1)),
                Some(SCE_KERNEL_ERROR_EINVAL)
            );
        }
    }

    #[test]
    fn offsets_clamp_at_eof_and_seek_by_whence() {
        // clamp read stops at eof.
        assert_eq!(clamp_read(0, 10, 100), Ok(10));
        assert_eq!(clamp_read(95, 10, 100), Ok(5));
        assert_eq!(clamp_read(100, 10, 100), Ok(0));
        assert_eq!(clamp_read(200, 10, 100), Ok(0));
        assert_eq!(clamp_read(5, 0, 100), Ok(0));
        assert_eq!(clamp_read(0, 10, 0), Ok(0));
        assert_eq!(clamp_read(-1, 10, 100), Err(SCE_KERNEL_ERROR_EINVAL));
        assert_eq!(clamp_read(0, usize::MAX, 7), Ok(7));

        // seek target follows whence.
        assert_eq!(seek_target(40, 100, 7, SEEK_SET), Ok(7));
        assert_eq!(seek_target(40, 100, -10, SEEK_CUR), Ok(30));
        assert_eq!(seek_target(40, 100, 0, SEEK_CUR), Ok(40));
        assert_eq!(seek_target(40, 100, -1, SEEK_END), Ok(99));
        // Past EOF is allowed; a read there returns 0.
        assert_eq!(seek_target(40, 100, 50, SEEK_END), Ok(150));
        assert_eq!(
            seek_target(40, 100, -1, SEEK_SET),
            Err(SCE_KERNEL_ERROR_EINVAL)
        );
        assert_eq!(
            seek_target(40, 100, -41, SEEK_CUR),
            Err(SCE_KERNEL_ERROR_EINVAL)
        );
        assert_eq!(
            seek_target(40, 100, -101, SEEK_END),
            Err(SCE_KERNEL_ERROR_EINVAL)
        );
        assert_eq!(
            seek_target(1, 0, off_t::MAX, SEEK_CUR),
            Err(SCE_KERNEL_ERROR_EINVAL)
        );
        assert_eq!(seek_target(0, 0, 0, 3), Err(SCE_KERNEL_ERROR_EINVAL));
    }

    #[test]
    fn submit_backoff_waits_out_slow_reads_and_stops_when_idle() {
        // Slow media: a completion every 150 ms keeps the read retrying far
        // past the old fixed ~0.2 s budget.
        let mut b = SubmitBackoff::new(1_000, 7);
        for step in 1..=100u64 {
            assert!(b.retry(1_000 + step * 150_000, 7 + step));
        }
        // No completion at all: retry until the idle limit, then give up.
        let start = 1_000 + 100 * 150_000;
        assert!(b.retry(start + SUBMIT_IDLE_LIMIT_USECS - 1, 107));
        assert!(!b.retry(start + SUBMIT_IDLE_LIMIT_USECS, 107));
        // Completions that never stop still end at the absolute cap.
        let mut busy = SubmitBackoff::new(1_000, 0);
        let steps = SUBMIT_TOTAL_LIMIT_USECS / 150_000;
        assert!((1..steps).all(|step| busy.retry(1_000 + step * 150_000, step)));
        assert!(!busy.retry(1_000 + SUBMIT_TOTAL_LIMIT_USECS, steps));
        // Same with the clock unavailable: the total retry count ends it.
        let mut busy0 = SubmitBackoff::new(0, 0);
        let total = SUBMIT_TOTAL_LIMIT_USECS / SUBMIT_RETRY_USECS as u64;
        assert!((1..=total).all(|n| busy0.retry(0, n)));
        assert!(!busy0.retry(0, total + 1));
        let mut idle = SubmitBackoff::new(5, 0);
        assert!(
            idle.retry(5 + 300_000, 0),
            "0.3 s of slow I/O is not a failure"
        );
        // Clock unavailable (now stays 0): the retry count still ends the wait.
        let mut stuck = SubmitBackoff::new(0, 0);
        let limit = SUBMIT_IDLE_LIMIT_USECS / SUBMIT_RETRY_USECS as u64;
        assert!((0..limit).all(|_| stuck.retry(0, 0)));
        assert!(!stuck.retry(0, 0));
    }

    #[test]
    fn segment_plan_follows_posix_vectors_and_resumes() {
        // segment plan matches posix vector semantics.
        // A readv of [3, 0, 4] bytes at offset 6 of a 10-byte file reads 4
        // bytes: 3 into a, 1 into the start of b.
        let (mut a, mut b) = ([0u8; 3], [0u8; 4]);
        let v = [iov(&mut a), NULL_IOV, iov(&mut b)];
        let length = clamp_read(6, iov_total(&v).unwrap(), 10).unwrap();
        assert_eq!(length, 4);
        let mut out = [(0u64, core::ptr::null_mut::<u8>(), 0usize); 4];
        assert_eq!(plan_segment_reads(&v, 6, length, 0, &mut out), 2);
        assert_eq!(out[..2], [(6, a.as_mut_ptr(), 3), (9, b.as_mut_ptr(), 1)]);

        // segment plan resumes mid vector and caps batch.
        let (mut a, mut b, mut c) = ([0u8; 3], [0u8; 4], [0u8; 2]);
        let v = [iov(&mut a), iov(&mut b), iov(&mut c)];
        let mut out = [(0u64, core::ptr::null_mut::<u8>(), 0usize); 1];
        // One slot: only the first segment is planned.
        assert_eq!(plan_segment_reads(&v, 100, 9, 0, &mut out), 1);
        assert_eq!(out[0], (100, a.as_mut_ptr(), 3));
        // Resuming at byte 5 starts two bytes into b.
        let mut out = [(0u64, core::ptr::null_mut::<u8>(), 0usize); 8];
        assert_eq!(plan_segment_reads(&v, 100, 9, 5, &mut out), 2);
        assert_eq!(
            out[..2],
            [
                (105, b.as_mut_ptr().wrapping_add(2), 2),
                (107, c.as_mut_ptr(), 2)
            ]
        );
        assert_eq!(plan_segment_reads(&v, 100, 9, 9, &mut out), 0);
    }

    #[test]
    fn read_queue_is_fifo_and_refuses_when_full() {
        let mut q = Fifo::<u32, 3>::new();
        assert_eq!(q.pop(), None);
        assert!(q.push(1) && q.push(2) && q.push(3));
        assert!(!q.push(4));
        assert_eq!(q.pop(), Some(1));
        // A freed slot takes the next call behind the queued ones, not first.
        assert!(q.push(4));
        assert_eq!([q.pop(), q.pop(), q.pop(), q.pop()], [Some(2), Some(3), Some(4), None]);
    }
}
