//! Virtual fd read/seek entry points, backing AIO completion and shutdown.

use super::*;
use core::ptr::addr_of_mut;

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
// read/pread/readv/preadv of a virtual pack fd queue one virtual job per
// iovec segment and wait for them on the caller's thread (sync reads,
// below), so chunks are read and decoded only on the pack workers, each with
// its own decoder. The caller sleeps on AIO_CV like a game's own
// sceKernelAioWaitRequests, without the AIO ids. pread*
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

// ---- sync reads on the caller's thread ---------------------------------------
//
// A packed read/pread/readv/preadv queues its pack jobs and waits for them
// on the caller's own thread, as upstream does (ampr_emu_pack.cpp:6416).
// Before, a read thread took every call (caller -> read thread -> worker ->
// read thread -> caller: 4 hops on a cache hit, 8 on a miss) because the
// AIO API arrays sized for 128 requests needed about 32 KB of the caller's
// stack (read_on_workers 12,024 B, sceKernelAioSubmitReadCommandsMultiple
// 13,528 B, publish_virtual_jobs 6,600 B in the debug PRX) and a game's
// video I/O thread faulted on the guard page in publish_virtual_jobs. This
// path skips the AIO ids: it reserves the jobs under PACK_M, queues them,
// sleeps on AIO_CV until every job is Done and frees them, with arrays for
// SYNC_BATCH segments: 0x748 B of frames from virtual_read down to the queue
// push in both PRX builds (read_on_workers 0x2e8), budgeted at 0x1000 in
// tools/check_stack_frames.py. The read hand-off threads, their 4 x 128 KiB
// stacks and their load group are gone.

/// Segments queued per round: one per iovec segment, so a pread is one round;
/// a read over >= 2 chunks still splits into parallel child jobs
/// (`prepare_virtual_request_locked`). 8 keeps the round's arrays small
/// (8 x 24 B plan, 8 x 16 B results, 8 x 8 B jobs).
const SYNC_BATCH: usize = 8;

/// Reads `[offset, offset + length)` (already clamped to EOF, nonzero) of
/// virtual fd `fd` into `vector` on the pack workers, SYNC_BATCH segments at
/// a time, so chunks decode only on workers (each owns one decoder). Returns
/// `length`, the bytes before the first short or failed request (a partial
/// read), or that error when nothing was read.
#[inline(never)]
unsafe fn read_on_workers(
    fd: c_int,
    vector: &[SceKernelIovec],
    offset: u64,
    length: u64,
) -> ssize_t {
    let mut done = 0u64;
    while done < length {
        let mut plan = [(0u64, null_mut::<u8>(), 0usize); SYNC_BATCH];
        let count = plan_segment_reads(vector, offset, length, done, &mut plan);
        if count == 0 {
            break;
        }
        let mut results = [SceKernelAioResult::EMPTY; SYNC_BATCH];
        let mut jobs = [(INVALID_INDEX, INVALID_INDEX); SYNC_BATCH];
        let mut backoff: Option<SubmitBackoff> = None;
        let rc = loop {
            let rc = unsafe { submit_sync(fd, &plan[..count], &mut results, &mut jobs) };
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
        // Returns only once every job is done: workers write `results`.
        unsafe { wait_sync(&jobs[..count]) };
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

/// scePthreadSetcancelstate(state, old). PTHREAD_CANCEL_DISABLE is 1 in the
/// FreeBSD thread library libkernel derives from.
static SET_CANCEL_STATE: crate::rt::sys::LazySym =
    crate::rt::sys::LazySym::new(c"scePthreadSetcancelstate");
/// The POSIX entry libkernel also exports, if the sce one is missing.
static SET_CANCEL_STATE_POSIX: crate::rt::sys::LazySym =
    crate::rt::sys::LazySym::new(c"pthread_setcancelstate");
type SetCancelStateFn = unsafe extern "C" fn(c_int, *mut c_int) -> c_int;
const CANCEL_DISABLE: c_int = 1;

/// Turns cancellation off for the calling game thread while its read is in
/// flight: the wait (`wait_sync`) is a cancellation point, and a thread
/// cancelled there would leave workers writing into its dead stack
/// (`results`, the iovec buffers) and its job slots never freed. Returns the
/// state to restore, None when libkernel lacks the call or refuses.
#[inline(never)]
fn no_cancel() -> Option<c_int> {
    let set = cancel_state_fn()?;
    let mut old: c_int = 0;
    (unsafe { set(CANCEL_DISABLE, &mut old) } == 0).then_some(old)
}

/// scePthreadSetcancelstate, else pthread_setcancelstate (same arguments;
/// PTHREAD_CANCEL_DISABLE is 1 in both).
fn cancel_state_fn() -> Option<SetCancelStateFn> {
    unsafe { SET_CANCEL_STATE.get::<SetCancelStateFn>() }
        .or_else(|| unsafe { SET_CANCEL_STATE_POSIX.get::<SetCancelStateFn>() })
}

/// Restores the state `no_cancel` replaced; a cancel asked meanwhile acts at
/// the thread's next cancellation point, after the read is done.
#[inline(never)]
fn restore_cancel(old: Option<c_int>) {
    let Some(old) = old else { return };
    if let Some(set) = cancel_state_fn() {
        let mut prev: c_int = 0;
        unsafe { set(old, &mut prev) };
    }
}

/// Reserves and queues one job per `plan` entry, all or none; one over two
/// or more chunks splits into children. `jobs[i]` gets (slot, split group
/// or INVALID_INDEX) and each result is zeroed. EAGAIN while the virtual
/// AIO table is full, as the AIO submit.
unsafe fn submit_sync(
    fd: c_int,
    plan: &[(u64, *mut u8, usize)],
    results: &mut [SceKernelAioResult; SYNC_BATCH],
    jobs: &mut [(u32, u32); SYNC_BATCH],
) -> c_int {
    let Some(fd_index) = decode_virtual_fd(fd) else {
        return SCE_KERNEL_ERROR_EBADF;
    };
    let state = unsafe { pack_state() };
    let queued_at_usec = pack_telemetry_usecs();
    let notify_one;
    {
        let _lock = PACK_M.lock();
        let rc = unsafe { submit_sync_locked(state, fd, fd_index, plan, results, jobs) };
        if rc != 0 {
            return rc;
        }
        let mut queued = 0usize;
        for &job in &jobs[..plan.len()] {
            queued += unsafe {
                for_each_job_locked(state, job, |i| queue_push_locked(state, i, queued_at_usec))
            };
        }
        notify_one = queued == 1 && unsafe { effective_latency_reserve_locked(state) } == 0;
    }
    if notify_one {
        QUEUE_CV.notify_one();
    } else {
        QUEUE_CV.notify_all();
    }
    0
}

/// Under PACK_M: the reserve half of `submit_sync`; on failure frees what it
/// reserved.
unsafe fn submit_sync_locked(
    state: *mut PackState,
    fd: c_int,
    fd_index: u32,
    plan: &[(u64, *mut u8, usize)],
    results: &mut [SceKernelAioResult; SYNC_BATCH],
    jobs: &mut [(u32, u32); SYNC_BATCH],
) -> c_int {
    let mut rc = 0;
    let mut prepared = 0usize;
    for (i, &(at, buf, nbyte)) in plan.iter().enumerate() {
        let req = SceKernelAioRWRequest {
            offset: at as off_t,
            nbyte,
            buf: buf.cast(),
            result: &mut results[i],
            fd,
        };
        let mut children = [0u32; SPLIT_MAX_CHILDREN];
        let rest = plan.len() - i - 1;
        match unsafe {
            prepare_virtual_request_locked(
                state,
                req,
                fd_index,
                SCE_KERNEL_AIO_PRIORITY_HIGH,
                rest + SPLIT_MIN_FREE_SLOTS,
                &mut children,
            )
        } {
            Ok((group, _)) => jobs[i] = (children[0], group),
            Err(e) => {
                rc = e;
                break;
            }
        }
        prepared += 1;
    }
    if rc == 0 && !unsafe { ensure_workers_locked(state) } {
        rc = SCE_KERNEL_ERROR_ENOMEM;
    }
    if rc != 0 {
        for &job in &jobs[..prepared] {
            unsafe { free_job_locked(state, job) };
        }
    }
    rc
}

/// Under PACK_M: runs `f` on each job slot of a sync request (its slot, or
/// every child of its split group) and returns how many.
unsafe fn for_each_job_locked(
    state: *mut PackState,
    (index, group): (u32, u32),
    mut f: impl FnMut(u32),
) -> usize {
    if group == INVALID_INDEX {
        f(index);
        return 1;
    }
    let slot = unsafe { &(*state).virtual_aio_groups[group as usize] };
    let mut walked = 0;
    for &id in &slot.children[..slot.child_count as usize] {
        let mut child = INVALID_INDEX;
        if unsafe { decode_virtual_aio(id, &mut child, null_mut()) } {
            f(child);
            walked += 1;
        }
    }
    walked
}

/// Under PACK_M: frees a sync request's job slots and its split group.
unsafe fn free_job_locked(state: *mut PackState, job: (u32, u32)) {
    unsafe { for_each_job_locked(state, job, |i| free_virtual_aio_locked(state, i)) };
    if job.1 != INVALID_INDEX {
        unsafe { free_virtual_aio_group_locked(state, job.1) };
    }
}

/// Sleeps on AIO_CV until every job of `jobs` is Done, then frees them. A
/// job completes under PACK_M (worker.rs `complete_virtual_job`: result,
/// phase, then the last split child's caller result), and shutdown aborts
/// queued and reserved jobs and requeues parked ones (`cancel_virtual_jobs`),
/// so the wait ends; returning before would leave workers writing into the
/// caller's `results`. AIO_CV is shared, so every waiting reader wakes on
/// each completion and rescans its jobs; few threads read this way (490
/// packed POSIX reads in 2.4 min on a zstd title, 45 on a pkg title, debug
/// `posix_reads`), so a per-reader condvar waits for a title where it shows.
unsafe fn wait_sync(jobs: &[(u32, u32)]) {
    let state = unsafe { pack_state() };
    let mut g = PACK_M.lock();
    loop {
        let mut pending = 0usize;
        for &job in jobs {
            unsafe {
                for_each_job_locked(state, job, |i| {
                    pending +=
                        ((*state).virtual_aio[i as usize].phase != VirtualAioPhase::Done) as usize
                })
            };
        }
        if pending == 0 {
            break;
        }
        AIO_CV.wait(&mut g);
    }
    for &job in jobs {
        unsafe { free_job_locked(state, job) };
    }
}

/// Stack left to the calling thread: its stack pointer minus the lowest
/// address of its stack, from libkernel's thread attributes. None when
/// libkernel lacks them or refuses.
fn stack_left() -> Option<usize> {
    type Attr = *mut c_void;
    type SelfFn = unsafe extern "C" fn() -> ScePthread;
    type InitFn = unsafe extern "C" fn(*mut Attr) -> c_int;
    type GetFn = unsafe extern "C" fn(ScePthread, *mut Attr) -> c_int;
    type StackFn = unsafe extern "C" fn(*const Attr, *mut *mut c_void, *mut usize) -> c_int;
    let init = unsafe { sys::resolve_kernel::<InitFn>(c"scePthreadAttrInit") }?;
    let get = unsafe { sys::resolve_kernel::<GetFn>(c"scePthreadAttrGet") }?;
    let get_stack = unsafe { sys::resolve_kernel::<StackFn>(c"scePthreadAttrGetstack") }?;
    let destroy = unsafe { sys::resolve_kernel::<InitFn>(c"scePthreadAttrDestroy") }?;
    let this = unsafe { sys::resolve_kernel::<SelfFn>(c"scePthreadSelf") }?;
    let mut attr: Attr = null_mut();
    if unsafe { init(&mut attr) } != 0 {
        return None;
    }
    let (mut base, mut size): (*mut c_void, usize) = (null_mut(), 0);
    let ok = unsafe { get(this(), &mut attr) } == 0
        && unsafe { get_stack(&attr, &mut base, &mut size) } == 0
        && !base.is_null()
        && size != 0;
    let _ = unsafe { destroy(&mut attr) };
    let here = 0u8;
    let sp = core::ptr::addr_of!(here) as usize;
    (ok && sp > base as usize && sp - (base as usize) <= size).then(|| sp - base as usize)
}

/// Callers with less stack left than this count in `read_inline_low_stack`:
/// 4x the 4 KiB the sync read's frames are pinned to (read_on_workers down
/// to the queue push, tools/check_stack_frames.py `READ_CHAIN_BUDGET`).
const LOW_STACK: usize = 16 * 1024;
/// One read in this many asks libkernel for the caller's stack (five symbol
/// lookups and an attribute copy), off the timed span, so the debug build's
/// read latency stays comparable.
const STACK_SAMPLE: u32 = 16;
static STACK_SAMPLES: AtomicU32 = AtomicU32::new(0);
static STACK_LEFT_MIN: AtomicU64 = AtomicU64::new(u64::MAX);

/// Debug: the least stack a packed reader had left (`read_inline_stack_left`)
/// and the callers under LOW_STACK, sampled.
fn note_caller_stack() {
    if !cfg!(feature = "mem_report")
        || !STACK_SAMPLES
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(STACK_SAMPLE)
    {
        return;
    }
    let Some(left) = stack_left() else {
        return;
    };
    let min = STACK_LEFT_MIN
        .fetch_min(left as u64, Ordering::Relaxed)
        .min(left as u64);
    stats::set(stats::Stat::ReadInlineStackLeft, min);
    if left < LOW_STACK {
        stats::add(stats::Stat::ReadInlineLowStack, 1);
    }
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
    if decode_virtual_directory_fd(fd).is_some() {
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
    note_caller_stack();
    // Debug: the read's latency as its caller sees it, the queue wait, the
    // pack job and the wake-up included (posix_read_ns, rt/stats.rs).
    let start = stats::now();
    let cancel = no_cancel();
    let rc = unsafe { read_on_workers(fd, vector, offset as u64, length) };
    restore_cancel(cancel);
    stats::span(
        start,
        stats::Stat::PosixReads,
        stats::Stat::PosixReadNs,
        stats::Stat::PosixReadNsMax,
    );
    rc
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
    let Some(index) = decode_virtual_directory_fd(fd) else {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    };
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
    if !slot.active {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    if slot.real_fd >= 0 {
        match unsafe { real_lseek() } {
            Some(f) if unsafe { f(slot.real_fd, 0, SEEK_SET) } >= 0 => {}
            _ => return SCE_KERNEL_ERROR_EIO as off_t,
        }
    }
    slot.real_exhausted = false;
    slot.real_failed = false;
    slot.directory_offset = 0;
    slot.dot_emitted = false;
    slot.dot_dot_emitted = false;
    slot.listing = slot.listing_first;
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

/// reactor::PackPreadCallback for a window read a worker queued to the pread
/// pool itself (worker.rs `submit_pipeline_io_locked`). A pool thread holding
/// no lock calls it, so after the job is requeued it may also start the
/// decode worker the requeue asked for (worker.rs `grow_workers`), which the
/// reactor thread never does.
pub(crate) unsafe extern "C" fn complete_pack_pread(
    context: *mut c_void,
    notification: *const reactor::AprExternalAioNotification,
) {
    unsafe {
        complete_pack_backing_aio(context, notification.cast());
        super::worker::grow_workers();
    }
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
    // A worker claimed before the stop flag may still be in creation
    // (worker.rs grow_workers): wait for its handle; no claim starts after
    // the flag, which every claim checks under PACK_M.
    while super::worker::WORKER_SPAWNING.load(Ordering::Acquire) != 0 {
        unsafe { sceKernelUsleep(100) };
    }
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
                directory.write(VirtualDirectorySlot::EMPTY);
                VIRTUAL_DIRECTORY_LIVE[i].store(false, Ordering::Release);
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
/// and the decoded cache.
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
    // Under CACHE_MUTEX: a late index load may be carving the cache again
    // (manifest.rs `grow_cache_from_index`); it gives up once it sees the
    // stop flag, so the block freed here is the one that stays.
    let _cache = CACHE_MUTEX.lock();
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

    /// A sync read's jobs are its own slot, or every child of its split
    /// group (the wait and the free walk these), skipping a stale child id.
    /// Freeing runs pipeline code the host cannot link (no
    /// scePthreadCond*), so it is not called here.
    #[test]
    fn sync_jobs_are_the_slot_or_the_split_children() {
        use std::alloc::{alloc_zeroed, dealloc, Layout};
        let layout = Layout::new::<PackState>();
        unsafe {
            let state = alloc_zeroed(layout).cast::<PackState>();
            assert!(!state.is_null());
            let single = allocate_virtual_aio_locked(state);
            let parent = allocate_virtual_aio_locked(state);
            let child = allocate_virtual_aio_locked(state);
            let group = allocate_virtual_aio_group_locked(state);
            let g = &mut (*state).virtual_aio_groups[group as usize];
            g.child_count = 3;
            for (k, i) in [parent, child].into_iter().enumerate() {
                g.children[k] = encode_virtual_aio(i, (*state).virtual_aio[i as usize].generation);
            }
            // Not a virtual AIO id: skipped.
            g.children[2] = 5;
            let mut seen = std::vec::Vec::new();
            assert_eq!(
                for_each_job_locked(state, (single, INVALID_INDEX), |i| seen.push(i)),
                1
            );
            assert_eq!(
                for_each_job_locked(state, (parent, group), |i| seen.push(i)),
                2
            );
            assert_eq!(seen, [single, parent, child]);
            dealloc(state.cast(), layout);
        }
    }
}
