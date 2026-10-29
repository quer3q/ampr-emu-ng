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

// ---- ordinary virtual fd reads (R7) -------------------------------------------
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

/// EAGAIN retries of a full virtual AIO table, 100 us apart (~0.2 s).
const SUBMIT_RETRIES: u32 = 2000;

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
        let mut retries = 0;
        let rc = loop {
            let rc = unsafe {
                sceKernelAioSubmitReadCommandsMultiple(
                    requests.as_mut_ptr(),
                    count as c_int,
                    SCE_KERNEL_AIO_PRIORITY_HIGH,
                    ids.as_mut_ptr(),
                )
            };
            if rc != SCE_KERNEL_ERROR_EAGAIN || retries >= SUBMIT_RETRIES {
                break rc;
            }
            retries += 1;
            unsafe { sceKernelUsleep(100) };
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

/// Logical size of the packed file behind a virtual fd slot.
unsafe fn virtual_file_size(state: *const PackState, file_id: u32) -> Option<u64> {
    unsafe { packed_read_file(state, file_id) }.map(|(_, size, _)| size)
}

/// A live virtual fd slot (`active` and the fd's generation), under PACK_M.
unsafe fn virtual_fd_snapshot(
    state: *const PackState,
    index: u32,
    generation: u16,
) -> Option<VirtualFdSlot> {
    let _lock = PACK_M.lock();
    let slot = (*state).virtual_fds[index as usize];
    (slot.active && slot.generation == generation).then_some(slot)
}

/// Classifies `fd` for a read: Some((slot, generation)) for a virtual pack
/// fd; None with `*handled` false for any physical fd (the caller runs the
/// real function) or true with `*rc` set for a virtual directory fd.
unsafe fn virtual_read_target(
    fd: c_int,
    handled: *mut bool,
    rc: &mut ssize_t,
) -> Option<(u32, u16)> {
    unsafe { clear_handled(handled) };
    *rc = SCE_KERNEL_ERROR_EBADF as ssize_t;
    let (mut index, mut generation) = (0u32, 0u16);
    if unsafe { decode_virtual_fd(fd, &mut index, &mut generation) } {
        if !handled.is_null() {
            unsafe { *handled = true };
        }
        return Some((index, generation));
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
    unsafe { read_on_workers(fd, vector, offset as u64, length) }
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
    let Some((index, generation)) = (unsafe { virtual_read_target(fd, handled, &mut rc) }) else {
        return rc;
    };
    let state = unsafe { pack_state() };
    let submission = PackSubmission::new(state);
    if !submission.admitted() {
        return SCE_KERNEL_ERROR_EBADF as ssize_t;
    }
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, index, generation) }) else {
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
    let Some((index, generation)) = (unsafe { virtual_read_target(fd, handled, &mut rc) }) else {
        return rc;
    };
    let state = unsafe { pack_state() };
    if unsafe { virtual_fd_snapshot(state, index, generation) }.is_none() {
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
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, index, generation) }) else {
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
        if s.active && s.generation == generation {
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
    let (mut index, mut generation) = (0u32, 0u16);
    if unsafe { decode_virtual_fd(fd, &mut index, &mut generation) } {
        if !handled.is_null() {
            unsafe { *handled = true };
        }
        return unsafe { lseek_virtual_fd(index, generation, offset, whence) };
    }
    let state = unsafe { pack_state() };
    if !unsafe { decode_virtual_directory_fd(fd, &mut index, &mut generation) } {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
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
unsafe fn lseek_virtual_fd(index: u32, generation: u16, offset: off_t, whence: c_int) -> off_t {
    let state = unsafe { pack_state() };
    if unsafe { virtual_fd_snapshot(state, index, generation) }.is_none() {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let _descriptor = VIRTUAL_FD_MUTEXES[index as usize].lock();
    if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    let Some(slot) = (unsafe { virtual_fd_snapshot(state, index, generation) }) else {
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
    if !s.active || s.generation != generation {
        return SCE_KERNEL_ERROR_EBADF as off_t;
    }
    s.cursor = target;
    target as off_t
}

pub unsafe fn ampr_pack_is_virtual_fd(fd: c_int) -> bool {
    let (mut slot, mut generation) = (0u32, 0u16);
    if !unsafe { decode_virtual_fd(fd, &mut slot, &mut generation) } {
        return false;
    }
    let state = unsafe { pack_state() };
    let _lock = PACK_M.lock();
    let s = &(*state).virtual_fds[slot as usize];
    s.active && s.generation == generation
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

    {
        let mut g = PACK_M.lock();
        (*state).submissions_closed = true;
        SUBMIT_CV.wait_until(
            &mut g,
            || unsafe { core::ptr::read_volatile(addr_of_mut!((*sp).active_submissions)) } == 0,
        );
    }
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
    unsafe { release_manifest_storage(state) };
    {
        let _g = MANIFEST_MUTEX.lock();
        LOAD_STATE.store(PACK_LOAD_UNAVAILABLE, Ordering::Release);
    }
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
        for fd in (*state).virtual_fds.iter_mut() {
            *fd = VirtualFdSlot::EMPTY;
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
                ampr_internal_amm_pool_free(
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
                ampr_internal_amm_pool_free(
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
            ampr_internal_amm_pool_free(
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
            ampr_internal_amm_pool_free(
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
    fn iov_total_sums_and_rejects_bad_vectors() {
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
    }

    #[test]
    fn iov_slice_checks_count_and_array() {
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
    fn clamp_read_stops_at_eof() {
        assert_eq!(clamp_read(0, 10, 100), Ok(10));
        assert_eq!(clamp_read(95, 10, 100), Ok(5));
        assert_eq!(clamp_read(100, 10, 100), Ok(0));
        assert_eq!(clamp_read(200, 10, 100), Ok(0));
        assert_eq!(clamp_read(5, 0, 100), Ok(0));
        assert_eq!(clamp_read(0, 10, 0), Ok(0));
        assert_eq!(clamp_read(-1, 10, 100), Err(SCE_KERNEL_ERROR_EINVAL));
        assert_eq!(clamp_read(0, usize::MAX, 7), Ok(7));
    }

    #[test]
    fn seek_target_follows_whence() {
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
    fn segment_plan_matches_posix_vector_semantics() {
        // A readv of [3, 0, 4] bytes at offset 6 of a 10-byte file reads 4
        // bytes: 3 into a, 1 into the start of b.
        let (mut a, mut b) = ([0u8; 3], [0u8; 4]);
        let v = [iov(&mut a), NULL_IOV, iov(&mut b)];
        let length = clamp_read(6, iov_total(&v).unwrap(), 10).unwrap();
        assert_eq!(length, 4);
        let mut out = [(0u64, core::ptr::null_mut::<u8>(), 0usize); 4];
        assert_eq!(plan_segment_reads(&v, 6, length, 0, &mut out), 2);
        assert_eq!(out[..2], [(6, a.as_mut_ptr(), 3), (9, b.as_mut_ptr(), 1)]);
    }

    #[test]
    fn segment_plan_resumes_mid_vector_and_caps_batch() {
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
}
