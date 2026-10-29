//! zstd: libkernel's internal fd entry points (`_read`, `_readv`, `_close`,
//! `_fstat`, `_getdirentries`, and `fcntl`/`_fcntl`/`sceKernelFcntl`), which
//! libc's stdio and dirent call in place of the hooked public names. A
//! virtual pack fd takes the pack helpers; any other fd calls that entry
//! point's own original, so a libkernel wrapper calling another never loops.

use super::*;

const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;

pub unsafe extern "C" fn underscore_read_emul(
    fd: c_int,
    buffer: *mut c_void,
    size: usize,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_read_fd(fd, buffer, size, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { kernel_slot::<KernelReadFn>(sys::hook::_read) }
        .map_or_else(posix_read_missing, |f| unsafe { f(fd, buffer, size) })
}

pub unsafe extern "C" fn underscore_readv_emul(
    fd: c_int,
    iov: *const SceKernelIovec,
    iovcnt: c_int,
) -> ssize_t {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_readv_fd(fd, iov, iovcnt, &mut handled) };
    if handled {
        return posix_count_from_pack(rc);
    }
    unsafe { kernel_slot::<KernelReadvFn>(sys::hook::_readv) }
        .map_or_else(posix_read_missing, |f| unsafe { f(fd, iov, iovcnt) })
}

pub unsafe extern "C" fn underscore_close_emul(fd: c_int) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_close_fd(fd, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    unsafe { kernel_slot::<KernelCloseFn>(sys::hook::_close) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fd) })
}

pub unsafe extern "C" fn underscore_fstat_emul(fd: c_int, stat: *mut SceKernelStat) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_fstat_fd(fd, stat, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    unsafe { kernel_slot::<KernelFstatFn>(sys::hook::_fstat) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fd, stat) })
}

pub unsafe extern "C" fn underscore_getdirentries_emul(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
) -> c_int {
    let mut handled = false;
    let rc = unsafe { ampr_pack_try_getdirentries_fd(fd, buffer, size, basep, &mut handled) };
    if handled {
        return posix_result_from_pack(rc);
    }
    unsafe { kernel_slot::<KernelGetdirentriesFn>(sys::hook::_getdirentries) }
        .map_or_else(posix_missing_original, |f| unsafe {
            f(fd, buffer, size, basep)
        })
}

/// `fcntl` of a virtual pack fd or directory, as an SCE result: the
/// descriptor and status flags read as a plain read-only fd and setting them
/// is a no-op; any other command is EINVAL. None for any other fd.
fn virtual_fcntl(fd: c_int, cmd: c_int) -> Option<c_int> {
    if !unsafe { ampr_pack_is_virtual_fd(fd) || ampr_pack_is_virtual_directory_fd(fd) } {
        return None;
    }
    Some(match cmd {
        F_GETFD | F_SETFD | F_SETFL => 0,
        F_GETFL => O_RDONLY,
        _ => SCE_KERNEL_ERROR_EINVAL,
    })
}

/// `int fcntl(int, int, ...)`: the one variadic argument arrives in the
/// third integer register on SysV x86-64 (see `posix_open_emul`).
type FcntlFn = unsafe extern "C" fn(c_int, c_int, ...) -> c_int;

unsafe fn posix_fcntl(id: usize, fd: c_int, cmd: c_int, arg: c_long) -> c_int {
    if let Some(rc) = virtual_fcntl(fd, cmd) {
        return posix_result_from_pack(rc);
    }
    unsafe { kernel_slot::<FcntlFn>(id) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fd, cmd, arg) })
}

pub unsafe extern "C" fn posix_fcntl_emul(fd: c_int, cmd: c_int, arg: c_long) -> c_int {
    unsafe { posix_fcntl(sys::hook::fcntl, fd, cmd, arg) }
}

pub unsafe extern "C" fn underscore_fcntl_emul(fd: c_int, cmd: c_int, arg: c_long) -> c_int {
    unsafe { posix_fcntl(sys::hook::_fcntl, fd, cmd, arg) }
}

pub unsafe extern "C" fn sceKernelFcntl_emul(fd: c_int, cmd: c_int, arg: c_long) -> c_int {
    if let Some(rc) = virtual_fcntl(fd, cmd) {
        return rc;
    }
    unsafe { kernel_slot::<FcntlFn>(sys::hook::sceKernelFcntl) }
        .map_or_else(|| SCE_KERNEL_ERROR_EIO, |f| unsafe { f(fd, cmd, arg) })
}
