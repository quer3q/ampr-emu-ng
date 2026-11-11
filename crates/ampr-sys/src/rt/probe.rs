//! Debug-only pass-through observers for fully packed games, LZ4 or zstd
//! packs (every game file except the executables, sce_sys, sce_module and
//! the fakelib packed): they show on a console which file APIs the runtime
//! does not serve a game uses on packed files (dup, poll, openat, ...).
//! Each calls its own original libkernel entry point (`sys::kernel_slot`,
//! as rt/pack/zstd_libc.rs does) and never changes the result; it only
//! logs through `stats::fs_note`, so `/fsfail` lists each distinct
//! (op, file) once. The op letters are documented at
//! `FsEvents` in rt/stats.rs. Built only with `mem_report`; rt/hook.rs
//! installs the observers into slots 112..=119, the game AIO submit hooks
//! (rt/pack/aio.rs) log their served packed requests through
//! `note_aio_submit`, and rt/index.rs
//! calls `probe_path` from the libc path hooks it installs as observers.
//! rt/pack/mmap.rs logs its b'X'/b'Y' events through `fd_path` and
//! `event_text`.

use super::index::{probe_file_path, probe_packed_path};
use super::pack::{
    has_virtual_fd, posix_missing_original, posix_read_missing, virtual_directory_fd_path,
    virtual_fd_file_id, SceKernelAioRWRequest, SCE_KERNEL_AIO_REQUEST_NUM_MAX,
};
use super::stats;
use super::sys::{self, kernel_slot, EACCES, EBADF, ENAMETOOLONG, ENOENT, ENOTDIR};
use core::ffi::{c_char, c_int, c_void};

// ---- event text ---------------------------------------------------------------

/// FsFails keeps 128 bytes of path; longer text would only be cut there.
const TEXT: usize = 128;
/// Lookup letter of an fd-based event: the fd is a virtual pack fd or dir.
pub(crate) const HOW_VIRTUAL: u8 = b'v';
const VIRTUAL_FD: &[u8] = b"<virtual fd>";

/// NUL-terminated event text, truncated to TEXT - 1 bytes.
#[derive(Clone, Copy)]
pub(crate) struct Text {
    buf: [u8; TEXT],
    n: usize,
}

impl Text {
    const fn new() -> Self {
        Self {
            buf: [0; TEXT],
            n: 0,
        }
    }
    fn push(&mut self, s: &[u8]) {
        for &b in s {
            if self.n + 1 >= TEXT {
                return;
            }
            self.buf[self.n] = b;
            self.n += 1;
        }
    }
    unsafe fn push_cstr(&mut self, p: *const c_char) {
        let mut i = 0;
        while !p.is_null() && self.n + 1 < TEXT {
            let b = unsafe { *p.add(i) } as u8;
            if b == 0 {
                break;
            }
            self.push(&[b]);
            i += 1;
        }
    }
    /// `call` and a space before the text, when the whole still fits.
    fn prefixed(&self, call: &[u8]) -> Self {
        if call.len() + 1 + self.n >= TEXT {
            return *self;
        }
        let mut t = Self::new();
        t.push(call);
        t.push(b" ");
        t.push(&self.buf[..self.n]);
        t
    }
    fn ptr(&self) -> *const c_char {
        self.buf.as_ptr().cast()
    }
}

/// The path behind a virtual pack fd or directory fd (or `<virtual fd>`
/// when the slot has no indexed path); None for any other fd.
pub(crate) unsafe fn fd_path(fd: c_int) -> Option<Text> {
    let mut t = Text::new();
    if let Some(id) = unsafe { virtual_fd_file_id(fd) } {
        t.n = probe_file_path(id, &mut t.buf).unwrap_or(0);
    } else {
        t.n = unsafe { virtual_directory_fd_path(fd, &mut t.buf) }?;
    }
    if t.n == 0 {
        t.push(VIRTUAL_FD);
    }
    Some(t)
}

/// Logs an fd-based event as "<call> <path>" when `fd` is virtual.
pub(crate) fn note_text(op: u8, how: u8, rc: i64, call: &[u8], t: &Text) {
    stats::fs_note(op, how, rc, t.prefixed(call).ptr());
}

/// As `note_text`, through `stats::fs_event`: only a failure (rc < 0) enters
/// `/fsfail` (rt/pack/mmap.rs, whose served maps are counted instead).
pub(crate) fn event_text(op: u8, how: u8, rc: i64, call: &[u8], t: &Text) {
    stats::fs_event(op, how, rc, t.prefixed(call).ptr());
}

// ---- AIO ----------------------------------------------------------------------

/// The path of the first virtual fd among `count` requests, if any.
unsafe fn aio_path(reqs: *const SceKernelAioRWRequest, count: c_int) -> Option<Text> {
    if reqs.is_null() || count <= 0 || count as usize > SCE_KERNEL_AIO_REQUEST_NUM_MAX {
        return None;
    }
    if !unsafe { has_virtual_fd(reqs, count) } {
        return None;
    }
    let first = (0..count as usize).find_map(|i| unsafe { fd_path((*reqs.add(i)).fd) });
    first.or_else(|| {
        let mut t = Text::new();
        t.push(VIRTUAL_FD);
        Some(t)
    })
}

/// Logs b'I' "<call> <path>" with `rc` when the game's own AIO submit
/// (rt/pack/aio.rs, hook ids 100 and 101) had a request on a packed fd,
/// which the runtime's AIO emulation served. The emulation already read
/// every request's fd before returning, so a bad `reqs` faults there first;
/// the callers skip this when the id pointer is null, the one rejection
/// that comes before that read.
pub(crate) unsafe fn note_aio_submit(
    call: &[u8],
    reqs: *const SceKernelAioRWRequest,
    count: c_int,
    rc: c_int,
) {
    if let Some(t) = unsafe { aio_path(reqs, count) } {
        note_text(b'I', HOW_VIRTUAL, rc.into(), call, &t);
    }
}

// ---- dup, poll, select --------------------------------------------------------

type DupFn = unsafe extern "C" fn(c_int) -> c_int;
type Dup2Fn = unsafe extern "C" fn(c_int, c_int) -> c_int;

pub(crate) unsafe extern "C" fn dup_probe(fd: c_int) -> c_int {
    let seen = unsafe { fd_path(fd) };
    let rc = unsafe { kernel_slot::<DupFn>(sys::hook::dup) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fd) });
    if let Some(t) = seen {
        note_text(b'D', HOW_VIRTUAL, rc.into(), b"dup", &t);
    }
    rc
}

pub(crate) unsafe extern "C" fn dup2_probe(fd: c_int, fd2: c_int) -> c_int {
    let seen = unsafe { fd_path(fd).or_else(|| fd_path(fd2)) };
    let rc = unsafe { kernel_slot::<Dup2Fn>(sys::hook::dup2) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fd, fd2) });
    if let Some(t) = seen {
        note_text(b'D', HOW_VIRTUAL, rc.into(), b"dup2", &t);
    }
    rc
}

/// FreeBSD `struct pollfd`.
#[repr(C)]
pub(crate) struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

type PollFn = unsafe extern "C" fn(*mut PollFd, u32, c_int) -> c_int;
type SelectFn =
    unsafe extern "C" fn(c_int, *mut c_void, *mut c_void, *mut c_void, *mut c_void) -> c_int;

/// FreeBSD `FD_SETSIZE`. `select` remains a pass-through probe; synthetic
/// packed fds (512..1024) fit in a set but are not implemented by this
/// observer.
const FD_SETSIZE: c_int = 1024;

/// Inspects `fds` only after the original returned >= 0: it validated the
/// array (an invalid pointer or `nfds` must get the original's EFAULT/EINVAL,
/// not a fault in the probe), and a virtual fd still shows,
/// since poll reports an unknown fd as POLLNVAL in `revents`, not an error.
pub(crate) unsafe extern "C" fn poll_probe(fds: *mut PollFd, nfds: u32, timeout: c_int) -> c_int {
    let rc = unsafe { kernel_slot::<PollFn>(sys::hook::poll) }
        .map_or_else(posix_missing_original, |f| unsafe { f(fds, nfds, timeout) });
    let seen = if fds.is_null() || rc < 0 {
        None
    } else {
        (0..nfds as usize).find_map(|i| unsafe { fd_path((*fds.add(i)).fd) })
    };
    if let Some(t) = seen {
        note_text(b'W', HOW_VIRTUAL, rc.into(), b"poll", &t);
    }
    rc
}

pub(crate) unsafe extern "C" fn select_probe(
    nfds: c_int,
    r: *mut c_void,
    w: *mut c_void,
    e: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    let rc = unsafe { kernel_slot::<SelectFn>(sys::hook::select) }
        .map_or_else(posix_missing_original, |f| unsafe {
            f(nfds, r, w, e, timeout)
        });
    // The sets are not read (the observer does not serve virtual fds); an nfds
    // past FD_SETSIZE is logged as itself, lookup b'n' (rt/stats.rs).
    if nfds > FD_SETSIZE {
        stats::fs_note(b'W', HOW_NFDS, rc.into(), select_text(nfds).ptr());
    }
    rc
}

/// Lookup letter of a select with nfds past FD_SETSIZE.
const HOW_NFDS: u8 = b'n';

/// "select nfds=<n>" in decimal.
fn select_text(nfds: c_int) -> Text {
    let mut t = Text::new();
    t.push(b"select nfds=");
    let mut digits = [0u8; 10];
    let mut v = nfds.unsigned_abs();
    let mut n = 0;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits[..n].reverse();
    t.push(&digits[..n]);
    t
}

// ---- path calls ---------------------------------------------------------------

/// Lookup letter and text of a path call worth logging: a path relative to
/// a virtual directory fd (b'd', "<dir>/<path>"), or an absolute packed
/// file (b'p') or indexed directory (b'd') path. None for anything else.
unsafe fn path_event(dirfd: c_int, path: *const c_char) -> Option<(u8, Text)> {
    if path.is_null() {
        return None;
    }
    let mut t = Text::new();
    if unsafe { *path } != b'/' as c_char {
        t.n = unsafe { virtual_directory_fd_path(dirfd, &mut t.buf) }?;
        t.push(b"/");
        unsafe { t.push_cstr(path) };
        return Some((b'd', t));
    }
    let how = unsafe { probe_packed_path(path) }?;
    unsafe { t.push_cstr(path) };
    Some((how, t))
}

/// Logs path call `op` with result `rc` through `path_event`, called right
/// after the original. The probe reads `path` only when the original did:
/// on success, or on an error FreeBSD namei returns only after its copyin
/// of the path (ENOENT, ENOTDIR, EACCES, EBADF of the dirfd, ENAMETOOLONG),
/// so a bad pointer gets the original's EFAULT instead of a fault in the
/// probe. A failed packed path open is ENOENT, so those
/// events still show. Errors that can come before the copyin (EINVAL of a
/// flag check, EMFILE, EFAULT, the missing original's EIO) are not
/// inspected. errno is read before the probe makes calls of its own.
unsafe fn note_path(op: u8, dirfd: c_int, path: *const c_char, rc: i64) {
    let read = rc >= 0
        || matches!(
            sys::errno(),
            ENOENT | ENOTDIR | EACCES | EBADF | ENAMETOOLONG
        );
    if !read {
        return;
    }
    if let Some((how, t)) = unsafe { path_event(dirfd, path) } {
        stats::fs_note(op, how, rc, t.ptr());
    }
}

/// `int openat(int, const char *, int, ...)`: the variadic mode arrives in
/// the fourth integer register on SysV x86-64 (as `underscore_openat_emul`
/// in rt/index.rs declares it).
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int;
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void, c_int) -> c_int;
type FaccessatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int;
type ReadlinkFn = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize;

pub(crate) unsafe extern "C" fn openat_probe(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    let rc = unsafe { kernel_slot::<OpenatFn>(sys::hook::openat) }
        .map_or_else(posix_missing_original, |f| unsafe {
            f(dirfd, path, flags, mode)
        });
    unsafe { note_path(b'T', dirfd, path, rc.into()) };
    rc
}

pub(crate) unsafe extern "C" fn fstatat_probe(
    dirfd: c_int,
    path: *const c_char,
    sb: *mut c_void,
    flag: c_int,
) -> c_int {
    let rc = unsafe { kernel_slot::<FstatatFn>(sys::hook::fstatat) }
        .map_or_else(posix_missing_original, |f| unsafe {
            f(dirfd, path, sb, flag)
        });
    unsafe { note_path(b'F', dirfd, path, rc.into()) };
    rc
}

pub(crate) unsafe extern "C" fn faccessat_probe(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flag: c_int,
) -> c_int {
    let rc = unsafe { kernel_slot::<FaccessatFn>(sys::hook::faccessat) }
        .map_or_else(posix_missing_original, |f| unsafe {
            f(dirfd, path, mode, flag)
        });
    unsafe { note_path(b'C', dirfd, path, rc.into()) };
    rc
}

pub(crate) unsafe extern "C" fn readlink_probe(
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    let rc = unsafe { kernel_slot::<ReadlinkFn>(sys::hook::readlink) }
        .map_or_else(posix_read_missing, |f| unsafe { f(path, buf, len) });
    unsafe { note_path(b'N', AT_FDCWD, path, rc as i64) };
    rc
}

// ---- libc path hooks in observe mode (rt/index.rs) ---------------------------

const AT_FDCWD: c_int = -100;

/// Logs `op` with the result `rc` of a pass-through libc path call (`_open`,
/// `_openat`, `access`, `lstat` whose `AMPR_ZSTD_LIBC_HOOKS` bit is off)
/// already made on `path`, when `path` is a packed file or indexed directory.
pub(crate) unsafe fn probe_path(path: *const c_char, op: u8, rc: c_int) {
    if let Some(how) = unsafe { probe_packed_path(path) } {
        stats::fs_note(op, how, rc.into(), path);
    }
}
