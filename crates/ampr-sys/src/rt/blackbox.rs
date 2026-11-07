//! Debug-only crash black box: `/data/ampr_emu_trace.txt`, written as
//! things happen so it survives a crash that kills the process before the
//! metrics server answers (a UE5 title with every libc hook
//! routing died ~1 s after start, SIGSEGV write to an unmapped page, no
//! :9090; it was the `_open` hook re-entering itself through libkernel
//! `open`, see `pack::libkernel::real_open`). It holds the loaded modules
//! with their segment addresses (all of them at module_start, then each
//! module a load returns), so a crash RIP from ShadowMount+'s log maps to a
//! module, and the failed path hook events (`stats::fs_event`, rc < 0) that
//! `/fsfail` would keep (`stats::fail_kept`) plus every module load (op b'K').
//! Probe events (`stats::fs_note`, rt/probe.rs) are written whatever their
//! rc, once per distinct (op, path) as `/fsfail` lists them: a probe that
//! succeeds (issue #22, `I v 0x0 ... noloc.larc`) shows what a game used on
//! packed files before it died. Other successful file calls are not written:
//! a write per file call would slow the debug build, and a crash is placed by
//! the module list and the last failures. The file is truncated at each
//! start.

use super::sys;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicI32, Ordering};

const PATH: &core::ffi::CStr = c"/data/ampr_emu_trace.txt";
const O_WRONLY: c_int = 0x1;
const O_APPEND: c_int = 0x8;
const O_CREAT: c_int = 0x200;
const O_TRUNC: c_int = 0x400;

static FD: AtomicI32 = AtomicI32::new(-1);

/// One output line, cut at 400 bytes.
struct Line {
    buf: [u8; 400],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Self { buf: [0; 400], n: 0 }
    }
    fn s(&mut self, b: &[u8]) -> &mut Self {
        for &c in b {
            if self.n < self.buf.len() - 1 {
                self.buf[self.n] = c;
                self.n += 1;
            }
        }
        self
    }
    fn x(&mut self, v: u64) -> &mut Self {
        let digits = (64 - (v | 1).leading_zeros()).div_ceil(4);
        self.s(b"0x");
        for i in (0..digits).rev() {
            self.s(&[b"0123456789abcdef"[((v >> (i * 4)) & 0xf) as usize]]);
        }
        self
    }
    unsafe fn cstr(&mut self, p: *const c_char) -> &mut Self {
        let mut i = 0;
        while !p.is_null() && i < 300 {
            let c = unsafe { *p.add(i) } as u8;
            if c == 0 {
                break;
            }
            self.s(&[c]);
            i += 1;
        }
        self
    }
    fn emit(&mut self) {
        // `s` keeps the last byte free, so a full line still ends in '\n'.
        self.buf[self.n] = b'\n';
        self.n += 1;
        let fd = FD.load(Ordering::Acquire);
        if fd >= 0 {
            let _ = unsafe { super::index::write_all(fd, &self.buf[..self.n]) };
        }
    }
}

/// Creates the file (truncating the previous run's) and logs the modules.
pub(crate) unsafe fn open() {
    // `pack::real_open`: the `_open` original once hooks install, so this
    // open never reaches the `_open` index routing; before them (module_start
    // calls this first) libkernel's dynamic `open`, whose `_open` is not
    // detoured yet. real_posix_open would return EIO with no slot filled.
    let open = unsafe { super::pack::real_open() };
    let flags = O_WRONLY | O_CREAT | O_TRUNC | O_APPEND;
    let fd = open.map_or(-1, |f| unsafe { f(PATH.as_ptr(), flags, 0o644 as c_int) });
    FD.store(fd, Ordering::Release);
    Line::new().s(b"start ").s(super::exports::BUILD_REV.as_bytes()).emit();
    unsafe { modules(b"start") };
}

/// module_stop: stops trace writes but leaves the fd open. A hook thread
/// can load FD in `Line::emit` just before this swap and write after it;
/// had the fd been closed, its number could already name another file
/// (a save file), and the trace line would land there. Without a lock no
/// close is race-free, and a lock per event is not worth it in the debug
/// build: the fd costs one descriptor per PRX reload in one process (a
/// reload opens a new one with O_TRUNC), and process exit closes it.
pub(crate) fn close() {
    FD.store(-1, Ordering::Release);
}

/// A path hook event: "fs <op> <how> <rc> <path>".
/// Only failures (rc < 0) and module loads (op b'K', rc is the handle),
/// filtered as `/fsfail` filters them (`stats::fail_kept`).
pub(crate) fn event(op: u8, how: u8, rc: i64, path: *const c_char) {
    if (rc >= 0 && op != b'K') || FD.load(Ordering::Relaxed) < 0 {
        return;
    }
    if !super::stats::fail_kept(how, rc, unsafe { &prefix(path) }) {
        return;
    }
    line(op, how, rc, path);
}

/// A probe event (`stats::fs_note`), same line as `event` whatever `rc` is.
/// The caller writes each distinct (op, path) once and has already applied
/// `stats::fail_kept`.
pub(crate) fn note(op: u8, how: u8, rc: i64, path: *const c_char) {
    if FD.load(Ordering::Relaxed) >= 0 {
        line(op, how, rc, path);
    }
}

fn line(op: u8, how: u8, rc: i64, path: *const c_char) {
    let mut l = Line::new();
    l.s(b"fs ").s(&[op, b' ', how, b' ']).x(rc as u64).s(b" ");
    unsafe { l.cstr(path) }.emit();
}

/// The first bytes of `path`, NUL-padded: enough for `stats::fail_kept`.
unsafe fn prefix(path: *const c_char) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        let c = if path.is_null() {
            0
        } else {
            (unsafe { *path.add(i) }) as u8
        };
        if c == 0 {
            break;
        }
        *b = c;
    }
    out
}

type InfoFn = unsafe extern "C" fn(c_int, *mut u8) -> c_int;

/// Every loaded module (module_start), one line each as `module` writes.
pub(crate) unsafe fn modules(tag: &[u8]) {
    if FD.load(Ordering::Relaxed) < 0 {
        return;
    }
    type ListFn = unsafe extern "C" fn(*mut c_int, usize, *mut usize) -> c_int;
    let list = unsafe { sys::resolve_kernel::<ListFn>(c"sceKernelGetModuleList") };
    let info = unsafe { sys::resolve_kernel::<InfoFn>(c"sceKernelGetModuleInfo") };
    let (Some(list), Some(info)) = (list, info) else {
        Line::new().s(b"mod unavailable").emit();
        return;
    };
    let mut mods = [0 as c_int; 256];
    let mut n = 0usize;
    if unsafe { list(mods.as_mut_ptr(), mods.len(), &mut n) } != 0 {
        Line::new().s(b"mod list failed").emit();
        return;
    }
    for &m in &mods[..n.min(mods.len())] {
        unsafe { module_line(info, tag, m) };
    }
}

/// The module `handle` a load just returned, as one `modules` line.
pub(crate) unsafe fn module(tag: &[u8], handle: c_int) {
    if FD.load(Ordering::Relaxed) < 0 {
        return;
    }
    match unsafe { sys::resolve_kernel::<InfoFn>(c"sceKernelGetModuleInfo") } {
        Some(info) => unsafe { module_line(info, tag, handle) },
        None => Line::new().s(b"mod unavailable").emit(),
    }
}

/// "mod <tag> <handle> <name> seg<i>=<addr>+<size>"; nothing when the info
/// call fails. SceKernelModuleInfo as rt/exports.rs `modules` reads it
/// (0x160 bytes: name +0x08, segments +0x108 as {addr u64, size u32,
/// prot u32} x 4, count +0x148).
unsafe fn module_line(info: InfoFn, tag: &[u8], m: c_int) {
    let mut buf = [0u8; 0x160];
    buf[..8].copy_from_slice(&0x160u64.to_ne_bytes());
    if unsafe { info(m, buf.as_mut_ptr()) } != 0 {
        return;
    }
    let name = &buf[8..0x108];
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
    let mut l = Line::new();
    l.s(b"mod ").s(tag).s(b" ").x(m as u32 as u64).s(b" ").s(name);
    for i in 0..(buf[0x148] as usize).min(4) {
        let at = 0x108 + i * 0x10;
        let addr = u64::from_ne_bytes(buf[at..at + 8].try_into().unwrap_or([0; 8]));
        let size = u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap_or([0; 4]));
        l.s(b" seg").x(i as u64).s(b"=").x(addr).s(b"+").x(size as u64);
    }
    l.emit();
}
