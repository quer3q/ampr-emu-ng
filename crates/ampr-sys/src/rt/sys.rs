//! libkernel / libScePthread / libc FFI used by the runtime ports.
//! Names are the plain C names; the PRX build renames them to NIDs.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};

// ---- C types -------------------------------------------------------------

pub type off_t = i64;
pub type ssize_t = isize;
/// FreeBSD `mode_t` (uint16); pass as `c_int` through variadic `open`.
pub type SceKernelMode = u16;
pub type SceKernelUseconds = c_uint;
pub type SceKernelClockid = c_int;
/// `pthread_mutex_t` on FreeBSD is an opaque pointer; null before init.
pub type ScePthreadMutex = *mut c_void;
pub type ScePthreadMutexattr = *mut c_void;
pub type ScePthreadCond = *mut c_void;
pub type ScePthreadCondattr = *mut c_void;
pub type SceKernelEqueue = *mut c_void;
pub type SceAmmSubmitId = u32;
pub type SceAprSubmitId = u32;
pub type SceAprFileId = u32;

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SceKernelTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `SceAmmResultBuffer` (SDK AMPR header).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SceAmmResultBuffer {
    pub result: c_int,
    pub error_offset: u32,
}

// ---- constants -----------------------------------------------------------

pub const SCE_KERNEL_CLOCK_MONOTONIC: SceKernelClockid = 4;
pub const SCE_KERNEL_PAGE_SIZE: usize = 16384;
pub const SCE_KERNEL_PROT_CPU_READ: c_int = 0x01;
pub const SCE_KERNEL_PROT_CPU_RW: c_int = 0x02;
pub const SCE_KERNEL_PROT_CPU_EXEC: c_int = 0x04;
pub const SCE_KERNEL_PROT_CPU_ALL: c_int = 0x07;
pub const SCE_KERNEL_PROT_AMPR_WRITE: c_int = 0x80;
pub const SCE_KERNEL_PROT_AMPR_ALL: c_int = 0xc0;

// ---- errno ---------------------------------------------------------------

/// FreeBSD POSIX errno values.
pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const ESRCH: c_int = 3;
pub const EINTR: c_int = 4;
pub const EIO: c_int = 5;
pub const ENXIO: c_int = 6;
pub const E2BIG: c_int = 7;
pub const EBADF: c_int = 9;
pub const ENOMEM: c_int = 12;
pub const EACCES: c_int = 13;
pub const EFAULT: c_int = 14;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const ENOTDIR: c_int = 20;
pub const EINVAL: c_int = 22;
pub const ENFILE: c_int = 23;
pub const EMFILE: c_int = 24;
pub const ENOSPC: c_int = 28;
pub const EPIPE: c_int = 32;
pub const EAGAIN: c_int = 35;
pub const EOPNOTSUPP: c_int = 45;
pub const ENOBUFS: c_int = 55;
pub const ETIMEDOUT: c_int = 60;
pub const ENAMETOOLONG: c_int = 63;
pub const ENOTEMPTY: c_int = 66;
pub const ENOSYS: c_int = 78;
pub const ECANCELED: c_int = 85;

/// `AMPR_SCE_ERRNO(v)`: 0x80020000 | v.
pub const fn sce_errno(v: c_int) -> c_int {
    (0x8002_0000u32 | v as u32) as c_int
}
pub const SCE_KERNEL_ERROR_UNKNOWN: c_int = sce_errno(0);
pub const SCE_KERNEL_ERROR_EPERM: c_int = sce_errno(EPERM);
pub const SCE_KERNEL_ERROR_ENOENT: c_int = sce_errno(ENOENT);
pub const SCE_KERNEL_ERROR_ESRCH: c_int = sce_errno(ESRCH);
pub const SCE_KERNEL_ERROR_EINTR: c_int = sce_errno(EINTR);
pub const SCE_KERNEL_ERROR_EIO: c_int = sce_errno(EIO);
pub const SCE_KERNEL_ERROR_ENXIO: c_int = sce_errno(ENXIO);
pub const SCE_KERNEL_ERROR_EBADF: c_int = sce_errno(EBADF);
pub const SCE_KERNEL_ERROR_ENOMEM: c_int = sce_errno(ENOMEM);
pub const SCE_KERNEL_ERROR_EFAULT: c_int = sce_errno(EFAULT);
pub const SCE_KERNEL_ERROR_EBUSY: c_int = sce_errno(EBUSY);
pub const SCE_KERNEL_ERROR_EEXIST: c_int = sce_errno(EEXIST);
pub const SCE_KERNEL_ERROR_ENOTDIR: c_int = sce_errno(ENOTDIR);
pub const SCE_KERNEL_ERROR_EINVAL: c_int = sce_errno(EINVAL);
pub const SCE_KERNEL_ERROR_ENFILE: c_int = sce_errno(ENFILE);
pub const SCE_KERNEL_ERROR_EMFILE: c_int = sce_errno(EMFILE);
pub const SCE_KERNEL_ERROR_EAGAIN: c_int = sce_errno(EAGAIN);
pub const SCE_KERNEL_ERROR_ETIMEDOUT: c_int = sce_errno(ETIMEDOUT);
pub const SCE_KERNEL_ERROR_ENAMETOOLONG: c_int = sce_errno(ENAMETOOLONG);
pub const SCE_KERNEL_ERROR_ENOSYS: c_int = sce_errno(ENOSYS);
pub const SCE_KERNEL_ERROR_ECANCELED: c_int = sce_errno(ECANCELED);

/// `ampr_sce_errno_from_posix`.
pub fn sce_errno_from_posix(err: c_int) -> c_int {
    match err {
        EINTR | EPERM | ENOENT | ESRCH | EIO | EBADF | EAGAIN | ENOMEM | EACCES | EFAULT
        | EBUSY | EEXIST | EINVAL | ENOTDIR | ENOSPC | EPIPE | EOPNOTSUPP | ENOTEMPTY | EMFILE
        | ENFILE | ENAMETOOLONG | ETIMEDOUT | ECANCELED | ENOBUFS | ENXIO | E2BIG | ENOSYS => {
            sce_errno(err)
        }
        _ => SCE_KERNEL_ERROR_UNKNOWN,
    }
}

/// `ampr_posix_errno_from_sce`.
pub fn posix_errno_from_sce(rc: c_int) -> c_int {
    let u = rc as u32;
    if u & 0xFFFF_0000 == 0x8002_0000 {
        let err = (u & 0xFFFF) as c_int;
        if err > 0 && err < 256 {
            return err;
        }
    }
    EIO
}

/// `ampr_posix_errno_is_fd_open_pressure`.
pub fn posix_errno_is_fd_open_pressure(err: c_int) -> bool {
    err == EAGAIN || err == EMFILE || err == ENFILE
}

/// Reads the thread errno.
pub fn errno() -> c_int {
    unsafe { *__error() }
}

/// A POSIX hook result as its sceKernel* form: -1 becomes the SCE error of
/// errno; other values pass through.
pub fn sce_result<R: Copy + Into<i64> + From<i32>>(rc: R) -> R {
    if rc.into() == -1 {
        R::from(sce_errno_from_posix(errno()))
    } else {
        rc
    }
}

/// Sets the thread errno.
pub fn set_errno(v: c_int) {
    unsafe { *__error() = v }
}

/// `ampr_libkernel_return_from_sce`: 0, or -1 with errno set.
pub fn libkernel_return_from_sce(rc: c_int) -> c_int {
    if rc == 0 {
        return 0;
    }
    set_errno(posix_errno_from_sce(rc));
    -1
}

/// `ampr_libkernel_return_from_sce_count`.
pub fn libkernel_return_from_sce_count(rc: c_int) -> c_int {
    if rc >= 0 {
        return rc;
    }
    let e = posix_errno_from_sce(rc);
    set_errno(e);
    if e != 0 {
        sce_errno_from_posix(e)
    } else {
        0
    }
}

// ---- libkernel / libScePthread / libc ------------------------------------

unsafe extern "C" {
    // libkernel: errno, time, sleep. Linux host tests: glibc's errno accessor.
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    pub fn __error() -> *mut c_int;
    pub fn sceKernelUsleep(usec: SceKernelUseconds) -> c_int;
    pub fn sceKernelClockGettime(clock: SceKernelClockid, tp: *mut SceKernelTimespec) -> c_int;

    // libkernel: AMM / mapper.
    pub fn sceKernelGiveDirectMemoryToMapper(
        search_start: off_t,
        search_end: off_t,
        size: usize,
        align: usize,
        usage: c_int,
        dmem_offset: *mut off_t,
    ) -> c_int;
    pub fn sceKernelMapperGetParam(param: *mut u64) -> c_int;
    pub fn sceKernelCallIndirectBuffer(priority: c_uint, base: u64, offset: u64) -> c_int;
    pub fn sceKernelCallIndirectBuffer2(
        priority: c_uint,
        base: u64,
        offset: u64,
        result: *mut SceAmmResultBuffer,
        submit_id: *mut SceAmmSubmitId,
    ) -> c_int;
    pub fn sceKernelWaitCommandBufferCompletion(submit_id: SceAmmSubmitId) -> c_int;

    // libkernel: AMM command writers.
    pub fn sceKernelWriteMapCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        ty: u64,
        prot: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMapCommand2(
        dst: *mut c_void,
        va: u64,
        size: u64,
        ty: u64,
        prot: u64,
        prt: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMapWithGpuMaskIdCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        ty: u64,
        prot: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMapDirectCommand(
        dst: *mut c_void,
        va: u64,
        dmem_offset: u64,
        size: u64,
        ty: u64,
        prot: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMapDirectWithGpuMaskIdCommand(
        dst: *mut c_void,
        va: u64,
        dmem_offset: u64,
        size: u64,
        ty: u64,
        prot: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteUnmapCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteRemapCommand(
        dst: *mut c_void,
        va_new: u64,
        va_old: u64,
        size: u64,
        prot: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteRemapWithGpuMaskIdCommand(
        dst: *mut c_void,
        va_new: u64,
        va_old: u64,
        size: u64,
        prot: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMultiMapCommand(
        dst: *mut c_void,
        va_new: u64,
        va_alias: u64,
        size: u64,
        prot: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteMultiMapWithGpuMaskIdCommand(
        dst: *mut c_void,
        va_new: u64,
        va_alias: u64,
        size: u64,
        prot: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteModifyProtectCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        prot: u64,
        prot_mask: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteModifyProtectWithGpuMaskIdCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        prot: u64,
        prot_mask: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteModifyMtypeProtectCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        ty: u64,
        prot: u64,
        prot_mask: u64,
        out_size: *mut u64,
    ) -> c_int;
    pub fn sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand(
        dst: *mut c_void,
        va: u64,
        size: u64,
        ty: u64,
        prot: u64,
        prot_mask: u64,
        gpu_mask_id: u64,
        out_size: *mut u64,
    ) -> c_int;

    // libScePthread.
    pub fn scePthreadMutexInit(
        m: *mut ScePthreadMutex,
        attr: *const ScePthreadMutexattr,
        name: *const c_char,
    ) -> c_int;
    pub fn scePthreadMutexDestroy(m: *mut ScePthreadMutex) -> c_int;
    pub fn scePthreadMutexLock(m: *mut ScePthreadMutex) -> c_int;
    pub fn scePthreadMutexTrylock(m: *mut ScePthreadMutex) -> c_int;
    pub fn scePthreadMutexUnlock(m: *mut ScePthreadMutex) -> c_int;
    pub fn scePthreadCondInit(
        c: *mut ScePthreadCond,
        attr: *const ScePthreadCondattr,
        name: *const c_char,
    ) -> c_int;
    pub fn scePthreadCondDestroy(c: *mut ScePthreadCond) -> c_int;
    pub fn scePthreadCondSignal(c: *mut ScePthreadCond) -> c_int;
    pub fn scePthreadCondBroadcast(c: *mut ScePthreadCond) -> c_int;
    pub fn scePthreadCondWait(c: *mut ScePthreadCond, m: *mut ScePthreadMutex) -> c_int;
    pub fn scePthreadCondTimedwait(
        c: *mut ScePthreadCond,
        m: *mut ScePthreadMutex,
        usec: SceKernelUseconds,
    ) -> c_int;

    // libc (LIBC_IMPORTS). Prefer core::ptr for copies; these are for parity.
    // Only the global allocator (lib.rs, non-test) calls these two.
    #[cfg(not(test))]
    pub fn malloc(size: usize) -> *mut c_void;
    #[cfg(not(test))]
    pub fn free(p: *mut c_void);
    pub fn strlen(s: *const c_char) -> usize;
    pub fn strnlen(s: *const c_char, max: usize) -> usize;
}

pub(crate) use super::pack::sceKernelClose;

// ---- hook slots (rt/hook.rs) -----------------------------------------------

/// `AmprLibkernelHookId` values (AMPR_EMU_APR_LOCAL_EQUEUE=1 layout).
pub mod hook {
    pub const open: usize = 0;
    pub const stat: usize = 1;
    pub const sceKernelCheckReachability: usize = 2;
    pub const unlink: usize = 3;
    pub const rename: usize = 4;
    pub const sceKernelMprotect: usize = 5;
    pub const sceKernelMtypeprotect: usize = 6;
    pub const sceKernelWaitCommandBufferCompletion: usize = 33;
    pub const sceKernelGetDirectMemorySize: usize = 34;
    pub const sceKernelAvailableDirectMemorySize: usize = 35;
    pub const sceKernelWriteMapCommand: usize = 36;
    pub const sceKernelWriteMapCommand2: usize = 37;
    pub const sceKernelWriteMapWithGpuMaskIdCommand: usize = 38;
    pub const sceKernelWriteMapDirectCommand: usize = 39;
    pub const sceKernelWriteMapDirectWithGpuMaskIdCommand: usize = 40;
    pub const sceKernelWriteRemapCommand: usize = 41;
    pub const sceKernelWriteRemapWithGpuMaskIdCommand: usize = 42;
    pub const sceKernelWriteMultiMapCommand: usize = 43;
    pub const sceKernelWriteMultiMapWithGpuMaskIdCommand: usize = 44;
    pub const sceKernelWriteModifyProtectCommand: usize = 45;
    pub const sceKernelWriteModifyProtectWithGpuMaskIdCommand: usize = 46;
    pub const sceKernelWriteModifyMtypeProtectCommand: usize = 47;
    pub const sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand: usize = 48;
    pub const sceKernelWriteRemapIntoPrtCommand: usize = 49;
    pub const sceKernelClose: usize = 64;
    pub const close: usize = 65;
    pub const fstat: usize = 66;
    pub const lseek: usize = 67;
    pub const getdents: usize = 68;
    pub const getdirentries: usize = 69;
    // Optional ordinary read interposers for virtual pack fds (rt/pack/fd_read.rs).
    pub const read: usize = 70;
    pub const pread: usize = 71;
    pub const readv: usize = 72;
    pub const preadv: usize = 73;
    pub const sceKernelRead: usize = 74;
    pub const sceKernelPread: usize = 75;
    pub const sceKernelReadv: usize = 76;
    pub const sceKernelPreadv: usize = 77;
    // 78..=83: sceKernelOpen, Stat, Fstat, Lseek, Getdents, Getdirentries
    // (zstd; the game's file layer opens /app0 through them). No slot lookups.
    // zstd: libc (fopen/fread, opendir, ...) calls libkernel's internal entry
    // points, which bypass every hook above; each falls back to its own
    // original so a libkernel wrapper that calls another never recurses.
    pub const _open: usize = 84;
    pub const _openat: usize = 85;
    pub const _read: usize = 86;
    pub const _readv: usize = 87;
    pub const _close: usize = 88;
    pub const _fstat: usize = 89;
    pub const _getdirentries: usize = 90;
    pub const access: usize = 91;
    pub const lstat: usize = 92;
    pub const fcntl: usize = 93;
    pub const _fcntl: usize = 94;
    pub const sceKernelFcntl: usize = 95;
    pub const COUNT: usize = 96;
}

/// Original (pre-detour) libkernel entry points, indexed by `hook::*`, and
/// the non-detouring libkernel resolver; both defined in rt/hook.rs.
pub use super::hook::{amprResolveLibkernelFunction, g_amprOriginalLibkernelById};

/// Casts a raw code pointer to the fn-pointer type `F`; None if null.
pub unsafe fn fn_from_ptr<F: Copy>(p: *mut c_void) -> Option<F> {
    debug_assert!(core::mem::size_of::<F>() == core::mem::size_of::<*mut c_void>());
    if p.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute_copy(&p) })
    }
}

/// Original libkernel slot `id` (acquire load).
pub unsafe fn kernel_slot<F: Copy>(id: usize) -> Option<F> {
    use core::sync::atomic::{AtomicPtr, Ordering};
    let slot = unsafe {
        &*(core::ptr::addr_of!(g_amprOriginalLibkernelById[id]) as *const AtomicPtr<c_void>)
    };
    unsafe { fn_from_ptr(slot.load(Ordering::Acquire)) }
}

/// `ampr_dynamic_kernel_func_or_null<F>(name)`.
pub unsafe fn resolve_kernel<F: Copy>(name: &CStr) -> Option<F> {
    unsafe { fn_from_ptr(amprResolveLibkernelFunction(name.as_ptr())) }
}

/// Resolve-once cache for an optional libkernel symbol.
pub struct LazySym {
    name: &'static CStr,
    p: core::sync::atomic::AtomicUsize, // 0 = unresolved, 1 = absent
}

impl LazySym {
    /// New unresolved cache for `name`.
    pub const fn new(name: &'static CStr) -> Self {
        Self {
            name,
            p: core::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Resolved function, or None if libkernel lacks it.
    pub unsafe fn get<F: Copy>(&self) -> Option<F> {
        use core::sync::atomic::Ordering;
        let mut v = self.p.load(Ordering::Acquire);
        if v == 0 {
            let r = unsafe { amprResolveLibkernelFunction(self.name.as_ptr()) } as usize;
            v = if r == 0 { 1 } else { r };
            self.p.store(v, Ordering::Release);
        }
        if v == 1 {
            None
        } else {
            unsafe { fn_from_ptr(v as *mut c_void) }
        }
    }
}

/// Crash like `std::abort()` without a plain libc import.
pub fn abort() -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("ud2", options(noreturn))
    }
    #[cfg(not(target_arch = "x86_64"))]
    loop {
        core::hint::spin_loop()
    }
}

// ---- real (un-detoured) memory and file wrappers ---------------------------

/// `ampr_real_sceKernelGetDirectMemorySize` (slot must be installed).
pub unsafe fn real_get_direct_memory_size() -> usize {
    type F = unsafe extern "C" fn() -> usize;
    match unsafe { kernel_slot::<F>(hook::sceKernelGetDirectMemorySize) } {
        Some(f) => unsafe { f() },
        None => abort(),
    }
}

/// `ampr_real_sceKernelAvailableDirectMemorySize` (slot must be installed).
pub unsafe fn real_available_direct_memory_size(
    start: off_t,
    end: off_t,
    align: usize,
    phys_out: *mut off_t,
    size_out: *mut usize,
) -> c_int {
    type F = unsafe extern "C" fn(off_t, off_t, usize, *mut off_t, *mut usize) -> c_int;
    match unsafe { kernel_slot::<F>(hook::sceKernelAvailableDirectMemorySize) } {
        Some(f) => unsafe { f(start, end, align, phys_out, size_out) },
        None => abort(),
    }
}

/// `ampr_real_sceKernelMprotect` (slot must be installed).
pub unsafe fn real_mprotect(addr: *const c_void, len: usize, prot: c_int) -> c_int {
    type F = unsafe extern "C" fn(*const c_void, usize, c_int) -> c_int;
    match unsafe { kernel_slot::<F>(hook::sceKernelMprotect) } {
        Some(f) => unsafe { f(addr, len, prot) },
        None => abort(),
    }
}

static MAPPER_USAGE_STATS: LazySym = LazySym::new(c"sceKernelMapperGetUsageStatsData");

/// `ampr_real_sceKernelMapperGetUsageStatsData`; ENXIO if absent.
pub unsafe fn real_mapper_get_usage_stats_data(data: *mut u64) -> c_int {
    type F = unsafe extern "C" fn(*mut u64) -> c_int;
    match unsafe { MAPPER_USAGE_STATS.get::<F>() } {
        Some(f) => unsafe { f(data) },
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

/// `ampr_real_posix_open`: fd, or -1 with errno set.
pub unsafe fn real_posix_open(path: *const c_char, flags: c_int, mode: SceKernelMode) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
    match unsafe { kernel_slot::<F>(hook::open) } {
        Some(f) => unsafe { f(path, flags, mode as c_int) },
        None => {
            set_errno(EIO);
            -1
        }
    }
}

/// `ampr_real_physical_close`: slot, then dynamic `close`, else -1/EIO.
pub unsafe fn real_physical_close(fd: c_int) -> c_int {
    type F = unsafe extern "C" fn(c_int) -> c_int;
    let f = unsafe { kernel_slot::<F>(hook::close).or_else(|| resolve_kernel::<F>(c"close")) };
    match f {
        Some(f) => unsafe { f(fd) },
        None => {
            set_errno(EIO);
            -1
        }
    }
}

/// `ampr_real_physical_pread`: the pre-detour `pread` slot, then dynamic
/// `pread` (the dynamic symbol is the detoured entry once hooks install).
/// -1/EIO if absent.
pub unsafe fn real_physical_pread(fd: c_int, buf: *mut c_void, size: usize, off: off_t) -> ssize_t {
    type F = unsafe extern "C" fn(c_int, *mut c_void, usize, off_t) -> ssize_t;
    match unsafe { kernel_slot::<F>(hook::pread).or_else(|| resolve_kernel::<F>(c"pread")) } {
        Some(f) => unsafe { f(fd, buf, size, off) },
        None => {
            set_errno(EIO);
            -1
        }
    }
}

/// Monotonic clock in nanoseconds; 0 on failure.
pub fn monotonic_ns() -> u64 {
    let mut ts = SceKernelTimespec::default();
    if unsafe { sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

// ---- libkernel imports for rt/hook.rs (dlsym + SDK fallback entry points) --
// The fallbacks are only taken by address; signatures follow the SDK headers.

pub type SceKernelModule = i32;

unsafe extern "C" {
    pub fn sceKernelDlsym(
        handle: SceKernelModule,
        symbol: *const c_char,
        addr: *mut *mut c_void,
    ) -> c_int;
    pub fn sceKernelCheckReachability(path: *const c_char) -> c_int;
    pub fn sceKernelMprotect(addr: *const c_void, len: usize, prot: c_int) -> c_int;
    pub fn sceKernelMtypeprotect(addr: *const c_void, len: usize, ty: c_int, prot: c_int) -> c_int;
    pub fn sceKernelMapFlexibleMemory(
        addr: *mut *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
    ) -> c_int;
    pub fn sceKernelMapDirectMemory(
        addr: *mut *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        off: off_t,
        max_page: usize,
    ) -> c_int;
    pub fn sceKernelMapDirectMemory2(
        addr: *mut *mut c_void,
        len: usize,
        ty: c_int,
        prot: c_int,
        flags: c_int,
        off: off_t,
        max_page: usize,
    ) -> c_int;
    pub fn sceKernelBatchMap(entries: *mut c_void, n: c_int, done: *mut c_int) -> c_int;
    pub fn sceKernelBatchMap2(
        entries: *mut c_void,
        n: c_int,
        done: *mut c_int,
        flags: c_int,
    ) -> c_int;
    pub fn sceKernelMemoryPoolBatch(
        entries: *const c_void,
        n: c_int,
        done: *mut c_int,
        flags: c_int,
    ) -> c_int;
    pub fn sceKernelMemoryPoolCommit(
        addr: *mut c_void,
        len: usize,
        ty: c_int,
        prot: c_int,
        flags: c_int,
    ) -> c_int;
    pub fn sceKernelMapNamedFlexibleMemory(
        addr: *mut *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        name: *const c_char,
    ) -> c_int;
    pub fn sceKernelMapNamedDirectMemory(
        addr: *mut *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        off: off_t,
        align: usize,
        name: *const c_char,
    ) -> c_int;
    pub fn sceKernelGetDirectMemorySize() -> usize;
    pub fn sceKernelAvailableDirectMemorySize(
        start: off_t,
        end: off_t,
        align: usize,
        phys_out: *mut off_t,
        size_out: *mut usize,
    ) -> c_int;
    // APR entry points (address-only fallbacks).
    pub fn sceKernelAprResolveFilepathsToIds();
    pub fn sceKernelAprResolveFilepathsToIdsAndFileSizes();
    pub fn sceKernelAprResolveFilepathsWithPrefixToIds();
    pub fn sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes();
    pub fn sceKernelAprResolveFilepathsToIdsForEach();
    pub fn sceKernelAprResolveFilepathsToIdsAndFileSizesForEach();
    pub fn sceKernelAprResolveFilepathsWithPrefixToIdsForEach();
    pub fn sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach();
    pub fn sceKernelAprGetFileSize();
    pub fn sceKernelAprGetFileStat();
    pub fn sceKernelAprSubmitCommandBuffer();
    pub fn sceKernelAprSubmitCommandBuffer_TEST();
    pub fn sceKernelAprSubmitCommandBufferAndGetResult();
    pub fn sceKernelAprSubmitCommandBufferAndGetResult_TEST();
    pub fn sceKernelAprSubmitCommandBufferAndGetId();
    pub fn sceKernelAprWaitCommandBuffer();
    // Equeue entry points (address-only fallbacks).
    pub fn sceKernelCreateEqueue();
    pub fn sceKernelWaitEqueue();
    pub fn sceKernelDeleteEqueue();
    pub fn sceKernelAddAmprEvent();
    pub fn sceKernelDeleteAmprEvent();
    pub fn sceKernelAddTimerEvent();
    pub fn sceKernelAddReadEvent();
    pub fn sceKernelAddWriteEvent();
    pub fn sceKernelAddFileEvent();
    pub fn sceKernelAddUserEvent();
    pub fn sceKernelAddUserEventEdge();
    pub fn sceKernelAddHRTimerEvent();
}

// ---- libkernel imports for rt/index.rs --------------------------------------

unsafe extern "C" {
    pub fn sceKernelWrite(fd: c_int, buf: *const c_void, size: usize) -> ssize_t;
}

// ---- libkernel imports for rt/equeue.rs -------------------------------------

pub const SCE_PTHREAD_MUTEX_RECURSIVE: c_int = 2;

unsafe extern "C" {
    pub fn scePthreadMutexattrInit(attr: *mut ScePthreadMutexattr) -> c_int;
    pub fn scePthreadMutexattrSettype(attr: *mut ScePthreadMutexattr, ty: c_int) -> c_int;
    pub fn scePthreadMutexattrDestroy(attr: *mut ScePthreadMutexattr) -> c_int;
    pub fn sceKernelGetProcessTimeCounter() -> u64;
    pub fn sceKernelGetProcessTimeCounterFrequency() -> u64;
}

// ---- libkernel imports for rt/equeue.rs (part 2) ----------------------------

unsafe extern "C" {
    pub fn sceKernelTriggerUserEvent(eq: SceKernelEqueue, id: c_int, udata: *mut c_void) -> c_int;
}

// ---- physical file wrappers for rt/index.rs ---------------------------------
// `st` is a FreeBSD `struct stat` (120 bytes).

unsafe fn slot_or_dynamic<F: Copy>(id: usize, name: &CStr) -> Option<F> {
    unsafe { kernel_slot::<F>(id).or_else(|| resolve_kernel::<F>(name)) }
}

pub(crate) fn eio() -> c_int {
    set_errno(EIO);
    -1
}

/// `ampr_real_posix_stat`.
pub unsafe fn real_posix_stat(path: *const c_char, st: *mut c_void) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
    unsafe { kernel_slot::<F>(hook::stat) }.map_or_else(eio, |f| unsafe { f(path, st) })
}

/// `ampr_real_posix_unlink`.
pub unsafe fn real_posix_unlink(path: *const c_char) -> c_int {
    type F = unsafe extern "C" fn(*const c_char) -> c_int;
    unsafe { kernel_slot::<F>(hook::unlink) }.map_or_else(eio, |f| unsafe { f(path) })
}

/// `ampr_real_posix_rename`.
pub unsafe fn real_posix_rename(from: *const c_char, to: *const c_char) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
    unsafe { kernel_slot::<F>(hook::rename) }.map_or_else(eio, |f| unsafe { f(from, to) })
}

/// `ampr_real_physical_fstat`: slot, then dynamic `fstat`.
pub unsafe fn real_physical_fstat(fd: c_int, st: *mut c_void) -> c_int {
    type F = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
    unsafe { slot_or_dynamic::<F>(hook::fstat, c"fstat") }
        .map_or_else(eio, |f| unsafe { f(fd, st) })
}

/// `ampr_real_physical_getdents`: slot, then dynamic `getdents`.
pub unsafe fn real_physical_getdents(fd: c_int, buf: *mut c_char, size: c_int) -> c_int {
    type F = unsafe extern "C" fn(c_int, *mut c_char, c_int) -> c_int;
    unsafe { slot_or_dynamic::<F>(hook::getdents, c"getdents") }
        .map_or_else(eio, |f| unsafe { f(fd, buf, size) })
}

// ---- libkernel imports for rt/equeue.rs (part 3) ----------------------------

unsafe extern "C" {
    pub fn sceKernelDeleteUserEvent(eq: SceKernelEqueue, id: c_int) -> c_int;
}

#[cfg(test)]
mod sce_result_tests {
    use super::*;

    #[test]
    fn minus_one_becomes_the_sce_error_of_errno() {
        set_errno(ENOENT);
        assert_eq!(sce_result(-1i32), sce_errno(ENOENT));
        assert_eq!(sce_result(-1i64), sce_errno(ENOENT) as i64);
        assert_eq!(sce_result(7i32), 7);
        assert_eq!(sce_result(0i64), 0);
    }
}
