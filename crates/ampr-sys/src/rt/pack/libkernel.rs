//! Cached libkernel resolution, physical pack fd close and checked u64 add.

use super::*;

/// Cached `amprResolveLibkernelFunction`; a failed lookup is retried next call
/// (a symbol missing early, before libkernel resolves it, must still bind later).
pub(crate) unsafe fn resolve_cached<F: Copy>(slot: &AtomicPtr<c_void>, symbol: &CStr) -> Option<F> {
    let mut value = slot.load(Ordering::Acquire);
    if value.is_null() {
        value = unsafe { amprResolveLibkernelFunction(symbol.as_ptr()) };
        if !value.is_null() {
            slot.store(value, Ordering::Release);
        }
    }
    unsafe { fn_from_ptr(value) }
}

/// Fixed pre-detour hook slot first, then the resolver cache. The six-argument
/// form takes the `_name` original before the public slot: libkernel's public
/// entry calls its `_name` twin, which is hooked in titles with packs (ids
/// 84..=95), so a runtime call through the public original re-enters that
/// hook. Through `close`, the debug build's tune::load closed its file into
/// the `_close` hook, whose `pack_state()` spun forever on the state it was
/// still creating (see `sys::real_physical_close`).
macro_rules! real_fn {
    ($name:ident, $ty:ty, $slot:ident, $sym:literal, $under:expr, $id:expr) => {
        #[allow(dead_code)]
        pub(crate) unsafe fn $name() -> Option<$ty> {
            unsafe {
                kernel_slot::<$ty>($under)
                    .or_else(|| kernel_slot::<$ty>($id))
                    .or_else(|| resolve_cached::<$ty>(&$slot, $sym))
            }
        }
    };
    ($name:ident, $ty:ty, $slot:ident, $sym:literal, $id:expr) => {
        #[allow(dead_code)]
        pub(crate) unsafe fn $name() -> Option<$ty> {
            unsafe { kernel_slot::<$ty>($id).or_else(|| resolve_cached::<$ty>(&$slot, $sym)) }
        }
    };
    ($name:ident, $ty:ty, $slot:ident, $sym:literal) => {
        #[allow(dead_code)]
        pub(crate) unsafe fn $name() -> Option<$ty> {
            unsafe { resolve_cached::<$ty>(&$slot, $sym) }
        }
    };
}

real_fn!(
    real_public_open,
    KernelOpenFn,
    g_real_open,
    c"open",
    sys::hook::open
);

/// The runtime's own physical open: the `_open` original while `_open` is
/// detoured, else `open`. libkernel's `open` calls `_open`, so with the
/// `_open` hook routing (`AMPR_ZSTD_LIBC_HOOKS` bit 0) an open through
/// `open` re-entered the index routing: a UE5 title opens
/// `/app0/..` as a directory, and `ampr_pack_open_directory`'s physical open
/// looped `open` -> `_open` hook -> `ampr_pack_open_directory` until the main
/// thread's stack ran out (0xA80 bytes a level; debug build trace
/// `/data/ampr_emu_trace.txt`).
pub(crate) unsafe fn real_open() -> Option<KernelOpenFn> {
    unsafe { kernel_slot::<KernelOpenFn>(sys::hook::_open).or_else(|| real_public_open()) }
}
real_fn!(
    real_close,
    KernelCloseFn,
    g_real_close,
    c"close",
    sys::hook::_close,
    sys::hook::close
);
real_fn!(
    real_sce_close,
    KernelCloseFn,
    g_real_sce_close,
    c"sceKernelClose",
    sys::hook::sceKernelClose
);
real_fn!(
    real_fstat,
    KernelFstatFn,
    g_real_fstat,
    c"fstat",
    sys::hook::_fstat,
    sys::hook::fstat
);
real_fn!(
    real_stat,
    KernelStatFn,
    g_real_stat,
    c"stat",
    sys::hook::stat
);
real_fn!(
    real_getdents,
    KernelGetdentsFn,
    g_real_getdents,
    c"getdents",
    sys::hook::getdents
);
real_fn!(
    real_getdirentries,
    KernelGetdirentriesFn,
    g_real_getdirentries,
    c"getdirentries",
    sys::hook::_getdirentries,
    sys::hook::getdirentries
);
// R7 read interposers: the pre-detour slot first, so a pack-internal read
// never re-enters its own hook once `pread`/`read` are detoured.
real_fn!(
    real_pread,
    KernelPreadFn,
    g_real_pread,
    c"pread",
    sys::hook::pread
);

pub(crate) type KernelReadFn = unsafe extern "C" fn(c_int, *mut c_void, usize) -> ssize_t;
pub(crate) type KernelReadvFn =
    unsafe extern "C" fn(c_int, *const SceKernelIovec, c_int) -> ssize_t;
pub(crate) type KernelPreadvFn =
    unsafe extern "C" fn(c_int, *const SceKernelIovec, c_int, off_t) -> ssize_t;

pub(crate) static g_real_read: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_readv: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_preadv: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_sce_read: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_sce_pread: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_sce_readv: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_sce_preadv: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

real_fn!(
    real_read,
    KernelReadFn,
    g_real_read,
    c"read",
    sys::hook::_read,
    sys::hook::read
);
real_fn!(
    real_readv,
    KernelReadvFn,
    g_real_readv,
    c"readv",
    sys::hook::_readv,
    sys::hook::readv
);
real_fn!(
    real_preadv,
    KernelPreadvFn,
    g_real_preadv,
    c"preadv",
    sys::hook::preadv
);
real_fn!(
    real_sce_read,
    KernelReadFn,
    g_real_sce_read,
    c"sceKernelRead",
    sys::hook::sceKernelRead
);
real_fn!(
    real_sce_pread,
    KernelPreadFn,
    g_real_sce_pread,
    c"sceKernelPread",
    sys::hook::sceKernelPread
);
real_fn!(
    real_sce_readv,
    KernelReadvFn,
    g_real_sce_readv,
    c"sceKernelReadv",
    sys::hook::sceKernelReadv
);
real_fn!(
    real_sce_preadv,
    KernelPreadvFn,
    g_real_sce_preadv,
    c"sceKernelPreadv",
    sys::hook::sceKernelPreadv
);
real_fn!(
    real_lseek,
    KernelLseekFn,
    g_real_lseek,
    c"lseek",
    sys::hook::lseek
);
real_fn!(
    real_aio_submit,
    KernelAioSubmitFn,
    g_real_aio_submit,
    c"sceKernelAioSubmitReadCommandsMultiple"
);
real_fn!(
    real_aio_submit_single,
    KernelAioSubmitFn,
    g_real_aio_submit_single,
    c"sceKernelAioSubmitReadCommands"
);
real_fn!(
    real_aio_poll_single,
    KernelAioPollSingleFn,
    g_real_aio_poll_single,
    c"sceKernelAioPollRequest"
);
real_fn!(
    real_aio_poll,
    KernelAioPollFn,
    g_real_aio_poll,
    c"sceKernelAioPollRequests"
);
real_fn!(
    real_aio_wait_single,
    KernelAioWaitSingleFn,
    g_real_aio_wait_single,
    c"sceKernelAioWaitRequest"
);
real_fn!(
    real_aio_wait,
    KernelAioWaitFn,
    g_real_aio_wait,
    c"sceKernelAioWaitRequests"
);
real_fn!(
    real_aio_delete_single,
    KernelAioDeleteSingleFn,
    g_real_aio_delete_single,
    c"sceKernelAioDeleteRequest"
);
real_fn!(
    real_aio_delete,
    KernelAioDeleteFn,
    g_real_aio_delete,
    c"sceKernelAioDeleteRequests"
);

pub(crate) unsafe fn close_physical_pack_fd(fd: c_int) -> c_int {
    if fd < 0 {
        return 0;
    }
    let Some(close_fn) = (unsafe { real_close() }) else {
        return SCE_KERNEL_ERROR_EIO;
    };
    let rc = unsafe { close_fn(fd) };
    // FreeBSD frees the descriptor even when close fails (EIO, EINTR); only
    // EBADF means none was open. Counting just rc == 0 would shrink the fd
    // budget for good on each failed close (a released USB image).
    let err = if rc == -1 { errno() } else { 0 };
    if err != EBADF {
        ampr_index_fd_pack_note_close();
    }
    if rc == -1 {
        sce_errno_from_posix(err)
    } else {
        rc
    }
}

pub(crate) fn checked_add_u64(a: u64, b: u64, out: *mut u64) -> bool {
    if out.is_null() || a > u64::MAX - b {
        return false;
    }
    unsafe { *out = a + b };
    true
}
