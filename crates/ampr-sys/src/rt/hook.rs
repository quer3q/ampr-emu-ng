//! Inline detours into libkernel (and the
//! external equeue producers), the original/fallback slot tables, and the
//! memory-protection `_emul` hooks that promote AMPR-write mappings to CPU_RW.
//! AMPR_EMU_APR_LOCAL_EQUEUE=1 layout only. Logging is dropped.
#![allow(non_snake_case, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{addr_of_mut, null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering::*};

use ampr_hook::{Hde64, F_ERROR, F_RELATIVE, F_RIP_RELATIVE, MAX_INSN_LEN};

use super::sync::{spin_pause_or_yield, SpinLock, SyncCell};
use super::sys::{self, hook as id, off_t, SceKernelModule};

// ---- constants -------------------------------------------------------------

const JUMP_SIZE: usize = 14;
const MAX_STOLEN: usize = 64;
const PAGE: usize = sys::SCE_KERNEL_PAGE_SIZE;
const TRAMP_SIZE: usize = 512;
const SLOTS_PER_PAGE: usize = PAGE / TRAMP_SIZE;
const POOL_COPY_PAGES: usize = 64;
const POOL_COPY_CAP: usize = POOL_COPY_PAGES * PAGE;
const LIBKERNEL: SceKernelModule = 0x2001;
const HOOK_COUNT: usize = id::COUNT;
const EXT_COUNT: usize = 5;
const TRAMP_PAGES: usize = (HOOK_COUNT + EXT_COUNT + 1 + SLOTS_PER_PAGE - 1) / SLOTS_PER_PAGE;
const PROT_ALL: c_int = sys::SCE_KERNEL_PROT_CPU_ALL;
const PROT_RX: c_int = sys::SCE_KERNEL_PROT_CPU_READ | sys::SCE_KERNEL_PROT_CPU_EXEC;

const _: () = {
    assert!(PAGE % TRAMP_SIZE == 0 && SLOTS_PER_PAGE <= 32);
    assert!(POOL_COPY_PAGES <= 64 && TRAMP_PAGES == 4);
    assert!(HOOK_COUNT == 96);
};

// ---- detour state (guarded by HOOK_LOCK) -------------------------------------

#[derive(Clone, Copy)]
struct Detour {
    target: *mut u8,
    /// Trampoline slot, or for a leading tail jump the libkernel destination.
    trampoline: *mut c_void,
    stolen: usize,
    original: [u8; MAX_STOLEN],
    installed: bool,
}

const DETOUR0: Detour = Detour {
    target: null_mut(),
    trampoline: null_mut(),
    stolen: 0,
    original: [0; MAX_STOLEN],
    installed: false,
};

struct State {
    hooks: [Detour; HOOK_COUNT],
    ext: [Detour; EXT_COUNT],
    loader: Detour,
    ext_coverage_safe: bool,
    tramp: Tramps,
}

/// Trampoline slot bitmap and the last protection applied per page.
struct Tramps {
    used: [u32; TRAMP_PAGES],
    prot: [c_int; TRAMP_PAGES],
}

static STATE: SyncCell<State> = SyncCell::new(State {
    hooks: [DETOUR0; HOOK_COUNT],
    ext: [DETOUR0; EXT_COUNT],
    loader: DETOUR0,
    ext_coverage_safe: false,
    tramp: Tramps {
        used: [0; TRAMP_PAGES],
        prot: [0; TRAMP_PAGES],
    },
});
static HOOK_LOCK: SpinLock = SpinLock::new();
static INSTALLED: AtomicU32 = AtomicU32::new(0);
static ORIGINAL_LOAD_START_MODULE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

#[repr(C, align(16384))]
struct Pages<const N: usize>([[u8; PAGE]; N]);

static TRAMPOLINES: SyncCell<Pages<TRAMP_PAGES>> = SyncCell::new(Pages([[0; PAGE]; TRAMP_PAGES]));
static POOL_COPY: SyncCell<Pages<POOL_COPY_PAGES>> =
    SyncCell::new(Pages([[0; PAGE]; POOL_COPY_PAGES]));
static POOL_COPY_USED: AtomicU64 = AtomicU64::new(0);

// ---- hook tables -------------------------------------------------------------

// `_emul` targets defined in other rt modules; taken by address only.
// Detour targets retain the C ABI; take their Rust definitions by address.
use super::equeue::{
    apr_equeue_overlay_set_hook_availability, apr_equeue_overlay_shutdown,
    sceAgcDriverAddEqEvent_emul, sceKernelAddAmprEvent_emul, sceKernelAddAmprSystemEvent_emul,
    sceKernelAddFileEvent_emul, sceKernelAddHRTimerEvent_emul, sceKernelAddReadEvent_emul,
    sceKernelAddTimerEvent_emul, sceKernelAddUserEventEdge_emul, sceKernelAddUserEvent_emul,
    sceKernelAddWriteEvent_emul, sceKernelCreateEqueue_emul, sceKernelDeleteAmprEvent_emul,
    sceKernelDeleteAmprSystemEvent_emul, sceKernelDeleteEqueue_emul, sceKernelWaitEqueue_emul,
    sceVideoOutAddFlipEvent_emul, sceVideoOutAddOutputModeEvent_emul,
    sceVideoOutAddPreVblankStartEvent_emul, sceVideoOutAddVblankEvent_emul,
};
use super::index::{
    posix_access_emul, posix_lstat_emul, posix_open_emul, posix_rename_emul, posix_stat_emul,
    posix_unlink_emul, sceKernelCheckReachability_emul, sceKernelOpen_emul, sceKernelStat_emul,
    underscore_open_emul, underscore_openat_emul,
};
use super::pack::zstd_libc::{
    posix_fcntl_emul, sceKernelFcntl_emul, underscore_close_emul, underscore_fcntl_emul,
    underscore_fstat_emul, underscore_getdirentries_emul, underscore_read_emul,
    underscore_readv_emul,
};
use super::pack::{
    posix_close_emul, posix_fstat_emul, posix_getdents_emul, posix_getdirentries_emul,
    posix_lseek_emul, posix_pread_emul, posix_preadv_emul, posix_read_emul, posix_readv_emul,
    sceKernelClose_emul, sceKernelFstat_emul, sceKernelGetdents_emul, sceKernelGetdirentries_emul,
    sceKernelLseek_emul, sceKernelPread_emul, sceKernelPreadv_emul, sceKernelRead_emul,
    sceKernelReadv_emul,
};
use super::services::{
    sceKernelAprGetFileSize_emul, sceKernelAprGetFileStat_emul,
    sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul,
    sceKernelAprResolveFilepathsToIdsAndFileSizes_emul,
    sceKernelAprResolveFilepathsToIdsForEach_emul, sceKernelAprResolveFilepathsToIds_emul,
    sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul,
    sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul,
    sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul,
    sceKernelAprResolveFilepathsWithPrefixToIds_emul, sceKernelAprSubmitCommandBufferAndGetId_emul,
    sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul,
    sceKernelAprSubmitCommandBufferAndGetResult_emul, sceKernelAprSubmitCommandBuffer_TEST_emul,
    sceKernelAprSubmitCommandBuffer_emul, sceKernelAprWaitCommandBuffer_emul,
    sceKernelWaitCommandBufferCompletion_emul,
};

struct HookSpec {
    symbol: &'static core::ffi::CStr,
    replacement: *mut c_void,
    mandatory: bool,
}
struct Table<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for Table<T, N> {}

macro_rules! specs {
    ($($(#[$a:meta])* $sym:literal => $f:path, $m:expr;)*) => {
        [$($(#[$a])* HookSpec { symbol: $sym, replacement: $f as *mut c_void, mandatory: $m },)*]
    };
}

const M: bool = true;
const O: bool = false;
use super::amm as a;

/// `g_hooks`: order is `AmprLibkernelHookId`.
static HOOKS: Table<HookSpec, HOOK_COUNT> = Table(specs![
    c"open" => posix_open_emul, M;
    c"stat" => posix_stat_emul, M;
    c"sceKernelCheckReachability" => sceKernelCheckReachability_emul, M;
    c"unlink" => posix_unlink_emul, M;
    c"rename" => posix_rename_emul, M;
    c"sceKernelMprotect" => sceKernelMprotect_emul, M;
    c"sceKernelMtypeprotect" => sceKernelMtypeprotect_emul, M;
    c"sceKernelMapFlexibleMemory" => sceKernelMapFlexibleMemory_emul, M;
    c"sceKernelMapDirectMemory" => sceKernelMapDirectMemory_emul, M;
    c"sceKernelMapDirectMemory2" => sceKernelMapDirectMemory2_emul, M;
    c"sceKernelBatchMap" => sceKernelBatchMap_emul, M;
    c"sceKernelBatchMap2" => sceKernelBatchMap2_emul, M;
    c"sceKernelJitMapSharedMemory" => sceKernelJitMapSharedMemory_emul, O;
    c"sceKernelMemoryPoolBatch" => sceKernelMemoryPoolBatch_emul, M;
    c"sceKernelMemoryPoolCommit" => sceKernelMemoryPoolCommit_emul, M;
    c"sceKernelMapNamedFlexibleMemory" => sceKernelMapNamedFlexibleMemory_emul, M;
    c"sceKernelMapNamedDirectMemory" => sceKernelMapNamedDirectMemory_emul, M;
    c"sceKernelAprResolveFilepathsToIds" => sceKernelAprResolveFilepathsToIds_emul, M;
    c"sceKernelAprResolveFilepathsToIdsAndFileSizes" => sceKernelAprResolveFilepathsToIdsAndFileSizes_emul, M;
    c"sceKernelAprResolveFilepathsWithPrefixToIds" => sceKernelAprResolveFilepathsWithPrefixToIds_emul, M;
    c"sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes" => sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul, M;
    c"sceKernelAprResolveFilepathsToIdsForEach" => sceKernelAprResolveFilepathsToIdsForEach_emul, M;
    c"sceKernelAprResolveFilepathsToIdsAndFileSizesForEach" => sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul, M;
    c"sceKernelAprResolveFilepathsWithPrefixToIdsForEach" => sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul, M;
    c"sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach" => sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul, M;
    c"sceKernelAprGetFileSize" => sceKernelAprGetFileSize_emul, M;
    c"sceKernelAprGetFileStat" => sceKernelAprGetFileStat_emul, M;
    c"sceKernelAprSubmitCommandBuffer" => sceKernelAprSubmitCommandBuffer_emul, M;
    c"sceKernelAprSubmitCommandBuffer_TEST" => sceKernelAprSubmitCommandBuffer_TEST_emul, M;
    c"sceKernelAprSubmitCommandBufferAndGetResult" => sceKernelAprSubmitCommandBufferAndGetResult_emul, M;
    c"sceKernelAprSubmitCommandBufferAndGetResult_TEST" => sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul, M;
    c"sceKernelAprSubmitCommandBufferAndGetId" => sceKernelAprSubmitCommandBufferAndGetId_emul, M;
    c"sceKernelAprWaitCommandBuffer" => sceKernelAprWaitCommandBuffer_emul, M;
    c"sceKernelWaitCommandBufferCompletion" => sceKernelWaitCommandBufferCompletion_emul, M;
    c"sceKernelGetDirectMemorySize" => a::sceKernelGetDirectMemorySize_emul, M;
    c"sceKernelAvailableDirectMemorySize" => a::sceKernelAvailableDirectMemorySize_emul, M;
    c"sceKernelWriteMapCommand" => a::sceKernelWriteMapCommand_emul, M;
    c"sceKernelWriteMapCommand2" => a::sceKernelWriteMapCommand2_emul, M;
    c"sceKernelWriteMapWithGpuMaskIdCommand" => a::sceKernelWriteMapWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteMapDirectCommand" => a::sceKernelWriteMapDirectCommand_emul, M;
    c"sceKernelWriteMapDirectWithGpuMaskIdCommand" => a::sceKernelWriteMapDirectWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteRemapCommand" => a::sceKernelWriteRemapCommand_emul, M;
    c"sceKernelWriteRemapWithGpuMaskIdCommand" => a::sceKernelWriteRemapWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteMultiMapCommand" => a::sceKernelWriteMultiMapCommand_emul, M;
    c"sceKernelWriteMultiMapWithGpuMaskIdCommand" => a::sceKernelWriteMultiMapWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteModifyProtectCommand" => a::sceKernelWriteModifyProtectCommand_emul, M;
    c"sceKernelWriteModifyProtectWithGpuMaskIdCommand" => a::sceKernelWriteModifyProtectWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteModifyMtypeProtectCommand" => a::sceKernelWriteModifyMtypeProtectCommand_emul, M;
    c"sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand" => a::sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand_emul, M;
    c"sceKernelWriteRemapIntoPrtCommand" => a::sceKernelWriteRemapIntoPrtCommand_emul, O;
    c"sceKernelCreateEqueue" => sceKernelCreateEqueue_emul, O;
    c"sceKernelWaitEqueue" => sceKernelWaitEqueue_emul, O;
    c"sceKernelDeleteEqueue" => sceKernelDeleteEqueue_emul, O;
    c"sceKernelAddAmprEvent" => sceKernelAddAmprEvent_emul, O;
    c"sceKernelDeleteAmprEvent" => sceKernelDeleteAmprEvent_emul, O;
    c"sceKernelAddTimerEvent" => sceKernelAddTimerEvent_emul, O;
    c"sceKernelAddReadEvent" => sceKernelAddReadEvent_emul, O;
    c"sceKernelAddWriteEvent" => sceKernelAddWriteEvent_emul, O;
    c"sceKernelAddFileEvent" => sceKernelAddFileEvent_emul, O;
    c"sceKernelAddUserEvent" => sceKernelAddUserEvent_emul, O;
    c"sceKernelAddUserEventEdge" => sceKernelAddUserEventEdge_emul, O;
    c"sceKernelAddHRTimerEvent" => sceKernelAddHRTimerEvent_emul, O;
    c"sceKernelAddAmprSystemEvent" => sceKernelAddAmprSystemEvent_emul, O;
    c"sceKernelDeleteAmprSystemEvent" => sceKernelDeleteAmprSystemEvent_emul, O;
    c"sceKernelClose" => sceKernelClose_emul, M;
    c"close" => posix_close_emul, M;
    c"fstat" => posix_fstat_emul, M;
    c"lseek" => posix_lseek_emul, M;
    c"getdents" => posix_getdents_emul, M;
    c"getdirentries" => posix_getdirentries_emul, M;
    // Ordinary reads of virtual pack fds (rt/pack/fd_read.rs); physical fds call
    // the original. Optional: a missing symbol leaves virtual fds AIO-only.
    // The sce variants call the syscall wrappers directly, not `read`.
    c"read" => posix_read_emul, O;
    c"pread" => posix_pread_emul, O;
    c"readv" => posix_readv_emul, O;
    c"preadv" => posix_preadv_emul, O;
    c"sceKernelRead" => sceKernelRead_emul, O;
    c"sceKernelPread" => sceKernelPread_emul, O;
    c"sceKernelReadv" => sceKernelReadv_emul, O;
    c"sceKernelPreadv" => sceKernelPreadv_emul, O;
    // zstd: packed files have no physical copy, so the sceKernel* file calls
    // run the libc hooks above and return SCE errors. Optional.
    c"sceKernelOpen" => sceKernelOpen_emul, O;
    c"sceKernelStat" => sceKernelStat_emul, O;
    c"sceKernelFstat" => sceKernelFstat_emul, O;
    c"sceKernelLseek" => sceKernelLseek_emul, O;
    c"sceKernelGetdents" => sceKernelGetdents_emul, O;
    c"sceKernelGetdirentries" => sceKernelGetdirentries_emul, O;
    // zstd: libkernel's internal entry points (libc's fopen/fread/opendir).
    c"_open" => underscore_open_emul, O;
    c"_openat" => underscore_openat_emul, O;
    c"_read" => underscore_read_emul, O;
    c"_readv" => underscore_readv_emul, O;
    c"_close" => underscore_close_emul, O;
    c"_fstat" => underscore_fstat_emul, O;
    c"_getdirentries" => underscore_getdirentries_emul, O;
    c"access" => posix_access_emul, O;
    c"lstat" => posix_lstat_emul, O;
    c"fcntl" => posix_fcntl_emul, O;
    c"_fcntl" => underscore_fcntl_emul, O;
    c"sceKernelFcntl" => sceKernelFcntl_emul, O;
]);

/// `g_externalEqueueHooks`: order is `AmprExternalEqueueHookId`.
static EXT_HOOKS: Table<HookSpec, EXT_COUNT> = Table(specs![
    c"sceAgcDriverAddEqEvent" => sceAgcDriverAddEqEvent_emul, O;
    c"sceVideoOutAddFlipEvent" => sceVideoOutAddFlipEvent_emul, O;
    c"sceVideoOutAddVblankEvent" => sceVideoOutAddVblankEvent_emul, O;
    c"sceVideoOutAddPreVblankStartEvent" => sceVideoOutAddPreVblankStartEvent_emul, O;
    c"sceVideoOutAddOutputModeEvent" => sceVideoOutAddOutputModeEvent_emul, O;
]);

macro_rules! ptrs {
    ($($e:expr),* $(,)?) => { [$($e as *mut c_void),*] };
}
const NUL: *mut c_void = null_mut();

/// `AMPR_LIBKERNEL_SDK_FALLBACKS`: SDK import used while a hook is not installed.
/// Ids past the shared 78 have no SDK fallback. The zstd sceKernel* file
/// wrappers call libc originals; internal-entry hooks resolve their originals.
const FALLBACK: [*mut c_void; HOOK_COUNT] = {
    let shared = FALLBACK_SHARED;
    let mut out = [NUL; HOOK_COUNT];
    let mut i = 0;
    while i < shared.len() {
        out[i] = shared[i];
        i += 1;
    }
    out
};

const FALLBACK_SHARED: [*mut c_void; 78] = {
    use super::sys::*;
    ptrs![
        NUL,
        NUL,
        sceKernelCheckReachability,
        NUL,
        NUL,
        sceKernelMprotect,
        sceKernelMtypeprotect,
        sceKernelMapFlexibleMemory,
        sceKernelMapDirectMemory,
        sceKernelMapDirectMemory2,
        sceKernelBatchMap,
        sceKernelBatchMap2,
        NUL,
        sceKernelMemoryPoolBatch,
        sceKernelMemoryPoolCommit,
        sceKernelMapNamedFlexibleMemory,
        sceKernelMapNamedDirectMemory,
        sceKernelAprResolveFilepathsToIds,
        sceKernelAprResolveFilepathsToIdsAndFileSizes,
        sceKernelAprResolveFilepathsWithPrefixToIds,
        sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes,
        sceKernelAprResolveFilepathsToIdsForEach,
        sceKernelAprResolveFilepathsToIdsAndFileSizesForEach,
        sceKernelAprResolveFilepathsWithPrefixToIdsForEach,
        sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach,
        sceKernelAprGetFileSize,
        sceKernelAprGetFileStat,
        sceKernelAprSubmitCommandBuffer,
        sceKernelAprSubmitCommandBuffer_TEST,
        sceKernelAprSubmitCommandBufferAndGetResult,
        sceKernelAprSubmitCommandBufferAndGetResult_TEST,
        sceKernelAprSubmitCommandBufferAndGetId,
        sceKernelAprWaitCommandBuffer,
        sceKernelWaitCommandBufferCompletion,
        sceKernelGetDirectMemorySize,
        sceKernelAvailableDirectMemorySize,
        sceKernelWriteMapCommand,
        sceKernelWriteMapCommand2,
        sceKernelWriteMapWithGpuMaskIdCommand,
        sceKernelWriteMapDirectCommand,
        sceKernelWriteMapDirectWithGpuMaskIdCommand,
        sceKernelWriteRemapCommand,
        sceKernelWriteRemapWithGpuMaskIdCommand,
        sceKernelWriteMultiMapCommand,
        sceKernelWriteMultiMapWithGpuMaskIdCommand,
        sceKernelWriteModifyProtectCommand,
        sceKernelWriteModifyProtectWithGpuMaskIdCommand,
        sceKernelWriteModifyMtypeProtectCommand,
        sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand,
        NUL,
        sceKernelCreateEqueue,
        sceKernelWaitEqueue,
        sceKernelDeleteEqueue,
        sceKernelAddAmprEvent,
        sceKernelDeleteAmprEvent,
        sceKernelAddTimerEvent,
        sceKernelAddReadEvent,
        sceKernelAddWriteEvent,
        sceKernelAddFileEvent,
        sceKernelAddUserEvent,
        sceKernelAddUserEventEdge,
        sceKernelAddHRTimerEvent,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        // read, pread, readv, preadv and their sceKernel* forms: no SDK
        // import; pack/libkernel.rs resolves them dynamically while not detoured.
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
        NUL,
    ]
};

static SDK_FALLBACK: Table<*mut c_void, HOOK_COUNT> = Table(FALLBACK);

/// Original libkernel entry per hook id; read via `sys::kernel_slot`.
#[no_mangle]
pub static mut g_amprOriginalLibkernelById: [*mut c_void; HOOK_COUNT] = FALLBACK;
/// Original external equeue producer per `AmprExternalEqueueHookId`.
#[no_mangle]
pub static mut g_amprOriginalExternalEqueueById: [*mut c_void; EXT_COUNT] = [NUL; EXT_COUNT];

/// `store_original_slot`: release store into a pointer slot.
unsafe fn store_slot(slot: *mut *mut c_void, v: *mut c_void) {
    if !slot.is_null() {
        unsafe { AtomicPtr::from_ptr(slot) }.store(v, Release);
    }
}

fn lib_slot(i: usize) -> *mut *mut c_void {
    unsafe { addr_of_mut!(g_amprOriginalLibkernelById[i]) }
}

fn ext_slot(i: usize) -> *mut *mut c_void {
    unsafe { addr_of_mut!(g_amprOriginalExternalEqueueById[i]) }
}

// ---- byte helpers ------------------------------------------------------------

// Volatile byte access: these touch live libkernel text and trampolines.
unsafe fn copy_bytes(dst: *mut u8, src: *const u8, len: usize) {
    for i in 0..len {
        unsafe { write_volatile(dst.add(i), read_volatile(src.add(i))) };
    }
}

unsafe fn set_bytes(dst: *mut u8, v: u8, len: usize) {
    for i in 0..len {
        unsafe { write_volatile(dst.add(i), v) };
    }
}

unsafe fn store_le(dst: *mut u8, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        unsafe { write_volatile(dst.add(i), *b) };
    }
}

unsafe fn load_i32_le(src: *const u8) -> i32 {
    let mut b = [0u8; 4];
    for (i, v) in b.iter_mut().enumerate() {
        *v = unsafe { read_volatile(src.add(i)) };
    }
    i32::from_le_bytes(b)
}

unsafe fn at(p: *const u8, i: usize) -> u8 {
    unsafe { read_volatile(p.add(i)) }
}

/// `jmp qword [rip+0]; dq target` (14 bytes).
unsafe fn write_abs_jump(dst: *mut u8, target: usize) {
    unsafe {
        store_le(dst, &[0xFF, 0x25, 0, 0, 0, 0]);
        store_le(dst.add(6), &(target as u64).to_le_bytes());
    }
}

fn rel_jump_disp(dst: *const u8, target: *const c_void) -> Option<i32> {
    let d = (target as usize as i64).wrapping_sub(dst as usize as i64 + 5);
    i32::try_from(d).ok()
}

fn page_floor(v: usize) -> usize {
    v & !(PAGE - 1)
}

fn page_ceil(v: usize) -> usize {
    (v + PAGE - 1) & !(PAGE - 1)
}

/// sceKernelMprotect through the original slot (the detour may be ours).
unsafe fn real_mprotect(addr: *const c_void, len: usize, prot: c_int) -> c_int {
    unsafe { sys::real_mprotect(addr, len, prot) }
}

unsafe fn make_code_writable(addr: *mut u8, len: usize) -> bool {
    let b = page_floor(addr as usize);
    let e = page_ceil(addr as usize + len);
    unsafe { real_mprotect(b as *const c_void, e - b, PROT_ALL) == 0 }
}

unsafe fn restore_code_protection(addr: *mut u8, len: usize) {
    let b = page_floor(addr as usize);
    let e = page_ceil(addr as usize + len);
    unsafe { real_mprotect(b as *const c_void, e - b, PROT_RX) };
}

fn tramp_page(i: usize) -> *mut u8 {
    unsafe { addr_of_mut!((*TRAMPOLINES.get()).0[i]) }.cast()
}

fn tramp_page_index(p: *const c_void) -> Option<usize> {
    let p = p as usize;
    (0..TRAMP_PAGES).find(|&i| {
        let b = tramp_page(i) as usize;
        p >= b && p < b + PAGE
    })
}

unsafe fn protect_tramp_page(t: &mut Tramps, i: usize, prot: c_int) -> bool {
    if t.prot[i] == prot {
        return true;
    }
    if unsafe { real_mprotect(tramp_page(i) as *const c_void, PAGE, prot) } != 0 {
        return false;
    }
    t.prot[i] = prot;
    true
}

unsafe fn allocate_trampoline(t: &mut Tramps) -> *mut u8 {
    for i in 0..TRAMP_PAGES {
        let used = t.used[i];
        if used == u32::MAX {
            continue;
        }
        for slot in 0..SLOTS_PER_PAGE {
            let bit = 1u32 << slot;
            if used & bit != 0 {
                continue;
            }
            if !unsafe { protect_tramp_page(t, i, PROT_ALL) } {
                return null_mut();
            }
            t.used[i] = used | bit;
            let t = unsafe { tramp_page(i).add(slot * TRAMP_SIZE) };
            unsafe { set_bytes(t, 0, TRAMP_SIZE) };
            return t;
        }
    }
    null_mut()
}

unsafe fn make_trampoline_executable(t: &mut Tramps, p: *mut u8) -> bool {
    match tramp_page_index(p as *const c_void) {
        Some(i) if !p.is_null() => unsafe { protect_tramp_page(t, i, PROT_RX) },
        _ => false,
    }
}

unsafe fn release_trampoline(t: &mut Tramps, p: *mut c_void) {
    if p.is_null() {
        return;
    }
    if let Some(i) = tramp_page_index(p) {
        let slot = (p as usize - tramp_page(i) as usize) / TRAMP_SIZE;
        t.used[i] &= !(1u32 << slot);
        unsafe { protect_tramp_page(t, i, PROT_RX) };
    }
}

// ---- trampolines and relocation ------------------------------------------------

/// Append-only writer over a trampoline slot (`dst`, `dstLen`, `dstCap`).
struct Buf {
    p: *mut u8,
    len: usize,
}

impl Buf {
    fn cur(&self) -> *mut u8 {
        unsafe { self.p.add(self.len) }
    }
    fn fits(&self, n: usize) -> bool {
        self.len + n <= TRAMP_SIZE
    }
    unsafe fn bytes(&mut self, src: *const u8, n: usize) -> bool {
        if !self.fits(n) {
            return false;
        }
        unsafe { copy_bytes(self.cur(), src, n) };
        self.len += n;
        true
    }
    unsafe fn raw(&mut self, b: &[u8]) {
        unsafe { store_le(self.cur(), b) };
        self.len += b.len();
    }
    unsafe fn push_reg(&mut self, reg: u8) -> bool {
        if reg >= 16 || !self.fits(2) {
            return false;
        }
        if reg >= 8 {
            unsafe { self.raw(&[0x41]) };
        }
        unsafe { self.raw(&[0x50 + (reg & 7)]) };
        true
    }
    unsafe fn pop_reg(&mut self, reg: u8) -> bool {
        if reg >= 16 || !self.fits(2) {
            return false;
        }
        if reg >= 8 {
            unsafe { self.raw(&[0x41]) };
        }
        unsafe { self.raw(&[0x58 + (reg & 7)]) };
        true
    }
    unsafe fn abs_jump(&mut self, target: usize) -> bool {
        if !self.fits(JUMP_SIZE) {
            return false;
        }
        unsafe { write_abs_jump(self.cur(), target) };
        self.len += JUMP_SIZE;
        true
    }
    /// `call qword [rip+2]; jmp +8; dq target` (16 bytes).
    unsafe fn abs_call(&mut self, target: usize) -> bool {
        if !self.fits(16) {
            return false;
        }
        unsafe {
            self.raw(&[0xFF, 0x15, 0x02, 0, 0, 0, 0xEB, 0x08]);
            self.raw(&(target as u64).to_le_bytes());
        }
        true
    }
    /// Inverted short Jcc over a 14-byte absolute jump (16 bytes).
    unsafe fn abs_cond_jump(&mut self, opcode: u8, target: usize) -> bool {
        if !self.fits(16) {
            return false;
        }
        unsafe {
            self.raw(&[opcode ^ 1, JUMP_SIZE as u8]);
            write_abs_jump(self.cur(), target);
        }
        self.len += JUMP_SIZE;
        true
    }
    /// `mov reg, imm64` (10 bytes).
    unsafe fn mov_reg_imm64(&mut self, reg: u8, v: usize) -> bool {
        if reg >= 16 || !self.fits(10) {
            return false;
        }
        unsafe {
            self.raw(&[0x48 | (reg >= 8) as u8, 0xB8 + (reg & 7)]);
            self.raw(&(v as u64).to_le_bytes());
        }
        true
    }
    /// push scratch; mov scratch, addr; `op` reg,[scratch]; pop scratch.
    /// `op` is 0x8B (mov reg,[m]) or 0x39 (cmp [m],reg); `need` is the required byte count.
    unsafe fn via_abs_ptr(&mut self, op: u8, need: usize, reg: u8, addr: usize) -> bool {
        if reg >= 16 || !self.fits(need) {
            return false;
        }
        let s: u8 = if reg == 11 { 10 } else { 11 };
        let sx = (s >= 8) as u8;
        unsafe {
            if s >= 8 {
                self.raw(&[0x41]);
            }
            self.raw(&[0x50 + (s & 7), 0x48 | sx, 0xB8 + (s & 7)]);
            self.raw(&(addr as u64).to_le_bytes());
            let rx: u8 = if reg >= 8 { 0x04 } else { 0 };
            self.raw(&[0x48 | rx | sx, op, ((reg & 7) << 3) | (s & 7)]);
            if s >= 8 {
                self.raw(&[0x41]);
            }
            self.raw(&[0x58 + (s & 7)]);
        }
        true
    }
}

fn window<'a>(p: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p, MAX_INSN_LEN) }
}

fn choose_low_scratch_reg(hs: &Hde64) -> u8 {
    let reg = hs.modrm_reg + if hs.rex_r != 0 { 8 } else { 0 };
    [3u8, 6, 7, 0, 1, 2]
        .into_iter()
        .find(|&c| c != reg)
        .unwrap_or(3)
}

unsafe fn clear_rex_b(insn: *mut u8, hs: &Hde64) -> bool {
    if insn.is_null() || hs.rex == 0 {
        return true;
    }
    for i in 0..usize::from(hs.len) {
        let b = unsafe { at(insn, i) };
        if b == hs.rex && (0x40..=0x4f).contains(&b) {
            unsafe { write_volatile(insn.add(i), b & 0xfe) };
            return true;
        }
    }
    false
}

fn rip_rel_changes_stack(hs: &Hde64) -> bool {
    // ff /2../6: call, jmp, push would see or skip the scratch push.
    hs.opcode == 0x8f || (hs.opcode == 0xff && (2..=6).contains(&(hs.modrm_reg & 7)))
}

fn rip_rel_uses_rsp(hs: &Hde64) -> bool {
    matches!(
        hs.meta,
        ampr_hook::META_RIP_REL_MOV_R64_PTR | ampr_hook::META_RIP_REL_CMP_PTR_R64
    ) && hs.operand_reg == 4
}

unsafe fn rip_rel_via_scratch(b: &mut Buf, src: *const u8, hs: &Hde64, abs: usize) -> bool {
    if src.is_null() || hs.disp_offset == 0 || rip_rel_changes_stack(hs) {
        return false;
    }
    let s = choose_low_scratch_reg(hs);
    if !b.fits(1 + 10 + usize::from(hs.len) + 1) {
        return false;
    }
    unsafe {
        if !b.push_reg(s) || !b.mov_reg_imm64(s, abs) {
            return false;
        }
        let copied = b.cur();
        if !b.bytes(src, usize::from(hs.len)) || !clear_rex_b(copied, hs) {
            return false;
        }
        let d = usize::from(hs.disp_offset);
        set_bytes(copied.add(d), 0, 4);
        write_volatile(
            copied.add(d - 1),
            0x80 | ((hs.modrm_reg & 7) << 3) | (s & 7),
        );
        b.pop_reg(s)
    }
}

/// `relocate_relative_instruction`: rel call/jmp/jcc become absolute forms.
unsafe fn relocate_relative(
    b: &mut Buf,
    src: *const u8,
    base: usize,
    ip: usize,
    hs: &Hde64,
    terminal: &mut bool,
    internal: &mut usize,
) -> bool {
    let Some(t) = ampr_hook::relative_target(window(src), ip, hs) else {
        return false;
    };
    if t >= base && t < base + MAX_STOLEN && (*internal == 0 || t < *internal) {
        *internal = t;
    }
    unsafe {
        match hs.meta {
            ampr_hook::META_REL_CALL => b.abs_call(t),
            ampr_hook::META_REL_JMP => {
                *terminal = true;
                b.abs_jump(t)
            }
            ampr_hook::META_REL_JCC => b.abs_cond_jump(hs.branch_opcode, t),
            _ => false,
        }
    }
}

/// `relocate_instruction`: copy one stolen instruction into the trampoline.
unsafe fn relocate(
    b: &mut Buf,
    src: *const u8,
    base: usize,
    ip: usize,
    hs: &Hde64,
    terminal: &mut bool,
    internal: &mut usize,
) -> bool {
    // syscall must stay in libkernel text.
    if hs.opcode == 0x0f && hs.opcode2 == 0x05 {
        return false;
    }
    if hs.flags & F_RELATIVE != 0 {
        return unsafe { relocate_relative(b, src, base, ip, hs, terminal, internal) };
    }
    let rip = hs.flags & F_RIP_RELATIVE != 0;
    let mut abs = 0usize;
    if rip {
        let Some(a) = ampr_hook::rip_absolute(window(src), ip, hs) else {
            return false;
        };
        abs = a;
        if rip_rel_uses_rsp(hs) {
            return false;
        }
        unsafe {
            match hs.meta {
                ampr_hook::META_RIP_REL_LEA64 => return b.mov_reg_imm64(hs.operand_reg, abs),
                ampr_hook::META_RIP_REL_MOV_R64_PTR => {
                    return b.via_abs_ptr(0x8B, 17, hs.operand_reg, abs)
                }
                ampr_hook::META_RIP_REL_CMP_PTR_R64 => {
                    return b.via_abs_ptr(0x39, 18, hs.operand_reg, abs)
                }
                _ => {}
            }
        }
    }
    let out = b.len;
    let dst_ip = b.cur() as usize;
    if !unsafe { b.bytes(src, usize::from(hs.len)) } {
        return false;
    }
    if !rip {
        return true;
    }
    let disp = (abs as i64).wrapping_sub((dst_ip + usize::from(hs.len)) as i64);
    match i32::try_from(disp) {
        Ok(d) => {
            unsafe { store_le(b.p.add(out + usize::from(hs.disp_offset)), &d.to_le_bytes()) };
            true
        }
        Err(_) => {
            b.len = out;
            unsafe { rip_rel_via_scratch(b, src, hs, abs) }
        }
    }
}

// ---- install / uninstall -------------------------------------------------------

enum Fixed {
    NotMatched,
    Installed,
    Failed,
}

fn publish(d: &mut Detour, target: *mut u8, tramp: *mut c_void, stolen: usize) {
    *d = Detour {
        target,
        trampoline: tramp,
        stolen,
        installed: true,
        ..*d
    };
}

/// `mov rax, imm32; mov r10, rcx; syscall`: copy the 10 bytes before the
/// syscall and patch a 5-byte rel jmp, so syscall runs in libkernel text.
unsafe fn try_syscall_wrapper(
    t: &mut Tramps,
    d: &mut Detour,
    src: *mut u8,
    repl: *mut c_void,
    tramp: *mut u8,
    slot: *mut *mut c_void,
) -> Fixed {
    let s = |i| unsafe { at(src, i) };
    let matched = s(0) == 0x48
        && s(1) == 0xC7
        && s(2) == 0xC0
        && s(7) == 0x49
        && s(8) == 0x89
        && s(9) == 0xCA
        && s(10) == 0x0F
        && s(11) == 0x05;
    if !matched {
        return Fixed::NotMatched;
    }
    let Some(disp) = rel_jump_disp(src, repl) else {
        return Fixed::Failed;
    };
    let mut b = Buf { p: tramp, len: 0 };
    unsafe {
        if !b.bytes(src, 10) || !b.abs_jump(src as usize + 10) {
            return Fixed::Failed;
        }
        copy_bytes(d.original.as_mut_ptr(), src, 5);
        if !make_trampoline_executable(t, tramp) {
            return Fixed::Failed;
        }
        store_slot(slot, tramp.cast());
        write_volatile(src, 0xE9);
        store_le(src.add(1), &disp.to_le_bytes());
        publish(d, src, tramp.cast(), 5);
    }
    Fixed::Installed
}

/// `test ecx,ecx; jcc +6; mov eax, imm32; ret; xor ecx,ecx; jmp body`.
unsafe fn try_loader_status_wrapper(
    t: &mut Tramps,
    d: &mut Detour,
    src: *mut u8,
    repl: *mut c_void,
    tramp: *mut u8,
    slot: *mut *mut c_void,
) -> Fixed {
    let s = |i| unsafe { at(src, i) };
    let base = src as isize;
    let jcc_target = (base + 4 + s(3) as i8 as isize) as usize;
    let ok = s(0) == 0x85
        && s(1) == 0xC9
        && (0x70..=0x7F).contains(&s(2))
        && jcc_target == src as usize + 10
        && s(4) == 0xB8
        && s(9) == 0xC3
        && ((s(10) == 0x31 || s(10) == 0x33) && s(11) == 0xC9);
    if !ok {
        return Fixed::NotMatched;
    }
    let (stolen, body) = match s(12) {
        0xEB => (14usize, (base + 14 + s(13) as i8 as isize) as usize),
        0xE9 => (
            17usize,
            (base + 17 + unsafe { load_i32_le(src.add(13)) } as isize) as usize,
        ),
        _ => return Fixed::NotMatched,
    };
    let mut b = Buf { p: tramp, len: 0 };
    unsafe {
        if !b.bytes(src, 12) || !b.abs_jump(body) {
            return Fixed::Failed;
        }
        copy_bytes(d.original.as_mut_ptr(), src, stolen);
        if !make_trampoline_executable(t, tramp) {
            return Fixed::Failed;
        }
        store_slot(slot, tramp.cast());
        write_abs_jump(src, repl as usize);
        set_bytes(src.add(JUMP_SIZE), 0x90, stolen - JUMP_SIZE);
        publish(d, src, tramp.cast(), stolen);
    }
    Fixed::Installed
}

/// `install_inline_detour`.
unsafe fn install(
    t: &mut Tramps,
    slot: *mut *mut c_void,
    d: &mut Detour,
    target: *mut c_void,
    repl: *mut c_void,
) -> bool {
    if d.installed {
        unsafe { store_slot(slot, d.trampoline) };
        return true;
    }
    if slot.is_null() || target.is_null() || repl.is_null() || target == repl {
        return false;
    }
    let tramp = unsafe { allocate_trampoline(t) };
    if tramp.is_null() {
        return false;
    }
    let src = target.cast::<u8>();
    if !unsafe { make_code_writable(src, MAX_STOLEN) } {
        unsafe { release_trampoline(t, tramp.cast()) };
        return false;
    }
    let ok = unsafe { install_writable(t, slot, d, src, repl, tramp) };
    unsafe {
        restore_code_protection(src, MAX_STOLEN);
        if !ok {
            release_trampoline(t, tramp.cast());
        }
    }
    ok
}

/// Body of `install_inline_detour` once the target is writable. On a
/// leading tail jump it releases the trampoline itself (and returns true).
unsafe fn install_writable(
    t: &mut Tramps,
    slot: *mut *mut c_void,
    d: &mut Detour,
    src: *mut u8,
    repl: *mut c_void,
    tramp: *mut u8,
) -> bool {
    match unsafe { try_syscall_wrapper(t, d, src, repl, tramp, slot) } {
        Fixed::Installed => return true,
        Fixed::Failed => return false,
        Fixed::NotMatched => {}
    }
    match unsafe { try_loader_status_wrapper(t, d, src, repl, tramp, slot) } {
        Fixed::Installed => return true,
        Fixed::Failed => return false,
        Fixed::NotMatched => {}
    }

    let base = src as usize;
    let mut b = Buf { p: tramp, len: 0 };
    let (mut stolen, mut terminal, mut internal, mut tail) = (0usize, false, 0usize, 0usize);
    while stolen < JUMP_SIZE && stolen < MAX_STOLEN {
        let p = unsafe { src.add(stolen) };
        let hs = ampr_hook::decode(window(p));
        let len = usize::from(hs.len);
        if len == 0 || hs.flags & F_ERROR != 0 || stolen + len > MAX_STOLEN {
            return false;
        }
        if !terminal {
            if stolen == 0 && hs.meta == ampr_hook::META_REL_JMP {
                if let Some(t) = ampr_hook::relative_target(window(src), base, &hs) {
                    if t < base || t >= base + MAX_STOLEN {
                        tail = t;
                    }
                }
            }
            if !unsafe {
                relocate(
                    &mut b,
                    p,
                    base,
                    p as usize,
                    &hs,
                    &mut terminal,
                    &mut internal,
                )
            } {
                return false;
            }
        }
        stolen += len;
    }
    if stolen < JUMP_SIZE || (internal != 0 && internal < base + stolen) {
        return false;
    }

    unsafe {
        if tail != 0 {
            // Exported POSIX thunks tail-jump into private syscall wrappers:
            // publish that libkernel destination as the original.
            copy_bytes(d.original.as_mut_ptr(), src, stolen);
            release_trampoline(t, tramp.cast());
            store_slot(slot, tail as *mut c_void);
            write_abs_jump(src, repl as usize);
            set_bytes(src.add(JUMP_SIZE), 0x90, stolen - JUMP_SIZE);
            publish(d, src, tail as *mut c_void, stolen);
            return true;
        }
        if !terminal && !b.abs_jump(base + stolen) {
            return false;
        }
        copy_bytes(d.original.as_mut_ptr(), src, stolen);
        if !make_trampoline_executable(t, tramp) {
            return false;
        }
        store_slot(slot, tramp.cast());
        write_abs_jump(src, repl as usize);
        set_bytes(src.add(JUMP_SIZE), 0x90, stolen - JUMP_SIZE);
        publish(d, src, tramp.cast(), stolen);
    }
    true
}

/// `uninstall_inline_detour`.
unsafe fn uninstall(t: &mut Tramps, d: &mut Detour) -> bool {
    if !d.installed {
        return true;
    }
    unsafe {
        if !make_code_writable(d.target, d.stolen) {
            return false;
        }
        copy_bytes(d.target, d.original.as_ptr(), d.stolen);
        restore_code_protection(d.target, d.stolen);
        release_trampoline(t, d.trampoline);
    }
    *d = DETOUR0;
    true
}

// ---- memory-protection _emul hooks ---------------------------------------------

/// `SceKernelBatchMapEntry` (sys/dmem.h).
#[repr(C)]
pub struct SceKernelBatchMapEntry {
    start: *mut c_void,
    offset: off_t,
    length: usize,
    protection: i8,
    ty: i8,
    pad1: i16,
    operation: c_int,
}

/// `SceKernelMemoryPoolBatchEntry` (sys/dmem.h). Every op that carries a
/// protection (commit, protect, typeProtect) keeps it at offset 24.
#[repr(C)]
pub struct SceKernelMemoryPoolBatchEntry {
    op: u32,
    flags: u32,
    addr: *mut c_void,
    len: usize,
    prot: u8,
    rest: [u8; 7],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SceKernelBatchMapEntry>() == 32);
    assert!(offset_of!(SceKernelBatchMapEntry, protection) == 24);
    assert!(offset_of!(SceKernelBatchMapEntry, operation) == 28);
    assert!(size_of::<SceKernelMemoryPoolBatchEntry>() == 32);
    assert!(offset_of!(SceKernelMemoryPoolBatchEntry, prot) == 24);
};

// SceKernelMapEntryOperation / SCE_KERNEL_MEMORY_POOL_OP_*.
const MAP_OP_MAP_DIRECT: c_int = 0;
const MAP_OP_PROTECT: c_int = 2;
const MAP_OP_MAP_FLEXIBLE: c_int = 3;
const MAP_OP_TYPE_PROTECT: c_int = 4;
const POOL_OP_COMMIT: u32 = 1;
const POOL_OP_PROTECT: u32 = 3;
const POOL_OP_TYPE_PROTECT: u32 = 4;

// AmprLibkernelHookId values not in sys::hook.
const ID_MAP_FLEXIBLE: usize = 7;
const ID_MAP_DIRECT: usize = 8;
const ID_MAP_DIRECT2: usize = 9;
const ID_BATCH_MAP: usize = 10;
const ID_BATCH_MAP2: usize = 11;
const ID_JIT_MAP_SHARED: usize = 12;
const ID_POOL_BATCH: usize = 13;
const ID_POOL_COMMIT: usize = 14;
const ID_MAP_NAMED_FLEXIBLE: usize = 15;
const ID_MAP_NAMED_DIRECT: usize = 16;

/// `adjusted_ampr_write_prot`.
fn adj(prot: c_int) -> c_int {
    super::amm::prot_with_cpu_rw(prot as u32 as u64) as c_int
}

/// Original slot as fn type `F`; the SDK fallback keeps it non-null.
unsafe fn orig<F: Copy>(id: usize) -> F {
    match unsafe { sys::kernel_slot::<F>(id) } {
        Some(f) => f,
        None => sys::abort(),
    }
}

type P = *mut *mut c_void;

pub unsafe extern "C" fn sceKernelMprotect_emul(
    addr: *const c_void,
    len: usize,
    prot: c_int,
) -> c_int {
    unsafe {
        orig::<unsafe extern "C" fn(*const c_void, usize, c_int) -> c_int>(id::sceKernelMprotect)(
            addr,
            len,
            adj(prot),
        )
    }
}

pub unsafe extern "C" fn sceKernelMtypeprotect_emul(
    addr: *const c_void,
    size: usize,
    ty: c_int,
    prot: c_int,
) -> c_int {
    type F = unsafe extern "C" fn(*const c_void, usize, c_int, c_int) -> c_int;
    unsafe { orig::<F>(id::sceKernelMtypeprotect)(addr, size, ty, adj(prot)) }
}

pub unsafe extern "C" fn sceKernelMapFlexibleMemory_emul(
    addr: P,
    len: usize,
    prot: c_int,
    flags: c_int,
) -> c_int {
    type F = unsafe extern "C" fn(P, usize, c_int, c_int) -> c_int;
    unsafe { orig::<F>(ID_MAP_FLEXIBLE)(addr, len, adj(prot), flags) }
}

pub unsafe extern "C" fn sceKernelMapDirectMemory_emul(
    addr: P,
    len: usize,
    prot: c_int,
    flags: c_int,
    start: off_t,
    max_page: usize,
) -> c_int {
    type F = unsafe extern "C" fn(P, usize, c_int, c_int, off_t, usize) -> c_int;
    unsafe { orig::<F>(ID_MAP_DIRECT)(addr, len, adj(prot), flags, start, max_page) }
}

pub unsafe extern "C" fn sceKernelMapDirectMemory2_emul(
    addr: P,
    len: usize,
    ty: c_int,
    prot: c_int,
    flags: c_int,
    start: off_t,
    max_page: usize,
) -> c_int {
    type F = unsafe extern "C" fn(P, usize, c_int, c_int, c_int, off_t, usize) -> c_int;
    unsafe { orig::<F>(ID_MAP_DIRECT2)(addr, len, ty, adj(prot), flags, start, max_page) }
}

/// `adjust_batch_map_entries_for_ampr_write` (in place).
unsafe fn adjust_batch_map(entries: *mut SceKernelBatchMapEntry, n: c_int) {
    if entries.is_null() || n <= 0 {
        return;
    }
    for i in 0..n as usize {
        let e = unsafe { &mut *entries.add(i) };
        if !matches!(
            e.operation,
            MAP_OP_MAP_DIRECT | MAP_OP_PROTECT | MAP_OP_MAP_FLEXIBLE | MAP_OP_TYPE_PROTECT
        ) {
            continue;
        }
        let prot = e.protection as u8;
        let a = adj(c_int::from(prot)) as u8;
        if a != prot {
            e.protection = a as i8;
        }
    }
}

pub unsafe extern "C" fn sceKernelBatchMap_emul(
    e: *mut SceKernelBatchMapEntry,
    n: c_int,
    out: *mut c_int,
) -> c_int {
    type F = unsafe extern "C" fn(*mut SceKernelBatchMapEntry, c_int, *mut c_int) -> c_int;
    unsafe {
        adjust_batch_map(e, n);
        orig::<F>(ID_BATCH_MAP)(e, n, out)
    }
}

pub unsafe extern "C" fn sceKernelBatchMap2_emul(
    e: *mut SceKernelBatchMapEntry,
    n: c_int,
    out: *mut c_int,
    flags: c_int,
) -> c_int {
    type F = unsafe extern "C" fn(*mut SceKernelBatchMapEntry, c_int, *mut c_int, c_int) -> c_int;
    unsafe {
        adjust_batch_map(e, n);
        orig::<F>(ID_BATCH_MAP2)(e, n, out, flags)
    }
}

pub unsafe extern "C" fn sceKernelJitMapSharedMemory_emul(
    fd: c_int,
    prot: c_int,
    start: P,
) -> c_int {
    type F = unsafe extern "C" fn(c_int, c_int, P) -> c_int;
    match unsafe { sys::kernel_slot::<F>(ID_JIT_MAP_SHARED) } {
        Some(f) => unsafe { f(fd, adj(prot), start) },
        None => sys::SCE_KERNEL_ERROR_ENOSYS,
    }
}

fn pool_entry_has_prot(e: &SceKernelMemoryPoolBatchEntry) -> bool {
    matches!(
        e.op,
        POOL_OP_COMMIT | POOL_OP_PROTECT | POOL_OP_TYPE_PROTECT
    )
}

/// Leases whole pages of the BSS scratch copy (`MemoryPoolBatchScratchLease`).
struct PoolLease {
    storage: *mut u8,
    pages: u64,
}

impl PoolLease {
    fn new(bytes: usize) -> Self {
        let count = bytes.div_ceil(PAGE);
        let base = if count == 64 {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };
        let mut spins = 0u32;
        loop {
            let occupied = POOL_COPY_USED.load(Relaxed);
            for first in 0..=(POOL_COPY_PAGES - count) {
                let mask = base << first;
                if occupied & mask != 0 {
                    continue;
                }
                if POOL_COPY_USED
                    .compare_exchange_weak(occupied, occupied | mask, Acquire, Relaxed)
                    .is_ok()
                {
                    let storage = unsafe { addr_of_mut!((*POOL_COPY.get()).0[first]) }.cast();
                    return Self {
                        storage,
                        pages: mask,
                    };
                }
                break;
            }
            spin_pause_or_yield(&mut spins);
        }
    }
}

impl Drop for PoolLease {
    fn drop(&mut self) {
        POOL_COPY_USED.fetch_and(!self.pages, Release);
    }
}

/// Adjusts a private copy so the caller's (possibly read-only) array is untouched.
pub unsafe extern "C" fn sceKernelMemoryPoolBatch_emul(
    entries: *const SceKernelMemoryPoolBatchEntry,
    n: c_int,
    index_out: *mut c_int,
    flags: c_int,
) -> c_int {
    type F = unsafe extern "C" fn(
        *const SceKernelMemoryPoolBatchEntry,
        c_int,
        *mut c_int,
        c_int,
    ) -> c_int;
    let call = |e| unsafe { orig::<F>(ID_POOL_BATCH)(e, n, index_out, flags) };
    if entries.is_null() || n <= 0 {
        return call(entries);
    }
    let needs = |e: &SceKernelMemoryPoolBatchEntry| {
        pool_entry_has_prot(e) && adj(c_int::from(e.prot)) as u8 != e.prot
    };
    let Some(first) = (0..n as usize).find(|&i| needs(unsafe { &*entries.add(i) })) else {
        return call(entries);
    };
    let bytes = n as usize * core::mem::size_of::<SceKernelMemoryPoolBatchEntry>();
    if bytes > POOL_COPY_CAP {
        return call(entries);
    }
    let lease = PoolLease::new(bytes);
    unsafe { copy_bytes(lease.storage, entries.cast(), bytes) };
    let copy = lease.storage.cast::<SceKernelMemoryPoolBatchEntry>();
    for i in first..n as usize {
        let e = unsafe { &mut *copy.add(i) };
        if pool_entry_has_prot(e) {
            e.prot = adj(c_int::from(e.prot)) as u8;
        }
    }
    call(copy)
}

pub unsafe extern "C" fn sceKernelMemoryPoolCommit_emul(
    addr: *mut c_void,
    len: usize,
    ty: c_int,
    prot: c_int,
    flags: c_int,
) -> c_int {
    type F = unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int) -> c_int;
    unsafe { orig::<F>(ID_POOL_COMMIT)(addr, len, ty, adj(prot), flags) }
}

pub unsafe extern "C" fn sceKernelMapNamedFlexibleMemory_emul(
    addr: P,
    len: usize,
    prot: c_int,
    flags: c_int,
    name: *const c_char,
) -> c_int {
    type F = unsafe extern "C" fn(P, usize, c_int, c_int, *const c_char) -> c_int;
    unsafe { orig::<F>(ID_MAP_NAMED_FLEXIBLE)(addr, len, adj(prot), flags, name) }
}

pub unsafe extern "C" fn sceKernelMapNamedDirectMemory_emul(
    addr: P,
    len: usize,
    prot: c_int,
    flags: c_int,
    start: off_t,
    align: usize,
    name: *const c_char,
) -> c_int {
    type F = unsafe extern "C" fn(P, usize, c_int, c_int, off_t, usize, *const c_char) -> c_int;
    unsafe { orig::<F>(ID_MAP_NAMED_DIRECT)(addr, len, adj(prot), flags, start, align, name) }
}

// ---- exports -------------------------------------------------------------------

unsafe fn state<'a>() -> &'a mut State {
    unsafe { &mut *STATE.get() }
}

/// Debug: bit `i` set when hook id `base + i` is installed.
#[cfg(feature = "mem_report")]
pub(crate) fn installed_bits(base: usize) -> u64 {
    let st = unsafe { &*STATE.get() };
    (0..64)
        .filter(|&i| st.hooks.get(base + i).is_some_and(|d| d.installed))
        .fold(0, |bits, i| bits | 1 << i)
}

/// zstd: Makefile `AMPR_ZSTD_LIBC_HOOKS`, bit i enables hook id 84 + i.
const ZSTD_LIBC_HOOKS: u32 = match option_env!("AMPR_ZSTD_LIBC_HOOKS") {
    Some(s) => parse_mask(s.as_bytes()),
    // ponytail: off until the startup crash is bisected (Makefile).
    None => 0,
};

/// A decimal or `0x` hex mask; zero allowed (unlike `parse_size`).
const fn parse_mask(s: &[u8]) -> u32 {
    let (mut i, radix) = if s.len() > 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        (2, 16)
    } else {
        (0, 10)
    };
    let mut v = 0u32;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' if radix == 16 => c - b'a' + 10,
            c @ b'A'..=b'F' if radix == 16 => c - b'A' + 10,
            _ => panic!("AMPR_ZSTD_LIBC_HOOKS: not a number"),
        };
        v = v * radix + d as u32;
        i += 1;
    }
    v
}

/// Ids past the shared 78 are zstd only: an LZ4 title gets exactly
/// the LZ4 hook set. Of those, 84..96 also need their `ZSTD_LIBC_HOOKS` bit.
fn hook_enabled(id: usize) -> bool {
    if id < FALLBACK_SHARED.len() {
        return true;
    }
    super::pack::zstd_mode() && (!(84..96).contains(&id) || ZSTD_LIBC_HOOKS & 1 << (id - 84) != 0)
}

fn hooks_installed() -> bool {
    INSTALLED.load(Acquire) != 0
}

unsafe fn resolve(lib: SceKernelModule, sym: *const c_char) -> *mut c_void {
    if lib < 0 || sym.is_null() {
        return null_mut();
    }
    let mut p = null_mut();
    if unsafe { sys::sceKernelDlsym(lib, sym, &mut p) } != 0 {
        return null_mut();
    }
    p
}

/// `refresh_hook_runtime_state_from_detours`: republish originals/fallbacks.
unsafe fn refresh(st: &mut State) {
    let mut mandatory_all = true;
    let mut any_mandatory = false;
    for (i, (d, spec)) in st.hooks.iter().zip(HOOKS.0.iter()).enumerate() {
        if spec.mandatory {
            any_mandatory = true;
            mandatory_all &= d.installed;
        }
        let v = if d.installed {
            d.trampoline
        } else {
            SDK_FALLBACK.0[i]
        };
        unsafe { store_slot(lib_slot(i), v) };
    }
    for (i, d) in st.ext.iter().enumerate() {
        unsafe {
            store_slot(
                ext_slot(i),
                if d.installed {
                    d.trampoline
                } else {
                    null_mut()
                },
            )
        };
    }
    let l = if st.loader.installed {
        st.loader.trampoline
    } else {
        null_mut()
    };
    ORIGINAL_LOAD_START_MODULE.store(l, Release);
    INSTALLED.store((any_mandatory && mandatory_all) as u32, Release);

    let h = |i: usize| st.hooks[i].installed;
    let local = h(51) && h(52) && h(53) && h(54);
    let classification = h(50) && (55..=63).all(h) && st.loader.installed && st.ext_coverage_safe;
    unsafe { apr_equeue_overlay_set_hook_availability(local, classification) };
}

/// `install_external_equeue_hooks`: hook producers in any loaded module.
unsafe fn install_external(st: &mut State, lib: SceKernelModule) -> bool {
    if st.ext.iter().all(|d| d.installed) {
        return true;
    }
    type ListFn = unsafe extern "C" fn(*mut SceKernelModule, usize, *mut usize) -> c_int;
    let list = unsafe { resolve(lib, c"sceKernelGetModuleList".as_ptr()) };
    let Some(list) = (unsafe { sys::fn_from_ptr::<ListFn>(list) }) else {
        return false;
    };
    let mut mods = [0 as SceKernelModule; 256];
    let mut n = 0usize;
    if unsafe { list(mods.as_mut_ptr(), mods.len(), &mut n) } != 0 {
        return false;
    }
    let mut safe = n <= mods.len();
    n = n.min(mods.len());
    for i in 0..EXT_COUNT {
        if st.ext[i].installed {
            continue;
        }
        let spec = &EXT_HOOKS.0[i];
        let mut target = null_mut();
        for &m in &mods[..n] {
            if unsafe { sys::sceKernelDlsym(m, spec.symbol.as_ptr(), &mut target) } == 0
                && !target.is_null()
            {
                break;
            }
            target = null_mut();
        }
        if target.is_null() {
            continue;
        }
        if !unsafe {
            install(
                &mut st.tramp,
                ext_slot(i),
                &mut st.ext[i],
                target,
                spec.replacement,
            )
        } {
            safe = false;
        }
    }
    safe
}

/// `install_module_load_observer`: rescan producers after each module load.
unsafe fn install_loader(st: &mut State, lib: SceKernelModule) -> bool {
    if st.loader.installed {
        return true;
    }
    let target = unsafe { resolve(lib, c"sceKernelLoadStartModule".as_ptr()) };
    if target.is_null() {
        return false;
    }
    let repl = sceKernelLoadStartModule_equeue_observer as *mut c_void;
    unsafe {
        install(
            &mut st.tramp,
            ORIGINAL_LOAD_START_MODULE.as_ptr(),
            &mut st.loader,
            target,
            repl,
        )
    }
}

pub unsafe extern "C" fn sceKernelLoadStartModule_equeue_observer(
    name: *const c_char,
    args: usize,
    argp: *const c_void,
    flags: u32,
    opt: *const c_void,
    result: *mut c_int,
) -> SceKernelModule {
    type F = unsafe extern "C" fn(
        *const c_char,
        usize,
        *const c_void,
        u32,
        *const c_void,
        *mut c_int,
    ) -> SceKernelModule;
    let Some(orig) = (unsafe { sys::fn_from_ptr::<F>(ORIGINAL_LOAD_START_MODULE.load(Acquire)) })
    else {
        return sys::SCE_KERNEL_ERROR_ENOSYS;
    };
    let module = unsafe { orig(name, args, argp, flags, opt, result) };
    if module < 0 {
        return module;
    }
    let _g = HOOK_LOCK.lock();
    if hooks_installed() {
        let st = unsafe { state() };
        st.ext_coverage_safe = st.ext_coverage_safe && unsafe { install_external(st, LIBKERNEL) };
        unsafe { refresh(st) };
    }
    module
}

/// `ampr_install_libkernel_hooks_for_module`.
unsafe fn install_all(lib: SceKernelModule) -> c_int {
    let _g = HOOK_LOCK.lock();
    let st = unsafe { state() };
    if hooks_installed() {
        let loader = unsafe { install_loader(st, lib) };
        st.ext_coverage_safe =
            st.ext_coverage_safe && loader && unsafe { install_external(st, lib) };
        unsafe { refresh(st) };
        return 0;
    }
    st.ext_coverage_safe = false;

    let (mut installed, mut mandatory_unavailable) = (0usize, false);
    for i in 0..HOOK_COUNT {
        let spec = &HOOKS.0[i];
        if !hook_enabled(i) {
            continue;
        }
        if st.hooks[i].installed {
            unsafe { store_slot(lib_slot(i), st.hooks[i].trampoline) };
            installed += 1;
            continue;
        }
        let target = unsafe { resolve(lib, spec.symbol.as_ptr()) };
        // Two names for one function (e.g. an alias): detour it once, or the
        // second trampoline would copy the first jump and loop.
        let alias = st.hooks[..i]
            .iter()
            .any(|d| d.installed && d.target == target.cast());
        let ok = !target.is_null()
            && !alias
            && unsafe {
                install(
                    &mut st.tramp,
                    lib_slot(i),
                    &mut st.hooks[i],
                    target,
                    spec.replacement,
                )
            };
        if ok {
            installed += 1;
        } else if spec.mandatory {
            mandatory_unavailable = true;
        }
    }

    if installed == 0 {
        unsafe { refresh(st) };
        return -1;
    }
    if mandatory_unavailable {
        // Roll back in reverse; a failed restore keeps its trampoline published.
        for i in (0..HOOK_COUNT).rev() {
            unsafe { uninstall(&mut st.tramp, &mut st.hooks[i]) };
        }
        unsafe { refresh(st) };
        return -1;
    }

    let loader = unsafe { install_loader(st, lib) };
    st.ext_coverage_safe = loader && unsafe { install_external(st, lib) };
    unsafe { refresh(st) };
    0
}

// ---- exports -------------------------------------------------------------------

pub unsafe fn amprInstallLibkernelHooks() -> c_int {
    unsafe { install_all(LIBKERNEL) }
}

pub unsafe fn amprUninstallLibkernelHooks() -> c_int {
    let _g = HOOK_LOCK.lock();
    unsafe { apr_equeue_overlay_shutdown() };
    let st = unsafe { state() };
    st.ext_coverage_safe = false;
    let mut ok = true;
    let was = st.loader.installed;
    let r = unsafe { uninstall(&mut st.tramp, &mut st.loader) };
    ok &= r;
    if was && r {
        ORIGINAL_LOAD_START_MODULE.store(null_mut(), Release);
    }
    for i in (0..EXT_COUNT).rev() {
        let was = st.ext[i].installed;
        let r = unsafe { uninstall(&mut st.tramp, &mut st.ext[i]) };
        ok &= r;
        if was && r {
            unsafe { store_slot(ext_slot(i), null_mut()) };
        }
    }
    for i in (0..HOOK_COUNT).rev() {
        ok &= unsafe { uninstall(&mut st.tramp, &mut st.hooks[i]) };
    }
    unsafe { refresh(st) };
    if ok {
        0
    } else {
        -1
    }
}

pub unsafe fn amprResolveLibkernelFunction(symbol: *const c_char) -> *mut c_void {
    unsafe { resolve(LIBKERNEL, symbol) }
}
