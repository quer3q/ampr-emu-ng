//! Seekable AMPR asset-pack runtime. Function bodies live in role-named
//! part files; this file holds shared data layouts, constants, global state
//! and imports from other modules.
//!
//! Naming conventions (parts call each other by name through the glob re-exports):
//! - Functions keep their upstream names (snake_case or camelCase as they
//!   are). Methods live in `impl` blocks that may be split across parts; a
//!   constructor is `new`, a destructor is `impl Drop`.
//! - Signatures keep a fixed parameter order, telemetry timestamps included
//!   (pass 0). Out-parameters are `&mut T`, read-only ones `&T`, raw buffers
//!   `*mut T` / `*const T`; `pack_state()` returns `*mut PackState`
//!   (access fields as `(*state).x`; never form `&PackState`).
//!   C scalars use `c_int`, `usize`, `c_long` and the `sys` aliases
//!   `off_t`/`ssize_t`. Struct fields are snake_case (`io_window_pack_id`).
//! - Build-time knobs keep their macro-style names (`AMPR_EMU_PACK_WORKERS`).
//!   Other constants are SCREAMING_SNAKE_CASE (`PACK_MAX_BLOCK_BYTES`,
//!   `AMPR_PACK_FILE_PACKED`, `APR_EXTERNAL_AIO_GROUP_MAX_REQUESTS`).
//! - The PackState mutexes, condvars and atomics live in separate statics
//!   (see "sync state"), so lock guards never borrow PackState:
//!   `PACK_M`, `CACHE_CVS[i]`, etc.
//! - Detour targets (`*_emul`) keep the C ABI; runtime helpers use Rust calls.
//! - Telemetry is not implemented: there are no pack stats counters or
//!   runtime stats export, and `pack_telemetry_usecs()` returns 0.
//! - Shared helpers: `sce_errno_from_posix`, `posix_errno_from_sce`,
//!   `errno()`, `kernel_slot::<F>`, hook ids `sys::hook::x`,
//!   `spin_pause_or_yield(&mut spins)`, and `ampr_lz4::decode_chunk`
//!   (Ok == rawSize) for LZ4 blocks.
//! - Name clashes between the `sys` glob and a part's own definition (e.g.
//!   `sceKernelClose`): the local definition wins; elsewhere qualify `sys::x`.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

pub(crate) use core::ffi::{c_char, c_int, c_long, c_void, CStr};
pub(crate) use core::mem::{offset_of, size_of, MaybeUninit};
pub(crate) use core::ptr::{null, null_mut};
pub(crate) use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

/// Debug counters (no-ops unless `mem_report`); use as `stats::Stat::X`,
/// since `Stat` here is the kernel `struct stat`.
pub(crate) use super::stats;
pub(crate) use super::sync::{spin_pause_or_yield, Condvar, Mutex, SyncCell};
pub(crate) use super::sys::{self, *};

// ---- helpers from other runtime modules -------------------------------------
pub(crate) use super::fd_cache::{
    ampr_index_fd_cache_release_open_fd_budget_headroom,
    ampr_index_fd_open_budget_progress_generation, ampr_index_fd_pack_note_close,
    ampr_index_fd_pack_note_open, FileEntryView,
};
pub(crate) use super::index::{
    ampr_index_get_entry_view, ampr_index_resolve_path_to_id, ampr_pack_core_make_task,
    ampr_pack_core_mount, ampr_pack_core_task_count, ampr_pack_core_validate_logical_file,
    ampr_pack_crc32, AmprPackBlockReadTask, AmprPackChunkView, AmprPackCoreView, Stat,
};
pub(crate) use super::runtime_memory::{ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_free};
pub(crate) use crate::cache_ffi::{
    ampr_rust_cache_chunk_key_hash, ampr_rust_cache_find_page_run, ampr_rust_cache_mark_pages,
    ampr_rust_cache_wait_bucket, ampr_rust_physical_cache_key_hash,
};
pub(crate) use crate::handle_ffi::{
    ampr_rust_virtual_decode, ampr_rust_virtual_encode, ampr_rust_virtual_next_generation,
};
pub(crate) use crate::overlay_ffi::{
    ampr_rust_overlay_build_order, ampr_rust_overlay_directory_range,
    ampr_rust_overlay_folded_hash, ampr_rust_overlay_next_child, ampr_rust_overlay_normalize_path,
    ampr_rust_overlay_packed_count, ampr_rust_overlay_packed_file_matches,
    ampr_rust_overlay_service_name_hidden,
};
pub(crate) use crate::volume_ffi::ampr_rust_volume_header_validate;

/// `SceKernelStat` (FreeBSD `struct stat`).
pub(crate) type SceKernelStat = Stat;

// ---- external AIO broker entry points (rt/reactor)
use super::reactor;
pub(crate) use super::reactor::apr_reactor_notify_external_progress;

// ---- libScePthread thread API (same signatures as rt/reactor/mod.rs) -------
pub(crate) type ScePthreadAttr = *mut c_void;
unsafe extern "C" {
    pub(crate) fn scePthreadCreate(
        thread: *mut ScePthread,
        attr: *const ScePthreadAttr,
        entry: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        name: *const c_char,
    ) -> c_int;
    pub(crate) fn scePthreadJoin(thread: ScePthread, value: *mut *mut c_void) -> c_int;
    pub(crate) fn scePthreadSelf() -> ScePthread;
    pub(crate) fn scePthreadSetprio(thread: ScePthread, prio: c_int) -> c_int;
    pub(crate) fn scePthreadSetaffinity(thread: ScePthread, mask: u64) -> c_int;
}

/// FreeBSD 11 `struct dirent` (PS5 libc).
#[repr(C)]
pub(crate) struct Dirent {
    pub d_fileno: u32,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_namlen: u8,
    pub d_name: [c_char; 256],
}
pub(crate) const DIRENT_NAME_OFFSET: usize = offset_of!(Dirent, d_name);
const _: () = assert!(DIRENT_NAME_OFFSET == 8 && size_of::<Dirent>() == 264);

// ---- parts ------------------------------------------------------------------
mod libkernel;
pub(crate) use libkernel::*;
mod align;
pub(crate) use align::*;
// zstd: the AMPRPAK4 directory order (build_packed_file_order) is unused
// until R6 replaces it with a zstd-backed one.
mod state;
pub(crate) use state::*;
mod manifest;
pub(crate) use manifest::*;
mod caches;
pub(crate) use caches::*;
mod leases;
pub(crate) use leases::*;
mod page_plan;
pub(crate) use page_plan::*;
mod window_aio;
pub(crate) use window_aio::*;
mod virtual_read;
pub(crate) use virtual_read::*;
mod schedule;
pub(crate) use schedule::*;
mod worker;
pub(crate) use worker::*;
mod slots;
pub(crate) use slots::*;
mod directories;
pub(crate) use directories::*;
mod fd_read;
pub(crate) use fd_read::*;
mod aio;
pub(crate) use aio::*;
mod aio_wait;
pub(crate) use aio_wait::*;
mod readahead;
pub(crate) use readahead::*;
/// zstd mount state and accessors (reached as `zstd::x`).
pub(crate) mod zstd;
pub(crate) mod zstd_libc;
/// zstd: a multi-chunk read split into parallel child jobs (aio.rs).
mod zstd_split;
pub(crate) use zstd_split::*;

/// Pack format of this title, chosen once at module_start before any hook
/// installs: zstd when `/app0/ampr_zstd.index` exists, else LZ4.
static ZSTD_MODE: AtomicBool = AtomicBool::new(false);

/// True when the title's packs are zstd (AMPRZPK1); false for LZ4 (AMPRPAK4).
#[inline(always)]
pub(crate) fn zstd_mode() -> bool {
    ZSTD_MODE.load(Ordering::Relaxed)
}

/// module_start, before hooks: picks the pack format from the files present.
pub(crate) unsafe fn select_pack_format() {
    type StatFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
    // FreeBSD struct stat is 224 bytes; room to spare.
    let mut st = [0u64; 64];
    let found = unsafe { sys::resolve_kernel::<StatFn>(c"stat") }.is_some_and(|f| unsafe {
        f(
            zstd::AMPR_EMU_ZSTD_INDEX_PATH.as_ptr(),
            st.as_mut_ptr().cast(),
        ) == 0
    });
    ZSTD_MODE.store(found, Ordering::Relaxed);
}

// ---- SDK AIO types ------------------------------------------------------------

pub(crate) type SceKernelAioSubmitId = c_int;
/// `pthread_t` / `ScePthread`.
pub(crate) type ScePthread = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SceKernelAioResult {
    pub return_value: i64,
    pub state: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SceKernelAioRWRequest {
    pub offset: off_t,
    pub nbyte: usize,
    pub buf: *mut c_void,
    pub result: *mut SceKernelAioResult,
    pub fd: c_int,
}

/// `SceKernelIovec` (`struct iovec`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SceKernelIovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

impl SceKernelAioResult {
    pub(crate) const EMPTY: Self = Self {
        return_value: 0,
        state: 0,
    };
}
impl SceKernelAioRWRequest {
    pub(crate) const EMPTY: Self = Self {
        offset: 0,
        nbyte: 0,
        buf: null_mut(),
        result: null_mut(),
        fd: 0,
    };
}

const _: () = {
    assert!(size_of::<SceKernelAioResult>() == 16 && offset_of!(SceKernelAioResult, state) == 8);
    assert!(
        size_of::<SceKernelAioRWRequest>() == 40 && offset_of!(SceKernelAioRWRequest, fd) == 32
    );
    assert!(size_of::<SceKernelIovec>() == 16);
};

pub(crate) const SCE_KERNEL_AIO_PRIORITY_LOW: c_int = 1;
pub(crate) const SCE_KERNEL_AIO_PRIORITY_MID: c_int = 2;
pub(crate) const SCE_KERNEL_AIO_PRIORITY_HIGH: c_int = 3;
pub(crate) const SCE_KERNEL_AIO_STATE_NOTIFIED: c_int = 0x10000;
pub(crate) const SCE_KERNEL_AIO_STATE_SUBMITTED: c_int = 1;
pub(crate) const SCE_KERNEL_AIO_STATE_PROCESSING: c_int = 2;
pub(crate) const SCE_KERNEL_AIO_STATE_COMPLETED: c_int = 3;
pub(crate) const SCE_KERNEL_AIO_STATE_ABORTED: c_int = 4;
pub(crate) const SCE_KERNEL_AIO_WAIT_AND: u32 = 0x01;
pub(crate) const SCE_KERNEL_AIO_WAIT_OR: u32 = 0x02;
pub(crate) const SCE_KERNEL_AIO_REQUEST_NUM_MAX: usize = 128;
pub(crate) const SCE_KERNEL_AIO_ID_NUM_MAX: usize = 128;
pub(crate) const SCE_KERNEL_PATH_MAX: usize = 1024;
pub(crate) const SCE_KERNEL_O_RDONLY: c_int = 0;

// FreeBSD libc constants.
pub(crate) const O_RDONLY: c_int = 0x0;
pub(crate) const O_ACCMODE: c_int = 0x3;
pub(crate) const O_NONBLOCK: c_int = 0x4;
pub(crate) const O_DIRECTORY: c_int = 0x20000;
pub(crate) const SEEK_SET: c_int = 0;
pub(crate) const SEEK_CUR: c_int = 1;
pub(crate) const S_IFDIR: u16 = 0o040000;
pub(crate) const S_IFREG: u16 = 0o100000;
pub(crate) const DT_UNKNOWN: u8 = 0;
pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_REG: u8 = 8;

// ---- external AIO broker ------------------------------------------------------

pub(crate) const APR_EXTERNAL_AIO_GROUP_MAX_REQUESTS: usize = 32;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AprExternalAioClass {
    Latency,
    Balanced,
    Bulk,
}

impl From<AprExternalAioClass> for reactor::AprExternalAioClass {
    fn from(class: AprExternalAioClass) -> Self {
        match class {
            AprExternalAioClass::Latency => Self::Latency,
            AprExternalAioClass::Balanced => Self::Balanced,
            AprExternalAioClass::Bulk => Self::Bulk,
        }
    }
}

// Constructed by the reactor across FFI.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // ABI values
pub(crate) enum AprExternalAioEvent {
    Submitted,
    SubmitDeferred,
    SubmitFailed,
    Completed,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct AprExternalAioNotification {
    pub event: AprExternalAioEvent,
    pub value: c_int,
    pub first_external_in_submit_batch: bool,
}
const _: () = assert!(
    size_of::<AprExternalAioNotification>() == 12
        && offset_of!(AprExternalAioNotification, value) == 4
        && offset_of!(AprExternalAioNotification, first_external_in_submit_batch) == 8
);

// ---- on-disk format -----------------------------------------------------------

pub(crate) const AMPR_PACK_BLOCK_SHIFT_MAX: u8 = 20;
pub(crate) const AMPR_PACK_IO_PAGE_SHIFT_MIN: u8 = 12;
pub(crate) const AMPR_PACK_IO_PAGE_SHIFT_MAX: u8 = 20;

pub(crate) const AMPR_PACK_FILE_PACKED: u32 = 1 << 0;
pub(crate) const AMPR_PACK_FILE_STREAMING: u32 = 1 << 2;
pub(crate) const AMPR_PACK_FILE_HOT: u32 = 1 << 3;
pub(crate) const AMPR_PACK_FILE_RANDOM_ACCESS: u32 = ampr_lz4::FILE_RANDOM_ACCESS;

pub(crate) const AMPR_PACK_CHUNK_RAW: u8 = 0;
pub(crate) const AMPR_PACK_CHUNK_LZ4: u8 = 1;
pub(crate) const AMPR_PACK_CHUNK_SHARED: u8 = 1 << 0;
pub(crate) const AMPR_PACK_CHUNK_STREAMING: u8 = 1 << 1;

// Packed records are read in place from the mounted manifest; read fields by
// value (`{ rec.field }`), never take references to them.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackIndexHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub header_size: u32,
    pub flags: u32,
    pub endian_marker: u32,
    pub build_id: [u8; 16],
    pub file_count: u64,
    pub chunk_count: u64,
    pub pack_count: u32,
    pub file_record_size: u32,
    pub chunk_record_size: u32,
    pub pack_record_size: u32,
    pub files_offset: u64,
    pub chunks_offset: u64,
    pub packs_offset: u64,
    pub strings_offset: u64,
    pub strings_size: u64,
    pub payload_crc32: u32,
    pub header_crc32: u32,
    pub reserved: u64,
}

/// Optional `<manifest>.runtime` companion ("AMPRCFG1").
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackRuntimeProfile {
    pub magic: [u8; 8],
    pub version: u32,
    pub size: u32,
    pub build_id: [u8; 16],
    pub decoded_cache_bytes: u64,
    pub physical_cache_bytes: u64,
    pub workers: u32,
    pub latency_reserve_workers: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackFileRecord {
    pub path_hash: u64,
    pub logical_size: u64,
    pub mtime: i64,
    pub first_chunk: u32,
    pub chunk_count: u32,
    pub path_offset: u32,
    pub path_length: u32,
    pub flags: u32,
    pub block_shift: u8,
    pub packing_class: u8,
    pub reserved: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackChunkRecord {
    pub location: u64,
    pub descriptor: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackDataRecord {
    pub payload_bytes: u64,
    pub file_size: u64,
    pub name_offset: u32,
    pub name_length: u32,
    pub flags: u32,
    pub io_page_size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct AmprPackDataHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub header_size: u32,
    pub pack_id: u32,
    pub flags: u32,
    pub build_id: [u8; 16],
    pub payload_offset: u64,
    pub payload_bytes: u64,
    pub header_crc32: u32,
    pub reserved: u32,
}

const _: () = {
    assert!(size_of::<AmprPackIndexHeader>() == 128);
    assert!(size_of::<AmprPackRuntimeProfile>() == 64);
    assert!(size_of::<AmprPackFileRecord>() == 48);
    assert!(size_of::<AmprPackChunkRecord>() == 12);
    assert!(size_of::<AmprPackDataRecord>() == 32);
    assert!(size_of::<AmprPackDataHeader>() == 64);
};

// ---- core result codes --------------------------------------------------------
pub(crate) const AMPR_PACK_CORE_OK: c_int = 0;

impl AmprPackCoreView {
    pub(crate) const EMPTY: Self = Self {
        base: null(),
        size: 0,
        header: null(),
        files: null(),
        chunks: null(),
        packs: null(),
        strings: null(),
        strings_size: 0,
    };
}

// ---- configuration (AMPR_PACK_ENABLE=1, AMPR_DIRECTORY_OVERLAY=1)
// Process open/AIO intercepts are off, unlike upstream 0.4.2.1 release (config.h
// AMPR_EMU_PACK_PROCESS_OPEN_ENABLE=1): LZ4 packs hold only files the game reads
// through AMPR, so plain open()/kernel AIO never target them.

pub(crate) const AMPR_EMU_PACK_PROCESS_OPEN_ENABLE: bool = false;
pub(crate) const AMPR_EMU_PACK_INTERCEPT_ALL_READ_ONLY: bool = AMPR_EMU_PACK_PROCESS_OPEN_ENABLE;

pub(crate) const AMPR_EMU_PACK_INDEX_PATH: &CStr = c"/app0/ampr_assets.index";
/// `AMPR_EMU_PACK_INDEX_PATH ".runtime"` (AMPRPAK4 only; zstd keeps the defaults).
pub(crate) const AMPR_EMU_PACK_RUNTIME_PROFILE_PATH: &CStr = c"/app0/ampr_assets.index.runtime";
pub(crate) const AMPR_EMU_PACK_ROOT_PATH: &CStr = c"/app0";
pub(crate) const AMPR_EMU_PACK_LOGICAL_ROOT_PATH: &CStr = c"/app0";

pub(crate) const AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS: usize = 256;
/// Decode workers, from the Makefile's `AMPR_PACK_WORKERS` (default 8).
pub(crate) const AMPR_EMU_PACK_WORKERS: u32 = match option_env!("AMPR_PACK_WORKERS") {
    Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
    None => 8,
};
const _: () = assert!(
    AMPR_EMU_PACK_WORKERS >= 1 && AMPR_EMU_PACK_WORKERS as usize <= AMPR_EMU_PACK_WORKER_CAPACITY
);
pub(crate) const AMPR_EMU_PACK_WORKER_CAPACITY: usize = 16;
/// Sequential read-ahead window in chunks, from the Makefile's
/// `AMPR_PACK_READAHEAD_CHUNKS` (default 32, a ~1-1.5 MiB prefetch run); 0
/// disables read-ahead (readahead.rs).
pub(crate) const AMPR_EMU_PACK_READAHEAD_CHUNKS: u32 =
    match option_env!("AMPR_PACK_READAHEAD_CHUNKS") {
        Some(s) if s.len() == 1 && s.as_bytes()[0] == b'0' => 0,
        Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
        None => 32,
    };
const _: () = assert!(AMPR_EMU_PACK_READAHEAD_CHUNKS <= 64);
/// Read-ahead disk-saturation gate, from the Makefile's
/// `AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT` (default 2): prefetch is skipped
/// while the pack has at least this many physical backing reads in flight
/// (readahead.rs); 0 disables prefetch starts entirely.
pub(crate) const AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT: u32 =
    match option_env!("AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT") {
        Some(s) if s.len() == 1 && s.as_bytes()[0] == b'0' => 0,
        Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
        None => 2,
    };
/// Read extension, from the Makefile's `AMPR_PACK_READ_EXTEND_BYTES` (default
/// 1 MiB): a backing request for cold physical pages also reads the following
/// uncached pages of the volume into the physical cache, up to this total
/// request size (page_plan.rs); 0 disables it.
pub(crate) const AMPR_EMU_PACK_READ_EXTEND_BYTES: usize =
    match option_env!("AMPR_PACK_READ_EXTEND_BYTES") {
        Some(s) if s.len() == 1 && s.as_bytes()[0] == b'0' => 0,
        Some(s) => super::runtime_memory::parse_size(s.as_bytes()),
        None => 1024 * 1024,
    };
/// Read extension runs only while fewer than this many pack disk reads are in
/// flight (Makefile `AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT`, default 2). Console
/// metrics: unconditional 1 MiB extension doubled throughput but raised busy-time
/// read latency (ShadowMount serializes requests).
pub(crate) const AMPR_EMU_PACK_READ_EXTEND_MAX_DISK_INFLIGHT: u32 =
    match option_env!("AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT") {
        Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
        None => 2,
    };
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES: u64 = 128 * 1024 * 1024;
/// 16 in release: each pipeline keeps a 2 MiB I/O window once used and the
/// cache reserve keeps room for all of them (manifest.rs), so a window never fails to
/// allocate; work waits in the queue while all pipelines are busy (schedule.rs). The
/// debug build has 32 slots and starts `tune::pipelines()` of them (worker.rs).
pub(crate) const AMPR_EMU_PACK_PIPELINE_SLOTS: usize = if super::tune::ON {
    32
} else {
    super::tune::RELEASE_PIPELINES as usize
};
pub(crate) const AMPR_EMU_PACK_WORKER_PRIORITY: c_int = 384;
pub(crate) const AMPR_EMU_PACK_WORKER_AFFINITY: u64 = 0x3f;
pub(crate) const AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS: u32 = 0;
pub(crate) const AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES: u64 = 64 * 1024;
pub(crate) const AMPR_EMU_PACK_BULK_READ_MIN_BYTES: u64 = 256 * 1024;
pub(crate) const AMPR_EMU_PACK_IO_STAGING_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_PREAD_MAX_BYTES: u64 = AMPR_EMU_PACK_IO_STAGING_BYTES;
pub(crate) const AMPR_EMU_PACK_VIRTUAL_FD_SLOTS: usize = 256;
pub(crate) const AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS: usize = 256;
pub(crate) const AMPR_EMU_PACK_MAX_PACKS: usize = 1024;
pub(crate) const AMPR_EMU_PACK_OPEN_PACK_FD_CAP: u32 = 18;
/// 0 = off: with read-ahead off it got 1-2.5% hits (the game re-reads chunks
/// only gigabytes later); reads take the Bypass path.
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_BYTES: u64 = 0;
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_MEMORY_RESERVE_BYTES: u64 = 4 * 1024 * 1024;
/// 32 MiB, the only cache: besides its hits it is where the read planner
/// (page_plan.rs) joins neighbouring pages into one large read; with it off reads fell
/// to 66 KB (one chunk) and load APR rose 1.65 -> 2.50 ms.
/// zstd too: 64 MiB gave APR read 1.11 -> 1.08/1.09 ms and -10% disk bytes
/// at 8.9 GB read for 32 MiB more pool;
/// 32 MiB is kept as the version to compare.
pub(crate) const AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP: usize = 4096;
pub(crate) const AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS: usize = 8192;
pub(crate) const AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS: usize = 64;
pub(crate) const AMPR_EMU_PACK_CACHE_ENTRY_CAP: usize = 8192;
pub(crate) const AMPR_EMU_PACK_CACHE_PAGE_SHIFT: u32 = 14;
pub(crate) const AMPR_EMU_PACK_CACHE_HASH_BUCKETS: usize = 16384;
pub(crate) const AMPR_EMU_PACK_TOUCH_TABLE_SIZE: usize = 16384;
pub(crate) const AMPR_EMU_PACK_INDEX_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_MAX_FILES: u64 = 2_000_000;
pub(crate) const AMPR_EMU_PACK_MAX_CHUNKS: u64 = 16_000_000;

// ---- derived constants --------------------------------------------------------

pub(crate) const PACK_MAX_BLOCK_BYTES: usize = 1 << AMPR_PACK_BLOCK_SHIFT_MAX;
pub(crate) const PACK_PIPELINE_IO_BYTES: usize = AMPR_EMU_PACK_IO_STAGING_BYTES as usize;
pub(crate) const PACK_PIPELINE_MAX_IO_PAGES: usize =
    PACK_PIPELINE_IO_BYTES / (1 << AMPR_PACK_IO_PAGE_SHIFT_MIN);
/// Backing AIO requests one mandatory page group may issue (one reactor group).
pub(crate) const PACK_MANDATORY_GROUP_MAX_REQUESTS: usize = APR_EXTERNAL_AIO_GROUP_MAX_REQUESTS;
/// Pages one mandatory page group may plan: one staging window of 16 KiB
/// pages, so contiguous cold pages coalesce into few large requests (page_plan.rs).
pub(crate) const PACK_MANDATORY_GROUP_MAX_PAGES: usize =
    PACK_PIPELINE_IO_BYTES / PACK_CACHE_PAGE_BYTES;
pub(crate) const PACK_COALESCED_AIO_MIN_BYTES: usize = 128 * 1024;
/// Console pread: ~700 us per request regardless of size up to 1 MiB, so one
/// backing request may cover a whole staging window.
pub(crate) const PACK_COALESCED_AIO_MAX_BYTES: usize = PACK_PIPELINE_IO_BYTES;
pub(crate) const PACK_CACHE_PAGE_BYTES: usize = 1 << AMPR_EMU_PACK_CACHE_PAGE_SHIFT;
pub(crate) const PACK_CACHE_MAX_PAGES: usize =
    AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES as usize / PACK_CACHE_PAGE_BYTES;
pub(crate) const PACK_CACHE_BITMAP_WORDS: usize = (PACK_CACHE_MAX_PAGES + 63) / 64;
pub(crate) const PACK_PHYSICAL_CACHE_MAX_PAGES: usize =
    AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES as usize / PACK_CACHE_PAGE_BYTES;
pub(crate) const PACK_PHYSICAL_CACHE_BITMAP_WORDS: usize =
    (PACK_PHYSICAL_CACHE_MAX_PAGES + 63) / 64;
pub(crate) const INVALID_INDEX: u32 = u32::MAX;
// ampr_format::handles::Kind; the tags live in Rust.
pub(crate) const VIRTUAL_KIND_FD: u32 = 0;
pub(crate) const VIRTUAL_KIND_AIO: u32 = 1;
pub(crate) const VIRTUAL_KIND_DIRECTORY_FD: u32 = 2;
pub(crate) const VIRTUAL_KIND_AIO_GROUP: u32 = 3;
pub(crate) const PACK_LOAD_UNINITIALIZED: u32 = 0;
pub(crate) const PACK_LOAD_LOADING: u32 = 1;
pub(crate) const PACK_LOAD_READY: u32 = 2;
pub(crate) const PACK_LOAD_UNAVAILABLE: u32 = 3;
pub(crate) const PACK_LOAD_INVALID: u32 = 4;
pub(crate) const PACK_CACHE_WAIT_BUCKET_COUNT: usize = 64;
pub(crate) const DIRECTORY_PHYSICAL_HASH_CAP: usize = 512;
pub(crate) const PACK_WORK_CLASS_COUNT: usize = PackWorkClass::Count as usize;

const _: () = {
    assert!(
        PACK_PIPELINE_MAX_IO_PAGES == 512
            && PACK_MANDATORY_GROUP_MAX_PAGES <= PACK_PIPELINE_MAX_IO_PAGES
    );
    assert!(
        PACK_MANDATORY_GROUP_MAX_PAGES == 128
            && PACK_MANDATORY_GROUP_MAX_REQUESTS <= PACK_MANDATORY_GROUP_MAX_PAGES
    );
    // A complete mandatory set owns one descriptor per pack (page_plan.rs FD cap check).
    assert!(AMPR_EMU_PACK_OPEN_PACK_FD_CAP as usize <= PACK_MANDATORY_GROUP_MAX_REQUESTS);
    assert!(
        PACK_COALESCED_AIO_MIN_BYTES <= PACK_COALESCED_AIO_MAX_BYTES
            && PACK_COALESCED_AIO_MAX_BYTES <= PACK_PIPELINE_IO_BYTES
    );
    assert!(PACK_CACHE_BITMAP_WORDS == 512 && PACK_PHYSICAL_CACHE_BITMAP_WORDS == 128);
    assert!(AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES <= AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES);
    assert!(AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS.is_power_of_two());
    assert!(AMPR_EMU_PACK_PIPELINE_SLOTS <= SCE_KERNEL_AIO_REQUEST_NUM_MAX);
    assert!(AMPR_EMU_PACK_IO_STAGING_BYTES >= 2 * (1 << AMPR_PACK_BLOCK_SHIFT_MAX));
};

// ---- un-detoured libkernel entry points ----------------------------------------

pub(crate) type KernelOpenFn = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
pub(crate) type KernelCloseFn = unsafe extern "C" fn(c_int) -> c_int;
pub(crate) type KernelFstatFn = unsafe extern "C" fn(c_int, *mut SceKernelStat) -> c_int;
pub(crate) type KernelStatFn = unsafe extern "C" fn(*const c_char, *mut SceKernelStat) -> c_int;
pub(crate) type KernelGetdentsFn = unsafe extern "C" fn(c_int, *mut c_char, c_int) -> c_int;
pub(crate) type KernelGetdirentriesFn =
    unsafe extern "C" fn(c_int, *mut c_char, c_int, *mut c_long) -> c_int;
pub(crate) type KernelPreadFn = unsafe extern "C" fn(c_int, *mut c_void, usize, off_t) -> ssize_t;
pub(crate) type KernelLseekFn = unsafe extern "C" fn(c_int, off_t, c_int) -> off_t;
pub(crate) type KernelAioSubmitFn = unsafe extern "C" fn(
    *mut SceKernelAioRWRequest,
    c_int,
    c_int,
    *mut SceKernelAioSubmitId,
) -> c_int;
pub(crate) type KernelAioPollSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int) -> c_int;
pub(crate) type KernelAioPollFn =
    unsafe extern "C" fn(*mut SceKernelAioSubmitId, c_int, *mut c_int) -> c_int;
#[allow(dead_code)]
pub(crate) type KernelAioWaitSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int, *mut SceKernelUseconds) -> c_int;
pub(crate) type KernelAioWaitFn = unsafe extern "C" fn(
    *mut SceKernelAioSubmitId,
    c_int,
    *mut c_int,
    u32,
    *mut SceKernelUseconds,
) -> c_int;
#[allow(dead_code)]
pub(crate) type KernelAioCancelSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int) -> c_int;
#[allow(dead_code)]
pub(crate) type KernelAioCancelFn =
    unsafe extern "C" fn(*mut SceKernelAioSubmitId, c_int, *mut c_int) -> c_int;
pub(crate) type KernelAioDeleteSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int) -> c_int;
pub(crate) type KernelAioDeleteFn =
    unsafe extern "C" fn(*mut SceKernelAioSubmitId, c_int, *mut c_int) -> c_int;

// `resolve_cached` slots: null until amprResolveLibkernelFunction succeeds
// (a failed lookup is retried on the next call).
pub(crate) static g_real_open: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_close: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_sce_close: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_fstat: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_stat: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_getdents: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_getdirentries: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_pread: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_lseek: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
#[allow(dead_code)]
pub(crate) static g_real_aio_submit_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_submit: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_poll_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_poll: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
#[allow(dead_code)]
pub(crate) static g_real_aio_wait_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_wait: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
#[allow(dead_code)]
pub(crate) static g_real_aio_cancel_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
#[allow(dead_code)]
pub(crate) static g_real_aio_cancel: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_delete_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_delete: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

// ---- runtime data layouts -----------------------------------------------------
// Every enum's first variant is 0 and `EMPTY` holds the default field
// values, so zeroed storage plus `EMPTY` for the non-zero fields
// reproduces `PackState()`.

#[derive(Clone, Copy)]
pub(crate) struct VirtualFdSlot {
    pub file_id: u32,
    /// First local chunk not yet covered by read-ahead (readahead.rs).
    pub readahead_next: u32,
    pub cursor: u64,
    pub generation: u16,
    pub active: bool,
}
impl VirtualFdSlot {
    pub(crate) const EMPTY: Self = Self {
        file_id: 0,
        readahead_next: 0,
        cursor: 0,
        generation: 0,
        active: false,
    };
}

pub(crate) struct VirtualDirectorySlot {
    pub real_fd: c_int,
    pub directory_offset: c_long,
    pub range_begin: u32,
    pub range_end: u32,
    pub virtual_cursor: u32,
    pub physical_hash_count: u32,
    pub generation: u16,
    pub path_length: u16,
    pub active: bool,
    pub real_exhausted: bool,
    pub dot_emitted: bool,
    pub dot_dot_emitted: bool,
    pub physical_hash_overflow: bool,
    pub path: [c_char; SCE_KERNEL_PATH_MAX],
    pub physical_name_hashes: [u64; DIRECTORY_PHYSICAL_HASH_CAP],
}
impl VirtualDirectorySlot {
    pub(crate) const EMPTY: Self = Self {
        real_fd: -1,
        directory_offset: 0,
        range_begin: 0,
        range_end: 0,
        virtual_cursor: 0,
        physical_hash_count: 0,
        generation: 0,
        path_length: 0,
        active: false,
        real_exhausted: false,
        dot_emitted: false,
        dot_dot_emitted: false,
        physical_hash_overflow: false,
        path: [0; SCE_KERNEL_PATH_MAX],
        physical_name_hashes: [0; DIRECTORY_PHYSICAL_HASH_CAP],
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VirtualAioPhase {
    Free,
    Reserved,
    Queued,
    Running,
    WaitingCache,
    WaitingFd,
    IoQueued,
    Done,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackWorkClass {
    Latency = 0,
    Balanced = 1,
    Bulk = 2,
    Count = 3,
}

pub(crate) struct VirtualAioSlot {
    pub request: SceKernelAioRWRequest,
    pub file_id: u32,
    pub next: u32,
    pub pipeline_index: u32,
    pub generation: u16,
    pub priority: u8,
    pub work_class: PackWorkClass,
    pub wait_notified: bool,
    pub phase: VirtualAioPhase,
    pub cancel_requested: AtomicBool,
    pub completion_state: c_int,
    pub return_value: i64,
    /// `stats::now()` at allocation (0 in normal builds).
    pub submit_ns: u64,
    /// Debug: when the job last parked (0: not parked), why (b'i' disk,
    /// b'c' cache page, b'f' fd budget), and when it was requeued.
    pub parked_ns: u64,
    pub park_kind: u8,
    pub requeued_ns: u64,
    /// Nonzero: a read-ahead job (readahead.rs) loading this many chunks into the
    /// decoded cache; no destination, no id, no game-visible completion.
    pub prefetch_chunks: u32,
    /// zstd: the split group this job is a child of (zstd_split), or
    /// INVALID_INDEX.
    pub split_group: u32,
}
impl VirtualAioSlot {
    pub(crate) const EMPTY: Self = Self {
        request: SceKernelAioRWRequest::EMPTY,
        file_id: 0,
        next: INVALID_INDEX,
        pipeline_index: INVALID_INDEX,
        generation: 0,
        priority: 0,
        work_class: PackWorkClass::Balanced,
        wait_notified: false,
        phase: VirtualAioPhase::Free,
        cancel_requested: AtomicBool::new(false),
        completion_state: 0,
        return_value: 0,
        submit_ns: 0,
        parked_ns: 0,
        park_kind: 0,
        requeued_ns: 0,
        prefetch_chunks: 0,
        split_group: INVALID_INDEX,
    };
}

pub(crate) struct VirtualAioGroupSlot {
    pub children: [SceKernelAioSubmitId; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
    pub generation: u16,
    pub child_count: u16,
    pub delete_result: c_int,
    pub active: bool,
    pub wait_notified: bool,
    pub has_native_children: bool,
    /// zstd: split-read state; `split.count == 0` for a plain group.
    pub split: SplitGroup,
}
impl VirtualAioGroupSlot {
    pub(crate) const EMPTY: Self = Self {
        children: [0; SCE_KERNEL_AIO_REQUEST_NUM_MAX],
        generation: 0,
        child_count: 0,
        delete_result: 0,
        active: false,
        wait_notified: false,
        has_native_children: false,
        split: SplitGroup::EMPTY,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PackHandle {
    pub fd: c_int,
    pub pins: u32,
    pub last_use: u64,
    pub payload_begin: u64,
    pub payload_end: u64,
    pub opening: bool,
}
impl PackHandle {
    pub(crate) const EMPTY: Self = Self {
        fd: -1,
        pins: 0,
        last_use: 0,
        payload_begin: 0,
        payload_end: 0,
        opening: false,
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheEntryState {
    Free,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy)]
pub(crate) struct CacheEntry {
    pub key_hash: u64,
    pub physical_offset: u64,
    pub stored_size: u32,
    pub raw_size: u32,
    pub page_start: u32,
    pub page_count: u32,
    pub pin_count: u32,
    pub hash_next_plus_one: u32,
    pub free_next: u32,
    pub pack_id: u16,
    pub state: CacheEntryState,
    pub referenced: bool,
    pub error: c_int,
}
impl CacheEntry {
    pub(crate) const EMPTY: Self = Self {
        key_hash: 0,
        physical_offset: 0,
        stored_size: 0,
        raw_size: 0,
        page_start: 0,
        page_count: 0,
        pin_count: 0,
        hash_next_plus_one: 0,
        free_next: INVALID_INDEX,
        pack_id: 0,
        state: CacheEntryState::Free,
        referenced: false,
        error: 0,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct TouchEntry {
    pub key_hash: u64,
    pub count: u8,
}
impl TouchEntry {}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalCacheEntryState {
    Free,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalCacheEntry {
    pub key_hash: u64,
    pub physical_offset: u64,
    pub size: u32,
    pub page_start: u32,
    pub page_count: u32,
    pub pin_count: u32,
    pub hash_next_plus_one: u32,
    pub free_next: u32,
    pub pack_id: u16,
    pub state: PhysicalCacheEntryState,
    pub referenced: bool,
    pub error: c_int,
}
impl PhysicalCacheEntry {
    pub(crate) const EMPTY: Self = Self {
        key_hash: 0,
        physical_offset: 0,
        size: 0,
        page_start: 0,
        page_count: 0,
        pin_count: 0,
        hash_next_plus_one: 0,
        free_next: INVALID_INDEX,
        pack_id: 0,
        state: PhysicalCacheEntryState::Free,
        referenced: false,
        error: 0,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalCacheLease {
    pub entry: u32,
    pub data: *mut u8,
    pub loader: bool,
    pub error: c_int,
}
impl PhysicalCacheLease {
    pub(crate) const EMPTY: Self = Self {
        entry: INVALID_INDEX,
        data: null_mut(),
        loader: false,
        error: 0,
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalCacheAcquireKind {
    Bypass,
    Ready,
    Load,
    Pending,
    Failed,
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalCacheAcquireResult {
    pub kind: PhysicalCacheAcquireKind,
    pub lease: PhysicalCacheLease,
}
impl PhysicalCacheAcquireResult {
    pub(crate) const EMPTY: Self = Self {
        kind: PhysicalCacheAcquireKind::Bypass,
        lease: PhysicalCacheLease::EMPTY,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalCachePublication {
    pub lease: *mut PhysicalCacheLease,
    pub error: c_int,
}
impl PhysicalCachePublication {
    pub(crate) const EMPTY: Self = Self {
        lease: null_mut(),
        error: 0,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalCacheAcquireBatchItem {
    pub result: *mut PhysicalCacheAcquireResult,
    pub offset: u64,
    pub size: u32,
    pub pack_id: u16,
}
impl PhysicalCacheAcquireBatchItem {
    pub(crate) const EMPTY: Self = Self {
        result: null_mut(),
        offset: 0,
        size: 0,
        pack_id: 0,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PipelineMandatoryPage {
    pub acquired: PhysicalCacheAcquireResult,
    pub offset: u64,
    pub size: u32,
    pub request_index: u32,
    pub staging_offset: u32,
    pub pack_id: u16,
    /// Read-extension page (page_plan.rs): cache fill only, no task reads it.
    pub extension: bool,
}
impl PipelineMandatoryPage {
    pub(crate) const EMPTY: Self = Self {
        acquired: PhysicalCacheAcquireResult::EMPTY,
        offset: 0,
        size: 0,
        request_index: INVALID_INDEX,
        staging_offset: INVALID_INDEX,
        pack_id: u16::MAX,
        extension: false,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct CacheLease {
    pub entry: u32,
    pub data: *mut u8,
    pub loader: bool,
    pub error: c_int,
}
impl CacheLease {
    pub(crate) const EMPTY: Self = Self {
        entry: INVALID_INDEX,
        data: null_mut(),
        loader: false,
        error: 0,
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheAcquireKind {
    Bypass,
    Ready,
    Load,
    Pending,
    Failed,
}

#[derive(Clone, Copy)]
pub(crate) struct CacheAcquireResult {
    pub kind: CacheAcquireKind,
    pub lease: CacheLease,
}
impl CacheAcquireResult {
    pub(crate) const EMPTY: Self = Self {
        kind: CacheAcquireKind::Bypass,
        lease: CacheLease::EMPTY,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct WorkerContext {
    pub index: u32,
    pub thread: ScePthread,
    pub decoded_scratch: *mut u8,
    pub decoded_scratch_size: usize,
    /// zstd: this worker's zstd decoder, made with the worker and kept until
    /// pack shutdown, so there is one per worker and no other decoder.
    pub decoder: *mut ampr_codec::ZstdDecoder,
    pub started: bool,
}
impl WorkerContext {
    pub(crate) const EMPTY: Self = Self {
        index: 0,
        thread: null_mut(),
        decoded_scratch: null_mut(),
        decoded_scratch_size: 0,
        decoder: null_mut(),
        started: false,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct PipelineIoRange {
    pub offset: u64,
    pub length: u32,
    pub io_page_size: u32,
    pub pack_id: u16,
}
impl PipelineIoRange {
    pub(crate) const EMPTY: Self = Self {
        offset: 0,
        length: 0,
        io_page_size: 0,
        pack_id: u16::MAX,
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheWaitDomain {
    Decoded,
    Physical,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineStep {
    Ready,
    YieldIo,
    YieldCache,
    YieldFd,
    Complete,
    Failed,
}

/// Physical-window state of one in-progress logical read; retained across
/// native AIO completion, any worker may resume its decode continuation.
pub(crate) struct ReadPipelineContext {
    pub next_free: u32,
    pub owner: u32,
    pub io_scratch: *mut u8,
    pub io_scratch_size: usize,
    pub io_window_offset: u64,
    pub io_window_size: u32,
    pub io_window_pack_id: u16,
    pub io_window_valid: bool,
    pub io_window_data: *const u8,
    pub io_range: PipelineIoRange,
    pub active: bool,
    pub task_index: usize,
    pub task_count: usize,
    pub decoded_lease: CacheLease,
    pub io_pages: [PhysicalCacheAcquireResult; PACK_PIPELINE_MAX_IO_PAGES],
    pub io_page_count: usize,
    pub mandatory_pages: [PipelineMandatoryPage; PACK_MANDATORY_GROUP_MAX_PAGES],
    pub mandatory_page_count: usize,
    pub mandatory_task_end: usize,
    pub mandatory_skip_task: usize,
    pub mandatory_requests: [SceKernelAioRWRequest; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub mandatory_results: [SceKernelAioResult; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub mandatory_request_uses_scratch: [bool; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub mandatory_fd_pack_ids: [u16; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub mandatory_fds: [c_int; PACK_MANDATORY_GROUP_MAX_REQUESTS],
    pub mandatory_request_count: usize,
    pub mandatory_fd_count: usize,
    pub mandatory_plan_active: bool,
    pub pack_fd: c_int,
    pub native_request: SceKernelAioRWRequest,
    pub native_result: SceKernelAioResult,
    pub cache_wait_epoch: u64,
    pub cache_wait_bucket: u16,
    pub cache_wait_domain: CacheWaitDomain,
    pub fd_wait_epoch: u64,
    pub fd_budget_wait_epoch: u64,
    pub native_io_error: c_int,
    pub native_completion_ready: bool,
    pub native_accepted: bool,
    pub native_submitted: bool,
    /// Physical backing reads this pipeline added to PACK_DISK_INFLIGHT (readahead.rs).
    pub disk_inflight: u32,
}
impl ReadPipelineContext {
    pub(crate) const EMPTY: Self = Self {
        next_free: INVALID_INDEX,
        owner: INVALID_INDEX,
        io_scratch: null_mut(),
        io_scratch_size: 0,
        io_window_offset: 0,
        io_window_size: 0,
        io_window_pack_id: u16::MAX,
        io_window_valid: false,
        io_window_data: null(),
        io_range: PipelineIoRange::EMPTY,
        active: false,
        task_index: 0,
        task_count: 0,
        decoded_lease: CacheLease::EMPTY,
        io_pages: [PhysicalCacheAcquireResult::EMPTY; PACK_PIPELINE_MAX_IO_PAGES],
        io_page_count: 0,
        mandatory_pages: [PipelineMandatoryPage::EMPTY; PACK_MANDATORY_GROUP_MAX_PAGES],
        mandatory_page_count: 0,
        mandatory_task_end: 0,
        mandatory_skip_task: usize::MAX,
        mandatory_requests: [SceKernelAioRWRequest::EMPTY; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        mandatory_results: [SceKernelAioResult::EMPTY; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        mandatory_request_uses_scratch: [false; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        mandatory_fd_pack_ids: [0; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        mandatory_fds: [0; PACK_MANDATORY_GROUP_MAX_REQUESTS],
        mandatory_request_count: 0,
        mandatory_fd_count: 0,
        mandatory_plan_active: false,
        pack_fd: -1,
        native_request: SceKernelAioRWRequest::EMPTY,
        native_result: SceKernelAioResult::EMPTY,
        cache_wait_epoch: 0,
        cache_wait_bucket: 0,
        cache_wait_domain: CacheWaitDomain::Decoded,
        fd_wait_epoch: 0,
        fd_budget_wait_epoch: 0,
        native_io_error: 0,
        native_completion_ready: false,
        native_accepted: false,
        native_submitted: false,
        disk_inflight: 0,
    };
}

/// RAII admission of one submission: `new(state)` bumps `active_submissions` under `PACK_M` unless
/// `submissions_closed`; `Drop` decrements and notifies `SUBMIT_CV` at zero.
/// Holds a raw pointer so the caller keeps using `state` meanwhile.
pub(crate) struct PackSubmission {
    pub state: *mut PackState,
    pub admitted: bool,
}

// ---- PackState, data only -----------------------------------------------------
// Non-zero defaults `pack_state_create` (state.rs) must apply in place on the
// zeroed storage: every array element = its type's `EMPTY` (virtual_directories,
// virtual_aio, pipelines, pack_handles, cache_entries, physical_cache_entries;
// the others are all-zero), queue_head/queue_tail =
// prefetch_head/prefetch_tail = INVALID_INDEX,
// decoded_cache_target_bytes = AMPR_EMU_PACK_DECODED_CACHE_BYTES,
// physical_cache_target_bytes = AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES,
// requested_workers = AMPR_EMU_PACK_WORKERS, latency_reserve_workers =
// AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS, pipeline_free_head = cache_free_head =
// physical_cache_free_head = INVALID_INDEX, tick = 1. Never build a whole
// PackState by value (several MB; worker stacks are small).
pub(crate) struct PackState {
    pub active_submissions: u32, // PACK_M, including singular groups.
    pub submissions_closed: bool,

    pub manifest_base: *mut c_void,
    pub manifest_bytes: usize,
    pub core_view: AmprPackCoreView,
    pub header: *const AmprPackIndexHeader,
    pub files: *const AmprPackFileRecord,
    pub chunks: *const AmprPackChunkRecord,
    pub packs: *const AmprPackDataRecord,
    pub strings: *const c_char,
    pub strings_bytes: usize,
    pub packed_file_order: *mut u32,
    pub packed_file_count: u32,

    pub virtual_fds: [VirtualFdSlot; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS],
    pub virtual_fd_cursor: u32,
    pub virtual_directories: [VirtualDirectorySlot; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS],
    pub virtual_directory_cursor: u32,
    pub virtual_aio: [VirtualAioSlot; AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS],
    pub virtual_aio_cursor: u32,
    pub virtual_aio_groups: [VirtualAioGroupSlot; AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS],
    pub virtual_aio_group_cursor: u32,
    pub queue_head: [[u32; PACK_WORK_CLASS_COUNT]; 3],
    pub queue_tail: [[u32; PACK_WORK_CLASS_COUNT]; 3],
    pub queue_depth: [u32; PACK_WORK_CLASS_COUNT],
    pub queue_pick_counter: u32,
    pub aio_completion_epoch: u64,
    /// Read-ahead jobs not yet started (linked by `next`), and the chunks of
    /// all read-ahead jobs in flight (readahead.rs).
    pub prefetch_head: u32,
    pub prefetch_tail: u32,
    pub prefetch_chunks_inflight: u32,

    pub decoded_cache_target_bytes: usize,
    pub physical_cache_target_bytes: usize,
    pub requested_workers: u32,
    pub latency_reserve_workers: u32,
    pub runtime_profile_loaded: bool,
    pub profile_decoded_bytes: usize, // Immutable after manifest publication.
    pub profile_physical_bytes: usize,
    pub workers: [WorkerContext; AMPR_EMU_PACK_WORKER_CAPACITY],
    pub pipelines: [ReadPipelineContext; AMPR_EMU_PACK_PIPELINE_SLOTS],
    pub pipeline_free_head: u32,
    pub pipeline_capacity: u32,
    pub cache_waiter_count: u32,
    pub fd_waiter_count: u32,
    pub workers_started: u32,
    pub worker_capacity: u32,
    pub pipeline_active_count: u32,

    pub pack_handles: [PackHandle; AMPR_EMU_PACK_MAX_PACKS],
    pub open_pack_count: u32,
    pub opening_pack_count: u32,
    pub tick: u64,

    pub cache_base: *mut u8,
    pub cache_bytes: usize,
    pub cache_page_count: u32,
    pub cache_page_bitmap: [u64; PACK_CACHE_BITMAP_WORDS],
    pub cache_entries: [CacheEntry; AMPR_EMU_PACK_CACHE_ENTRY_CAP],
    pub cache_free_head: u32,
    pub cache_hash_heads: [u32; AMPR_EMU_PACK_CACHE_HASH_BUCKETS],
    pub cache_page_cursor: u32,
    pub cache_clock: u32,
    pub touches: [TouchEntry; AMPR_EMU_PACK_TOUCH_TABLE_SIZE],

    pub physical_cache_base: *mut u8,
    pub physical_cache_bytes: usize,
    pub physical_cache_page_count: u32,
    pub physical_cache_page_bitmap: [u64; PACK_PHYSICAL_CACHE_BITMAP_WORDS],
    pub physical_cache_entries: [PhysicalCacheEntry; AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP],
    pub physical_cache_free_head: u32,
    pub physical_cache_hash_heads: [u32; AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS],
    pub physical_cache_page_cursor: u32,
    pub physical_cache_clock: u32,
}

// ---- sync state ---------------------------------------------------------------
// Locks, condvars and atomics of the pack runtime, kept outside PackState.

pub(crate) static PACK_M: Mutex = Mutex::new();
/// Cursor operations and close on the same synthetic descriptor.
pub(crate) static VIRTUAL_FD_MUTEXES: [Mutex; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS] =
    [const { Mutex::new() }; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS];
pub(crate) static CACHE_MUTEX: Mutex = Mutex::new();
pub(crate) static PHYSICAL_CACHE_MUTEX: Mutex = Mutex::new();
/// Cold manifest publication (may include large index I/O).
pub(crate) static MANIFEST_MUTEX: Mutex = Mutex::new();
pub(crate) static DIRECTORY_TABLE_MUTEX: Mutex = Mutex::new();
pub(crate) static DIRECTORY_MUTEXES: [Mutex; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS] =
    [const { Mutex::new() }; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS];
pub(crate) static QUEUE_CV: Condvar = Condvar::new();
pub(crate) static AIO_CV: Condvar = Condvar::new();
pub(crate) static SUBMIT_CV: Condvar = Condvar::new();
pub(crate) static CACHE_CVS: [Condvar; PACK_CACHE_WAIT_BUCKET_COUNT] =
    [const { Condvar::new() }; PACK_CACHE_WAIT_BUCKET_COUNT];
pub(crate) static MANIFEST_CV: Condvar = Condvar::new();
pub(crate) static LOAD_STATE: AtomicU32 = AtomicU32::new(PACK_LOAD_UNINITIALIZED);
pub(crate) static PROFILE_STARTED_WORKERS: AtomicU32 = AtomicU32::new(0);
pub(crate) static PACK_FD_PROGRESS_EPOCH: AtomicU64 = AtomicU64::new(1);
pub(crate) static PACK_FD_WAITER_COUNT: AtomicU32 = AtomicU32::new(0);
pub(crate) static WORKER_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub(crate) static DECODED_CACHE_PUBLICATION_EPOCH: [AtomicU64; PACK_CACHE_WAIT_BUCKET_COUNT] =
    [const { AtomicU64::new(0) }; PACK_CACHE_WAIT_BUCKET_COUNT];
pub(crate) static PHYSICAL_CACHE_PUBLICATION_EPOCH: [AtomicU64; PACK_CACHE_WAIT_BUCKET_COUNT] =
    [const { AtomicU64::new(0) }; PACK_CACHE_WAIT_BUCKET_COUNT];

// ---- global state -------------------------------------------------------------
// Zeroed .bss storage, initialized in place by pack_state_create (state.rs), which
// publishes g_pack_state and sets g_pack_state_init 0 -> 1 -> 2.
// `pack_state()` (state.rs) returns `*mut PackState`; see its comment for why.

pub(crate) static g_pack_state: AtomicPtr<PackState> = AtomicPtr::new(null_mut());
pub(crate) static g_pack_state_storage: SyncCell<MaybeUninit<PackState>> =
    SyncCell::new(MaybeUninit::zeroed());
pub(crate) static g_pack_state_init: AtomicU32 = AtomicU32::new(0);
