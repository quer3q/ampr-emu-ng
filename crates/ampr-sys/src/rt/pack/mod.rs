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
//!   `AMPR_PACK_FILE_PACKED`, `INVALID_INDEX`).
//! - The PackState mutexes, condvars and atomics live in separate statics
//!   (see "sync state"), so lock guards never borrow PackState:
//!   `PACK_M`, `CACHE_CVS[i]`, etc.
//! - Detour targets (`*_emul`) keep the C ABI; runtime helpers use Rust calls.
//! - Telemetry timestamps are not implemented: `pack_telemetry_usecs()`
//!   returns 0. Debug counters go through `stats::*` (no-ops unless
//!   `mem_report`).
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
pub(crate) use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering,
};

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
    ampr_index_get_entry_view, ampr_index_get_entry_view_path, ampr_index_resolve_path_to_id,
    ampr_pack_core_chunk_shift, ampr_pack_core_make_task, ampr_pack_core_mount,
    ampr_pack_core_task_count,
    ampr_pack_core_validate_logical_file, ampr_pack_crc32, AmprPackBlockReadTask,
    AmprPackChunkView, AmprPackCoreView, Lz4Manifest, Stat,
};
pub(crate) use crate::cache_ffi::{
    ampr_rust_cache_chunk_key_hash, ampr_rust_cache_find_page_run, ampr_rust_cache_mark_pages,
    ampr_rust_cache_wait_bucket,
};
pub(crate) use crate::handle_ffi::{
    ampr_rust_virtual_decode, ampr_rust_virtual_encode, ampr_rust_virtual_next_generation,
};
pub(crate) use crate::overlay_ffi::{
    ampr_rust_overlay_build_order, ampr_rust_overlay_directory_range,
    ampr_rust_overlay_folded_hash, ampr_rust_overlay_normalize_path,
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
unsafe extern "C" {
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
// zstd: directories walk the zstd file order (`packed_order`, rt/pack/
// directories.rs), not the AMPRPAK4 `build_packed_file_order`.
mod state;
pub(crate) use state::*;
mod manifest;
pub(crate) use manifest::*;
mod caches;
pub(crate) use caches::*;
mod leases;
pub(crate) use leases::*;
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
/// mmap of a packed file (both formats) through a disk cache copy (hook ids
/// 96, 97).
pub(crate) mod mmap;
/// `AMPR_ZSTD_MMAP=1`: decode-on-access mappings and their fault handler.
/// zstd only; an LZ4 mapping takes the disk cache copy in `mmap`.
pub(crate) mod mmap_fault;
/// A multi-chunk packed read split into parallel child jobs (aio.rs).
mod zstd_split;
pub(crate) use zstd_split::*;
/// Pkg mode: pack 0 read straight from the .pkg `/app0/kraken.image` names.
mod pkg;
pub(crate) use pkg::*;

// ---- pack format ----

/// Pack format of this title, chosen once at module_start before any hook
/// installs (`select_pack_format`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum PackFormat {
    /// No packs: loose files only, the v0.2.0 hook set.
    Plain = 0,
    /// AMPRPAK4 manifest and AMPRDAT3 volumes.
    Lz4 = 1,
    /// AMPRZPK1 index and AMPRZDT1 volumes.
    Zstd = 2,
    /// AMPRPAK4 manifest whose pack 0 is the title's .pkg (pkg.rs).
    Pkg = 3,
}

impl PackFormat {
    pub(crate) const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Lz4,
            2 => Self::Zstd,
            3 => Self::Pkg,
            _ => Self::Plain,
        }
    }

    /// Name in the load notice, `/metrics` and the black box.
    pub(crate) const fn label(self) -> &'static [u8] {
        match self {
            Self::Plain => b"plain",
            Self::Lz4 => b"lz4",
            Self::Zstd => b"zstd",
            Self::Pkg => b"pkg",
        }
    }

    pub(crate) const fn is_zstd(self) -> bool {
        matches!(self, Self::Zstd)
    }

    pub(crate) const fn is_pkg(self) -> bool {
        matches!(self, Self::Pkg)
    }

    pub(crate) const fn has_packs(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

static PACK_FORMAT: AtomicU8 = AtomicU8::new(PackFormat::Plain as u8);

#[inline(always)]
pub(crate) fn pack_format() -> PackFormat {
    PackFormat::from_u8(PACK_FORMAT.load(Ordering::Relaxed))
}

/// zstd packs (AMPRZPK1) only. Its `else` branches are the AMPRPAK4 code
/// and keep a plain title too: a sceAmpr call loads the manifest on demand
/// whatever the stat at module_start saw (any stat error reads as Plain).
#[inline(always)]
pub(crate) fn zstd_mode() -> bool {
    pack_format().is_zstd()
}

/// Pkg mode: pack 0 is the .pkg `/app0/kraken.image` names (pkg.rs).
#[inline(always)]
pub(crate) fn pkg_mode() -> bool {
    pack_format().is_pkg()
}

/// True when this title ships packs of any format. Only such a title can
/// have files with no physical copy, so only it gets the hooks past the
/// shared 78 (rt/hook.rs `hook_enabled`), the eager index load in
/// module_start and the mmap cache sweep. A title with no packs keeps the
/// v0.2.0 behavior.
#[inline(always)]
pub(crate) fn packs_present() -> bool {
    pack_format().has_packs()
}

/// True when one-based `file_id` names a packed file, one with no physical
/// copy that only a virtual fd can serve. zstd: the id has a record in the
/// AMPRIDX3 projection (zstd.rs). LZ4: its AMPRPAK4 record (record index `file_id - 1`)
/// carries `AMPR_PACK_FILE_PACKED`. False when the manifest is not loaded or
/// the id is out of range. Lock-free, so the open hooks and the debug
/// probes can call it. `_reader` is the proof that the caller holds the
/// manifest gate: every caller goes on to read the manifest and holds one
/// `ManifestReader` across both.
pub(crate) fn file_id_is_packed(_reader: &ManifestReader, file_id: u32) -> bool {
    if zstd_mode() {
        return zstd::zstd_entry(file_id).is_some();
    }
    let state = g_pack_state.load(Ordering::Acquire);
    if file_id == 0 || state.is_null() || LOAD_STATE.load(Ordering::Acquire) != PACK_LOAD_READY {
        return false;
    }
    unsafe { state::lz4_file(state, file_id - 1) }
        .is_some_and(|f| f.flags & AMPR_PACK_FILE_PACKED != 0)
}

// ---- manifest reader guard ----

/// Counts the hook threads that read the manifest (LZ4 `header`/`files`/
/// `core_view`, the zstd mount and projection) without a `PackSubmission`.
/// Hooks stay installed while `ampr_pack_shutdown` runs (module_stop
/// uninstalls them after it), so without this count a reader that passed
/// the READY check could still load from storage that
/// `release_manifest_storage` has freed. A lock would cost every open and
/// stat a mutex; two atomic RMWs do not.
///
/// Contract: a reader calls `ReaderGate::enter` before its first manifest
/// load and keeps the returned `ManifestReader` until its last one. A
/// refused enter means "manifest not loaded". Shutdown closes the gate first
/// and, before it frees the manifest, waits with no lock held until the
/// count is zero. A reader must not wait while holding the guard on anything
/// that only shutdown can release after its wait; waiting on MANIFEST_CV is
/// allowed because shutdown sets the stop flag and wakes it before the wait.
pub(crate) struct ReaderGate {
    readers: AtomicU32,
    closed: AtomicBool,
}

impl ReaderGate {
    pub(crate) const fn new() -> Self {
        Self {
            readers: AtomicU32::new(0),
            closed: AtomicBool::new(false),
        }
    }

    /// The increment comes before the closed check and both are SeqCst, so
    /// either shutdown sees this reader in its count or this reader sees the
    /// gate closed; never neither.
    pub(crate) fn enter(&'static self) -> Option<ManifestReader> {
        self.readers.fetch_add(1, Ordering::SeqCst);
        if self.closed.load(Ordering::SeqCst) {
            self.readers.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(ManifestReader { gate: self })
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn readers(&self) -> u32 {
        self.readers.load(Ordering::SeqCst)
    }

    /// Spins until no reader holds the gate, calling `pause` between checks.
    /// True once the count is zero; false when `pause` returns false (the
    /// host test bounds the wait this way, shutdown never gives up).
    pub(crate) fn wait_drained(&self, mut pause: impl FnMut() -> bool) -> bool {
        while self.readers() != 0 {
            if !pause() {
                return false;
            }
        }
        true
    }
}

/// RAII hold on a `ReaderGate`; the drop releases it.
pub(crate) struct ManifestReader {
    gate: &'static ReaderGate,
}

impl ManifestReader {
    /// Enters the runtime's manifest gate; None once shutdown has started.
    #[inline]
    pub(crate) fn enter() -> Option<ManifestReader> {
        MANIFEST_READERS.enter()
    }
}

impl Drop for ManifestReader {
    fn drop(&mut self) {
        // Release orders this reader's manifest loads before the
        // decrement that shutdown's SeqCst count load observes.
        self.gate.readers.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) static MANIFEST_READERS: ReaderGate = ReaderGate::new();

/// module_start, before hooks: picks the pack format from the files present.
pub(crate) unsafe fn select_pack_format() {
    type StatFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
    // FreeBSD struct stat is 224 bytes; room to spare.
    let mut st = [0u64; 64];
    // Any stat error reads as absent: the title then gets the plain hook
    // set. Resolved here because `sys::real_posix_stat` reads the stat hook
    // slot, which stays null until the hooks install (rt/hook.rs
    // `FALLBACK_SHARED`).
    let mut exists = |path: &CStr| {
        unsafe { sys::resolve_kernel::<StatFn>(c"stat") }
            .is_some_and(|f| unsafe { f(path.as_ptr(), st.as_mut_ptr().cast()) == 0 })
    };
    // A title without /app0/kraken.image costs one failed open. A pkg
    // title wins over a zstd index also present: its manifest is AMPRPAK4.
    let format = if unsafe { discover_pkg() } {
        PackFormat::Pkg
    } else if exists(zstd::AMPR_EMU_ZSTD_INDEX_PATH) {
        PackFormat::Zstd
    } else if exists(AMPR_EMU_PACK_INDEX_PATH) {
        PackFormat::Lz4
    } else {
        PackFormat::Plain
    };
    PACK_FORMAT.store(format as u8, Ordering::Relaxed);
    let packs = packs_present();
    // A crash between a cache file's create and unlink leaves it named.
    // Every pack format maps packed files through that cache, so sweep for
    // any; a title with no packs never creates cache files.
    if packs && mmap::MMAP_MODE != 0 {
        unsafe { mmap::sweep_cache_dir() };
    }
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

pub(crate) const AMPR_PACK_FILE_PACKED: u32 = 1 << 0;
pub(crate) const AMPR_PACK_FILE_STREAMING: u32 = 1 << 2;
pub(crate) const AMPR_PACK_FILE_HOT: u32 = 1 << 3;
pub(crate) const AMPR_PACK_FILE_RANDOM_ACCESS: u32 = ampr_lz4::FILE_RANDOM_ACCESS;

pub(crate) const AMPR_PACK_CHUNK_RAW: u8 = 0;
pub(crate) const AMPR_PACK_CHUNK_LZ4: u8 = 1;
pub(crate) const AMPR_PACK_CHUNK_KRAKEN: u8 = ampr_pkg::CHUNK_KRAKEN;
pub(crate) const AMPR_PACK_CHUNK_KRAKEN_FULL: u8 = ampr_pkg::CHUNK_KRAKEN_FULL;
pub(crate) const AMPR_PACK_CHUNK_SHARED: u8 = 1 << 0;
pub(crate) const AMPR_PACK_CHUNK_STREAMING: u8 = 1 << 1;

// Packed records are copied out of the mounted manifest (state.rs
// `lz4_file`, `lz4_pack`); read fields by value (`{ rec.field }`), never
// take references to them.
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
    /// A page cache size the runtime no longer has; still in the format and
    /// added to the decoded cache (manifest.rs `load_runtime_profile`).
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
        manifest: None,
        // All-zero is a valid header value (plain integers and arrays).
        header: unsafe { core::mem::zeroed() },
    };
}

// ---- configuration (AMPR_PACK_ENABLE=1, AMPR_DIRECTORY_OVERLAY=1)
// Plain read-only opens of packed files get a virtual fd in both formats
// (slots.rs `pack_open_flags_supported`). Upstream 0.4.2.1 assumed LZ4 packs
// hold only files the game reads through AMPR; titles also plain open() them.

pub(crate) const AMPR_EMU_PACK_INDEX_PATH: &CStr = c"/app0/ampr_assets.index";
/// `AMPR_EMU_PACK_INDEX_PATH ".runtime"` (AMPRPAK4 only; zstd keeps the defaults).
pub(crate) const AMPR_EMU_PACK_RUNTIME_PROFILE_PATH: &CStr = c"/app0/ampr_assets.index.runtime";
pub(crate) const AMPR_EMU_PACK_ROOT_PATH: &CStr = c"/app0";
pub(crate) const AMPR_EMU_PACK_LOGICAL_ROOT_PATH: &CStr = c"/app0";

/// Directories open at once through the index (a directory missing on disk,
/// or opened with O_DIRECTORY). The numbers are plain, `DIRECTORY_BASE + slot`
/// (below). The only bound on a title's own directory opens is the kernel's
/// 259-entry fd table, and the most seen at once is 7-8, so 256 is far beyond
/// anything measured.
pub(crate) const AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS: usize = 256;
/// Decode workers, from the Makefile's `AMPR_PACK_WORKERS` (default 4, also
/// outside the Makefile): each has a 1 MiB decode buffer from prepare to
/// shutdown; threads start at 1 and grow on demand (worker.rs). Decode took
/// ~0.21 cores on a zstd title, and 4 against 8 workers gave the same game
/// wait per read, 312 vs 315 us (debug /metrics).
pub(crate) const AMPR_EMU_PACK_WORKERS: u32 = match option_env!("AMPR_PACK_WORKERS") {
    Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
    None => 4,
};
const _: () = assert!(
    AMPR_EMU_PACK_WORKERS >= 1 && AMPR_EMU_PACK_WORKERS as usize <= AMPR_EMU_PACK_WORKER_CAPACITY
);
pub(crate) const AMPR_EMU_PACK_WORKER_CAPACITY: usize = 16;
/// Sequential read-ahead window in chunks, from the Makefile's
/// `AMPR_PACK_READAHEAD_CHUNKS` (Makefile default 0, off; 32, a ~1-1.5 MiB
/// prefetch run, when built outside the Makefile); 0 disables read-ahead
/// (readahead.rs).
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
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Pipeline slots, from the Makefile's `AMPR_PACK_PIPELINES` (default 12,
/// at most AMPR_EMU_PACK_PIPELINE_MAX) in both builds: each pipeline keeps a
/// 2 MiB I/O window from the worker start to shutdown, from the pool under
/// the Buffer ledger, which holds 12 of them (rt/index_memory.rs); only
/// pipelines whose window was granted are used (worker.rs `buffer_split`).
/// Work waits in the queue while all pipelines are busy (schedule.rs). The
/// debug build starts up to `tune::pipelines()` of them; built outside the
/// Makefile it keeps room for 32.
pub(crate) const AMPR_EMU_PACK_PIPELINE_SLOTS: usize =
    if super::tune::ON && option_env!("AMPR_PACK_PIPELINES").is_none() {
        AMPR_EMU_PACK_PIPELINE_MAX
    } else {
        super::tune::RELEASE_PIPELINES as usize
    };
/// Most pipeline slots a build can have (the debug `high` profile's 32).
pub(crate) const AMPR_EMU_PACK_PIPELINE_MAX: usize = 32;
const _: () = assert!(
    super::tune::RELEASE_PIPELINES >= 1
        && super::tune::RELEASE_PIPELINES as usize <= AMPR_EMU_PACK_PIPELINE_SLOTS
        && AMPR_EMU_PACK_PIPELINE_SLOTS <= AMPR_EMU_PACK_PIPELINE_MAX
);
pub(crate) const AMPR_EMU_PACK_WORKER_PRIORITY: c_int = 384;
pub(crate) const AMPR_EMU_PACK_WORKER_AFFINITY: u64 = 0x3f;
pub(crate) const AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS: u32 = 0;
pub(crate) const AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES: u64 = 64 * 1024;
pub(crate) const AMPR_EMU_PACK_BULK_READ_MIN_BYTES: u64 = 256 * 1024;
pub(crate) const AMPR_EMU_PACK_IO_STAGING_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_PREAD_MAX_BYTES: u64 = AMPR_EMU_PACK_IO_STAGING_BYTES;
/// Packed files open at once. The slots serve the title's own opens and the
/// runtime's cached ones alike: the APR fd cache opens packed files through
/// the same allocator (rt/fd_cache.rs `open_indexed_or_real`), so up to
/// `CACHE_CAP` (45) of these belong to the runtime. A closed slot is reused,
/// so this is the number of packed files open at one time, not a lifetime
/// limit. A retail title never holds more than the kernel's 259 fd table
/// entries open at once, plus the runtime's cached ones (`CACHE_CAP`, 45):
/// 304 at most. One title held 220 during its world load; 320 covers the
/// worst case and is 45% above that measured peak. A title that needs more
/// already ran degraded on a console (it opened until EMFILE and skipped what
/// failed), and hitting this limit gives it the same outcome.
pub(crate) const AMPR_EMU_PACK_VIRTUAL_FD_SLOTS: usize = 320;
/// First synthetic packed-file descriptor: a packed fd is `BASE + slot`, in
/// `448..768`. That range is above the kernel's effective fd table and below
/// the strictest title limit:
/// - the kernel's table tops out at 259 on the two titles measured (248
///   `open("/dev/null")` calls succeeded, highest fd 258), despite
///   `RLIMIT_NOFILE` reporting 13,952, so a real descriptor can never land in
///   the synthetic range;
/// - one title rejects fd >= 1024: base 1000 failed on its first packed fd
///   at 1024, while base 768 and 512 boot. Another accepted 170 packed fds
///   at 1024..1193, so 1024 is that title's own limit, not a system one.
///
/// The range needs no kernel descriptor, so the title keeps its whole fd table
/// for real files. The runtime serves reads, seeks, fstat, close, AIO and mmap
/// on the synthetic number. 448 leaves 189 numbers above the last real fd, so
/// a table up to 73% larger than the measured one still cannot land a real
/// descriptor in the range, where it would be served as packed data.
pub(crate) const AMPR_EMU_PACK_VIRTUAL_FD_BASE: usize = 448;
/// First synthetic directory descriptor: a directory fd is `BASE + slot`, in
/// `768..1024`, right above the packed range and under the same title limit
/// (fd >= 1024 is rejected by one title). Directory handles were tagged
/// values near 1.7 billion before. Without a generation in the number, a
/// closed slot's number is reused like a kernel fd; the live flag
/// (`VIRTUAL_DIRECTORY_LIVE`) sends a number with no open slot to the kernel.
pub(crate) const AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE: usize = 768;
/// Highest real fd measured: the kernel table is 259 entries (numbers
/// `0..=258`) on the two titles measured.
pub(crate) const KERNEL_FD_TABLE_TOP: usize = 258;
const _: () = assert!(
    AMPR_EMU_PACK_VIRTUAL_FD_BASE > KERNEL_FD_TABLE_TOP
        && AMPR_EMU_PACK_VIRTUAL_FD_BASE + AMPR_EMU_PACK_VIRTUAL_FD_SLOTS
            <= AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE
        && AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE + AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS <= 1024
);
pub(crate) const AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS: usize = 256;
pub(crate) const AMPR_EMU_PACK_MAX_PACKS: usize = 1024;
/// Pack volume descriptors open at once, at most one per volume; the least
/// recently used closes to open another. A zstd title with 28 volumes kept
/// all 18 of the old cap busy (debug /metrics).
pub(crate) const AMPR_EMU_PACK_OPEN_PACK_FD_CAP: u32 = 32;
/// 64 MiB (both builds; debug `decoded_mib`), the whole 64 MiB Cache
/// ledger: the only pack cache. Exact reads with 64 MiB decoded gave 11-14%
/// lower game wait per read than 32 + 32 MiB page reads on two zstd titles
/// (debug /metrics). At 16 MiB a zstd title (debug /metrics, 150 s)
/// re-decoded an evicted chunk in 73% of its misses: 29.9 GB decoded for
/// 6.56 GB read. It is off when less than its 16 MiB minimum is left under
/// the Cache cap.
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_CACHE_ENTRY_CAP: usize = 8192;
pub(crate) const AMPR_EMU_PACK_CACHE_PAGE_SHIFT: u32 = 14;
pub(crate) const AMPR_EMU_PACK_CACHE_HASH_BUCKETS: usize = 16384;
pub(crate) const AMPR_EMU_PACK_TOUCH_TABLE_SIZE: usize = 16384;
/// Largest pack index file the loader registers (pack/manifest.rs
/// `load_manifest`, fstat size). The file is paged, not loaded whole, but
/// registering it still costs a page table of 2 B per 16 KiB page from the
/// Index ledger (64 KiB at this size) and validation reads the whole payload
/// for its CRC through the page cache before the file and chunk counts are
/// checked; this bounds both for a corrupt or foreign file. The largest
/// index measured is 25.2 MiB.
pub(crate) const AMPR_EMU_PACK_INDEX_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const AMPR_EMU_PACK_MAX_FILES: u64 = 2_000_000;
pub(crate) const AMPR_EMU_PACK_MAX_CHUNKS: u64 = 16_000_000;

// ---- derived constants --------------------------------------------------------

pub(crate) const PACK_MAX_BLOCK_BYTES: usize = 1 << AMPR_PACK_BLOCK_SHIFT_MAX;
pub(crate) const PACK_PIPELINE_IO_BYTES: usize = AMPR_EMU_PACK_IO_STAGING_BYTES as usize;
pub(crate) const PACK_CACHE_PAGE_BYTES: usize = 1 << AMPR_EMU_PACK_CACHE_PAGE_SHIFT;
pub(crate) const PACK_CACHE_MAX_PAGES: usize =
    AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES as usize / PACK_CACHE_PAGE_BYTES;
pub(crate) const PACK_CACHE_BITMAP_WORDS: usize = (PACK_CACHE_MAX_PAGES + 63) / 64;
pub(crate) const INVALID_INDEX: u32 = u32::MAX;
// ampr_format::handles::Kind; the tags live in Rust. Packed and directory fds
// are plain numbers, not tagged handles.
pub(crate) const VIRTUAL_KIND_AIO: u32 = 1;
pub(crate) const VIRTUAL_KIND_AIO_GROUP: u32 = 2;
// `handles::encode` ORs the slot in unmasked and `decode` masks 8 bits, so a
// tagged table past 256 would alias slot 256 onto slot 0.
const _: () = assert!(AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS <= 256);
pub(crate) const PACK_LOAD_UNINITIALIZED: u32 = 0;
pub(crate) const PACK_LOAD_LOADING: u32 = 1;
pub(crate) const PACK_LOAD_READY: u32 = 2;
pub(crate) const PACK_LOAD_UNAVAILABLE: u32 = 3;
pub(crate) const PACK_LOAD_INVALID: u32 = 4;
pub(crate) const PACK_CACHE_WAIT_BUCKET_COUNT: usize = 64;
pub(crate) const DIRECTORY_PHYSICAL_HASH_CAP: usize = 512;
pub(crate) const PACK_WORK_CLASS_COUNT: usize = PackWorkClass::Count as usize;

const _: () = {
    assert!(PACK_CACHE_BITMAP_WORDS == 512);
    assert!(AMPR_EMU_PACK_DECODED_CACHE_BYTES <= AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES);
    assert!(AMPR_EMU_PACK_CACHE_HASH_BUCKETS.is_power_of_two());
    assert!(AMPR_EMU_PACK_TOUCH_TABLE_SIZE.is_power_of_two());
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
pub(crate) type KernelAioWaitSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int, *mut SceKernelUseconds) -> c_int;
pub(crate) type KernelAioWaitFn = unsafe extern "C" fn(
    *mut SceKernelAioSubmitId,
    c_int,
    *mut c_int,
    u32,
    *mut SceKernelUseconds,
) -> c_int;
pub(crate) type KernelAioCancelSingleFn =
    unsafe extern "C" fn(SceKernelAioSubmitId, *mut c_int) -> c_int;
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
pub(crate) static g_real_aio_submit_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_submit: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_poll_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_poll: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_wait_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_wait: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static g_real_aio_cancel_single: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
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
    /// The value returned to the game: `AMPR_EMU_PACK_VIRTUAL_FD_BASE + slot`.
    /// A reused slot returns the same number, like a reused OS fd.
    pub handle: c_int,
    /// First local chunk not yet covered by read-ahead (readahead.rs).
    pub readahead_next: u32,
    pub cursor: u64,
    pub active: bool,
}
impl VirtualFdSlot {
    pub(crate) const EMPTY: Self = Self {
        file_id: 0,
        handle: -1,
        readahead_next: 0,
        cursor: 0,
        active: false,
    };

    /// Open and still the slot of `fd`. A closed slot that has been reused
    /// for another file returns the same number, like a reused OS fd.
    pub(crate) fn holds(&self, fd: c_int) -> bool {
        self.active && self.handle == fd
    }
}

pub(crate) struct VirtualDirectorySlot {
    pub real_fd: c_int,
    pub directory_offset: c_long,
    pub range_begin: u32,
    pub range_end: u32,
    pub virtual_cursor: u32,
    pub physical_hash_count: u32,
    pub path_length: u16,
    pub active: bool,
    pub real_exhausted: bool,
    /// The physical `getdents` failed for good; the rest of the listing is
    /// the packed entries (directories.rs `directory_read_fd`).
    pub real_failed: bool,
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
        path_length: 0,
        active: false,
        real_exhausted: false,
        real_failed: false,
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
    /// A plain group (`sceKernelAioSubmitReadCommands`, aio.rs) holds a
    /// native kernel id: kernel completions do not bump
    /// `aio_completion_epoch`, so `sceKernelAioWaitRequests` must poll it.
    /// Never set on a zstd split group (all children are virtual jobs).
    pub has_native_children: bool,
    /// Split-read state; `split.count == 0` for a plain group.
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
    /// Stale-fd reopen state (leases.rs `PackFdReopen`). Kept across
    /// eviction so a reopened fd keeps its one-retry bound.
    pub reopen: PackFdReopen,
}
impl PackHandle {
    pub(crate) const EMPTY: Self = Self {
        fd: -1,
        pins: 0,
        last_use: 0,
        payload_begin: 0,
        payload_end: 0,
        opening: false,
        reopen: PackFdReopen::Clean,
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
    /// zstd: this worker's zstd decoder, at the start of its 112 KiB
    /// workspace from the Buffer ledger; made when the thread starts and
    /// freed when it leaves (worker.rs `release_worker_decoder`).
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
    pub pack_id: u16,
}
impl PipelineIoRange {
    pub(crate) const EMPTY: Self = Self {
        offset: 0,
        length: 0,
        pack_id: u16::MAX,
    };
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineStep {
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
    pub pack_fd: c_int,
    pub native_request: SceKernelAioRWRequest,
    pub native_result: SceKernelAioResult,
    pub cache_wait_epoch: u64,
    pub cache_wait_bucket: u16,
    /// Key of the decoded chunk this pipeline last parked on (0: none). A
    /// Failed entry serves its error only to the readers that waited on its
    /// load; any other reader drops it and loads again (caches.rs).
    pub decoded_wait_key: u64,
    pub fd_wait_epoch: u64,
    pub fd_budget_wait_epoch: u64,
    pub native_io_error: c_int,
    pub native_completion_ready: bool,
    /// The finished read got EAGAIN from a stale pack fd marked for reopen
    /// (`release_pack_fd_after_read`): retry the job, do not fail it.
    pub fd_reopen_retry: bool,
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
        pack_fd: -1,
        native_request: SceKernelAioRWRequest::EMPTY,
        native_result: SceKernelAioResult::EMPTY,
        cache_wait_epoch: 0,
        cache_wait_bucket: 0,
        decoded_wait_key: 0,
        fd_wait_epoch: 0,
        fd_budget_wait_epoch: 0,
        native_io_error: 0,
        native_completion_ready: false,
        fd_reopen_retry: false,
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
// zeroed storage: every array element = its type's `EMPTY` (virtual_fds,
// virtual_directories, virtual_aio, pipelines, pack_handles, cache_entries;
// the others are all-zero), queue_head/queue_tail =
// prefetch_head/prefetch_tail = INVALID_INDEX, decoded_cache_target_bytes
// and requested_workers from `tune` (in release
// AMPR_EMU_PACK_DECODED_CACHE_BYTES and AMPR_EMU_PACK_WORKERS),
// latency_reserve_workers = AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS,
// pipeline_free_head = cache_free_head = INVALID_INDEX, tick = 1. Never build a whole
// PackState by value (several MB; worker stacks are small).
pub(crate) struct PackState {
    pub active_submissions: u32, // PACK_M, including singular groups.
    pub submissions_closed: bool,

    /// The mounted AMPRPAK4 manifest (read through the index page cache)
    /// and a copy of its header; `header` points at that copy when mounted.
    pub core_view: AmprPackCoreView,
    pub header: *const AmprPackIndexHeader,
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
    pub requested_workers: u32,
    pub latency_reserve_workers: u32,
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
    /// One past the highest entry index ever allocated: the LIFO free list
    /// hands out low indices first, so the CLOCK hand scans only below it.
    pub cache_entry_high_water: u32,
    pub touches: [TouchEntry; AMPR_EMU_PACK_TOUCH_TABLE_SIZE],
}

// ---- sync state ---------------------------------------------------------------
// Locks, condvars and atomics of the pack runtime, kept outside PackState.

pub(crate) static PACK_M: Mutex = Mutex::new();
/// Cursor operations and close on the same packed fd.
pub(crate) static VIRTUAL_FD_MUTEXES: [Mutex; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS] =
    [const { Mutex::new() }; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS];
/// Set while a slot is open. Written only under PACK_M; read lock-free by
/// `decode_virtual_fd`, so a number in the synthetic range with no open slot
/// goes to the kernel without taking PACK_M. A real fd is not expected
/// there (kernel table: 259).
pub(crate) static VIRTUAL_FD_LIVE: [AtomicBool; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS] =
    [const { AtomicBool::new(false) }; AMPR_EMU_PACK_VIRTUAL_FD_SLOTS];
/// Set while a directory slot is open, like `VIRTUAL_FD_LIVE`: written under
/// the slot's DIRECTORY_MUTEXES entry, read lock-free by
/// `decode_virtual_directory_fd`, so a number in `768..1024` with no open slot
/// goes to the kernel without creating or waiting on the pack state.
pub(crate) static VIRTUAL_DIRECTORY_LIVE: [AtomicBool; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS] =
    [const { AtomicBool::new(false) }; AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS];
pub(crate) static CACHE_MUTEX: Mutex = Mutex::new();
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

// ---- global state -------------------------------------------------------------
// Zeroed .bss storage, initialized in place by pack_state_create (state.rs), which
// publishes g_pack_state and sets g_pack_state_init 0 -> 1 -> 2.
// `pack_state()` (state.rs) returns `*mut PackState`; see its comment for why.

pub(crate) static g_pack_state: AtomicPtr<PackState> = AtomicPtr::new(null_mut());
pub(crate) static g_pack_state_storage: SyncCell<MaybeUninit<PackState>> =
    SyncCell::new(MaybeUninit::zeroed());
pub(crate) static g_pack_state_init: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    const FORMATS: [PackFormat; 4] = [
        PackFormat::Plain,
        PackFormat::Lz4,
        PackFormat::Zstd,
        PackFormat::Pkg,
    ];

    #[test]
    fn pack_format_round_trips_through_u8() {
        for f in FORMATS {
            assert_eq!(PackFormat::from_u8(f as u8), f);
        }
        assert_eq!(PackFormat::from_u8(4), PackFormat::Plain);
        assert_eq!(PackFormat::from_u8(u8::MAX), PackFormat::Plain);
    }

    #[test]
    fn pack_format_predicates_per_format() {
        // (zstd, pkg, packs, label): a pkg title is not an LZ4 or zstd one.
        let want: [(bool, bool, bool, &[u8]); 4] = [
            (false, false, false, b"plain"),
            (false, false, true, b"lz4"),
            (true, false, true, b"zstd"),
            (false, true, true, b"pkg"),
        ];
        for (f, w) in FORMATS.into_iter().zip(want) {
            let got = (f.is_zstd(), f.is_pkg(), f.has_packs(), f.label());
            assert_eq!(got, w, "{f:?}");
        }
    }

    #[test]
    fn accessors_follow_the_stored_format() {
        // The host never runs select_pack_format, so the store keeps Plain.
        assert_eq!(pack_format(), PackFormat::Plain);
        assert!(!zstd_mode() && !pkg_mode());
        assert!(!packs_present());
    }

    #[test]
    fn reader_gate_wait_blocks_while_held_and_close_refuses_enter() {
        // A gate of its own: closing the runtime's MANIFEST_READERS would
        // refuse readers in the other tests of this binary.
        static GATE: ReaderGate = ReaderGate::new();
        let reader = GATE.enter().expect("open gate admits a reader");
        assert_eq!(GATE.readers(), 1);
        GATE.close();
        let mut pauses = 0u32;
        let drained = GATE.wait_drained(|| {
            pauses += 1;
            pauses < 1000
        });
        assert!(!drained, "the wait must not finish while a reader holds the gate");
        assert_eq!(pauses, 1000);
        assert!(GATE.enter().is_none(), "a closed gate refuses new readers");
        assert_eq!(GATE.readers(), 1, "a refused enter leaves the count as it was");
        drop(reader);
        assert_eq!(GATE.readers(), 0);
        assert!(GATE.wait_drained(|| false), "an empty gate drains without a pause");
    }
}
