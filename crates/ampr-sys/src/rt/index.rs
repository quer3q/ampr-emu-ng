//! The resident AMPRIDX3 /app0 file index, its runtime builder and the
//! /app0 file hooks. Pure AMPRIDX3 parsing/lookup lives in
//! ampr_format::index{,_key}; the AMPRPAK4 core shim is at the end.
//!
//! Layout:
//! 1. constants, on-disk types, global state: `INDEX_LOCK` + `INDEX_CV` guard
//!    `INDEX` (C++ FileIndexState; `state()`), `PUBLISH` is the lock-free
//!    release publication (C++ g_file_index_publish_state; `published()`),
//!    `WORKSPACE` is the single builder's scratch (serialized by `loading`).
//! 2. key helpers, SDK CPU memory (`sdk_alloc`/`sdk_release`), `ScratchBuffer`,
//!    `PathStack`, `Compact` image helpers, `write_all`/`BufWriter`.
//! 3. `RuntimeBuilder`, /app0 dirent walk (`build_app0_index`),
//!    `load_compact_index`, `ensure_ready_slow`.
//! 4. `ensure_ready`, lock-free resident lookups (`lookup_resident_path`).
//! 5. file hooks `*_emul`, the `ampr_index_*` helpers, the `ampr_pack_core_*` shim.

#![allow(non_snake_case)]

use super::fd_cache::{EntryPath, FileEntryView};
use super::index_file::{pread_fd, BlobSource, FileSource, PathSource, ResidentSource, WINDOW};
use super::index_view::{self, BuildError, ViewMem};
use super::runtime_memory::{
    ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_free,
    ampr_internal_amm_pool_ready_has_capacity, ampr_sdk_cpu_memory_class_name,
    ampr_small_slab_alloc, ampr_small_slab_free,
};
use super::rw;
use super::stats;
use super::sync::{Condvar, Mutex, SyncCell};
use super::sys::*;
use ampr_format::index::{read_layout, Index, Layout};
use ampr_format::source::{Source, PATH_BUF};
use ampr_format::view::{Builder, Hit, Packs, View, NO_CHUNK};
use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering::*};

// ---- constants -------------------------------------------------------------

pub(crate) const APP0_ROOT: &CStr = c"/app0";
pub(crate) const INDEX_PATH: &CStr = c"/app0/ampr_emu.index";
pub(crate) const INDEX_TEMP_PATH: &CStr = c"/app0/ampr_emu.index.tmp";
pub(crate) const INDEX_BACKUP_PATH: &CStr = c"/app0/ampr_emu.index.bak";
pub(crate) const INDEX_MAGIC: [u8; 8] = *b"AMPRIDX3";
pub(crate) const INDEX_VERSION: u32 = 3;
pub(crate) const INDEX_LOAD_WAIT_US: u64 = 500_000;
pub(crate) const KERNEL_PATH_MAX: usize = 1024; // SCE_KERNEL_PATH_MAX
pub(crate) const RUNTIME_PATH_CAPACITY: usize = KERNEL_PATH_MAX + 1;
/// The walk's path buffers and `PathStack` slots: a path the key
/// normalize refuses (1024 bytes or more) is skipped anyway, so a longer
/// buffer (4096 before) only held paths that were dropped after the copy.
pub(crate) const INDEX_MAX_PATH: usize = RUNTIME_PATH_CAPACITY;
pub(crate) const FILEID_INVALID: u32 = u32::MAX; // SCE_AMPR_APR_FILEID_INVALID
/// alignof(std::max_align_t), the C++ default allocation alignment.
const MAX_ALIGN: usize = 16;

/// `AmprSharedSdkCpuMemoryClass`: only transient allocations remain (the
/// persistent class, which could create the pool, had no caller).
pub(crate) const MEM_TRANSIENT: u8 = 1;

// ---- on-disk AMPRIDX3 types ------------------------------------------------

/// `CompactFileIndexEntry`: one fixed record.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CompactEntry {
    pub path_offset: u32,
    pub path_length: u32,
    pub size: u64,
    pub mtime: i64,
}
const _: () = assert!(core::mem::size_of::<CompactEntry>() == 24);

/// `CompactFileIndexHeader`: the 48-byte file header.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CompactHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub entry_size: u32,
    pub entry_count: u64,
    pub path_bytes: u64,
    pub hash_offset: u64,
    pub hash_slot_size: u32,
    pub hash_slot_count: u32,
}
const _: () = assert!(core::mem::size_of::<CompactHeader>() == 48);

/// `CompactFileIndexHashSlot`: one open-addressed hash slot.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct HashSlot {
    pub hash: u64,
    pub index_plus_one: u32,
    pub reserved: u32,
}
const _: () = assert!(core::mem::size_of::<HashSlot>() == 16);

/// `CompactIndexLoadResult`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadResult {
    Loaded,
    Missing,
    Invalid,
    Memory,
    /// The index file exists but an open or read failed with an I/O error
    /// (a USB hiccup, EINTR past the retry bound). Not a reason to rebuild:
    /// a rebuild would replace a shipped index whose file IDs packs and
    /// traces depend on. The load is retried on the next ensure_ready that
    /// may build (`allow_build` and autobuild on) once its backoff has
    /// passed (`next_retry_at`); other calls return unavailable. Without packs, after `UNREADABLE_LOAD_LIMIT` in a row it is
    /// built in memory, never installed; with packs it is only retried.
    Unreadable,
}

/// Consecutive Unreadable loads before a build replaces the index in memory.
/// Three retries ride out a USB hiccup without retrying I/O forever.
const UNREADABLE_LOAD_LIMIT: u32 = 3;
/// Unreadable loads in a row; only the single `loading` thread touches it.
static UNREADABLE_LOADS: AtomicU32 = AtomicU32::new(0);

/// The name of a load result in the black box (`blackbox::idx`).
#[cfg(feature = "mem_report")]
fn load_result_name(r: LoadResult) -> &'static [u8] {
    match r {
        LoadResult::Loaded => b"Loaded",
        LoadResult::Missing => b"Missing",
        LoadResult::Invalid => b"Invalid",
        LoadResult::Memory => b"Memory",
        LoadResult::Unreadable => b"Unreadable",
    }
}

/// The Unreadable run length after a load with `result`.
fn next_unreadable_loads(count: u32, result: LoadResult) -> u32 {
    if result == LoadResult::Unreadable {
        count.saturating_add(1)
    } else {
        0
    }
}

/// Backoff after an Unreadable load: the first retry waits 100 ms and each
/// one after doubles it, up to 2 s. Without it a title with packs, which
/// only retries, ran the open, fstat and view build again on every
/// `ensure_ready(true)` caller while the file stayed unreadable. Without
/// packs the three loads before the walk build span 300 ms.
const UNREADABLE_RETRY_NS: u64 = 100_000_000;
const UNREADABLE_RETRY_MAX_NS: u64 = 2_000_000_000;
/// Monotonic ns before which no load is retried; 0 after any other result.
/// Written by the single `loading` thread before it clears `loading` under
/// `INDEX_LOCK`, read under that lock.
static RETRY_AT_NS: AtomicU64 = AtomicU64::new(0);

/// When the next load may run after `run` Unreadable loads in a row, the
/// last at `now`; 0 (at once) after a run of 0 or with no clock.
fn next_retry_at(now: u64, run: u32) -> u64 {
    if run == 0 || now == 0 {
        return 0;
    }
    let shift = (run - 1).min(16);
    now.saturating_add((UNREADABLE_RETRY_NS << shift).min(UNREADABLE_RETRY_MAX_NS))
}

/// Whether a load may run at `now`; always with no clock (`now` 0).
fn retry_due(now: u64, retry_at: u64) -> bool {
    retry_at == 0 || now == 0 || now >= retry_at
}

// ---- global state ----------------------------------------------------------

/// The file index (C++ FileIndexState compact* fields): the compiled view
/// of `ampr_emu.index` (rt/index_view.rs), built once in one pass over the
/// file and resident in one Index ledger block, plus the source its paths
/// are read from afterwards. A path is read only to confirm a hash match
/// or to hand a path out; sizes and mtimes come from the view's columns.
pub(crate) struct Compact {
    pub count: usize,
    /// The finished view; None until `finish`, and on a cleared index.
    pub view: Option<View<'static>>,
    /// The view between the build and `finish`, so the pack index can be
    /// joined into it before it is published.
    pub builder: Option<Builder<'static>>,
    /// The ledger blocks `view` and `builder` live in; the transient one
    /// only until `finish`.
    mem: Option<ViewMem>,
    /// Where the view reads paths.
    pub paths: Paths,
    pub available: bool,
    /// The build walk saw a symlink and did not index it, so misses are not
    /// authoritative (see `miss_is_authoritative`). Only a runtime build sets
    /// it; a loaded index file carries no such flag.
    pub links: bool,
}

/// The paths of the loaded index: the index file on an fd kept open for
/// the life of the module, or, for an image the walk built and could not
/// install, its path blob copied into the Index ledger.
pub(crate) enum Paths {
    None,
    File(PathSource),
    Blob(BlobSource<'static>),
}

impl ampr_format::source::Source for Paths {
    fn len(&self) -> u64 {
        match self {
            Paths::None => 0,
            Paths::File(f) => f.len(),
            Paths::Blob(b) => b.len(),
        }
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
        match self {
            Paths::None => Err(ampr_format::Error::Truncated),
            Paths::File(f) => f.read_at(at, out),
            Paths::Blob(b) => b.read_at(at, out),
        }
    }
}

impl Compact {
    pub const EMPTY: Self = Self {
        count: 0,
        view: None,
        builder: None,
        mem: None,
        paths: Paths::None,
        available: false,
        links: false,
    };
}

/// `FileIndexState` minus its mutex/condvar (`INDEX_LOCK`/`INDEX_CV`).
pub(crate) struct FileIndexState {
    pub loaded: bool,
    pub load_attempted: bool,
    pub loading: bool,
    pub available: bool,
    pub compact: Compact,
}

pub(crate) static INDEX_LOCK: Mutex = Mutex::new();
pub(crate) static INDEX_CV: Condvar = Condvar::new();
pub(crate) static INDEX: SyncCell<FileIndexState> = SyncCell::new(FileIndexState {
    loaded: false,
    load_attempted: false,
    loading: false,
    available: false,
    compact: Compact::EMPTY,
});

/// The index state. Caller holds `INDEX_LOCK` (or is the sole builder).
#[allow(clippy::mut_from_ref)]
pub(crate) unsafe fn state() -> &'static mut FileIndexState {
    unsafe { &mut *INDEX.get() }
}

/// `FileIndexPublishState`; a release store of `PUB_AVAILABLE` makes every
/// `Compact` pointer and count immutable for the life of the module
/// (`release_resident_index` does not free it).
pub(crate) const PUB_PENDING: u8 = 0;
pub(crate) const PUB_AVAILABLE: u8 = 1;
pub(crate) const PUB_UNAVAILABLE: u8 = 2;
pub(crate) static PUBLISH: AtomicU8 = AtomicU8::new(PUB_PENDING);

/// The published image for lock-free readers, once `PUB_AVAILABLE`.
pub(crate) fn published() -> Option<&'static Compact> {
    (PUBLISH.load(Acquire) == PUB_AVAILABLE).then(|| unsafe { &(*INDEX.get()).compact })
}

/// module_stop, after the hooks are gone: lookups after this see no index.
/// The view and its path source are not freed: `published()` hands out a
/// reference without a lock or count, so a thread still inside a lookup
/// may read them,
/// and the pool is the PRX's .bss, gone with the module.
pub(crate) unsafe fn release_resident_index() {
    let _g = INDEX_LOCK.lock();
    PUBLISH.store(PUB_UNAVAILABLE, Release);
    unsafe { state() }.available = false;
}

/// The index fd kept open for path reads (`Paths::File`), or -1. The
/// close hooks refuse it (rt/pack/aio.rs): a game that closes that number
/// (a double close, a stale fd) would otherwise close the index under
/// the lookups, and once the number is reused a path pread returns another
/// file's bytes, read as a false authoritative ENOENT.
static KEPT_FD: AtomicI32 = AtomicI32::new(-1);

/// Whether `fd` is the index fd the lookups read paths from.
#[inline]
pub(crate) fn is_kept_index_fd(fd: c_int) -> bool {
    fd >= 0 && KEPT_FD.load(Relaxed) == fd
}

/// `App0IndexBuildWorkspace`: path scratch for the single runtime builder.
pub(crate) struct BuildWorkspace {
    pub dir: [u8; INDEX_MAX_PATH],
    pub path: [u8; INDEX_MAX_PATH],
    pub path_key: [u8; INDEX_MAX_PATH],
}

/// `FileIndexState::loading` serializes the only user.
pub(crate) static WORKSPACE: SyncCell<BuildWorkspace> = SyncCell::new(BuildWorkspace {
    dir: [0; INDEX_MAX_PATH],
    path: [0; INDEX_MAX_PATH],
    path_key: [0; INDEX_MAX_PATH],
});

// ---- key and arithmetic helpers ----------------------------------------------

/// `normalize_app0_path_key_result`: Ok((len, had_trailing_separator)) or
/// Err(EFAULT/EINVAL/ENAMETOOLONG). `out` gets the NUL-terminated key.
pub(crate) unsafe fn normalize_key_result(
    path: *const c_char,
    out: &mut [u8],
) -> Result<(usize, bool), c_int> {
    unsafe { normalize_key_full(path, out) }.map(|k| (k.len, k.had_trailing_separator))
}

/// `normalize_key_result` with the whole `Key` (its `plain` flag too).
pub(crate) unsafe fn normalize_key_full(
    path: *const c_char,
    out: &mut [u8],
) -> Result<ampr_format::index_key::Key, c_int> {
    use ampr_format::index_key::{normalize, KeyError, PATH_MAX};
    let Some(first) = out.first_mut() else {
        return Err(EFAULT);
    };
    *first = 0;
    if path.is_null() {
        return Err(EFAULT);
    }
    let p = path.cast::<u8>();
    if !matches!(unsafe { *p }, b'/' | b'\\') {
        return Err(EINVAL);
    }
    let len = (0..PATH_MAX)
        .find(|&i| unsafe { *p.add(i) } == 0)
        .ok_or(ENAMETOOLONG)?;
    match normalize(unsafe { core::slice::from_raw_parts(p, len) }, out) {
        Ok(k) => Ok(k),
        Err(KeyError::Invalid) => Err(EINVAL),
        Err(KeyError::NameTooLong) => Err(ENAMETOOLONG),
    }
}

/// `normalize_app0_path_key`: the key length, or None for an unusable path.
pub(crate) unsafe fn normalize_key(path: *const c_char, out: &mut [u8]) -> Option<usize> {
    unsafe { normalize_key_result(path, out) }
        .ok()
        .map(|(len, _)| len)
}

/// Bytes of a NUL-terminated string; null reads as "".
pub(crate) unsafe fn cstr_bytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        &[]
    } else {
        unsafe { CStr::from_ptr(p) }.to_bytes()
    }
}

/// `ampr_round_up_page_size`: usize::MAX on overflow.
pub(crate) fn round_up_page(v: usize) -> usize {
    let mask = SCE_KERNEL_PAGE_SIZE - 1;
    if v > usize::MAX - mask {
        usize::MAX
    } else {
        (v + mask) & !mask
    }
}

/// `ampr_align_up_u64`: u64::MAX on overflow, `v` for alignment 0.
pub(crate) fn align_up_u64(v: u64, a: u64) -> u64 {
    if a == 0 {
        return v;
    }
    let mask = a - 1;
    if v > u64::MAX - mask {
        u64::MAX
    } else {
        (v + mask) & !mask
    }
}

// ---- SDK CPU memory ----------------------------------------------------------

/// `ampr_alloc_sdk_cpu_memory`: small slab first, then the internal AMM pool,
/// which this never creates.
pub(crate) unsafe fn sdk_alloc(size: usize, class: u8) -> *mut c_void {
    if size == 0 {
        return null_mut();
    }
    let name = unsafe { ampr_sdk_cpu_memory_class_name(class) };
    let mut slot = 0usize;
    let small = unsafe { ampr_small_slab_alloc(size, MAX_ALIGN, &mut slot, name, false) };
    if !small.is_null() {
        return small;
    }
    let mapped = round_up_page(size);
    if mapped == usize::MAX {
        return null_mut();
    }
    if !unsafe { ampr_internal_amm_pool_ready_has_capacity(mapped, MAX_ALIGN) } {
        super::index_memory::note_pool_failure();
        return null_mut();
    }
    let mut got = 0usize;
    unsafe { ampr_internal_amm_pool_alloc(mapped, &mut got, name, false, MAX_ALIGN) }
}

/// `ampr_release_sdk_cpu_memory`.
pub(crate) unsafe fn sdk_release(base: *mut c_void, size: usize, class: u8) {
    if base.is_null() || size == 0 || round_up_page(size) == usize::MAX {
        return;
    }
    let name = unsafe { ampr_sdk_cpu_memory_class_name(class) };
    if !unsafe { ampr_small_slab_free(base, name, null_mut()) } {
        unsafe { ampr_internal_amm_pool_free(base, name) };
    }
}

/// A file index build buffer (file count, path bytes, directories) from the
/// pool's Index ledger; null when refused, after the one-time index notice:
/// the build fails and the title runs without the index.
unsafe fn build_alloc(bytes: usize, tag: &CStr) -> *mut u8 {
    unsafe { super::index_memory::index_alloc(bytes, MAX_ALIGN, tag.as_ptr()) }
}

/// Frees a `build_alloc` result (null is a no-op).
pub(crate) unsafe fn title_free(base: *mut u8, tag: &CStr) {
    unsafe { super::index_memory::index_free(base.cast(), tag.as_ptr()) };
}

/// `AmprSdkCpuScratchBuffer`: an owned SDK CPU allocation, released on drop.
pub(crate) struct ScratchBuffer {
    base: *mut u8,
    size: usize,
    class: u8,
}

impl ScratchBuffer {
    pub const fn new() -> Self {
        Self {
            base: null_mut(),
            size: 0,
            class: MEM_TRANSIENT,
        }
    }
    pub fn allocate(&mut self, size: usize, class: u8) -> bool {
        self.reset();
        if size == 0 {
            return false;
        }
        self.class = class;
        self.base = unsafe { sdk_alloc(size, class) }.cast();
        if self.base.is_null() {
            return false;
        }
        self.size = size;
        true
    }
    pub fn reset(&mut self) {
        if !self.base.is_null() {
            unsafe { sdk_release(self.base.cast(), self.size, self.class) };
        }
        // Field writes, not `*self = Self::new()`: an assignment drops the
        // old value first, and `Drop::drop` calls this function.
        self.base = null_mut();
        self.size = 0;
        self.class = MEM_TRANSIENT;
    }
    pub fn data(&self) -> *mut u8 {
        self.base
    }
    pub fn valid(&self) -> bool {
        !self.base.is_null()
    }
}

impl Drop for ScratchBuffer {
    fn drop(&mut self) {
        self.reset();
    }
}

/// `AmprIndexPathStack`: LIFO of NUL-terminated paths in fixed
/// `INDEX_MAX_PATH` (1025 B) slots, grown by doubling (from 256, 256 KiB)
/// in index memory (rt/index_memory.rs):
/// it grows with the directories waiting to be scanned.
pub(crate) struct PathStack {
    base: *mut u8,
    bytes: usize,
    capacity: usize,
    count: usize,
}

impl PathStack {
    const SLOT: usize = INDEX_MAX_PATH;

    pub const fn new() -> Self {
        Self {
            base: null_mut(),
            bytes: 0,
            capacity: 0,
            count: 0,
        }
    }
    fn slot(&self, i: usize) -> *mut u8 {
        unsafe { self.base.add(i * Self::SLOT) }
    }
    /// Pushes a non-empty path shorter than INDEX_MAX_PATH.
    pub fn push(&mut self, path: &[u8]) -> bool {
        let len = path.len();
        if len == 0 || len >= INDEX_MAX_PATH {
            return false;
        }
        let want = if self.capacity == 0 {
            256
        } else {
            self.capacity * 2
        };
        if self.count == self.capacity && !self.grow(want) {
            return false;
        }
        unsafe {
            let s = self.slot(self.count);
            core::ptr::copy_nonoverlapping(path.as_ptr(), s, len);
            *s.add(len) = 0;
        }
        self.count += 1;
        true
    }
    /// Pops into `out` (NUL-terminated); false if empty or `out` too small.
    pub fn pop(&mut self, out: &mut [u8]) -> bool {
        if out.is_empty() || self.count == 0 {
            return false;
        }
        self.count -= 1;
        let s = self.slot(self.count);
        let len = unsafe { CStr::from_ptr(s.cast()) }.to_bytes().len();
        if len + 1 > out.len() {
            out[0] = 0;
            return false;
        }
        unsafe { core::ptr::copy_nonoverlapping(s, out.as_mut_ptr(), len + 1) };
        true
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    fn grow(&mut self, cap: usize) -> bool {
        if cap <= self.capacity || cap > usize::MAX / Self::SLOT {
            return false;
        }
        let bytes = cap * Self::SLOT;
        let base = unsafe { build_alloc(bytes, c"apr.index.build.dirs") };
        if base.is_null() {
            return false;
        }
        if !self.base.is_null() && self.count != 0 {
            unsafe { core::ptr::copy_nonoverlapping(self.base, base, self.count * Self::SLOT) };
        }
        self.release();
        (self.base, self.bytes, self.capacity) = (base, bytes, cap);
        true
    }
    fn release(&mut self) {
        unsafe { title_free(self.base, c"apr.index.build.dirs") };
        (self.base, self.bytes, self.capacity) = (null_mut(), 0, 0);
    }
}

impl Drop for PathStack {
    fn drop(&mut self) {
        self.count = 0;
        self.release();
    }
}

// ---- resident image helpers ----------------------------------------------------

impl Compact {
    /// `clear_compact_file_index_locked`: gives back the view block, the
    /// path blob and the index fd. Never on a published index.
    pub unsafe fn clear(&mut self) {
        self.view = None;
        self.builder = None;
        if let Some(mem) = self.mem.take() {
            // SAFETY: the view and builder of the block are gone above, and
            // an unpublished index has no reader.
            unsafe { mem.free() };
        }
        match core::mem::replace(&mut self.paths, Paths::None) {
            Paths::None => {}
            // Host tests link no libkernel and open no file.
            Paths::File(_f) => {
                // Unguarded before the close, so the number is free to reuse.
                let _ = KEPT_FD.compare_exchange(_f.fd(), -1, Relaxed, Relaxed);
                #[cfg(not(test))]
                unsafe {
                    real_physical_close(_f.fd())
                };
            }
            Paths::Blob(b) => unsafe {
                title_free(b.blob.as_ptr().cast_mut(), c"apr.index.paths.release")
            },
        }
        *self = Self::EMPTY;
    }
    /// `move_compact_file_index_locked(dst=self, src)`: clears `self`,
    /// takes `src`'s view and leaves `src` empty.
    pub unsafe fn move_from(&mut self, src: &mut Compact) {
        unsafe { self.clear() };
        *self = core::mem::replace(src, Self::EMPTY);
    }
    /// The built view made read-only, and the build's transient columns
    /// given back to the Index ledger; a no-op once finished. The pack join
    /// runs before it in a title with packs.
    pub fn finish(&mut self) {
        if let Some(b) = self.builder.take() {
            self.view = Some(b.finish());
            if let Some(mem) = self.mem.as_mut() {
                // SAFETY: the builder is consumed above and the view reads
                // no transient column.
                unsafe { mem.free_scratch() };
            }
        }
    }
    /// The finished view.
    pub fn view(&self) -> Option<View<'static>> {
        self.view
    }
    /// `compact_index_entry_view`: one-based file `id`. Size and mtime come
    /// from the view; the path is read only when `path` is given, copied
    /// there NUL-terminated with `out.path` pointing at it. Without `path`,
    /// `out.path` is null and `out.path_length` 0 (the view keeps no path
    /// lengths). `Io` when the path read failed, which callers must not
    /// report as a missing file.
    pub fn try_entry_view(
        &self,
        id: u32,
        out: &mut FileEntryView,
        path: Option<&mut EntryPath>,
    ) -> ampr_format::Result<()> {
        let v = self.view.ok_or(ampr_format::Error::Invalid)?;
        if id == 0 || id > v.files() {
            return Err(ampr_format::Error::Invalid);
        }
        out.path = null();
        out.path_length = 0;
        if let Some(buf) = path {
            let n = v.path(&self.paths, id, buf)?.len();
            buf[n] = 0;
            out.path = buf.as_ptr().cast();
            out.path_length = n as u32;
        }
        out.size = v.size(id) as usize;
        out.mtime = v.mtime(id);
        Ok(())
    }
}

// ---- buffered kernel writes ------------------------------------------------------

/// `ampr_sce_write_all`.
pub(crate) unsafe fn write_all(fd: c_int, data: &[u8]) -> bool {
    write_all_with(data, |chunk| unsafe {
        sceKernelWrite(fd, chunk.as_ptr().cast(), chunk.len()) as isize
    })
}

/// `write_all` over `write(chunk) -> n` (sceKernelWrite: bytes or an SCE
/// error). Short writes continue and SCE EINTR retries up to
/// `EINTR_RETRY_MAX` times in a row; 0 or any other error fails.
fn write_all_with(data: &[u8], mut write: impl FnMut(&[u8]) -> isize) -> bool {
    let (mut done, mut eintr) = (0usize, 0u32);
    while done < data.len() {
        let n = write(&data[done..]);
        if n == SCE_KERNEL_ERROR_EINTR as isize && eintr < EINTR_RETRY_MAX {
            eintr += 1;
            continue;
        }
        if n <= 0 || n as usize > data.len() - done {
            return false;
        }
        eintr = 0;
        done += n as usize;
    }
    true
}

/// `AmprSceBufferedWriter`: 256 KiB transient buffer in front of sceKernelWrite.
pub(crate) struct BufWriter {
    fd: c_int,
    buf: ScratchBuffer,
    used: usize,
}

/// The index writer's buffer, a fixed pool site (rt/runtime_memory.rs).
pub(crate) const BUF_WRITER_SIZE: usize = 256 * 1024;

impl BufWriter {
    const SIZE: usize = BUF_WRITER_SIZE;

    pub const fn new() -> Self {
        Self {
            fd: -1,
            buf: ScratchBuffer::new(),
            used: 0,
        }
    }
    pub fn open(&mut self, fd: c_int) -> bool {
        self.reset();
        self.fd = fd;
        if fd < 0 || !self.buf.allocate(Self::SIZE, MEM_TRANSIENT) {
            self.fd = -1;
            return false;
        }
        true
    }
    pub fn reset(&mut self) {
        self.buf.reset();
        self.used = 0;
        self.fd = -1;
    }
    pub fn valid(&self) -> bool {
        self.fd >= 0 && self.buf.valid()
    }
    pub fn write(&mut self, mut data: &[u8]) -> bool {
        if !self.valid() {
            return false;
        }
        while !data.is_empty() {
            if self.used == Self::SIZE && !self.flush() {
                return false;
            }
            if self.used == 0 && data.len() >= Self::SIZE {
                return unsafe { write_all(self.fd, data) };
            }
            let take = (Self::SIZE - self.used).min(data.len());
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf.data().add(self.used), take)
            };
            self.used += take;
            data = &data[take..];
        }
        true
    }
    /// Writes the buffered bytes; they stay buffered when the write fails.
    pub fn flush(&mut self) -> bool {
        if !self.valid() {
            return false;
        }
        if self.used == 0 {
            return true;
        }
        let ok = unsafe {
            write_all(
                self.fd,
                core::slice::from_raw_parts(self.buf.data(), self.used),
            )
        };
        if ok {
            self.used = 0;
        }
        ok
    }
}

// ---- part 2: runtime builder, /app0 walk, load and ensure_ready -----------------

const O_RDONLY: c_int = 0x0;
const O_WRONLY: c_int = 0x1;
const O_CREAT: c_int = 0x200;
const O_TRUNC: c_int = 0x400;
const O_DIRECTORY: c_int = 0x20000;
const S_IRWU: SceKernelMode = 0o600; // SCE_KERNEL_S_IRWU
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
/// AMPR_EMU_COMMAND_LOG_PATH / AMPR_EMU_DEBUG_LOG_PATH (excluded from the index).
const COMMAND_LOG_PATH: &CStr = c"/app0/ampr_commands.bin";
const DEBUG_LOG_PATH: &CStr = c"/app0/ampr_emu.log";

/// The runtime's own /app0 files, which the walk never indexes. Each is
/// its own normalized key (lowercase, single `/`), so a key compares to it
/// as bytes; a test checks that.
const SKIPPED_KEYS: [&CStr; 5] = [
    INDEX_PATH,
    INDEX_TEMP_PATH,
    INDEX_BACKUP_PATH,
    COMMAND_LOG_PATH,
    DEBUG_LOG_PATH,
];

/// Whether `key`, a normalized key or a spelling of one (any ASCII case),
/// is one of `SKIPPED_KEYS`.
fn is_skipped_key(key: &[u8]) -> bool {
    let folded_eq = |p: &[u8]| {
        p.len() == key.len()
            && p.iter()
                .zip(key)
                .all(|(&a, &b)| a == ampr_format::folded(b))
    };
    SKIPPED_KEYS.iter().any(|p| folded_eq(p.to_bytes()))
}
/// AMPR_EMU_APP0_INDEX_AUTOBUILD.
pub(crate) const APP0_INDEX_AUTOBUILD: bool = true;

/// FreeBSD 11 amd64 `struct stat` (== SceKernelStat).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Stat {
    pub st_dev: u32,
    pub st_ino: u32,
    pub st_mode: u16,
    pub st_nlink: u16,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u32,
    pub st_atim: SceKernelTimespec,
    pub st_mtim: SceKernelTimespec,
    pub st_ctim: SceKernelTimespec,
    pub st_size: i64,
    pub st_blocks: i64,
    pub st_blksize: i32,
    pub st_flags: u32,
    pub st_gen: u32,
    pub st_lspare: i32,
    pub st_birthtim: SceKernelTimespec,
}
const _: () = {
    assert!(size_of::<Stat>() == 120);
    assert!(core::mem::offset_of!(Stat, st_mtim) == 40);
    assert!(core::mem::offset_of!(Stat, st_size) == 72);
    assert!(core::mem::offset_of!(Stat, st_blksize) == 88);
};

impl Stat {
    fn is_dir(&self) -> bool {
        self.st_mode & S_IFMT == S_IFDIR
    }
    pub(crate) fn is_reg(&self) -> bool {
        self.st_mode & S_IFMT == S_IFREG
    }
    fn is_lnk(&self) -> bool {
        self.st_mode & S_IFMT == S_IFLNK
    }
}

/// FreeBSD 11 `struct dirent` header; `d_name` follows at offset 8.
#[repr(C)]
#[derive(Clone, Copy)]
struct DirentHeader {
    d_fileno: u32,
    d_reclen: u16,
    d_type: u8,
    d_namlen: u8,
}
const DIRENT_HEADER: usize = size_of::<DirentHeader>();
const _: () = assert!(DIRENT_HEADER == 8);

/// `AmprRuntimeIndexBuilder`: records and path blob in transient SDK CPU
/// memory, sorted, hashed and written to INDEX_TEMP_PATH, then renamed.
pub(crate) struct RuntimeBuilder {
    records: *mut CompactEntry,
    record_bytes: usize,
    record_capacity: usize,
    paths: *mut u8,
    path_capacity: usize,
    entry_count: u64,
    path_bytes: u64,
    failed: bool,
    /// A symlink was skipped (see `Compact::links`).
    links: bool,
}

impl RuntimeBuilder {
    pub const fn new() -> Self {
        Self {
            records: null_mut(),
            record_bytes: 0,
            record_capacity: 0,
            paths: null_mut(),
            path_capacity: 0,
            entry_count: 0,
            path_bytes: 0,
            failed: false,
            links: false,
        }
    }

    pub fn open(&mut self) -> bool {
        unsafe { real_posix_unlink(INDEX_TEMP_PATH.as_ptr()) };
        true
    }

    pub fn add_file(&mut self, path: &[u8], size: usize, mtime: i64) -> bool {
        let len = path.len();
        if len == 0
            || len as u64 > u32::MAX as u64
            || self.path_bytes + len as u64 + 1 > u32::MAX as u64
            || self.entry_count >= FILEID_INVALID as u64 - 1
        {
            self.failed = true;
            return false;
        }
        if !self.ensure_record_capacity(self.entry_count as usize + 1)
            || !self.ensure_path_capacity(self.path_bytes as usize + len + 1)
        {
            self.failed = true;
            return false;
        }
        unsafe {
            *self.records.add(self.entry_count as usize) = CompactEntry {
                path_offset: self.path_bytes as u32,
                path_length: len as u32,
                size: size as u64,
                mtime,
            };
            let dst = self.paths.add(self.path_bytes as usize);
            core::ptr::copy_nonoverlapping(path.as_ptr(), dst, len);
            *dst.add(len) = 0;
        }
        self.entry_count += 1;
        self.path_bytes += len as u64 + 1;
        true
    }
}

impl RuntimeBuilder {
    /// Doubling growth from `start`; None on overflow.
    fn grown(cur: usize, start: usize, min: usize) -> Option<usize> {
        let mut cap = if cur != 0 { cur } else { start };
        while cap < min {
            cap = cap.checked_mul(2)?;
        }
        Some(cap)
    }

    fn ensure_record_capacity(&mut self, min: usize) -> bool {
        if min <= self.record_capacity {
            return true;
        }
        let Some(cap) = Self::grown(self.record_capacity, 4096, min) else {
            return false;
        };
        let Some(bytes) = cap.checked_mul(size_of::<CompactEntry>()) else {
            return false;
        };
        let base: *mut CompactEntry =
            unsafe { build_alloc(bytes, c"apr.index.build.records") }.cast();
        if base.is_null() {
            return false;
        }
        if !self.records.is_null() && self.entry_count != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.records, base, self.entry_count as usize)
            };
        }
        self.release_records();
        (self.records, self.record_bytes, self.record_capacity) = (base, bytes, cap);
        true
    }

    fn ensure_path_capacity(&mut self, min: usize) -> bool {
        if min <= self.path_capacity {
            return true;
        }
        let Some(cap) = Self::grown(self.path_capacity, 1024 * 1024, min) else {
            return false;
        };
        let base = unsafe { build_alloc(cap, c"apr.index.build.paths") };
        if base.is_null() {
            return false;
        }
        if !self.paths.is_null() && self.path_bytes != 0 {
            unsafe { core::ptr::copy_nonoverlapping(self.paths, base, self.path_bytes as usize) };
        }
        self.release_paths();
        (self.paths, self.path_capacity) = (base, cap);
        true
    }

    fn release_records(&mut self) {
        if self.records.is_null() {
            return;
        }
        unsafe { title_free(self.records.cast(), c"apr.index.build.records") };
        (self.records, self.record_bytes, self.record_capacity) = (null_mut(), 0, 0);
    }

    fn release_paths(&mut self) {
        if self.paths.is_null() {
            return;
        }
        unsafe { title_free(self.paths, c"apr.index.build.paths") };
        (self.paths, self.path_capacity) = (null_mut(), 0);
    }

    fn release_buffers(&mut self) {
        self.release_records();
        self.release_paths();
    }
}

impl Drop for RuntimeBuilder {
    fn drop(&mut self) {
        self.release_buffers();
    }
}

impl RuntimeBuilder {
    /// `save_final`: sort, hash, write the temp image, install it; always
    /// releases the record/path buffers. True only when INDEX_PATH was
    /// installed; a built image that cannot (or, `!install`, must not) be
    /// installed is adopted into `idx`.
    pub fn save_final(&mut self, idx: &mut FileIndexState, install: bool) -> bool {
        let ok = !self.failed && self.entry_count != 0 && unsafe { self.save_image(idx, install) };
        self.release_buffers();
        ok
    }

    /// Builds the image in transient memory, writes it to INDEX_TEMP_PATH and
    /// installs it. If the write or install fails (read-only /app0), the image
    /// is adopted into `idx` in memory so the scan is not lost.
    unsafe fn save_image(&mut self, idx: &mut FileIndexState, install: bool) -> bool {
        let count = self.entry_count as usize;
        let records = unsafe { core::slice::from_raw_parts_mut(self.records, count) };
        let paths = self.paths;
        let order = |l: &CompactEntry, r: &CompactEntry| unsafe {
            ampr_format::index_key::compare(
                core::slice::from_raw_parts(
                    paths.add(l.path_offset as usize),
                    l.path_length as usize,
                ),
                core::slice::from_raw_parts(
                    paths.add(r.path_offset as usize),
                    r.path_length as usize,
                ),
            )
        };
        records.sort_unstable_by(order);
        // Paths that fold to one key (case or separator variants) would make
        // the reload reject the image; keep the first of each run. Their path
        // bytes stay in the blob unreferenced.
        let mut kept = 0usize;
        for i in 0..count {
            let Some(&cur) = records.get(i) else { break };
            let dup = kept
                .checked_sub(1)
                .and_then(|p| records.get(p))
                .is_some_and(|prev| order(prev, &cur) == core::cmp::Ordering::Equal);
            if !dup {
                if let Some(slot) = records.get_mut(kept) {
                    *slot = cur;
                }
                kept += 1;
            }
        }
        self.entry_count = kept as u64;
        let count = kept;

        let Some(l) = image_layout(count, self.path_bytes) else {
            return false;
        };
        let image = unsafe { build_alloc(l.map_bytes, c"apr.index.build.image") };
        if image.is_null() {
            return false;
        }
        let built = unsafe {
            let out = core::slice::from_raw_parts_mut(image, l.map_bytes);
            let records = core::slice::from_raw_parts(self.records.cast::<u8>(), l.records_bytes);
            let paths = core::slice::from_raw_parts(self.paths, self.path_bytes as usize);
            fill_image(out, &l, records, paths)
        };
        self.release_buffers();
        let file = unsafe { core::slice::from_raw_parts(image, l.file_bytes) };
        let ok = built
            && install
            && unsafe { write_temp_index(file) }
            && unsafe { install_temp_index() };
        // An installed image is read back from the file by `save_final`'s
        // caller; one that could not be installed is served from memory.
        if built && !ok {
            unsafe { adopt_compact_index(idx, image, l.file_bytes) };
        } else {
            unsafe { title_free(image, c"apr.index.build.image") };
        }
        ok
    }
}

/// Geometry of a compact index image of `count` records and `path_bytes`
/// path bytes, as `save_image` builds it and `read_compact` maps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImageLayout {
    pub count: usize,
    pub path_bytes: usize,
    pub records_bytes: usize,
    pub path_at: usize,
    pub hash_at: usize,
    pub slot_count: usize,
    pub file_bytes: usize,
    /// `file_bytes` page-rounded: the build buffer.
    pub map_bytes: usize,
}

/// None when the counts overflow the format.
pub(crate) fn image_layout(count: usize, path_bytes: u64) -> Option<ImageLayout> {
    let slot_count = ampr_format::index::slot_count_for(count)?;
    if slot_count > u32::MAX as usize || slot_count > usize::MAX / size_of::<HashSlot>() {
        return None;
    }
    let records_bytes = count.checked_mul(size_of::<CompactEntry>())?;
    let path_at = size_of::<CompactHeader>().checked_add(records_bytes)?;
    let path_end = (path_at as u64).checked_add(path_bytes)?;
    let hash_at = align_up_u64(path_end, align_of::<HashSlot>() as u64);
    let hash_bytes = slot_count as u64 * size_of::<HashSlot>() as u64;
    let file_bytes = hash_at.checked_add(hash_bytes)?;
    if hash_at < path_end || file_bytes > usize::MAX as u64 {
        return None;
    }
    let map_bytes = round_up_page(file_bytes as usize);
    (map_bytes != usize::MAX).then_some(ImageLayout {
        count,
        path_bytes: path_bytes as usize,
        records_bytes,
        path_at,
        hash_at: hash_at as usize,
        slot_count,
        file_bytes: file_bytes as usize,
        map_bytes,
    })
}

/// Zeroes `image` and fills header, records, paths and hash slots; false
/// (nothing written) when `image` or the inputs do not match `l`.
pub(crate) fn fill_image(image: &mut [u8], l: &ImageLayout, records: &[u8], paths: &[u8]) -> bool {
    if image.len() != l.map_bytes || records.len() != l.records_bytes || paths.len() != l.path_bytes
    {
        return false;
    }
    let header = CompactHeader {
        magic: INDEX_MAGIC,
        version: INDEX_VERSION,
        entry_size: size_of::<CompactEntry>() as u32,
        entry_count: l.count as u64,
        path_bytes: l.path_bytes as u64,
        hash_offset: l.hash_at as u64,
        hash_slot_size: size_of::<HashSlot>() as u32,
        hash_slot_count: l.slot_count as u32,
    };
    // SAFETY: CompactHeader is repr(C) plain data.
    let header = unsafe {
        core::slice::from_raw_parts((&raw const header).cast::<u8>(), size_of::<CompactHeader>())
    };
    image.fill(0);
    image[..header.len()].copy_from_slice(header);
    image[header.len()..l.path_at].copy_from_slice(records);
    image[l.path_at..l.path_at + l.path_bytes].copy_from_slice(paths);
    let slots = &mut image[l.hash_at..l.file_bytes];
    ampr_format::index::fill_slots(records, paths, slots).is_ok()
}

/// What a fully resident image costs: records, paths and hash slots past
/// the header, page-rounded (the ledger tests size the index with it).
#[cfg(test)]
pub(crate) fn resident_bytes(l: &ampr_format::index::Layout) -> usize {
    let slots_rel = (l.slots_at - ampr_format::IDX_HEADER as u64) as usize;
    round_up_page(slots_rel + l.slots_len as usize)
}

/// Writes `image` to a fresh INDEX_TEMP_PATH; unlinks it on failure.
unsafe fn write_temp_index(image: &[u8]) -> bool {
    let fd = unsafe {
        real_posix_open(
            INDEX_TEMP_PATH.as_ptr(),
            O_WRONLY | O_CREAT | O_TRUNC,
            S_IRWU,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut w = BufWriter::new();
    let mut ok = w.open(fd) && w.write(image) && w.flush();
    w.reset();
    if unsafe { real_physical_close(fd) } < 0 {
        ok = false;
    }
    if !ok {
        unsafe { real_posix_unlink(INDEX_TEMP_PATH.as_ptr()) };
    }
    ok
}

/// Renames INDEX_TEMP_PATH over INDEX_PATH. If the filesystem refuses to
/// replace an existing target, the old index is parked as INDEX_BACKUP_PATH
/// and restored if the second rename fails. A stale backup is removed once
/// the new index is installed.
unsafe fn install_temp_index() -> bool {
    let (tmp, dst, bak) = (
        INDEX_TEMP_PATH.as_ptr(),
        INDEX_PATH.as_ptr(),
        INDEX_BACKUP_PATH.as_ptr(),
    );
    unsafe {
        let mut rc = real_posix_rename(tmp, dst);
        if rc < 0 {
            let mut st = Stat::default();
            let mut old_moved = false;
            if real_posix_stat(dst, (&raw mut st).cast()) == 0 {
                real_posix_unlink(bak);
                old_moved = real_posix_rename(dst, bak) >= 0;
            }
            rc = real_posix_rename(tmp, dst);
            if rc < 0 && old_moved {
                real_posix_rename(bak, dst);
            } else if rc >= 0 && old_moved {
                real_posix_unlink(bak);
            }
        }
        if rc < 0 {
            real_posix_unlink(tmp);
            return false;
        }
        real_posix_unlink(bak);
    }
    true
}

// ---- /app0 directory walk ----------------------------------------------------

/// `ampr_path_name_is_dot_or_dotdot`.
fn is_dot_or_dotdot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// `ampr_path_has_unsupported_index_char`: tab, LF or CR.
fn has_unsupported_index_char(path: &[u8]) -> bool {
    path.iter().any(|&c| matches!(c, b'\t' | b'\n' | b'\r'))
}

/// `ampr_join_dirent_path`: `dir` + '/' (if missing) + `name`, NUL-terminated
/// into `out`; returns the joined length (out[0] = 0 on failure).
fn join_dirent_path(dir: &[u8], name: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    let slash = !dir.is_empty() && dir[dir.len() - 1] != b'/';
    let len = dir.len() + slash as usize + name.len();
    if dir.is_empty() || name.is_empty() || len + 1 > out.len() {
        out[0] = 0;
        return None;
    }
    out[..dir.len()].copy_from_slice(dir);
    if slash {
        out[dir.len()] = b'/';
    }
    out[len - name.len()..len].copy_from_slice(name);
    out[len] = 0;
    Some(len)
}

/// `build_app0_index_locked`: depth-first scan of /app0 into a fresh index
/// file, then reload it into `idx` (or keep it in memory when it cannot be
/// installed, or when `!install`). Runs only as the single `loading` builder.
pub(crate) unsafe fn build_app0_index(idx: &mut FileIndexState, install: bool) {
    idx.available = false;
    if !unsafe {
        super::runtime_memory::ampr_internal_amm_pool_prepare_static_storage(
            c"app0-index.build".as_ptr(),
        )
    } {
        return;
    }
    let mut builder = RuntimeBuilder::new();
    let mut dirs = PathStack::new();
    if !builder.open() || !dirs.push(APP0_ROOT.to_bytes()) {
        return;
    }
    let ws = unsafe { &mut *WORKSPACE.get() };
    while !dirs.is_empty() {
        if !dirs.pop(&mut ws.dir) || !unsafe { scan_dir(ws, &mut dirs, &mut builder) } {
            return;
        }
    }
    // An index file has no field for `links`, so an image built past a
    // link stays in memory: the next boot walks again and sees it.
    let links = builder.links;
    if builder.save_final(idx, install && !links)
        && unsafe { load_compact_index(idx) } != LoadResult::Loaded
    {
        idx.available = false;
    }
    idx.compact.links = links;
}

/// Scans `ws.dir`; false when the scan is incomplete. An unreadable entry
/// aborts the build on purpose: index misses are authoritative, so a partial
/// index would turn that subtree into ENOENT; no index falls back to the kernel.
unsafe fn scan_dir(
    ws: &mut BuildWorkspace,
    dirs: &mut PathStack,
    builder: &mut RuntimeBuilder,
) -> bool {
    let fd = unsafe { real_posix_open(ws.dir.as_ptr().cast(), O_RDONLY | O_DIRECTORY, 0) };
    if fd < 0 {
        return false;
    }
    let mut size = 16 * 1024usize;
    let mut st = Stat::default();
    if unsafe { real_physical_fstat(fd, (&raw mut st).cast()) } == 0 && st.st_blksize > 0 {
        size = size.max(st.st_blksize as usize);
    }
    // getdents needs at least st_blksize bytes. Up to DENTS_POOL_MAX the
    // buffer is a fixed pool site (rt/runtime_memory.rs); a larger block
    // size takes index memory, so the pool never holds more.
    let ok = if size <= DENTS_POOL_MAX {
        let mut dents = ScratchBuffer::new();
        dents.allocate(size, MEM_TRANSIENT)
            && unsafe { scan_dents(fd, dents.data(), size, ws, dirs, builder) }
    } else {
        let dents = unsafe { build_alloc(size, c"apr.index.build.dents") };
        let ok = !dents.is_null() && unsafe { scan_dents(fd, dents, size, ws, dirs, builder) };
        unsafe { title_free(dents, c"apr.index.build.dents") };
        ok
    };
    unsafe { real_physical_close(fd) };
    ok
}

/// Largest getdents buffer taken from the pool.
pub(crate) const DENTS_POOL_MAX: usize = 64 * 1024;

/// getdents loop over `fd` with validated record bounds.
unsafe fn scan_dents(
    fd: c_int,
    buf: *mut u8,
    size: usize,
    ws: &mut BuildWorkspace,
    dirs: &mut PathStack,
    builder: &mut RuntimeBuilder,
) -> bool {
    loop {
        let nread = unsafe { real_physical_getdents(fd, buf.cast(), size as c_int) };
        if nread < 0 || nread as usize > size {
            return false;
        }
        if nread == 0 {
            return true;
        }
        let end = nread as usize;
        let mut off = 0usize;
        while end - off >= DIRENT_HEADER {
            let ent = unsafe { buf.add(off).cast::<DirentHeader>().read_unaligned() };
            let (rec, namlen) = (ent.d_reclen as usize, ent.d_namlen as usize);
            if rec < DIRENT_HEADER + 1 || rec > end - off || namlen > rec - DIRENT_HEADER - 1 {
                return false;
            }
            let name = unsafe { core::slice::from_raw_parts(buf.add(off + DIRENT_HEADER), namlen) };
            off += rec;
            if namlen == 0 || ent.d_fileno == 0 || is_dot_or_dotdot(name) {
                continue;
            }
            if !unsafe { add_dirent(ent.d_type, name, ws, dirs, builder) } {
                return false;
            }
        }
        if off != end {
            return false;
        }
    }
}

/// One directory entry: queue a subdirectory or add a regular file. Skipped
/// entries return true; false aborts the scan.
unsafe fn add_dirent(
    d_type: u8,
    name: &[u8],
    ws: &mut BuildWorkspace,
    dirs: &mut PathStack,
    builder: &mut RuntimeBuilder,
) -> bool {
    let dir = unsafe { cstr_bytes(ws.dir.as_ptr().cast()) };
    let Some(len) = join_dirent_path(dir, name, &mut ws.path) else {
        return true;
    };
    let path_ptr: *const c_char = ws.path.as_ptr().cast();
    if has_unsupported_index_char(&ws.path[..len]) {
        return true;
    }
    match unsafe { normalize_key(path_ptr, &mut ws.path_key) } {
        Some(klen)
            if !is_kraken_key(&ws.path_key[..klen]) && !is_skipped_key(&ws.path_key[..klen]) => {}
        _ => return true,
    }
    let path = &ws.path[..len];
    if d_type == DT_DIR {
        return dirs.push(path);
    }
    // Links are not indexed (retail pfs has none): an indexed link would
    // lstat as its target, and a dangling or looping one has nothing to
    // index. The flag sends every miss to the FS, which answers links right.
    if d_type == DT_LNK {
        builder.links = true;
        return true;
    }
    if !matches!(d_type, DT_REG | DT_UNKNOWN) {
        return true;
    }
    let mut st = Stat::default();
    // DT_UNKNOWN may be a link: lstat tells (if it fails, stat decides).
    if d_type == DT_UNKNOWN
        && unsafe { real_lstat(path_ptr, (&raw mut st).cast()) } == 0
        && st.is_lnk()
    {
        builder.links = true;
        return true;
    }
    if unsafe { real_posix_stat(path_ptr, (&raw mut st).cast()) } != 0 {
        return false;
    }
    if d_type == DT_UNKNOWN && st.is_dir() {
        return dirs.push(path);
    }
    !st.is_reg() || builder.add_file(path, st.st_size as usize, st.st_mtim.tv_sec)
}

// ---- load / validate -------------------------------------------------------------

/// Bound on back-to-back EINTR retries of one index write call.
const EINTR_RETRY_MAX: u32 = 64;

/// `load_compact_app0_index_locked`: builds the view of INDEX_PATH in one
/// pass over the file (`load_file`) and keeps the fd open for path reads.
/// In a title with no packs the view is finished here; with packs
/// `ensure_ready_slow` finishes it after the pack index load.
pub(crate) unsafe fn load_compact_index(idx: &mut FileIndexState) -> LoadResult {
    unsafe { idx.compact.clear() };
    let fd = unsafe { real_posix_open(INDEX_PATH.as_ptr(), O_RDONLY, 0) };
    if fd < 0 {
        return open_failure_result(errno());
    }
    let mut st = Stat::default();
    let rc = if unsafe { real_physical_fstat(fd, (&raw mut st).cast()) } != 0 {
        LoadResult::Unreadable
    } else if st.st_size < ampr_format::IDX_HEADER as i64 {
        LoadResult::Invalid
    } else {
        let len = st.st_size as u64;
        let read = |at: u64, out: &mut [u8]| pread_fd(fd, at, out);
        unsafe { load_file(idx, len, read, view_packs()) }
    };
    if rc == LoadResult::Loaded {
        idx.compact.paths = Paths::File(PathSource::new(fd, st.st_size as u64));
        KEPT_FD.store(fd, Relaxed);
    } else {
        unsafe { real_physical_close(fd) };
    }
    rc
}

/// The pack columns the view carries for this title's pack format: LZ4
/// and pkg titles join their records by position and compare each with the
/// row's `pak_path_hash` (`Packs::Lz4`); a title with no packs carries none.
fn view_packs() -> Packs {
    match super::pack::pack_format() {
        f if f.is_zstd() => Packs::Zstd,
        f if f.has_packs() => Packs::Lz4,
        _ => Packs::None,
    }
}

/// Builds the view of an AMPRIDX3 file of `len` bytes, read through
/// `read` (a pread that fills the slice), into `idx` and marks it
/// available; the caller sets `idx.compact.paths`. The header is checked
/// before any memory is taken, so a corrupt file takes nothing. The file
/// is read through two `WINDOW` buffers from the Index ledger, given back
/// once the view is built. Memory when the ledger refuses the windows or
/// the view, Unreadable on a read error, Invalid for a bad file.
unsafe fn load_file(
    idx: &mut FileIndexState,
    len: u64,
    read: impl Fn(u64, &mut [u8]) -> bool,
    packs: Packs,
) -> LoadResult {
    let mut head = [0u8; ampr_format::IDX_HEADER];
    if !read(0, &mut head) {
        return LoadResult::Unreadable;
    }
    if let Err(e) = Layout::parse(&head) {
        return load_error(e);
    }
    let windows = unsafe { build_alloc(2 * WINDOW, c"apr.index.load.windows") };
    if windows.is_null() {
        return LoadResult::Memory;
    }
    // SAFETY: the block holds two windows, apart, used only here.
    let (a, b) = unsafe {
        (
            &mut *windows.cast::<[u8; WINDOW]>(),
            &mut *windows.add(WINDOW).cast::<[u8; WINDOW]>(),
        )
    };
    let src = FileSource::new(len, read, a, b);
    let rc = unsafe { load_from(idx, &src, packs) };
    drop(src);
    unsafe { title_free(windows, c"apr.index.load.windows.release") };
    rc
}

/// Builds the view of the AMPRIDX3 in `src` into `idx` (see `load_file`);
/// `view::build` checks every record path and refuses two files of one
/// folded path. The view is finished here when `packs` is `None`.
unsafe fn load_from<S: Source + ?Sized>(
    idx: &mut FileIndexState,
    src: &S,
    packs: Packs,
) -> LoadResult {
    let index = match read_layout(src).and_then(|l| Index::view_validated(src, &l)) {
        Ok(index) => index,
        Err(e) => return load_error(e),
    };
    // SAFETY: the builder and the view it finishes into live in `mem`,
    // which `Compact::clear` frees only after dropping both, and a
    // published index is never cleared.
    match unsafe { index_view::build::<S>(&index, packs) } {
        Ok((mem, b)) => {
            let c = &mut idx.compact;
            c.count = index.len() as usize;
            c.mem = Some(mem);
            c.builder = Some(b);
            if packs == Packs::None {
                c.finish();
            }
            c.available = true;
            idx.available = true;
            LoadResult::Loaded
        }
        Err(BuildError::Memory) => LoadResult::Memory,
        Err(BuildError::Format(e)) => load_error(e),
    }
}

/// Only ENOENT means there is no index to load; any other open error
/// (EIO, EMFILE, EINTR) leaves an existing index in place.
fn open_failure_result(err: c_int) -> LoadResult {
    if err == ENOENT {
        LoadResult::Missing
    } else {
        LoadResult::Unreadable
    }
}

fn load_error(e: ampr_format::Error) -> LoadResult {
    match e {
        ampr_format::Error::Io => LoadResult::Unreadable,
        _ => LoadResult::Invalid,
    }
}

/// Serves a built image (header first, `len` bytes at `image`, a
/// `build_alloc` block this call frees) that cannot be installed as
/// INDEX_PATH: the view is built from it, its path blob is copied into
/// the Index ledger for later path reads (`Paths::Blob`) and the image is
/// given back. The image, the view and the blob are held at once for the
/// copy. Memory when the blob does not fit; `idx` is cleared on any error.
unsafe fn adopt_compact_index(idx: &mut FileIndexState, image: *mut u8, len: usize) -> LoadResult {
    unsafe { idx.compact.clear() };
    let bytes = unsafe { core::slice::from_raw_parts(image.cast_const(), len) };
    let mut rc = unsafe { load_from(idx, bytes, view_packs()) };
    if rc == LoadResult::Loaded {
        rc = unsafe { keep_paths(&mut idx.compact, bytes) };
    }
    unsafe { title_free(image, c"apr.index.build.image") };
    if rc != LoadResult::Loaded {
        unsafe { idx.compact.clear() };
        idx.available = false;
    }
    rc
}

/// Copies the path blob of the checked image `bytes` into an Index ledger
/// block that `c` owns from here on.
unsafe fn keep_paths(c: &mut Compact, bytes: &[u8]) -> LoadResult {
    let Ok(l) = read_layout(bytes) else {
        return LoadResult::Invalid;
    };
    let (at, n) = (l.paths_at as usize, l.path_bytes as usize);
    let Some(src) = bytes.get(at..at + n) else {
        return LoadResult::Invalid;
    };
    let blob = unsafe { build_alloc(n.max(1), c"apr.index.paths") };
    if blob.is_null() {
        return LoadResult::Memory;
    }
    // SAFETY: `blob` holds at least `n` bytes and is owned by `c` until
    // `clear`, which outlives every reader of a published index.
    let blob: &'static [u8] = unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), blob, n);
        core::slice::from_raw_parts(blob, n)
    };
    c.paths = Paths::Blob(BlobSource {
        blob,
        base: l.paths_at,
    });
    LoadResult::Loaded
}

// ---- pack manifest probe -----------------------------------------------------------

/// True when /app0 has an LZ4 or zstd pack manifest.
/// Only ENOENT means no manifest: an I/O error on a present manifest must not
/// let a walk build replace the shipped index (its file IDs belong to packs).
unsafe fn pack_manifest_present() -> bool {
    let mut st = Stat::default();
    zstd_mode()
        || unsafe {
            real_posix_stat(
                super::pack::AMPR_EMU_PACK_INDEX_PATH.as_ptr(),
                (&raw mut st).cast(),
            )
        } == 0
        || errno() != ENOENT
}

// ---- ensure ready (slow path) --------------------------------------------------------

use super::pack::{ampr_pack_ensure_manifest_ready_safe, ampr_pack_mount_and_join};

/// `ensure_app0_index_ready_slow`: one thread loads (or, if allowed, builds)
/// the index outside the lock while others wait on `INDEX_CV`; the result is
/// moved into `INDEX` and published once it is final.
pub(crate) unsafe fn ensure_ready_slow(allow_build: bool) -> bool {
    loop {
        {
            let mut g = INDEX_LOCK.lock();
            let idx = unsafe { state() };
            if idx.loaded {
                return idx.available;
            }
            if idx.loading {
                INDEX_CV.wait_for_us(&mut g, INDEX_LOAD_WAIT_US);
                continue;
            }
            if idx.load_attempted && (!allow_build || !APP0_INDEX_AUTOBUILD) {
                return idx.available;
            }
            if idx.load_attempted
                && !retry_due(super::sys::monotonic_ns(), RETRY_AT_NS.load(Relaxed))
            {
                return idx.available;
            }
            idx.load_attempted = true;
            idx.loading = true;
            idx.available = false;
        }

        let mut work = FileIndexState {
            loaded: false,
            load_attempted: false,
            loading: false,
            available: false,
            compact: Compact::EMPTY,
        };
        // With packs deployed the shipped index is the file-ID namespace of
        // the manifest (one record per AMPRIDX3 id) and packed originals are
        // gone from /app0, so it is never replaced; a fallback build stays
        // in memory.
        let packs = unsafe { pack_manifest_present() };
        let build = allow_build && APP0_INDEX_AUTOBUILD;
        // `index_mount_ns`: this load, from the index read to the finished
        // view (the pack mount and join included).
        let started = stats::now();
        let result = unsafe { load_compact_index(&mut work) };
        #[cfg(feature = "mem_report")]
        super::blackbox::idx(load_result_name(result), work.compact.count as u64);
        let unreadable = next_unreadable_loads(UNREADABLE_LOADS.load(Relaxed), result);
        UNREADABLE_LOADS.store(unreadable, Relaxed);
        RETRY_AT_NS.store(
            next_retry_at(super::sys::monotonic_ns(), unreadable),
            Relaxed,
        );
        let final_loaded = match result {
            LoadResult::Loaded => true,
            LoadResult::Memory => {
                work.available = false;
                true
            }
            // With packs the shipped index is the only file-ID namespace (a
            // walk lacks the packed originals), so it is retried, never
            // replaced.
            LoadResult::Unreadable if build && !packs && unreadable >= UNREADABLE_LOAD_LIMIT => {
                unsafe { build_app0_index(&mut work, false) };
                #[cfg(feature = "mem_report")]
                super::blackbox::idx(b"walk memory", work.compact.count as u64);
                true
            }
            LoadResult::Unreadable => false,
            LoadResult::Missing | LoadResult::Invalid if build => {
                unsafe { build_app0_index(&mut work, !packs) };
                #[cfg(feature = "mem_report")]
                super::blackbox::idx(
                    if packs {
                        b"walk memory"
                    } else {
                        b"walk installed"
                    },
                    work.compact.count as u64,
                );
                true
            }
            _ => false,
        };
        // Finish the pack snapshot at this known-safe boundary: hooks must not
        // see the index resident before the manifest load is terminal. The
        // view is still being built, so the pack index is joined into it
        // here (every mount needs that and is started nowhere else).
        if final_loaded && work.available {
            match work.compact.builder.as_mut() {
                // A mount that is not ready (invalid, unavailable, stopping)
                // may have linked some rows before it failed; none of them
                // is served, so they go back to loose.
                Some(b) => {
                    let joined = unsafe { ampr_pack_mount_and_join(b) };
                    if !joined {
                        b.unlink_all();
                    }
                    #[cfg(feature = "mem_report")]
                    super::blackbox::idx_join(joined);
                }
                None => {
                    unsafe { ampr_pack_ensure_manifest_ready_safe() };
                }
            };
        }
        // A title with packs finishes the view here, after the pack index
        // load; with none `load_from` already did.
        work.compact.finish();
        // The Index ledger is final now: its idle room goes to the cache,
        // before the index is published and any read can reach the cache.
        if final_loaded && work.available && packs {
            unsafe { crate::rt::pack::grow_cache_from_index(crate::rt::pack::pack_state()) };
            unsafe { crate::rt::pack::start_first_worker() };
        }
        stats::set(stats::Stat::IndexMountNs, stats::since(started));

        let _g = INDEX_LOCK.lock();
        let idx = unsafe { state() };
        let available = work.available;
        unsafe { idx.compact.move_from(&mut work.compact) };
        idx.available = available;
        idx.loaded = final_loaded;
        idx.loading = false;
        if final_loaded {
            PUBLISH.store(
                if available {
                    PUB_AVAILABLE
                } else {
                    PUB_UNAVAILABLE
                },
                Release,
            );
        }
        INDEX_CV.notify_all();
        return idx.available;
    }
}

// ---- part 3: ensure ready and lookups ------------------------------------------------

/// `ensure_app0_index_ready`: published fast path, then the slow loader.
pub(crate) unsafe fn ensure_ready(allow_build: bool) -> bool {
    match PUBLISH.load(Acquire) {
        PUB_PENDING => {}
        p => return p == PUB_AVAILABLE,
    }
    {
        let _g = INDEX_LOCK.lock();
        let idx = unsafe { state() };
        if idx.loaded {
            return idx.available;
        }
    }
    unsafe { ensure_ready_slow(allow_build) }
}

const fn empty_view() -> FileEntryView {
    FileEntryView {
        path: null(),
        path_length: 0,
        size: 0,
        mtime: 0,
    }
}

/// A lookup that could not read the index file (a path read error).
/// It is not a miss: the file may exist, so no caller answers ENOENT or
/// "not packed" for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexIo;

/// `Io` as `IndexIo`; any other error reads as no answer, as before.
fn io_or_none<T>(r: ampr_format::Result<Option<T>>) -> Result<Option<T>, IndexIo> {
    match r {
        Err(ampr_format::Error::Io) => Err(IndexIo),
        r => Ok(r.ok().flatten()),
    }
}

/// What the normalized `key` names in the published view. A file hit is
/// trusted on its hash; a hit on a collision-listed id is confirmed by
/// `View::lookup` itself.
#[cfg(test)]
fn view_lookup(c: &Compact, key: &[u8]) -> ampr_format::Result<Option<Hit>> {
    let Some(view) = c.view() else {
        return Ok(None);
    };
    view.lookup(&c.paths, key).map(Some)
}

/// What one lookup of a normalized key found, with the entry the hooks
/// answer from.
enum KeyHit {
    /// A file: its entry and one-based id.
    File(FileEntryView, u32),
    /// A directory: its stored spelling (`path_length` is the key's; the
    /// path is null when not read) and the mtime of its representative
    /// file, and its view directory id.
    Dir(FileEntryView, u32),
    Miss,
}

/// One `View::lookup` of `key` in `c`, answering a file only when
/// `file_ok` and a directory only when `dir_ok`; anything else is a miss.
/// A key that names both a file and a directory answers the file, so it
/// is a miss when only a directory is wanted (a filesystem never has
/// both). `IndexIo` when a path read failed, which is not a miss.
fn resolve_key(
    c: &Compact,
    key: &[u8],
    file_ok: bool,
    dir_ok: bool,
    path: Option<&mut EntryPath>,
) -> Result<KeyHit, IndexIo> {
    resolve_key_paths(c, key, file_ok, dir_ok, path, false)
}

/// `resolve_key`; with `lazy` a hit, a file packed or loose or a
/// directory, leaves its path unread (null) even when `path` is given. A packed file is served by id
/// and a loose one is asked for by the game's own spelling first
/// (`loose_call`), so the path costs a pread only a fallback uses
/// (`hit_path`, `loose_call`).
fn resolve_key_paths(
    c: &Compact,
    key: &[u8],
    file_ok: bool,
    dir_ok: bool,
    path: Option<&mut EntryPath>,
    lazy: bool,
) -> Result<KeyHit, IndexIo> {
    let Some(view) = c.view() else {
        return Ok(KeyHit::Miss);
    };
    // A directory-only caller probes directories alone: a file of the same
    // folded key (`Data` beside `data/` on a case-sensitive install) must
    // not hide the directory's indexed spelling.
    let found = if file_ok {
        view.lookup(&c.paths, key).map(Some)
    } else {
        view.lookup_dir(&c.paths, key).map(|d| d.map(Hit::Dir))
    };
    let hit = match io_or_none(found)? {
        Some(Hit::File(id)) if file_ok => file_entry(c, &view, id, key, path, lazy),
        Some(Hit::Dir(d)) if dir_ok => dir_entry(c, &view, d, key, path, lazy),
        _ => return Ok(KeyHit::Miss),
    };
    Ok(io_or_none(hit)?.unwrap_or(KeyHit::Miss))
}

/// File `id`'s entry for `key`. Size and mtime come from the view. With
/// no `path` asked for, or `lazy`, the hit is trusted on its 64-bit hash
/// and no path is read (`resolve_key_paths`; ids on the view's collision
/// list are confirmed by `View::lookup` itself). With `path`, a packed
/// file's path is read there, and a loose file's is read and compared
/// (`View::confirm`), so the real call it goes to is for this exact file
/// and a hash that matched another path is a miss.
fn file_entry(
    c: &Compact,
    view: &View<'_>,
    id: u32,
    key: &[u8],
    path: Option<&mut EntryPath>,
    lazy: bool,
) -> ampr_format::Result<Option<KeyHit>> {
    if id == 0 || id == FILEID_INVALID || id as usize > c.count {
        return Ok(None);
    }
    let mut e = FileEntryView {
        size: view.size(id) as usize,
        mtime: view.mtime(id),
        ..empty_view()
    };
    let packed = view_packed(view, id);
    // No path asked for (an id resolve): the hash answers, as for every
    // lazy hit, so a resolve costs no pread.
    if lazy || path.is_none() {
        return Ok(Some(KeyHit::File(e, id)));
    }
    let given = path.is_some();
    let mut scratch: EntryPath = [0; PATH_BUF];
    let buf = path.unwrap_or(&mut scratch);
    let n = if packed {
        view.path(&c.paths, id, buf)?.len()
    } else {
        match view.confirm(&c.paths, id, key, buf)? {
            Some(p) => p.len(),
            None => return Ok(None),
        }
    };
    if given {
        buf[n] = 0;
        e.path = buf.as_ptr().cast();
        e.path_length = n as u32;
    }
    Ok(Some(KeyHit::File(e, id)))
}

/// File `id` lives in a pack: a packed record or a zstd chunk.
fn view_packed(view: &View<'_>, id: u32) -> bool {
    view.packed(id) || view.chunk(id) != NO_CHUNK
}

/// Directory `d`'s entry for `key`: with `path`, its representative
/// file's path is read there (NUL-terminated at that file's length) and
/// `path_length` is the key's, so the first `path_length` bytes are the
/// directory's stored spelling. The mtime is that file's.
fn dir_entry(
    c: &Compact,
    view: &View<'_>,
    d: u32,
    key: &[u8],
    path: Option<&mut EntryPath>,
    lazy: bool,
) -> ampr_format::Result<Option<KeyHit>> {
    let rep = view.dir(d).rep_file;
    if c.count == 0 || rep == 0 || rep as usize > c.count {
        return Ok(None);
    }
    let mut e = FileEntryView {
        path_length: key.len() as u32,
        mtime: view.mtime(rep),
        ..empty_view()
    };
    // Only an open uses the spelling; a lazy stat, access or
    // reachability of a directory reads none (`dir_path` reads it later).
    if let Some(buf) = path.filter(|_| !lazy) {
        view.dir_path(&c.paths, d, buf)?;
        e.path = buf.as_ptr().cast();
    }
    Ok(Some(KeyHit::Dir(e, d)))
}

/// `lookup_app0_index_key_view`: (view, one-based id) of a file key; the
/// stored path is copied into `path` when given (see `file_entry`).
unsafe fn lookup_key_view(
    key: &[u8],
    allow_build: bool,
    path: Option<&mut EntryPath>,
) -> Result<Option<(FileEntryView, u32)>, IndexIo> {
    if !unsafe { ensure_ready(allow_build) } {
        return Ok(None);
    }
    // A true ensure_ready means the image was published as available.
    let Some(c) = published().filter(|c| c.available) else {
        return Ok(None);
    };
    match resolve_key(c, key, true, false, path)? {
        KeyHit::File(e, id) => Ok(Some((e, id))),
        _ => Ok(None),
    }
}

/// `lookup_resident_app0_directory_key`: a representative view for a
/// directory key that has at least one resident descendant file (see
/// `dir_entry`).
unsafe fn lookup_directory_key(
    key: &[u8],
    path: Option<&mut EntryPath>,
) -> Result<Option<FileEntryView>, IndexIo> {
    let Some(c) = published().filter(|c| c.available) else {
        return Ok(None);
    };
    match resolve_key(c, key, false, true, path)? {
        KeyHit::Dir(e, _) => Ok(Some(e)),
        _ => Ok(None),
    }
}

fn is_app0_key(key: &[u8]) -> bool {
    ampr_format::index_key::is_app0_key(key)
}

/// True when `path` starts with the `/app0` root.
unsafe fn has_app0_root(path: *const c_char) -> bool {
    !path.is_null()
        && ampr_format::index_key::has_app0_root(|i| unsafe { *path.cast::<u8>().add(i) })
}

fn is_resident_ready() -> bool {
    PUBLISH.load(Acquire) == PUB_AVAILABLE
}

/// `ResidentApp0LookupState`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resident {
    NotApp0,
    IndexNotReady,
    Miss,
    Hit,
    Directory,
}

/// `ResidentApp0Lookup`.
struct Lookup {
    state: Resident,
    entry: FileEntryView,
    file_id: u32,
    expected_miss: bool,
    /// A `Miss` the index can answer (see `miss_is_authoritative`); a
    /// non-authoritative miss goes to the real call.
    authoritative: bool,
    /// A `Miss` because the index could not be read (`IndexIo`): never
    /// authoritative, and an ENOENT from the real call becomes EIO while
    /// packs are mounted (`io_miss`).
    io: bool,
    /// A loose `Hit` whose stored path is unread and unconfirmed: its real
    /// call tries the game's spelling first (`loose_call`).
    unconfirmed: bool,
    /// A `Miss` the published view answered with no read error, from a
    /// lazy lookup. Every packed file and packed directory is a view row
    /// (the pack index is joined to the view by id), so the pack overlay
    /// cannot find more and the hooks do not ask it (`pack_miss`); a test
    /// checks that over the view fixtures.
    final_miss: bool,
    /// A `Directory`'s view directory id, so a lazy lookup that did not
    /// read its spelling can read it when an open needs it (`dir_path`).
    dir: u32,
    /// A `Hit` the view links to a pack (`view_packed`), read once at the
    /// lookup so `hit_is_packed` enters no manifest gate.
    packed: bool,
    /// The pack manifest's resident-ready state, asked once per call:
    /// 0 not asked yet, 1 not ready, 2 ready (`packs_ready`).
    packs: core::cell::Cell<u8>,
}

impl Lookup {
    const fn empty() -> Self {
        Self {
            state: Resident::NotApp0,
            entry: empty_view(),
            file_id: 0,
            expected_miss: false,
            authoritative: false,
            io: false,
            unconfirmed: false,
            final_miss: false,
            dir: 0,
            packed: false,
            packs: core::cell::Cell::new(0),
        }
    }

    /// `ampr_pack_manifest_is_resident_ready`, entered once per lookup:
    /// each entry is two SeqCst read-modify-writes on the shared gate line
    /// (rt/pack/mod.rs `ManifestReader`), and a call asked it up to three
    /// times. Once the index is published the mount is terminal, so the
    /// answer holds for the call; a shutdown that starts after it is
    /// caught by the gate each pack call enters itself.
    fn packs_ready(&self) -> bool {
        match self.packs.get() {
            0 => {
                let ready = unsafe { ampr_pack_manifest_is_resident_ready() };
                self.packs.set(if ready { 2 } else { 1 });
                ready
            }
            v => v == 2,
        }
    }

    /// Whether a pack lookup of this miss can find anything: not after a
    /// final view miss, and only with the manifest ready.
    fn pack_miss(&self) -> bool {
        !self.final_miss && self.packs_ready()
    }
}

/// The walk indexes every regular file of /app0 under a key that folds ASCII
/// case, so a miss is authoritative on case-sensitive (bfs, ext) and
/// case-insensitive (exFAT, pfs) trees alike, except for paths the walk can
/// never list: names with tab/LF/CR (`has_unsupported_index_char`), the
/// runtime's own files it skips, and non-ASCII names, which exFAT folds by
/// its Unicode upcase table while keys fold ASCII only. Those go to the FS.
/// With `links` (the walk skipped a symlink) no miss is authoritative: the
/// link and anything under it are absent from the index.
/// `plain` is `Key::plain` of the game's path (no byte >= 0x80 and no
/// tab/LF/CR), taken in the normalize pass.
fn miss_is_authoritative(plain: bool, key: &[u8], links: bool) -> bool {
    !links && plain && !is_skipped_key(key)
}

/// `/app0/kraken` and below (normalized key): the read-only mount of the
/// folder that holds the .pkg (rt/pack/pkg.rs). Its files are not the
/// title's, so the walk skips it and lookups there go to the filesystem.
/// Only in pkg mode: a folder title may ship its own `kraken` directory.
fn is_kraken_key(key: &[u8]) -> bool {
    super::pack::pkg_mode() && kraken_key_shape(key)
}

fn kraken_key_shape(key: &[u8]) -> bool {
    key.strip_prefix(b"/app0/kraken".as_slice())
        .is_some_and(|rest| rest.is_empty() || rest[0] == b'/')
}

/// A `Miss` lookup that could not read the index: not authoritative, so
/// the hook asks the real call (`io_miss`).
fn io_lookup(r: &mut Lookup) {
    stats::add(stats::Stat::IndexLookupIo, 1);
    (r.state, r.io, r.authoritative) = (Resident::Miss, true, false);
    (r.final_miss, r.packed) = (false, false);
}

/// The errno a hook returns when the real call answered `err` for a path
/// whose lookup could not read the index: with packs mounted an ENOENT
/// becomes EIO, as the file may be packed and have no copy on disk.
fn io_miss_errno(err: c_int, packs: bool) -> c_int {
    if packs && err == ENOENT {
        EIO
    } else {
        err
    }
}

/// The real call's `rc` (-1 and errno on failure) for a non-authoritative
/// miss, with `io_miss_errno` applied when the lookup failed to read.
unsafe fn io_miss(l: &Lookup, rc: c_int) -> c_int {
    unsafe { io_miss_if(l.io, rc) }
}

/// `io_miss` for a read failure known by the caller: the lookup's, or the
/// pack index's (`ampr_pack_try_stat_path` unhandled EIO).
unsafe fn io_miss_if(io: bool, rc: c_int) -> c_int {
    if rc == -1 && io {
        let packs = unsafe { ampr_pack_manifest_is_resident_ready() };
        set_errno(io_miss_errno(errno(), packs));
    }
    rc
}

/// `lookup_resident_app0_path`: consumes only the immutable published image;
/// never builds or loads the index. One `View::lookup` answers file and
/// directory alike; paths are read by this thread from the index file
/// (one pread, like the open() the hook replaces) and a hook never waits
/// on another thread. The entry's path is copied into `pbuf` (a hit's
/// path, or a directory's canonical prefix).
#[inline(never)]
unsafe fn lookup_resident_path(path: *const c_char, pbuf: &mut EntryPath) -> Lookup {
    unsafe { lookup_resident(path, pbuf, false) }
}

/// `lookup_resident_path`; with `lazy` a file hit has a null `entry.path`
/// (see `resolve_key_paths`) and a loose one is `unconfirmed`; a directory
/// hit leaves its spelling unread too (`dir_path` reads it for an open).
unsafe fn lookup_resident(path: *const c_char, pbuf: &mut EntryPath, lazy: bool) -> Lookup {
    let mut r = Lookup::empty();
    if !unsafe { has_app0_root(path) } {
        return r;
    }
    if !is_resident_ready() {
        r.state = Resident::IndexNotReady;
        return r;
    }
    // A path that fails to normalize or folds outside /app0 goes to the
    // kernel, which returns the real target or the right errno.
    let mut buf = [0u8; RUNTIME_PATH_CAPACITY];
    let Ok(k) = (unsafe { normalize_key_full(path, &mut buf) }) else {
        return r;
    };
    let (len, trailing) = (k.len, k.had_trailing_separator);
    let key = &buf[..len];
    // The kraken mount is not the title's: an index built before the walk
    // skipped it may still list it, so it goes to the filesystem unlooked.
    if !is_app0_key(key) || is_kraken_key(key) {
        return r;
    }
    r.state = Resident::Miss;
    // is_resident_ready() holds, so the published index is final. The
    // /app0 root and a key with a trailing separator name no file.
    let Some(c) = published() else {
        return r;
    };
    let hit = if c.available {
        resolve_key_paths(c, key, !trailing && len > 5, true, Some(pbuf), lazy)
    } else {
        Ok(KeyHit::Miss)
    };
    match hit {
        Ok(KeyHit::File(e, id)) => {
            (r.state, r.entry, r.file_id) = (Resident::Hit, e, id);
            r.packed = c.view().is_some_and(|v| view_packed(&v, id));
            r.unconfirmed = r.entry.path.is_null() && !r.packed;
            return r;
        }
        Ok(KeyHit::Dir(e, d)) => {
            (r.state, r.entry, r.dir) = (Resident::Directory, e, d);
            return r;
        }
        Err(IndexIo) => {
            io_lookup(&mut r);
            return r;
        }
        Ok(KeyHit::Miss) => {}
    }
    miss_lookup(&mut r, k.plain, key, c.links);
    // A lazy lookup reads no path, so its miss is the view's own answer;
    // one that confirmed a loose path may have missed on a hash that a
    // directory of the key shares.
    r.final_miss = lazy && c.available;
    r
}

/// Makes `r` the miss of normalized `key` (`plain` as `Key::plain` of the
/// game's path), authoritative as `miss_is_authoritative` and
/// `miss_authority` say.
fn miss_lookup(r: &mut Lookup, plain: bool, key: &[u8], links: bool) {
    (r.state, r.entry, r.file_id, r.unconfirmed) = (Resident::Miss, empty_view(), 0, false);
    (r.final_miss, r.packed) = (false, false);
    r.expected_miss = true;
    r.authoritative = miss_authority(
        miss_is_authoritative(plain, key, links),
        rw::app0_writable(),
    );
}

/// Writable /app0: files the game creates live only on the FS, so no miss
/// is authoritative. A read-only /app0 keeps the index's answer.
fn miss_authority(authoritative: bool, rw: bool) -> bool {
    authoritative && !rw
}

// ---- probe lookups (rt/probe.rs, debug only) ------------------------------------

/// What the published index says of `path` for the debug probes: b'p' a
/// packed file (an AMPRIDX3 hit that rt/pack `file_id_is_packed` accepts:
/// a zstd record, or an LZ4 record flagged packed), b'd' an indexed
/// directory, None otherwise (loose file, miss, not /app0, index or pack
/// manifest not ready). The probes run
/// inside libkernel hooks, possibly during early init, so this reads only
/// the published lock-free image: it never builds, waits or opens files.
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn probe_packed_path(path: *const c_char) -> Option<u8> {
    if !unsafe { has_app0_root(path) } || !is_resident_ready() {
        return None;
    }
    let mut buf = [0u8; RUNTIME_PATH_CAPACITY];
    let (len, trailing) = unsafe { normalize_key_result(path, &mut buf) }.ok()?;
    let key = &buf[..len];
    if !is_app0_key(key) {
        return None;
    }
    let c = published().filter(|c| c.available)?;
    match resolve_key(c, key, !trailing && len > 5, true, None).ok()? {
        KeyHit::File(_, id) => {
            // A refused guard reads as "manifest not ready": no answer.
            let reader = super::pack::ManifestReader::enter()?;
            super::pack::file_id_is_packed(&reader, id).then_some(b'p')
        }
        KeyHit::Dir(..) => Some(b'd'),
        KeyHit::Miss => None,
    }
}

/// Copies the indexed path of one-based file `id` into `out` (truncated,
/// NUL-terminated) and returns its length; None when the index is not
/// published or `id` is unknown. Lock-free, like `probe_packed_path`.
#[cfg(feature = "mem_report")]
pub(crate) fn probe_file_path(id: u32, out: &mut [u8]) -> Option<usize> {
    let c = published().filter(|c| c.available)?;
    if id == 0 || id == FILEID_INVALID || id as usize > c.count || out.is_empty() {
        return None;
    }
    let mut v = empty_view();
    let mut buf: EntryPath = [0; PATH_BUF];
    if c.try_entry_view(id, &mut v, Some(&mut buf)).is_err() {
        return None;
    }
    let n = (v.path_length as usize).min(out.len() - 1);
    out[..n].copy_from_slice(&buf[..n]);
    out[n] = 0;
    Some(n)
}

/// `maybe_resolve_app0_path_arg`: the indexed path for a resident hit,
/// copied into `pbuf` (the result points there), else `path`.
#[inline(never)]
pub(crate) unsafe fn maybe_resolve_path(
    path: *const c_char,
    pbuf: &mut EntryPath,
) -> *const c_char {
    let l = unsafe { lookup_resident_path(path, pbuf) };
    if l.state == Resident::Hit {
        l.entry.path
    } else {
        path
    }
}

/// `is_app0_path_arg`.
#[inline(never)]
unsafe fn is_app0_path(path: *const c_char) -> bool {
    if !unsafe { has_app0_root(path) } {
        return false;
    }
    let mut buf = [0u8; RUNTIME_PATH_CAPACITY];
    unsafe { normalize_key(path, &mut buf) }.is_some_and(|len| is_app0_key(&buf[..len]))
}

// ---- /app0 file hooks --------------------------------------------------------------

use super::pack::{
    ampr_pack_manifest_is_resident_ready, ampr_pack_open_directory,
    ampr_pack_open_virtual_directory, ampr_pack_try_open_indexed, ampr_pack_try_reachability,
    ampr_pack_try_stat_path, directory_open_flags,
};

/// `ampr_real_sceKernelCheckReachability` (slot must be installed).
unsafe fn real_check_reachability(path: *const c_char) -> c_int {
    type F = unsafe extern "C" fn(*const c_char) -> c_int;
    match unsafe { kernel_slot::<F>(hook::sceKernelCheckReachability) } {
        Some(f) => unsafe { f(path) },
        None => abort(),
    }
}

/// `app0_file_hook_should_try_index_fallback`: ENOENT/ENOTDIR failures.
fn should_try_index_fallback(rc: c_int, err: c_int) -> bool {
    if rc == 0 {
        return false;
    }
    let e = if rc == -1 {
        err
    } else if rc as u32 & 0xFFFF_0000 == 0x8002_0000 {
        posix_errno_from_sce(rc)
    } else {
        rc.wrapping_abs()
    };
    e == ENOENT || e == ENOTDIR
}

/// `app0_file_hook_return_direct`.
fn return_direct(rc: c_int, err: c_int) -> c_int {
    if rc == -1 {
        set_errno(err);
    }
    rc
}

/// `app0_posix_return_from_sce`.
fn posix_return_from_sce(rc: c_int) -> c_int {
    if rc >= 0 {
        return rc;
    }
    if rc != -1 {
        set_errno(posix_errno_from_sce(rc));
    }
    -1
}

fn index_miss() -> c_int {
    set_errno(ENOENT);
    -1
}

/// `fill_indexed_file_stat`.
fn file_stat(l: &Lookup) -> Stat {
    let size = l.entry.size as i64;
    let t = SceKernelTimespec {
        tv_sec: l.entry.mtime,
        tv_nsec: 0,
    };
    Stat {
        st_mode: S_IFREG | 0o444,
        st_nlink: 1,
        st_size: size,
        st_blksize: 65536,
        st_blocks: (l.entry.size / 512 + (l.entry.size % 512 != 0) as usize) as i64,
        st_mtim: t,
        st_atim: t,
        st_ctim: t,
        // Resident file IDs are unique and non-zero.
        st_ino: l.file_id,
        ..Stat::default()
    }
}

/// `fill_indexed_directory_stat`.
fn dir_stat(l: &Lookup) -> Stat {
    let t = SceKernelTimespec {
        tv_sec: l.entry.mtime,
        tv_nsec: 0,
    };
    Stat {
        st_mode: S_IFDIR | 0o555,
        st_nlink: 2,
        st_blksize: 65536,
        st_mtim: t,
        st_atim: t,
        st_ctim: t,
        ..Stat::default()
    }
}

/// The stored spelling of directory hit `l` for an open: `entry.path`,
/// else (a lazy lookup) read into `pbuf` once and kept in `l`. False when
/// the read failed or the index is gone; the caller then treats `l` as a
/// lookup that could not read the index (`io_lookup`).
fn dir_path_in(c: Option<&Compact>, l: &mut Lookup, pbuf: &mut EntryPath) -> bool {
    if !l.entry.path.is_null() {
        return true;
    }
    let Some((c, view)) = c.and_then(|c| Some((c, c.view()?))) else {
        return false;
    };
    if view.dir_path(&c.paths, l.dir, pbuf).is_err() {
        return false;
    }
    l.entry.path = pbuf.as_ptr().cast();
    true
}

/// `copy_indexed_directory_path`.
unsafe fn copy_dir_path(l: &Lookup, out: &mut [u8]) -> bool {
    let len = l.entry.path_length as usize;
    if l.entry.path.is_null() || len + 1 > out.len() {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(l.entry.path.cast::<u8>(), out.as_mut_ptr(), len) };
    out[len] = 0;
    true
}

/// `posix_open_impl`: the published index answers /app0; an authoritative
/// miss returns at once (see `miss_is_authoritative`), other misses and
/// indexed loose files reach the physical open.
unsafe fn open_impl(path: *const c_char, flags: c_int, mode: SceKernelMode) -> c_int {
    unsafe { open_with(path, flags, mode, real_posix_open, b'o') }
}

/// The original a path hook falls back to: each hook calls its own, so a
/// libkernel wrapper that calls another detoured entry point never loops.
type RealOpen = unsafe fn(*const c_char, c_int, SceKernelMode) -> c_int;
type RealStat = unsafe fn(*const c_char, *mut c_void) -> c_int;

unsafe fn open_with(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    real: RealOpen,
    op: u8,
) -> c_int {
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let mut l = unsafe { lookup_resident(path, &mut pbuf, true) };
    let fd = unsafe { open_resolved(&mut l, &mut pbuf, path, flags, mode, real) };
    // A file hit opened with O_DIRECTORY fails ENOTDIR, as on retail. Not
    // logged: a UE3 title tests every cooked file this way at start (~5000
    // calls on the console), which filled all 96 /fsfail slots.
    if !(fd < 0 && l.state == Resident::Hit && flags & O_DIRECTORY != 0) {
        stats::fs_event(op, how(&l), fd as i64, path);
    }
    fd
}

/// Debug trace letter of a resident lookup outcome.
fn how(l: &Lookup) -> u8 {
    match l.state {
        Resident::Hit => b'h',
        // 'M': a miss the index cannot answer, sent to the FS.
        Resident::Miss if !l.authoritative => b'M',
        Resident::Miss => b'm',
        Resident::Directory => b'd',
        Resident::IndexNotReady => b'n',
        Resident::NotApp0 => b'x',
    }
}

/// The stored path of file hit `l` for a real call: `entry.path`, else
/// (a packed hit looked up without its path) read into `pbuf` once and
/// kept in `l`. Null with errno EIO when the read failed, ENOENT when the
/// index is gone; never a miss the caller could answer itself.
unsafe fn hit_path(l: &mut Lookup, pbuf: &mut EntryPath) -> *const c_char {
    hit_path_in(published(), l, pbuf)
}

/// `hit_path` with the index `c` it reads from.
fn hit_path_in(c: Option<&Compact>, l: &mut Lookup, pbuf: &mut EntryPath) -> *const c_char {
    if !l.entry.path.is_null() {
        return l.entry.path;
    }
    let mut e = empty_view();
    let rc = match c {
        Some(c) => c.try_entry_view(l.file_id, &mut e, Some(pbuf)),
        None => Err(ampr_format::Error::Invalid),
    };
    match rc {
        Ok(()) => {
            (l.entry.path, l.entry.path_length) = (e.path, e.path_length);
            l.entry.path
        }
        Err(err) => {
            let io = matches!(err, ampr_format::Error::Io);
            set_errno(if io { EIO } else { ENOENT });
            null()
        }
    }
}

// ---- loose hits: the game's spelling first ----------------------------------------

/// What the real call of an `unconfirmed` loose hit came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Loose {
    /// The real call's result, errno set as it left it.
    Done(c_int),
    /// The stored path does not fold to the key: the hash matched another
    /// path, so the lookup is now a miss (`miss_lookup`) for the caller to
    /// answer as one.
    Miss,
    /// The stored path could not be read. Not a miss: the file is indexed
    /// and may exist under that spelling, so the caller answers EIO.
    Io,
}

/// Whether `raw` is `Key::plain`: no byte >= 0x80, no tab/LF/CR.
fn key_plain(raw: &[u8]) -> bool {
    !raw.iter().any(|&b| b >= 0x80) && !has_unsupported_index_char(raw)
}

/// `raw` normalized into `out` (NUL-terminated) without folding case;
/// None when it does not fit or `..` climbs above the root.
fn spell(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut len = 0usize;
    for comp in raw.split(|&b| b == b'/' || b == b'\\') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." {
            if len == 0 {
                return None;
            }
            while out[len - 1] != b'/' {
                len -= 1;
            }
            len -= 1;
            continue;
        }
        let end = len + 1 + comp.len();
        if end >= out.len() {
            return None;
        }
        out[len] = b'/';
        out[len + 1..end].copy_from_slice(comp);
        len = end;
    }
    *out.get_mut(len)? = 0;
    Some(len)
}

/// The real `call` of loose file hit `l` (file id, `key`). With
/// `spelling`, the game's own spelling goes first: on a hit that is the
/// file the game asked for, so no path is read. Only when it fails ENOENT
/// or ENOTDIR (`should_try_index_fallback`), or with no `spelling`, is
/// the stored path read into `pbuf` and confirmed (`View::confirm`): one
/// that differs from the spelling is called once, one equal to it keeps
/// the first answer. The path is kept in `l` for a later fallback.
fn loose_call_in<S: Source + ?Sized>(
    view: Option<&View<'_>>,
    src: &S,
    l: &mut Lookup,
    key: &[u8],
    spelling: Option<*const c_char>,
    pbuf: &mut EntryPath,
    mut call: impl FnMut(*const c_char) -> c_int,
) -> Loose {
    let mut first = None;
    if let Some(s) = spelling {
        let rc = call(s);
        let err = if rc == -1 { errno() } else { 0 };
        if !should_try_index_fallback(rc, err) {
            return Loose::Done(rc);
        }
        first = Some((s, rc, err));
    }
    let Some(view) = view else {
        return Loose::Miss;
    };
    let n = match view.confirm(src, l.file_id, key, pbuf) {
        Ok(Some(p)) => p.len(),
        Err(ampr_format::Error::Io) => return Loose::Io,
        Ok(None) | Err(_) => return Loose::Miss,
    };
    pbuf[n] = 0;
    (l.entry.path, l.entry.path_length, l.unconfirmed) = (pbuf.as_ptr().cast(), n as u32, false);
    match first {
        Some((s, rc, err)) if unsafe { cstr_bytes(s) } == &pbuf[..n] => {
            Loose::Done(return_direct(rc, err))
        }
        _ => Loose::Done(call(l.entry.path)),
    }
}

/// `loose_call_in` over the published index, for hook path `path`; the
/// game's spelling goes first only with `first`. A `Miss` turns `l` into
/// the miss of `path`; an `Io` counts as an index read error.
#[inline(never)]
unsafe fn loose_call(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    first: bool,
    call: impl FnMut(*const c_char) -> c_int,
) -> Loose {
    // The game's spelling, normalized without folding, is the key in the
    // game's case: the confirm and the skip list fold, so the path is not
    // normalized a second time for a folded key. The hook's lookup already
    // normalized it, so `spell` cannot fail on a hit.
    let mut sbuf = [0u8; RUNTIME_PATH_CAPACITY];
    let raw = unsafe { cstr_bytes(path) };
    let (Some(c), Some(len)) = (published(), spell(raw, &mut sbuf)) else {
        // No index to confirm against: a miss the index cannot answer.
        (l.state, l.unconfirmed, l.authoritative) = (Resident::Miss, false, false);
        return Loose::Miss;
    };
    let key = &sbuf[..len];
    let spelling = match first {
        true if raw == key => Some(path),
        true => Some(sbuf.as_ptr().cast()),
        false => None,
    };
    let r = loose_call_in(c.view().as_ref(), &c.paths, l, key, spelling, pbuf, call);
    match r {
        Loose::Miss => miss_lookup(l, key_plain(raw), key, c.links),
        Loose::Io => stats::add(stats::Stat::IndexLookupIo, 1),
        Loose::Done(_) => {}
    }
    r
}

/// A file hit opened by its stored path (`real`, or -1 when `hit_path`
/// could not read it), an unconfirmed loose one by `loose_call`. None when
/// the loose hit was a false hash match: `l` is then a miss to open as one.
/// An O_CREAT open reads the stored path first: the game's spelling would
/// create a second file beside one stored in another case, and on a
/// read-only /app0 fail EROFS, not ENOENT.
unsafe fn open_hit_path(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    real: RealOpen,
) -> Option<c_int> {
    let first = flags & O_CREAT == 0;
    match unsafe { hit_call(l, pbuf, path, first, |p| real(p, flags, mode)) } {
        Loose::Done(fd) => Some(fd),
        Loose::Miss => None,
        Loose::Io => {
            set_errno(EIO);
            Some(-1)
        }
    }
}

/// The real `call` of file hit `l`: `loose_call` for an unconfirmed loose
/// hit, else on its stored path (`hit_path`), where a path that cannot be
/// read is `Io`, never a miss.
unsafe fn hit_call(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    first: bool,
    mut call: impl FnMut(*const c_char) -> c_int,
) -> Loose {
    if l.unconfirmed {
        return unsafe { loose_call(l, pbuf, path, first, call) };
    }
    let p = unsafe { hit_path(l, pbuf) };
    if p.is_null() {
        return Loose::Io;
    }
    Loose::Done(call(p))
}

/// `l` from a lazy `lookup_resident`: a file hit has a null `entry.path`,
/// read into `pbuf` only when the open falls back to the real file
/// (`hit_path`), or for a loose hit, when its own spelling is not found
/// (`loose_call`).
unsafe fn open_resolved(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    real: RealOpen,
) -> c_int {
    let dir_flag = flags & O_DIRECTORY != 0;
    let mut handled = false;
    match l.state {
        Resident::Directory => {
            if !dir_path_in(published(), l, pbuf) {
                io_lookup(l);
                return unsafe { open_resolved(l, pbuf, path, flags, mode, real) };
            }
            stats::add(stats::Stat::OpenDirectory, 1);
            let mut canon = [0u8; RUNTIME_PATH_CAPACITY];
            if !unsafe { copy_dir_path(&l, &mut canon) } {
                set_errno(ENAMETOOLONG);
                return -1;
            }
            let canon: *const c_char = canon.as_ptr().cast();
            if directory_open_flags(flags) && l.packs_ready() {
                let rc = unsafe { ampr_pack_open_directory(canon, flags, mode, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
            }
            unsafe { real(canon, flags, mode) }
        }
        Resident::Hit => {
            if dir_flag {
                // A writable /app0 may have replaced a loose file with a
                // directory: the filesystem answers, as for stat and access.
                if rw::app0_writable() && !unsafe { hit_is_packed(l) } {
                    return match unsafe { open_hit_path(l, pbuf, path, flags, mode, real) } {
                        Some(fd) => fd,
                        None => unsafe { open_resolved(l, pbuf, path, flags, mode, real) },
                    };
                }
                set_errno(ENOTDIR);
                return -1;
            }
            // A packed file lives only in a pack volume (ampr_zstd-NNN.pak or
            // an AMPRPAK4 volume), so a packed hit opens a virtual fd; a loose
            // one (unhandled) opens the physical file below.
            stats::add(stats::Stat::OpenHit, 1);
            if l.packs_ready() {
                let rc = unsafe {
                    ampr_pack_try_open_indexed(l.file_id, &l.entry, flags, mode, &mut handled)
                };
                if handled {
                    stats::add(stats::Stat::OpenVirtual, 1);
                    #[cfg(feature = "mem_report")]
                    if rc < 0 {
                        stats::fs_event(b'Q', b'H', rc as i64, path);
                    }
                    return posix_return_from_sce(rc);
                }
            }
            let Some(mut fd) = (unsafe { open_hit_path(l, pbuf, path, flags, mode, real) }) else {
                return unsafe { open_resolved(l, pbuf, path, flags, mode, real) };
            };
            // A loose file the game unlinked, then removed its real parent:
            // the index still lists both, so make the parents and retry once.
            if fd < 0
                && errno() == ENOENT
                && !l.entry.path.is_null()
                && create_needs_parents(flags, rw::app0_writable())
                && !unsafe { hit_is_packed(l) }
            {
                fd = unsafe { create_in_indexed_parent(l.entry.path, flags, mode, real) };
            }
            if fd < 0 {
                stats::add(stats::Stat::OpenRealFailed, 1);
                #[cfg(feature = "mem_report")]
                stats::fs_event(b'Q', b'R', errno() as i64, path);
            }
            fd
        }
        Resident::Miss => {
            stats::add(stats::Stat::OpenMiss, 1);
            // The runtime's own opens of its volumes and indexes can come
            // back through the `_open` hook (from inside libkernel's `open`);
            // they are physical files the index need not list.
            if is_service_path(path) {
                return unsafe { real(path, flags, mode) };
            }
            if directory_open_flags(flags) && l.pack_miss() {
                let rc =
                    unsafe { ampr_pack_open_virtual_directory(path, flags, mode, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
            }
            // A writable /app0 has no authoritative miss, so this is the
            // real open the line below would make.
            if create_needs_parents(flags, rw::app0_writable()) {
                return unsafe { io_miss(l, create_in_indexed_parent(path, flags, mode, real)) };
            }
            if !l.authoritative {
                return unsafe { io_miss(l, with_miss_path(path, |p| real(p, flags, mode))) };
            }
            index_miss()
        }
        Resident::NotApp0 | Resident::IndexNotReady => {
            let not_ready = l.state == Resident::IndexNotReady;
            stats::add(
                if not_ready {
                    stats::Stat::OpenIndexNotReady
                } else {
                    stats::Stat::OpenNotApp0
                },
                1,
            );
            if directory_open_flags(flags) && unsafe { has_app0_root(path) } && l.packs_ready() {
                let rc = unsafe { ampr_pack_open_directory(path, flags, mode, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
            }
            let fd = unsafe { real(path, flags, mode) };
            if fd < 0 {
                stats::add(stats::Stat::OpenRealFailed, 1);
                #[cfg(feature = "mem_report")]
                stats::fs_event(b'Q', b'R', errno() as i64, path);
            }
            fd
        }
    }
}

/// `access` on an indexed file or directory: 0 or the errno. Packed files
/// stat as 0444, so a file hit is not executable (directories are
/// searchable). W_OK is EROFS on a read-only /app0, and on a packed file in
/// any mode (packed files stay read-only); 0 otherwise.
fn indexed_access_errno(state: Resident, mode: c_int, rw: bool, packed: bool) -> c_int {
    if mode & W_OK != 0 && (!rw || (state == Resident::Hit && packed)) {
        EROFS
    } else if state == Resident::Hit && mode & X_OK != 0 {
        EACCES
    } else {
        0
    }
}

/// A miss opened with O_CREAT on a writable /app0 makes its real parents
/// first; a read-only /app0 makes none.
fn create_needs_parents(flags: c_int, rw: bool) -> bool {
    rw && flags & O_CREAT != 0
}

/// Writable /app0: a create under an indexed directory opens the index's
/// spelling of that directory plus the caller's leaf, so a case-sensitive
/// install finds it, after making the directory if it is packed-only. Any
/// other create, or a failed mkdir, opens the caller's path as given.
/// Kept out of `open_resolved` so its path buffers stay off that frame.
#[inline(never)]
unsafe fn create_in_indexed_parent(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    real: RealOpen,
) -> c_int {
    let mut key = [0u8; RUNTIME_PATH_CAPACITY];
    let mut target: EntryPath = [0; PATH_BUF];
    let ok = unsafe { indexed_parent_path(path, true, &mut key, &mut target) };
    unsafe { real(if ok { target.as_ptr().cast() } else { path }, flags, mode) }
}

/// Writable /app0: `f` gets a miss's path with its indexed parent's
/// spelling, so a file made by `create_in_indexed_parent` is found again by
/// the caller's spelling on a case-sensitive install. A read-only /app0, or
/// a parent the index does not know, passes the caller's path.
#[inline(never)]
unsafe fn with_miss_path<R>(path: *const c_char, f: impl FnOnce(*const c_char) -> R) -> R {
    if !rw::app0_writable() {
        return f(path);
    }
    let mut key = [0u8; RUNTIME_PATH_CAPACITY];
    let mut target: EntryPath = [0; PATH_BUF];
    let ok = unsafe { indexed_parent_path(path, false, &mut key, &mut target) };
    f(if ok { target.as_ptr().cast() } else { path })
}

/// Writes the NUL-terminated path under the indexed parent's spelling into
/// `target`, making a packed-only parent first when `make`; false to keep
/// the caller's path. `key` is scratch. The directory lookup copies a
/// descendant's indexed path into `target`, whose first `path_length`
/// bytes are then the directory's spelling; an index read error keeps the
/// caller's path too.
unsafe fn indexed_parent_path(
    path: *const c_char,
    make: bool,
    key: &mut [u8],
    target: &mut EntryPath,
) -> bool {
    let raw = unsafe { cstr_bytes(path) };
    let leaf = raw.rsplit(|&b| b == b'/').next().unwrap_or(raw);
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return false;
    }
    let Some(n) = (unsafe { normalize_key(path, key) }) else {
        return false;
    };
    // A file directly in /app0 has no parent to make.
    let cut = match key[..n].iter().rposition(|&b| b == b'/') {
        Some(c) if c > 5 => c,
        _ => return false,
    };
    let Ok(Some(e)) = (unsafe { lookup_directory_key(&key[..cut], Some(&mut *target)) }) else {
        return false;
    };
    let dir = e.path_length as usize;
    if e.path.is_null() || dir + 1 + leaf.len() >= target.len() {
        return false;
    }
    if make && unsafe { rw::make_dirs(&target[..dir], key) }.is_err() {
        return false;
    }
    target[dir] = b'/';
    target[dir + 1..dir + 1 + leaf.len()].copy_from_slice(leaf);
    target[dir + 1 + leaf.len()] = 0;
    true
}

/// A file hit the index answers: always on a read-only /app0; on a
/// writable one only a packed file, since a loose file can be rewritten,
/// truncated or unlinked after the walk.
fn hit_from_index(rw: bool, packed: bool) -> bool {
    !rw || packed
}

/// A loose file hit on a writable /app0: stat, access and reachability ask
/// the FS on its indexed spelling. A read-only /app0 pays one Relaxed load.
unsafe fn live_loose_hit(l: &Lookup) -> bool {
    let rw = rw::app0_writable();
    l.state == Resident::Hit && !hit_from_index(rw, rw && unsafe { hit_is_packed(l) })
}

/// A hit the packs serve: with the manifest ready, the view's link the
/// lookup read (`Lookup::packed`, what `file_id_is_packed` reads from the
/// same view). Before the manifest is ready, or once shutdown has started,
/// a title with packs counts its hits as packed (no real copy to ask); a
/// title without packs has only loose files.
unsafe fn hit_is_packed(l: &Lookup) -> bool {
    if !l.packs_ready() {
        return super::pack::packs_present();
    }
    l.packed
}

/// `posix_stat_impl`.
unsafe fn stat_impl(path: *const c_char, sb: *mut Stat) -> c_int {
    if sb.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    unsafe { stat_with(path, sb, real_posix_stat, b's') }
}

unsafe fn stat_with(path: *const c_char, sb: *mut Stat, real: RealStat, op: u8) -> c_int {
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let mut l = unsafe { lookup_resident(path, &mut pbuf, true) };
    let rc = unsafe { stat_resolved(&mut l, &mut pbuf, path, sb, real) };
    stats::fs_event(op, how(&l), rc as i64, path);
    rc
}

/// `l` from a lazy `lookup_resident`: a file hit the index answers reads
/// no path (a loose one is trusted on its hash, as a packed one is); a
/// live loose hit asks the FS through `hit_call`.
unsafe fn stat_resolved(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    sb: *mut Stat,
    real: RealStat,
) -> c_int {
    match l.state {
        Resident::Directory => unsafe { sb.write_unaligned(dir_stat(l)) },
        Resident::Hit if unsafe { live_loose_hit(l) } => {
            return match unsafe { hit_call(l, pbuf, path, true, |p| real(p, sb.cast())) } {
                Loose::Done(rc) => rc,
                Loose::Miss => unsafe { stat_resolved(l, pbuf, path, sb, real) },
                Loose::Io => {
                    set_errno(EIO);
                    -1
                }
            };
        }
        Resident::Hit => unsafe { sb.write_unaligned(file_stat(l)) },
        Resident::Miss => {
            let mut pack_io = false;
            if l.pack_miss() {
                let mut handled = false;
                let rc = unsafe { ampr_pack_try_stat_path(path, sb, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
                // The pack index could not be read: the file may be loose.
                pack_io = rc == SCE_KERNEL_ERROR_EIO;
            }
            if !l.authoritative || pack_io {
                let rc = unsafe { with_miss_path(path, |p| real(p, sb.cast())) };
                return unsafe { io_miss_if(l.io || pack_io, rc) };
            }
            return index_miss();
        }
        _ => return unsafe { real(path, sb.cast()) },
    }
    0
}

/// `sceKernelCheckReachability_impl`.
unsafe fn reachability_impl(path: *const c_char) -> c_int {
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let mut l = unsafe { lookup_resident(path, &mut pbuf, true) };
    let rc = unsafe { reachability_resolved(&mut l, &mut pbuf, path) };
    stats::fs_event(b'r', how(&l), rc as i64, path);
    rc
}

/// As `stat_resolved`, with SCE error codes.
unsafe fn reachability_resolved(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
) -> c_int {
    match l.state {
        Resident::Hit if unsafe { live_loose_hit(l) } => {
            match unsafe { hit_call(l, pbuf, path, true, |p| real_check_reachability(p)) } {
                Loose::Done(rc) => rc,
                Loose::Miss => unsafe { reachability_resolved(l, pbuf, path) },
                Loose::Io => sce_errno(EIO),
            }
        }
        Resident::Directory | Resident::Hit => 0,
        Resident::Miss => {
            let mut pack_io = false;
            if l.pack_miss() {
                let mut handled = false;
                let rc = unsafe { ampr_pack_try_reachability(path, &mut handled) };
                if handled {
                    return rc;
                }
                pack_io = rc == SCE_KERNEL_ERROR_EIO;
            }
            if !l.authoritative || pack_io {
                let rc = unsafe { with_miss_path(path, |p| real_check_reachability(p)) };
                if (l.io || pack_io) && rc == SCE_KERNEL_ERROR_ENOENT {
                    let packs = l.packs_ready();
                    return sce_errno(io_miss_errno(ENOENT, packs));
                }
                return rc;
            }
            SCE_KERNEL_ERROR_ENOENT
        }
        _ => unsafe { real_check_reachability(path) },
    }
}

/// The first call's result when nothing changed, else the retry.
fn retry_or(same: bool, rc: c_int, err: c_int, retry: impl FnOnce() -> c_int) -> c_int {
    if same {
        return_direct(rc, err)
    } else {
        retry()
    }
}

/// `posix_unlink_impl`: direct first; on ENOENT/ENOTDIR retry the indexed path.
unsafe fn unlink_impl(path: *const c_char) -> c_int {
    let rc = unsafe { real_posix_unlink(path) };
    let err = if rc == -1 { errno() } else { 0 };
    if rc == 0 || !should_try_index_fallback(rc, err) || !unsafe { is_app0_path(path) } {
        return return_direct(rc, err);
    }
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let real = unsafe { maybe_resolve_path(path, &mut pbuf) };
    if real == path {
        if rw::app0_writable() {
            return unsafe {
                with_miss_path(path, |p| {
                    retry_or(p == path, rc, err, || real_posix_unlink(p))
                })
            };
        }
        return return_direct(rc, err);
    }
    unsafe { real_posix_unlink(real) }
}

/// `posix_rename_impl`: as unlink, resolving either side through the index.
unsafe fn rename_impl(from: *const c_char, to: *const c_char) -> c_int {
    let rc = unsafe { real_posix_rename(from, to) };
    let err = if rc == -1 { errno() } else { 0 };
    if rc == 0 {
        return rc;
    }
    if !should_try_index_fallback(rc, err)
        || !(unsafe { is_app0_path(from) } || unsafe { is_app0_path(to) })
    {
        return return_direct(rc, err);
    }
    let (mut from_buf, mut to_buf): (EntryPath, EntryPath) = ([0; PATH_BUF], [0; PATH_BUF]);
    let (rf, rt) = unsafe {
        (
            maybe_resolve_path(from, &mut from_buf),
            maybe_resolve_path(to, &mut to_buf),
        )
    };
    if rw::app0_writable() {
        // A miss on either side takes its indexed parent's spelling.
        return unsafe {
            with_miss_path(rf, |f| {
                with_miss_path(rt, |t| {
                    retry_or(f == from && t == to, rc, err, || real_posix_rename(f, t))
                })
            })
        };
    }
    if rf == from && rt == to {
        return return_direct(rc, err);
    }
    unsafe { real_posix_rename(rf, rt) }
}

// ---- exports ----

/// `int posix_open_emul(const char*, int, ...)`. Stable Rust cannot define a
/// variadic; on SysV x86-64 the first variadic int arrives in the same
/// register as a third fixed one, and it is read only for O_CREAT.
pub unsafe extern "C" fn posix_open_emul(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    let mode = if flags & O_CREAT != 0 {
        mode as SceKernelMode
    } else {
        0
    };
    let t = stats::now();
    let fd = unsafe { open_impl(path, flags, mode) };
    stats::path_span(hook::open, t);
    fd
}

// ---- libkernel's internal path entry points (libc fopen, opendir) ----

const AT_FDCWD: c_int = -100;
const W_OK: c_int = 2;
const X_OK: c_int = 1;
const EROFS: c_int = 30;

/// A runtime file by name, for both formats: `ampr_emu.index`, zstd's
/// `ampr_zstd.index` and `ampr_zstd-NNN.pak`, LZ4's `ampr_assets.index`,
/// `ampr_assets.index.runtime` and `ampr_assets-*.pak`. The LZ4 volume names
/// are the packer's default prefix `ampr_assets-`, as in rt/pack/state.rs
/// `service_name_hidden` (which also folds case and hides more names); a
/// manifest that names its volumes otherwise is not matched here.
fn is_service_path(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    let name = bytes.rsplit(|&b| b == b'/').next().unwrap_or(bytes);
    use ampr_format::zstd::{INDEX_NAME, VOLUME_PREFIX, VOLUME_SUFFIX};
    const LZ4_VOLUME_PREFIX: &[u8] = b"ampr_assets-";
    let volume = |prefix: &[u8], suffix: &[u8]| {
        name.len() > prefix.len() + suffix.len()
            && name.starts_with(prefix)
            && name.ends_with(suffix)
    };
    name == INDEX_NAME.as_bytes()
        || name == b"ampr_emu.index"
        || name == b"ampr_assets.index"
        || name == b"ampr_assets.index.runtime"
        || volume(VOLUME_PREFIX.as_bytes(), VOLUME_SUFFIX.as_bytes())
        || volume(LZ4_VOLUME_PREFIX, b".pak")
}

unsafe fn real_underscore_open(path: *const c_char, flags: c_int, mode: SceKernelMode) -> c_int {
    unsafe { real_underscore_open_raw(path, flags, mode as c_int) }
}

/// `_open` original with the caller's mode word as passed.
unsafe fn real_underscore_open_raw(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
    match unsafe { kernel_slot::<F>(hook::_open) } {
        Some(f) => unsafe { f(path, flags, mode) },
        None => eio(),
    }
}

/// Logs a pass-through libc path call (debug only; see rt/hook.rs
/// `observed_only`).
#[inline(always)]
unsafe fn observe_note(path: *const c_char, op: u8, rc: c_int) {
    #[cfg(feature = "mem_report")]
    unsafe {
        super::probe::probe_path(path, op, rc)
    };
    #[cfg(not(feature = "mem_report"))]
    let _ = (path, op, rc);
}

unsafe fn real_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    type F = unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int;
    match unsafe { kernel_slot::<F>(hook::_openat) } {
        Some(f) => unsafe { f(dirfd, path, flags, mode) },
        None => eio(),
    }
}

/// `_openat` of an absolute or cwd-relative path, as `real_underscore_open`.
unsafe fn real_openat_cwd(path: *const c_char, flags: c_int, mode: SceKernelMode) -> c_int {
    unsafe { real_openat(AT_FDCWD, path, flags, mode as c_int) }
}

unsafe fn real_lstat(path: *const c_char, st: *mut c_void) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
    unsafe { kernel_slot::<F>(hook::lstat) }.map_or_else(eio, |f| unsafe { f(path, st) })
}

unsafe fn real_access(path: *const c_char, mode: c_int) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
    unsafe { kernel_slot::<F>(hook::access) }.map_or_else(eio, |f| unsafe { f(path, mode) })
}

fn creat_mode(flags: c_int, mode: c_int) -> SceKernelMode {
    if flags & O_CREAT != 0 {
        mode as SceKernelMode
    } else {
        0
    }
}

/// Debug: one call into libc open hook `id` that returned `fd`, packed
/// when `fd` is a virtual pack fd (rt/stats.rs `libc_hit`).
#[inline(always)]
fn note_libc_open(id: usize, fd: c_int) {
    if cfg!(feature = "mem_report") {
        stats::libc_hit(
            id,
            fd >= 0 && unsafe { super::pack::ampr_pack_is_virtual_fd(fd) },
        );
    }
}

/// `_open`, variadic like `open` (see `posix_open_emul`).
pub unsafe extern "C" fn underscore_open_emul(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    let t = stats::now();
    let rc = unsafe { underscore_open_body(path, flags, mode) };
    stats::path_span(hook::_open, t);
    rc
}

/// `underscore_open_emul` without its debug span.
#[inline(always)]
unsafe fn underscore_open_body(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    if super::hook::observed_only(hook::_open) {
        let rc = unsafe { real_underscore_open_raw(path, flags, mode) };
        unsafe { observe_note(path, b'O', rc) };
        note_libc_open(hook::_open, rc);
        return rc;
    }
    let fd = unsafe {
        open_with(
            path,
            flags,
            creat_mode(flags, mode),
            real_underscore_open,
            b'O',
        )
    };
    note_libc_open(hook::_open, fd);
    fd
}

/// `_openat`: an absolute or cwd-relative path takes the `open` routing; a
/// path relative to another directory fd goes to the original.
pub unsafe extern "C" fn underscore_openat_emul(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    let t = stats::now();
    let rc = unsafe { underscore_openat_body(dirfd, path, flags, mode) };
    stats::path_span(hook::_openat, t);
    rc
}

/// `underscore_openat_emul` without its debug span.
#[inline(always)]
unsafe fn underscore_openat_body(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    if path.is_null() || (unsafe { *path } != b'/' as c_char && dirfd != AT_FDCWD) {
        stats::libc_hit(hook::_openat, false);
        return unsafe { real_openat(dirfd, path, flags, mode) };
    }
    if super::hook::observed_only(hook::_openat) {
        let rc = unsafe { real_openat(dirfd, path, flags, mode) };
        unsafe { observe_note(path, b'A', rc) };
        note_libc_open(hook::_openat, rc);
        return rc;
    }
    let fd = unsafe { open_with(path, flags, creat_mode(flags, mode), real_openat_cwd, b'A') };
    note_libc_open(hook::_openat, fd);
    fd
}

pub unsafe extern "C" fn posix_lstat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
    let t = stats::now();
    let rc = unsafe { posix_lstat_body(path, sb) };
    stats::path_span(hook::lstat, t);
    rc
}

/// `posix_lstat_emul` without its debug span.
#[inline(always)]
unsafe fn posix_lstat_body(path: *const c_char, sb: *mut Stat) -> c_int {
    stats::libc_hit(hook::lstat, false);
    if super::hook::observed_only(hook::lstat) {
        let rc = unsafe { real_lstat(path, sb.cast()) };
        unsafe { observe_note(path, b'l', rc) };
        return rc;
    }
    if sb.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    unsafe { stat_with(path, sb, real_lstat, b'l') }
}

/// `access`: an indexed /app0 file or directory exists (read-only); an
/// authoritative miss takes the stat routing (pack overlay, else ENOENT);
/// others the original.
pub unsafe extern "C" fn posix_access_emul(path: *const c_char, mode: c_int) -> c_int {
    let t = stats::now();
    let rc = unsafe { posix_access_body(path, mode) };
    stats::path_span(hook::access, t);
    rc
}

/// `posix_access_emul` without its debug span.
#[inline(always)]
unsafe fn posix_access_body(path: *const c_char, mode: c_int) -> c_int {
    stats::libc_hit(hook::access, false);
    if super::hook::observed_only(hook::access) {
        let rc = unsafe { real_access(path, mode) };
        unsafe { observe_note(path, b'a', rc) };
        return rc;
    }
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let mut l = unsafe { lookup_resident(path, &mut pbuf, true) };
    let rc = unsafe { access_resolved(&mut l, &mut pbuf, path, mode) };
    stats::fs_event(b'a', how(&l), rc as i64, path);
    rc
}

/// `posix_access_emul` for lookup `l`, as `stat_resolved`.
unsafe fn access_resolved(
    l: &mut Lookup,
    pbuf: &mut EntryPath,
    path: *const c_char,
    mode: c_int,
) -> c_int {
    match l.state {
        Resident::Hit if unsafe { live_loose_hit(l) } => {
            match unsafe { hit_call(l, pbuf, path, true, |p| real_access(p, mode)) } {
                Loose::Done(rc) => rc,
                Loose::Miss => unsafe { access_resolved(l, pbuf, path, mode) },
                Loose::Io => {
                    set_errno(EIO);
                    -1
                }
            }
        }
        Resident::Hit | Resident::Directory => {
            // live_loose_hit was false: on a writable /app0 a hit is packed.
            let rw = rw::app0_writable();
            match indexed_access_errno(l.state, mode, rw, rw) {
                0 => 0,
                e => {
                    set_errno(e);
                    -1
                }
            }
        }
        // The pack overlay first (packed-only directories), then the FS.
        Resident::Miss if !l.authoritative => {
            let mut st = core::mem::MaybeUninit::<Stat>::uninit();
            let mut handled = false;
            let rc = if l.pack_miss() {
                unsafe { ampr_pack_try_stat_path(path, st.as_mut_ptr(), &mut handled) }
            } else {
                0
            };
            if handled {
                posix_return_from_sce(rc)
            } else {
                let pack_io = rc == SCE_KERNEL_ERROR_EIO;
                let rc = unsafe { with_miss_path(path, |p| real_access(p, mode)) };
                unsafe { io_miss_if(l.io || pack_io, rc) }
            }
        }
        Resident::Miss => {
            let mut st = core::mem::MaybeUninit::<Stat>::uninit();
            unsafe { stat_resolved(l, pbuf, path, st.as_mut_ptr(), real_lstat) }
        }
        _ => unsafe { real_access(path, mode) },
    }
}

pub unsafe extern "C" fn posix_stat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
    let t = stats::now();
    let rc = unsafe { stat_impl(path, sb) };
    stats::path_span(hook::stat, t);
    rc
}

/// Hook ids of `sceKernelOpen` and `sceKernelStat` (rt/sys.rs `hook`, the
/// 78..=83 group), for the debug path spans.
const HOOK_SCE_OPEN: usize = 78;
const HOOK_SCE_STAT: usize = 79;

pub unsafe extern "C" fn sceKernelOpen_emul(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
) -> c_int {
    let t = stats::now();
    let rc = sce_result(unsafe { open_impl(path, flags, mode) });
    stats::path_span(HOOK_SCE_OPEN, t);
    rc
}

pub unsafe extern "C" fn sceKernelStat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
    let t = stats::now();
    let rc = sce_result(unsafe { stat_impl(path, sb) });
    stats::path_span(HOOK_SCE_STAT, t);
    rc
}

pub unsafe extern "C" fn sceKernelCheckReachability_emul(path: *const c_char) -> c_int {
    let t = stats::now();
    let rc = unsafe { reachability_impl(path) };
    stats::path_span(hook::sceKernelCheckReachability, t);
    rc
}

pub unsafe extern "C" fn posix_unlink_emul(path: *const c_char) -> c_int {
    let t = stats::now();
    let rc = unsafe { unlink_impl(path) };
    stats::path_span(hook::unlink, t);
    rc
}

pub unsafe extern "C" fn posix_rename_emul(from: *const c_char, to: *const c_char) -> c_int {
    let t = stats::now();
    let rc = unsafe { rename_impl(from, to) };
    stats::path_span(hook::rename, t);
    rc
}

pub unsafe fn ampr_index_ensure_ready_safe() -> bool {
    unsafe { ensure_ready(APP0_INDEX_AUTOBUILD) }
}

/// One-based id, its size (if `out_size`), or -EFAULT/-EINVAL/-ENAMETOOLONG/
/// -ENOENT/-EOPNOTSUPP (the /app0 root or a trailing separator).
pub unsafe fn ampr_index_resolve_path_to_id(
    path: *const c_char,
    out_id: *mut u32,
    out_size: *mut usize,
) -> c_int {
    if path.is_null() || out_id.is_null() {
        return -EFAULT;
    }
    let mut buf = [0u8; RUNTIME_PATH_CAPACITY];
    let (len, trailing) = match unsafe { normalize_key_result(path, &mut buf) } {
        Ok(k) => k,
        Err(e) => return -e,
    };
    if !is_app0_key(&buf[..len]) {
        return -ENOENT;
    }
    if len == 5 || trailing {
        return -EOPNOTSUPP;
    }
    let Some((v, id)) = (match unsafe { lookup_key_view(&buf[..len], APP0_INDEX_AUTOBUILD, None) } {
        Ok(found) => found,
        // Not ENOENT: the file may be packed (rt/pack callers serve EIO).
        Err(IndexIo) => return -EIO,
    }) else {
        return -ENOENT;
    };
    unsafe {
        if !out_size.is_null() {
            *out_size = v.size;
        }
        *out_id = id;
    }
    0
}

/// Size and mtime of one-based file `id`; `out.path` is null (callers that
/// need the path use `ampr_index_get_entry_view_path`).
pub unsafe fn ampr_index_get_entry_view(id: u32, out: *mut FileEntryView) -> c_int {
    unsafe { entry_view_by_id(id, out, None) }
}

/// `ampr_index_get_entry_view` plus the path, copied NUL-terminated into
/// `path`; `out.path` points there and lives as long as `path`.
pub unsafe fn ampr_index_get_entry_view_path(
    id: u32,
    out: *mut FileEntryView,
    path: &mut EntryPath,
) -> c_int {
    unsafe { entry_view_by_id(id, out, Some(path)) }
}

unsafe fn entry_view_by_id(
    id: u32,
    out: *mut FileEntryView,
    path: Option<&mut EntryPath>,
) -> c_int {
    if id == 0 || id == FILEID_INVALID || !unsafe { ensure_ready(APP0_INDEX_AUTOBUILD) } {
        return -ENOENT;
    }
    let Some(c) = published().filter(|c| c.available && (id as usize - 1) < c.count) else {
        return -ENOENT;
    };
    let mut v = empty_view();
    match c.try_entry_view(id, &mut v, path) {
        Ok(()) => {}
        Err(ampr_format::Error::Io) => return -EIO,
        Err(_) => return -ENOENT,
    }
    if !out.is_null() {
        unsafe { *out = v };
    }
    0
}

// ---- AMPRPAK4 core shim ----

// zstd mode routes the five `ampr_pack_core_*` bodies to rt/pack/zstd.rs
// (same ABI); the AMPRPAK4 helpers below serve LZ4 mode.
use super::pack::{zstd, zstd_mode};
use ampr_lz4::manifest::{FileRecord, Manifest};
use ampr_lz4::plan::{self, CoreError};
use ampr_lz4::plan::{ChunkView, ReadTask};
use ampr_lz4::{FILE_RECORD, PAK_HEADER};

const PACK_OK: c_int = 0;
const PACK_INVALID_ARGUMENT: c_int = -1;

/// The mounted AMPRPAK4 manifest over the resident parts of its file
/// (header, record sections, pack names), its records read through the
/// fast table (rt/pack/manifest.rs `LZ4_IMAGE`).
pub(crate) type Lz4Manifest = Manifest<'static, ResidentSource<'static>>;

/// `AmprPackCoreView`: the mounted manifest and a copy of its header.
#[derive(Clone, Copy)]
pub(crate) struct AmprPackCoreView {
    pub manifest: Option<Lz4Manifest>,
    pub header: super::pack::AmprPackIndexHeader,
}

/// `AmprPackChunkView`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AmprPackChunkView {
    pub offset: u64,
    pub stored_size: u32,
    pub raw_size: u32,
    pub pack_id: u16,
    pub codec: u8,
    pub flags: u8,
    /// KRAKEN chunks' even_len | mode << 19 (`ampr_pkg::pkg_chunk`),
    /// in what was tail padding.
    pub kraken: u32,
}

/// `AmprPackBlockReadTask`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AmprPackBlockReadTask {
    pub chunk_index: u32,
    pub source_offset: u32,
    pub copy_length: u32,
    pub destination_offset: u32,
    pub chunk: AmprPackChunkView,
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<AmprPackChunkView>() == 24);
    assert!(
        offset_of!(AmprPackChunkView, stored_size) == 8
            && offset_of!(AmprPackChunkView, raw_size) == 12
    );
    assert!(
        offset_of!(AmprPackChunkView, pack_id) == 16 && offset_of!(AmprPackChunkView, codec) == 18
    );
    assert!(
        offset_of!(AmprPackChunkView, flags) == 19 && offset_of!(AmprPackChunkView, kraken) == 20
    );
    assert!(
        size_of::<AmprPackBlockReadTask>() == 40 && offset_of!(AmprPackBlockReadTask, chunk) == 16
    );
};

impl From<ChunkView> for AmprPackChunkView {
    fn from(v: ChunkView) -> Self {
        // A KRAKEN location only splits right in pkg mode, where `open_pkg`
        // admitted it; elsewhere upstream `open` refused the codec.
        let (offset, pack_id, kraken) = if crate::rt::pack::pkg_mode() {
            ampr_pkg::pkg_chunk(v.chunk)
        } else {
            (v.chunk.offset, v.chunk.pack_id, 0)
        };
        Self {
            offset,
            stored_size: v.chunk.stored_size,
            raw_size: v.raw_size,
            pack_id,
            codec: v.chunk.codec,
            flags: v.chunk.flags,
            kraken,
        }
    }
}

impl From<ReadTask> for AmprPackBlockReadTask {
    fn from(t: ReadTask) -> Self {
        Self {
            chunk_index: t.chunk_index,
            source_offset: t.source_offset,
            copy_length: t.copy_length,
            destination_offset: t.destination_offset,
            chunk: t.chunk.into(),
        }
    }
}

/// A borrowed region; None for null or overflowing ranges.
unsafe fn region<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    (!p.is_null() && len <= isize::MAX as usize && (p as usize).checked_add(len).is_some())
        .then(|| unsafe { core::slice::from_raw_parts(p, len) })
}

/// `file` is a caller-owned copy of a 48-byte record (rt/pack
/// virtual_read.rs `TaskFile`), never a pointer into the manifest.
unsafe fn file_record(file: *const u8) -> Option<FileRecord> {
    FileRecord::parse(unsafe { region(file, FILE_RECORD) }?).ok()
}

/// The manifest of a mounted view (trusted: validated once at mount).
unsafe fn view_manifest(v: *const AmprPackCoreView) -> Option<Lz4Manifest> {
    unsafe { v.as_ref() }?.manifest
}

pub unsafe fn ampr_pack_crc32(data: *const c_void, size: usize, seed: u32) -> u32 {
    if size == 0 {
        return ampr_format::crc32_seeded(&[], seed);
    }
    unsafe { region(data.cast(), size) }.map_or(0, |b| ampr_format::crc32_seeded(b, seed))
}

/// Full `Manifest::open` (`open_pkg` when `pkg`) validation of the whole
/// file through `check`, then fills `out` (empty on error) with a manifest
/// over `resident`, the parts of the same file kept after the mount; LZ4
/// and pkg only (zstd mounts through `zstd::zstd_mount_join`).
pub(crate) unsafe fn ampr_pack_core_mount<S: Source + ?Sized>(
    check: &S,
    resident: &'static ResidentSource<'static>,
    pkg: bool,
    out: *mut AmprPackCoreView,
) -> c_int {
    if out.is_null() {
        return PACK_INVALID_ARGUMENT;
    }
    unsafe { out.write(AmprPackCoreView::EMPTY) };
    let mut h = [0u8; PAK_HEADER];
    if resident.read_at(0, &mut h).is_err() {
        return PACK_INVALID_ARGUMENT;
    }
    // The checked manifest reads through `check`, so it is dropped; the
    // kept one is the same header over `resident`, whose bytes are the
    // file's, without a second pass.
    let m = match open_manifest(check, pkg).and_then(|_| Manifest::view_trusted(resident)) {
        Ok(m) => m,
        Err(e) => return CoreError::from(e).code(),
    };
    // Manifest::open checked the header; the copy keeps its on-disk layout.
    let header = unsafe { core::ptr::read_unaligned(h.as_ptr().cast()) };
    unsafe {
        out.write(AmprPackCoreView {
            manifest: Some(m),
            header,
        })
    };
    PACK_OK
}

/// `Manifest::open`, or with `pkg` `open_pkg`, which loosens validation
/// for pack 0 (the .pkg) only, so upstream `open` never sees the KRAKEN
/// codec it refuses.
fn open_manifest<S: Source + ?Sized>(src: &S, pkg: bool) -> ampr_lz4::Result<()> {
    if pkg {
        ampr_pkg::open_pkg(src).map(|_| ())
    } else {
        Manifest::open(src).map(|_| ())
    }
}

/// Log2 of the chunk size of `file`, the read task size: 256 KiB for zstd,
/// the file record's `block_shift` for LZ4 and pkg. None for a bad record.
pub unsafe fn ampr_pack_core_chunk_shift(file: *const u8) -> Option<u32> {
    if zstd_mode() {
        return Some(u32::from(ampr_format::zstd::CHUNK_SHIFT));
    }
    unsafe { file_record(file) }.map(|f| u32::from(f.block_shift))
}

/// Block tasks for a read of `file`; zero for a rejected request. zstd:
/// `file` points at a `zstd::ZstdExtent`, tasks are 256 KiB chunks.
pub unsafe fn ampr_pack_core_task_count(file: *const u8, offset: u64, length: u64) -> usize {
    if zstd_mode() {
        return zstd::zstd_core_task_count(file, offset, length);
    }
    {
        unsafe { file_record(file) }.map_or(0, |f| plan::task_count(&f, offset, length))
    }
}

/// Task `task_index` of a read; `*out` is zeroed on every error.
pub unsafe fn ampr_pack_core_make_task(
    view: *const AmprPackCoreView,
    file: *const u8,
    offset: u64,
    length: u64,
    task_index: usize,
    out: *mut AmprPackBlockReadTask,
) -> c_int {
    // zstd: `file` points at a `zstd::ZstdExtent`; `view` is unused.
    if zstd_mode() {
        return unsafe { zstd::zstd_core_make_task(file, offset, length, task_index, out) };
    }
    {
        if out.is_null() {
            return PACK_INVALID_ARGUMENT;
        }
        unsafe { out.write(AmprPackBlockReadTask::default()) };
        let task = unsafe { view_manifest(view) }
            .zip(unsafe { file_record(file) })
            .ok_or(CoreError::InvalidArgument)
            .and_then(|(m, f)| m.read_task(&f, offset, length, task_index));
        match task {
            Ok(t) => {
                unsafe { out.write(t.into()) };
                PACK_OK
            }
            Err(e) => e.code(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::index_memory as im;
    use super::*;

    /// `reset` once ended in `*self = Self::new()`, which drops the old
    /// value first: `Drop::drop` calls `reset`, so every reset and every
    /// drop of a ScratchBuffer, empty ones included, recursed until the
    /// stack was gone. The walk build of a title without `ampr_emu.index`
    /// (a getdents buffer per directory, then the index writer's buffer)
    /// died with a stack overflow in the main thread at module load:
    /// Final Fantasy XVI (PPSA10665, coredump PPSA10665_1794984023), and
    /// v0.4.1 carries it too. The host has no pool, so only an empty buffer
    /// is tested; the recursion did not depend on holding memory, since the
    /// compiled drop called itself on the null path as well.
    #[test]
    fn an_empty_scratch_buffer_resets_and_drops() {
        let mut b = ScratchBuffer::new();
        b.reset();
        assert!(!b.valid());
        b.reset();
        drop(b);
    }

    /// zstd runtime files and the shared AMPRIDX3 index bypass the index.
    #[test]
    fn service_path_covers_zstd_index_and_volumes() {
        for yes in [
            c"/app0/ampr_zstd.index",
            c"/app0/ampr_zstd-000.pak",
            c"/app0/ampr_zstd-1234.pak",
            c"/app0/ampr_emu.index",
        ] {
            assert!(is_service_path(yes.as_ptr()), "{yes:?}");
        }
        for no in [
            c"/app0/ampr_zstd-000.pak.tmp",
            c"/app0/game.index",
            c"/app0/game/game.uproject",
            c"/app0/uecommandline.txt",
        ] {
            assert!(!is_service_path(no.as_ptr()), "{no:?}");
        }
        assert!(!is_service_path(core::ptr::null()));
    }

    /// LZ4 runtime files bypass the index too: its manifest, the runtime
    /// profile next to it, and the default-named AMPRPAK4 volumes.
    #[test]
    fn service_path_covers_lz4_index_and_volumes() {
        for yes in [
            c"/app0/ampr_assets.index",
            c"/app0/ampr_assets.index.runtime",
            c"/app0/ampr_assets-000.pak",
            c"/app0/ampr_assets-17.pak",
        ] {
            assert!(is_service_path(yes.as_ptr()), "{yes:?}");
        }
        for no in [
            c"/app0/ampr_assets-.pak",
            c"/app0/ampr_assets-000.pak.tmp",
            c"/app0/ampr_assets.index.bak",
            c"/app0/d/0/actor",
        ] {
            assert!(!is_service_path(no.as_ptr()), "{no:?}");
        }
    }

    /// Only misses the /app0 walk can answer are final; the rest go to the
    /// filesystem.
    #[test]
    fn authoritative_misses() {
        let miss_with = |raw: &CStr, links: bool| {
            let mut key = [0u8; RUNTIME_PATH_CAPACITY];
            let len = unsafe { normalize_key(raw.as_ptr(), &mut key) }.unwrap();
            assert_eq!(key_plain(raw.to_bytes()), {
                let mut k = [0u8; RUNTIME_PATH_CAPACITY];
                unsafe { normalize_key_full(raw.as_ptr(), &mut k) }
                    .unwrap()
                    .plain
            });
            miss_is_authoritative(key_plain(raw.to_bytes()), &key[..len], links)
        };
        let miss = |raw: &CStr| miss_with(raw, false);
        // ASCII case variants fold to the indexed key: the miss holds on exFAT too.
        assert!(miss(c"/app0/Data/Missing.BIN"));
        assert!(miss(c"/APP0/data//missing.bin"));
        // exFAT folds non-ASCII case; keys do not.
        assert!(!miss(c"/app0/Donn\xc3\xa9es/x.bin"));
        assert!(!miss(c"/app0/a\tb.bin"));
        for own in [
            c"/app0/ampr_emu.index",
            c"/app0/AMPR_EMU.LOG",
            c"/app0/ampr_commands.bin",
        ] {
            assert!(!miss(own), "{own:?}");
        }
        // A skipped directory link hides a subtree: no ASCII miss holds.
        assert!(!miss_with(c"/app0/Data/Missing.BIN", true));
        assert!(!miss_with(c"/app0/linked/x.bin", true));
        // Outside pkg mode (host tests) a kraken dir is the title's own.
        assert!(miss(c"/app0/kraken"));
        assert!(miss(c"/app0/Kraken/game.pkg"));
        assert!(miss(c"/app0/krakenx/a.bin"));
    }

    /// `/app0/kraken` and its subtree bypass the index, in any ASCII case
    /// and spelling; a sibling with the same prefix does not.
    #[test]
    fn kraken_key_shape_covers_the_mount() {
        let shape = |p: &CStr| {
            let mut key = [0u8; RUNTIME_PATH_CAPACITY];
            unsafe { normalize_key(p.as_ptr(), &mut key) }
                .is_some_and(|n| kraken_key_shape(&key[..n]))
        };
        for yes in [
            c"/app0/kraken",
            c"/app0/kraken/",
            c"/app0/kraken/game.pkg",
            c"/APP0//Kraken/sub/x.bin",
            c"/app0/x/../kraken/a.pkg",
        ] {
            assert!(shape(yes), "{yes:?}");
            // Not a service path: in pkg mode lookup_resident_path sends
            // the mount to the filesystem before any miss handling.
            assert!(!is_service_path(yes.as_ptr()), "{yes:?}");
        }
        for no in [
            c"/app0/krakenx",
            c"/app0/kraken.pkg",
            c"/app0/data/kraken/a.pkg",
        ] {
            assert!(!shape(no), "{no:?}");
        }
    }

    /// USB index I/O: the write loop continues short transfers and retries
    /// EINTR, and fails on errors and endless EINTR. (Index file reads go
    /// through rt/index_file.rs `pread_fd` and the pack `pread_loop`.)
    #[test]
    fn io_loops_continue_short_transfers_and_retry_eintr() {
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut out = std::vec::Vec::new();
        let mut calls = 0;
        assert!(write_all_with(&data, |chunk| {
            calls += 1;
            if calls % 3 == 0 {
                return SCE_KERNEL_ERROR_EINTR as isize;
            }
            let n = chunk.len().min(77);
            out.extend_from_slice(&chunk[..n]);
            n as isize
        }));
        assert_eq!(out, data);
        assert!(!write_all_with(&data, |_| SCE_KERNEL_ERROR_EIO as isize));
        assert!(!write_all_with(&data, |_| SCE_KERNEL_ERROR_EINTR as isize));
    }

    /// rw mode lifts EROFS for loose files and directories only; packed
    /// files stay read-only, and outside rw mode access answers as before.
    #[test]
    fn indexed_access_in_and_out_of_rw_mode() {
        use Resident::{Directory, Hit};
        // (state, mode, packed, read-only answer, writable answer)
        for (state, mode, packed, ro, rw) in [
            (Hit, 0, true, 0, 0),
            (Hit, W_OK, true, EROFS, EROFS),
            (Hit, W_OK, false, EROFS, 0),
            (Directory, W_OK, false, EROFS, 0),
            (Directory, W_OK, true, EROFS, 0),
            (Hit, X_OK, true, EACCES, EACCES),
            (Hit, W_OK | X_OK, true, EROFS, EROFS),
            (Hit, W_OK | X_OK, false, EROFS, EACCES),
            (Directory, X_OK, false, 0, 0),
        ] {
            assert_eq!(indexed_access_errno(state, mode, false, packed), ro);
            assert_eq!(indexed_access_errno(state, mode, true, packed), rw);
        }
    }

    /// A read-only /app0 answers every file hit from the index; a writable
    /// one only packed hits, a loose one asks the FS.
    #[test]
    fn hit_from_index_in_and_out_of_rw_mode() {
        assert!(hit_from_index(false, true));
        assert!(hit_from_index(false, false));
        assert!(hit_from_index(true, true));
        assert!(!hit_from_index(true, false));
    }

    /// A read-only /app0 keeps an authoritative miss; a writable one never has one.
    #[test]
    fn miss_authority_in_and_out_of_rw_mode() {
        assert!(miss_authority(true, false));
        assert!(!miss_authority(false, false));
        assert!(!miss_authority(true, true));
        assert!(!miss_authority(false, true));
    }

    /// Only an O_CREAT open on a writable /app0 makes real parents.
    #[test]
    fn create_parents_only_in_rw_mode() {
        for flags in [O_CREAT | O_WRONLY, O_CREAT | O_TRUNC | O_WRONLY] {
            assert!(create_needs_parents(flags, true));
            assert!(!create_needs_parents(flags, false));
        }
        for flags in [O_RDONLY, O_WRONLY, O_WRONLY | O_TRUNC] {
            assert!(!create_needs_parents(flags, true));
            assert!(!create_needs_parents(flags, false));
        }
    }

    #[test]
    fn index_stat_keeps_64_bit_sizes() {
        let l = Lookup {
            state: Resident::Hit,
            entry: FileEntryView {
                path: c"/app0/Big.pak".as_ptr(),
                path_length: 13,
                size: 8_130_000_000,
                mtime: 1,
            },
            file_id: 2,
            expected_miss: false,
            authoritative: false,
            io: false,
            unconfirmed: false,
            ..Lookup::empty()
        };
        let st = file_stat(&l);
        assert_eq!(st.st_size, 8_130_000_000);
        assert_eq!(st.st_blocks, 8_130_000_000 / 512 + 1);
    }

    /// A lookup that cannot read the index is not a miss: `find` and
    /// `find_directory` errors come back as `IndexIo` (other errors still
    /// read as no answer), the lookup is a non-authoritative miss that the
    /// hook sends to the real call, and an ENOENT from that call becomes EIO
    /// while packs are mounted.
    #[test]
    fn an_index_read_error_is_not_an_authoritative_miss() {
        use core::cell::Cell;
        struct Failing<'a>(&'a [u8], Cell<bool>);
        impl ampr_format::source::Source for Failing<'_> {
            fn len(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
                if self.1.get() {
                    return Err(ampr_format::Error::Io);
                }
                self.0.read_at(at, out)
            }
        }
        let image = sized_image(64, 8 << 10);
        let src = Failing(&image, Cell::new(false));
        let view = Index::open(&src).unwrap();
        let mut buf: EntryPath = [0; PATH_BUF];
        let path = view
            .path(&view.record(3).unwrap(), &mut buf)
            .unwrap()
            .to_vec();
        assert_eq!(io_or_none(view.find(&path)), Ok(Some(3)));
        assert_eq!(io_or_none(view.find(b"no/app0")), Ok(None));
        src.1.set(true);
        assert_eq!(io_or_none(view.find(&path)), Err(IndexIo));
        assert_eq!(
            io_or_none(view.find_directory(b"/app0/d001", true)),
            Err(IndexIo)
        );
        assert_eq!(io_or_none(view.find(b"no/app0")), Ok(None));

        let mut l = Lookup {
            state: Resident::NotApp0,
            entry: empty_view(),
            file_id: 0,
            expected_miss: false,
            authoritative: true,
            io: false,
            unconfirmed: false,
            ..Lookup::empty()
        };
        io_lookup(&mut l);
        assert!(l.state == Resident::Miss && l.io && !l.authoritative);
        assert_eq!(how(&l), b'M');
        assert_eq!(io_miss_errno(ENOENT, true), EIO);
        assert_eq!(io_miss_errno(ENOENT, false), ENOENT);
        assert_eq!(io_miss_errno(EACCES, true), EACCES);
    }

    /// Only ENOENT means the index is missing; unreadable loads count only
    /// in a row, saturating.
    /// An Unreadable load waits 100 ms, then 200, 400, ... up to 2 s
    /// before the next; any other result, or no clock, retries at once.
    #[test]
    fn an_unreadable_index_backs_off() {
        let ms = 1_000_000u64;
        assert_eq!(next_retry_at(5 * ms, 0), 0);
        assert_eq!(next_retry_at(0, 3), 0);
        assert_eq!(next_retry_at(5 * ms, 1), 105 * ms);
        assert_eq!(next_retry_at(5 * ms, 2), 205 * ms);
        assert_eq!(next_retry_at(5 * ms, 5), 1605 * ms);
        assert_eq!(next_retry_at(5 * ms, 6), 2005 * ms);
        assert_eq!(next_retry_at(5 * ms, u32::MAX), 2005 * ms);
        assert!(retry_due(1, 0) && retry_due(0, 9) && retry_due(9, 9));
        assert!(!retry_due(8, 9));
    }

    /// The kept fd is refused only while the index holds it.
    #[test]
    fn the_kept_index_fd_is_guarded_until_cleared() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!is_kept_index_fd(-1));
        let mut c = Compact::EMPTY;
        c.paths = Paths::File(PathSource::new(9_999, 0));
        KEPT_FD.store(9_999, Relaxed);
        assert!(is_kept_index_fd(9_999) && !is_kept_index_fd(9_998));
        unsafe { c.clear() };
        assert!(!is_kept_index_fd(9_999));
    }

    #[test]
    fn load_results_missing_vs_unreadable() {
        assert!(open_failure_result(ENOENT) == LoadResult::Missing);
        for e in [EIO, EINTR, EMFILE, EACCES] {
            assert!(open_failure_result(e) == LoadResult::Unreadable, "{e}");
        }
        let mut n = 0;
        for _ in 0..UNREADABLE_LOAD_LIMIT {
            assert!(n < UNREADABLE_LOAD_LIMIT);
            n = next_unreadable_loads(n, LoadResult::Unreadable);
        }
        assert_eq!(n, UNREADABLE_LOAD_LIMIT);
        assert_eq!(next_unreadable_loads(n, LoadResult::Missing), 0);
        assert_eq!(next_unreadable_loads(2, LoadResult::Loaded), 0);
        assert_eq!(
            next_unreadable_loads(u32::MAX, LoadResult::Unreadable),
            u32::MAX
        );
    }

    // ---- view load ----

    /// A sorted AMPRIDX3 image of `n` files and exactly `file_bytes` bytes:
    /// the paths take what records and hash slots leave.
    fn sized_image(n: usize, file_bytes: usize) -> Vec<u8> {
        sized_image_in(n, file_bytes, |i| i * 997 / n)
    }

    /// `sized_image` with file `i` in directory `dir(i)`.
    fn sized_image_in(n: usize, file_bytes: usize, dir: impl Fn(usize) -> usize) -> Vec<u8> {
        let fixed = image_layout(n, 0).unwrap();
        let slots = fixed.slot_count * size_of::<HashSlot>();
        let path_bytes = file_bytes - fixed.path_at - slots;
        let (base, extra) = (path_bytes / n, path_bytes % n);
        let (mut records, mut paths) = (Vec::with_capacity(n * 24), Vec::new());
        for i in 0..n {
            // 18 bytes: the 3000-file image leaves 18 or 19 per path, so
            // no path is cut to another's.
            let mut p = format!("/app0/d{:03}/f{i:06}", dir(i)).into_bytes();
            p.resize(base - 1 + usize::from(i < extra), b'a');
            records.extend_from_slice(&(paths.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&(i as u64).to_le_bytes());
            records.extend_from_slice(&0i64.to_le_bytes());
            paths.extend_from_slice(&p);
            paths.push(0);
        }
        let l = image_layout(n, paths.len() as u64).unwrap();
        assert_eq!(l.file_bytes, file_bytes);
        let mut image = vec![0u8; l.map_bytes];
        assert!(fill_image(&mut image, &l, &records, &paths));
        image.truncate(l.file_bytes);
        image
    }

    fn empty_state() -> FileIndexState {
        FileIndexState {
            loaded: false,
            load_attempted: false,
            loading: false,
            available: false,
            compact: Compact::EMPTY,
        }
    }

    /// An AMPRIDX3 image of `paths` in that order, file `i` of size `i`.
    fn image_of(paths: &[&[u8]]) -> Vec<u8> {
        let sized: Vec<(&[u8], u64)> = paths.iter().zip(0..).map(|(&p, i)| (p, i)).collect();
        image_sized(&sized)
    }

    /// An AMPRIDX3 image of `files` (path, size) in that order.
    fn image_sized(files: &[(&[u8], u64)]) -> Vec<u8> {
        let (mut records, mut blob) = (Vec::new(), Vec::new());
        for &(p, size) in files {
            records.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&size.to_le_bytes());
            records.extend_from_slice(&0i64.to_le_bytes());
            blob.extend_from_slice(p);
            blob.push(0);
        }
        let l = image_layout(files.len(), blob.len() as u64).unwrap();
        let mut image = vec![0u8; l.map_bytes];
        assert!(fill_image(&mut image, &l, &records, &blob));
        image.truncate(l.file_bytes);
        image
    }

    /// A zstd title's view of `files` (path, size) between the build and
    /// `finish`, for the pack join tests (rt/pack/zstd.rs), in Index ledger
    /// memory: the caller holds `POOL_TEST_LOCK` and gives it back with
    /// `drop_view`. The image is leaked, as the view reads paths from it.
    pub(crate) fn zstd_builder(files: &[(&[u8], u64)]) -> FileIndexState {
        let image: &'static [u8] = image_sized(files).leak();
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, image, Packs::Zstd) } == LoadResult::Loaded);
        idx
    }

    /// `zstd_builder` for an LZ4 or pkg title: the view carries the
    /// `pak_path_hash` column the LZ4 join compares (rt/pack/state.rs).
    pub(crate) fn lz4_builder(files: &[(&[u8], u64)]) -> FileIndexState {
        let image: &'static [u8] = image_sized(files).leak();
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, image, Packs::Lz4) } == LoadResult::Loaded);
        idx
    }

    pub(crate) fn drop_view(idx: &mut FileIndexState) {
        unload(idx);
    }

    /// `load_file` over `image` in memory, reading it as the loader reads
    /// the file; paths are then read from the image itself, which the test
    /// owns (`unload` drops that source before `clear`).
    unsafe fn load_image(
        idx: &mut FileIndexState,
        image: &'static [u8],
        packs: Packs,
    ) -> LoadResult {
        let read = |at: u64, out: &mut [u8]| {
            let bytes = image.get(at as usize..).and_then(|t| t.get(..out.len()));
            bytes.map(|b| out.copy_from_slice(b)).is_some()
        };
        let rc = unsafe { load_file(idx, image.len() as u64, read, packs) };
        if rc == LoadResult::Loaded {
            idx.compact.paths = Paths::Blob(BlobSource {
                blob: image,
                base: 0,
            });
        }
        rc
    }

    fn unload(idx: &mut FileIndexState) {
        idx.compact.paths = Paths::None;
        unsafe { idx.compact.clear() };
    }

    /// The view's own block, page-rounded as the ledger counts it.
    fn view_bytes(idx: &FileIndexState) -> usize {
        round_up_page(idx.compact.mem.as_ref().unwrap().bytes())
    }

    /// The view's transient block, page-rounded; 0 once given back.
    fn scratch_bytes(idx: &FileIndexState) -> usize {
        round_up_page(idx.compact.mem.as_ref().unwrap().scratch_bytes())
    }

    /// With packs the build's transient columns stay in the ledger until
    /// `finish` and then go back, so the finished view holds only its own
    /// block; a mount that failed and unlinked its rows finishes the same
    /// way, and an index cleared before `finish` gives both blocks back.
    #[test]
    fn finish_gives_the_transient_columns_back() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let files: &[(&[u8], u64)] = &[(b"/app0/a/x.bin", 10), (b"/app0/b/y.bin", 20)];
        let used = im::test_index_used();
        for packs in [Packs::Zstd, Packs::Lz4] {
            for failed_mount in [false, true] {
                let mut idx = empty_state();
                let image: &'static [u8] = image_sized(files).leak();
                assert!(unsafe { load_image(&mut idx, image, packs) } == LoadResult::Loaded);
                let (view, scratch) = (view_bytes(&idx), scratch_bytes(&idx));
                assert!(scratch > 0);
                assert_eq!(im::test_index_used(), used + view + scratch);
                if failed_mount {
                    idx.compact.builder.as_mut().unwrap().unlink_all();
                }
                idx.compact.finish();
                assert_eq!(scratch_bytes(&idx), 0);
                assert_eq!(im::test_index_used(), used + view);
                idx.compact.finish();
                assert_eq!(im::test_index_used(), used + view);
                unload(&mut idx);
                assert_eq!(im::test_index_used(), used);
            }
            let mut idx = empty_state();
            let image: &'static [u8] = image_sized(files).leak();
            assert!(unsafe { load_image(&mut idx, image, packs) } == LoadResult::Loaded);
            unload(&mut idx);
            assert_eq!(im::test_index_used(), used);
        }
    }

    /// An index whose records are not in folded order (as the external
    /// packer writes them) loads into the view in one pass: the read
    /// windows go back to the ledger, every path answers its id, size and
    /// stored path, every directory answers with a file below it, and
    /// `clear` gives every byte back. With packs the view waits for
    /// `finish`, which `ensure_ready_slow` calls after the pack load.
    #[test]
    fn a_file_index_loads_into_the_view_and_frees_to_zero() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000;
        let image: &'static [u8] = sized_image_in(n, 256 << 10, |i| i * 7919 % 997).leak();
        let plain = Index::open(image).unwrap();
        assert!(!plain.records_sorted());
        let used = im::test_index_used();
        im::test_take_index_notice();
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, image, Packs::None) } == LoadResult::Loaded);
        assert!(idx.available && idx.compact.available && idx.compact.count == n);
        assert!(idx.compact.builder.is_none() && idx.compact.view.is_some());
        assert_eq!(im::test_index_used(), used + view_bytes(&idx));
        assert!(!im::test_take_index_notice());
        let c = &idx.compact;
        let mut buf: EntryPath = [0; PATH_BUF];
        for id in 1..=n as u32 {
            let path = plain
                .path(&plain.record(id).unwrap(), &mut buf)
                .unwrap()
                .to_vec();
            assert_eq!(view_lookup(c, &path), Ok(Some(Hit::File(id))));
            let mut v = empty_view();
            let mut out: EntryPath = [0xA5; PATH_BUF];
            assert_eq!(c.try_entry_view(id, &mut v, Some(&mut out)), Ok(()));
            assert_eq!(v.path, out.as_ptr().cast());
            assert_eq!(&out[..v.path_length as usize], &path[..]);
            assert_eq!(out[v.path_length as usize], 0);
            assert_eq!(v.size, id as usize - 1);
            let dir = &path[..10];
            let Ok(Some(Hit::Dir(d))) = view_lookup(c, dir) else {
                panic!("no directory {dir:?}");
            };
            let rep = c.view().unwrap().dir(d).rep_file;
            assert_eq!(c.try_entry_view(rep, &mut v, Some(&mut out)), Ok(()));
            assert!(out[..10].eq_ignore_ascii_case(dir));
        }
        assert_eq!(view_lookup(c, b"/app0/d997"), Ok(Some(Hit::Miss)));
        assert!(matches!(view_lookup(c, b"/app0"), Ok(Some(Hit::Dir(_)))));
        let mut v = empty_view();
        assert!(c.try_entry_view(7, &mut v, None).is_ok() && v.path.is_null());
        assert_eq!(v.size, 6);
        for id in [0, n as u32 + 1] {
            assert!(c.try_entry_view(id, &mut v, None).is_err());
        }
        unload(&mut idx);
        assert!(idx.compact.view.is_none() && idx.compact.mem.is_none());
        assert_eq!(im::test_index_used(), used);

        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, image, Packs::Zstd) } == LoadResult::Loaded);
        assert!(idx.compact.view.is_none() && idx.compact.builder.is_some());
        idx.compact.finish();
        assert!(idx.compact.builder.is_none());
        assert_eq!(
            view_lookup(&idx.compact, &image_path(&plain, 9)),
            Ok(Some(Hit::File(9)))
        );
        unload(&mut idx);
        assert_eq!(im::test_index_used(), used);
    }

    fn image_path(index: &Index<'_>, id: u32) -> Vec<u8> {
        let mut buf = [0u8; PATH_BUF];
        index
            .path(&index.record(id).unwrap(), &mut buf)
            .unwrap()
            .to_vec()
    }

    /// Two files whose paths fold to one key are refused at load, as
    /// `Index::check` refused them, and the refused load takes nothing.
    #[test]
    fn a_duplicate_folded_path_is_refused() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = im::test_index_used();
        let ok: &'static [u8] = image_of(&[b"/app0/Data/a.bin", b"/app0/data/b.bin"]).leak();
        let dup: &'static [u8] = image_of(&[b"/app0/Data/a.bin", b"/app0/data/A.BIN"]).leak();
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, ok, Packs::None) } == LoadResult::Loaded);
        unload(&mut idx);
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, dup, Packs::None) } == LoadResult::Invalid);
        assert!(!idx.available && idx.compact.view.is_none() && idx.compact.mem.is_none());
        assert_eq!(im::test_index_used(), used);
    }

    /// A file that is not an AMPRIDX3, or that cannot be read, is refused
    /// before memory is taken; a view the ledger cannot hold is Memory,
    /// with the index notice, after the read windows went back.
    #[test]
    fn a_bad_unreadable_or_oversized_file_takes_nothing() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000;
        let image: &'static [u8] = sized_image(n, 256 << 10).leak();
        let used = im::test_index_used();
        im::test_take_index_notice();
        let mut idx = empty_state();
        let mut bad = image.to_vec();
        bad[0] ^= 1;
        let bad: &'static [u8] = bad.leak();
        assert!(unsafe { load_image(&mut idx, bad, Packs::None) } == LoadResult::Invalid);
        let fail = |_: u64, _: &mut [u8]| false;
        let rc = unsafe { load_file(&mut idx, image.len() as u64, fail, Packs::None) };
        assert!(rc == LoadResult::Unreadable);
        assert_eq!(im::test_index_used(), used);
        assert!(!im::test_take_index_notice());

        // Room for the two windows and a page, not for the view.
        let page = SCE_KERNEL_PAGE_SIZE;
        let fill = im::index_room() - round_up_page(2 * WINDOW) - page;
        let other = unsafe { im::index_alloc(fill, page, c"test.other.tables".as_ptr()) };
        assert!(!other.is_null());
        let rc = unsafe { load_image(&mut idx, image, Packs::None) };
        assert!(rc == LoadResult::Memory);
        assert!(im::test_take_index_notice());
        assert!(!idx.available && idx.compact.mem.is_none());
        assert_eq!(im::test_index_used(), used + fill);
        unsafe { im::index_free(other.cast(), c"test.other.tables.free".as_ptr()) };
        assert_eq!(im::test_index_used(), used);
    }

    /// A built image that cannot be installed is served from its path
    /// blob: `adopt_compact_index` builds the view from the image, copies
    /// the blob into the Index ledger and frees the image, so the view and
    /// the blob are all that stay; lookups and entry views read paths from
    /// the blob, and `clear` gives both back. A corrupt image is refused
    /// and freed the same way.
    #[test]
    fn an_uninstalled_image_is_served_from_its_path_blob_and_given_back() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 20_000;
        let image = sized_image(n, 4 << 20);
        let plain = Index::open(&image[..]).unwrap();
        let blob_len = plain.layout().path_bytes as usize;
        let used = im::test_index_used();
        let adopt = |image: &[u8]| {
            let mem = unsafe { build_alloc(image.len(), c"test.index.image") };
            assert!(!mem.is_null());
            unsafe { core::ptr::copy_nonoverlapping(image.as_ptr(), mem, image.len()) };
            let mut idx = empty_state();
            let rc = unsafe { adopt_compact_index(&mut idx, mem, image.len()) };
            (idx, rc)
        };
        let (mut idx, rc) = adopt(&image);
        assert!(rc == LoadResult::Loaded);
        assert!(idx.available && idx.compact.count == n && idx.compact.view.is_some());
        let Paths::Blob(b) = &idx.compact.paths else {
            panic!("not served from the blob");
        };
        assert_eq!(b.blob.len(), blob_len);
        assert_eq!(b.base, plain.layout().paths_at);
        let kept = view_bytes(&idx) + round_up_page(blob_len);
        assert_eq!(im::test_index_used(), used + kept);
        for id in [1, 7, n as u32 / 2, n as u32] {
            let path = image_path(&plain, id);
            assert_eq!(view_lookup(&idx.compact, &path), Ok(Some(Hit::File(id))));
            let mut v = empty_view();
            let mut out: EntryPath = [0xA5; PATH_BUF];
            assert_eq!(
                idx.compact.try_entry_view(id, &mut v, Some(&mut out)),
                Ok(())
            );
            assert_eq!(&out[..v.path_length as usize], &path[..]);
            assert_eq!(out[v.path_length as usize], 0);
        }
        unsafe { idx.compact.clear() };
        assert!(matches!(idx.compact.paths, Paths::None));
        assert_eq!(im::test_index_used(), used);

        // A path with no NUL after it fails the build's path check.
        let mut bad = image.clone();
        let at = plain.layout().paths_at as usize;
        let len = plain.record(1).unwrap().path_len as usize;
        bad[at + len] = b'x';
        let (idx, rc) = adopt(&bad);
        assert!(rc == LoadResult::Invalid);
        assert!(!idx.available && idx.compact.view.is_none() && idx.compact.mem.is_none());
        assert!(matches!(idx.compact.paths, Paths::None));
        assert_eq!(im::test_index_used(), used);
    }

    // ---- lookups against the old index ----

    /// What the old lookups answered for `key`: `Index::find` for a file
    /// when `file_ok`, then `Index::find_directory` (record order, the
    /// unsorted scan) for a directory, as `lookup_resident_path` probed
    /// them. A directory answers its first file's mtime and stored path.
    #[derive(Debug, PartialEq)]
    enum Old {
        File(u32, usize, i64, Vec<u8>),
        Dir(i64, Vec<u8>),
        Miss,
    }

    fn old_lookup(index: &Index<'_>, key: &[u8], file_ok: bool, dir_ok: bool) -> Old {
        let mut buf = [0u8; PATH_BUF];
        if let Some(id) = file_ok
            .then(|| io_or_none(index.find(key)).unwrap())
            .flatten()
        {
            let rec = index.record(id).unwrap();
            let path = index.path(&rec, &mut buf).unwrap().to_vec();
            return Old::File(id, rec.size as usize, rec.mtime, path);
        }
        let dir = dir_ok.then(|| io_or_none(index.find_directory(key, false)).unwrap());
        match dir.flatten() {
            Some(id) => {
                let rec = index.record(id).unwrap();
                let path = index.path(&rec, &mut buf).unwrap();
                Old::Dir(rec.mtime, path[..key.len()].to_vec())
            }
            None => Old::Miss,
        }
    }

    /// `resolve_key` in the shape of `Old`, checking the entry's path
    /// fields on the way.
    fn new_lookup(c: &Compact, key: &[u8], file_ok: bool, dir_ok: bool) -> Old {
        let mut buf: EntryPath = [0xA5; PATH_BUF];
        match resolve_key(c, key, file_ok, dir_ok, Some(&mut buf)).unwrap() {
            KeyHit::File(e, id) => {
                let n = e.path_length as usize;
                assert_eq!(e.path, buf.as_ptr().cast());
                assert_eq!(buf[n], 0);
                let KeyHit::File(bare, bare_id) = resolve_key(c, key, true, false, None).unwrap()
                else {
                    panic!("{key:?} answers no file without a path buffer");
                };
                assert!(bare_id == id && bare.path.is_null() && bare.size == e.size);
                Old::File(id, e.size, e.mtime, buf[..n].to_vec())
            }
            KeyHit::Dir(e, _) => {
                assert_eq!(e.path, buf.as_ptr().cast());
                assert_eq!((e.path_length as usize, e.size), (key.len(), 0));
                Old::Dir(e.mtime, buf[..key.len()].to_vec())
            }
            KeyHit::Miss => Old::Miss,
        }
    }

    /// An AMPRIDX3 image of `paths` in that order: file `i` has size
    /// `7 * i + 3` and mtime `1000 - i`, so every column is told apart.
    fn timed_image(paths: &[Vec<u8>]) -> Vec<u8> {
        let (mut records, mut blob) = (Vec::new(), Vec::new());
        for (i, p) in paths.iter().enumerate() {
            records.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&(7 * i as u64 + 3).to_le_bytes());
            records.extend_from_slice(&(1000 - i as i64).to_le_bytes());
            blob.extend_from_slice(p);
            blob.push(0);
        }
        let l = image_layout(paths.len(), blob.len() as u64).unwrap();
        let mut image = vec![0u8; l.map_bytes];
        assert!(fill_image(&mut image, &l, &records, &blob));
        image.truncate(l.file_bytes);
        image
    }

    /// Every path, case variant, byte prefix and miss of a test image
    /// answers what `Index::find` and `Index::find_directory` answered:
    /// the same kind, id, size, mtime and stored spelling, for the file
    /// and directory probes alone and for `lookup_resident_path`'s pair.
    #[test]
    fn view_lookups_answer_what_the_old_index_answered() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut paths: Vec<Vec<u8>> = [
            "/app0/sce_sys/param.json",
            "/app0/Data/Maps/m1.pak",
            "/app0/eboot.bin",
            "/app0/data/maps/M2.pak",
            "/app0/DATA/Sound/s.bnk",
            "/app0/a/b/c/d/e/f.txt",
            "/app0/a/bc",
            "/app0/ab/c",
            "/app0/Movies/intro.mp4",
            "/app0/a.b/c.d",
        ]
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
        for i in 0..300 {
            paths.push(format!("/app0/gen/D{:02}/f{:04}.dat", (i * 7) % 23, 300 - i).into_bytes());
        }
        let image: &'static [u8] = timed_image(&paths).leak();
        let index = Index::open(image).unwrap();
        let mut idx = empty_state();
        assert!(unsafe { load_image(&mut idx, image, Packs::None) } == LoadResult::Loaded);
        let c = &idx.compact;

        let mut keys: Vec<Vec<u8>> = Vec::new();
        for p in &paths {
            keys.push(p.clone());
            keys.push([p.as_slice(), b"/x"].concat());
            keys.push([p.as_slice(), b"x"].concat());
            keys.extend(
                (5..p.len())
                    .filter(|&n| p[n - 1] != b'/')
                    .map(|n| p[..n].to_vec()),
            );
        }
        for miss in [
            "/app0/nothing",
            "/app0/data/maps/m3.pak",
            "/app0/gen/D99",
            "/app0/A/B/C/D/E",
        ] {
            keys.push(miss.as_bytes().to_vec());
        }
        // Lookup keys are normalized, so folded: every spelling above folds
        // to one key.
        let mut keys: Vec<Vec<u8>> = keys.iter().map(|k| k.to_ascii_lowercase()).collect();
        keys.sort();
        keys.dedup();
        let (mut files, mut dirs, mut misses) = (0, 0, 0);
        for key in &keys {
            for (file_ok, dir_ok) in [(true, true), (false, true), (true, false)] {
                let old = old_lookup(&index, key, file_ok, dir_ok);
                assert_eq!(
                    new_lookup(c, key, file_ok, dir_ok),
                    old,
                    "{:?}",
                    String::from_utf8_lossy(key)
                );
                match old {
                    Old::File(..) => files += 1,
                    Old::Dir(..) => dirs += 1,
                    Old::Miss => misses += 1,
                }
            }
        }
        // Each kind was exercised, not only misses.
        assert!(
            files > 600 && dirs > 60 && misses > 5000,
            "{files} {dirs} {misses}"
        );
        unload(&mut idx);
    }

    /// A lazy lookup (open, stat, access) finds a packed file without its
    /// path (no pread): the hit's path is null and `hit_path` reads it only
    /// for a real-file fallback. A lookup that is not lazy reads the path of
    /// a packed hit and confirms a loose one; a lazy loose hit reads none.
    #[test]
    fn an_open_reads_a_packed_path_only_for_a_real_fallback() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = im::test_index_used();
        let files: &[(&[u8], u64)] = &[(b"/app0/eboot.bin", 7), (b"/app0/Data/P.bin", 9)];
        let mut idx = zstd_builder(files);
        let b = idx.compact.builder.as_mut().unwrap();
        b.set_chunk(2, 0);
        assert!(b.link_packed(2));
        idx.compact.finish();
        let c = &idx.compact;
        let mut buf: EntryPath = [0xA5; PATH_BUF];
        let r = resolve_key_paths(c, b"/app0/data/p.bin", true, true, Some(&mut buf), true);
        let Ok(KeyHit::File(e, 2)) = r else {
            panic!("packed hit");
        };
        assert!(e.path.is_null() && e.size == 9);
        let mut l = Lookup {
            state: Resident::Hit,
            entry: e,
            file_id: 2,
            expected_miss: false,
            authoritative: false,
            io: false,
            unconfirmed: false,
            ..Lookup::empty()
        };
        let mut pbuf: EntryPath = [0; PATH_BUF];
        let p = hit_path_in(Some(c), &mut l, &mut pbuf);
        assert!(!p.is_null() && p == l.entry.path);
        assert_eq!(&pbuf[..l.entry.path_length as usize], b"/app0/Data/P.bin");
        assert_eq!(pbuf[l.entry.path_length as usize], 0);
        // Read once: a second call keeps the path it has.
        assert_eq!(hit_path_in(None, &mut l, &mut [0; PATH_BUF]), p);
        // No index to read from: null, not a path.
        l.entry.path = null();
        assert!(hit_path_in(None, &mut l, &mut pbuf).is_null());

        let r = resolve_key_paths(c, b"/app0/data/p.bin", true, true, Some(&mut buf), false);
        let Ok(KeyHit::File(e, 2)) = r else {
            panic!("packed hit with its path");
        };
        assert!(!e.path.is_null());
        let r = resolve_key_paths(c, b"/app0/eboot.bin", true, true, Some(&mut buf), false);
        let Ok(KeyHit::File(e, 1)) = r else {
            panic!("loose hit");
        };
        assert_eq!(&buf[..e.path_length as usize], b"/app0/eboot.bin");
        let r = resolve_key_paths(c, b"/app0/eboot.bin", true, true, Some(&mut buf), true);
        let Ok(KeyHit::File(e, 1)) = r else {
            panic!("lazy loose hit");
        };
        assert!(e.path.is_null() && e.size == 7);
        drop_view(&mut idx);
        assert_eq!(im::test_index_used(), used);
    }

    /// A path source that counts reads and fails them with `Io` on demand.
    struct Counting<'a, S: Source> {
        src: &'a S,
        reads: core::cell::Cell<u32>,
        fail: core::cell::Cell<bool>,
    }

    impl<S: Source> Source for Counting<'_, S> {
        fn len(&self) -> u64 {
            self.src.len()
        }
        fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
            self.reads.set(self.reads.get() + 1);
            if self.fail.get() {
                return Err(ampr_format::Error::Io);
            }
            self.src.read_at(at, out)
        }
    }

    fn loose_hit(id: u32) -> Lookup {
        Lookup {
            state: Resident::Hit,
            entry: empty_view(),
            file_id: id,
            expected_miss: false,
            authoritative: false,
            io: false,
            unconfirmed: true,
            ..Lookup::empty()
        }
    }

    /// The game's spelling keeps its case and normalizes as the key does
    /// (`loose_call` passes a path already in that form as is), so it folds
    /// to the key `normalize` makes and the skip list matches it in any case.
    #[test]
    fn the_game_spelling_keeps_case() {
        let mut out = [0u8; RUNTIME_PATH_CAPACITY];
        for raw in [
            &b"/app0/Data/Real.bin"[..],
            b"/app0//Data/./x/../Real.bin",
            b"\\app0\\Data\\Real.bin",
        ] {
            let n = spell(raw, &mut out).unwrap();
            assert_eq!(&out[..n + 1], b"/app0/Data/Real.bin\0");
            let mut key = [0u8; RUNTIME_PATH_CAPACITY];
            let k = ampr_format::index_key::normalize(raw, &mut key).unwrap();
            assert_eq!(&key[..k.len], out[..n].to_ascii_lowercase().as_slice());
        }
        assert_eq!(spell(b"/..", &mut out), None);
        assert!(is_skipped_key(b"/APP0/Ampr_Emu.Index") && is_skipped_key(b"/app0/ampr_emu.log"));
        assert!(!is_skipped_key(b"/app0/ampr_emu.indexx"));
        // Each skipped name is its own normalized key.
        for p in SKIPPED_KEYS {
            let mut key = [0u8; RUNTIME_PATH_CAPACITY];
            let n = unsafe { normalize_key(p.as_ptr(), &mut key) }.unwrap();
            assert_eq!(&key[..n], p.to_bytes());
        }
    }

    /// A loose hit asks for the game's spelling first and reads its stored
    /// path only when that is not found. The real call is a stand-in for a
    /// case-sensitive tree that holds only the stored spelling.
    #[test]
    fn a_loose_hit_reads_its_path_only_when_its_spelling_is_not_found() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let files: &[(&[u8], u64)] = &[(b"/app0/eboot.bin", 7), (b"/app0/Data/Real.bin", 5)];
        let mut idx = zstd_builder(files);
        idx.compact.finish();
        let c = &idx.compact;
        let view = c.view();
        let src = Counting {
            src: &c.paths,
            reads: Default::default(),
            fail: Default::default(),
        };
        let calls = core::cell::Cell::new(0u32);
        let disk = |p: *const c_char| {
            calls.set(calls.get() + 1);
            if unsafe { cstr_bytes(p) } == b"/app0/Data/Real.bin" {
                3
            } else {
                set_errno(ENOENT);
                -1
            }
        };
        let key = b"/app0/data/real.bin";
        let mut pbuf: EntryPath = [0; PATH_BUF];
        let run = |l: &mut Lookup, spelling: &CStr, pbuf: &mut EntryPath| {
            (calls.set(0), src.reads.set(0));
            let s = Some(spelling.as_ptr());
            loose_call_in(view.as_ref(), &src, l, key, s, pbuf, disk)
        };

        // The game's spelling is on disk: no path read.
        let mut l = loose_hit(2);
        assert_eq!(
            run(&mut l, c"/app0/Data/Real.bin", &mut pbuf),
            Loose::Done(3)
        );
        assert_eq!((src.reads.get(), calls.get()), (0, 1));
        assert!(l.unconfirmed && l.entry.path.is_null());

        // Another case: one read, then the stored spelling opens.
        let mut l = loose_hit(2);
        assert_eq!(
            run(&mut l, c"/app0/DATA/real.BIN", &mut pbuf),
            Loose::Done(3)
        );
        assert_eq!((src.reads.get(), calls.get()), (1, 2));
        assert!(!l.unconfirmed);
        assert_eq!(unsafe { cstr_bytes(l.entry.path) }, b"/app0/Data/Real.bin");

        // A hash that matched another file's id: a miss, no second call.
        let mut l = loose_hit(1);
        assert_eq!(run(&mut l, c"/app0/data/real.bin", &mut pbuf), Loose::Miss);
        assert_eq!(calls.get(), 1);
        miss_lookup(&mut l, true, key, false);
        assert!(l.state == Resident::Miss && l.expected_miss && !l.unconfirmed);
        assert_eq!(l.authoritative, !rw::app0_writable());

        // The stored path equals the spelling: the first answer stands.
        let mut l = loose_hit(1);
        calls.set(0);
        let eboot = loose_call_in(
            view.as_ref(),
            &src,
            &mut l,
            b"/app0/eboot.bin",
            Some(c"/app0/eboot.bin".as_ptr()),
            &mut pbuf,
            disk,
        );
        assert_eq!(eboot, Loose::Done(-1));
        assert_eq!((errno(), calls.get()), (ENOENT, 1));

        // A read error on the retry is not ENOENT; with no spelling (an
        // O_CREAT open) the stored path goes first and fails the same way.
        src.fail.set(true);
        let mut l = loose_hit(2);
        assert_eq!(run(&mut l, c"/app0/data/real.bin", &mut pbuf), Loose::Io);
        assert!(l.unconfirmed);
        calls.set(0);
        let r = loose_call_in(view.as_ref(), &src, &mut l, key, None, &mut pbuf, disk);
        assert_eq!((r, calls.get()), (Loose::Io, 0));
        src.fail.set(false);
        let r = loose_call_in(view.as_ref(), &src, &mut l, key, None, &mut pbuf, disk);
        assert_eq!((r, calls.get()), (Loose::Done(3), 1));
        drop_view(&mut idx);
    }

    /// A lazy lookup's miss is final. Over view fixtures with packed
    /// and loose files in mixed-case directories, every probe the view
    /// misses is missed by the pack overlay's own lookups too: the id
    /// resolve (`ampr_index_resolve_path_to_id`: same key, files only, no
    /// path read) and the directory listing (`packed_dir_in`: the overlay
    /// normalize, then `View::lookup_dir`, which finds every directory a
    /// packed one could be). So the hooks skip both (`Lookup::pack_miss`).
    #[test]
    fn a_view_miss_leaves_nothing_for_the_pack_lookups() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let files: &[(&[u8], u64)] = &[
            (b"/app0/eboot.bin", 7),
            (b"/app0/Data/P.bin", 9),
            (b"/app0/Data/Sub/Q.pak", 3),
            (b"/app0/data2/r.bin", 4),
            (b"/app0/Movies/Intro.MP4", 5),
            (b"/app0/a/b/c/d/e.txt", 6),
        ];
        let mut idx = zstd_builder(files);
        let b = idx.compact.builder.as_mut().unwrap();
        for (id, first) in [(2u32, 0u32), (3, 1), (5, 2)] {
            b.set_chunk(id, first);
            assert!(b.link_packed(id));
        }
        idx.compact.finish();
        let c = &idx.compact;
        let view = c.view().unwrap();
        let mut probes: Vec<Vec<u8>> = Vec::new();
        for &(p, _) in files {
            let leaf = p.iter().rposition(|&b| b == b'/').unwrap();
            let (dir, name) = (&p[..leaf], &p[leaf + 1..]);
            for v in [
                p.to_vec(),
                p.to_ascii_uppercase(),
                [p, b"x"].concat(),
                p[..p.len() - 1].to_vec(),
                [p, b"/"].concat(),
                [dir, b"/./", name].concat(),
                [dir, b"/zz/../", name].concat(),
                [dir, b"//", name].concat(),
                [dir, b"/zz"].concat(),
                [dir, b"/zz/"].concat(),
                [dir, b"x"].concat(),
                [dir, b"/"].concat(),
                dir.to_vec(),
                dir.to_ascii_uppercase(),
                [dir, b"/..", b"/", name].concat(),
                p.iter()
                    .map(|&b| if b == b'/' { b'\\' } else { b })
                    .collect(),
            ] {
                probes.push(v);
            }
        }
        for extra in [
            &b"/app0"[..],
            b"/app0/",
            b"/APP0",
            b"/app0/.",
            b"/app0/a/b/c/d",
            b"/app0/a/b/x",
        ] {
            probes.push(extra.to_vec());
        }
        let (mut hits, mut misses) = (0, 0);
        for raw in &probes {
            let mut buf = [0u8; RUNTIME_PATH_CAPACITY];
            let Ok(k) = ampr_format::index_key::normalize(raw, &mut buf) else {
                continue;
            };
            let key = &buf[..k.len];
            if !is_app0_key(key) {
                continue;
            }
            let file_ok = !k.had_trailing_separator && k.len > 5;
            let mut pbuf: EntryPath = [0; PATH_BUF];
            match resolve_key_paths(c, key, file_ok, true, Some(&mut pbuf), true) {
                Ok(KeyHit::Miss) => misses += 1,
                Ok(_) => {
                    hits += 1;
                    continue;
                }
                Err(IndexIo) => panic!("no read fails here"),
            }
            let name = String::from_utf8_lossy(raw);
            if file_ok {
                assert!(
                    matches!(resolve_key(c, key, true, false, None), Ok(KeyHit::Miss)),
                    "{name}: the id resolve found a file"
                );
            }
            let mut norm = [0u8; KERNEL_PATH_MAX];
            if let Some(n) = ampr_format::overlay::normalize_path(raw.iter().copied(), &mut norm) {
                let found = view.lookup_dir(&c.paths, &norm[..n as usize]).unwrap();
                assert!(found.is_none(), "{name}: the listing found a directory");
            }
        }
        assert!(hits > 40 && misses > 30, "{hits} hits, {misses} misses");
        drop_view(&mut idx);
    }

    /// Stat, access and reachability look a hit up lazily: a packed file
    /// is found with no path read. With no path source at all (every read
    /// fails) the lazy lookup still hits and a stat answers from the index.
    #[test]
    fn a_stat_of_a_packed_file_reads_no_path() {
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let files: &[(&[u8], u64)] = &[(b"/app0/eboot.bin", 7), (b"/app0/Data/P.bin", 9)];
        let mut idx = zstd_builder(files);
        let b = idx.compact.builder.as_mut().unwrap();
        b.set_chunk(2, 0);
        assert!(b.link_packed(2));
        idx.compact.finish();
        let paths = core::mem::replace(&mut idx.compact.paths, Paths::None);
        let c = &idx.compact;
        let mut buf: EntryPath = [0; PATH_BUF];
        let r = resolve_key_paths(c, b"/app0/data/p.bin", true, true, Some(&mut buf), true);
        let Ok(KeyHit::File(e, 2)) = r else {
            panic!("packed hit with no read");
        };
        let l = Lookup {
            entry: e,
            unconfirmed: false,
            ..loose_hit(2)
        };
        let st = file_stat(&l);
        assert_eq!((st.st_size, st.st_ino), (9, 2));
        // The same lookup, not lazy, must read and so fails here.
        let r = resolve_key_paths(c, b"/app0/data/p.bin", true, true, Some(&mut buf), false);
        assert!(matches!(r, Ok(KeyHit::Miss)));
        idx.compact.paths = paths;
        drop_view(&mut idx);
    }
}
