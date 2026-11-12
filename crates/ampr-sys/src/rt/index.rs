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
use super::index_memory::{self as im, lookup_alloc, lookup_free};
use super::index_pages::{self, IndexSource};
use super::runtime_memory::{
    ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_ensure, ampr_internal_amm_pool_free,
    ampr_internal_amm_pool_ready_has_capacity, ampr_sdk_cpu_memory_class_name,
    ampr_small_slab_alloc, ampr_small_slab_free,
};
use super::stats;
use super::sync::{Condvar, Mutex, SyncCell};
use super::sys::*;
use ampr_format::index::{FastEntry, Index, Layout};
use ampr_format::source::PATH_BUF;
use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering::*};

// ---- constants -------------------------------------------------------------

pub(crate) const APP0_ROOT: &CStr = c"/app0";
pub(crate) const INDEX_PATH: &CStr = c"/app0/ampr_emu.index";
pub(crate) const INDEX_TEMP_PATH: &CStr = c"/app0/ampr_emu.index.tmp";
pub(crate) const INDEX_BACKUP_PATH: &CStr = c"/app0/ampr_emu.index.bak";
pub(crate) const INDEX_MAGIC: [u8; 8] = *b"AMPRIDX3";
pub(crate) const INDEX_VERSION: u32 = 3;
pub(crate) const INDEX_LOAD_WAIT_US: u64 = 500_000;
pub(crate) const INDEX_MAX_PATH: usize = 4096;
pub(crate) const KERNEL_PATH_MAX: usize = 1024; // SCE_KERNEL_PATH_MAX
pub(crate) const RUNTIME_PATH_CAPACITY: usize = KERNEL_PATH_MAX + 1;
pub(crate) const FILEID_INVALID: u32 = u32::MAX; // SCE_AMPR_APR_FILEID_INVALID
/// alignof(std::max_align_t), the C++ default allocation alignment.
const MAX_ALIGN: usize = 16;

/// `AmprSharedSdkCpuMemoryClass`.
pub(crate) const MEM_PERSISTENT: u8 = 0;
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
    /// may build (`allow_build` and autobuild on); other calls return
    /// unavailable. Without packs, after `UNREADABLE_LOAD_LIMIT` in a row it is
    /// built in memory, never installed; with packs it is only retried.
    Unreadable,
}

/// Consecutive Unreadable loads before a build replaces the index in memory.
/// Three retries ride out a USB hiccup without retrying I/O forever.
const UNREADABLE_LOAD_LIMIT: u32 = 3;
/// Unreadable loads in a row; only the single `loading` thread touches it.
static UNREADABLE_LOADS: AtomicU32 = AtomicU32::new(0);

/// The Unreadable run length after a load with `result`.
fn next_unreadable_loads(count: u32, result: LoadResult) -> u32 {
    if result == LoadResult::Unreadable {
        count.saturating_add(1)
    } else {
        0
    }
}

// ---- global state ----------------------------------------------------------

/// The file index (C++ FileIndexState compact* fields): the AMPRIDX3 image
/// read at the offsets of its checked header, whole in index memory when it
/// fits with its tables (as in v0.3.5), else through the index page cache
/// (rt/index_pages.rs) with a resident fast table, so a large index keeps
/// only part of itself in memory. A paged file stays open at `fd`; an image
/// that could not be installed is served from its build buffer at `mem`.
pub(crate) struct Compact {
    pub src: Option<IndexSource>,
    pub layout: Layout,
    pub count: usize,
    /// The paged index file, -1 for none or an image in memory.
    pub fd: c_int,
    /// The image in memory (a file read whole, or the build buffer; Index
    /// ledger), null for a paged file.
    pub mem: *mut u8,
    /// The fast table of a paged file (`count` entries, `lookup_alloc`),
    /// null for an image in memory.
    pub fast: *mut FastEntry,
    pub sorted: bool,
    pub available: bool,
    /// The build walk saw a symlink and did not index it, so misses are not
    /// authoritative (see `miss_is_authoritative`). Only a runtime build sets
    /// it; a loaded index file carries no such flag.
    pub links: bool,
}

const LAYOUT0: Layout = Layout {
    count: 0,
    records_len: 0,
    paths_at: 0,
    path_bytes: 0,
    slots_at: 0,
    slot_count: 0,
    slots_len: 0,
    file_len: 0,
};

impl Compact {
    pub const EMPTY: Self = Self {
        src: None,
        layout: LAYOUT0,
        count: 0,
        fd: -1,
        mem: null_mut(),
        fast: null_mut(),
        sorted: false,
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
/// The resident image is not freed: `published()` hands out a reference
/// without a lock or count, so a thread still inside a lookup may read it,
/// and the pool is the PRX's .bss, gone with the module.
pub(crate) unsafe fn release_resident_index() {
    let _g = INDEX_LOCK.lock();
    PUBLISH.store(PUB_UNAVAILABLE, Release);
    unsafe { state() }.available = false;
}

/// `App0IndexBuildWorkspace`: key/path scratch for the single runtime builder.
pub(crate) struct BuildWorkspace {
    pub index_key: [u8; INDEX_MAX_PATH],
    pub temp_index_key: [u8; INDEX_MAX_PATH],
    pub backup_index_key: [u8; INDEX_MAX_PATH],
    pub command_log_key: [u8; INDEX_MAX_PATH],
    pub debug_log_key: [u8; INDEX_MAX_PATH],
    pub dir: [u8; INDEX_MAX_PATH],
    pub path: [u8; INDEX_MAX_PATH],
    pub path_key: [u8; INDEX_MAX_PATH],
}

/// `FileIndexState::loading` serializes the only user.
pub(crate) static WORKSPACE: SyncCell<BuildWorkspace> = SyncCell::new(BuildWorkspace {
    index_key: [0; INDEX_MAX_PATH],
    temp_index_key: [0; INDEX_MAX_PATH],
    backup_index_key: [0; INDEX_MAX_PATH],
    command_log_key: [0; INDEX_MAX_PATH],
    debug_log_key: [0; INDEX_MAX_PATH],
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
        Ok(k) => Ok((k.len, k.had_trailing_separator)),
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

/// `compare_index_path_key`: folded comparison, -1/0/1; null reads as "".
pub(crate) unsafe fn compare_key(path: *const c_char, key: *const c_char) -> i32 {
    ampr_format::index_key::compare(unsafe { cstr_bytes(path) }, unsafe { cstr_bytes(key) }) as i32
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

/// `ampr_alloc_sdk_cpu_memory`: small slab first, then the internal AMM pool
/// (only persistent allocations may create the pool).
pub(crate) unsafe fn sdk_alloc(size: usize, class: u8) -> *mut c_void {
    if size == 0 {
        return null_mut();
    }
    let name = unsafe { ampr_sdk_cpu_memory_class_name(class) };
    let may_create = class == MEM_PERSISTENT;
    let mut slot = 0usize;
    let small = unsafe { ampr_small_slab_alloc(size, MAX_ALIGN, &mut slot, name, may_create) };
    if !small.is_null() {
        return small;
    }
    let mapped = round_up_page(size);
    if mapped == usize::MAX {
        return null_mut();
    }
    let usable = if may_create {
        unsafe { ampr_internal_amm_pool_ensure(mapped, name) }
    } else {
        unsafe { ampr_internal_amm_pool_ready_has_capacity(mapped, MAX_ALIGN) }
    };
    if !usable {
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

/// A transient buffer sized by the title (save icon, decode-on-access
/// slots) from the pool's Index ledger, not a fixed pool site
/// (rt/index_memory.rs); null when refused, counted without the index
/// notice.
pub(crate) unsafe fn title_alloc(bytes: usize, tag: &CStr) -> *mut u8 {
    unsafe { super::index_memory::index_scratch_alloc(bytes, MAX_ALIGN, tag.as_ptr()) }
}

/// A file index build buffer (file count, path bytes, directories) from the
/// pool's Index ledger; null when refused, after the one-time index notice:
/// the build fails and the title runs without the index.
unsafe fn build_alloc(bytes: usize, tag: &CStr) -> *mut u8 {
    unsafe { super::index_memory::index_alloc(bytes, MAX_ALIGN, tag.as_ptr()) }
}

/// Frees a `title_alloc` or `build_alloc` result (null is a no-op).
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
        *self = Self::new();
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

/// `AmprIndexPathStack`: LIFO of NUL-terminated paths in fixed 4 KiB slots,
/// grown by doubling (from 256, 1 MiB) in index memory (rt/index_memory.rs):
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
    /// `clear_compact_file_index_locked`: gives back the page cache source,
    /// the file and the in-memory image. Never on a published index.
    pub unsafe fn clear(&mut self) {
        if let Some(IndexSource::Paged(src)) = self.src {
            index_pages::unregister(src);
        }
        unsafe { self.free_fast() };
        // Host tests link no libkernel and register no file.
        #[cfg(not(test))]
        if self.fd >= 0 {
            unsafe { real_physical_close(self.fd) };
        }
        unsafe { title_free(self.mem, c"apr.index.build.image") };
        *self = Self::EMPTY;
    }
    /// `move_compact_file_index_locked(dst=self, src)`: clears `self`,
    /// takes `src`'s image and leaves `src` empty.
    pub unsafe fn move_from(&mut self, src: &mut Compact) {
        unsafe { self.clear() };
        *self = core::mem::replace(src, Self::EMPTY);
    }
    /// O(1) lookup view over the validated image, with the fast table of
    /// a paged file.
    pub fn view(&self) -> Option<Index<'_, IndexSource>> {
        let view = Index::view_validated(self.src.as_ref()?, &self.layout).ok()?;
        if self.fast.is_null() {
            return Some(view);
        }
        let fast = unsafe { core::slice::from_raw_parts(self.fast, self.count) };
        view.with_fast(fast).ok()
    }
    fn fast_bytes(&self) -> usize {
        (self.count * size_of::<FastEntry>()).max(1)
    }
    unsafe fn free_fast(&mut self) {
        if !self.fast.is_null() {
            stats::sub(stats::Stat::IndexFastBytes, self.fast_bytes() as u64);
            let tag = c"apr.index.fast.release".as_ptr();
            unsafe { lookup_free(self.fast.cast(), self.fast_bytes(), tag) };
            self.fast = null_mut();
        }
    }
    /// `compact_index_entry_view`: one-based record `id` of the image. The
    /// path is copied into `path` (NUL-terminated) and `out.path` points
    /// there; without `path`, `out.path` is null (size and mtime only).
    /// `Io` when a paged read failed, which callers must not report as a
    /// missing file.
    pub fn try_entry_view(
        &self,
        id: u32,
        out: &mut FileEntryView,
        path: Option<&mut EntryPath>,
    ) -> ampr_format::Result<()> {
        let v = self.view().ok_or(ampr_format::Error::Invalid)?;
        let r = v.record(id)?;
        out.path = null();
        if let Some(buf) = path {
            let n = r.path_len as usize;
            v.path(&r, &mut buf[..n])?;
            buf[n] = 0;
            out.path = buf.as_ptr().cast();
        }
        out.path_length = r.path_len;
        out.size = r.size as usize;
        out.mtime = r.mtime;
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
    fn is_reg(&self) -> bool {
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
    for (path, key) in [
        (INDEX_PATH, &mut ws.index_key),
        (INDEX_TEMP_PATH, &mut ws.temp_index_key),
        (INDEX_BACKUP_PATH, &mut ws.backup_index_key),
        (COMMAND_LOG_PATH, &mut ws.command_log_key),
        (DEBUG_LOG_PATH, &mut ws.debug_log_key),
    ] {
        if unsafe { normalize_key(path.as_ptr(), key) }.is_none() {
            return;
        }
    }
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
    if has_unsupported_index_char(&ws.path[..len])
        || unsafe { normalize_key(path_ptr, &mut ws.path_key) }.is_none()
    {
        return true;
    }
    let key: *const c_char = ws.path_key.as_ptr().cast();
    for skip in [
        &ws.index_key,
        &ws.temp_index_key,
        &ws.backup_index_key,
        &ws.command_log_key,
        &ws.debug_log_key,
    ] {
        if unsafe { compare_key(key, skip.as_ptr().cast()) } == 0 {
            return true;
        }
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

/// `load_compact_app0_index_locked`: reads INDEX_PATH whole into index
/// memory when it fits with its tables, else registers it with the index
/// page cache (the fd stays open, misses read it again); validates it fully
/// and marks `idx` available.
pub(crate) unsafe fn load_compact_index(idx: &mut FileIndexState) -> LoadResult {
    unsafe { idx.compact.clear() };
    let fd = unsafe { real_posix_open(INDEX_PATH.as_ptr(), O_RDONLY, 0) };
    if fd < 0 {
        return open_failure_result(errno());
    }
    let mut st = Stat::default();
    let len = if unsafe { real_physical_fstat(fd, (&raw mut st).cast()) } != 0 {
        Err(LoadResult::Unreadable)
    } else if st.st_size < ampr_format::IDX_HEADER as i64 {
        Err(LoadResult::Invalid)
    } else {
        Ok(st.st_size as u64)
    };
    // The header is checked before any memory is committed: a corrupt file
    // must not take the page arena (rt/index_pages.rs).
    let src = len
        .and_then(|len| Ok((len, unsafe { read_count(fd) }?)))
        .and_then(|(len, count)| match unsafe { read_whole(fd, len, count) } {
            Some(bytes) => Ok(IndexSource::Resident(bytes)),
            None => index_pages::register_file(fd, len)
                .map(IndexSource::Paged)
                .ok_or(LoadResult::Memory),
        });
    match src {
        Ok(src) => {
            if let IndexSource::Resident(bytes) = src {
                unsafe { real_physical_close(fd) };
                idx.compact.mem = bytes.as_ptr().cast_mut();
            } else {
                idx.compact.fd = fd;
            }
            idx.compact.src = Some(src);
            unsafe { finish_compact(idx) }
        }
        Err(e) => {
            unsafe { real_physical_close(fd) };
            e
        }
    }
}

/// Lookup bytes a paged index adds per record: its fast table entry and
/// about 20 B of pack tables built from it (16 B of projection per id and
/// 4 B of order, rt/pack/zstd.rs `lookup_bytes`).
const LOOKUP_PER_FILE: usize = size_of::<FastEntry>() + 20;

/// The record count of the index file `fd` from its checked header:
/// Unreadable on a read error, Invalid when it is not an AMPRIDX3 header.
unsafe fn read_count(fd: c_int) -> Result<usize, LoadResult> {
    let mut head = [0u8; ampr_format::IDX_HEADER];
    if !index_pages::read_head(fd, &mut head) {
        return Err(LoadResult::Unreadable);
    }
    Layout::parse(&head)
        .map(|l| l.count as usize)
        .map_err(load_error)
}

/// The index file `fd` of `len` bytes and `count` records read whole, when
/// it and the tables a paged one would need fit the Index room left; None
/// otherwise (then it is paged) or on a read error.
unsafe fn read_whole(fd: c_int, len: u64, count: usize) -> Option<&'static [u8]> {
    let fits = usize::try_from(len)
        .ok()
        .and_then(|n| n.checked_add(count.checked_mul(LOOKUP_PER_FILE)?))
        .is_some_and(|n| n <= im::index_room());
    if !fits {
        return None;
    }
    unsafe { index_pages::read_resident(fd, len, c"apr.index.file") }
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

/// Adopts a built image (header first, `len` bytes at `image`, a
/// `build_alloc` block that `idx` now owns) for when it cannot be installed
/// as INDEX_PATH. It is read from memory like a file read whole (no page
/// cache, no fast table), validated like `load_compact_index` and freed by
/// `clear`.
unsafe fn adopt_compact_index(idx: &mut FileIndexState, image: *mut u8, len: usize) -> LoadResult {
    unsafe { idx.compact.clear() };
    idx.compact.mem = image;
    let bytes = unsafe { core::slice::from_raw_parts(image.cast_const(), len) };
    idx.compact.src = Some(IndexSource::Resident(bytes));
    unsafe { finish_compact(idx) }
}

/// Checks the image (`check_compact`) and marks `idx` available; clears
/// it on any error. A read error is Unreadable; a fast table that does not
/// fit, or a paged file that is not sorted, refuses the index (Memory)
/// with the one index notice.
unsafe fn finish_compact(idx: &mut FileIndexState) -> LoadResult {
    let c = &mut idx.compact;
    match unsafe { check_compact(c) } {
        Ok(()) => {
            c.available = true;
            idx.available = true;
            // With no pack index to mount after it, this file's fast table
            // is the last lookup table: the page arena takes the room left
            // (the pack mounts grow it in a title with packs).
            if !super::pack::packs_present() {
                index_pages::grow_arena(0);
            }
            LoadResult::Loaded
        }
        Err(e) => {
            unsafe { idx.compact.clear() };
            e
        }
    }
}

fn load_error(e: ampr_format::Error) -> LoadResult {
    match e {
        ampr_format::Error::Io => LoadResult::Unreadable,
        _ => LoadResult::Invalid,
    }
}

/// Sets `c`'s layout, count and sort flag from its source. A paged file
/// gets its fast table first and is checked against it in one sequential
/// pass over records and paths (`Index::check`), with no slot probe
/// through the page cache. A paged file must be sorted: an unsorted one
/// would answer `find_directory` with a scan of every record through the
/// cache, so it is served only read whole (the runtime builder writes
/// sorted images).
unsafe fn check_compact(c: &mut Compact) -> Result<(), LoadResult> {
    let src = c.src.as_ref().ok_or(LoadResult::Invalid)?;
    let layout = ampr_format::index::read_layout(src).map_err(load_error)?;
    (c.layout, c.count) = (layout, layout.count as usize);
    let paged = !src.is_resident();
    if paged {
        unsafe { attach_fast(c) }?;
    }
    let src = c.src.as_ref().ok_or(LoadResult::Invalid)?;
    let mut view = Index::view_validated(src, &c.layout).map_err(load_error)?;
    if !c.fast.is_null() {
        let fast = unsafe { core::slice::from_raw_parts(c.fast, c.count) };
        view = view.with_fast(fast).map_err(load_error)?;
    }
    c.sorted = view.check().map_err(load_error)?;
    if paged && !c.sorted {
        let len = ampr_format::source::Source::len(src);
        let needed = usize::try_from(len).unwrap_or(usize::MAX);
        unsafe { index_pages::refuse(needed) };
        return Err(LoadResult::Memory);
    }
    Ok(())
}

/// The fast table of a paged index (`count` and `layout` set), one
/// lookup allocation filled by one pass over its hash slots. Without it
/// the index is refused: a paged lookup would probe slots through the
/// page cache. Memory, with the index notice, when it and the pack tables
/// built from it do not fit the lookup cap or the Index room.
unsafe fn attach_fast(c: &mut Compact) -> Result<(), LoadResult> {
    let needed = c.count.saturating_mul(LOOKUP_PER_FILE);
    if im::lookup_used().saturating_add(needed) > im::INDEX_LOOKUP_MAX || needed > im::index_room()
    {
        unsafe { index_pages::refuse(needed) };
        return Err(LoadResult::Memory);
    }
    let src = c.src.as_ref().ok_or(LoadResult::Invalid)?;
    let view = Index::view_validated(src, &c.layout).map_err(load_error)?;
    let p = unsafe { lookup_alloc(c.fast_bytes(), 4, c"apr.index.fast".as_ptr()) };
    if p.is_null() {
        return Err(LoadResult::Memory);
    }
    let out = unsafe { core::slice::from_raw_parts_mut(p.cast::<FastEntry>(), c.count) };
    let filled = view.fill_fast(out);
    c.fast = p.cast();
    stats::add(stats::Stat::IndexFastBytes, c.fast_bytes() as u64);
    // On an error `clear` frees the table with the rest.
    filled.map_err(load_error)
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

use super::pack::ampr_pack_ensure_manifest_ready_safe;

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
        let result = unsafe { load_compact_index(&mut work) };
        let unreadable = next_unreadable_loads(UNREADABLE_LOADS.load(Relaxed), result);
        UNREADABLE_LOADS.store(unreadable, Relaxed);
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
                true
            }
            LoadResult::Unreadable => false,
            LoadResult::Missing | LoadResult::Invalid if build => {
                unsafe { build_app0_index(&mut work, !packs) };
                true
            }
            _ => false,
        };
        // Finish the pack snapshot at this known-safe boundary: hooks must not
        // see the index resident before the manifest load is terminal.
        if final_loaded && work.available {
            unsafe { ampr_pack_ensure_manifest_ready_safe() };
        }

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

/// A lookup that could not read the index file (a page cache read error).
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

/// `lookup_app0_index_key_view`: (view, one-based id) of a file key; the
/// view's path is copied into `path` when given (see `entry_view`).
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
    let Some(view) = c.view() else {
        return Ok(None);
    };
    let Some(id) = io_or_none(view.find(key))? else {
        return Ok(None);
    };
    if id == 0 || id == FILEID_INVALID || id as usize > c.count {
        return Ok(None);
    }
    let mut v = empty_view();
    io_or_none(c.try_entry_view(id, &mut v, path).map(|()| Some((v, id))))
}

/// `lookup_resident_app0_directory_key`: a representative view for a
/// directory key that has at least one resident descendant file. Its path
/// is that file's, copied into `path`, cut to the key's length.
unsafe fn lookup_directory_key(
    key: &[u8],
    path: Option<&mut EntryPath>,
) -> Result<Option<FileEntryView>, IndexIo> {
    let Some(c) = published().filter(|c| c.available && c.count != 0) else {
        return Ok(None);
    };
    let Some(view) = c.view() else {
        return Ok(None);
    };
    let Some(id) = io_or_none(view.find_directory(key, c.sorted))? else {
        return Ok(None);
    };
    let mut e = empty_view();
    let Some(()) = io_or_none(c.try_entry_view(id, &mut e, path).map(Some))? else {
        return Ok(None);
    };
    Ok(Some(FileEntryView {
        path: e.path,
        path_length: key.len() as u32,
        size: 0,
        mtime: e.mtime,
    }))
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
}

/// The walk indexes every regular file of /app0 under a key that folds ASCII
/// case, so a miss is authoritative on case-sensitive (bfs, ext) and
/// case-insensitive (exFAT, pfs) trees alike, except for paths the walk can
/// never list: names with tab/LF/CR (`has_unsupported_index_char`), the
/// runtime's own files it skips, and non-ASCII names, which exFAT folds by
/// its Unicode upcase table while keys fold ASCII only. Those go to the FS.
/// With `links` (the walk skipped a symlink) no miss is authoritative: the
/// link and anything under it are absent from the index.
fn miss_is_authoritative(raw: &[u8], key: &[u8], links: bool) -> bool {
    let skipped = [
        INDEX_PATH,
        INDEX_TEMP_PATH,
        INDEX_BACKUP_PATH,
        COMMAND_LOG_PATH,
        DEBUG_LOG_PATH,
    ];
    !links
        && !raw.iter().any(|&b| b >= 0x80)
        && !has_unsupported_index_char(raw)
        && !skipped.iter().any(|p| p.to_bytes() == key)
}

/// A `Miss` lookup that could not read the index: not authoritative, so
/// the hook asks the real call (`io_miss`).
fn io_lookup(mut r: Lookup) -> Lookup {
    stats::add(stats::Stat::IndexLookupIo, 1);
    (r.state, r.io, r.authoritative) = (Resident::Miss, true, false);
    r
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
/// never builds or loads the index. A page of a large index that is not
/// resident is read from the index file by the page cache. A hook never
/// waits on another thread here: a page another thread is loading is read
/// from the index file by this thread, like the open() the hook replaces.
/// The entry's path is copied into `pbuf` (a hit's path, or a directory's
/// canonical prefix).
#[inline(never)]
unsafe fn lookup_resident_path(path: *const c_char, pbuf: &mut EntryPath) -> Lookup {
    let mut r = Lookup {
        state: Resident::NotApp0,
        entry: empty_view(),
        file_id: 0,
        expected_miss: false,
        authoritative: false,
        io: false,
    };
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
    let Ok((len, trailing)) = (unsafe { normalize_key_result(path, &mut buf) }) else {
        return r;
    };
    let key = &buf[..len];
    if !is_app0_key(key) {
        return r;
    }
    r.state = Resident::Miss;
    let file = if !trailing && len > 5 {
        unsafe { lookup_key_view(key, false, Some(&mut *pbuf)) }
    } else {
        Ok(None)
    };
    match file {
        Ok(Some((e, id))) => {
            (r.state, r.entry, r.file_id) = (Resident::Hit, e, id);
            return r;
        }
        Err(IndexIo) => return io_lookup(r),
        Ok(None) => {}
    }
    match unsafe { lookup_directory_key(key, Some(pbuf)) } {
        Ok(Some(e)) => {
            (r.state, r.entry) = (Resident::Directory, e);
            return r;
        }
        Err(IndexIo) => return io_lookup(r),
        Ok(None) => {}
    }
    r.expected_miss = true;
    let links = published().is_some_and(|c| c.links);
    r.authoritative = miss_is_authoritative(unsafe { cstr_bytes(path) }, key, links);
    r
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
    // is_resident_ready() holds, so ensure_ready inside returns at once.
    if !trailing && len > 5 {
        if let Ok(Some((_, id))) = unsafe { lookup_key_view(key, false, None) } {
            // A refused guard reads as "manifest not ready": no answer.
            let reader = super::pack::ManifestReader::enter()?;
            return super::pack::file_id_is_packed(&reader, id).then_some(b'p');
        }
    }
    unsafe { lookup_directory_key(key, None) }
        .ok()
        .flatten()
        .map(|_| b'd')
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
    let l = unsafe { lookup_resident_path(path, &mut pbuf) };
    let fd = unsafe { open_resolved(&l, path, flags, mode, real) };
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

unsafe fn open_resolved(
    l: &Lookup,
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    real: RealOpen,
) -> c_int {
    let dir_flag = flags & O_DIRECTORY != 0;
    let mut handled = false;
    match l.state {
        Resident::Directory => {
            stats::add(stats::Stat::OpenDirectory, 1);
            let mut canon = [0u8; RUNTIME_PATH_CAPACITY];
            if !unsafe { copy_dir_path(&l, &mut canon) } {
                set_errno(ENAMETOOLONG);
                return -1;
            }
            let canon: *const c_char = canon.as_ptr().cast();
            if directory_open_flags(flags) && unsafe { ampr_pack_manifest_is_resident_ready() } {
                let rc = unsafe { ampr_pack_open_directory(canon, flags, mode, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
            }
            unsafe { real(canon, flags, mode) }
        }
        Resident::Hit => {
            if dir_flag {
                set_errno(ENOTDIR);
                return -1;
            }
            // A packed file lives only in a pack volume (ampr_zstd-NNN.pak or
            // an AMPRPAK4 volume), so a packed hit opens a virtual fd; a loose
            // one (unhandled) opens the physical file below.
            stats::add(stats::Stat::OpenHit, 1);
            if unsafe { ampr_pack_manifest_is_resident_ready() } {
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
            let fd = unsafe { real(l.entry.path, flags, mode) };
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
            if directory_open_flags(flags) && unsafe { ampr_pack_manifest_is_resident_ready() } {
                let rc =
                    unsafe { ampr_pack_open_virtual_directory(path, flags, mode, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
            }
            if !l.authoritative {
                return unsafe { io_miss(l, real(path, flags, mode)) };
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
            if directory_open_flags(flags)
                && unsafe { has_app0_root(path) && ampr_pack_manifest_is_resident_ready() }
            {
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
    let l = unsafe { lookup_resident_path(path, &mut pbuf) };
    let rc = unsafe { stat_resolved(&l, path, sb, real) };
    stats::fs_event(op, how(&l), rc as i64, path);
    rc
}

unsafe fn stat_resolved(l: &Lookup, path: *const c_char, sb: *mut Stat, real: RealStat) -> c_int {
    match l.state {
        Resident::Directory => unsafe { sb.write_unaligned(dir_stat(&l)) },
        Resident::Hit => unsafe { sb.write_unaligned(file_stat(&l)) },
        Resident::Miss => {
            let mut pack_io = false;
            if unsafe { ampr_pack_manifest_is_resident_ready() } {
                let mut handled = false;
                let rc = unsafe { ampr_pack_try_stat_path(path, sb, &mut handled) };
                if handled {
                    return posix_return_from_sce(rc);
                }
                // The pack index could not be read: the file may be loose.
                pack_io = rc == SCE_KERNEL_ERROR_EIO;
            }
            if !l.authoritative || pack_io {
                return unsafe { io_miss_if(l.io || pack_io, real(path, sb.cast())) };
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
    let l = unsafe { lookup_resident_path(path, &mut pbuf) };
    let rc = unsafe { reachability_resolved(&l, path) };
    stats::fs_event(b'r', how(&l), rc as i64, path);
    rc
}

unsafe fn reachability_resolved(l: &Lookup, path: *const c_char) -> c_int {
    match l.state {
        Resident::Directory | Resident::Hit => 0,
        Resident::Miss => {
            let mut pack_io = false;
            if unsafe { ampr_pack_manifest_is_resident_ready() } {
                let mut handled = false;
                let rc = unsafe { ampr_pack_try_reachability(path, &mut handled) };
                if handled {
                    return rc;
                }
                pack_io = rc == SCE_KERNEL_ERROR_EIO;
            }
            if !l.authoritative || pack_io {
                let rc = unsafe { real_check_reachability(path) };
                if (l.io || pack_io) && rc == SCE_KERNEL_ERROR_ENOENT {
                    let packs = unsafe { ampr_pack_manifest_is_resident_ready() };
                    return sce_errno(io_miss_errno(ENOENT, packs));
                }
                return rc;
            }
            SCE_KERNEL_ERROR_ENOENT
        }
        _ => unsafe { real_check_reachability(path) },
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
    unsafe { open_impl(path, flags, mode) }
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

/// `_open`, variadic like `open` (see `posix_open_emul`).
pub unsafe extern "C" fn underscore_open_emul(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    if super::hook::observed_only(hook::_open) {
        let rc = unsafe { real_underscore_open_raw(path, flags, mode) };
        unsafe { observe_note(path, b'O', rc) };
        return rc;
    }
    unsafe {
        open_with(
            path,
            flags,
            creat_mode(flags, mode),
            real_underscore_open,
            b'O',
        )
    }
}

/// `_openat`: an absolute or cwd-relative path takes the `open` routing; a
/// path relative to another directory fd goes to the original.
pub unsafe extern "C" fn underscore_openat_emul(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    if path.is_null() || (unsafe { *path } != b'/' as c_char && dirfd != AT_FDCWD) {
        return unsafe { real_openat(dirfd, path, flags, mode) };
    }
    if super::hook::observed_only(hook::_openat) {
        let rc = unsafe { real_openat(dirfd, path, flags, mode) };
        unsafe { observe_note(path, b'A', rc) };
        return rc;
    }
    unsafe { open_with(path, flags, creat_mode(flags, mode), real_openat_cwd, b'A') }
}

pub unsafe extern "C" fn posix_lstat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
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
    if super::hook::observed_only(hook::access) {
        let rc = unsafe { real_access(path, mode) };
        unsafe { observe_note(path, b'a', rc) };
        return rc;
    }
    let mut pbuf: EntryPath = [0; PATH_BUF];
    let l = unsafe { lookup_resident_path(path, &mut pbuf) };
    let rc = match l.state {
        Resident::Hit | Resident::Directory if mode & W_OK != 0 => {
            set_errno(EROFS);
            -1
        }
        // Packed files stat as 0444: not executable (directories are searchable).
        Resident::Hit if mode & X_OK != 0 => {
            set_errno(EACCES);
            -1
        }
        Resident::Hit | Resident::Directory => 0,
        // The pack overlay first (packed-only directories), then the FS.
        Resident::Miss if !l.authoritative => {
            let mut st = core::mem::MaybeUninit::<Stat>::uninit();
            let mut handled = false;
            let rc = if unsafe { ampr_pack_manifest_is_resident_ready() } {
                unsafe { ampr_pack_try_stat_path(path, st.as_mut_ptr(), &mut handled) }
            } else {
                0
            };
            if handled {
                posix_return_from_sce(rc)
            } else {
                let pack_io = rc == SCE_KERNEL_ERROR_EIO;
                unsafe { io_miss_if(l.io || pack_io, real_access(path, mode)) }
            }
        }
        Resident::Miss => {
            let mut st = core::mem::MaybeUninit::<Stat>::uninit();
            unsafe { stat_resolved(&l, path, st.as_mut_ptr(), real_lstat) }
        }
        _ => unsafe { real_access(path, mode) },
    };
    stats::fs_event(b'a', how(&l), rc as i64, path);
    rc
}

pub unsafe extern "C" fn posix_stat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
    unsafe { stat_impl(path, sb) }
}

pub unsafe extern "C" fn sceKernelOpen_emul(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
) -> c_int {
    sce_result(unsafe { open_impl(path, flags, mode) })
}

pub unsafe extern "C" fn sceKernelStat_emul(path: *const c_char, sb: *mut Stat) -> c_int {
    sce_result(unsafe { stat_impl(path, sb) })
}

pub unsafe extern "C" fn sceKernelCheckReachability_emul(path: *const c_char) -> c_int {
    unsafe { reachability_impl(path) }
}

pub unsafe extern "C" fn posix_unlink_emul(path: *const c_char) -> c_int {
    unsafe { unlink_impl(path) }
}

pub unsafe extern "C" fn posix_rename_emul(from: *const c_char, to: *const c_char) -> c_int {
    unsafe { rename_impl(from, to) }
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

/// The mounted AMPRPAK4 manifest: a file read whole, or paged with its
/// records in a resident fast table (rt/pack/manifest.rs).
pub(crate) type Lz4Manifest = Manifest<'static, IndexSource>;

/// `AmprPackCoreView`: the mounted manifest and a copy of its header. The
/// manifest may be paged, so the view holds no pointers into it.
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
    assert!(offset_of!(AmprPackChunkView, flags) == 19);
    assert!(
        size_of::<AmprPackBlockReadTask>() == 40 && offset_of!(AmprPackBlockReadTask, chunk) == 16
    );
};

impl From<ChunkView> for AmprPackChunkView {
    fn from(v: ChunkView) -> Self {
        Self {
            offset: v.chunk.offset,
            stored_size: v.chunk.stored_size,
            raw_size: v.raw_size,
            pack_id: v.chunk.pack_id,
            codec: v.chunk.codec,
            flags: v.chunk.flags,
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

/// Full `Manifest::open` validation through the mounted source, then
/// fills `out` (empty on error); LZ4 only (zstd mounts through
/// `zstd::zstd_mount_validate`).
pub(crate) unsafe fn ampr_pack_core_mount(
    src: &'static IndexSource,
    out: *mut AmprPackCoreView,
) -> c_int {
    use ampr_format::source::Source;
    if out.is_null() {
        return PACK_INVALID_ARGUMENT;
    }
    unsafe { out.write(AmprPackCoreView::EMPTY) };
    if src.len() < PAK_HEADER as u64 {
        return PACK_INVALID_ARGUMENT;
    }
    let m = match Manifest::open(src) {
        Ok(m) => m,
        Err(e) => return CoreError::from(e).code(),
    };
    let mut h = [0u8; PAK_HEADER];
    if let Err(e) = src.read_at(0, &mut h) {
        return CoreError::from(e).code();
    }
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

/// One-based `file_id` against `path`/`logical_size` of a mounted view.
pub unsafe fn ampr_pack_core_validate_logical_file(
    view: *const AmprPackCoreView,
    file_id: u32,
    path: *const c_char,
    path_len: usize,
    logical_size: u64,
) -> c_int {
    // zstd: `file_id` is an AMPRIDX3 id, checked against the zstd pack index.
    if zstd_mode() {
        return unsafe {
            zstd::zstd_core_validate_logical_file(file_id, path, path_len, logical_size)
        };
    }
    {
        let (Some(m), Some(path)) = (unsafe { view_manifest(view) }, unsafe {
            region(path.cast(), path_len)
        }) else {
            return PACK_INVALID_ARGUMENT;
        };
        match m.validate_logical_file(file_id, path, logical_size) {
            Ok(()) => PACK_OK,
            // As zstd: a packed file whose index could not be read is EIO.
            Err(CoreError::Io) => zstd::VALIDATE_IO,
            Err(e) => e.code(),
        }
    }
}

/// Block tasks for a read of `file`; zero for a rejected request. zstd:
/// `file` is `zstd::zstd_task_file(ampr_id)`, tasks are 256 KiB chunks.
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
    // zstd: `file` is `zstd::zstd_task_file(ampr_id)`; `view` is unused.
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
mod tests {
    use super::*;

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
            miss_is_authoritative(raw.to_bytes(), &key[..len], links)
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
    }

    /// USB index I/O: the write loop continues short transfers and retries
    /// EINTR, and fails on errors and endless EINTR. (Index file reads go
    /// through rt/index_pages.rs and the pack `pread_loop`.)
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
        };
        l = io_lookup(l);
        assert!(l.state == Resident::Miss && l.io && !l.authoritative);
        assert_eq!(how(&l), b'M');
        assert_eq!(io_miss_errno(ENOENT, true), EIO);
        assert_eq!(io_miss_errno(ENOENT, false), ENOENT);
        assert_eq!(io_miss_errno(EACCES, true), EACCES);
    }

    /// Only ENOENT means the index is missing; unreadable loads count only
    /// in a row, saturating.
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

    // ---- uninstalled image (rt/index_pages.rs memory source) ----

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

    /// A paged AMPRIDX3 file mounts only with its fast table: with less
    /// Index room than the table and the pack tables built from it need, it
    /// is refused with the index notice and takes nothing; with the room,
    /// `find` answers as the plain image does and `clear` gives every byte
    /// back. In a title with no packs the mount then grows the page arena.
    #[test]
    fn a_paged_file_index_needs_its_fast_table() {
        use super::super::index_memory as im;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 3000;
        let image: &'static [u8] = sized_image(n, 256 << 10).leak();
        let plain = Index::open(image).unwrap();
        let paged = |idx: &mut FileIndexState| {
            let src = unsafe { index_pages::register_memory(image.as_ptr(), image.len()) };
            idx.compact.src = Some(IndexSource::Paged(src.unwrap()));
            unsafe { finish_compact(idx) }
        };
        let page = SCE_KERNEL_PAGE_SIZE;
        let used = im::test_index_used();
        let grows = index_pages::test_grow_calls();
        im::test_take_index_notice();
        unsafe {
            // Leave a page less than the tables need.
            let need = (n * LOOKUP_PER_FILE).next_multiple_of(page);
            let fill = im::index_room() - need + page;
            let other = im::index_alloc(fill, page, c"test.other.tables".as_ptr());
            assert!(!other.is_null());
            let mut idx = empty_state();
            assert!(paged(&mut idx) == LoadResult::Memory);
            assert!(im::test_take_index_notice());
            assert!(!idx.available && idx.compact.src.is_none() && idx.compact.fast.is_null());
            assert_eq!(im::test_index_used(), used + fill);
            assert_eq!(index_pages::test_grow_calls(), grows);
            im::index_free(other.cast(), c"test.other.tables.free".as_ptr());

            assert!(paged(&mut idx) == LoadResult::Loaded);
            assert!(!im::test_take_index_notice());
            assert!(idx.compact.sorted);
            assert_eq!(index_pages::test_grow_calls(), grows + 1);
            assert!(!idx.compact.fast.is_null());
            assert_eq!(im::lookup_used(), (n * 12).next_multiple_of(page));
            let view = idx.compact.view().unwrap();
            assert!(view.has_fast());
            let mut buf: EntryPath = [0; PATH_BUF];
            for id in [1, n as u32 / 2, n as u32] {
                let path = plain.path(&plain.record(id).unwrap(), &mut buf).unwrap();
                assert_eq!(view.find(path), Ok(Some(id)));
            }
            assert_eq!(view.find(b"/app0/none"), plain.find(b"/app0/none"));
            idx.compact.clear();

            // An unsorted file is not paged: `find_directory` would scan
            // every record through the cache. Refused with the notice.
            let unsorted: &'static [u8] = sized_image_in(n, 256 << 10, |i| i % 997).leak();
            let src = index_pages::register_memory(unsorted.as_ptr(), unsorted.len());
            let mut idx = empty_state();
            idx.compact.src = Some(IndexSource::Paged(src.unwrap()));
            assert!(finish_compact(&mut idx) == LoadResult::Memory);
            assert!(im::test_take_index_notice());
            assert!(!idx.available && idx.compact.src.is_none() && idx.compact.fast.is_null());
        }
        assert_eq!(im::test_index_used(), used);
        assert_eq!(im::lookup_used(), 0);
    }

    /// A built image that cannot be installed is served from its own
    /// build buffer like a file read whole (no page cache, no fast table):
    /// `adopt_compact_index` validates it, lookups and entry views copy
    /// paths out of it, and `clear` gives the buffer back. A corrupt image
    /// is refused and freed the same way.
    #[test]
    fn an_uninstalled_image_is_served_from_memory_and_given_back() {
        use super::super::index_memory as im;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 20_000;
        let image = sized_image(n, 4 << 20);
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
        assert!(idx.available && idx.compact.count == n);
        assert!(idx.compact.fast.is_null());
        assert!(idx.compact.src.is_some_and(|s| s.is_resident()));
        let view = idx.compact.view().unwrap();
        let mut a: EntryPath = [0xA5; PATH_BUF];
        let rec = view.record(7).unwrap();
        let path = view.path(&rec, &mut a).unwrap().to_vec();
        assert_eq!(view.find(&path), Ok(Some(7)));
        let mut v = empty_view();
        let mut b: EntryPath = [0xA5; PATH_BUF];
        assert_eq!(idx.compact.try_entry_view(7, &mut v, Some(&mut b)), Ok(()));
        assert_eq!(v.path, b.as_ptr().cast());
        assert_eq!(&b[..v.path_length as usize], &path[..]);
        assert_eq!(b[v.path_length as usize], 0);
        assert!(idx.compact.try_entry_view(7, &mut v, None).is_ok() && v.path.is_null());
        assert!(idx
            .compact
            .try_entry_view(n as u32 + 1, &mut v, None)
            .is_err());
        unsafe { idx.compact.clear() };
        assert!(idx.compact.src.is_none());
        assert_eq!(im::test_index_used(), used);

        let mut bad = image.clone();
        let slots_at = u64::from_le_bytes(bad[32..40].try_into().unwrap()) as usize;
        let hit = (slots_at..bad.len())
            .step_by(16)
            .find(|&at| bad[at + 8..at + 12] != [0; 4])
            .unwrap();
        bad[hit] ^= 1;
        let (idx, rc) = adopt(&bad);
        assert!(rc == LoadResult::Invalid);
        assert!(!idx.available && idx.compact.src.is_none() && idx.compact.mem.is_null());
        assert_eq!(im::test_index_used(), used);
    }
}
