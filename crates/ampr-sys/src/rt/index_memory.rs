//! Runtime memory that grows with the title, and the pack cache and
//! buffers, carved from the PRX's static pool (rt/runtime_memory.rs) under
//! three ledgers with hard caps: Index (the compiled index view, the pack
//! index tables and every build buffer sized by file count, path bytes or
//! file size), Cache (the
//! decoded chunk cache) and Buffer (the pipeline I/O windows and worker decode
//! buffers). The Index and Buffer caps, the fixed pool sites and the thread
//! stack block are fixed and the Cache cap is the rest of the pool (checked
//! at build time), so no ledger can take another's room and none needs room
//! held back for it. Never direct or flexible memory: the pool is PRX .bss and did not
//! lower the game's free direct memory, while our direct allocations did (a
//! title had 42 MiB of direct memory free during play), and flexible memory
//! had 0-28 MiB free in another title (debug /metrics `flex_*` and the
//! former direct memory lines).
//!
//! A refused allocation degrades: an index that does not fit leaves the
//! packs unserved (packed files read as missing, ENOENT) after one console
//! notice naming the size and the cap; a refused cache stays off; every
//! I/O window is taken at the worker start and a refused one lowers the
//! pipeline count (pack/worker.rs `buffer_split`).

use super::runtime_memory::{ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_free};
use super::sync::{SpinLock, SyncCell};
use super::sys::*;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

const MIB: usize = 1 << 20;

/// Cap on index memory, all index allocations together: the compiled
/// index view, the pack index tables kept after the mount (zstd chunk and
/// volume tables, the AMPRPAK4 header, record sections and pack names and
/// its mismatch bitmap) and the
/// transient buffers (the 64 KiB windows a build reads an index file
/// through, the walk build, the debug /bench buffer). A
/// walk-built AMPRIDX3 is built whole first, at 104-124 bytes per file at
/// 48-byte paths (a 24-byte record, the path, 16-32 bytes of hash slots;
/// tests below), so a build image of 699,050 files fits
/// (`files_the_index_cap_covers`).
/// The compiled index view is one block of the cap (rt/index_view.rs
/// `layout`): at 300,000 files and the first directory capacity it is
/// 12.6 MiB with no packs, 14.9 MiB for zstd packs and 16.0 MiB for LZ4
/// (computed: 24 B of columns, 8 B of `path_at` and `dir_of` and 7 B of
/// hash slots per file, plus 32 B per directory).
/// An AMPRPAK4 mount keeps 48 B per file and 12 B per chunk (its record
/// sections), 32 B per pack and its name plus a 16 B span,
/// and the 128 B header; the paths are read once, at the mount, through
/// the windows (rt/pack/manifest.rs `LZ4_IMAGE`). At 223,180 files,
/// 1,513,210 chunks and 18 packs that is 27.5 MiB (computed), plus one
/// mismatch bit per view id.
/// 80 MiB: room for a zstd view of about 870,000 files at 5.5 chunks per
/// file (computed from a 242,409-file index: 21.74 MiB with its chunk
/// table), 16 MiB more than the 64 MiB before it, taken by a larger PRX
/// (Makefile `AMPR_INTERNAL_POOL_SIZE`), not from another ledger.
pub(crate) const INDEX_MEMORY_MAX: usize = 80 * MIB;

/// Cap on cache memory: what the pool has left after the Index and Buffer
/// caps, the fixed sites budget and the thread stack block, rounded down to
/// a 16 KiB cache page. The cache is the only part whose size changes
/// behaviour (more I/O windows, 12 vs 16, and more decode workers, 4 vs 8,
/// measured flat: 312 vs 315 us game wait per read), so the PRX total is a
/// round number and the cache takes the rest: 133.64 MiB in the debug pool,
/// 134.98 MiB in the release one at the 256 MiB layout (pools fitted from
/// a `dist` build, Makefile).
/// The decoded cache default is this whole cap (rt/pack/mod.rs
/// `AMPR_EMU_PACK_DECODED_CACHE_BYTES`); a runtime profile or debug knob
/// asking less gets that (pack/manifest.rs `cache_region`).
pub(crate) const CACHE_MEMORY_MAX: usize = {
    let fixed = INDEX_MEMORY_MAX
        + BUFFER_MEMORY_MAX
        + super::runtime_memory::POOL_SITES_BUDGET
        + STACK_MEMORY_MAX;
    let page = crate::rt::pack::PACK_CACHE_PAGE_BYTES;
    match super::runtime_memory::STATIC_POOL_SIZE.checked_sub(fixed) {
        Some(left) => left / page * page,
        None => panic!("AMPR_INTERNAL_POOL_SIZE / AMPR_DEBUG_POOL_SIZE below the Index and Buffer caps, the sites budget and the stack block"),
    }
};

/// Pool block for the runtime's own thread stacks (rt/thread_stack.rs),
/// carved at the first thread start. Worst case under the 16-thread budget:
/// 4 x 128 KiB + 12 x 64 KiB + reactor and metrics 64 KiB each = 1.38 MiB,
/// plus one 16 KiB guard page per stack (18, 0.28 MiB): 1.66 MiB
/// (`the_block_holds_the_worst_case_thread_set`).
pub(crate) const STACK_MEMORY_MAX: usize = 2 * MIB;

/// Cap on buffer memory: a 1 MiB decode buffer and a 112 KiB zstd decoder
/// workspace for each build worker (Makefile `AMPR_PACK_WORKERS`, default
/// 4), a 2 MiB I/O window for each build pipeline (`AMPR_PACK_PIPELINES`,
/// default 12): 28.44 MiB at the defaults (rt/pack/mod.rs).
/// Buffers past it are refused: a worker without one does not start, a
/// pipeline without a window is not used (worker.rs `buffer_split`).
pub(crate) const BUFFER_MEMORY_MAX: usize = BUFFER_WORKERS * crate::rt::pack::PACK_MAX_BLOCK_BYTES
    + BUFFER_PIPELINES * crate::rt::pack::PACK_PIPELINE_IO_BYTES
    + BUFFER_DECODERS * ampr_codec::ZSTD_DECODER_WORKSPACE;
const BUFFER_WORKERS: usize = crate::rt::pack::AMPR_EMU_PACK_WORKERS as usize;
const BUFFER_PIPELINES: usize = crate::rt::tune::RELEASE_PIPELINES as usize;
/// zstd decoder workspaces: one per build worker.
const BUFFER_DECODERS: usize = BUFFER_WORKERS;
// A workspace is whole pages, so the ledger counts it at its size.
const _: () = assert!(ampr_codec::ZSTD_DECODER_WORKSPACE % SCE_KERNEL_PAGE_SIZE == 0);

/// The three caps together; with the 2 MiB fixed sites budget
/// (rt/runtime_memory.rs `POOL_SITES_BUDGET`) and the 2 MiB stack block
/// they fill the pool to its last 16 KiB page. A knob that grows a cap past
/// the pool fails the build in `CACHE_MEMORY_MAX` or here instead of
/// refusing buffers at run time.
pub(crate) const LEDGER_MEMORY_MAX: usize = INDEX_MEMORY_MAX + CACHE_MEMORY_MAX + BUFFER_MEMORY_MAX;
const _: () = assert!(
    LEDGER_MEMORY_MAX + super::runtime_memory::POOL_SITES_BUDGET + STACK_MEMORY_MAX
        <= super::runtime_memory::STATIC_POOL_SIZE,
    "AMPR_INTERNAL_POOL_SIZE / AMPR_DEBUG_POOL_SIZE below the ledger caps plus the sites budget and the stack block"
);
const _: () = assert!(
    CACHE_MEMORY_MAX as u64 >= crate::rt::pack::AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES
        && CACHE_MEMORY_MAX as u64 <= crate::rt::pack::AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES,
    "the pool leaves the decoded cache outside its 16 MiB minimum or its maximum"
);

/// Who an allocation is for; each kind has its own ledger and cap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Index,
    Cache,
    Buffer,
}

impl Kind {
    #[cfg(test)]
    const ALL: [Kind; 3] = [Kind::Index, Kind::Cache, Kind::Buffer];

    fn name(self) -> &'static [u8] {
        match self {
            Kind::Index => b"index",
            Kind::Cache => b"cache",
            Kind::Buffer => b"buffer",
        }
    }
}

// ---- ledger (pure accounting) ---------------------------------------------

#[derive(Clone, Copy)]
struct Block {
    /// 0 = free slot, 1 = claimed while the pool is asked.
    ptr: usize,
    mapped: usize,
}

const BLOCK0: Block = Block { ptr: 0, mapped: 0 };
const PENDING: usize = 1;
/// Index blocks live at once, at most: four resident (the compiled index
/// view, the path blob of a walk-built index, the kept AMPRPAK4 parts or
/// the zstd chunk and volume tables, the AMPRPAK4 mismatch bitmap), the walk
/// build's records, paths and directory stack (two of each while one
/// doubles), its getdents buffer over `DENTS_POOL_MAX` and its image, the
/// one block of two 64 KiB windows an index file is read through
/// (rt/index_file.rs; the AMPRIDX3 load gives its block back before the
/// pack index mount takes one) and the debug /bench buffer: 14.
const INDEX_BLOCKS: usize = 14;
/// The decoded cache.
const CACHE_BLOCKS: usize = 1;
/// One per pipeline window and per worker decode buffer and decoder
/// workspace.
const BUFFER_BLOCKS: usize = crate::rt::pack::AMPR_EMU_PACK_PIPELINE_SLOTS
    + 2 * crate::rt::pack::AMPR_EMU_PACK_WORKER_CAPACITY;
const BLOCK_ARRAY: usize = if BUFFER_BLOCKS > INDEX_BLOCKS {
    BUFFER_BLOCKS
} else {
    INDEX_BLOCKS
};

/// Why an allocation was refused before the pool was asked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Refusal {
    /// Past the kind's own cap.
    LedgerCap,
    /// No block slot left.
    NoSlot,
}

struct Ledger {
    blocks: [Block; BLOCK_ARRAY],
    /// Slots this ledger may use, at most BLOCK_ARRAY.
    slots: usize,
    /// Pool bytes, claimed and allocated, counted against `cap`.
    used: usize,
    cap: usize,
}

impl Ledger {
    const fn new(cap: usize, slots: usize) -> Self {
        Self {
            blocks: [BLOCK0; BLOCK_ARRAY],
            slots,
            used: 0,
            cap,
        }
    }

    /// Claims a slot and `mapped` bytes of the cap.
    fn reserve(&mut self, mapped: usize) -> Result<usize, Refusal> {
        if mapped > self.cap - self.used {
            return Err(Refusal::LedgerCap);
        }
        let i = self.blocks[..self.slots]
            .iter()
            .position(|b| b.ptr == 0)
            .ok_or(Refusal::NoSlot)?;
        self.blocks[i] = Block {
            ptr: PENDING,
            mapped,
        };
        self.used += mapped;
        Ok(i)
    }

    /// Gives back a claim the pool could not fill.
    fn cancel(&mut self, i: usize) {
        self.used -= self.blocks[i].mapped;
        self.blocks[i] = BLOCK0;
    }

    fn fill(&mut self, i: usize, ptr: usize) {
        self.blocks[i].ptr = ptr;
    }

    /// Removes the block at `ptr`.
    fn take(&mut self, ptr: usize) -> Option<Block> {
        let i = self
            .blocks
            .iter()
            .position(|b| b.ptr == ptr && ptr > PENDING)?;
        let b = self.blocks[i];
        self.used -= b.mapped;
        self.blocks[i] = BLOCK0;
        Some(b)
    }
}

// ---- ledgers and pool -------------------------------------------------------

/// The three ledgers.
struct Ledgers {
    index: Ledger,
    cache: Ledger,
    buffer: Ledger,
}

impl Ledgers {
    const fn new() -> Self {
        Self {
            index: Ledger::new(INDEX_MEMORY_MAX, INDEX_BLOCKS),
            cache: Ledger::new(CACHE_MEMORY_MAX, CACHE_BLOCKS),
            buffer: Ledger::new(BUFFER_MEMORY_MAX, BUFFER_BLOCKS),
        }
    }

    /// `move_index_room_to_cache` on these ledgers.
    fn move_index_room(&mut self, page: usize) -> usize {
        let room = self.index.cap - self.index.used;
        let moved = room.saturating_sub(INDEX_KEPT_ROOM) / page * page;
        self.index.cap -= moved;
        self.cache.cap += moved;
        moved
    }

    /// `return_cache_room_to_index` on these ledgers.
    fn return_cache_room(&mut self, bytes: usize) {
        let b = bytes.min(self.cache.cap - self.cache.used);
        self.cache.cap -= b;
        self.index.cap += b;
    }

    fn get(&mut self, kind: Kind) -> &mut Ledger {
        match kind {
            Kind::Index => &mut self.index,
            Kind::Cache => &mut self.cache,
            Kind::Buffer => &mut self.buffer,
        }
    }

    /// Bytes over all ledgers, claims included.
    #[cfg(any(test, feature = "mem_report"))]
    fn total(&self) -> usize {
        self.index.used + self.cache.used + self.buffer.used
    }
}

static LOCK: SpinLock = SpinLock::new();
static LEDGERS: SyncCell<Ledgers> = SyncCell::new(Ledgers::new());

fn with_all<R>(f: impl FnOnce(&mut Ledgers) -> R) -> R {
    let _g = LOCK.lock();
    f(unsafe { &mut *LEDGERS.get() })
}

fn with_kind<R>(kind: Kind, f: impl FnOnce(&mut Ledger) -> R) -> R {
    with_all(|l| f(l.get(kind)))
}

fn page_round(bytes: usize) -> usize {
    (bytes + SCE_KERNEL_PAGE_SIZE - 1) & !(SCE_KERNEL_PAGE_SIZE - 1)
}

/// Frees a `kind` block (null is a no-op).
unsafe fn free_kind(kind: Kind, ptr: *mut c_void, tag: *const c_char) {
    if ptr.is_null() {
        return;
    }
    // Pool first, then the ledger, both under the ledger lock: a same-kind
    // allocation that passes the ledger then finds the pool room too, and
    // cannot get this address back before its block is taken. The pool
    // lock nests inside the ledger lock and the pool never takes the
    // ledger lock, so the order holds.
    with_kind(kind, |l| {
        unsafe { ampr_internal_amm_pool_free(ptr, tag) };
        l.take(ptr as usize)
    });
}

/// `mapped` (page-rounded) pool bytes for `kind` under its cap; None when
/// refused (a cap refusal counted here, and noticed once when `notice`; a
/// failed pool allocation counted in `pool_alloc_failed`).
unsafe fn alloc_kind(
    kind: Kind,
    mapped: usize,
    tag: *const c_char,
    notice: bool,
) -> Option<*mut u8> {
    let claim = with_kind(kind, |l| {
        let needed = l.used.saturating_add(mapped);
        l.reserve(mapped).map_err(|r| (r, needed))
    });
    let i = match claim {
        Ok(i) => i,
        Err((reason, needed)) => {
            unsafe { refused(kind, reason, needed, mapped, notice) };
            return None;
        }
    };
    let mut got = 0usize;
    // The ledger lock is not held here: the first pool use publishes the
    // pool with an mprotect.
    let p: *mut u8 =
        unsafe { ampr_internal_amm_pool_alloc(mapped, &mut got, tag, false, SCE_KERNEL_PAGE_SIZE) }
            .cast();
    if p.is_null() || got < mapped {
        if !p.is_null() {
            unsafe { ampr_internal_amm_pool_free(p.cast(), tag) };
        }
        with_kind(kind, |l| l.cancel(i));
        return None;
    }
    with_kind(kind, |l| l.fill(i, p as usize));
    Some(p)
}

// ---- refusals: counters and one-time notices --------------------------------

/// /metrics `pool_alloc_failed`: pool allocations that returned null
/// (rt/runtime_memory.rs, rt/index.rs `sdk_alloc`).
static POOL_ALLOC_FAILED: AtomicU64 = AtomicU64::new(0);
/// /metrics `ledger_alloc_refused`: allocations refused by a ledger cap or
/// a full slot table, before the pool was asked.
static LEDGER_ALLOC_REFUSED: AtomicU64 = AtomicU64::new(0);
static LEDGER_NOTICED: AtomicBool = AtomicBool::new(false);
static INDEX_NOTICED: AtomicBool = AtomicBool::new(false);

/// Counts a refusal and, when `notice`, sends at most one notice per
/// process for each class: the index cap (with the size it needed), any
/// other refusal. A transient buffer (`index_scratch_alloc`) is only
/// counted: its caller degrades on its own and the packs stay served.
unsafe fn refused(kind: Kind, reason: Refusal, needed: usize, mapped: usize, notice: bool) {
    LEDGER_ALLOC_REFUSED.fetch_add(1, Relaxed);
    if !notice {
        return;
    }
    let mut text = [0u8; 128];
    let n = if kind == Kind::Index && reason == Refusal::LedgerCap {
        if INDEX_NOTICED.swap(true, Relaxed) {
            return;
        }
        index_cap_notice(needed, &mut text)
    } else {
        if LEDGER_NOTICED.swap(true, Relaxed) {
            return;
        }
        ledger_refused_notice(kind, mapped, &mut text)
    };
    unsafe { super::exports::notify(&text[..n]) };
}

/// Called by the pool on a failed allocation. Counted only, no notice:
/// every ledger is capped inside the pool, so only a fixed site past its
/// budget could fail, and the debug counter shows that.
pub(crate) fn note_pool_failure() {
    POOL_ALLOC_FAILED.fetch_add(1, Relaxed);
}

#[cfg(feature = "mem_report")]
pub(crate) fn pool_alloc_failed() -> u64 {
    POOL_ALLOC_FAILED.load(Relaxed)
}

#[cfg(feature = "mem_report")]
pub(crate) fn ledger_alloc_refused() -> u64 {
    LEDGER_ALLOC_REFUSED.load(Relaxed)
}

/// Bytes over all ledgers (/metrics `ledger_mem_bytes`).
#[cfg(feature = "mem_report")]
pub(crate) fn ledger_mem_bytes() -> usize {
    with_all(|l| l.total())
}

struct Out<'a> {
    buf: &'a mut [u8; 128],
    n: usize,
}

impl Out<'_> {
    fn s(&mut self, s: &[u8]) -> &mut Self {
        let end = (self.n + s.len()).min(self.buf.len());
        self.buf[self.n..end].copy_from_slice(&s[..end - self.n]);
        self.n = end;
        self
    }
    /// `v` in units of `unit` bytes, rounded up, so a size just over a cap
    /// does not read as equal to it.
    fn num(&mut self, v: usize, unit: usize) -> &mut Self {
        let (mut v, mut digits, mut d) = (v.div_ceil(unit), [0u8; 20], 20);
        loop {
            d -= 1;
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.s(&digits[d..])
    }
}

/// "ampr-emu-ng: index needs 81 MiB, over the 80 MiB cap; packed files
/// not served"; its length.
fn index_cap_notice(needed: usize, buf: &mut [u8; 128]) -> usize {
    let mut o = Out { buf, n: 0 };
    o.s(b"ampr-emu-ng: index needs ").num(needed, MIB);
    o.s(b" MiB, over the ").num(INDEX_MEMORY_MAX, MIB);
    o.s(b" MiB cap; packed files not served").n
}

/// "ampr-emu-ng: cache memory refused, 64 MiB; running without it".
fn ledger_refused_notice(kind: Kind, bytes: usize, buf: &mut [u8; 128]) -> usize {
    let mut o = Out { buf, n: 0 };
    o.s(b"ampr-emu-ng: ").s(kind.name()).s(b" memory refused, ");
    o.num(bytes, MIB).s(b" MiB; running without it").n
}

// ---- public API ---------------------------------------------------------------

/// `bytes` of index memory aligned to `align` (at most a page), page-rounded,
/// from the pool under the index cap, for a real index load: the pack index
/// and its tables, the file index and its build buffers. Null when refused:
/// the caller degrades (the pack index or file index stays unavailable, a
/// build buffer fails the build) after the one-time index notice.
pub(crate) unsafe fn index_alloc(bytes: usize, align: usize, tag: *const c_char) -> *mut u8 {
    unsafe { index_alloc_with(bytes, align, tag, true) }
}

/// `index_alloc` for a transient buffer sized by the title (debug
/// /bench), freed with `index_free` after
/// use. A refusal is only counted (`ledger_alloc_refused`), no notice: the
/// caller skips its work and the packs stay served.
#[cfg(any(test, feature = "mem_report"))]
pub(crate) unsafe fn index_scratch_alloc(
    bytes: usize,
    align: usize,
    tag: *const c_char,
) -> *mut u8 {
    unsafe { index_alloc_with(bytes, align, tag, false) }
}

unsafe fn index_alloc_with(
    bytes: usize,
    align: usize,
    tag: *const c_char,
    notice: bool,
) -> *mut u8 {
    if bytes == 0 || bytes > usize::MAX - SCE_KERNEL_PAGE_SIZE || align > SCE_KERNEL_PAGE_SIZE {
        return null_mut();
    }
    unsafe { alloc_kind(Kind::Index, page_round(bytes), tag, notice) }.unwrap_or(null_mut())
}

/// Frees an `index_alloc` result (null is a no-op).
pub(crate) unsafe fn index_free(ptr: *mut c_void, tag: *const c_char) {
    unsafe { free_kind(Kind::Index, ptr, tag) }
}

/// Index bytes not yet taken under the cap.
pub(crate) fn index_room() -> usize {
    with_kind(Kind::Index, |l| l.cap - l.used)
}

/// An index refused before any allocation, because its tables do not
/// fit: the one index notice, with the `needed` bytes against the whole
/// cap.
pub(crate) unsafe fn index_refused(needed: usize) {
    let used = with_kind(Kind::Index, |l| l.used);
    unsafe { refused(Kind::Index, Refusal::LedgerCap, used + needed, needed, true) };
}

/// Index bytes (/metrics `index_mem_bytes`).
#[cfg(feature = "mem_report")]
pub(crate) fn index_mem_bytes() -> usize {
    with_kind(Kind::Index, |l| l.used)
}

// ---- pack caches ---------------------------------------------------------------

/// `bytes` of cache memory from the pool (page-aligned) under the cache
/// cap, or null when refused; the cache then stays off.
pub(crate) unsafe fn cache_alloc(bytes: usize, tag: *const c_char) -> *mut u8 {
    if bytes == 0 || bytes > usize::MAX - SCE_KERNEL_PAGE_SIZE {
        return null_mut();
    }
    unsafe { alloc_kind(Kind::Cache, page_round(bytes), tag, true) }.unwrap_or(null_mut())
}

/// Cache bytes still free under the cache cap, so a cache target past it
/// can be cut to fit instead of refused.
pub(crate) fn cache_room() -> usize {
    with_kind(Kind::Cache, |l| l.cap - l.used)
}

/// Index room kept when the rest moves to the cache: for any later Index
/// allocation (debug /bench) and the holes the build left in the pool.
pub(crate) const INDEX_KEPT_ROOM: usize = 4 * MIB;

/// Once the index is finished (rt/pack/manifest.rs `grow_cache_from_index`):
/// moves the Index cap's unused room above INDEX_KEPT_ROOM to the Cache cap,
/// in whole `page`s, and returns the bytes moved. The caps' sum stays the
/// same, so the pool still holds every ledger. Nothing allocates from the
/// Index ledger after startup but the debug /bench buffer.
pub(crate) fn move_index_room_to_cache(page: usize) -> usize {
    with_all(|l| l.move_index_room(page))
}

/// Debug /metrics: the Index and Cache caps now, after any room moved.
#[cfg(feature = "mem_report")]
pub(crate) fn live_caps() -> (usize, usize) {
    with_all(|l| (l.index.cap, l.cache.cap))
}

/// Gives `bytes` of unused Cache cap back to the Index cap: the part of a
/// move the cache could not take in one block.
pub(crate) fn return_cache_room_to_index(bytes: usize) {
    with_all(|l| l.return_cache_room(bytes))
}

/// Frees a `cache_alloc` result (null is a no-op).
pub(crate) unsafe fn cache_free(ptr: *mut c_void, tag: *const c_char) {
    unsafe { free_kind(Kind::Cache, ptr, tag) }
}

/// Cache bytes (/metrics `cache_mem_bytes`).
#[cfg(feature = "mem_report")]
pub(crate) fn cache_mem_bytes() -> usize {
    with_kind(Kind::Cache, |l| l.used)
}

// ---- pack buffers --------------------------------------------------------------

/// A pipeline I/O window, worker decode buffer or zstd decoder workspace of
/// `bytes` from the pool under the buffer cap, page-aligned. Returns the
/// block and its usable size, (null, 0) when refused. Called at the worker
/// start (decode buffers, then I/O windows; both kept until shutdown), at a zstd
/// worker's start (its decoder, freed when it leaves).
pub(crate) unsafe fn buffer_alloc(bytes: usize, tag: *const c_char) -> (*mut u8, usize) {
    if bytes == 0 || bytes > usize::MAX - SCE_KERNEL_PAGE_SIZE {
        return (null_mut(), 0);
    }
    let mapped = page_round(bytes);
    match unsafe { alloc_kind(Kind::Buffer, mapped, tag, true) } {
        Some(p) => (p, mapped),
        None => (null_mut(), 0),
    }
}

/// Frees a `buffer_alloc` result (null is a no-op).
pub(crate) unsafe fn buffer_free(ptr: *mut c_void, tag: *const c_char) {
    unsafe { free_kind(Kind::Buffer, ptr, tag) }
}

/// Buffer bytes not yet taken under the cap, so the worker start can size
/// its pipelines to windows that will be granted.
pub(crate) fn buffer_room() -> usize {
    with_kind(Kind::Buffer, |l| l.cap - l.used)
}

/// Buffer bytes (/metrics `buffer_mem_bytes`).
#[cfg(feature = "mem_report")]
pub(crate) fn buffer_mem_bytes() -> usize {
    with_kind(Kind::Buffer, |l| l.used)
}

// ---- test helpers ----------------------------------------------------------

/// Serializes host tests that fill the shared pool and ledgers.
#[cfg(test)]
pub(crate) static POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Index bytes in use (host tests).
#[cfg(test)]
pub(crate) fn test_index_used() -> usize {
    with_kind(Kind::Index, |l| l.used)
}

/// Re-arms the one-time index notice; true when it had been sent since the
/// last call (host tests).
#[cfg(test)]
pub(crate) fn test_take_index_notice() -> bool {
    INDEX_NOTICED.swap(false, Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rt::runtime_memory::{POOL_SITES_BUDGET, POOL_SITES_MAX, STATIC_POOL_SIZE};

    #[test]
    fn cap_holds_and_claims_come_back() {
        let mut l = Ledger::new(64 << 10, INDEX_BLOCKS);
        let a = l.reserve(32 << 10).unwrap();
        l.fill(a, 0x10000);
        let b = l.reserve(16 << 10).unwrap();
        l.fill(b, 0x20000);
        assert_eq!(l.used, 48 << 10);
        assert_eq!(l.reserve(32 << 10), Err(Refusal::LedgerCap));
        assert_eq!(l.take(0x10000).map(|b| b.mapped), Some(32 << 10));
        assert_eq!(l.used, 16 << 10);
        assert!(l.take(0x10000).is_none());
        // A failed pool allocation gives its claim back.
        let c = l.reserve(48 << 10).unwrap();
        l.cancel(c);
        assert_eq!(l.used, 16 << 10);
        assert!(l.reserve(48 << 10).is_ok());
        assert_eq!(l.reserve(1), Err(Refusal::LedgerCap));
    }

    #[test]
    fn caps_and_sites_fit_the_pool() {
        assert_eq!(INDEX_MEMORY_MAX, 80 << 20);
        assert_eq!(BUFFER_DECODERS, 4);
        assert_eq!(BUFFER_MEMORY_MAX, ((4 + 12 * 2) << 20) + 4 * (112 << 10));
        assert_eq!(STACK_MEMORY_MAX, 2 << 20);
        // Host tests build with the debug pool, the smaller of the two.
        assert_eq!(
            STATIC_POOL_SIZE,
            crate::rt::runtime_memory::DEFAULT_POOL_SIZE
        );
        // The ledgers, sites and stacks leave less than one cache page.
        let all = LEDGER_MEMORY_MAX + POOL_SITES_BUDGET + STACK_MEMORY_MAX;
        assert!(all <= STATIC_POOL_SIZE);
        assert!(STATIC_POOL_SIZE - all < crate::rt::pack::PACK_CACHE_PAGE_BYTES);
        assert!(POOL_SITES_MAX <= POOL_SITES_BUDGET);
        // Every ledger full stops at its own cap.
        let mut l = Ledgers::new();
        for kind in Kind::ALL {
            let cap = l.get(kind).cap;
            l.get(kind).reserve(cap).unwrap();
            assert_eq!(
                l.get(kind).reserve(SCE_KERNEL_PAGE_SIZE),
                Err(Refusal::LedgerCap)
            );
        }
        assert_eq!(l.total(), LEDGER_MEMORY_MAX);
    }

    #[test]
    fn idle_index_room_moves_to_the_cache_and_back() {
        use crate::rt::pack::PACK_CACHE_PAGE_BYTES as PAGE;
        let mut l = Ledgers::new();
        let sum = l.index.cap + l.cache.cap;
        l.index.used = 5 * MIB + 3; // a title's view and pack tables
        let moved = l.move_index_room(PAGE);
        assert_eq!(moved % PAGE, 0);
        assert!(l.index.cap - l.index.used >= INDEX_KEPT_ROOM);
        assert!(l.index.cap - l.index.used < INDEX_KEPT_ROOM + PAGE);
        assert_eq!(l.index.cap + l.cache.cap, sum);
        // What the cache could not take goes back; never more than it has free.
        l.cache.used = CACHE_MEMORY_MAX + moved / 2;
        l.return_cache_room(moved);
        assert_eq!(l.cache.cap, l.cache.used);
        assert_eq!(l.index.cap + l.cache.cap, sum);
        // A full Index ledger moves nothing.
        let mut full = Ledgers::new();
        full.index.used = INDEX_MEMORY_MAX - MIB;
        assert_eq!(full.move_index_room(PAGE), 0);
    }

    #[test]
    fn cache_is_the_pool_remainder() {
        use crate::rt::pack::PACK_CACHE_PAGE_BYTES as PAGE;
        let fixed = INDEX_MEMORY_MAX + BUFFER_MEMORY_MAX + POOL_SITES_BUDGET + STACK_MEMORY_MAX;
        assert_eq!(CACHE_MEMORY_MAX, (STATIC_POOL_SIZE - fixed) / PAGE * PAGE);
        assert_eq!(CACHE_MEMORY_MAX % PAGE, 0);
        // The debug pool of the 256 MiB layout, 0xf614000 (246.07 MiB):
        // 80 + 28.44 + 2 + 2 MiB fixed, the cache 133.64 MiB.
        assert_eq!(STATIC_POOL_SIZE, 0xf61_4000);
        assert_eq!(CACHE_MEMORY_MAX, 0xf61_4000 - fixed);
        assert_eq!(CACHE_MEMORY_MAX, 140_132_352);
    }

    #[test]
    fn cache_cap_holds_the_default_cache() {
        use crate::rt::pack::AMPR_EMU_PACK_DECODED_CACHE_BYTES as DECODED;
        assert_eq!(DECODED as usize, CACHE_MEMORY_MAX);
        let mut l = Ledgers::new();
        let d = l.cache.reserve(DECODED as usize).unwrap();
        l.cache.fill(d, 0x4000_0000);
        assert_eq!(l.cache.used, CACHE_MEMORY_MAX);
        assert_eq!(
            l.cache.reserve(SCE_KERNEL_PAGE_SIZE),
            Err(Refusal::LedgerCap)
        );
        l.cache.take(0x4000_0000).unwrap();
        assert_eq!(l.cache.used, 0);
    }

    #[test]
    fn buffer_cap_holds_default_windows_and_decode_buffers() {
        use crate::rt::pack::{PACK_MAX_BLOCK_BYTES, PACK_PIPELINE_IO_BYTES};
        assert_eq!(
            (PACK_PIPELINE_IO_BYTES, PACK_MAX_BLOCK_BYTES),
            (2 << 20, 1 << 20)
        );
        assert_eq!(page_round(PACK_PIPELINE_IO_BYTES), PACK_PIPELINE_IO_BYTES);
        // Host tests build with the default knobs.
        assert_eq!((BUFFER_WORKERS, BUFFER_PIPELINES), (4, 12));
        let mut l = Ledgers::new();
        // Decode buffers are taken at the worker start, before the windows; a zstd
        // worker takes its decoder workspace when it starts.
        for i in 0..BUFFER_WORKERS {
            let b = l.buffer.reserve(PACK_MAX_BLOCK_BYTES).unwrap();
            l.buffer.fill(b, 0x8000_0000 + i * PACK_MAX_BLOCK_BYTES);
            let d = l
                .buffer
                .reserve(ampr_codec::ZSTD_DECODER_WORKSPACE)
                .unwrap();
            l.buffer
                .fill(d, 0x9000_0000 + i * ampr_codec::ZSTD_DECODER_WORKSPACE);
        }
        for i in 0..BUFFER_PIPELINES {
            let b = l.buffer.reserve(PACK_PIPELINE_IO_BYTES).unwrap();
            l.buffer.fill(b, 0x1000_0000 + i * PACK_PIPELINE_IO_BYTES);
        }
        assert_eq!(l.buffer.used, BUFFER_MEMORY_MAX);
        // A 13th window (debug `pipelines` knob) is refused.
        assert_eq!(
            l.buffer.reserve(PACK_PIPELINE_IO_BYTES),
            Err(Refusal::LedgerCap)
        );
        assert_eq!(
            l.buffer.take(0x1000_0000).unwrap().mapped,
            PACK_PIPELINE_IO_BYTES
        );
        assert!(l.buffer.reserve(PACK_PIPELINE_IO_BYTES).is_ok());
    }

    /// The startup carve through the real pool (host: no mprotect), then
    /// every ledger filled to its cap at once: all of it fits the pool.
    #[test]
    fn caches_carve_at_startup_and_every_ledger_fits_the_pool() {
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::rt::pack::{
            initialize_caches, PackState, PACK_MAX_BLOCK_BYTES, PACK_PIPELINE_IO_BYTES,
        };
        let layout = std::alloc::Layout::new::<PackState>();
        let state = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<PackState>();
        assert!(!state.is_null());
        unsafe {
            (*state).decoded_cache_target_bytes = CACHE_MEMORY_MAX as _;
            initialize_caches(state);
            assert_eq!((*state).cache_bytes as usize, CACHE_MEMORY_MAX);
            assert!(!(*state).cache_base.is_null());
        }
        assert_eq!(cache_room(), 0);
        let index = unsafe { index_alloc(INDEX_MEMORY_MAX, 16, c"test.index".as_ptr()) };
        assert!(!index.is_null());
        // A transient buffer past the cap is counted, without the notice.
        INDEX_NOTICED.store(false, Relaxed);
        let refused = LEDGER_ALLOC_REFUSED.load(Relaxed);
        let scratch =
            unsafe { index_scratch_alloc(SCE_KERNEL_PAGE_SIZE, 16, c"test.scratch".as_ptr()) };
        assert!(scratch.is_null());
        assert_eq!(LEDGER_ALLOC_REFUSED.load(Relaxed), refused + 1);
        assert!(!INDEX_NOTICED.load(Relaxed));
        // Past the index cap: refused before the pool is asked, counted.
        let refused = LEDGER_ALLOC_REFUSED.load(Relaxed);
        let more = unsafe { index_alloc(SCE_KERNEL_PAGE_SIZE, 16, c"test.index".as_ptr()) };
        assert!(more.is_null());
        assert_eq!(LEDGER_ALLOC_REFUSED.load(Relaxed), refused + 1);
        assert!(INDEX_NOTICED.load(Relaxed));
        let mut buffers = Vec::new();
        for _ in 0..BUFFER_WORKERS {
            buffers.push(unsafe { buffer_alloc(PACK_MAX_BLOCK_BYTES, c"test.decode".as_ptr()) });
            buffers.push(unsafe {
                buffer_alloc(ampr_codec::ZSTD_DECODER_WORKSPACE, c"test.decoder".as_ptr())
            });
        }
        for _ in 0..BUFFER_PIPELINES {
            buffers.push(unsafe { buffer_alloc(PACK_PIPELINE_IO_BYTES, c"test.window".as_ptr()) });
        }
        assert!(buffers.iter().all(|b| !b.0.is_null()));
        let (used, _, size) = crate::rt::runtime_memory::pool_usage();
        assert_eq!((used, size), (LEDGER_MEMORY_MAX, STATIC_POOL_SIZE));
        assert_eq!(with_all(|l| l.total()), LEDGER_MEMORY_MAX);
        unsafe {
            for (p, _) in buffers {
                buffer_free(p.cast(), c"test.buffer.free".as_ptr());
            }
            index_free(index.cast(), c"test.index.free".as_ptr());
            cache_free((*state).cache_base.cast(), c"test.cache.free".as_ptr());
            std::alloc::dealloc(state.cast(), layout);
        }
        assert_eq!(with_all(|l| l.total()), 0);
        assert_eq!(crate::rt::runtime_memory::pool_usage().0, 0);
    }

    #[test]
    fn slots_run_out_before_the_cap() {
        let mut l = Ledger::new(usize::MAX, INDEX_BLOCKS);
        for _ in 0..INDEX_BLOCKS {
            assert!(l.reserve(1).is_ok());
        }
        assert_eq!(l.reserve(1), Err(Refusal::NoSlot));
        // Pending claims are not live allocations.
        assert!(l.take(PENDING).is_none());
    }

    // ---- index size per file -------------------------------------------------

    use crate::rt::index::{fill_image, image_layout, resident_bytes};

    /// `n` synthetic records and their paths, 48 bytes each with the NUL.
    fn synthetic(n: usize) -> (Vec<u8>, Vec<u8>) {
        let (mut records, mut paths) = (Vec::with_capacity(n * 24), Vec::new());
        for i in 0..n {
            let p = format!("/app0/paks/dir{:05}/asset_{:014}.uasset", i / 500, i);
            assert_eq!(p.len() + 1, 48);
            records.extend_from_slice(&(paths.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&(i as u64 * 4096).to_le_bytes());
            records.extend_from_slice(&0i64.to_le_bytes());
            paths.extend_from_slice(p.as_bytes());
            paths.push(0);
        }
        (records, paths)
    }

    /// Resident index memory for `n` files of 48-byte paths, by layout.
    fn resident_for(n: usize) -> usize {
        let l = image_layout(n, n as u64 * 48).unwrap();
        page_round(l.file_bytes - ampr_format::IDX_HEADER)
    }

    #[test]
    fn index_memory_per_file_for_10k_100k_1m_files() {
        const GUARD: usize = 4096;
        for n in [10_000usize, 100_000, 1_000_000] {
            let (records, paths) = synthetic(n);
            let l = image_layout(n, paths.len() as u64).unwrap();
            // The walk build's image buffer, with a guard after it.
            let mut buf = vec![0xA5u8; l.map_bytes + GUARD];
            let (image, guard) = buf.split_at_mut(l.map_bytes);
            // A buffer one byte short is refused with nothing written.
            assert!(!fill_image(
                &mut image[..l.map_bytes - 1],
                &l,
                &records,
                &paths
            ));
            assert!(image.iter().all(|&b| b == 0xA5));
            assert!(fill_image(image, &l, &records, &paths));
            assert!(guard.iter().all(|&b| b == 0xA5), "write past the buffer");
            // What it costs fully resident, through the format's own header
            // check and the runtime's sizing.
            let header = &image[..ampr_format::IDX_HEADER];
            let parsed = ampr_format::index::Layout::parse(header).unwrap();
            let resident = resident_bytes(&parsed);
            assert_eq!(resident, resident_for(n));
            let index = ampr_format::index::Index::open(&image[..l.file_bytes]).unwrap();
            assert_eq!(index.len() as usize, n);
            // The walk build holds records and paths (doubled capacities)
            // and the image at once.
            let records_cap = (n.max(4096)).next_power_of_two() * 24;
            let paths_cap = paths.len().max(1 << 20).next_power_of_two();
            let build_peak = records_cap + paths_cap + l.map_bytes;
            let mut ledgers = Ledgers::new();
            let fits = ledgers.index.reserve(page_round(resident));
            assert_eq!(fits.is_ok(), resident <= INDEX_MEMORY_MAX);
            eprintln!(
                "index {n} files: {} B/file resident ({:.1} MiB), build peak {:.1} MiB, \
                 under the {} MiB cap: {}",
                resident / n,
                resident as f64 / MIB as f64,
                build_peak as f64 / MIB as f64,
                INDEX_MEMORY_MAX / MIB,
                fits.is_ok()
            );
        }
        // 10k and 100k fit; 1M (about 101 MiB) is refused, not written.
        assert!(resident_for(100_000) <= INDEX_MEMORY_MAX);
        assert!(resident_for(1_000_000) > INDEX_MEMORY_MAX);
        let mut ledgers = Ledgers::new();
        assert_eq!(
            ledgers.index.reserve(page_round(resident_for(1_000_000))),
            Err(Refusal::LedgerCap)
        );
        assert_eq!(ledgers.total(), 0);
    }

    #[test]
    fn files_the_index_cap_covers() {
        let (mut lo, mut hi) = (1usize, 4_000_000usize);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if resident_for(mid) <= INDEX_MEMORY_MAX {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        eprintln!(
            "index cap {} MiB covers {lo} files of 48-byte paths ({} B/file)",
            INDEX_MEMORY_MAX / MIB,
            resident_for(lo) / lo
        );
        // 104-120 B/file at 48-byte paths; past 2^19 records the hash
        // table doubles, and the cap ends inside that step.
        assert_eq!(lo, 699_050);
        assert!(resident_for(lo + 1) > INDEX_MEMORY_MAX);
    }

    /// The notice names the size needed, rounded up, against the cap.
    #[test]
    fn index_notice_reports_the_cap() {
        let mut buf = [0u8; 128];
        let n = index_cap_notice(INDEX_MEMORY_MAX + MIB, &mut buf);
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            "ampr-emu-ng: index needs 81 MiB, over the 80 MiB cap; packed files not served"
        );
    }
}
