//! Runtime memory that grows with the title, and the pack caches and
//! buffers, carved from the PRX's static pool (rt/runtime_memory.rs) under
//! three ledgers with hard caps: Index (index files read whole, the index
//! page arena, the lookup tables and every build buffer sized by file
//! count, path bytes or file size), Cache (the
//! two pack caches) and Buffer (the pipeline I/O windows and worker decode
//! buffers). The caps plus the fixed pool sites fit the pool (checked at
//! build time), so no ledger can take another's room and no reserve is
//! needed. Never direct or flexible memory: the pool is PRX .bss and did not
//! lower the game's free direct memory, while our direct allocations did (a
//! title had 42 MiB of direct memory free during play), and flexible memory
//! had 0-28 MiB free in another title (debug /metrics `flex_*` and the
//! former direct memory lines).
//!
//! A refused allocation degrades: an index that does not fit leaves the
//! packs unserved (packed files read as missing, ENOENT) after one console
//! notice naming the size and the cap; a refused cache stays off; a refused
//! I/O window takes the slow path (page_plan.rs); a refused save icon is
//! skipped (pack/mmap.rs).

use super::runtime_memory::{ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_free};
use super::sync::{SpinLock, SyncCell};
use super::sys::*;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};

const MIB: usize = 1 << 20;

/// Cap on index memory, all index allocations together: index files
/// read whole (an index that fits is used as is, no page cache), the
/// lookup tables, the page arena for the index files read in pages
/// (rt/index_pages.rs), the page tables and the transient buffers (walk
/// build, save icon, decode-on-access slots). A walk-built AMPRIDX3 is
/// built whole first, at 104-124 bytes per file at 48-byte paths (a
/// 24-byte record, the path, 16-32 bytes of hash slots; tests below), so
/// a build image of 524,288 files fits (`files_the_index_cap_covers`).
/// 64 MiB: 9 MiB more than v0.3.5's 55 MiB, taken by a larger PRX (Makefile
/// `AMPR_INTERNAL_POOL_SIZE`), not from another ledger.
pub(crate) const INDEX_MEMORY_MAX: usize = 64 * MIB;

/// Lookup tables at most, inside the cap: the fast tables of paged index
/// files (zstd 16 B per file, 8 B per chunk and volume) and the tables derived
/// from the indexes (zstd projection 16 B per AMPRIDX3 id and order 4 B
/// per packed file). About 17.6 MiB at 300k files and 100 GB.
pub(crate) const INDEX_LOOKUP_MAX: usize = 48 * MIB;

/// Page arena at least, once any index file is paged: half of a ~32 MiB
/// paged index stays resident. The arena takes this floor when the first
/// paged file registers and the room the tables left when the mounts are
/// done (rt/index_pages.rs `grow_arena`).
pub(crate) const INDEX_ARENA_MIN: usize = 16 * MIB;
const _: () = assert!(INDEX_LOOKUP_MAX + INDEX_ARENA_MIN == INDEX_MEMORY_MAX);

/// Cap on cache memory: the 16 + 16 MiB cache defaults (rt/pack/mod.rs).
/// A runtime profile or debug knob asking more gets what is left under the
/// cap (pack/manifest.rs `cache_region`).
pub(crate) const CACHE_MEMORY_MAX: usize = 32 * MIB;

/// Cap on buffer memory: a 1 MiB decode buffer and a 112 KiB zstd decoder
/// workspace for each build worker (Makefile `AMPR_PACK_WORKERS`, default
/// 4), a 2 MiB I/O window for each build pipeline (`AMPR_PACK_PIPELINES`,
/// default 12) and, with `AMPR_ZSTD_MMAP=1`, a decoder workspace per
/// decode-on-access slot: 28.44 MiB at the defaults (rt/pack/mod.rs).
/// Buffers past it are refused: a worker without one does not start, a
/// pipeline without a window reads the slow way.
pub(crate) const BUFFER_MEMORY_MAX: usize = BUFFER_WORKERS * crate::rt::pack::PACK_MAX_BLOCK_BYTES
    + BUFFER_PIPELINES * crate::rt::pack::PACK_PIPELINE_IO_BYTES
    + BUFFER_DECODERS * ampr_codec::ZSTD_DECODER_WORKSPACE;
const BUFFER_WORKERS: usize = crate::rt::pack::AMPR_EMU_PACK_WORKERS as usize;
const BUFFER_PIPELINES: usize = crate::rt::tune::RELEASE_PIPELINES as usize;
/// zstd decoder workspaces: one per build worker and per decode-on-access
/// slot (rt/pack/mmap_fault.rs).
const BUFFER_DECODERS: usize = BUFFER_WORKERS + BUFFER_MMAP_SLOTS;
const BUFFER_MMAP_SLOTS: usize = if crate::rt::pack::mmap::MMAP_MODE == 1 {
    crate::rt::pack::mmap_fault::SLOTS
} else {
    0
};
// A workspace is whole pages, so the ledger counts it at its size.
const _: () = assert!(ampr_codec::ZSTD_DECODER_WORKSPACE % SCE_KERNEL_PAGE_SIZE == 0);

/// The three caps together, 124.44 MiB at the default knobs; the pool also
/// holds the 2 MiB fixed sites budget (rt/runtime_memory.rs
/// `POOL_SITES_BUDGET`). A knob that grows a cap past the pool fails the
/// build here instead of refusing buffers at run time.
pub(crate) const LEDGER_MEMORY_MAX: usize = INDEX_MEMORY_MAX + CACHE_MEMORY_MAX + BUFFER_MEMORY_MAX;
const _: () = assert!(
    LEDGER_MEMORY_MAX + super::runtime_memory::POOL_SITES_BUDGET
        <= super::runtime_memory::STATIC_POOL_SIZE,
    "AMPR_INTERNAL_POOL_SIZE / AMPR_DEBUG_POOL_SIZE below the ledger caps plus the 2 MiB sites budget"
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
/// Index blocks live at once, at most: four resident (pack index image,
/// LZ4 directory order or zstd projection and its order, the compact file
/// index), the walk build's records, paths and directory stack (two of
/// each while one doubles), its getdents buffer over `DENTS_POOL_MAX` and
/// its image, the save icon buffer, the decode-on-access scratch and the
/// debug /bench buffer: 16. The page cache (rt/index_pages.rs) adds its
/// arena and one page table per registered source (4 at most): 21.
const INDEX_BLOCKS: usize = 21;
/// The two caches.
const CACHE_BLOCKS: usize = 2;
/// One per pipeline window, per worker decode buffer and decoder workspace,
/// and one for the decode-on-access decoder workspaces.
const BUFFER_BLOCKS: usize = crate::rt::pack::AMPR_EMU_PACK_PIPELINE_SLOTS
    + 2 * crate::rt::pack::AMPR_EMU_PACK_WORKER_CAPACITY
    + (BUFFER_MMAP_SLOTS != 0) as usize;
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
/// Page arena bytes taken (rt/index_pages.rs, `note_arena`): the index
/// notice then reports the tables against the room left beside it.
static ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);
/// Lookup table bytes in use (`lookup_alloc`), at most `INDEX_LOOKUP_MAX`.
static LOOKUP_USED: AtomicUsize = AtomicUsize::new(0);

/// Counts a refusal and, when `notice`, sends at most one notice per
/// process for each class: the index cap (with the size it needed; with
/// the arena taken, the tables against the room left beside it), any
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
        let arena = ARENA_BYTES.load(Relaxed);
        index_cap_notice(
            needed.saturating_sub(arena),
            INDEX_MEMORY_MAX - arena,
            arena != 0,
            &mut text,
        )
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

/// "ampr-emu-ng: index tables need 49 MiB, over the 48 MiB beside the page
/// cache; packed files not served" once the page cache arena is taken
/// (`tables`), else "ampr-emu-ng: index needs 65 MiB, over the 64 MiB cap;
/// packed files not served"; its length.
fn index_cap_notice(needed: usize, room: usize, tables: bool, buf: &mut [u8; 128]) -> usize {
    let mut o = Out { buf, n: 0 };
    if tables {
        o.s(b"ampr-emu-ng: index tables need ").num(needed, MIB);
        o.s(b" MiB, over the ").num(room, MIB);
        o.s(b" MiB beside the page cache; packed files not served")
            .n
    } else {
        o.s(b"ampr-emu-ng: index needs ").num(needed, MIB);
        o.s(b" MiB, over the ").num(room, MIB);
        o.s(b" MiB cap; packed files not served").n
    }
}

/// "ampr-emu-ng: cache memory refused, 32 MiB; running without it".
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

/// `index_alloc` for a transient buffer sized by the title (save icon,
/// decode-on-access slots, debug /bench), freed with `index_free` after
/// use. A refusal is only counted (`ledger_alloc_refused`), no notice: the
/// caller skips its work and the packs stay served.
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

/// rt/index_pages.rs: `bytes` more (or, negative, fewer) of page arena.
pub(crate) fn note_arena(bytes: isize) {
    if bytes >= 0 {
        ARENA_BYTES.fetch_add(bytes as usize, Relaxed);
    } else {
        ARENA_BYTES.fetch_sub(bytes.unsigned_abs(), Relaxed);
    }
}

/// An index refused before any allocation, because its tables, its image
/// or the arena floor do not fit: the one index notice, with the `needed`
/// bytes against the whole cap.
pub(crate) unsafe fn index_refused(needed: usize) {
    let used = with_kind(Kind::Index, |l| l.used);
    unsafe { refused(Kind::Index, Refusal::LedgerCap, used + needed, needed, true) };
}

/// `index_alloc` for a lookup table (a fast table, a projection, an
/// order): also refused, with the index notice, past `INDEX_LOOKUP_MAX`.
/// Freed with `lookup_free` and the same `bytes`.
pub(crate) unsafe fn lookup_alloc(bytes: usize, align: usize, tag: *const c_char) -> *mut u8 {
    let mapped = page_round(bytes);
    let used = LOOKUP_USED.fetch_add(mapped, Relaxed);
    if used + mapped > INDEX_LOOKUP_MAX {
        LOOKUP_USED.fetch_sub(mapped, Relaxed);
        unsafe { index_refused(mapped) };
        return null_mut();
    }
    let p = unsafe { index_alloc(bytes, align, tag) };
    if p.is_null() {
        LOOKUP_USED.fetch_sub(mapped, Relaxed);
    }
    p
}

/// Frees a `lookup_alloc` result of `bytes` (null is a no-op).
pub(crate) unsafe fn lookup_free(ptr: *mut c_void, bytes: usize, tag: *const c_char) {
    if !ptr.is_null() {
        LOOKUP_USED.fetch_sub(page_round(bytes), Relaxed);
        unsafe { index_free(ptr, tag) };
    }
}

/// Lookup table bytes in use (`lookup_alloc`).
pub(crate) fn lookup_used() -> usize {
    LOOKUP_USED.load(Relaxed)
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
/// block and its usable size, (null, 0) when refused. Called at pack
/// prepare (decode buffers, so they come before any window), on a
/// pipeline's first use (I/O windows; both kept until shutdown), at a zstd
/// worker's start (its decoder, freed when it leaves) and on the first
/// decode-on-access map (slot decoders, kept).
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
        assert_eq!(INDEX_MEMORY_MAX, 64 << 20);
        assert_eq!(CACHE_MEMORY_MAX, 32 << 20);
        assert_eq!(BUFFER_DECODERS, 4);
        assert_eq!(BUFFER_MEMORY_MAX, ((4 + 12 * 2) << 20) + 4 * (112 << 10));
        assert_eq!(LEDGER_MEMORY_MAX, (124 << 20) + (448 << 10));
        // Host tests build with the debug pool, the smaller of the two.
        assert_eq!(
            STATIC_POOL_SIZE,
            crate::rt::runtime_memory::DEFAULT_POOL_SIZE
        );
        assert!(LEDGER_MEMORY_MAX + POOL_SITES_BUDGET <= STATIC_POOL_SIZE);
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
    fn cache_cap_holds_the_default_caches() {
        use crate::rt::pack::{
            AMPR_EMU_PACK_DECODED_CACHE_BYTES as DECODED,
            AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES as PHYSICAL,
        };
        assert_eq!((DECODED + PHYSICAL) as usize, CACHE_MEMORY_MAX);
        let mut l = Ledgers::new();
        let p = l.cache.reserve(PHYSICAL as usize).unwrap();
        l.cache.fill(p, 0x1000_0000);
        let d = l.cache.reserve(DECODED as usize).unwrap();
        l.cache.fill(d, 0x4000_0000);
        assert_eq!(l.cache.used, CACHE_MEMORY_MAX);
        assert_eq!(
            l.cache.reserve(SCE_KERNEL_PAGE_SIZE),
            Err(Refusal::LedgerCap)
        );
        l.cache.take(0x4000_0000).unwrap();
        l.cache.take(0x1000_0000).unwrap();
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
        // Decode buffers are taken at prepare, before any window; a zstd
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
        // A 13th window (debug `pipelines` knob) is refused: slow path.
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
            (*state).physical_cache_target_bytes = 16 << 20;
            (*state).decoded_cache_target_bytes = 16 << 20;
            initialize_caches(state);
            assert_eq!((*state).physical_cache_bytes, 16 << 20);
            assert_eq!((*state).cache_bytes, 16 << 20);
            assert!(!(*state).physical_cache_base.is_null() && !(*state).cache_base.is_null());
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
            cache_free(
                (*state).physical_cache_base.cast(),
                c"test.cache.free".as_ptr(),
            );
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
        // 104 B/file at 48-byte paths up to 2^19 records; the hash table
        // doubles past that, over the cap.
        assert_eq!(lo, 524_288);
        assert!(resident_for(lo + 1) > INDEX_MEMORY_MAX);
    }

    /// With the page cache arena taken the notice names the tables and the
    /// room beside the arena, sizes rounded up; before it, the whole cap.
    #[test]
    fn index_notice_reports_the_table_room() {
        let text = |needed, room, tables| {
            let mut buf = [0u8; 128];
            let n = index_cap_notice(needed, room, tables, &mut buf);
            std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
        };
        assert_eq!(
            text(INDEX_LOOKUP_MAX + 1, INDEX_LOOKUP_MAX, true),
            "ampr-emu-ng: index tables need 49 MiB, over the 48 MiB beside the page \
             cache; packed files not served"
        );
        assert_eq!(
            text(INDEX_MEMORY_MAX + MIB, INDEX_MEMORY_MAX, false),
            "ampr-emu-ng: index needs 65 MiB, over the 64 MiB cap; packed files not served"
        );
    }
}
