//! Page cache for the index files (AMPRPAK4, AMPRZPK1, AMPRIDX3) that do
//! not fit the Index ledger whole (`IndexSource`: a file that fits is read
//! whole and used as is). The readers in ampr-format and ampr-lz4 read a
//! paged file through `PagedSource`, which keeps 16 KiB pages of it in an
//! arena of two segments (Index ledger, rt/index_memory.rs): a 16 MiB
//! floor taken when the first paged file registers, and the room the
//! lookup tables left, added by `grow_arena` once the mounts are done.
//! Pages are evicted by CLOCK and read again from the file on a miss, so
//! an index file needs no size cap of its own. No reader waits on another
//! thread: a page being loaded elsewhere, or a miss with no evictable
//! slot, is read from the file into the caller's buffer. Counters on the
//! debug /metrics page (`index_page_*`, `index_arena_bytes`, rt/stats.rs).

use super::index_memory::{
    index_alloc, index_free, index_refused, index_room, note_arena, INDEX_ARENA_MIN,
    INDEX_MEMORY_MAX,
};
use super::stats::{self, Stat};
use super::sync::SyncCell;
use ampr_format::source::Source;
use ampr_format::{Error, Result};
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr::null_mut;

/// Page size: a whole 4 KiB CRC step and several records per page, and
/// small enough that the 16 MiB floor holds 1022 of them.
pub(crate) const PAGE: usize = 16 << 10;
/// Registered sources at most: the pack index, the file index, and room
/// for a remount.
const SOURCES: usize = 4;
/// Page table entry of a page that is not resident.
const ABSENT: u16 = u16::MAX;
/// `Slot::src` of a slot that holds no page.
const FREE: u8 = u8::MAX;
/// CLOCK reference bit: set on every hit, cleared as the hand passes.
const REF: u8 = 1;
/// The page is being read; its slot is neither copied from nor evicted.
const LOADING: u8 = 2;
/// Set with LOADING by `unregister`: the source went away while its page
/// was read. The slot stays out of the CLOCK until the loader frees it.
const DROPPED: u8 = 4;
/// Slot table bytes: a slot for every page of the whole Index cap.
const SLOT_TABLE: usize = (INDEX_MEMORY_MAX / PAGE * size_of::<Slot>()).div_ceil(PAGE) * PAGE;
/// Index room `grow_arena` leaves for the transient buffers: a save icon
/// of up to 2 MiB (rt/pack/mmap.rs) and, with `AMPR_ZSTD_MMAP=1`, the
/// 2 MiB of decode-on-access slots (rt/pack/mmap_fault.rs).
const TRANSIENT_ROOM: usize = (2 << 20)
    + if super::pack::mmap::MMAP_MODE == 1 {
        2 << 20
    } else {
        0
    };

// ---- lock seam ----

#[cfg(not(test))]
mod lock {
    use super::super::sync::{Mutex, MutexGuard};

    /// One lock over the cache's tables, held only for table updates and
    /// page copies: no reader waits on another thread's load. If
    /// contention shows in /metrics, split per source.
    pub(super) struct Lock {
        m: Mutex,
    }
    pub(super) type Guard<'a> = MutexGuard<'a>;

    impl Lock {
        pub(super) const fn new() -> Self {
            Self { m: Mutex::new() }
        }
        pub(super) fn lock(&self) -> Guard<'_> {
            self.m.lock()
        }
    }
}

/// Host tests have no scePthread*: the same lock over std.
#[cfg(test)]
mod lock {
    pub(super) struct Lock {
        m: std::sync::Mutex<()>,
    }
    pub(super) type Guard<'a> = std::sync::MutexGuard<'a, ()>;

    impl Lock {
        pub(super) const fn new() -> Self {
            Self {
                m: std::sync::Mutex::new(()),
            }
        }
        pub(super) fn lock(&self) -> Guard<'_> {
            self.m.lock().unwrap()
        }
    }
}

// ---- state ----

/// One arena page: which source page it holds and its CLOCK state.
#[derive(Clone, Copy)]
#[repr(C)]
struct Slot {
    src: u8,
    flags: u8,
    page: u32,
}

const SLOT0: Slot = Slot {
    src: FREE,
    flags: 0,
    page: 0,
};

/// Where a source's bytes come from.
#[derive(Clone, Copy)]
enum Backing {
    None,
    /// An index file, read with the raw pread the index loader uses.
    File(c_int),
    /// Host tests: an image in memory, read without pages or the lock.
    #[cfg(test)]
    Memory(*const u8),
    /// Host tests: an in-memory file, false = the read failed.
    #[cfg(test)]
    Test(&'static (dyn Fn(u64, &mut [u8]) -> bool + Sync)),
}

#[derive(Clone, Copy)]
struct Src {
    backing: Backing,
    len: u64,
    /// One arena slot per file page, `ABSENT` when not resident.
    table: *mut u16,
}

impl Backing {
    /// The image of a memory source; None for a paged one.
    fn memory(self) -> Option<*const u8> {
        match self {
            #[cfg(test)]
            Backing::Memory(p) => Some(p),
            _ => None,
        }
    }
}

const SRC0: Src = Src {
    backing: Backing::None,
    len: 0,
    table: null_mut(),
};

struct Cache {
    /// The floor segment's `base_slots` pages; the slot table, sized for
    /// the whole cap, is carved from its start.
    arena: *mut u8,
    base_slots: usize,
    /// The growth segment (`grow_arena`), slots `base_slots..nslots`.
    grown: *mut u8,
    /// The segments came from the Index ledger (`ensure_arena`), so the
    /// last paged source's `unregister` gives them back; host test caches
    /// adopt heap memory and keep it.
    owned: bool,
    slots: *mut Slot,
    nslots: usize,
    hand: usize,
    srcs: [Src; SOURCES],
    nsrcs: usize,
    /// Mirrors of the /metrics counters, for the host tests.
    hits: u64,
    misses: u64,
    evictions: u64,
    resident: u64,
    direct: u64,
}

/// The cache: its lock and the state the lock guards.
pub(crate) struct Pages {
    lock: lock::Lock,
    cache: SyncCell<Cache>,
}

static PAGES: Pages = Pages::new();

impl Pages {
    const fn new() -> Self {
        Self {
            lock: lock::Lock::new(),
            cache: SyncCell::new(Cache {
                arena: null_mut(),
                base_slots: 0,
                grown: null_mut(),
                owned: false,
                slots: null_mut(),
                nslots: 0,
                hand: 0,
                srcs: [SRC0; SOURCES],
                nsrcs: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
                resident: 0,
                direct: 0,
            }),
        }
    }

    /// The state; call with `lock` held.
    #[allow(clippy::mut_from_ref)]
    fn cache(&self, _g: &lock::Guard<'_>) -> &mut Cache {
        unsafe { &mut *self.cache.get() }
    }
}

impl Cache {
    fn slot(&mut self, i: usize) -> &mut Slot {
        unsafe { &mut *self.slots.add(i) }
    }

    fn table(&self, id: usize) -> *mut u16 {
        self.srcs[id].table
    }

    /// Start of slot `i`'s page.
    fn page_ptr(&self, i: usize) -> *mut u8 {
        if i < self.base_slots {
            unsafe { self.arena.add(i * PAGE) }
        } else {
            unsafe { self.grown.add((i - self.base_slots) * PAGE) }
        }
    }

    /// Takes the floor segment when the first paged file registers: the
    /// slot table for the whole cap first (4096 slots, 32 KiB), pages
    /// after it. False when the Index ledger refused it (the caller then
    /// registers nothing and the index stays unserved, with the notice).
    fn ensure_arena(&mut self) -> bool {
        if !self.arena.is_null() {
            return true;
        }
        let p = unsafe { index_alloc(INDEX_ARENA_MIN, PAGE, c"index.pages".as_ptr()) };
        if p.is_null() {
            return false;
        }
        unsafe { self.adopt(p, SLOT_TABLE, (INDEX_ARENA_MIN - SLOT_TABLE) / PAGE) };
        self.owned = true;
        note_arena(INDEX_ARENA_MIN as isize);
        stats::add(Stat::IndexArenaBytes, INDEX_ARENA_MIN as u64);
        true
    }

    /// Uses `p`: `meta` bytes of slot table, then `nslots` pages.
    unsafe fn adopt(&mut self, p: *mut u8, meta: usize, nslots: usize) {
        self.slots = p.cast();
        self.arena = unsafe { p.add(meta) };
        self.base_slots = nslots;
        self.nslots = nslots;
        for i in 0..nslots {
            *self.slot(i) = SLOT0;
        }
    }

    /// Adds `nslots` pages at `p` as slots past the floor segment.
    unsafe fn adopt_growth(&mut self, p: *mut u8, nslots: usize) {
        self.grown = p;
        for i in self.nslots..self.nslots + nslots {
            *self.slot(i) = SLOT0;
        }
        self.nslots += nslots;
    }

    /// CLOCK: the first free slot, or the first unreferenced one past the
    /// hand, clearing reference bits on the way; slots being loaded are
    /// skipped. None when every slot is loading.
    fn victim(&mut self) -> Option<usize> {
        if self.nslots == 0 {
            return None;
        }
        for _ in 0..2 * self.nslots + 1 {
            let i = self.hand;
            self.hand = (i + 1) % self.nslots;
            let s = self.slot(i);
            if s.src == FREE {
                return Some(i);
            }
            if s.flags & LOADING != 0 {
                continue;
            }
            if s.flags & REF != 0 {
                s.flags &= !REF;
                continue;
            }
            return Some(i);
        }
        None
    }
}

// ---- registration ----

/// An index file or image registered with the cache; copies are cheap and
/// all read the same pages. `backing` and `len` are fixed at register, so
/// `len()` and a memory read (host tests) take no lock, and a direct read
/// needs none.
#[derive(Clone, Copy)]
pub(crate) struct PagedSource {
    pages: &'static Pages,
    id: u8,
    backing: Backing,
    len: u64,
}

// The backing is an fd or a pointer to memory that stays read-only for the
// module lifetime: any thread may read through it.
unsafe impl Send for PagedSource {}
unsafe impl Sync for PagedSource {}

/// Page table for a file of `pages` pages, all absent. From the Index
/// ledger; host tests take it from the heap so the
/// ledger tests running beside them see no change.
fn table_alloc(pages: usize) -> *mut u16 {
    let bytes = pages.max(1) * size_of::<u16>();
    #[cfg(not(test))]
    let t: *mut u16 = unsafe { index_alloc(bytes, 16, c"index.page_table".as_ptr()) }.cast();
    #[cfg(test)]
    let t: *mut u16 = if TABLE_REFUSED.with(|r| r.get()) {
        null_mut()
    } else {
        std::vec![0u16; bytes / 2].leak().as_mut_ptr()
    };
    if !t.is_null() {
        for i in 0..pages {
            unsafe { *t.add(i) = ABSENT };
        }
    }
    t
}

#[cfg(test)]
std::thread_local! {
    /// Host tests: `table_alloc` refuses while set, as the ledger can.
    static TABLE_REFUSED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

impl Pages {
    /// Adds a source; None when all `SOURCES` are taken, the file has more
    /// pages than a `Slot` can name, or the arena or page table is refused.
    fn register(&'static self, backing: Backing, len: u64) -> Option<PagedSource> {
        let paged = backing.memory().is_none();
        let pages = len.div_ceil(PAGE as u64);
        if pages > u32::MAX as u64 {
            return None;
        }
        let g = self.lock.lock();
        let c = self.cache(&g);
        if c.nsrcs == SOURCES || (paged && !c.ensure_arena()) {
            return None;
        }
        let table = if paged {
            let t = table_alloc(pages as usize);
            if t.is_null() {
                // The arena may have been taken just now for this source:
                // with no paged source left it goes back to the ledger.
                c.release_arena_if_idle();
                return None;
            }
            t
        } else {
            null_mut()
        };
        // A free id: never used, or given back by `unregister`.
        let id = c
            .srcs
            .iter()
            .position(|s| matches!(s.backing, Backing::None))?;
        c.srcs[id] = Src {
            backing,
            len,
            table,
        };
        c.nsrcs += 1;
        stats::add(Stat::IndexFilesBytes, len);
        Some(PagedSource {
            pages: self,
            id: id as u8,
            backing,
            len,
        })
    }
}

impl Pages {
    /// Gives source `id` back: its pages return to the free slots and the
    /// id is reused. The caller guarantees no reader holds it any more.
    fn unregister(&self, id: usize) {
        let g = self.lock.lock();
        let c = self.cache(&g);
        let Some(src) = c.srcs.get(id).copied() else {
            return;
        };
        if matches!(src.backing, Backing::None) {
            return;
        }
        for i in 0..c.nslots {
            let s = c.slot(i);
            if s.src as usize != id {
                continue;
            }
            // A page still being read was never counted resident and its
            // loader writes it: mark it, the loader frees the slot.
            if s.flags & LOADING != 0 {
                s.flags |= DROPPED;
                continue;
            }
            *s = SLOT0;
            c.resident -= 1;
            stats::leave(Stat::IndexPageResident);
        }
        if !src.table.is_null() {
            #[cfg(not(test))]
            unsafe {
                index_free(src.table.cast(), c"index.page_table".as_ptr())
            };
        }
        c.srcs[id] = SRC0;
        c.nsrcs -= 1;
        stats::sub(Stat::IndexFilesBytes, src.len);
        c.release_arena_if_idle();
    }
}

impl Cache {
    /// Releases the arena once no paged source is left and no loader is
    /// still writing a page into it.
    fn release_arena_if_idle(&mut self) {
        let paged = self
            .srcs
            .iter()
            .any(|s| !matches!(s.backing, Backing::None) && s.backing.memory().is_none());
        let loading = (0..self.nslots).any(|i| self.slot(i).flags & LOADING != 0);
        if !paged && !loading {
            self.release_arena();
        }
    }

    /// Gives a ledger arena back once no paged source is left (a failed or
    /// replaced load), so a corrupt index file does not keep the 16 MiB
    /// floor for the module lifetime. The next paged file takes it again.
    fn release_arena(&mut self) {
        if !self.owned {
            return;
        }
        let bytes = INDEX_ARENA_MIN + (self.nslots - self.base_slots) * PAGE;
        unsafe {
            index_free(self.slots.cast(), c"index.pages.free".as_ptr());
            if !self.grown.is_null() {
                index_free(self.grown.cast(), c"index.pages.grow.free".as_ptr());
            }
        }
        note_arena(-(bytes as isize));
        stats::sub(Stat::IndexArenaBytes, bytes as u64);
        (self.arena, self.grown, self.slots) = (null_mut(), null_mut(), null_mut());
        (self.nslots, self.base_slots, self.hand, self.owned) = (0, 0, 0, false);
    }
}

/// Drops a source registered by a load that then failed, or whose file
/// was replaced: it frees the source's pages and page table and its id.
/// Only for a source never published to lookups (no reader can hold it).
/// The caller closes a file source's fd.
pub(crate) fn unregister(src: PagedSource) {
    src.pages.unregister(src.id as usize);
}

/// Registers an open index file of `len` bytes. The fd stays open for the
/// module lifetime: misses read it again.
pub(crate) fn register_file(fd: c_int, len: u64) -> Option<PagedSource> {
    PAGES.register(Backing::File(fd), len)
}

/// Host tests: registers an image of `len` bytes at `ptr` as a paged
/// source with no file. The caller keeps the memory alive; reads copy from
/// it and take no arena pages.
#[cfg(test)]
pub(crate) unsafe fn register_memory(ptr: *const u8, len: usize) -> Option<PagedSource> {
    PAGES.register(Backing::Memory(ptr), len as u64)
}

/// Host tests: `image` as a paged file in a one-page cache of its own
/// (heap, not the Index ledger) whose reads fail with `Io` while `fail` is
/// set.
#[cfg(test)]
pub(crate) fn test_file(
    image: &'static [u8],
    fail: &'static core::sync::atomic::AtomicBool,
) -> PagedSource {
    use core::sync::atomic::Ordering::SeqCst;
    let p: &'static Pages = std::boxed::Box::leak(std::boxed::Box::new(Pages::new()));
    let (nslots, meta) = (1, size_of::<Slot>());
    let mem = std::vec![0u64; (meta + nslots * PAGE).div_ceil(8)].leak();
    let g = p.lock.lock();
    unsafe { p.cache(&g).adopt(mem.as_mut_ptr().cast(), meta, nslots) };
    drop(g);
    let read = move |at: u64, out: &mut [u8]| {
        let Some(bytes) = image.get(at as usize..at as usize + out.len()) else {
            return false;
        };
        out.copy_from_slice(bytes);
        !fail.load(SeqCst)
    };
    let read: &'static (dyn Fn(u64, &mut [u8]) -> bool + Sync) =
        std::boxed::Box::leak(std::boxed::Box::new(read));
    p.register(Backing::Test(read), image.len() as u64).unwrap()
}

impl Pages {
    /// The growth segment, once: the Index room past `reserve` and
    /// `TRANSIENT_ROOM`, in whole pages. False when the floor segment was
    /// never taken (no file is paged) or it already grew.
    fn grow(&self, reserve: usize) -> bool {
        let g = self.lock.lock();
        let c = self.cache(&g);
        if c.arena.is_null() || !c.grown.is_null() {
            return false;
        }
        let room = index_room().saturating_sub(reserve + TRANSIENT_ROOM);
        let max = INDEX_MEMORY_MAX / PAGE - c.nslots;
        let nslots = (room / PAGE).min(max);
        if nslots == 0 {
            return false;
        }
        let p = unsafe { index_alloc(nslots * PAGE, PAGE, c"index.pages.grow".as_ptr()) };
        if p.is_null() {
            return false;
        }
        unsafe { c.adopt_growth(p, nslots) };
        note_arena((nslots * PAGE) as isize);
        stats::add(Stat::IndexArenaBytes, (nslots * PAGE) as u64);
        true
    }
}

/// Grows the page arena past its 16 MiB floor, once the mounts that page
/// an index have their lookup tables: the arena gets the Index room the
/// tables left, less `reserve` (tables still to be built) and the
/// transient buffers' room. A no-op while no file is paged.
pub(crate) fn grow_arena(reserve: usize) -> bool {
    #[cfg(test)]
    GROW_CALLS.with(|c| c.set(c.get() + 1));
    PAGES.grow(reserve)
}

#[cfg(test)]
std::thread_local! {
    static GROW_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Host tests: `grow_arena` calls made on this thread.
#[cfg(test)]
pub(crate) fn test_grow_calls() -> usize {
    GROW_CALLS.with(|c| c.get())
}

// ---- mounted index sources ----

/// How a mounted index file is read: whole in index memory when it fits
/// the room left with its tables (no lock, no page cache, as in v0.3.5),
/// else in pages (`PagedSource`) with a resident fast table beside it.
#[derive(Clone, Copy)]
pub(crate) enum IndexSource {
    Resident(&'static [u8]),
    Paged(PagedSource),
}

impl Source for IndexSource {
    fn len(&self) -> u64 {
        match self {
            Self::Resident(b) => b.len() as u64,
            Self::Paged(p) => p.len(),
        }
    }
    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        match self {
            Self::Resident(b) => b.read_at(at, out),
            Self::Paged(p) => p.read_at(at, out),
        }
    }
}

impl IndexSource {
    pub(crate) fn is_resident(&self) -> bool {
        matches!(self, Self::Resident(_))
    }

    /// Gives the source back: a resident image's memory, or the paged
    /// registration (`unregister`, same rules). The caller closes the fd.
    pub(crate) unsafe fn release(self, tag: &core::ffi::CStr) {
        match self {
            Self::Resident(b) => unsafe { index_free(b.as_ptr() as *mut _, tag.as_ptr()) },
            Self::Paged(p) => unregister(p),
        }
    }
}

/// Reads the index file `fd` of `len` bytes whole into index memory.
/// None when refused (counted, no notice: the caller then pages it) or
/// on a read error.
#[cfg(not(test))]
pub(crate) unsafe fn read_resident(
    fd: c_int,
    len: u64,
    tag: &core::ffi::CStr,
) -> Option<&'static [u8]> {
    let len = usize::try_from(len).ok().filter(|&n| n > 0)?;
    let p = unsafe { super::index_memory::index_scratch_alloc(len, PAGE, tag.as_ptr()) };
    if p.is_null() {
        return None;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(p, len) };
    if !pread_file(fd, 0, out) {
        unsafe { index_free(p.cast(), tag.as_ptr()) };
        return None;
    }
    Some(out)
}

/// Host tests read no files.
#[cfg(test)]
pub(crate) unsafe fn read_resident(_: c_int, _: u64, _: &core::ffi::CStr) -> Option<&'static [u8]> {
    None
}

/// The first `out.len()` bytes of the index file `fd` (a header, read
/// before the mount decides how to hold the file); false on an error.
pub(crate) fn read_head(fd: c_int, out: &mut [u8]) -> bool {
    pread_file(fd, 0, out)
}

/// An index refused for lack of room: `needed` bytes did not fit.
pub(crate) unsafe fn refuse(needed: usize) {
    unsafe { index_refused(needed) };
}

// ---- reads ----

/// Reads `out.len()` bytes of the source at `at` into `out`, without the
/// cache lock; false on a read error or a short file.
fn fill(backing: Backing, at: u64, out: &mut [u8]) -> bool {
    match backing {
        Backing::File(fd) => pread_file(fd, at, out),
        #[cfg(test)]
        Backing::Test(f) => f(at, out),
        _ => false,
    }
}

/// The raw pre-detour pread, as the pack loader's: short reads
/// continue, EINTR retries, EOF fails. Never a hooked call: the hooks
/// themselves look paths up in the index.
#[cfg(not(test))]
fn pread_file(fd: c_int, at: u64, out: &mut [u8]) -> bool {
    let dst = out.as_mut_ptr();
    super::pack::pread_loop(
        out.len(),
        at,
        PAGE,
        |done, want, off| unsafe {
            super::sys::real_physical_pread(fd, dst.add(done).cast(), want, off)
        },
        super::sys::errno,
    )
}

/// Host tests link no libkernel: files are `Backing::Test`.
#[cfg(test)]
fn pread_file(_fd: c_int, _at: u64, _out: &mut [u8]) -> bool {
    false
}

impl Pages {
    /// Copies `out.len()` bytes at `off` of page `page` of `src` (all
    /// within the page) into `out`, loading the page into a slot on a
    /// miss. A page another thread is loading, or a miss with no evictable
    /// slot, is read straight from the file into `out` instead of waiting:
    /// a hook never waits on another thread, it reads the index file
    /// itself, as the call it replaces would have.
    fn read_page(&self, src: &PagedSource, page: usize, off: usize, out: &mut [u8]) -> Result<()> {
        let id = src.id as usize;
        let at = (page * PAGE) as u64;
        let g = self.lock.lock();
        let c = self.cache(&g);
        let t = c.table(id);
        let s = unsafe { *t.add(page) };
        let victim = if s == ABSENT { c.victim() } else { None };
        if s != ABSENT && c.slot(s as usize).flags & LOADING == 0 {
            let s = s as usize;
            c.slot(s).flags |= REF;
            let from = unsafe { c.page_ptr(s).add(off) };
            unsafe { core::ptr::copy_nonoverlapping(from, out.as_mut_ptr(), out.len()) };
            c.hits += 1;
            stats::add(Stat::IndexPageHits, 1);
            return Ok(());
        }
        let Some(v) = victim else {
            c.direct += 1;
            drop(g);
            stats::add(Stat::IndexPageDirectReads, 1);
            return if fill(src.backing, at + off as u64, out) {
                Ok(())
            } else {
                Err(Error::Io)
            };
        };
        let old = *c.slot(v);
        if old.src != FREE {
            unsafe { *c.table(old.src as usize).add(old.page as usize) = ABSENT };
            c.evictions += 1;
            c.resident -= 1;
            stats::add(Stat::IndexPageEvictions, 1);
            stats::leave(Stat::IndexPageResident);
        }
        *c.slot(v) = Slot {
            src: id as u8,
            flags: LOADING,
            page: page as u32,
        };
        unsafe { *t.add(page) = v as u16 };
        let n = (src.len - at).min(PAGE as u64) as usize;
        let dst = unsafe { core::slice::from_raw_parts_mut(c.page_ptr(v), n) };
        c.misses += 1;
        drop(g);
        // Only this thread touches a LOADING slot's page.
        let start = stats::now();
        let ok = fill(src.backing, at, dst);
        stats::add(Stat::IndexPageMisses, 1);
        stats::add(Stat::IndexPageMissNs, stats::since(start));
        let g = self.lock.lock();
        let c = self.cache(&g);
        if c.slot(v).flags & DROPPED != 0 {
            // The source was unregistered meanwhile: its page table is gone
            // and its fd may be closed, so the bytes are not trusted. The
            // slot was never counted resident.
            *c.slot(v) = SLOT0;
            c.release_arena_if_idle();
            return Err(Error::Io);
        }
        if ok {
            c.slot(v).flags = REF;
            c.resident += 1;
            stats::enter(Stat::IndexPageResident);
            out.copy_from_slice(&dst[off..off + out.len()]);
            Ok(())
        } else {
            *c.slot(v) = SLOT0;
            unsafe { *t.add(page) = ABSENT };
            Err(Error::Io)
        }
    }

    fn read(&self, src: &PagedSource, at: u64, out: &mut [u8]) -> Result<()> {
        let end = at.checked_add(out.len() as u64).ok_or(Error::Truncated)?;
        if end > src.len {
            return Err(Error::Truncated);
        }
        if let Some(p) = src.backing.memory() {
            let from = unsafe { p.add(at as usize) };
            unsafe { core::ptr::copy_nonoverlapping(from, out.as_mut_ptr(), out.len()) };
            return Ok(());
        }
        let mut done = 0usize;
        while done < out.len() {
            let pos = at + done as u64;
            let (page, off) = ((pos / PAGE as u64) as usize, (pos % PAGE as u64) as usize);
            let n = (PAGE - off).min(out.len() - done);
            self.read_page(src, page, off, &mut out[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}

impl Source for PagedSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        self.pages.read(self, at, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::vec::Vec;

    fn byte(i: u64) -> u8 {
        (i * 7 + i / PAGE as u64) as u8
    }

    /// A cache of `nslots` heap pages.
    fn cache(nslots: usize) -> &'static Pages {
        let p: &'static Pages = Box::leak(Box::new(Pages::new()));
        let meta = nslots * size_of::<Slot>();
        let words = (meta + nslots * PAGE).div_ceil(8);
        let mem = std::vec![0u64; words].leak().as_mut_ptr().cast::<u8>();
        let g = p.lock.lock();
        unsafe { p.cache(&g).adopt(mem, meta, nslots) };
        drop(g);
        p
    }

    /// An in-memory file of `len` bytes: counts reads, fails while `fail`
    /// is set; the first read blocks while `hold` is set.
    struct File {
        loads: AtomicUsize,
        fail: AtomicBool,
        hold: AtomicBool,
    }

    fn file(p: &'static Pages, len: u64, hold: bool) -> (PagedSource, &'static File) {
        let f: &'static File = Box::leak(Box::new(File {
            loads: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            hold: AtomicBool::new(hold),
        }));
        let read = move |at: u64, out: &mut [u8]| {
            if f.loads.fetch_add(1, SeqCst) == 0 {
                while f.hold.load(SeqCst) {
                    std::thread::yield_now();
                }
            }
            if f.fail.load(SeqCst) || at + out.len() as u64 > len {
                return false;
            }
            for (i, b) in out.iter_mut().enumerate() {
                *b = byte(at + i as u64);
            }
            true
        };
        let read: &'static (dyn Fn(u64, &mut [u8]) -> bool + Sync) = Box::leak(Box::new(read));
        (p.register(Backing::Test(read), len).unwrap(), f)
    }

    /// The first paged file takes the 16 MiB floor; `grow` then adds the
    /// Index room past the reserve and the transient room, once, and
    /// reads use slots of both segments. The last paged source's
    /// unregister gives both back.
    #[test]
    fn arena_takes_the_floor_then_the_room_the_tables_left() {
        use crate::rt::index_memory::{test_index_used, POOL_TEST_LOCK};
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = test_index_used();
        let p: &'static Pages = Box::leak(Box::new(Pages::new()));
        assert!(!p.grow(0), "nothing paged yet");
        let len = INDEX_MEMORY_MAX as u64;
        let (s, f) = file(p, len, false);
        assert_eq!(test_index_used(), used + INDEX_ARENA_MIN);
        let reserve = 3 << 20;
        assert!(p.grow(reserve));
        assert!(!p.grow(0), "grows once");
        let room = index_room();
        assert!(room >= reserve + TRANSIENT_ROOM && room < reserve + TRANSIENT_ROOM + PAGE);
        let (base, all) = {
            let g = p.lock.lock();
            let c = p.cache(&g);
            (c.base_slots, c.nslots)
        };
        assert_eq!(base, (INDEX_ARENA_MIN - SLOT_TABLE) / PAGE);
        assert_eq!(
            all - base,
            (test_index_used() - used - INDEX_ARENA_MIN) / PAGE
        );
        // Every slot of both segments loads a page, and hits after.
        for page in 0..all as u64 {
            check(&s, page * PAGE as u64, 8);
        }
        assert_eq!(f.loads.load(SeqCst), all);
        for page in 0..all as u64 {
            check(&s, page * PAGE as u64 + 8, 8);
        }
        assert_eq!(f.loads.load(SeqCst), all);
        p.unregister(s.id as usize);
        assert_eq!(test_index_used(), used);
        {
            let g = p.lock.lock();
            let c = p.cache(&g);
            assert!(c.arena.is_null() && c.grown.is_null() && c.nslots == 0);
        }
        // The next paged file takes the floor again.
        let (s, _) = file(p, PAGE as u64, false);
        assert_eq!(test_index_used(), used + INDEX_ARENA_MIN);
        check(&s, 0, 8);
        unregister(s);
        assert_eq!(test_index_used(), used);
    }

    /// The first paged file takes the arena, then its page table is
    /// refused: the register fails and the arena goes back to the ledger
    /// instead of staying with no source. The next file takes it again.
    #[test]
    fn refused_page_table_gives_the_arena_back() {
        use crate::rt::index_memory::{test_index_used, POOL_TEST_LOCK};
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let used = test_index_used();
        let p: &'static Pages = Box::leak(Box::new(Pages::new()));
        let read: &'static (dyn Fn(u64, &mut [u8]) -> bool + Sync) =
            Box::leak(Box::new(|_: u64, _: &mut [u8]| true));
        TABLE_REFUSED.with(|r| r.set(true));
        let refused = p.register(Backing::Test(read), PAGE as u64);
        TABLE_REFUSED.with(|r| r.set(false));
        assert!(refused.is_none());
        assert_eq!(test_index_used(), used);
        {
            let g = p.lock.lock();
            let c = p.cache(&g);
            assert!(c.arena.is_null() && !c.owned && c.nslots == 0 && c.nsrcs == 0);
        }
        let (s, _) = file(p, PAGE as u64, false);
        assert_eq!(test_index_used(), used + INDEX_ARENA_MIN);
        check(&s, 0, 8);
        unregister(s);
        assert_eq!(test_index_used(), used);
    }

    fn check(s: &PagedSource, at: u64, len: usize) {
        let mut out = std::vec![0u8; len];
        assert_eq!(s.read_at(at, &mut out), Ok(()));
        let want: Vec<u8> = (0..len as u64).map(|i| byte(at + i)).collect();
        assert!(out == want, "bytes at {at}+{len}");
    }

    fn counts(p: &Pages) -> (u64, u64, u64, u64) {
        let g = p.lock.lock();
        let c = p.cache(&g);
        (c.hits, c.misses, c.evictions, c.resident)
    }

    fn direct(p: &Pages) -> u64 {
        let g = p.lock.lock();
        p.cache(&g).direct
    }

    /// Runs `f` on another thread and fails if it has not returned within
    /// 5 s: the way a test sees that `f` did not block.
    fn returns<F: FnOnce() + Send + 'static>(f: F) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            tx.send(()).unwrap();
        });
        let r = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(r.is_ok(), "blocked");
    }

    #[test]
    fn hits_after_first_load_and_reads_span_pages() {
        let p = cache(4);
        let (s, f) = file(p, 3 * PAGE as u64 + 100, false);
        assert_eq!(s.len(), 3 * PAGE as u64 + 100);
        check(&s, PAGE as u64 - 50, 100);
        assert_eq!(f.loads.load(SeqCst), 2);
        check(&s, PAGE as u64 - 10, 20);
        assert_eq!(f.loads.load(SeqCst), 2);
        assert_eq!(counts(p), (2, 2, 0, 2));
        check(&s, 0, 3 * PAGE + 100);
        assert_eq!(f.loads.load(SeqCst), 4);
        assert_eq!(counts(p).3, 4);
        let mut out = [0u8; 2];
        assert_eq!(
            s.read_at(3 * PAGE as u64 + 99, &mut out),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn evicts_and_reads_again_after_eviction() {
        let p = cache(2);
        let (s, f) = file(p, 5 * PAGE as u64, false);
        for page in 0..5u64 {
            check(&s, page * PAGE as u64 + 3, 8);
        }
        let (_, misses, evictions, resident) = counts(p);
        assert_eq!((misses, evictions, resident), (5, 3, 2));
        // Page 0 was evicted: read from the file again, same bytes.
        check(&s, 0, 2 * PAGE);
        assert!(f.loads.load(SeqCst) >= 6);
        assert_eq!(counts(p).3, 2);
    }

    #[test]
    fn io_error_frees_the_slot() {
        let p = cache(1);
        let (s, f) = file(p, 2 * PAGE as u64, false);
        f.fail.store(true, SeqCst);
        let mut out = [0u8; 4];
        assert_eq!(s.read_at(0, &mut out), Err(Error::Io));
        assert_eq!(counts(p).3, 0);
        f.fail.store(false, SeqCst);
        check(&s, 0, 4);
        check(&s, PAGE as u64, 4);
        assert_eq!(counts(p), (0, 3, 1, 1));
    }

    /// Starts a load of page 0 that blocks inside the file read, and
    /// returns once its slot is LOADING.
    fn hold_page0(s: PagedSource, f: &'static File) -> std::thread::JoinHandle<()> {
        let t = std::thread::spawn(move || check(&s, 0, 8));
        while f.loads.load(SeqCst) == 0 {
            std::thread::yield_now();
        }
        t
    }

    #[test]
    fn reader_of_a_loading_page_reads_the_file_itself() {
        let p = cache(2);
        let (s, f) = file(p, 2 * PAGE as u64, true);
        let loader = hold_page0(s, f);
        // The same page, loading on the other thread: read past the cache.
        returns(move || check(&s, 100, 300));
        assert_eq!((direct(p), f.loads.load(SeqCst)), (1, 2));
        f.hold.store(false, SeqCst);
        loader.join().unwrap();
        assert_eq!(counts(p), (0, 1, 0, 1));
        check(&s, 100, 300);
        assert_eq!((counts(p).0, direct(p)), (1, 1));
    }

    #[test]
    fn miss_with_no_evictable_slot_reads_the_file_itself() {
        let p = cache(1);
        let (s, f) = file(p, 2 * PAGE as u64, true);
        let loader = hold_page0(s, f);
        // The only slot is loading page 0: page 1 has no victim.
        returns(move || check(&s, PAGE as u64 + 5, 40));
        assert_eq!(direct(p), 1);
        f.hold.store(false, SeqCst);
        loader.join().unwrap();
        assert_eq!(counts(p), (0, 1, 0, 1));
    }

    #[test]
    fn memory_source_and_len_take_no_lock() {
        let p = cache(1);
        let image: &'static [u8] = Box::leak((0..64u8).collect::<Box<[u8]>>());
        let m = p.register(Backing::Memory(image.as_ptr()), 64).unwrap();
        let (fs, _) = file(p, 3 * PAGE as u64, false);
        // With the cache lock held here, a reader that took it would block.
        let g = p.lock.lock();
        returns(move || {
            let mut out = [0u8; 4];
            assert_eq!(m.read_at(10, &mut out), Ok(()));
            assert_eq!(out, [10, 11, 12, 13]);
            assert_eq!((m.len(), fs.len()), (64, 3 * PAGE as u64));
            assert_eq!(fs.read_at(3 * PAGE as u64, &mut out), Err(Error::Truncated));
        });
        drop(g);
        assert_eq!((counts(p), direct(p)), ((0, 0, 0, 0), 0));
    }

    #[test]
    fn memory_source_and_source_limit() {
        let p = cache(1);
        let image: &'static [u8] = Box::leak((0..64u8).collect::<Box<[u8]>>());
        let m = p.register(Backing::Memory(image.as_ptr()), 64).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(m.read_at(60, &mut out), Ok(()));
        assert_eq!(out, [60, 61, 62, 63]);
        assert_eq!(m.read_at(61, &mut out), Err(Error::Truncated));
        assert_eq!(counts(p), (0, 0, 0, 0));
        for _ in 1..SOURCES {
            file(p, 1, false);
        }
        assert!(p.register(Backing::Memory(image.as_ptr()), 64).is_none());
        // A given-back id is reused; its pages go back to the free slots.
        unregister(m);
        let m2 = p.register(Backing::Memory(image.as_ptr()), 64).unwrap();
        assert_eq!(m2.read_at(0, &mut out), Ok(()));
    }

    #[test]
    fn unregister_frees_pages_of_the_source() {
        let p = cache(2);
        let (a, _) = file(p, 2 * PAGE as u64, false);
        check(&a, 0, 1);
        check(&a, PAGE as u64, 1);
        assert_eq!(counts(p).3, 2);
        unregister(a);
        assert_eq!(counts(p).3, 0);
        let (b, fb) = file(p, PAGE as u64, false);
        check(&b, 0, 1);
        assert_eq!((counts(p).2, fb.loads.load(SeqCst)), (0, 1));
    }

    /// Unregister while a page of the source is loading: the resident count
    /// does not underflow, the loader frees its slot without marking it
    /// resident, and the slot serves the next source.
    #[test]
    fn unregister_while_a_page_is_loading() {
        let p = cache(1);
        let (a, fa) = file(p, PAGE as u64, true);
        let mut out = [0u8; 8];
        let loader = std::thread::spawn(move || a.read_at(0, &mut out));
        while fa.loads.load(SeqCst) == 0 {
            std::thread::yield_now();
        }
        p.unregister(a.id as usize);
        assert_eq!(counts(p).3, 0);
        {
            let g = p.lock.lock();
            let c = p.cache(&g);
            assert_eq!(c.slot(0).flags, LOADING | DROPPED);
        }
        // The same id again: the dropped slot is not its victim yet.
        let (b, fb) = file(p, PAGE as u64, false);
        assert_eq!(b.id, a.id);
        check(&b, 0, 8);
        assert_eq!((direct(p), fb.loads.load(SeqCst)), (1, 1));
        fa.hold.store(false, SeqCst);
        assert_eq!(loader.join().unwrap(), Err(Error::Io));
        {
            let g = p.lock.lock();
            let c = p.cache(&g);
            assert_eq!((c.slot(0).src, c.slot(0).flags, c.resident), (FREE, 0, 0));
        }
        check(&b, 0, 8);
        assert_eq!(counts(p), (0, 2, 0, 1));
    }
}
