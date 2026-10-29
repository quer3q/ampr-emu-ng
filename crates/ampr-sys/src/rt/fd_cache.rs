//! The APR descriptor cache and the combined cached+direct+pack FD open
//! budget.
//!
//! The cache never promotes (no SLRU promote/balance), so one LRU list
//! of unpinned open entries is kept. Closed unpinned entries are freed at
//! once instead of parked on a closed list: both hold no fd, and a lookup of
//! either is a miss.

use super::sync::{Mutex, SyncCell};
use super::sys::*;
use core::ffi::{c_char, c_int, c_uint};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::*};

// ---- config -----------------------------------------------------------------

const BUDGET_CAP: usize = 50; // AMPR_EMU_FD_OPEN_BUDGET_CAP
const CACHE_CAP: usize = 45; // AMPR_EMU_FD_CACHE_CAP: min(50, max(50*90/100, 1))
const PRESSURE_MIN_CAP: usize = 12; // ceil(45 * 25%)
const BUDGET_MIN_CAP: usize = PRESSURE_MIN_CAP + 1;
const EMFILE_REDUCE_PERCENT: usize = 5;
const EMFILE_IDLE_CLOSE_PERCENT: c_uint = 10;
const IDLE_CLOSE_NS: u64 = 10_000_000_000;
const IDLE_SCAN_NS: u64 = 250_000_000;
const OPEN_PRESSURE_IDLE_CLOSE_PERCENT: c_uint = 100;
const BUCKETS: usize = CACHE_CAP * 2 + 1;
const NIL: u32 = u32::MAX;

// ---- shared types -----------------------------------------------------------

/// `FileEntryView`: one resident file index entry.
#[repr(C)]
pub struct FileEntryView {
    pub path: *const c_char,
    pub path_length: u32,
    pub size: usize,
    pub mtime: i64,
}
const _: () = assert!(core::mem::size_of::<FileEntryView>() == 32);
const _: () = assert!(core::mem::offset_of!(FileEntryView, size) == 16);

/// `AmprIndexFdPressureCaps`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PressureCaps {
    pub fd_budget: usize,
    pub cache_cap: usize,
}
const _: () = assert!(core::mem::size_of::<PressureCaps>() == 16);

/// `AmprIndexFdCacheStats`; `open`/`pinned_open`/`pins`/`evictable` count
/// physical descriptors only (virtual pack fds use no kernel fd).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CacheStats {
    pub entries: usize,
    pub handles: usize,
    pub open: usize,
    pub pinned_open: usize,
    pub pins: usize,
    pub evictable: usize,
    pub probationary: usize,
    pub protected_entries: usize,
}
const _: () = assert!(core::mem::size_of::<CacheStats>() == 64);
const _: () = assert!(core::mem::offset_of!(CacheStats, evictable) == 40);

use super::pack::{ampr_pack_notify_fd_budget_progress, ampr_pack_try_open_indexed};

// ---- cache state (guarded by LOCK) ----------------------------------------

#[derive(Clone, Copy)]
struct Slot {
    id: u32,
    fd: c_int,
    last_use_ns: u64,
    pins: u32,
    prev: u32,
    next: u32,      // LRU link; free-list link while inactive
    hash_next: u32, // index + 1; 0 ends the chain
    active: bool,
    physical: bool,
    on_lru: bool,
}

impl Slot {
    const EMPTY: Slot = Slot {
        id: 0,
        fd: -1,
        last_use_ns: 0,
        pins: 0,
        prev: NIL,
        next: NIL,
        hash_next: 0,
        active: false,
        physical: false,
        on_lru: false,
    };
}

struct State {
    s: [Slot; CACHE_CAP],
    heads: [u32; BUCKETS],
    lru_head: u32,
    lru_tail: u32,
    lru_len: usize,
    free: u32,
    ready: bool,
    active: usize,
    open: usize,
    pinned_open: usize,
    open_pins: usize,
    evictable: usize,
    phys_open: usize,
    phys_pinned_open: usize,
    phys_open_pins: usize,
    phys_evictable: usize,
}

static LOCK: Mutex = Mutex::new();
static STATE: SyncCell<State> = SyncCell::new(State {
    s: [Slot::EMPTY; CACHE_CAP],
    heads: [0; BUCKETS],
    lru_head: NIL,
    lru_tail: NIL,
    lru_len: 0,
    free: NIL,
    ready: false,
    active: 0,
    open: 0,
    pinned_open: 0,
    open_pins: 0,
    evictable: 0,
    phys_open: 0,
    phys_pinned_open: 0,
    phys_open_pins: 0,
    phys_evictable: 0,
});

/// Runs `f` with the cache locked (`AmprLockGuard lk(fs.m)`).
fn locked<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let _g = LOCK.lock();
    let st = unsafe { &mut *STATE.get() };
    if !st.ready {
        for i in 0..CACHE_CAP {
            st.s[i].next = st.free;
            st.free = i as u32;
        }
        st.ready = true;
    }
    f(st)
}

fn dec(v: &mut usize, by: usize) {
    *v = v.saturating_sub(by);
}

fn bucket(id: u32) -> usize {
    ((id as u64 * 2_654_435_761) % BUCKETS as u64) as usize
}

impl State {
    fn find(&self, id: u32) -> Option<usize> {
        if id == 0 {
            return None;
        }
        let mut p = self.heads[bucket(id)];
        while p != 0 {
            let i = (p - 1) as usize;
            if self.s[i].active && self.s[i].id == id {
                return Some(i);
            }
            p = self.s[i].hash_next;
        }
        None
    }

    fn hash_unlink(&mut self, i: usize) {
        let mut link: *mut u32 = &mut self.heads[bucket(self.s[i].id)];
        unsafe {
            while *link != 0 {
                let cur = (*link - 1) as usize;
                if cur == i {
                    *link = self.s[i].hash_next;
                    break;
                }
                link = &mut self.s[cur].hash_next;
            }
        }
        self.s[i].hash_next = 0;
    }

    fn lru_unlink(&mut self, i: usize) {
        let Slot {
            prev, next, on_lru, ..
        } = self.s[i];
        if on_lru {
            if prev != NIL {
                self.s[prev as usize].next = next
            } else {
                self.lru_head = next
            }
            if next != NIL {
                self.s[next as usize].prev = prev
            } else {
                self.lru_tail = prev
            }
            dec(&mut self.lru_len, 1);
        }
        let e = &mut self.s[i];
        (e.prev, e.next, e.on_lru) = (NIL, NIL, false);
    }

    fn lru_append(&mut self, i: usize) {
        let e = self.s[i];
        if !e.active || e.fd < 0 || e.pins != 0 {
            return;
        }
        self.lru_unlink(i);
        self.s[i].prev = self.lru_tail;
        if self.lru_tail != NIL {
            self.s[self.lru_tail as usize].next = i as u32
        } else {
            self.lru_head = i as u32
        }
        self.lru_tail = i as u32;
        self.lru_len += 1;
        self.s[i].on_lru = true;
    }

    /// Activates a free slot for `id`.
    fn activate(&mut self, i: usize, id: u32) {
        let b = bucket(id);
        self.s[i] = Slot {
            id,
            active: true,
            hash_next: self.heads[b],
            ..Slot::EMPTY
        };
        self.heads[b] = i as u32 + 1;
        self.active += 1;
    }

    /// Returns a closed, unpinned slot to the free list.
    fn release(&mut self, i: usize) {
        self.hash_unlink(i);
        self.s[i] = Slot {
            next: self.free,
            ..Slot::EMPTY
        };
        self.free = i as u32;
        dec(&mut self.active, 1);
    }

    fn note_open(&mut self, i: usize, fd: c_int, physical: bool) {
        let e = &mut self.s[i];
        if e.fd >= 0 {
            return;
        }
        (e.fd, e.physical) = (fd, physical);
        let pins = e.pins as usize;
        self.open += 1;
        if pins != 0 {
            self.pinned_open += 1;
            self.open_pins += pins;
        } else {
            self.evictable += 1;
            self.lru_append(i);
        }
        if physical {
            self.phys_open += 1;
            if pins != 0 {
                self.phys_pinned_open += 1;
                self.phys_open_pins += pins;
            } else {
                self.phys_evictable += 1;
            }
        }
    }

    /// Detaches the slot's fd (caller closes it); frees the slot if unpinned.
    fn detach(&mut self, i: usize) -> c_int {
        let Slot {
            fd, physical, pins, ..
        } = self.s[i];
        if fd < 0 {
            return -1;
        }
        let pins = pins as usize;
        if pins != 0 {
            dec(&mut self.pinned_open, 1);
            dec(&mut self.open_pins, pins);
        } else {
            self.lru_unlink(i);
            dec(&mut self.evictable, 1);
        }
        dec(&mut self.open, 1);
        if physical {
            dec(&mut self.phys_open, 1);
            if pins != 0 {
                dec(&mut self.phys_pinned_open, 1);
                dec(&mut self.phys_open_pins, pins);
            } else {
                dec(&mut self.phys_evictable, 1);
            }
        }
        (self.s[i].fd, self.s[i].physical) = (-1, false);
        if pins == 0 {
            self.release(i);
        }
        fd
    }

    fn pin(&mut self, i: usize) {
        let e = &mut self.s[i];
        if e.pins == u32::MAX {
            return;
        }
        e.pins += 1;
        let (first, open, physical) = (e.pins == 1, e.fd >= 0, e.physical);
        if !open {
            return;
        }
        self.open_pins += 1;
        if first {
            self.lru_unlink(i);
            dec(&mut self.evictable, 1);
            self.pinned_open += 1;
            if physical {
                dec(&mut self.phys_evictable, 1);
                self.phys_pinned_open += 1;
            }
        }
        if physical {
            self.phys_open_pins += 1;
        }
    }

    fn unpin(&mut self, i: usize) {
        let e = &mut self.s[i];
        if e.pins == 0 {
            return;
        }
        e.pins -= 1;
        let (last, open, physical) = (e.pins == 0, e.fd >= 0, e.physical);
        if !open {
            if last {
                self.release(i);
            }
            return;
        }
        dec(&mut self.open_pins, 1);
        if physical {
            dec(&mut self.phys_open_pins, 1);
        }
        if last {
            dec(&mut self.pinned_open, 1);
            self.evictable += 1;
            if physical {
                dec(&mut self.phys_pinned_open, 1);
                self.phys_evictable += 1;
            }
            self.lru_append(i);
        }
    }

    /// Oldest unpinned open slot (optionally physical fds only).
    fn victim(&self, physical_only: bool) -> Option<usize> {
        let mut i = self.lru_head;
        while i != NIL && physical_only && !self.s[i as usize].physical {
            i = self.s[i as usize].next;
        }
        (i != NIL).then_some(i as usize)
    }

    /// `fd_runtime_create_locked`: existing slot, a free one, or the LRU
    /// victim (its fd goes to `close`). None when every slot is pinned.
    fn create(&mut self, id: u32, close: &mut c_int) -> Option<usize> {
        *close = -1;
        if id == 0 {
            return None;
        }
        if let Some(i) = self.find(id) {
            return Some(i);
        }
        if self.free == NIL {
            let v = self.victim(false)?;
            *close = self.detach(v);
        }
        if self.free == NIL {
            return None;
        }
        let i = self.free as usize;
        self.free = self.s[i].next;
        self.activate(i, id);
        Some(i)
    }

    fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.active,
            handles: self.open,
            open: self.phys_open,
            pinned_open: self.phys_pinned_open,
            pins: self.phys_open_pins,
            evictable: self.phys_evictable,
            probationary: self.lru_len,
            protected_entries: 0,
        }
    }
}

// ---- open budget ---------------------------------------------------------

static BUDGET_EFF: AtomicUsize = AtomicUsize::new(BUDGET_CAP);
static CACHE_EFF: AtomicUsize = AtomicUsize::new(CACHE_CAP);
static DIRECT_OPEN: AtomicUsize = AtomicUsize::new(0);
static PACK_OPEN: AtomicUsize = AtomicUsize::new(0);
static PROGRESS_GEN: AtomicU64 = AtomicU64::new(1);
static PRESSURE_GEN: AtomicU64 = AtomicU64::new(0);
static LAST_IDLE_SCAN: AtomicU64 = AtomicU64::new(0);

fn note_progress() {
    PROGRESS_GEN.fetch_add(1, Release);
    unsafe { ampr_pack_notify_fd_budget_progress() };
}

fn clamp_cap(cap: usize, max: usize) -> usize {
    if cap == 0 || cap > max {
        max
    } else {
        cap
    }
}

fn caps_for_budget(budget: usize) -> PressureCaps {
    let budget = clamp_cap(budget, BUDGET_CAP).max(BUDGET_MIN_CAP);
    let mut cache = (budget * CACHE_CAP / BUDGET_CAP).max(1);
    if cache < PRESSURE_MIN_CAP && budget >= PRESSURE_MIN_CAP {
        cache = PRESSURE_MIN_CAP;
    }
    cache = cache.min(CACHE_CAP);
    if cache >= budget && budget > 1 {
        cache = budget - 1;
    }
    PressureCaps {
        fd_budget: budget,
        cache_cap: cache,
    }
}

fn cache_effective_cap() -> usize {
    clamp_cap(CACHE_EFF.load(Relaxed), CACHE_CAP)
}

fn uncached_open() -> usize {
    DIRECT_OPEN.load(Relaxed) + PACK_OPEN.load(Relaxed)
}

/// Decrements an open counter (no-op at 0) and signals budget progress.
fn note_close(counter: &AtomicUsize) {
    if counter
        .try_update(Relaxed, Relaxed, |v| v.checked_sub(1))
        .is_ok()
    {
        note_progress();
    }
}

pub fn ampr_index_fd_open_budget_effective_cap() -> usize {
    clamp_cap(BUDGET_EFF.load(Relaxed), BUDGET_CAP)
}

pub fn ampr_index_fd_open_budget_set_effective_cap(cap: usize) {
    let cap = clamp_cap(cap, BUDGET_CAP).max(BUDGET_MIN_CAP);
    if cap > BUDGET_EFF.swap(cap, AcqRel) {
        note_progress();
    }
}

pub fn ampr_index_fd_cache_set_effective_cap(cap: usize) {
    CACHE_EFF.store(clamp_cap(cap, CACHE_CAP), Relaxed);
}

pub fn ampr_index_fd_pressure_current_caps() -> PressureCaps {
    caps_for_budget(ampr_index_fd_open_budget_effective_cap())
}

/// EMFILE-class failure: shrink the budget by 5% of the observed open count.
pub fn ampr_index_fd_cache_mark_open_pressure(observed: usize) -> PressureCaps {
    let old = ampr_index_fd_open_budget_effective_cap();
    let observed = if observed == 0 { old } else { observed };
    let reduce = ((observed * EMFILE_REDUCE_PERCENT + 99) / 100).max(1);
    let budget = observed
        .saturating_sub(reduce)
        .max(1)
        .min(old)
        .max(BUDGET_MIN_CAP);
    ampr_index_fd_open_budget_set_effective_cap(budget);
    let caps = caps_for_budget(budget);
    ampr_index_fd_cache_set_effective_cap(caps.cache_cap);
    PRESSURE_GEN.fetch_add(1, Relaxed);
    caps
}

pub fn ampr_index_fd_cache_open_pressure_generation() -> u64 {
    PRESSURE_GEN.load(Relaxed)
}

pub fn ampr_index_fd_open_budget_progress_generation() -> u64 {
    PROGRESS_GEN.load(Acquire)
}

pub fn ampr_index_fd_direct_note_open() {
    DIRECT_OPEN.fetch_add(1, Relaxed);
}

pub fn ampr_index_fd_direct_note_close() {
    note_close(&DIRECT_OPEN);
}

pub fn ampr_index_fd_direct_open_count() -> usize {
    DIRECT_OPEN.load(Relaxed)
}

pub fn ampr_index_fd_pack_note_open() {
    PACK_OPEN.fetch_add(1, Relaxed);
}

pub fn ampr_index_fd_pack_note_close() {
    note_close(&PACK_OPEN);
}

#[cfg(feature = "mem_report")]
pub fn ampr_index_fd_pack_open_count() -> usize {
    PACK_OPEN.load(Relaxed)
}

pub fn ampr_index_fd_uncached_open_count() -> usize {
    uncached_open()
}

pub fn ampr_index_fd_cache_stats() -> CacheStats {
    locked(|st| st.stats())
}

// ---- eviction ------------------------------------------------------------

/// Fds detached under the lock, closed after it is dropped.
struct CloseList {
    fds: [c_int; CACHE_CAP],
    n: usize,
}

impl CloseList {
    const fn new() -> Self {
        Self {
            fds: [-1; CACHE_CAP],
            n: 0,
        }
    }
    fn push(&mut self, fd: c_int) {
        if self.n >= CACHE_CAP {
            abort();
        }
        self.fds[self.n] = fd;
        self.n += 1;
    }
    /// Closes everything; any close counts as budget progress.
    fn close(&mut self) {
        for &fd in &self.fds[..self.n] {
            if fd >= 0 {
                unsafe { sceKernelClose(fd) };
            }
        }
        if self.n != 0 {
            self.n = 0;
            note_progress();
        }
    }
}

impl State {
    /// Detaches up to `max` LRU victims; returns how many.
    fn evict(
        &mut self,
        out: &mut CloseList,
        physical_only: bool,
        mut keep_going: impl FnMut(&State, usize) -> bool,
    ) -> usize {
        let mut n = 0;
        while keep_going(self, n) {
            let Some(v) = self.victim(physical_only) else {
                break;
            };
            let fd = self.detach(v);
            if fd < 0 {
                break;
            }
            out.push(fd);
            n += 1;
        }
        n
    }

    /// Keeps `open + reserve <= cap`.
    fn evict_to_cap(&mut self, out: &mut CloseList, reserve: usize, cap: usize) {
        self.evict(out, false, |st, _| st.open + reserve > cap);
    }

    /// Keeps physical cached fds within the budget left by uncached opens.
    fn evict_budget_headroom(&mut self, out: &mut CloseList, reserve: usize) {
        let cap = ampr_index_fd_open_budget_effective_cap().saturating_sub(uncached_open());
        self.evict(out, true, |st, _| st.phys_open + reserve > cap);
    }

    /// Closes `percent`% (rounded up, at least 1) of idle physical fds.
    fn evict_idle_percent(&mut self, out: &mut CloseList, percent: c_uint) -> usize {
        let idle = self.phys_evictable;
        if percent == 0 || idle == 0 {
            return 0;
        }
        let want = ((idle * percent as usize + 99) / 100).clamp(1, idle);
        self.evict(out, true, |_, n| n < want)
    }

    /// High (85%) / critical (95%) watermark reclaim of idle fds.
    fn evict_watermark(&mut self, out: &mut CloseList, reserve: usize) -> usize {
        let budget = ampr_index_fd_open_budget_effective_cap();
        if self.phys_evictable == 0 || budget == 0 {
            return 0;
        }
        let mark = |pct: usize| ((budget * pct + 99) / 100).clamp(1, budget);
        let projected = self.phys_open + uncached_open() + reserve;
        if projected < mark(85) {
            return 0;
        }
        let critical = projected >= mark(95) || projected > budget;
        let pct = if critical {
            EMFILE_IDLE_CLOSE_PERCENT.max(50)
        } else {
            EMFILE_IDLE_CLOSE_PERCENT.max(25)
        };
        self.evict_idle_percent(out, pct)
    }

    /// Closes idle fds unused for IDLE_CLOSE_NS (oldest first).
    fn evict_stale(&mut self, out: &mut CloseList, now: u64) -> usize {
        if now == 0 {
            return 0;
        }
        let mut closed = 0;
        for _ in 0..self.evictable {
            if self.lru_head == NIL {
                break;
            }
            let v = self.lru_head as usize;
            let last = self.s[v].last_use_ns;
            if last == 0 {
                self.s[v].last_use_ns = now;
                self.lru_append(v);
                continue;
            }
            if now < last || now - last < IDLE_CLOSE_NS {
                break;
            }
            let fd = self.detach(v);
            if fd < 0 {
                break;
            }
            out.push(fd);
            closed += 1;
        }
        closed
    }
}

pub fn ampr_index_fd_cache_release_open_fd_headroom(reserve: usize, cap: usize) {
    let cap = if cap == usize::MAX {
        cache_effective_cap()
    } else {
        cap
    };
    let mut out = CloseList::new();
    locked(|st| st.evict_to_cap(&mut out, reserve, cap));
    out.close();
}

/// Evicts idle physical fds until `reserve` more opens fit the budget.
pub fn ampr_index_fd_cache_release_open_fd_budget_headroom(reserve: usize) -> bool {
    let mut out = CloseList::new();
    let ok = locked(|st| {
        st.evict_budget_headroom(&mut out, reserve);
        st.phys_open + uncached_open() + reserve <= ampr_index_fd_open_budget_effective_cap()
    });
    out.close();
    ok
}

/// True if `reserve` more opens fit the budget, counting idle fds as
/// reclaimable. Out pointers may be null.
pub unsafe fn ampr_index_fd_common_open_budget_headroom_available(
    reserve: usize,
    out_observed: *mut usize,
    out_budget: *mut usize,
    out_evictable: *mut usize,
) -> bool {
    locked(|st| {
        let budget = ampr_index_fd_open_budget_effective_cap();
        let observed = st.phys_open + uncached_open();
        unsafe {
            if !out_observed.is_null() {
                *out_observed = observed
            }
            if !out_budget.is_null() {
                *out_budget = budget
            }
            if !out_evictable.is_null() {
                *out_evictable = st.phys_evictable
            }
        }
        observed + reserve <= budget || st.phys_evictable >= observed + reserve - budget
    })
}

pub fn ampr_index_fd_cache_release_idle_percent(percent: c_uint) -> usize {
    let mut out = CloseList::new();
    let n = locked(|st| st.evict_idle_percent(&mut out, percent));
    out.close();
    n
}

/// Rate-limits idle scans to one per IDLE_SCAN_NS unless forced.
fn idle_scan_allowed(now: u64, force: bool) -> bool {
    if force {
        LAST_IDLE_SCAN.store(now, Relaxed);
        return true;
    }
    LAST_IDLE_SCAN
        .try_update(Relaxed, Relaxed, |last| {
            (last == 0 || now < last || now - last >= IDLE_SCAN_NS).then_some(now)
        })
        .is_ok()
}

fn release_stale(force: bool, now: u64) -> usize {
    let now = if now == 0 { monotonic_ns() } else { now };
    if now == 0 || !idle_scan_allowed(now, force) {
        return 0;
    }
    let mut out = CloseList::new();
    let n = locked(|st| st.evict_stale(&mut out, now));
    out.close();
    n
}

pub fn ampr_index_fd_cache_release_stale(now_ns: u64) -> usize {
    release_stale(false, now_ns)
}

// ---- acquire / release ---------------------------------------------------

/// `ampr_open_indexed_or_real`: packed virtual fd, else a real open (sets
/// `physical` even on failure). Errors are in the SCE domain. None: no
/// fd-budget headroom for the real open, checked before the syscall.
unsafe fn open_indexed_or_real(
    id: u32,
    entry: *const FileEntryView,
    flags: c_int,
    mode: SceKernelMode,
    physical: &mut bool,
) -> Option<c_int> {
    *physical = false;
    let mut handled = false;
    let fd = unsafe { ampr_pack_try_open_indexed(id, entry, flags, mode, &mut handled) };
    if handled {
        return Some(fd);
    }
    if !ampr_index_fd_cache_release_open_fd_budget_headroom(1) {
        return None;
    }
    *physical = true;
    let fd = unsafe { real_posix_open((*entry).path, flags, mode) };
    if fd >= 0 {
        return Some(fd);
    }
    Some(if fd == -1 {
        sce_errno_from_posix(errno())
    } else {
        fd
    })
}

/// Returns a pinned cached fd for file `id`, opening it when `allow_open`
/// and the cache has room. Errors are negative POSIX errno (-EAGAIN when
/// the caller should retry after a pin is released).
pub unsafe fn ampr_index_acquire_cached_fd(
    _job_id: u64,
    id: u32,
    entry: *const FileEntryView,
    flags: c_int,
    mode: c_int,
    allow_open: bool,
) -> c_int {
    if unsafe { (*entry).path.is_null() } {
        return -ENOENT;
    }
    let mut out = CloseList::new();
    let (hit, may_open) = locked(|st| {
        if let Some(i) = st.find(id).filter(|&i| st.s[i].fd >= 0) {
            st.pin(i);
            st.evict_to_cap(&mut out, 0, cache_effective_cap());
            st.evict_watermark(&mut out, 0);
            return (st.s[i].fd, false);
        }
        if !allow_open {
            return (-1, false);
        }
        st.evict_to_cap(&mut out, 1, cache_effective_cap());
        st.evict_watermark(&mut out, 1);
        (-1, st.open < cache_effective_cap())
    });
    out.close();
    if hit >= 0 {
        return hit;
    }
    if !may_open {
        return -EAGAIN;
    }

    let mut physical = false;
    let Some(opened) =
        (unsafe { open_indexed_or_real(id, entry, flags, mode as SceKernelMode, &mut physical) })
    else {
        // Our own soft budget, not a kernel EMFILE: skip caching, no pressure path.
        return -EAGAIN;
    };
    if opened < 0 {
        let err = posix_errno_from_sce(opened);
        if physical && posix_errno_is_fd_open_pressure(err) {
            ampr_index_fd_cache_mark_open_pressure(
                ampr_index_fd_cache_stats().open + uncached_open(),
            );
            release_stale(true, 0);
            ampr_index_fd_cache_release_idle_percent(OPEN_PRESSURE_IDLE_CLOSE_PERCENT);
        }
        return -err;
    }

    let mut close_opened = false;
    let fd = locked(|st| {
        let mut reclaimed = -1;
        let slot = st.create(id, &mut reclaimed);
        if reclaimed >= 0 {
            out.push(reclaimed);
        }
        let Some(i) = slot else {
            // Every slot is pinned by in-flight AIO: transient, retry later.
            close_opened = true;
            return -EAGAIN;
        };
        st.pin(i);
        let fd = if st.s[i].fd >= 0 {
            close_opened = true; // raced with another open of the same file
            st.s[i].fd
        } else {
            st.note_open(i, opened, physical);
            opened
        };
        st.evict_to_cap(&mut out, 0, cache_effective_cap());
        fd
    });
    if close_opened {
        unsafe { sceKernelClose(opened) };
    }
    out.close();
    fd
}

/// Drops one pin taken by `ampr_index_acquire_cached_fd` and stamps last use.
pub fn ampr_index_release_cached_fd_pin(file_id: u32) {
    if file_id == 0 {
        return;
    }
    let now = monotonic_ns();
    let mut out = CloseList::new();
    locked(|st| {
        let Some(i) = st.find(file_id) else { return };
        if now != 0 {
            st.s[i].last_use_ns = now;
        }
        st.unpin(i);
        st.evict_to_cap(&mut out, 0, cache_effective_cap());
    });
    out.close();
}
