//! The emulator-owned CPU pool (one page-aligned .bss buffer, best-fit chunk
//! list), the small/exact slab on top of it, and no-op stubs for the stripped
//! debug and command logging backends.
#![allow(non_snake_case)]

use super::sync::{spin_pause_or_yield, SpinLock, SyncCell};
use super::sys::*;
use core::ffi::{c_char, c_void, CStr};
use core::ptr::{null, null_mut};

// ---- internal AMM pool ---------------------------------------------------

/// Pool size from the Makefile's `AMPR_INTERNAL_POOL_SIZE` (release) and
/// `AMPR_DEBUG_POOL_SIZE` (debug), decimal or 0x hex, optional C `ull`
/// suffix; `DEFAULT_POOL_SIZE` if unset. Rounded up to a page multiple.
/// All runtime memory is in it: the pool is .bss and did not lower the
/// game's free direct memory (measured with the former debug /metrics
/// direct memory lines).
///
/// Layout: the Index, Cache and Buffer ledgers (rt/index_memory.rs,
/// 55 + 32 + 28 MiB caps) and `POOL_SITES_BUDGET` (2 MiB) for these fixed
/// sites with their largest live size:
/// - small slab (`sdk_alloc` up to a page): at most 64 blocks of 16 KiB,
///   1 MiB; its users are the getdents buffer up to 16 KiB and the
///   decode-on-access chunk states, 2 KiB per mapping (pack/mmap_fault.rs
///   `STATES_MAX`, 64 mappings, 128 KiB);
/// - the index writer's buffer, 256 KiB, one (rt/index.rs `BufWriter`);
/// - a getdents buffer over 16 KiB, at most 64 KiB, one (rt/index.rs
///   `DENTS_POOL_MAX`; a larger st_blksize takes index memory);
/// - the disk cache copy piece, 256 KiB, one under CACHE_M
///   (pack/mmap.rs `PIECE`).
/// Sites sum: 1.56 MiB (`POOL_SITES_MAX`); the caps plus the budget, 117 MiB,
/// are checked against the pool at build time (index_memory.rs).
pub(crate) const STATIC_POOL_SIZE: usize = {
    let v = match option_env!("AMPR_INTERNAL_POOL_SIZE") {
        Some(s) => parse_size(s.as_bytes()),
        None => DEFAULT_POOL_SIZE,
    };
    (v + SCE_KERNEL_PAGE_SIZE - 1) / SCE_KERNEL_PAGE_SIZE * SCE_KERNEL_PAGE_SIZE
};

/// The Makefile's `AMPR_DEBUG_POOL_SIZE`, the smaller of the two pools, so
/// host tests check the tighter fit.
pub(crate) const DEFAULT_POOL_SIZE: usize = 0x750_8000;

/// Compile-time number parser (Makefile knobs); a malformed value fails the build.
pub(crate) const fn parse_size(s: &[u8]) -> usize {
    let (mut i, radix) = if s.len() > 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        (2, 16)
    } else {
        (0, 10)
    };
    let mut v: usize = 0;
    let mut digits = 0;
    while i < s.len() {
        let c = s[i];
        let d = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as usize,
            b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as usize,
            b'u' | b'U' | b'l' | b'L' => break,
            _ => panic!("AMPR_INTERNAL_POOL_SIZE: bad digit"),
        };
        v = v * radix + d;
        digits += 1;
        i += 1;
    }
    assert!(
        digits > 0 && v > 0,
        "AMPR_INTERNAL_POOL_SIZE: empty or zero"
    );
    v
}
const _: () = assert!(STATIC_POOL_SIZE % SCE_KERNEL_PAGE_SIZE == 0);

/// The fixed pool sites above, largest live bytes each.
pub(crate) const POOL_SITES: [(&str, usize); 4] = [
    ("small slab", SMALL_SLAB_BLOCKS * SCE_KERNEL_PAGE_SIZE),
    ("index writer", super::index::BUF_WRITER_SIZE),
    ("getdents", super::index::DENTS_POOL_MAX),
    ("disk cache piece", super::pack::mmap::PIECE),
];
pub(crate) const POOL_SITES_MAX: usize = {
    let mut sum = 0;
    let mut i = 0;
    while i < POOL_SITES.len() {
        sum += POOL_SITES[i].1;
        i += 1;
    }
    sum
};
/// Pool room set aside for the fixed sites: 2 MiB, 1.56 MiB used, the rest
/// for page rounding and fragmentation between them.
pub(crate) const POOL_SITES_BUDGET: usize = 2 << 20;
const _: () = assert!(POOL_SITES_MAX <= POOL_SITES_BUDGET);
const MAX_CHUNKS: usize = 512;
const NIL: i32 = -1;

#[repr(C, align(16384))]
struct StaticPool([u8; STATIC_POOL_SIZE]);
const _: () = assert!(core::mem::align_of::<StaticPool>() == SCE_KERNEL_PAGE_SIZE);
static STATIC_POOL: SyncCell<StaticPool> = SyncCell::new(StaticPool([0; STATIC_POOL_SIZE]));

#[derive(Clone, Copy)]
struct Chunk {
    offset: usize,
    size: usize,
    prev: i32,
    next: i32,
    active: bool,
    free: bool,
    /// Allocation tag of a used chunk (null for the small slab).
    tag: *const c_char,
}
const CHUNK0: Chunk = Chunk {
    offset: 0,
    size: 0,
    prev: NIL,
    next: NIL,
    active: false,
    free: false,
    tag: null(),
};

/// Bytes per allocation tag (`tag_totals`); the last slot also takes overflow.
pub(crate) type TagTotals = [(*const c_char, usize); 16];
const TAGS0: TagTotals = [(null(), 0); 16];

struct Pool {
    ready: bool,
    initializing: bool,
    base: *mut u8,
    size: usize,
    apr_visible: bool,
    head: i32,
    used: usize,
    peak: usize,
    chunks: [Chunk; MAX_CHUNKS],
    /// mem_report: per-tag bytes at the last peak snapshot (every 1 MiB of
    /// new peak) and the peak it was taken at.
    peak_tags: TagTotals,
    peak_tags_at: usize,
}

static POOL_LOCK: SpinLock = SpinLock::new();
static POOL: SyncCell<Pool> = SyncCell::new(Pool {
    ready: false,
    initializing: false,
    base: null_mut(),
    size: 0,
    apr_visible: false,
    head: NIL,
    used: 0,
    peak: 0,
    chunks: [CHUNK0; MAX_CHUNKS],
    peak_tags: TAGS0,
    peak_tags_at: 0,
});

/// (bytes in use, peak bytes in use, pool size); read by the mem_report build.
#[cfg(any(test, feature = "mem_report"))]
pub(crate) fn pool_usage() -> (usize, usize, usize) {
    let _g = POOL_LOCK.lock();
    let p = unsafe { pool() };
    (p.used, p.peak, STATIC_POOL_SIZE)
}

/// (bytes per tag in use now, bytes per tag at the peak); mem_report only.
#[cfg(feature = "mem_report")]
pub(crate) fn pool_tags() -> (TagTotals, TagTotals) {
    let _g = POOL_LOCK.lock();
    let p = unsafe { pool() };
    (p.tag_totals(), p.peak_tags)
}

/// Pool state; caller holds POOL_LOCK.
unsafe fn pool() -> &'static mut Pool {
    unsafe { &mut *POOL.get() }
}

fn static_pool_base() -> *mut u8 {
    STATIC_POOL.get().cast()
}

/// Rounds up to a power-of-two `a` (0 = unchanged); usize::MAX on bad input/overflow.
fn align_up(v: usize, a: usize) -> usize {
    if a == 0 {
        return v;
    }
    if !a.is_power_of_two() {
        return usize::MAX;
    }
    match v.checked_add(a - 1) {
        Some(x) => x & !(a - 1),
        None => usize::MAX,
    }
}

/// Pool allocations are at least page aligned; usize::MAX if not a power of two.
fn pool_alignment(a: usize) -> usize {
    if a < SCE_KERNEL_PAGE_SIZE {
        SCE_KERNEL_PAGE_SIZE
    } else if a.is_power_of_two() {
        a
    } else {
        usize::MAX
    }
}

impl Pool {
    fn tag_totals(&self) -> TagTotals {
        let same = |a: *const c_char, b: *const c_char| {
            a == b
                || (!a.is_null()
                    && !b.is_null()
                    && unsafe { CStr::from_ptr(a) == CStr::from_ptr(b) })
        };
        let mut out = TAGS0;
        let mut n = 0;
        for c in self.chunks.iter().filter(|c| c.active && !c.free) {
            let slot = match out[..n].iter().position(|t| same(t.0, c.tag)) {
                Some(i) => i,
                None if n < out.len() => {
                    out[n].0 = c.tag;
                    n += 1;
                    n - 1
                }
                None => out.len() - 1,
            };
            out[slot].1 += c.size;
        }
        out
    }

    fn new_chunk(&mut self) -> i32 {
        for (i, c) in self.chunks.iter_mut().enumerate() {
            if !c.active {
                *c = Chunk {
                    active: true,
                    ..CHUNK0
                };
                return i as i32;
            }
        }
        NIL
    }

    fn init_chunks(&mut self, size: usize) {
        self.chunks = [CHUNK0; MAX_CHUNKS];
        let h = self.new_chunk();
        self.chunks[h as usize] = Chunk {
            offset: 0,
            size,
            free: true,
            ..self.chunks[h as usize]
        };
        self.head = h;
    }

    /// Offset in free chunk `c` where `size` bytes fit with the absolute
    /// address (base + offset) aligned to `align`; None if they do not fit.
    fn fit_offset(&self, c: &Chunk, size: usize, align: usize) -> Option<usize> {
        if !c.active || !c.free || size == 0 {
            return None;
        }
        let base = self.base as usize;
        let addr = align_up(base.checked_add(c.offset)?, align);
        let end = c.offset.checked_add(c.size)?;
        if addr == usize::MAX {
            return None;
        }
        let ao = addr - base;
        (ao <= end && size <= end - ao).then_some(ao)
    }

    fn has_capacity(&self, size: usize, align: usize) -> bool {
        let align = pool_alignment(align);
        if align == usize::MAX {
            return false;
        }
        let mut i = self.head;
        while i >= 0 {
            if self
                .fit_offset(&self.chunks[i as usize], size, align)
                .is_some()
            {
                return true;
            }
            i = self.chunks[i as usize].next;
        }
        false
    }
}

impl Pool {
    /// Best-fit split of the smallest free chunk that fits; null if none.
    fn alloc(&mut self, mapped: usize, align: usize, tag: *const c_char) -> *mut u8 {
        let (mut sel, mut sel_ao, mut sel_usable) = (NIL, 0usize, usize::MAX);
        let mut i = self.head;
        while i >= 0 {
            let c = self.chunks[i as usize];
            if let Some(ao) = self.fit_offset(&c, mapped, align) {
                let usable = c.offset + c.size - ao;
                if usable < sel_usable {
                    (sel, sel_ao, sel_usable) = (i, ao, usable);
                }
            }
            i = c.next;
        }
        if sel < 0 {
            return null_mut();
        }
        let s = sel as usize;
        let Chunk {
            offset: old_off,
            size: old_size,
            next: old_next,
            prev: old_prev,
            ..
        } = self.chunks[s];
        let alloc_end = sel_ao + mapped;
        let prefix = sel_ao - old_off;
        let suffix = old_off + old_size - alloc_end;
        let mut a = sel;
        if prefix != 0 {
            a = self.new_chunk();
            if a < 0 {
                return null_mut();
            }
            self.chunks[s].size = prefix;
            self.chunks[s].free = true;
            self.chunks[a as usize].prev = sel;
            self.chunks[a as usize].next = old_next;
            self.chunks[s].next = a;
            if old_next >= 0 {
                self.chunks[old_next as usize].prev = a;
            }
        }
        let mut sfx = NIL;
        if suffix != 0 {
            sfx = self.new_chunk();
            if sfx < 0 {
                if prefix != 0 {
                    self.chunks[s].next = old_next;
                    self.chunks[s].size = old_size;
                    if old_next >= 0 {
                        self.chunks[old_next as usize].prev = sel;
                    }
                    self.chunks[a as usize] = CHUNK0;
                }
                return null_mut();
            }
        }
        let ac = &mut self.chunks[a as usize];
        ac.offset = sel_ao;
        ac.size = mapped;
        ac.free = false;
        ac.tag = tag;
        if prefix == 0 {
            ac.prev = old_prev;
            ac.next = old_next;
        }
        if sfx >= 0 {
            ac.next = sfx;
            self.chunks[sfx as usize] = Chunk {
                offset: alloc_end,
                size: suffix,
                free: true,
                prev: a,
                next: old_next,
                active: true,
                tag: null(),
            };
            if old_next >= 0 {
                self.chunks[old_next as usize].prev = sfx;
            }
        }
        unsafe { self.base.add(sel_ao) }
    }

    /// Frees the used chunk starting at `p` and merges free neighbours.
    fn free(&mut self, p: *mut u8) -> bool {
        let base = self.base as usize;
        let addr = p as usize;
        if !self.ready || self.base.is_null() || addr < base || addr >= base + self.size {
            return false;
        }
        let off = addr - base;
        let mut cur = self.head;
        while cur >= 0 {
            let c = &self.chunks[cur as usize];
            if c.active && !c.free && c.offset == off {
                break;
            }
            cur = c.next;
        }
        if cur < 0 {
            return false;
        }
        self.chunks[cur as usize].free = true;
        let c = self.chunks[cur as usize];
        self.used = self.used.saturating_sub(c.size);
        if c.prev >= 0 && self.chunks[c.prev as usize].active && self.chunks[c.prev as usize].free {
            let pc = &mut self.chunks[c.prev as usize];
            pc.size += c.size;
            pc.next = c.next;
            if c.next >= 0 {
                self.chunks[c.next as usize].prev = c.prev;
            }
            self.chunks[cur as usize] = CHUNK0;
            cur = c.prev;
        }
        let m = self.chunks[cur as usize];
        if m.next >= 0 && self.chunks[m.next as usize].active && self.chunks[m.next as usize].free {
            let n = self.chunks[m.next as usize];
            self.chunks[cur as usize].size += n.size;
            self.chunks[cur as usize].next = n.next;
            if n.next >= 0 {
                self.chunks[n.next as usize].prev = cur;
            }
            self.chunks[m.next as usize] = CHUNK0;
        }
        true
    }
}

pub unsafe fn ampr_internal_amm_pool_ready_has_capacity(size: usize, align: usize) -> bool {
    let _g = POOL_LOCK.lock();
    let p = unsafe { pool() };
    p.ready && !p.base.is_null() && p.has_capacity(size, align)
}

/// Publishes the static .bss pool on first use (mprotect CPU_RW | AMPR_ALL).
pub unsafe fn ampr_internal_amm_pool_ensure(required: usize, _reason: *const c_char) -> bool {
    let req = align_up(required, SCE_KERNEL_PAGE_SIZE);
    if req == 0 || req == usize::MAX {
        return false;
    }
    {
        let _g = POOL_LOCK.lock();
        let p = unsafe { pool() };
        if p.ready {
            return p.has_capacity(req, SCE_KERNEL_PAGE_SIZE);
        }
    }
    if req > STATIC_POOL_SIZE {
        return false;
    }
    let mut spins = 0u32;
    loop {
        {
            let _g = POOL_LOCK.lock();
            let p = unsafe { pool() };
            if p.ready {
                return p.has_capacity(req, SCE_KERNEL_PAGE_SIZE);
            }
            if !p.initializing {
                p.initializing = true;
                break;
            }
        }
        spin_pause_or_yield(&mut spins);
    }
    let prot = SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL;
    // Host tests have no kernel; the .bss is already read-write there.
    let rc = if cfg!(test) {
        0
    } else {
        unsafe { real_mprotect(static_pool_base() as *const c_void, STATIC_POOL_SIZE, prot) }
    };
    let _g = POOL_LOCK.lock();
    let p = unsafe { pool() };
    p.initializing = false;
    if rc != 0 {
        return false;
    }
    p.init_chunks(STATIC_POOL_SIZE);
    p.base = static_pool_base();
    p.size = STATIC_POOL_SIZE;
    p.apr_visible = true;
    p.ready = true;
    true
}

pub unsafe fn ampr_internal_amm_pool_prepare_static_storage(reason: *const c_char) -> bool {
    {
        let _g = POOL_LOCK.lock();
        let p = unsafe { pool() };
        if p.ready {
            return p.base == static_pool_base() && p.apr_visible;
        }
    }
    unsafe { ampr_internal_amm_pool_ensure(SCE_KERNEL_PAGE_SIZE, reason) }
}

/// Page-aligned (or stricter) pool allocation; `*out_size` = rounded size.
/// A null result counts in /metrics `pool_alloc_failed`
/// (rt/index_memory.rs `note_pool_failure`).
pub unsafe fn ampr_internal_amm_pool_alloc(
    size: usize,
    out_size: *mut usize,
    tag: *const c_char,
    may_create: bool,
    align: usize,
) -> *mut c_void {
    let p = unsafe { ampr_internal_amm_pool_try_alloc(size, out_size, tag, may_create, align) };
    if p.is_null() && size != 0 {
        super::index_memory::note_pool_failure();
    }
    p
}

/// `ampr_internal_amm_pool_alloc` without the failure count. Publishes the
/// pool on first use: the eager pack index load and the cache carve run
/// before anything else asks for it, and an unpublished pool failed the
/// startup carve (pool_alloc_failed 1, caches off, 12 of 64 MiB used;
/// debug /metrics).
unsafe fn ampr_internal_amm_pool_try_alloc(
    size: usize,
    out_size: *mut usize,
    tag: *const c_char,
    _may_create: bool,
    align: usize,
) -> *mut c_void {
    if !out_size.is_null() {
        unsafe { *out_size = 0 };
    }
    if size == 0 {
        return null_mut();
    }
    let align = pool_alignment(align);
    let mapped = if align != usize::MAX {
        align_up(size, align)
    } else {
        usize::MAX
    };
    if mapped == usize::MAX || !unsafe { ampr_internal_amm_pool_prepare_static_storage(null()) } {
        return null_mut();
    }
    let ptr = {
        let _g = POOL_LOCK.lock();
        let p = unsafe { pool() };
        if !p.ready || p.base.is_null() {
            null_mut()
        } else {
            let ptr = p.alloc(mapped, align, tag);
            if !ptr.is_null() {
                p.used += mapped;
                p.peak = p.peak.max(p.used);
                if cfg!(feature = "mem_report") && p.peak >= p.peak_tags_at + (1 << 20) {
                    p.peak_tags_at = p.peak;
                    p.peak_tags = p.tag_totals();
                }
            }
            ptr
        }
    };
    if !ptr.is_null() && !out_size.is_null() {
        unsafe { *out_size = mapped };
    }
    ptr.cast()
}

pub unsafe fn ampr_internal_amm_pool_free(ptr: *mut c_void, _tag: *const c_char) -> bool {
    if ptr.is_null() {
        return false;
    }
    let _g = POOL_LOCK.lock();
    unsafe { pool() }.free(ptr.cast())
}

// ---- SDK CPU memory class (stats were log-only) ----------------------------

pub unsafe fn ampr_sdk_cpu_memory_class_name(class: u8) -> *const c_char {
    if class == 1 {
        c"transient".as_ptr()
    } else {
        c"persistent".as_ptr()
    }
}

// ---- exact slab ----------------------------------------------------------

const SLAB_NIL: u32 = u32::MAX;

/// One pool-backed block of equal slots; free slots hold the next free index.
#[derive(Clone, Copy)]
struct SlabBlock {
    base: *mut u8,
    slot_size: usize,
    slot_count: u32,
    free_head: u32,
    free_count: u32,
    active: bool,
}
const BLOCK0: SlabBlock = SlabBlock {
    base: null_mut(),
    slot_size: 0,
    slot_count: 0,
    free_head: SLAB_NIL,
    free_count: 0,
    active: false,
};

impl SlabBlock {
    unsafe fn slot(&self, i: u32) -> *mut u32 {
        unsafe { self.base.add(i as usize * self.slot_size) }.cast()
    }

    unsafe fn take(&mut self) -> Option<(*mut u8, usize)> {
        let i = self.free_head;
        if i == SLAB_NIL || i >= self.slot_count {
            return None;
        }
        let s = unsafe { self.slot(i) };
        self.free_head = unsafe { *s };
        self.free_count -= 1;
        Some((s.cast(), self.slot_size))
    }

    unsafe fn is_free(&self, idx: u32) -> bool {
        let mut cur = self.free_head;
        let mut steps = 0;
        while cur != SLAB_NIL && steps < self.slot_count {
            if cur == idx {
                return true;
            }
            if cur >= self.slot_count {
                return false;
            }
            cur = unsafe { *self.slot(cur) };
            steps += 1;
        }
        false
    }
}

/// `AmprSharedExactSlabPool` with a fixed block table.
pub struct ExactSlab<const N: usize> {
    lock: SpinLock,
    blocks: SyncCell<[SlabBlock; N]>,
}

impl<const N: usize> ExactSlab<N> {
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            blocks: SyncCell::new([BLOCK0; N]),
        }
    }

    /// Caller holds `self.lock`.
    unsafe fn blocks(&self) -> &mut [SlabBlock; N] {
        unsafe { &mut *self.blocks.get() }
    }

    unsafe fn take_locked(&self, slot: usize) -> Option<(*mut u8, usize)> {
        let b = unsafe { self.blocks() }
            .iter_mut()
            .find(|b| b.active && b.slot_size == slot && b.free_head != SLAB_NIL)?;
        unsafe { b.take() }
    }

    /// Carves a fresh block into slots; None if the table is full.
    unsafe fn publish_locked(
        &self,
        slot: usize,
        base: *mut u8,
        bytes: usize,
    ) -> Option<&mut SlabBlock> {
        let b = unsafe { self.blocks() }
            .iter_mut()
            .find(|b| !b.active && b.base.is_null())?;
        let count = bytes / slot;
        if base.is_null() || count == 0 || count > u32::MAX as usize {
            return None;
        }
        *b = SlabBlock {
            base,
            slot_size: slot,
            slot_count: count as u32,
            free_head: 0,
            free_count: count as u32,
            active: true,
        };
        for i in 0..b.slot_count {
            unsafe {
                *b.slot(i) = if i + 1 < b.slot_count {
                    i + 1
                } else {
                    SLAB_NIL
                }
            };
        }
        Some(b)
    }

    /// `ampr_exact_slab_alloc`: slot of `align_up(size, align)` bytes; (ptr, slot size).
    pub unsafe fn alloc(
        &self,
        size: usize,
        align: usize,
        min_block: usize,
        may_create: bool,
    ) -> Option<(*mut u8, usize)> {
        let slot = align_up(size, align);
        if slot == usize::MAX || slot < 4 {
            return None;
        }
        {
            let _g = self.lock.lock();
            if let Some(r) = unsafe { self.take_locked(slot) } {
                return Some(r);
            }
        }
        let Some((block, bytes)) = (unsafe { alloc_block(slot, min_block, may_create) }) else {
            let _g = self.lock.lock();
            return unsafe { self.take_locked(slot) };
        };
        let (r, spare) = {
            let _g = self.lock.lock();
            // Another thread may have published a block for this size meanwhile.
            match unsafe { self.take_locked(slot) } {
                Some(r) => (Some(r), block),
                None => match unsafe { self.publish_locked(slot, block, bytes) } {
                    Some(b) => (unsafe { b.take() }, null_mut()),
                    None => (None, block),
                },
            }
        };
        if !spare.is_null() {
            unsafe { ampr_internal_amm_pool_free(spare.cast(), core::ptr::null()) };
        }
        r
    }

    /// `ampr_exact_slab_free`: Some(slot size) if `ptr` was a live slot. A block
    /// that becomes empty goes back to the pool when another empty block of
    /// the same size exists.
    pub unsafe fn free(&self, ptr: *mut u8) -> Option<usize> {
        if ptr.is_null() {
            return None;
        }
        let addr = ptr as usize;
        let (slot, release) = {
            let _g = self.lock.lock();
            let blocks = unsafe { self.blocks() };
            let i = blocks.iter().position(|b| {
                let base = b.base as usize;
                b.active
                    && !b.base.is_null()
                    && b.slot_size != 0
                    && addr >= base
                    && addr < base + b.slot_size * b.slot_count as usize
            })?;
            let b = &mut blocks[i];
            let off = addr - b.base as usize;
            if off % b.slot_size != 0 || b.free_count >= b.slot_count {
                return None;
            }
            let idx = (off / b.slot_size) as u32;
            if unsafe { b.is_free(idx) } {
                return None;
            }
            unsafe { *ptr.cast::<u32>() = b.free_head };
            b.free_head = idx;
            b.free_count += 1;
            let b = blocks[i];
            let mut release = null_mut();
            if b.free_count == b.slot_count {
                let empty_twin = blocks.iter().enumerate().any(|(j, o)| {
                    j != i && o.active && o.slot_size == b.slot_size && o.free_count == o.slot_count
                });
                if empty_twin {
                    release = b.base;
                    blocks[i] = BLOCK0;
                }
            }
            (b.slot_size, release)
        };
        if !release.is_null() {
            unsafe { ampr_internal_amm_pool_free(release.cast(), core::ptr::null()) };
        }
        Some(slot)
    }
}

/// Pool-backed page-rounded block of at least max(slot, min_block) bytes.
unsafe fn alloc_block(slot: usize, min_block: usize, may_create: bool) -> Option<(*mut u8, usize)> {
    let bytes = align_up(slot.max(min_block), SCE_KERNEL_PAGE_SIZE);
    if bytes == 0 || bytes == usize::MAX {
        return None;
    }
    let usable = if may_create {
        unsafe { ampr_internal_amm_pool_ensure(bytes, core::ptr::null()) }
    } else {
        unsafe { ampr_internal_amm_pool_ready_has_capacity(bytes, 16) }
    };
    if !usable {
        return None;
    }
    let mut got = 0usize;
    let p = unsafe {
        ampr_internal_amm_pool_alloc(
            bytes,
            &mut got,
            core::ptr::null(),
            false,
            SCE_KERNEL_PAGE_SIZE,
        )
    };
    if p.is_null() {
        return None;
    }
    if got < bytes {
        unsafe { ampr_internal_amm_pool_free(p, core::ptr::null()) };
        return None;
    }
    Some((p.cast(), got))
}

// ---- small slab (SDK CPU allocations up to a page) -------------------------

const SMALL_CLASSES: [usize; 4] = [256, 1024, 2048, SCE_KERNEL_PAGE_SIZE];
const SMALL_SLAB_BLOCKS: usize = 64;
static SMALL_SLAB: ExactSlab<SMALL_SLAB_BLOCKS> = ExactSlab::new();

pub unsafe fn ampr_small_slab_alloc(
    size: usize,
    align: usize,
    out_slot: *mut usize,
    _tag: *const c_char,
    may_create: bool,
) -> *mut c_void {
    if !out_slot.is_null() {
        unsafe { *out_slot = 0 };
    }
    let align = align.max(1);
    if size == 0 || !align.is_power_of_two() {
        return null_mut();
    }
    let Some(&slot) = SMALL_CLASSES.iter().find(|&&s| size <= s && align <= s) else {
        return null_mut();
    };
    match unsafe { SMALL_SLAB.alloc(slot, slot, SCE_KERNEL_PAGE_SIZE, may_create) } {
        Some((p, s)) => {
            if !out_slot.is_null() {
                unsafe { *out_slot = s };
            }
            p.cast()
        }
        None => null_mut(),
    }
}

pub unsafe fn ampr_small_slab_free(
    ptr: *mut c_void,
    _tag: *const c_char,
    out_slot: *mut usize,
) -> bool {
    let r = unsafe { SMALL_SLAB.free(ptr.cast()) };
    if !out_slot.is_null() {
        unsafe { *out_slot = r.unwrap_or(0) };
    }
    r.is_some()
}

#[cfg(test)]
mod pool_site_tests {
    /// Every pool allocation call in the runtime, with why it is fixed in
    /// size or held under a ledger cap.
    const ALLOWED: [(&str, &str); 10] = [
        // The Index, Cache and Buffer ledgers, each under its cap.
        (
            "rt/index_memory.rs",
            "ampr_internal_amm_pool_alloc(mapped, &mut got, tag, false, SCE_KERNEL_PAGE_SIZE)",
        ),
        // sdk_alloc itself: the small slab, then the pool.
        ("rt/index.rs", "ampr_small_slab_alloc(size, MAX_ALIGN"),
        (
            "rt/index.rs",
            "ampr_internal_amm_pool_alloc(mapped, &mut got, name",
        ),
        // ScratchBuffer, used by the two sites below.
        ("rt/index.rs", "sdk_alloc(size, class)"),
        ("rt/index.rs", "self.buf.allocate(Self::SIZE"),
        ("rt/index.rs", "dents.allocate(size"),
        // The pool's own plumbing: the counted wrapper and slab blocks.
        (
            "rt/runtime_memory.rs",
            "ampr_internal_amm_pool_try_alloc(size, out_size",
        ),
        ("rt/runtime_memory.rs", "ampr_internal_amm_pool_alloc("),
        ("rt/pack/mmap.rs", "sdk_alloc(PIECE"),
        ("rt/pack/mmap_fault.rs", "sdk_alloc(count"),
    ];
    const CALLS: [&str; 5] = [
        "sdk_alloc(",
        "ampr_internal_amm_pool_alloc(",
        "ampr_internal_amm_pool_try_alloc(",
        "ampr_small_slab_alloc(",
        ".allocate(",
    ];

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// A new pool allocation call fails this test until it is shown to be
    /// fixed in size and added to the sites in the pool's doc comment.
    #[test]
    fn the_pool_only_has_the_listed_fixed_size_sites() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let mut seen = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).unwrap();
            let body = text.split("#[cfg(test)]\nmod ").next().unwrap();
            for line in body.lines() {
                let l = line.trim();
                if l.starts_with("//") || l.contains("fn ") || !CALLS.iter().any(|c| l.contains(c))
                {
                    continue;
                }
                let hit = ALLOWED
                    .iter()
                    .position(|(file, s)| *file == rel && l.contains(s));
                assert!(hit.is_some(), "unlisted pool allocation: {rel}: {l}");
                seen.push(hit.unwrap());
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..ALLOWED.len()).collect::<Vec<_>>());
    }

    #[test]
    fn the_ledgers_and_the_sites_budget_fit_the_pool() {
        use super::{POOL_SITES, POOL_SITES_BUDGET, POOL_SITES_MAX, STATIC_POOL_SIZE};
        use crate::rt::index_memory::LEDGER_MEMORY_MAX;
        assert_eq!(
            POOL_SITES_MAX,
            (1 << 20) + (256 << 10) + (64 << 10) + (256 << 10)
        );
        assert!(POOL_SITES_MAX <= POOL_SITES_BUDGET);
        assert!(LEDGER_MEMORY_MAX + POOL_SITES_BUDGET <= STATIC_POOL_SIZE);
        assert_eq!(POOL_SITES.len(), 4);
    }
}
