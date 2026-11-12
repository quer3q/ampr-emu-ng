//! zstd packs, Makefile `AMPR_ZSTD_MMAP=1`: decode on access. Only zstd
//! packs are served here: the fault path reads zstd chunk records and their
//! fixed 256 KiB geometry, so a map of an LZ4 (AMPRPAK4) packed file takes
//! the disk fallback in rt/pack/mmap.rs (`try_map` returns Fallback). An
//! mmap of a zstd virtual pack fd reserves the range as anonymous PROT_NONE
//! memory and registers it here; nothing is decoded until the game touches a page.
//! The SIGSEGV/SIGBUS handler (installed once, on the first such mmap,
//! chaining to the previous handlers for any other address) finds the
//! 256 KiB chunks behind the faulting 16 KiB page, reads them with the
//! original pread on a private volume fd, decodes them into a scratch slot,
//! makes the pages RW, copies, sets the caller's prot and returns so the
//! instruction re-executes. The handler takes no pack lock, runtime mutex
//! or allocation: the faulting thread may hold any of them.
//!
//! rt/pack/mmap.rs sends a mapping to its disk fallback instead when prot
//! has GPU (or AMPR) bits (a GPU fault never reaches a CPU handler), when
//! the offset is not 4 KiB aligned, when the file spans more volumes than
//! `VOLUME_FDS` holds, when the table is full, or when sigaction is missing
//! or fails. A MAP_SHARED map with PROT_WRITE of a packed file fails with
//! EACCES before either path (`serve`): the file is read-only. A MAP_FIXED
//! map is bracketed by `begin_replace`/`end_replace` in rt/pack/mmap.rs,
//! which free the mappings it replaces.
//!
//! A page holding file bytes opens with them and, past the last byte, a
//! zero tail. A fault on a page wholly past the end of the file leaves it
//! closed and chains to the previous handler, so the game gets the SIGBUS
//! (or SIGSEGV) a real file mapping raises there (`past_end`).
//!
//! Opt-in and unverified: no measured game mmapped a packed file
//! (three fully packed games on a console: mmap_virtual 0), so this path
//! has never served a game. The Makefile default is 2, the disk cache
//! (rt/pack/mmap.rs), a kernel file mapping.
//!
//! A write or exec fault on a page already open (every chunk behind it
//! READY) is an access the mapping prot does not allow. It used to be
//! retried forever; now it retries once (it may be a race with the thread
//! that opened the page) and its repeat chains to the previous handler,
//! so the game gets its SIGSEGV (`Strikes`).
//!
//! Known limits, unsolved:
//! - mprotect and sceKernelMprotect on a decode-on-access range are not
//!   tracked: a page the game opens before its first touch shows zeros
//!   (no fault reaches us), and a later fill sets the prot of the mmap
//!   call over the game's change.
//! - The handler runs on the faulting thread's stack (no sigaltstack):
//!   pread, a zstd decode and mprotect there can overflow a small-stack
//!   thread, the small-stack crash class rt/pack/fd_read.rs avoids with
//!   its read threads.
//! - A range replaced by a VM call we do not hook (e.g. a MAP_FIXED map
//!   through another entry point) stays registered: a later fault there is
//!   taken for ours.
//! - The handler stays installed after module_stop.
//! - A syscall given an untouched page of such a mapping (read into it,
//!   write from it) gets EFAULT, since no fault reaches us.
//! - While a chunk is copied its pages are RW, so another thread touching
//!   them in that window (a copy of 256 KiB) can read bytes not yet
//!   written.
//! - A munmap that overlaps a mapping at all unregisters all of it: a
//!   later fault on a page left mapped goes to the previous handler.
//! - A game that replaces our SIGSEGV/SIGBUS handler after the first map
//!   takes those faults itself.
//!
//! Memory, only after the game maps a packed file with the knob at 1:
//! `SLOTS` x 512 KiB scratch (2 MiB, Index ledger) plus a 112 KiB zstd
//! decoder workspace each (448 KiB, Buffer ledger), persistent; one byte per mapped chunk from the
//! small slab, transient, released on munmap. Unmeasured on a console (Makefile).

use super::super::index::{sdk_alloc, sdk_release, title_alloc, title_free, MEM_TRANSIENT};
use super::zstd::{zstd_chunk_resident, zstd_chunks_resident, zstd_entry, zstd_index};
use super::*;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize};

// ---- page and chunk math ------------------------------------------------------

const PAGE: u64 = SCE_KERNEL_PAGE_SIZE as u64;
const CHUNK_SHIFT: u32 = ampr_format::zstd::CHUNK_SHIFT as u32;
const CHUNK: u64 = 1 << CHUNK_SHIFT;

/// File chunks `first..=last` behind page `page` of a mapping of the file
/// from byte `map_off`, clipped to `file_size`; None for a page wholly past
/// the end of the file. An unaligned `map_off` makes a page span two chunks.
fn page_chunks(map_off: u64, page: u64, file_size: u64) -> Option<(u64, u64)> {
    let begin = map_off.checked_add(page.checked_mul(PAGE)?)?;
    if begin >= file_size {
        return None;
    }
    let end = begin.saturating_add(PAGE).min(file_size);
    Some((begin >> CHUNK_SHIFT, (end - 1) >> CHUNK_SHIFT))
}

/// Page `page` of a mapping of the file from byte `map_off` holds no byte
/// of the file: a fault there chains (a real file mapping raises SIGBUS),
/// while a page partly inside keeps its zero tail.
fn past_end(map_off: u64, page: u64, file_size: u64) -> bool {
    page_chunks(map_off, page, file_size).is_none()
}

/// Mapping pages `first..end` that hold bytes of file chunk `chunk`, for a
/// mapping of `pages` pages of the file from byte `map_off`; empty when the
/// chunk is outside the mapping.
fn chunk_pages(map_off: u64, pages: u64, chunk: u64, file_size: u64) -> (u64, u64) {
    let map_end = map_off.saturating_add(pages * PAGE).min(file_size);
    let begin = (chunk << CHUNK_SHIFT).max(map_off);
    let end = ((chunk + 1) << CHUNK_SHIFT).min(map_end);
    if begin >= end {
        return (0, 0);
    }
    ((begin - map_off) / PAGE, (end - map_off).div_ceil(PAGE))
}

/// File chunks a mapping of `len` bytes from `map_off` covers:
/// `first..first + count`; count 0 when the mapping starts past the end.
fn mapping_chunks(map_off: u64, len: u64, file_size: u64) -> (u64, u64) {
    let end = map_off.saturating_add(len).min(file_size);
    if map_off >= end {
        return (map_off >> CHUNK_SHIFT, 0);
    }
    let first = map_off >> CHUNK_SHIFT;
    (first, ((end - 1) >> CHUNK_SHIFT) - first + 1)
}

// ---- chunk state --------------------------------------------------------------

const EMPTY: u8 = 0;
const FILLING: u8 = 1;
const READY: u8 = 2;
/// Read or decode failed; the mapping fails with it.
const FAILED: u8 = 3;

/// What a faulting thread does with one chunk.
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// It moved EMPTY -> FILLING and must fill the chunk.
    Fill,
    Ready,
    Failed,
}

/// Claims `s` for filling, or waits (spinning) while another thread fills.
fn claim(s: &AtomicU8) -> Claim {
    let mut spins = 0u32;
    loop {
        match s.compare_exchange(EMPTY, FILLING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => return Claim::Fill,
            Err(READY) => return Claim::Ready,
            Err(FILLING) => backoff(&mut spins),
            Err(_) => return Claim::Failed,
        }
    }
}

/// A wait inside the handler: spin, then 1 us sleeps (rt/sync.rs
/// `spin_pause_or_yield`, a syscall, safe there). Host tests yield instead.
fn backoff(spins: &mut u32) {
    #[cfg(test)]
    {
        let _ = spins;
        std::thread::yield_now();
    }
    #[cfg(not(test))]
    spin_pause_or_yield(spins);
}

/// FILLING -> READY or FAILED, by the thread that claimed it.
fn finish(s: &AtomicU8, ok: bool) {
    s.store(if ok { READY } else { FAILED }, Ordering::Release);
}

// ---- volume fds ---------------------------------------------------------------

/// Volumes the handler reads, opened outside it on the first map of a file
/// on them and kept to exit. Not the pack leases (rt/pack/leases.rs): those
/// take PACK_M, which the faulting thread may hold.
const VOLUME_FDS: usize = 16;
static VOL_IDS: [AtomicU32; VOLUME_FDS] = [const { AtomicU32::new(u32::MAX) }; VOLUME_FDS];
static VOL_FDS: [AtomicI32; VOLUME_FDS] = [const { AtomicI32::new(-1) }; VOLUME_FDS];
static VOL_USED: AtomicUsize = AtomicUsize::new(0);
/// The original pread, cached before the first mapping is registered.
static PREAD: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Handler side, lock-free: the open fd of `volume`, or -1.
fn volume_fd(volume: u16) -> c_int {
    let used = VOL_USED.load(Ordering::Acquire);
    (0..used)
        .find(|&i| VOL_IDS[i].load(Ordering::Relaxed) == u32::from(volume))
        .map_or(-1, |i| VOL_FDS[i].load(Ordering::Relaxed))
}

/// Under FAULT_M: opens volumes `first..=last` not open yet; false when
/// VOLUME_FDS cannot hold them or an open fails.
unsafe fn open_volumes(first: u16, last: u16) -> bool {
    let Some(open) = (unsafe { real_open() }) else {
        return false;
    };
    for volume in first..=last {
        if volume_fd(volume) >= 0 {
            continue;
        }
        let used = VOL_USED.load(Ordering::Relaxed);
        let mut path = [0 as c_char; SCE_KERNEL_PATH_MAX];
        if used == VOLUME_FDS
            || !unsafe { build_pack_path(pack_state(), volume, path.as_mut_ptr(), path.len()) }
        {
            return false;
        }
        let fd = unsafe { open(path.as_ptr(), O_RDONLY, 0) };
        if fd < 0 {
            return false;
        }
        VOL_IDS[used].store(u32::from(volume), Ordering::Relaxed);
        VOL_FDS[used].store(fd, Ordering::Relaxed);
        VOL_USED.store(used + 1, Ordering::Release);
    }
    true
}

// ---- scratch slots ------------------------------------------------------------

/// Most chunk states of one mapping, one byte per 256 KiB chunk: 512 MiB.
pub(crate) const STATES_MAX: usize = 2048;

/// Concurrent fills; a fault with every slot busy spins for one.
pub(crate) const SLOTS: usize = 4;
/// Stored bytes (at most one chunk) then the decoded chunk.
const SLOT_BYTES: usize = 2 * CHUNK as usize;
const _: () = assert!(CHUNK as usize == ampr_codec::ZSTD_MAX_CHUNK_SIZE);

struct Slot {
    busy: AtomicBool,
    buf: AtomicPtr<u8>,
    decoder: AtomicPtr<ampr_codec::ZstdDecoder>,
}

static SLOT_TABLE: [Slot; SLOTS] = [const {
    Slot {
        busy: AtomicBool::new(false),
        buf: AtomicPtr::new(null_mut()),
        decoder: AtomicPtr::new(null_mut()),
    }
}; SLOTS];
/// 0 not made, 1 ready, 2 allocation failed (every mapping goes to disk).
static SLOTS_STATE: AtomicU8 = AtomicU8::new(0);

/// Under FAULT_M, on the first fault-path map: the scratch buffers (one
/// 2 MiB block from the Index ledger, rt/index_memory.rs, not a fixed
/// pool site) and a warmed-up decoder per slot (one 448 KiB block of
/// decoder workspaces from the Buffer ledger, not the libc heap), so a
/// fill allocates nothing. False when any allocation fails; what was made
/// is released.
/// The slot decoders are made, so their workspaces are already in the
/// Buffer ledger's use and need no room kept for them.
pub(crate) fn slots_made() -> bool {
    SLOTS_STATE.load(Ordering::Acquire) == 1
}

unsafe fn make_slots() -> bool {
    match SLOTS_STATE.load(Ordering::Acquire) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let block = unsafe { title_alloc(SLOTS * SLOT_BYTES, c"apr.mmap.fault-slots") };
    const WS: usize = ampr_codec::ZSTD_DECODER_WORKSPACE;
    let ws_tag = c"apr.mmap.fault-decoders".as_ptr();
    let (ws, ws_len) = unsafe { crate::rt::index_memory::buffer_alloc(SLOTS * WS, ws_tag) };
    let mut ok = !block.is_null() && ws_len >= SLOTS * WS;
    for (i, slot) in SLOT_TABLE.iter().enumerate() {
        if !ok {
            break;
        }
        let buf = unsafe { block.add(i * SLOT_BYTES) };
        let decoder = unsafe { ampr_codec::ZstdDecoder::init_in(ws.add(i * WS), WS) };
        let Some(decoder) = (unsafe { decoder.as_mut() }) else {
            ok = false;
            break;
        };
        if crate::rt::tune::zstd_verify() {
            let _ = decoder.set_verify_checksum(true);
        }
        let out = unsafe { core::slice::from_raw_parts_mut(buf.add(CHUNK as usize), CHUNK as usize) };
        // A decoder that cannot warm up would fail its first fill; fail the
        // setup instead, so every map takes the disk cache.
        if decoder.warm_up(out).is_err() {
            ok = false;
            break;
        }
        slot.buf.store(buf, Ordering::Relaxed);
        slot.decoder.store(decoder, Ordering::Relaxed);
    }
    if !ok {
        unsafe { title_free(block, c"apr.mmap.fault-slots") };
        // The decoders sit in this block; a static DCtx has nothing to free.
        unsafe { crate::rt::index_memory::buffer_free(ws.cast(), ws_tag) };
        for slot in &SLOT_TABLE {
            slot.buf.store(null_mut(), Ordering::Relaxed);
            slot.decoder.store(null_mut(), Ordering::Relaxed);
        }
    }
    SLOTS_STATE.store(if ok { 1 } else { 2 }, Ordering::Release);
    ok
}

/// A taken slot, given back on drop.
struct SlotGuard(&'static Slot);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

/// Handler side: the first free slot, spinning while all are busy.
fn take_slot() -> SlotGuard {
    let mut spins = 0u32;
    loop {
        for slot in &SLOT_TABLE {
            if !slot.busy.swap(true, Ordering::Acquire) {
                return SlotGuard(slot);
            }
        }
        backoff(&mut spins);
    }
}

// ---- mapping table ------------------------------------------------------------

/// Live decode-on-access mappings; one more maps from the disk cache.
const MAPPINGS: usize = 64;
const FREE: u32 = 0;
const LIVE: u32 = 1;
/// Being unregistered: no new handler users; freed once `users` is 0.
const DYING: u32 = 2;

/// What the handler needs; written only while the entry is FREE.
#[derive(Clone, Copy)]
struct MapInfo {
    base: usize,
    /// Reserved bytes, whole pages.
    len: usize,
    file_off: u64,
    file_size: u64,
    /// Index chunk record of file chunk 0.
    first_record: u32,
    ampr_id: u32,
    prot: c_int,
    /// File chunk of `states[0]`; `state_count` chunks follow.
    chunk_base: u64,
    states: *mut AtomicU8,
    state_count: usize,
}

impl MapInfo {
    const EMPTY: Self = Self {
        base: 0,
        len: 0,
        file_off: 0,
        file_size: 0,
        first_record: 0,
        ampr_id: 0,
        prot: 0,
        chunk_base: 0,
        states: null_mut(),
        state_count: 0,
    };
    fn pages(&self) -> u64 {
        self.len as u64 / PAGE
    }
    fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr - self.base < self.len
    }
    /// The state of file chunk `chunk`, which the mapping covers.
    unsafe fn state(&self, chunk: u64) -> &AtomicU8 {
        unsafe { &*self.states.add((chunk - self.chunk_base) as usize) }
    }
}

struct Mapping {
    phase: AtomicU32,
    /// Handlers using `info` now; munmap waits for 0.
    users: AtomicU32,
    /// A chunk failed: every later fault in it goes to the previous handler.
    failed: AtomicBool,
    info: SyncCell<MapInfo>,
}

static TABLE: [Mapping; MAPPINGS] = [const {
    Mapping {
        phase: AtomicU32::new(FREE),
        users: AtomicU32::new(0),
        failed: AtomicBool::new(false),
        info: SyncCell::new(MapInfo::EMPTY),
    }
}; MAPPINGS];
static LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Serializes registration, unregistration and the one-time setup. Never
/// taken by the handler.
static FAULT_M: Mutex = Mutex::new();

/// Handler side: the live mapping holding `addr`, with `users` raised (the
/// caller lowers it). The phase and range are checked again after the raise,
/// since the entry may have been freed and reused in between.
fn enter(addr: usize) -> Option<&'static Mapping> {
    TABLE.iter().find(|m| {
        // `info` is read only with `users` raised and the phase LIVE after
        // the raise: quiesce_locked waits for users to drop to 0 before it
        // frees and a later register rewrites the entry, so a racing
        // unregister can no longer be read half-written.
        if m.phase.load(Ordering::Acquire) != LIVE {
            return false;
        }
        // SeqCst pairs with quiesce_locked's store-then-load: with
        // Release/Acquire both sides may read the other's old value (x86
        // reorders a store before a later load), as in ReaderGate.
        m.users.fetch_add(1, Ordering::SeqCst);
        if m.phase.load(Ordering::SeqCst) == LIVE && unsafe { (*m.info.get()).contains(addr) } {
            return true;
        }
        m.users.fetch_sub(1, Ordering::Release);
        false
    })
}

/// Under FAULT_M: stores `info` in a free entry; false when all are used.
unsafe fn register(info: MapInfo) -> bool {
    let Some(m) = TABLE.iter().find(|m| m.phase.load(Ordering::Acquire) == FREE) else {
        return false;
    };
    unsafe { *m.info.get() = info };
    m.failed.store(false, Ordering::Relaxed);
    m.phase.store(LIVE, Ordering::Release);
    LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// munmap and MAP_FIXED replacement of a range, in two steps around the
/// replacing call: `begin_replace` marks the overlapping mappings DYING and
/// waits until no fault handler uses them, so none copies into pages the
/// call is about to replace; `end_replace` then frees them when the call
/// succeeded, or makes them LIVE again when it failed and the PROT_NONE
/// pages are still there.
pub(crate) fn begin_replace(addr: usize, len: usize) {
    if LIVE_COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    let _guard = FAULT_M.lock();
    unsafe { quiesce_locked(addr, len) };
}

/// See `begin_replace`; `gone`: the replacing call succeeded.
pub(crate) fn end_replace(addr: usize, len: usize, gone: bool) {
    if LIVE_COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    let _guard = FAULT_M.lock();
    unsafe { settle_locked(addr, len, gone) };
}

/// The bytes a MAP_FIXED map of `len` replaces, as `try_map` reserves
/// them: `len` rounded up to whole pages (saturating).
pub(crate) fn replace_len(len: usize) -> usize {
    len.checked_next_multiple_of(PAGE as usize).unwrap_or(usize::MAX)
}

fn overlaps(info: &MapInfo, addr: usize, end: usize) -> bool {
    info.base < end && addr < info.base + info.len
}

/// Under FAULT_M: the LIVE mappings overlapping `[addr, addr + len)` become
/// DYING, then this waits until no handler holds them.
unsafe fn quiesce_locked(addr: usize, len: usize) {
    let end = addr.saturating_add(len);
    for m in &TABLE {
        let info = unsafe { *m.info.get() };
        if m.phase.load(Ordering::Acquire) != LIVE || !overlaps(&info, addr, end) {
            continue;
        }
        m.phase.store(DYING, Ordering::SeqCst);
        let mut spins = 0u32;
        while m.users.load(Ordering::SeqCst) != 0 {
            backoff(&mut spins);
        }
    }
}

/// Under FAULT_M: the DYING mappings overlapping the range are freed with
/// their chunk states when `gone`, else LIVE again.
unsafe fn settle_locked(addr: usize, len: usize, gone: bool) {
    let end = addr.saturating_add(len);
    for m in &TABLE {
        let info = unsafe { *m.info.get() };
        if m.phase.load(Ordering::Acquire) != DYING || !overlaps(&info, addr, end) {
            continue;
        }
        if !gone {
            m.phase.store(LIVE, Ordering::Release);
            continue;
        }
        {
            let _fill = fill_lock();
            unsafe { (*STRUCK.get()).forget(info.base, info.len) };
        }
        unsafe { sdk_release(info.states.cast(), info.state_count, MEM_TRANSIENT) };
        unsafe { *m.info.get() = MapInfo::EMPTY };
        m.phase.store(FREE, Ordering::Release);
        LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---- map ----------------------------------------------------------------------

/// File offsets the fault path takes: 4 KiB, the x86 page. One that is not
/// a multiple of 16 KiB makes a 16 KiB page span two chunks.
const FILE_OFF_ALIGN: u64 = 4096;
const MAP_SHARED: c_int = 0x1;
const MAP_PRIVATE: c_int = 0x2;
const MAP_ANON: c_int = 0x1000;
const PROT_NONE: c_int = 0;
const PROT_RW: c_int = SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_RW;
type MmapFn = unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, off_t) -> *mut c_void;

pub(crate) enum MapResult {
    /// Reserved and registered at this address.
    Mapped(*mut c_void),
    /// The reservation itself failed with this errno.
    Failed(c_int),
    /// Not served here: map the disk cache file instead.
    Fallback,
}

/// mmap/sceKernelMmap of packed file `ampr_id` with `AMPR_ZSTD_MMAP=1`:
/// reserves `[addr, len)` as anonymous PROT_NONE memory with the caller's
/// placement flags (MAP_FIXED, hint address) and registers it for the fault
/// handler. Fallback when the mapping cannot be served by faults (module doc).
/// rt/pack/mmap.rs `serve` has already failed a shared writable map with
/// EACCES.
pub(crate) unsafe fn try_map(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    ampr_id: u32,
    off: off_t,
) -> MapResult {
    let gpu = prot & (SCE_KERNEL_PROT_GPU_READ | SCE_KERNEL_PROT_GPU_WRITE) != 0;
    // Any other non-CPU bit (AMPR access) is not a CPU fault either.
    let not_cpu = prot & !SCE_KERNEL_PROT_CPU_ALL != 0;
    // LZ4 packs (AMPRPAK4) have no fixed 256 KiB chunk geometry or zstd
    // record table, so every map of one takes the disk fallback. Without
    // this check zstd_entry would also return None there (no zstd mount),
    // but the format, not the mount state, is the reason.
    if !zstd_mode() {
        return MapResult::Fallback;
    }
    if len == 0 || off < 0 || !(off as u64).is_multiple_of(FILE_OFF_ALIGN) || gpu || not_cpu {
        return MapResult::Fallback;
    }
    let (Some(entry), Some(index)) = (zstd_entry(ampr_id), zstd_index()) else {
        return MapResult::Fallback;
    };
    // The fault handler reads chunk records from memory only.
    if !zstd_chunks_resident() {
        return MapResult::Fallback;
    }
    let Ok(file) = index.file(u64::from(entry.zstd_id)) else {
        return MapResult::Fallback;
    };
    let Some(mmap) = (unsafe { kernel_slot::<MmapFn>(hook::mmap) }) else {
        return MapResult::Fallback;
    };
    let Some(len) = (len as u64).checked_next_multiple_of(PAGE) else {
        return MapResult::Fallback;
    };
    if len > isize::MAX as u64 {
        return MapResult::Fallback;
    }
    let (chunk_base, count) = mapping_chunks(off as u64, len, file.logical_size);
    // The chunk states are a fixed pool site (rt/runtime_memory.rs): at most
    // a 2 KiB slab slot per mapping; a longer mapping takes the disk cache.
    if count as usize > STATES_MAX {
        return MapResult::Fallback;
    }
    let _guard = FAULT_M.lock();
    let ready = unsafe { install_handler() && make_slots() }
        && unsafe { open_volumes(entry.first_volume, entry.last_volume) }
        && unsafe { cache_pread() };
    if !ready {
        return MapResult::Fallback;
    }
    let count = count as usize;
    let states = if count == 0 {
        null_mut()
    } else {
        unsafe { sdk_alloc(count, MEM_TRANSIENT) }.cast::<AtomicU8>()
    };
    if count != 0 && states.is_null() {
        return MapResult::Fallback;
    }
    if count != 0 {
        unsafe { core::ptr::write_bytes(states, EMPTY, count) };
    }
    let release = || unsafe { sdk_release(states.cast(), count, MEM_TRANSIENT) };
    if !TABLE.iter().any(|m| m.phase.load(Ordering::Acquire) == FREE) {
        release();
        return MapResult::Fallback;
    }
    let anon = (flags & !(MAP_SHARED | MAP_PRIVATE)) | MAP_PRIVATE | MAP_ANON;
    // A MAP_FIXED reservation replaces whatever is at `addr`; the callers in
    // rt/pack/mmap.rs bracket it with begin_replace/end_replace over the
    // same page-rounded range (`replace_len`), which free only the old
    // mappings there, never the one registered below (it is LIVE, not
    // DYING).
    let base = unsafe { mmap(addr, len as usize, PROT_NONE, anon, -1, 0) };
    if base as usize == usize::MAX {
        let e = errno();
        release();
        return MapResult::Failed(if e == 0 { ENOMEM } else { e });
    }
    let info = MapInfo {
        base: base as usize,
        len: len as usize,
        file_off: off as u64,
        file_size: file.logical_size,
        first_record: entry.first_chunk,
        ampr_id,
        prot,
        chunk_base,
        states,
        state_count: count,
    };
    // A free entry was seen above and FAULT_M is held, so this succeeds.
    if !unsafe { register(info) } {
        release();
        return MapResult::Fallback;
    }
    stats::add(stats::Stat::MmapFaultMappings, 1);
    MapResult::Mapped(base)
}

/// Under FAULT_M: caches the original pread for the handler.
unsafe fn cache_pread() -> bool {
    let Some(f) = (unsafe { real_pread() }) else {
        return false;
    };
    PREAD.store(f as *mut c_void, Ordering::Release);
    true
}

// ---- signal handler -----------------------------------------------------------

// FreeBSD sys/signal.h of the ps5-payload-sdk (/opt/ps5-payload-sdk in the
// build image): `struct sigaction` is the handler union, int sa_flags and a
// 4-word sigset_t (32 bytes); siginfo_t holds si_addr after six ints.
const SIGBUS: c_int = 10;
const SIGSEGV: c_int = 11;
const SA_ONSTACK: c_int = 0x1;
const SA_SIGINFO: c_int = 0x40;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SigAction {
    handler: usize,
    flags: c_int,
    mask: [u32; 4],
}
const _: () = assert!(size_of::<SigAction>() == 32 && offset_of!(SigAction, mask) == 12);

impl SigAction {
    const DEFAULT: Self = Self {
        handler: SIG_DFL,
        flags: 0,
        mask: [0; 4],
    };
}

#[repr(C)]
struct SigInfo {
    signo: c_int,
    errno: c_int,
    code: c_int,
    pid: c_int,
    uid: u32,
    status: c_int,
    addr: *mut c_void,
}
const _: () = assert!(offset_of!(SigInfo, addr) == 24);

type SigactionFn = unsafe extern "C" fn(c_int, *const SigAction, *mut SigAction) -> c_int;
type InfoHandler = unsafe extern "C" fn(c_int, *mut SigInfo, *mut c_void);
type PlainHandler = unsafe extern "C" fn(c_int);

static SIGACTION: LazySym = LazySym::new(c"sigaction");
/// Actions before ours, [SIGBUS, SIGSEGV]; written before ours is set.
static PREV: SyncCell<[SigAction; 2]> = SyncCell::new([SigAction::DEFAULT; 2]);
/// 0 not tried, 1 installed, 2 failed (every mapping goes to disk).
static HANDLER_STATE: AtomicU8 = AtomicU8::new(0);

const fn prev_index(sig: c_int) -> usize {
    (sig == SIGSEGV) as usize
}

/// Under FAULT_M, on the first fault-path map: installs `on_fault` for
/// SIGBUS and SIGSEGV, keeping the previous actions. On failure the old
/// actions stay and debug builds log it once (op b'X', lookup b'F').
unsafe fn install_handler() -> bool {
    match HANDLER_STATE.load(Ordering::Acquire) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = unsafe { try_install() };
    HANDLER_STATE.store(if ok { 1 } else { 2 }, Ordering::Release);
    if !ok {
        stats::fs_note(b'X', b'F', -i64::from(EIO), c"mmap-fault sigaction".as_ptr());
    }
    ok
}

unsafe fn try_install() -> bool {
    let Some(sigaction) = (unsafe { SIGACTION.get::<SigactionFn>() }) else {
        return false;
    };
    let prev = unsafe { &mut *PREV.get() };
    for sig in [SIGBUS, SIGSEGV] {
        if unsafe { sigaction(sig, null(), &mut prev[prev_index(sig)]) } != 0 {
            return false;
        }
    }
    let ours = SigAction {
        handler: on_fault as *const () as usize,
        // On the alternate stack when the thread has one; no effect when not.
        flags: SA_SIGINFO | SA_ONSTACK,
        mask: [0; 4],
    };
    if unsafe { sigaction(SIGBUS, &ours, null_mut()) } != 0 {
        return false;
    }
    if unsafe { sigaction(SIGSEGV, &ours, null_mut()) } != 0 {
        unsafe { sigaction(SIGBUS, &prev[0], null_mut()) };
        return false;
    }
    true
}

/// A fault outside our mappings (or in a failed one): the previous action.
/// SIG_DFL and SIG_IGN restore the default and return, so the instruction
/// faults again and the process dies as it would have without us.
unsafe fn chain(sig: c_int, info: *mut SigInfo, ctx: *mut c_void) {
    let prev = unsafe { (*PREV.get())[prev_index(sig)] };
    if prev.handler == SIG_DFL || prev.handler == SIG_IGN {
        if let Some(sigaction) = unsafe { SIGACTION.get::<SigactionFn>() } {
            unsafe { sigaction(sig, &SigAction::DEFAULT, null_mut()) };
        }
    } else if prev.flags & SA_SIGINFO != 0 {
        let f: InfoHandler = unsafe { core::mem::transmute(prev.handler) };
        unsafe { f(sig, info, ctx) };
    } else {
        let f: PlainHandler = unsafe { core::mem::transmute(prev.handler) };
        unsafe { f(sig) };
    }
}

/// SIGSEGV/SIGBUS: fills the page behind a fault in one of our mappings and
/// returns so the access re-executes; anything else chains. errno is kept
/// for the interrupted code.
unsafe extern "C" fn on_fault(sig: c_int, info: *mut SigInfo, ctx: *mut c_void) {
    let saved = errno();
    let addr = if info.is_null() {
        0
    } else {
        unsafe { (*info).addr as usize }
    };
    if let Some(m) = enter(addr) {
        stats::add(stats::Stat::MmapFaults, 1);
        let ok = !m.failed.load(Ordering::Acquire) && unsafe { fill_page(m, addr, ctx as usize) };
        m.users.fetch_sub(1, Ordering::Release);
        if ok {
            set_errno(saved);
            return;
        }
    }
    set_errno(saved);
    unsafe { chain(sig, info, ctx) };
}

// ---- fill ---------------------------------------------------------------------

/// Serializes copies and page protection changes, so a page shared by two
/// chunks opens only once both are READY. Decoding runs outside it.
static FILL_LOCK: AtomicBool = AtomicBool::new(false);

struct FillGuard;

impl Drop for FillGuard {
    fn drop(&mut self) {
        FILL_LOCK.store(false, Ordering::Release);
    }
}

fn fill_lock() -> FillGuard {
    let mut spins = 0u32;
    while FILL_LOCK.swap(true, Ordering::Acquire) {
        backoff(&mut spins);
    }
    FillGuard
}

// ---- faults on open pages -----------------------------------------------------

/// Entries of `Strikes`: faults let retry at once, a few threads each.
const STRIKES: usize = 16;

/// Faults on a page whose chunks were all READY that the handler let retry,
/// as (page address, ucontext address). Such a fault is a race (the page
/// opened between the fault and the handler) or an access the mapping prot
/// does not allow (a write to a PROT_READ map, an exec). One retry tells
/// them apart: a race does not fault again; a disallowed access faults
/// again at once with the same ucontext address (it is on the faulting
/// thread's stack, so it names the thread), and that second fault chains
/// to the previous handler, the SIGSEGV the game gets without us. Without
/// this, such a fault was retried forever. Guarded by FILL_LOCK; address 0
/// is a free entry (no mapping starts at page 0).
struct Strikes {
    seen: [(usize, usize); STRIKES],
    next: usize,
}

impl Strikes {
    const fn new() -> Self {
        Self {
            seen: [(0, 0); STRIKES],
            next: 0,
        }
    }

    /// True when `(page, ctx)` was let retry before: the entry is dropped
    /// and the fault chains. Else it is recorded (over the oldest) and the
    /// fault retries.
    fn second_fault(&mut self, page: usize, ctx: usize) -> bool {
        if let Some(e) = self.seen.iter_mut().find(|e| **e == (page, ctx)) {
            *e = (0, 0);
            return true;
        }
        self.seen[self.next] = (page, ctx);
        self.next = (self.next + 1) % STRIKES;
        false
    }

    /// Drops the entries of pages in `[base, base + len)`: a later mapping
    /// there starts with closed pages, whose first fault must retry.
    fn forget(&mut self, base: usize, len: usize) {
        for e in &mut self.seen {
            if e.0 >= base && e.0 - base < len {
                *e = (0, 0);
            }
        }
    }
}

static STRUCK: SyncCell<Strikes> = SyncCell::new(Strikes::new());

/// Sets pages `first..end` of `info` to `prot`; true on success or empty.
unsafe fn protect(info: &MapInfo, first: u64, end: u64, prot: c_int) -> bool {
    if first >= end {
        return true;
    }
    let at = (info.base + (first * PAGE) as usize) as *const c_void;
    unsafe { real_mprotect(at, ((end - first) * PAGE) as usize, prot) == 0 }
}

/// Every chunk behind page `page` is READY (a page past the end has none,
/// though `fill_page` chains those before asking).
unsafe fn page_ready(info: &MapInfo, page: u64) -> bool {
    page_chunks(info.file_off, page, info.file_size).is_none_or(|(first, last)| {
        (first..=last).all(|c| unsafe { info.state(c) }.load(Ordering::Acquire) == READY)
    })
}

/// Fills every chunk behind the page holding `addr`, then opens the page;
/// false chains the fault. A page wholly past the end of the file stays
/// closed and chains, as a real file mapping raises SIGBUS there. A page
/// with nothing to fill goes through `Strikes` with `ctx`, the handler's
/// ucontext address.
unsafe fn fill_page(m: &Mapping, addr: usize, ctx: usize) -> bool {
    let info = unsafe { &*m.info.get() };
    let page = ((addr - info.base) as u64) / PAGE;
    if past_end(info.file_off, page, info.file_size) {
        return false;
    }
    if unsafe { page_ready(info, page) } {
        // Under FILL_LOCK every READY chunk's pages are open already: this
        // fault raced the filler or is an access the prot does not allow.
        let _fill = fill_lock();
        let page_addr = info.base + (page * PAGE) as usize;
        if unsafe { (*STRUCK.get()).second_fault(page_addr, ctx) } {
            return false;
        }
        return unsafe { protect(info, page, page + 1, info.prot) };
    }
    if let Some((first, last)) = page_chunks(info.file_off, page, info.file_size) {
        for chunk in first..=last {
            if !unsafe { fill_chunk(m, info, chunk) } {
                return false;
            }
        }
    }
    // Every chunk is READY and the filler opened the page already; opening
    // it again is harmless.
    let _fill = fill_lock();
    unsafe { protect(info, page, page + 1, info.prot) }
}

/// Fills `chunk` once: the claiming thread decodes and copies it, others
/// wait for it. A failure fails the whole mapping.
unsafe fn fill_chunk(m: &Mapping, info: &MapInfo, chunk: u64) -> bool {
    let state = unsafe { info.state(chunk) };
    match claim(state) {
        Claim::Ready => return true,
        Claim::Failed => return false,
        Claim::Fill => {}
    }
    if unsafe { decode_and_copy(info, chunk, state) } {
        return true;
    }
    finish(state, false);
    m.failed.store(true, Ordering::Release);
    stats::add(stats::Stat::MmapFaultErrors, 1);
    note_error(info.ampr_id, chunk);
    false
}

/// Reads and decodes `chunk` into a scratch slot, makes its pages RW,
/// copies the part the mapping covers, marks it READY and sets every page
/// whose chunks are all READY to the mapping prot (the others stay
/// PROT_NONE).
unsafe fn decode_and_copy(info: &MapInfo, chunk: u64, state: &AtomicU8) -> bool {
    let Some(pread) = (unsafe { fn_from_ptr::<KernelPreadFn>(PREAD.load(Ordering::Acquire)) }) else {
        return false;
    };
    // The record lookup reads the zstd mount, which module_stop frees once
    // the reader count is zero, so it runs under a ManifestReader (two
    // atomics, safe in the signal handler). A refused enter fails the fill
    // as a missing mount does. The record comes from memory only (the fast
    // table or a resident index): the page cache lock, a wait or an index
    // pread could deadlock or stall a faulting thread, so a record that
    // would need one fails the fill. The record is a copy, so the guard
    // ends with the lookup; the slot and fill spin locks below are never
    // held by shutdown, so no reader waits on them while shutdown waits
    // for readers.
    let record = {
        let Some(_reader) = ManifestReader::enter() else {
            return false;
        };
        let Some(record) = zstd_chunk_resident(info.first_record + chunk as u32) else {
            return false;
        };
        record
    };
    let chunk_begin = chunk << CHUNK_SHIFT;
    let raw = (info.file_size - chunk_begin).min(CHUNK) as usize;
    let stored = record.stored_size as usize;
    let fd = volume_fd(record.volume_id);
    if fd < 0 || stored > CHUNK as usize {
        return false;
    }
    let slot = take_slot();
    let buf = slot.0.buf.load(Ordering::Relaxed);
    let decoder = unsafe { &mut *slot.0.decoder.load(Ordering::Relaxed) };
    if !unsafe { read_volume(pread, fd, buf, stored, off_t::from(record.offset)) } {
        return false;
    }
    let input = unsafe { core::slice::from_raw_parts(buf, stored) };
    let out = unsafe { core::slice::from_raw_parts_mut(buf.add(CHUNK as usize), CHUNK as usize) };
    if decoder.decode(record.codec, raw, input, out).is_err() {
        return false;
    }
    let out = unsafe { core::slice::from_raw_parts(buf.add(CHUNK as usize), CHUNK as usize) };
    let map_end = info.file_off + info.len as u64;
    let begin = chunk_begin.max(info.file_off);
    let end = (chunk_begin + raw as u64).min(map_end);
    let (first, last_end) = chunk_pages(info.file_off, info.pages(), chunk, info.file_size);
    if begin >= end || first >= last_end {
        return false;
    }
    let _fill = fill_lock();
    if !unsafe { protect(info, first, last_end, PROT_RW) } {
        return false;
    }
    let dst = (info.base + (begin - info.file_off) as usize) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr().add((begin - chunk_begin) as usize), dst, (end - begin) as usize) };
    finish(state, true);
    stats::add(stats::Stat::MmapFaultBytes, end - begin);
    // Only the first and last page can hold bytes of another chunk.
    let last = last_end - 1;
    let open = |p: u64| if unsafe { page_ready(info, p) } { info.prot } else { PROT_NONE };
    unsafe {
        protect(info, first + 1, last, info.prot)
            && protect(info, first, first + 1, open(first))
            && (last == first || protect(info, last, last_end, open(last)))
    }
}

/// `stored` bytes of volume fd `fd` from `at` into `buf` with the original
/// pread; false on an error or EOF first.
unsafe fn read_volume(pread: KernelPreadFn, fd: c_int, buf: *mut u8, stored: usize, at: off_t) -> bool {
    let mut got = 0usize;
    while got < stored {
        let n = unsafe { pread(fd, buf.add(got).cast(), stored - got, at + got as off_t) };
        if n < 0 && errno() == EINTR {
            continue;
        }
        if n <= 0 {
            return false;
        }
        got += n as usize;
    }
    true
}

/// Debug: a failed fill as op b'X', lookup b'F', path "mmap-fault
/// fid=<ampr id> chunk=<file chunk>" (hex). Lock-free: `fs_note` drops the
/// event when its log is busy.
fn note_error(ampr_id: u32, chunk: u64) {
    if !cfg!(feature = "mem_report") {
        return;
    }
    let mut buf = [0u8; 64];
    let mut n = 0;
    let mut text = |s: &[u8]| {
        buf[n..n + s.len()].copy_from_slice(s);
        n += s.len();
    };
    text(b"mmap-fault fid=");
    let (digits, k) = hex(u64::from(ampr_id));
    text(&digits[..k]);
    text(b" chunk=");
    let (digits, k) = hex(chunk);
    text(&digits[..k]);
    stats::fs_note(b'X', b'F', -i64::from(EIO), buf.as_ptr().cast());
}

/// Hex digits of `v` without leading zeros (at least one) and their count.
fn hex(v: u64) -> ([u8; 16], usize) {
    let digits = (64 - (v | 1).leading_zeros()).div_ceil(4) as usize;
    let mut out = [0u8; 16];
    for (i, d) in out[..digits].iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((v >> ((digits - 1 - i) * 4)) & 0xf) as usize];
    }
    (out, digits)
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const K: u64 = 1024;

    #[test]
    fn aligned_pages_map_to_one_chunk_and_stop_at_the_end() {
        // 16 pages per chunk; a 600 KiB file has chunks 0..=2.
        let size = 600 * K;
        assert_eq!(page_chunks(0, 0, size), Some((0, 0)));
        assert_eq!(page_chunks(0, 15, size), Some((0, 0)));
        assert_eq!(page_chunks(0, 16, size), Some((1, 1)));
        // Page 37 holds bytes 592..600 KiB only: chunk 2.
        assert_eq!(page_chunks(0, 37, size), Some((2, 2)));
        assert_eq!(page_chunks(0, 38, size), None);
        // A mapping from chunk 1 sees chunk 1 at page 0.
        assert_eq!(page_chunks(CHUNK, 0, size), Some((1, 1)));
    }

    #[test]
    fn only_pages_wholly_past_the_end_chain() {
        // A 600 KiB file: page 37 holds its last 8 KiB and a zero tail.
        let size = 600 * K;
        assert!(!past_end(0, 0, size) && !past_end(0, 37, size));
        assert!(past_end(0, 38, size) && past_end(0, 100, size));
        // From byte 596 KiB only page 0 holds file bytes.
        assert!(!past_end(596 * K, 0, size) && past_end(596 * K, 1, size));
        // A mapping that starts at the end, or an offset that overflows.
        assert!(past_end(size, 0, size) && past_end(u64::MAX, 1, size));
    }

    #[test]
    fn unaligned_offset_makes_a_page_span_two_chunks() {
        let off = 4 * K;
        let size = 1024 * K;
        // Page 15 holds bytes 244..260 KiB: the end of chunk 0, start of 1.
        assert_eq!(page_chunks(off, 15, size), Some((0, 1)));
        assert_eq!(page_chunks(off, 14, size), Some((0, 0)));
        assert_eq!(page_chunks(off, 16, size), Some((1, 1)));
        // Chunk 0 is pages 0..16 (page 15 shared), chunk 1 pages 15..32.
        assert_eq!(chunk_pages(off, 64, 0, size), (0, 16));
        assert_eq!(chunk_pages(off, 64, 1, size), (15, 32));
    }

    #[test]
    fn chunk_pages_clip_to_the_mapping_and_the_file() {
        let size = 600 * K;
        // 4-page mapping from 0: only chunk 0, pages 0..4.
        assert_eq!(chunk_pages(0, 4, 0, size), (0, 4));
        assert_eq!(chunk_pages(0, 4, 1, size), (0, 0));
        // Chunk 2 is 88 KiB: pages 32..38, the last one partial.
        assert_eq!(chunk_pages(0, 64, 2, size), (32, 38));
        assert_eq!(chunk_pages(0, 64, 3, size), (0, 0));
    }

    #[test]
    fn mapping_chunks_count_the_chunks_a_range_covers() {
        let size = 600 * K;
        assert_eq!(mapping_chunks(0, 64 * PAGE, size), (0, 3));
        assert_eq!(mapping_chunks(CHUNK, PAGE, size), (1, 1));
        assert_eq!(mapping_chunks(4 * K, 16 * PAGE, size), (0, 2));
        assert_eq!(mapping_chunks(size, PAGE, size), (size >> CHUNK_SHIFT, 0));
        assert_eq!(mapping_chunks(1024 * K, PAGE, size).1, 0);
    }

    #[test]
    fn chunk_state_claims_once_then_reports_the_outcome() {
        let s = AtomicU8::new(EMPTY);
        assert_eq!(claim(&s), Claim::Fill);
        assert_eq!(s.load(Ordering::Relaxed), FILLING);
        finish(&s, true);
        assert_eq!(claim(&s), Claim::Ready);
        let f = AtomicU8::new(EMPTY);
        assert_eq!(claim(&f), Claim::Fill);
        finish(&f, false);
        assert_eq!(claim(&f), Claim::Failed);
    }

    #[test]
    fn waiter_spins_until_the_filler_finishes() {
        static S: AtomicU8 = AtomicU8::new(FILLING);
        let waiter = std::thread::spawn(|| claim(&S));
        std::thread::sleep(std::time::Duration::from_millis(20));
        finish(&S, true);
        assert_eq!(waiter.join().unwrap(), Claim::Ready);
    }

    #[test]
    fn open_page_fault_retries_once_then_chains() {
        let mut s = Strikes::new();
        // First fault of a thread on an open page retries (a race), the
        // same thread faulting there again chains (a disallowed access).
        assert!(!s.second_fault(0x10_0000, 0x7000));
        assert!(!s.second_fault(0x10_0000, 0x9000));
        assert!(s.second_fault(0x10_0000, 0x7000));
        // The chained entry is dropped: a next fault retries once again.
        assert!(!s.second_fault(0x10_0000, 0x7000));
        // An unmap forgets its pages only.
        assert!(!s.second_fault(0x20_0000, 0x7000));
        s.forget(0x10_0000, 0x4000);
        assert!(!s.second_fault(0x10_0000, 0x9000));
        assert!(s.second_fault(0x20_0000, 0x7000));
    }

    #[test]
    fn strikes_overwrite_the_oldest_entry() {
        let mut s = Strikes::new();
        for i in 0..=STRIKES {
            assert!(!s.second_fault(0x4000 * (i + 1), 1));
        }
        // Entry 0 was overwritten by the 17th; the rest are kept.
        assert!(!s.second_fault(0x4000, 1));
        assert!(s.second_fault(0x4000 * 3, 1));
    }
}
