//! Manifest validation and loading, cache initialization, runtime profile
//! and decoded-cache hash table.

use super::*;
use crate::rt::index_file::{merge_spans, FileSource, ResidentSource, Span, WINDOW};
use crate::rt::index_memory::{self as im, cache_alloc, cache_room};
use ampr_format::source::Source;
use ampr_format::view::Builder;

/// The mounted index image: AMPRZPK1 in zstd mode, else AMPRPAK4.
fn manifest_path() -> &'static CStr {
    if zstd_mode() {
        zstd::AMPR_EMU_ZSTD_INDEX_PATH
    } else {
        AMPR_EMU_PACK_INDEX_PATH
    }
}

fn manifest_min_bytes() -> usize {
    if zstd_mode() {
        zstd::ZSTD_INDEX_MIN_BYTES
    } else {
        size_of::<AmprPackIndexHeader>()
    }
}

/// AMPRPAK4 only: `ampr_pack_core_mount` runs the full `Manifest::open`
/// validation (`open_pkg` when `pkg`) over the whole file through
/// `check`, then the runtime caps. The kept manifest reads `resident`,
/// whose record sections become the fast table, so after the mount
/// records and pack names are memory reads and nothing reads the file. A
/// zstd index is mounted by `load_zstd_manifest`; its AMPRPAK4 view stays
/// empty (`(*state).header` null), so the AMPRPAK4 paths treat nothing as
/// packed.
unsafe fn validate_manifest_layout<S: Source + ?Sized>(
    state: *mut PackState,
    check: &S,
    resident: &'static ResidentSource<'static>,
    pkg: bool,
) -> bool {
    let mut view = AmprPackCoreView::EMPTY;
    let mount_rc = unsafe { ampr_pack_core_mount(check, resident, pkg, &mut view) };
    let header = view.header;
    if mount_rc != AMPR_PACK_CORE_OK
        || { header.file_count } > AMPR_EMU_PACK_MAX_FILES
        || { header.chunk_count } > AMPR_EMU_PACK_MAX_CHUNKS
        || { header.pack_count } as usize > AMPR_EMU_PACK_MAX_PACKS
    {
        return false;
    }
    let Some(m) = view.manifest.and_then(|m| head_fast(m, resident.head())) else {
        return false;
    };
    view.manifest = Some(m);
    (*state).core_view = view;
    (*state).header = &raw const (*state).core_view.header;
    true
}

/// `m` reading its records from the record sections in `head`, the file
/// from offset 0: the fast table without a second copy. `open` and
/// `open_pkg` checked that the sections start at the header offset 72
/// names and lie back to back.
fn head_fast(m: Lz4Manifest, head: &'static [u8]) -> Option<Lz4Manifest> {
    let at = usize::try_from(ampr_lz4::u64_at(head, 72).ok()?).ok()?;
    let fast = head.get(at..at.checked_add(m.fast_len())?)?;
    m.with_fast(fast).ok()
}

/// The index file as the mount's validation reads it: `head` (the file
/// from offset 0) from memory, the rest through `rest`.
struct HeadSource<'a, S> {
    head: &'a [u8],
    rest: S,
}

impl<S: Source> Source for HeadSource<'_, S> {
    fn len(&self) -> u64 {
        self.rest.len()
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> ampr_format::Result<()> {
        let split = (self.head.len() as u64)
            .saturating_sub(at)
            .min(out.len() as u64) as usize;
        let (mem, file) = out.split_at_mut(split);
        if !mem.is_empty() {
            self.head.read_at(at, mem)?;
        }
        if !file.is_empty() {
            self.rest.read_at(at + split as u64, file)?;
        }
        Ok(())
    }
}

// ---- resident AMPRPAK4 parts ----

/// The block holding the parts of the mounted AMPRPAK4 index file the
/// manifest reads after the mount, and the source over them; null and
/// empty when none is mounted. Those parts are the header and record
/// sections (the fast table) and the pack names a pack open and a
/// directory listing read; the file paths, most of the file, are read
/// only by the mount's validation, and the view join compares sizes and
/// path hashes. That is 48 B per file, 12 B per chunk, 32 B per pack and
/// its name plus a 16 B span, and the 128 B header: 27.5 MiB at 223,180
/// files, 1,513,210 chunks and 18 packs (computed). The mount's peak is
/// this block plus the 128 KiB of windows, below the whole file it read
/// into memory before. Written only by the single manifest loader before
/// `LOAD_STATE` turns ready; it outlives the view (hooks past the reader
/// gate may still read it) until a failed mount or a reload. The middle
/// field is the block's size, counted in `index_view_bytes` while it is
/// held.
static LZ4_IMAGE: SyncCell<(*mut u8, usize, ResidentSource<'static>)> =
    SyncCell::new((null_mut(), 0, ResidentSource::EMPTY));

/// Mounts the `len`-byte AMPRPAK4 file read by `read` (fills the slice at
/// the offset; false on an error or a short file). Its kept parts go to a
/// new Index block (`read_resident`), which replaces the one mounted
/// before (a reload); the validation reads the string section through two
/// 64 KiB windows from the Index ledger, given back at the end. False
/// after giving everything back, on a read error, a refused block (after
/// the index notice) or a failed check: the pack index is then invalid,
/// never absent.
pub(crate) unsafe fn mount_lz4_file(
    state: *mut PackState,
    len: u64,
    read: impl Fn(u64, &mut [u8]) -> bool,
    pkg: bool,
) -> bool {
    unsafe { drop_lz4_image() };
    let tag = c"apr.pack.index.window";
    let w = unsafe { im::index_alloc(2 * WINDOW, SCE_KERNEL_PAGE_SIZE, tag.as_ptr()) };
    if w.is_null() {
        return false;
    }
    // SAFETY: two disjoint, page-aligned windows of the block just taken.
    let (a, b) = unsafe { (&mut *w.cast::<[u8; WINDOW]>(), &mut *w.add(WINDOW).cast()) };
    let mounted = unsafe { read_resident(len, &read, a, b) }.is_some_and(|src| {
        let rest = FileSource::new(len, &read, a, b);
        let check = HeadSource {
            head: src.head(),
            rest,
        };
        unsafe { validate_manifest_layout(state, &check, src, pkg) }
    });
    unsafe { im::index_free(w.cast(), tag.as_ptr()) };
    if !mounted {
        clear_manifest_view(state);
        unsafe { drop_lz4_image() };
    }
    mounted
}

/// Gives the mounted parts back. Only for a file no published view
/// reads: a failed mount, or a reload before the new file is read.
pub(crate) unsafe fn drop_lz4_image() {
    let (p, bytes, _) = core::mem::replace(
        unsafe { &mut *LZ4_IMAGE.get() },
        (null_mut(), 0, ResidentSource::EMPTY),
    );
    if !p.is_null() {
        stats::sub(stats::Stat::IndexViewBytes, bytes as u64);
        unsafe { im::index_free(p.cast(), c"apr.pack.index.release".as_ptr()) };
    }
}

/// Reads the kept parts of the `len`-byte file into one Index block laid
/// out as [file from offset 0 to the string section][spans][pack names],
/// mounts it in `LZ4_IMAGE` and returns its source. `a` and `b` are
/// scratch: the pack records, then the pack name spans before they are
/// merged. Only bounds the parts need are checked here (`open` checks the
/// rest); None on a bad bound, a read error or a refused block.
unsafe fn read_resident(
    len: u64,
    read: &impl Fn(u64, &mut [u8]) -> bool,
    a: &mut [u8; WINDOW],
    b: &mut [u8; WINDOW],
) -> Option<&'static ResidentSource<'static>> {
    let mut h = [0u8; ampr_lz4::PAK_HEADER];
    if len < h.len() as u64 || !read(0, &mut h) {
        return None;
    }
    let (_, _, packs) = ampr_lz4::manifest::header_counts(&h).ok()?;
    let at = |off| ampr_lz4::u64_at(&h, off).ok();
    let (packs_at, strings_at, strings_len) = (at(88)?, at(96)?, at(104)?);
    let packs = packs as usize;
    let pack_bytes = packs * ampr_lz4::PACK_RECORD;
    if packs > AMPR_EMU_PACK_MAX_PACKS
        || packs_at.checked_add(pack_bytes as u64) != Some(strings_at)
        || strings_at < h.len() as u64
        || strings_at.checked_add(strings_len) != Some(len)
    {
        return None;
    }
    let records = &mut a[..pack_bytes];
    if !read(packs_at, records) {
        return None;
    }
    const _: () = assert!(AMPR_EMU_PACK_MAX_PACKS * size_of::<Span>() <= WINDOW);
    // SAFETY: `b` is page aligned and holds `packs` spans (assert above).
    let spans: &mut [Span] =
        unsafe { core::slice::from_raw_parts_mut(b.as_mut_ptr().cast(), packs) };
    for (s, r) in spans
        .iter_mut()
        .zip(records.chunks_exact(ampr_lz4::PACK_RECORD))
    {
        let (off, n) = (ampr_lz4::u32_at(r, 16).ok()?, ampr_lz4::u32_at(r, 20).ok()?);
        // As `Manifest::string`: shorter than PATH_BUF, its NUL inside.
        if n as usize >= ampr_format::source::PATH_BUF
            || u64::from(off) + u64::from(n) >= strings_len
        {
            return None;
        }
        *s = Span {
            at: strings_at + u64::from(off),
            off: 0,
            len: n + 1,
        };
    }
    let (count, names) = merge_spans(spans);
    let head_len = usize::try_from(strings_at).ok()?;
    let spans_at = head_len.next_multiple_of(align_of::<Span>());
    let names_at = spans_at + count * size_of::<Span>();
    let total = names_at + names as usize;
    let p = unsafe { im::index_alloc(total, SCE_KERNEL_PAGE_SIZE, c"apr.pack.index".as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: three disjoint ranges of the `total`-byte block just taken;
    // `spans_at` is aligned for `Span`.
    let (head, kept, bytes) = unsafe {
        (
            core::slice::from_raw_parts_mut(p, head_len),
            core::slice::from_raw_parts_mut(p.add(spans_at).cast::<Span>(), count),
            core::slice::from_raw_parts_mut(p.add(names_at), names as usize),
        )
    };
    kept.copy_from_slice(&spans[..count]);
    let ok = read(0, head)
        && kept
            .iter()
            .all(|s| read(s.at, &mut bytes[s.off as usize..][..s.len as usize]));
    if !ok {
        unsafe { im::index_free(p.cast(), c"apr.pack.index.invalid".as_ptr()) };
        return None;
    }
    let slot = unsafe { &mut *LZ4_IMAGE.get() };
    *slot = (p, total, ResidentSource::new(head, kept, bytes, len));
    stats::add(stats::Stat::IndexViewBytes, total as u64);
    Some(&slot.2)
}

/// The target from the pool under the cache cap, cut to what is left under
/// it (rt/index_memory.rs `cache_room`) but not below `min_bytes`. Freed by
/// `cache_free`.
unsafe fn cache_region(target: usize, min_bytes: usize, tag: &CStr) -> Option<(*mut u8, usize)> {
    let room = cache_room() & !(PACK_CACHE_PAGE_BYTES - 1);
    let bytes = align_up_size(target, PACK_CACHE_PAGE_BYTES).min(room);
    if bytes == 0 || bytes < target.min(min_bytes) {
        return None;
    }
    let memory = unsafe { cache_alloc(bytes, tag.as_ptr()) };
    (!memory.is_null()).then_some((memory, bytes))
}

/// AMPRPAK4 only: its `build_id` and path do not apply to a zstd mount.
pub(crate) unsafe fn load_runtime_profile(state: *mut PackState) -> bool {
    let (Some(open_fn), Some(fstat_fn), Some(close_fn)) =
        (unsafe { real_open() }, unsafe { real_fstat() }, unsafe {
            real_close()
        })
    else {
        return false;
    };
    let fd = unsafe {
        open_fn(
            AMPR_EMU_PACK_RUNTIME_PROFILE_PATH.as_ptr(),
            SCE_KERNEL_O_RDONLY,
            0 as c_int,
        )
    };
    if fd < 0 {
        let error = if fd == -1 {
            errno()
        } else {
            posix_errno_from_sce(fd)
        };
        return error == ENOENT;
    }
    let mut profile: AmprPackRuntimeProfile = unsafe { core::mem::zeroed() };
    let mut st: SceKernelStat = unsafe { core::mem::zeroed() };
    let size = size_of::<AmprPackRuntimeProfile>();
    let mut valid = unsafe { fstat_fn(fd, &mut st) } == 0
        && st.st_size == size as off_t
        && unsafe { pread_exact(fd, &mut profile as *mut _ as *mut c_void, size, 0) };
    let close_rc = unsafe { close_fn(fd) };
    let expected_crc = profile.crc32;
    profile.crc32 = 0;
    let (workers, reserve) = (profile.workers, profile.latency_reserve_workers);
    let (decoded, physical) = (profile.decoded_cache_bytes, profile.physical_cache_bytes);
    valid = valid
        && close_rc == 0
        && { profile.magic } == *b"AMPRCFG1"
        && { profile.version } == 1
        && { profile.size } as usize == size
        && { profile.reserved } == 0
        && { profile.build_id } == unsafe { (*(*state).header).build_id }
        && unsafe { ampr_pack_crc32(&profile as *const _ as *const c_void, size, 0) }
            == expected_crc
        && (1..=16).contains(&workers)
        && reserve < workers
        && decoded % PACK_CACHE_PAGE_BYTES as u64 == 0
        && physical % PACK_CACHE_PAGE_BYTES as u64 == 0;
    if !valid {
        return false;
    }
    // The format still carries a physical page cache size; there is no
    // such cache now, so its share goes to the decoded cache.
    let decoded = decoded.saturating_add(physical);
    (*state).decoded_cache_target_bytes =
        decoded.min(AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES) as usize;
    (*state).requested_workers = workers.min(AMPR_EMU_PACK_WORKER_CAPACITY as u32);
    (*state).latency_reserve_workers = reserve.min((*state).requested_workers - 1);
    true
}

/// Allocates the decoded cache, or leaves it off: a 0 target, or refused
/// under the cache cap.
unsafe fn initialize_decoded_cache(state: *mut PackState) {
    if (*state).decoded_cache_target_bytes == 0 || PACK_CACHE_MAX_PAGES == 0 {
        return;
    }
    let Some((memory, candidate)) = (unsafe {
        cache_region(
            (*state).decoded_cache_target_bytes,
            AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES as usize,
            c"apr.pack.decoded-cache",
        )
    }) else {
        return;
    };
    (*state).cache_base = memory;
    (*state).cache_bytes = candidate;
    (*state).cache_page_count = (candidate / PACK_CACHE_PAGE_BYTES) as u32;
    (*state).cache_page_bitmap.fill(0);
    (*state).cache_hash_heads.fill(0);
    (*state).cache_page_cursor = 0;
    (*state).cache_free_head = 0;
    for (i, entry) in (*state).cache_entries.iter_mut().enumerate() {
        *entry = CacheEntry::EMPTY;
        entry.free_next = if i + 1 < AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            i as u32 + 1
        } else {
            INVALID_INDEX
        };
    }
}

/// Carves the 64 MiB decoded cache from the pool at startup. No reserve is
/// held for the pipelines and workers: their windows and decode buffers
/// have their own Buffer ledger, and the Index, Cache and Buffer caps plus
/// the fixed sites fit the pool (rt/index_memory.rs), so a cache cannot
/// take their room. A refused cache stays off.
pub(crate) unsafe fn initialize_caches(state: *mut PackState) {
    unsafe {
        initialize_decoded_cache(state);
    }
}

pub(crate) unsafe fn clear_manifest_view(state: *mut PackState) {
    (*state).core_view = AmprPackCoreView::EMPTY;
    (*state).header = null();
    if zstd_mode() {
        zstd::zstd_mount_clear();
    }
}

pub(crate) unsafe fn release_manifest_storage(state: *mut PackState) {
    // The zstd chunk tables go with the mount that reads them.
    if zstd_mode() {
        unsafe { zstd::zstd_mount_release() };
    }
    let bits = core::mem::replace(&mut (*state).lz4_mismatch, null_mut());
    (*state).lz4_mismatch_bytes = 0;
    if !bits.is_null() {
        unsafe { im::index_free(bits.cast(), c"apr.pack.mismatch.release".as_ptr()) };
    }
    // The kept AMPRPAK4 parts stay mounted: hooks past the reader gate may
    // still read them; a failed mount or a reload gives them back, and
    // their `index_view_bytes` with them (`drop_lz4_image`).
    clear_manifest_view(state);
}

/// Mounts the pack index joined to the view `b`; none is mounted without
/// it.
pub(crate) unsafe fn load_manifest(
    state: *mut PackState,
    absent: *mut bool,
    b: Option<&mut Builder<'_>>,
) -> bool {
    if !absent.is_null() {
        unsafe { *absent = false };
    }
    let (Some(open_fn), Some(close_fn), Some(fstat_fn), Some(_)) = (
        unsafe { real_open() },
        unsafe { real_close() },
        unsafe { real_fstat() },
        unsafe { real_pread() },
    ) else {
        return false;
    };
    let fd = unsafe { open_fn(manifest_path().as_ptr(), SCE_KERNEL_O_RDONLY, 0 as c_int) };
    if fd < 0 {
        let open_errno = if fd == -1 {
            errno()
        } else {
            posix_errno_from_sce(fd)
        };
        if !absent.is_null() && open_errno == ENOENT {
            unsafe { *absent = true };
        }
        return false;
    }
    let mut stat: SceKernelStat = unsafe { core::mem::zeroed() };
    let stat_rc = unsafe { fstat_fn(fd, &mut stat) };
    if stat_rc != 0
        || stat.st_size < manifest_min_bytes() as off_t
        || stat.st_size as u64 > AMPR_EMU_PACK_INDEX_MAX_BYTES
    {
        unsafe { close_fn(fd) };
        return false;
    }
    let Some(b) = b else {
        unsafe { close_fn(fd) };
        return false;
    };
    if zstd_mode() {
        return unsafe { load_zstd_manifest(state, fd, stat.st_size as u64, b) };
    }
    unsafe { load_lz4_manifest(state, fd, stat.st_size as u64, b) }
}

/// AMPRPAK4: the index file is mounted with its kept parts in the Index
/// ledger (`mount_lz4_file`) and `fd` closed, then joined to the view `b`
/// (`join_lz4`).
unsafe fn load_lz4_manifest(
    state: *mut PackState,
    fd: c_int,
    len: u64,
    b: &mut Builder<'_>,
) -> bool {
    let read = |at: u64, out: &mut [u8]| unsafe {
        pread_exact(fd, out.as_mut_ptr().cast(), out.len(), at)
    };
    let mounted = unsafe { mount_lz4_file(state, len, read, pkg_mode()) };
    if let Some(close_fn) = unsafe { real_close() } {
        unsafe { close_fn(fd) };
    }
    mounted && unsafe { finish_lz4_mount(state, b) }
}

/// Links each packed AMPRPAK4 record to view id `record + 1` when its size
/// and `pak_path_hash` match that row (`view_join::join_records`), so an
/// open by id reads no path: the per-open check of the record against the
/// AMPRIDX3 path runs once here. A record that does not match sets its bit
/// in the mismatch bitmap, one bit per view id from the Index ledger, and
/// stays unlinked (`lz4_mismatch`). False when the bitmap does not fit or
/// a record cannot be read; the caller then unlinks every row.
pub(crate) unsafe fn join_lz4(state: *mut PackState, b: &mut Builder<'_>) -> bool {
    let bytes = (b.files() as usize + 1).div_ceil(8);
    let p = unsafe { im::index_alloc(bytes, 8, c"apr.pack.mismatch".as_ptr()) };
    if p.is_null() {
        return false;
    }
    let bits = unsafe { core::slice::from_raw_parts_mut(p, bytes) };
    (*state).lz4_mismatch = p;
    (*state).lz4_mismatch_bytes = bytes;
    let count = (*state).core_view.manifest.map_or(0, |m| m.file_count());
    let record = |i: u32| {
        let f = unsafe { state::lz4_file(state, i) }.ok_or(ampr_format::Error::Invalid)?;
        Ok((f.flags & AMPR_PACK_FILE_PACKED != 0).then_some((f.logical_size, f.path_hash)))
    };
    ampr_format::view_join::join_records(b, count, record, bits).is_ok()
}

/// Whether the packed AMPRPAK4 record of one-based `file_id` failed the
/// join to its view row (`join_lz4`): an open of it answers as a failed
/// record check did, EIO for an APR open and unhandled for a plain one.
/// False with no mounted LZ4 index, or for an id past the bitmap.
pub(crate) unsafe fn lz4_mismatch(state: *const PackState, file_id: u32) -> bool {
    let (p, bytes) = unsafe { ((*state).lz4_mismatch, (*state).lz4_mismatch_bytes) };
    let byte = file_id as usize / 8;
    !p.is_null() && byte < bytes && unsafe { *p.add(byte) } & (1 << (file_id % 8)) != 0
}

/// Loads the runtime profile of the mounted manifest and joins its
/// records to the view `b`, which also gives the directory listings. A
/// failure gives the mount back.
unsafe fn finish_lz4_mount(state: *mut PackState, b: &mut Builder<'_>) -> bool {
    if !unsafe { load_runtime_profile(state) } || !unsafe { join_lz4(state, b) } {
        unsafe { release_manifest_storage(state) };
        unsafe { drop_lz4_image() };
        return false;
    }
    unsafe { initialize_caches(state) };
    true
}

/// zstd: the index file is read once through two windows, validated and
/// joined to the view `b` with its chunk and volume tables kept in the
/// Index ledger (zstd::zstd_mount_join), and `fd` closed. A failed mount
/// gives the tables back. zstd keeps the cache defaults.
unsafe fn load_zstd_manifest(
    state: *mut PackState,
    fd: c_int,
    len: u64,
    b: &mut Builder<'_>,
) -> bool {
    if !unsafe { zstd::zstd_mount_fd(fd, len, b) } {
        unsafe { zstd::zstd_mount_release() };
        clear_manifest_view(state);
        return false;
    }
    unsafe { initialize_caches(state) };
    true
}

/// Whether the pack index is mounted. Every mount joins the pack index to
/// the view the index load builds, so only `mount_and_join` starts it and
/// this waits for it or answers false.
pub(crate) unsafe fn ensure_manifest_ready() -> bool {
    unsafe { ensure_manifest_loaded(None) }
}

/// `ensure_ready_slow` (rt/index.rs), before it publishes the index:
/// mounts the pack index and joins it to `b`.
pub(crate) unsafe fn mount_and_join(b: &mut Builder<'_>) -> bool {
    unsafe { ensure_manifest_loaded(Some(b)) }
}

/// The single claimed load; with `b == None` a load is never claimed.
pub(crate) unsafe fn ensure_manifest_loaded(mut b: Option<&mut Builder<'_>>) -> bool {
    let state = unsafe { pack_state() };
    loop {
        if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
            return false;
        }
        let current = LOAD_STATE.load(Ordering::Acquire);
        if current == PACK_LOAD_READY {
            return true;
        }
        if current == PACK_LOAD_UNAVAILABLE || current == PACK_LOAD_INVALID {
            return false;
        }
        if current == PACK_LOAD_UNINITIALIZED && b.is_none() {
            return false;
        }
        // Claimed under MANIFEST_MUTEX with the stop flag rechecked: shutdown
        // sets the flag and then waits for LOADING to end under the same
        // mutex, so a load either starts before that wait or not at all.
        let claimed = {
            let _lock = MANIFEST_MUTEX.lock();
            !WORKER_STOP_REQUESTED.load(Ordering::Acquire)
                && LOAD_STATE
                    .compare_exchange(
                        PACK_LOAD_UNINITIALIZED,
                        PACK_LOAD_LOADING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
        };
        if claimed {
            let mut absent = false;
            let loaded = unsafe { load_manifest(state, &mut absent, b.as_deref_mut()) };
            {
                let _lock = MANIFEST_MUTEX.lock();
                let next = if loaded {
                    PACK_LOAD_READY
                } else if absent {
                    PACK_LOAD_UNAVAILABLE
                } else {
                    PACK_LOAD_INVALID
                };
                LOAD_STATE.store(next, Ordering::Release);
            }
            MANIFEST_CV.notify_all();
            return loaded;
        }
        let mut lock = MANIFEST_MUTEX.lock();
        MANIFEST_CV.wait_until(&mut lock, || {
            LOAD_STATE.load(Ordering::Acquire) != PACK_LOAD_LOADING
                || WORKER_STOP_REQUESTED.load(Ordering::Acquire)
        });
    }
}

pub(crate) fn chunk_key_hash(chunk: &AmprPackChunkView) -> u64 {
    ampr_rust_cache_chunk_key_hash(
        chunk.offset,
        chunk.pack_id,
        chunk.stored_size,
        chunk.raw_size,
    )
}

pub(crate) fn cache_key_equal(
    entry: &CacheEntry,
    chunk: &AmprPackChunkView,
    key_hash: u64,
) -> bool {
    entry.state != CacheEntryState::Free
        && entry.key_hash == key_hash
        && entry.pack_id == chunk.pack_id
        && entry.physical_offset == chunk.offset
        && entry.stored_size == chunk.stored_size
        && entry.raw_size == chunk.raw_size
}

pub(crate) unsafe fn cache_find_locked(
    state: *mut PackState,
    chunk: &AmprPackChunkView,
    key_hash: u64,
) -> u32 {
    let bucket = ampr_format::cache::bucket_index(key_hash, AMPR_EMU_PACK_CACHE_HASH_BUCKETS);
    let mut link = (*state).cache_hash_heads[bucket];
    while link != 0 {
        let index = link - 1;
        if index as usize >= AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            break;
        }
        let entry = &(*state).cache_entries[index as usize];
        if cache_key_equal(entry, chunk, key_hash) {
            return index;
        }
        link = entry.hash_next_plus_one;
    }
    INVALID_INDEX
}

pub(crate) unsafe fn cache_hash_link_locked(state: *mut PackState, index: u32) {
    let entry = &mut (*state).cache_entries[index as usize];
    let bucket = ampr_format::cache::bucket_index(entry.key_hash, AMPR_EMU_PACK_CACHE_HASH_BUCKETS);
    entry.hash_next_plus_one = (*state).cache_hash_heads[bucket];
    (*state).cache_hash_heads[bucket] = index + 1;
}

pub(crate) unsafe fn cache_hash_unlink_locked(state: *mut PackState, index: u32) {
    let bucket = ampr_format::cache::bucket_index(
        (*state).cache_entries[index as usize].key_hash,
        AMPR_EMU_PACK_CACHE_HASH_BUCKETS,
    );
    let next = (*state).cache_entries[index as usize].hash_next_plus_one;
    // `prev` is None while the link is the bucket head.
    let mut prev: Option<usize> = None;
    let mut link = (*state).cache_hash_heads[bucket];
    while link != 0 {
        let current = link - 1;
        if current == index {
            match prev {
                None => (*state).cache_hash_heads[bucket] = next,
                Some(p) => (*state).cache_entries[p].hash_next_plus_one = next,
            }
            break;
        }
        if current as usize >= AMPR_EMU_PACK_CACHE_ENTRY_CAP {
            break;
        }
        prev = Some(current as usize);
        link = (*state).cache_entries[current as usize].hash_next_plus_one;
    }
    (*state).cache_entries[index as usize].hash_next_plus_one = 0;
}

/// `bitmap_words(arr)`: the word count of a fixed bitmap array.
pub(crate) const fn bitmap_words<const N: usize>(_: &[u64; N]) -> usize {
    N
}

// Page-bitmap allocator (next-fit with cursor wrap): ampr_format::cache.
pub(crate) unsafe fn cache_mark_pages(state: *mut PackState, start: u32, count: u32, used: bool) {
    let words = bitmap_words(&(*state).cache_page_bitmap);
    unsafe {
        ampr_rust_cache_mark_pages(
            (*state).cache_page_bitmap.as_mut_ptr(),
            words,
            start,
            count,
            used,
        )
    };
}
