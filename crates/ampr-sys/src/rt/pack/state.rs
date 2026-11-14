//! PackState creation, submission admission, virtual fd/AIO id encoding,
//! clocks, pread_exact and overlay path/manifest helpers.

use super::*;

use crate::rt::index::IndexIo;
use core::mem::align_of;
use core::ptr::addr_of_mut;

pub(crate) unsafe fn pack_state_create() -> *mut PackState {
    let state = g_pack_state.load(Ordering::Acquire);
    if !state.is_null() {
        return state;
    }
    if g_pack_state_init
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Storage is zeroed .bss; apply the non-zero `PackState()` defaults in place.
        let s = g_pack_state_storage.get() as *mut PackState;
        unsafe {
            for i in 0..AMPR_EMU_PACK_VIRTUAL_FD_SLOTS {
                addr_of_mut!((*s).virtual_fds[i]).write(VirtualFdSlot::EMPTY);
            }
            for i in 0..AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS {
                addr_of_mut!((*s).virtual_directories[i]).write(VirtualDirectorySlot::EMPTY);
            }
            for i in 0..AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
                addr_of_mut!((*s).virtual_aio[i]).write(VirtualAioSlot::EMPTY);
            }
            for i in 0..AMPR_EMU_PACK_PIPELINE_SLOTS {
                addr_of_mut!((*s).pipelines[i]).write(ReadPipelineContext::EMPTY);
            }
            for i in 0..AMPR_EMU_PACK_MAX_PACKS {
                addr_of_mut!((*s).pack_handles[i]).write(PackHandle::EMPTY);
            }
            for i in 0..AMPR_EMU_PACK_CACHE_ENTRY_CAP {
                addr_of_mut!((*s).cache_entries[i]).write(CacheEntry::EMPTY);
            }
            let st = &mut *s;
            st.queue_head = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            st.queue_tail = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            st.prefetch_head = INVALID_INDEX;
            st.prefetch_tail = INVALID_INDEX;
            st.decoded_cache_target_bytes = super::super::tune::decoded_bytes();
            st.requested_workers = super::super::tune::workers();
            st.latency_reserve_workers = AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS;
            st.pipeline_free_head = INVALID_INDEX;
            st.cache_free_head = INVALID_INDEX;
            st.tick = 1;
        }
        g_pack_state.store(s, Ordering::Release);
        g_pack_state_init.store(2, Ordering::Release);
        return s;
    }
    let mut spins = 0u32;
    while g_pack_state_init.load(Ordering::Acquire) != 2 {
        spin_pause_or_yield(&mut spins);
    }
    g_pack_state.load(Ordering::Acquire)
}

/// The shared PackState, as a raw pointer on purpose. Workers, the reactor
/// and game threads use it at once, each field under its own lock (PACK_M,
/// CACHE_MUTEX, ...). A `&mut PackState` (or `&PackState`) would claim the
/// whole struct for its lifetime, so two threads holding one each is UB and
/// lets LLVM cache fields across a condvar wait (`noalias`). Field places
/// `(*state).x` and references to single fields or elements carry no such
/// claim, so they are sound as long as the field's lock is held, as before.
/// Callers must not form a reference to the whole PackState.
pub(crate) unsafe fn pack_state() -> *mut PackState {
    unsafe { pack_state_create() }
}

impl PackSubmission {
    pub(crate) unsafe fn new(state: *mut PackState) -> Self {
        let _lock = PACK_M.lock();
        let admitted = !(*state).submissions_closed;
        if admitted {
            (*state).active_submissions += 1;
        }
        Self { state, admitted }
    }
    pub(crate) fn admitted(&self) -> bool {
        self.admitted
    }
}

impl Drop for PackSubmission {
    fn drop(&mut self) {
        if !self.admitted {
            return;
        }
        let _lock = PACK_M.lock();
        // SAFETY: `state` is the published PackState (`pack_state()`), and
        // PACK_M guards `active_submissions`.
        let state = self.state;
        let left = unsafe {
            (*state).active_submissions -= 1;
            (*state).active_submissions
        };
        if left == 0 {
            SUBMIT_CV.notify_all();
        }
    }
}

pub(crate) fn next_generation(current: u16) -> u32 {
    ampr_rust_virtual_next_generation(current)
}

/// Open slot named by a synthetic packed fd (`BASE + slot`), or None for a
/// number outside the range or whose slot is closed. The kernel's effective
/// table tops out at 258. Callers confirm the slot under PACK_M with
/// `VirtualFdSlot::holds`.
fn packed_fd_slot(value: u32) -> Option<u32> {
    let slot = value.checked_sub(AMPR_EMU_PACK_VIRTUAL_FD_BASE as u32)?;
    ((slot as usize) < AMPR_EMU_PACK_VIRTUAL_FD_SLOTS
        && VIRTUAL_FD_LIVE[slot as usize].load(Ordering::Acquire))
    .then_some(slot)
}

pub(crate) fn decode_virtual_fd(fd: c_int) -> Option<u32> {
    if fd < 0 || g_pack_state.load(Ordering::Acquire).is_null() {
        return None;
    }
    packed_fd_slot(fd as u32)
}

/// The number a directory slot has: `DIRECTORY_BASE + slot`.
pub(crate) fn encode_virtual_directory_fd(slot: u32) -> c_int {
    (AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE as u32 + slot) as c_int
}

/// Open slot named by a synthetic directory fd, or None for a number outside
/// `DIRECTORY_BASE..DIRECTORY_BASE + SLOTS` or whose slot is closed. Callers
/// confirm the slot under its DIRECTORY_MUTEXES entry with `active`: a slot
/// closed and opened again keeps its number, as a kernel fd would.
fn directory_fd_slot(value: u32) -> Option<u32> {
    let slot = value.checked_sub(AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE as u32)?;
    ((slot as usize) < AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS
        && VIRTUAL_DIRECTORY_LIVE[slot as usize].load(Ordering::Acquire))
    .then_some(slot)
}

/// Decided before `pack_state()`, like `decode_virtual_fd`: a physical fd never
/// creates or waits on the pack state.
pub(crate) fn decode_virtual_directory_fd(fd: c_int) -> Option<u32> {
    if fd < 0 || g_pack_state.load(Ordering::Acquire).is_null() {
        return None;
    }
    directory_fd_slot(fd as u32)
}

pub(crate) fn encode_virtual_aio(slot: u32, generation: u16) -> SceKernelAioSubmitId {
    ampr_rust_virtual_encode(VIRTUAL_KIND_AIO, slot, generation) as SceKernelAioSubmitId
}

pub(crate) unsafe fn decode_virtual_aio(
    id: SceKernelAioSubmitId,
    slot: *mut u32,
    generation: *mut u16,
) -> bool {
    unsafe {
        ampr_rust_virtual_decode(
            VIRTUAL_KIND_AIO,
            id as u32,
            AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32,
            slot,
            generation,
        )
    }
}

/// Tag-only check: the low byte is always below 256, so any slot passes.
pub(crate) fn has_virtual_aio_tag(id: SceKernelAioSubmitId) -> bool {
    unsafe { ampr_rust_virtual_decode(VIRTUAL_KIND_AIO, id as u32, 256, null_mut(), null_mut()) }
}

pub(crate) fn encode_virtual_aio_group(slot: u32, generation: u16) -> SceKernelAioSubmitId {
    ampr_rust_virtual_encode(VIRTUAL_KIND_AIO_GROUP, slot, generation) as SceKernelAioSubmitId
}

pub(crate) unsafe fn decode_virtual_aio_group(
    id: SceKernelAioSubmitId,
    slot: *mut u32,
    generation: *mut u16,
) -> bool {
    unsafe {
        ampr_rust_virtual_decode(
            VIRTUAL_KIND_AIO_GROUP,
            id as u32,
            AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32,
            slot,
            generation,
        )
    }
}

pub(crate) fn pack_monotonic_usecs() -> u64 {
    let mut ts = SceKernelTimespec::default();
    if unsafe { sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000)
        .wrapping_add(ts.tv_nsec as u64 / 1000)
}

pub(crate) fn pack_telemetry_usecs() -> u64 {
    0
}

pub(crate) fn elapsed_usecs(start: u64, end: u64) -> u64 {
    if start != 0 && end >= start {
        end - start
    } else {
        0
    }
}

pub(crate) unsafe fn pread_exact(
    fd: c_int,
    destination: *mut c_void,
    size: usize,
    offset: u64,
) -> bool {
    let Some(f) = (unsafe { real_pread() }) else {
        return false;
    };
    let out = destination as *mut u8;
    pread_loop(
        size,
        offset,
        AMPR_EMU_PACK_PREAD_MAX_BYTES as usize,
        |done, request, at| unsafe { f(fd, out.add(done) as *mut c_void, request, at) },
        errno,
    )
}

/// Consecutive EINTR results `pread_loop` retries before it gives up.
pub(crate) const PREAD_EINTR_RETRIES: u32 = 16;

/// The `pread_exact` loop over `read(done, request, offset) -> rc` (libc
/// pread semantics: -1 with `errno()`). A short read continues from where it
/// stopped: a USB (exFAT, bfs) pread may return fewer bytes than asked before
/// EOF. EINTR is retried (a signal is not an I/O error; the old loop failed
/// the manifest load or pack open on it); EOF (0) or any other error fails.
pub(crate) fn pread_loop(
    size: usize,
    offset: u64,
    max_request: usize,
    mut read: impl FnMut(usize, usize, off_t) -> ssize_t,
    errno: impl Fn() -> c_int,
) -> bool {
    if offset > off_t::MAX as u64 || size as u64 > off_t::MAX as u64 - offset {
        return false;
    }
    let mut done = 0usize;
    let mut interrupted = 0u32;
    while done < size {
        let request = (size - done).min(max_request.max(1));
        let rc = read(done, request, (offset + done as u64) as off_t);
        if rc < 0 && errno() == EINTR && interrupted < PREAD_EINTR_RETRIES {
            interrupted += 1;
            continue;
        }
        if rc <= 0 || rc as usize > request {
            return false;
        }
        interrupted = 0;
        done += rc as usize;
    }
    true
}

// ---- AMPRPAK4 records, copied out of the mounted manifest ----

/// File record `index` (zero-based) of the mounted manifest; None when no
/// manifest is mounted or the index is out of range.
pub(crate) unsafe fn lz4_file(state: *const PackState, index: u32) -> Option<AmprPackFileRecord> {
    let raw = (*state).core_view.manifest?.file_record_raw(index).ok()?;
    Some(unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) })
}

/// Pack record `id` of the mounted manifest, as `lz4_file`.
pub(crate) unsafe fn lz4_pack(state: *const PackState, id: u32) -> Option<AmprPackDataRecord> {
    let raw = (*state).core_view.manifest?.pack_record_raw(id).ok()?;
    Some(unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) })
}

/// The NUL-terminated string-table entry at `offset` copied into `buf`
/// (without its NUL); None when absent or longer than `buf`.
pub(crate) unsafe fn manifest_string<'b>(
    state: *const PackState,
    offset: u32,
    length: u32,
    buf: &'b mut [u8],
) -> Option<&'b [u8]> {
    (*state)
        .core_view
        .manifest?
        .string(offset, length, buf)
        .ok()
}

pub(crate) fn overlay_bytes(value: *const c_char) -> *const u8 {
    value as *const u8
}

/// The view the overlay shims (overlay_ffi.rs) read the manifest from.
pub(crate) unsafe fn overlay_manifest(state: *const PackState) -> *const AmprPackCoreView {
    &raw const (*state).core_view
}

fn fold(c: c_char) -> u8 {
    (c as u8).to_ascii_lowercase()
}

pub(crate) unsafe fn folded_equal(
    a: *const c_char,
    a_length: usize,
    b: *const c_char,
    b_length: usize,
) -> bool {
    a_length == b_length && (0..a_length).all(|i| unsafe { fold(*a.add(i)) == fold(*b.add(i)) })
}

/// File record `file_index`'s path copied into `buf`; `Err(Io)` for a
/// read error of a paged index, apart from an absent record.
pub(crate) unsafe fn file_record_path<'b>(
    state: *const PackState,
    file_index: u32,
    buf: &'b mut [u8],
) -> ampr_format::Result<&'b [u8]> {
    let manifest = (*state)
        .core_view
        .manifest
        .ok_or(ampr_format::Error::Invalid)?;
    let raw = manifest.file_record_raw(file_index)?;
    let file: AmprPackFileRecord = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) };
    manifest.string(file.path_offset, file.path_length, buf)
}

pub(crate) unsafe fn folded_hash(value: *const c_char, length: usize) -> u64 {
    unsafe { ampr_rust_overlay_folded_hash(overlay_bytes(value), length) }
}

pub(crate) unsafe fn normalize_overlay_path(
    input: *const c_char,
    output: *mut c_char,
    capacity: usize,
    out_length: *mut u16,
) -> bool {
    unsafe {
        ampr_rust_overlay_normalize_path(
            overlay_bytes(input),
            output as *mut u8,
            capacity,
            out_length,
        )
    }
}

pub(crate) unsafe fn build_packed_file_order(state: *mut PackState) -> bool {
    if (*state).header.is_null() || (*state).core_view.manifest.is_none() {
        return false;
    }
    let count = unsafe { ampr_rust_overlay_packed_count(overlay_manifest(state)) };
    (*state).packed_file_count = count;
    if count == 0 {
        return true;
    }
    let bytes = count as usize * size_of::<u32>();
    let memory = unsafe {
        crate::rt::index_memory::lookup_alloc(
            bytes,
            align_of::<u32>(),
            c"apr.pack.directory-index".as_ptr(),
        )
    };
    if memory.is_null() {
        return false;
    }
    (*state).packed_file_order = memory as *mut u32;
    unsafe {
        ampr_rust_overlay_build_order(overlay_manifest(state), (*state).packed_file_order, count)
    }
}

/// The packed directory order: AMPRPAK4 record indexes from
/// `build_packed_file_order`, or (zstd) the zstd file ids sorted when the
/// projection was built.
pub(crate) unsafe fn packed_order(state: *const PackState) -> (*const u32, u32) {
    if zstd_mode() {
        let order = zstd::zstd_packed_order();
        (order.as_ptr(), order.len() as u32)
    } else {
        ((*state).packed_file_order, (*state).packed_file_count)
    }
}

/// The packed span below `directory`; `Err(IndexIo)` when an index read
/// failed on the way (the directory may be packed: EIO, not ENOENT).
pub(crate) unsafe fn find_virtual_directory_range(
    state: *const PackState,
    directory: *const c_char,
    directory_length: u16,
    out_begin: *mut u32,
    out_end: *mut u32,
) -> Result<bool, IndexIo> {
    let (order, count) = packed_order(state);
    let found = unsafe {
        ampr_rust_overlay_directory_range(
            overlay_manifest(state),
            order,
            count,
            overlay_bytes(directory),
            directory_length,
            out_begin,
            out_end,
        )
    };
    match found {
        Ok(found) => Ok(found),
        Err(ampr_format::Error::Io) => Err(IndexIo),
        Err(_) => Ok(false),
    }
}

/// A packed file found by `resolve_packed_file`, per pack format.
pub(crate) enum PackedFile {
    /// AMPRPAK4: the manifest file record, copied out.
    Lz4(AmprPackFileRecord),
    /// zstd: the resident AMPRIDX3 entry view.
    Zstd(FileEntryView),
}

/// The one-based AMPRIDX3 id of `path` and its packed file, when the id
/// names a packed file of the indexed size (for zstd: an R4 projection onto
/// a zstd file). An id without a packed record is loose (`Ok(None)`).
/// `Err(IndexIo)` when an index read failed on the way: the file may be
/// packed and has no disk copy then, so the caller answers EIO, never
/// "not packed".
pub(crate) unsafe fn resolve_packed_file(
    state: *const PackState,
    path: *const c_char,
) -> Result<Option<(u32, PackedFile)>, IndexIo> {
    let zstd = zstd_mode();
    let mut file_id = 0u32;
    let mut indexed_size = 0usize;
    if path.is_null() {
        return Ok(None);
    }
    match unsafe { ampr_index_resolve_path_to_id(path, &mut file_id, &mut indexed_size) } {
        0 => {}
        rc if rc == -EIO => return Err(IndexIo),
        _ => return Ok(None),
    }
    if !zstd && (*state).header.is_null() {
        return Ok(None);
    }
    let packed = unsafe {
        ampr_rust_overlay_packed_file_matches(overlay_manifest(state), file_id, indexed_size as u64)
    };
    match packed {
        Ok(true) => {}
        Err(ampr_format::Error::Io) => return Err(IndexIo),
        _ => return Ok(None),
    }
    let file = if zstd {
        let mut entry = FileEntryView {
            path: null(),
            path_length: 0,
            size: 0,
            mtime: 0,
        };
        match unsafe { ampr_index_get_entry_view(file_id, &mut entry) } {
            0 => PackedFile::Zstd(entry),
            rc if rc == -EIO => return Err(IndexIo),
            _ => return Ok(None),
        }
    } else {
        let Some(m) = (*state).core_view.manifest else {
            return Ok(None);
        };
        match m.file_record_raw(file_id - 1) {
            Ok(raw) => PackedFile::Lz4(unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) }),
            Err(ampr_format::Error::Io) => return Err(IndexIo),
            Err(_) => return Ok(None),
        }
    };
    Ok(Some((file_id, file)))
}

pub(crate) unsafe fn fill_synthetic_stat(
    stat: *mut SceKernelStat,
    directory: bool,
    size: u64,
    mtime: i64,
    inode_seed: u64,
) {
    if stat.is_null() {
        return;
    }
    unsafe { stat.write_bytes(0, 1) };
    let st = unsafe { &mut *stat };
    st.st_mode = if directory {
        S_IFDIR | 0o555
    } else {
        S_IFREG | 0o444
    };
    st.st_nlink = if directory { 2 } else { 1 };
    st.st_size = size as i64;
    st.st_blksize = 65536;
    st.st_blocks = (size.wrapping_add(511) / 512) as i64;
    st.st_mtim.tv_sec = mtime;
    st.st_atim.tv_sec = mtime;
    st.st_ctim.tv_sec = mtime;
    st.st_ino = ((inode_seed & 0x7fff_ffff) | 1) as u32;
}

pub(crate) unsafe fn joined_entry_matches_path(
    directory: *const c_char,
    directory_length: u16,
    name: *const c_char,
    name_length: usize,
    target: *const c_char,
) -> bool {
    if directory.is_null() || name.is_null() || target.is_null() {
        return false;
    }
    let dir_len = directory_length as usize;
    let target_length = unsafe { CStr::from_ptr(target) }.count_bytes();
    let slash = dir_len == 0 || unsafe { *directory.add(dir_len - 1) } != b'/' as c_char;
    if dir_len + slash as usize + name_length != target_length {
        return false;
    }
    if !unsafe { folded_equal(directory, dir_len, target, dir_len) } {
        return false;
    }
    let mut target_cursor = dir_len;
    if slash {
        if unsafe { *target.add(target_cursor) } != b'/' as c_char {
            return false;
        }
        target_cursor += 1;
    }
    unsafe { folded_equal(name, name_length, target.add(target_cursor), name_length) }
}

pub(crate) unsafe fn service_name_hidden(
    state: *const PackState,
    directory: *const c_char,
    directory_length: u16,
    name: *const c_char,
    name_length: usize,
) -> bool {
    // AMPR_EMU_PACK_INDEX_PATH is /app0/ampr_assets.index.
    const FIXED_PATHS: [&CStr; 4] = [
        c"/app0/ampr_emu.index",
        c"/app0/ampr_commands.bin",
        c"/app0/ampr_emu.log",
        AMPR_EMU_PACK_INDEX_PATH,
    ];
    // zstd: ampr_zstd.index and the mounted ampr_zstd-NNN.pak volumes.
    if zstd_mode()
        && !directory.is_null()
        && !name.is_null()
        && unsafe {
            ampr_rust_overlay_service_name_hidden(
                null(),
                directory as *const u8,
                directory_length,
                name as *const u8,
                name_length,
            )
        }
    {
        return true;
    }
    for path in FIXED_PATHS {
        if unsafe {
            joined_entry_matches_path(
                directory,
                directory_length,
                name,
                name_length,
                path.as_ptr(),
            )
        } {
            return true;
        }
    }

    // Hide the exact physical volumes named by the loaded manifest; pack
    // names are deployment-relative to the logical /app0 namespace.
    let root = AMPR_EMU_PACK_LOGICAL_ROOT_PATH.to_bytes();
    if !(*state).header.is_null() {
        let root_slash = root.last() != Some(&b'/');
        for pack_id in 0..unsafe { (*(*state).header).pack_count } {
            let Some(record) = (unsafe { lz4_pack(state, pack_id) }) else {
                continue;
            };
            let mut pack_name = [0u8; SCE_KERNEL_PATH_MAX];
            let Some(pack_name) = (unsafe {
                manifest_string(
                    state,
                    record.name_offset,
                    record.name_length,
                    &mut pack_name,
                )
            }) else {
                continue;
            };
            let name_len = pack_name.len();
            let target_length = root.len() + root_slash as usize + name_len;
            if target_length >= SCE_KERNEL_PATH_MAX {
                continue;
            }
            let mut target = [0 as c_char; SCE_KERNEL_PATH_MAX];
            let t = target.as_mut_ptr();
            unsafe {
                core::ptr::copy_nonoverlapping(root.as_ptr() as *const c_char, t, root.len());
                let mut cursor = root.len();
                if root_slash {
                    *t.add(cursor) = b'/' as c_char;
                    cursor += 1;
                }
                core::ptr::copy_nonoverlapping(
                    pack_name.as_ptr() as *const c_char,
                    t.add(cursor),
                    name_len,
                );
                if joined_entry_matches_path(directory, directory_length, name, name_length, t) {
                    return true;
                }
            }
        }
    }

    // Also hide stale/default-named volumes in /app0.
    if !unsafe {
        folded_equal(
            directory,
            directory_length as usize,
            root.as_ptr() as *const c_char,
            root.len(),
        )
    } {
        return false;
    }
    const PACK_PREFIX: &[u8] = b"ampr_assets-";
    const SUFFIX: &[u8] = b".pak";
    name_length > PACK_PREFIX.len()
        && name_length >= SUFFIX.len()
        && unsafe {
            folded_equal(
                name,
                PACK_PREFIX.len(),
                PACK_PREFIX.as_ptr() as *const c_char,
                PACK_PREFIX.len(),
            ) && folded_equal(
                name.add(name_length - SUFFIX.len()),
                SUFFIX.len(),
                SUFFIX.as_ptr() as *const c_char,
                SUFFIX.len(),
            )
        }
}

pub(crate) unsafe fn join_directory_child(
    slot: &VirtualDirectorySlot,
    name: *const c_char,
    name_length: usize,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    let path_len = slot.path_length as usize;
    let slash = path_len == 0 || slot.path[path_len - 1] != b'/' as c_char;
    let needed = path_len + slash as usize + name_length + 1;
    if output.is_null() || needed > capacity {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(slot.path.as_ptr(), output, path_len);
        let mut cursor = path_len;
        if slash {
            *output.add(cursor) = b'/' as c_char;
            cursor += 1;
        }
        core::ptr::copy_nonoverlapping(name, output.add(cursor), name_length);
        *output.add(cursor + name_length) = 0;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Serves `data` from `offset`, with the per-call results in `script`
    /// (Some(n): at most n bytes; None: -1 with EINTR), then whole requests.
    fn run(data: &[u8], offset: u64, size: usize, script: &[Option<usize>]) -> (bool, Vec<u8>) {
        let mut out = vec![0u8; size];
        let calls = Cell::new(0usize);
        let ok = pread_loop(
            size,
            offset,
            4,
            |done, request, at| {
                let step = calls.get();
                calls.set(step + 1);
                let limit = match script.get(step) {
                    Some(None) => return -1,
                    Some(Some(n)) => *n,
                    None => request,
                };
                let at = at as usize;
                let n = request.min(limit).min(data.len().saturating_sub(at));
                out[done..done + n].copy_from_slice(&data[at..at + n]);
                n as ssize_t
            },
            || EINTR,
        );
        (ok, out)
    }

    #[test]
    fn pread_loop_handles_short_reads_eintr_eof_and_errors() {
        // pread loop continues short reads and retries eintr.
        let data: Vec<u8> = (0..32u8).collect();
        let (ok, out) = run(&data, 3, 10, &[Some(1), None, Some(2), None, None]);
        assert!(ok);
        assert_eq!(out, data[3..13]);

        // pread loop fails on eof errors and endless eintr.
        let data: Vec<u8> = (0..8u8).collect();
        assert!(!run(&data, 4, 8, &[]).0, "EOF before size");
        let endless = vec![None; PREAD_EINTR_RETRIES as usize + 1];
        assert!(!run(&data, 0, 4, &endless).0);
        assert!(!pread_loop(1, 0, 4, |_, _, _| -1, || EINTR + 1), "EIO");
        assert!(!pread_loop(1, off_t::MAX as u64, 4, |_, _, _| 1, || 0));
        assert!(!pread_loop(2, 0, 4, |_, _, _| 3, || 0), "rc above request");
    }

    /// A directory fd is `DIRECTORY_BASE + slot`, claimed only while its slot
    /// is open, and the packed and directory ranges never overlap, so a stale
    /// number cannot decode as the other kind.
    #[test]
    fn directory_fd_range_and_slot_reuse() {
        let base = AMPR_EMU_PACK_VIRTUAL_DIRECTORY_BASE as u32;
        let end = base + AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS as u32;
        let last = AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS - 1;
        assert_eq!(end, 1024, "top of the range a title accepts");
        assert_eq!(encode_virtual_directory_fd(0), base as c_int);
        assert_eq!(encode_virtual_directory_fd(last as u32), end as c_int - 1);
        // A closed slot's number is not claimed: it goes to the kernel.
        assert_eq!(directory_fd_slot(base), None);
        VIRTUAL_DIRECTORY_LIVE[0].store(true, Ordering::Release);
        VIRTUAL_DIRECTORY_LIVE[last].store(true, Ordering::Release);
        assert_eq!(directory_fd_slot(base - 1), None);
        assert_eq!(directory_fd_slot(base), Some(0));
        assert_eq!(directory_fd_slot(end - 1), Some(last as u32));
        assert_eq!(directory_fd_slot(end), None);
        // The old tagged value is not a directory fd any more.
        assert_eq!(directory_fd_slot(0x6700_0000), None);
        VIRTUAL_DIRECTORY_LIVE[0].store(false, Ordering::Release);
        VIRTUAL_DIRECTORY_LIVE[last].store(false, Ordering::Release);
        assert_eq!(directory_fd_slot(base), None);

        // Packed numbers never decode as a directory, nor the reverse.
        VIRTUAL_FD_LIVE[AMPR_EMU_PACK_VIRTUAL_FD_SLOTS - 1].store(true, Ordering::Release);
        VIRTUAL_DIRECTORY_LIVE[0].store(true, Ordering::Release);
        let packed_top = (AMPR_EMU_PACK_VIRTUAL_FD_BASE + AMPR_EMU_PACK_VIRTUAL_FD_SLOTS - 1) as u32;
        assert_eq!(directory_fd_slot(packed_top), None);
        assert_eq!(packed_fd_slot(base), None);
        VIRTUAL_FD_LIVE[AMPR_EMU_PACK_VIRTUAL_FD_SLOTS - 1].store(false, Ordering::Release);
        VIRTUAL_DIRECTORY_LIVE[0].store(false, Ordering::Release);
    }

    #[test]
    fn packed_fd_range_and_slot_reuse() {
        let base = AMPR_EMU_PACK_VIRTUAL_FD_BASE as u32;
        let end = base + AMPR_EMU_PACK_VIRTUAL_FD_SLOTS as u32;
        let last = AMPR_EMU_PACK_VIRTUAL_FD_SLOTS - 1;
        // A closed slot's number is not claimed: it goes to the kernel.
        assert_eq!(packed_fd_slot(base), None);
        VIRTUAL_FD_LIVE[0].store(true, Ordering::Release);
        VIRTUAL_FD_LIVE[last].store(true, Ordering::Release);
        assert_eq!(packed_fd_slot(base - 1), None);
        assert_eq!(packed_fd_slot(base), Some(0));
        assert_eq!(packed_fd_slot(end - 1), Some(last as u32));
        assert_eq!(packed_fd_slot(end), None);
        VIRTUAL_FD_LIVE[0].store(false, Ordering::Release);
        VIRTUAL_FD_LIVE[last].store(false, Ordering::Release);
        assert_eq!(packed_fd_slot(base), None);

        let slot = VirtualFdSlot {
            handle: base as c_int,
            active: true,
            ..VirtualFdSlot::EMPTY
        };
        assert!(slot.holds(base as c_int));
        assert!(!slot.holds(base as c_int + 1));
        assert!(!VirtualFdSlot::EMPTY.holds(-1));
    }

    // ---- paged AMPRPAK4 index ----

    /// An AMPRPAK4 image of `n` empty packed files and exactly `bytes`
    /// bytes: the paths take what the records leave. No chunks, no packs.
    fn lz4_index(n: usize, bytes: usize) -> Vec<u8> {
        use ampr_format::{crc32, header_crc, pak_path_hash};
        const HEADER: usize = 128;
        let strings_at = HEADER + n * 48;
        let (base, extra) = ((bytes - strings_at) / n, (bytes - strings_at) % n);
        let mut b = vec![0u8; strings_at];
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        for i in 0..n {
            let mut path = format!("/app0/d{:03}/f{i:07}", i % 997).into_bytes();
            path.resize(base - 1 + usize::from(i < extra), b'a');
            let at = HEADER + i * 48;
            put64(&mut b, at, pak_path_hash(&path));
            let off = (b.len() - strings_at) as u32;
            put32(&mut b, at + 32, off);
            put32(&mut b, at + 36, path.len() as u32);
            put32(&mut b, at + 40, 1); // FILE_PACKED, empty: no chunks
            b[at + 44] = 14; // block_shift
            b.extend_from_slice(&path);
            b.push(0);
        }
        assert_eq!(b.len(), bytes);
        b[..8].copy_from_slice(b"AMPRPAK4");
        put32(&mut b, 8, 4);
        put32(&mut b, 12, HEADER as u32);
        put32(&mut b, 20, 0x0102_0304);
        put64(&mut b, 40, n as u64);
        put32(&mut b, 60, 48);
        put32(&mut b, 64, 12);
        put32(&mut b, 68, 32);
        put64(&mut b, 72, HEADER as u64);
        for at in [80, 88, 96] {
            put64(&mut b, at, strings_at as u64);
        }
        put64(&mut b, 104, (bytes - strings_at) as u64);
        let payload = crc32(&b[HEADER..]);
        put32(&mut b, 112, payload);
        let crc = header_crc(&b, HEADER, 116).unwrap();
        put32(&mut b, 116, crc);
        b
    }

    /// An LZ4 index read error is not a miss: the open validation answers
    /// EIO (as zstd `VALIDATE_IO`) and the packed check `Err(Io)`, so
    /// neither the open nor the stat (rt/pack/directories.rs) falls to a
    /// disk copy the packed file does not have.
    #[test]
    fn an_lz4_index_read_error_is_eio_not_a_miss() {
        use crate::rt::index::AmprPackCoreView;
        use crate::rt::index_pages::{self, IndexSource};
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        // 2000 records span six 16 KiB pages; the cache holds one page.
        let n = 2000u32;
        let image: &'static [u8] = lz4_index(n as usize, 128 + 2000 * 88).leak();
        let fail: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let src = IndexSource::Paged(index_pages::test_file(image, fail));
        let src: &'static IndexSource = Box::leak(Box::new(src));
        let mut view = AmprPackCoreView::EMPTY;
        view.manifest = Some(ampr_lz4::manifest::Manifest::open(src).unwrap());
        let m = view.manifest.unwrap();
        let path = |id: u32| {
            let mut buf = [0u8; SCE_KERNEL_PATH_MAX];
            m.path(&m.file(id - 1).unwrap(), &mut buf).unwrap().to_vec()
        };
        let (first, last) = (path(1), path(n));
        let validate = |id: u32, p: &[u8]| unsafe {
            ampr_pack_core_validate_logical_file(&view, id, p.as_ptr().cast(), p.len(), 0)
        };
        let matches = |id: u32| unsafe { ampr_rust_overlay_packed_file_matches(&view, id, 0) };
        assert_eq!((validate(1, &first), matches(1)), (0, Ok(true)));
        // The one cached page now holds paths; the last records are paged out.
        fail.store(true, SeqCst);
        assert_eq!(validate(n, &last), SCE_KERNEL_ERROR_EIO);
        assert_eq!(matches(n - 1), Err(ampr_format::Error::Io));
        // An id outside the index stays an answer, not an error.
        assert_eq!(matches(n + 1), Ok(false));
        assert_ne!(validate(n + 1, &last), SCE_KERNEL_ERROR_EIO);
        fail.store(false, SeqCst);
        assert_eq!((validate(n, &last), matches(n - 1)), (0, Ok(true)));
    }

    /// A 52 MiB AMPRPAK4 index of 786,432 packed files mounts paged: its
    /// fast table (the 48 B records) and its directory order (4 B per
    /// packed file) are index memory, its paths are not. With a page less
    /// room than those need it is refused with the index notice and takes
    /// nothing; the release gives every byte back.
    #[test]
    fn a_52_mib_lz4_index_mounts_paged_with_its_fast_table() {
        use crate::rt::index_memory as im;
        use crate::rt::index_pages::{self, IndexSource};
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 786_432usize;
        let image = lz4_index(n, 52 << 20);
        let layout = std::alloc::Layout::new::<PackState>();
        let state = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<PackState>();
        assert!(!state.is_null());
        let manifest = super::super::manifest::validate_manifest_layout;
        unsafe {
            let src = index_pages::register_memory(image.as_ptr(), image.len()).unwrap();
            let src: &'static IndexSource = Box::leak(Box::new(IndexSource::Paged(src)));
            let used = im::test_index_used();
            let (page, needed) = (SCE_KERNEL_PAGE_SIZE, n * 48 + n * 4);
            im::test_take_index_notice();
            let fill = (im::index_room() - needed) / page * page + page;
            let other = im::index_alloc(fill, page, c"test.other.tables".as_ptr());
            assert!(!other.is_null());
            assert!(!manifest(state, src));
            assert!(im::test_take_index_notice());
            assert_eq!(im::test_index_used(), used + fill);
            assert!((*state).header.is_null());
            im::index_free(other.cast(), c"test.other.tables.free".as_ptr());

            assert!(manifest(state, src));
            assert!(!im::test_take_index_notice());
            assert_eq!({ (*(*state).header).file_count }, n as u64);
            assert!((*state).core_view.manifest.is_some_and(|m| m.has_fast()));
            assert!(build_packed_file_order(state));
            assert_eq!((*state).packed_file_count as usize, n);
            let grown = im::test_index_used() - used;
            assert!(grown >= needed && grown < image.len(), "{grown}");
            assert_eq!(
                lz4_file(state, 0).map(|f| f.flags),
                Some(AMPR_PACK_FILE_PACKED)
            );
            assert!(lz4_file(state, n as u32).is_none());
            let mut buf = [0u8; SCE_KERNEL_PATH_MAX];
            let path = file_record_path(state, 0, &mut buf).unwrap();
            assert!(path.starts_with(b"/app0/"));
            super::super::manifest::release_manifest_storage(state);
            assert!((*state).header.is_null() && lz4_file(state, 0).is_none());
            assert_eq!(im::test_index_used(), used);
            assert_eq!(im::lookup_used(), 0);
            index_pages::unregister(match *src {
                IndexSource::Paged(p) => p,
                IndexSource::Resident(_) => unreachable!(),
            });
            std::alloc::dealloc(state.cast(), layout);
        }
    }
}
