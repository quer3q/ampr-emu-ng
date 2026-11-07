//! PackState creation, submission admission, virtual fd/AIO id encoding,
//! clocks, pread_exact and overlay path/manifest helpers.

use super::*;

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
            for i in 0..AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP {
                addr_of_mut!((*s).physical_cache_entries[i]).write(PhysicalCacheEntry::EMPTY);
            }
            let st = &mut *s;
            st.queue_head = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            st.queue_tail = [[INVALID_INDEX; PACK_WORK_CLASS_COUNT]; 3];
            st.prefetch_head = INVALID_INDEX;
            st.prefetch_tail = INVALID_INDEX;
            super::super::tune::load();
            st.decoded_cache_target_bytes = super::super::tune::decoded_bytes();
            st.physical_cache_target_bytes = super::super::tune::physical_bytes();
            st.requested_workers = super::super::tune::workers();
            st.latency_reserve_workers = AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS;
            st.pipeline_free_head = INVALID_INDEX;
            st.cache_free_head = INVALID_INDEX;
            st.physical_cache_free_head = INVALID_INDEX;
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

/// Slot mapped to low fd `number`, or None when it is a physical fd.
pub(crate) fn virtual_fd_slot_for(number: u32) -> Option<u32> {
    if number as usize >= AMPR_EMU_PACK_VIRTUAL_FD_LIMIT {
        return None;
    }
    let entry = VIRTUAL_FD_SLOTS[number as usize].load(Ordering::Acquire);
    entry.checked_sub(1)
}

/// Tagged packed-file handle for `slot` (`0x6500_0000 | generation << 8 |
/// slot`). Used when no low descriptor could be reserved, so the open does
/// not fail with EMFILE once the process is at its file limit.
pub(crate) fn encode_virtual_fd(slot: u32, generation: u16) -> c_int {
    ampr_rust_virtual_encode(VIRTUAL_KIND_FD, slot, generation) as c_int
}

/// Slot named by a tagged packed-file handle, before `VirtualFdSlot::holds`
/// confirms it is still the same generation.
fn tagged_virtual_fd_slot(fd: c_int) -> Option<u32> {
    if fd < 0 {
        return None;
    }
    let mut slot = 0u32;
    let found = unsafe {
        ampr_rust_virtual_decode(
            VIRTUAL_KIND_FD,
            fd as u32,
            AMPR_EMU_PACK_VIRTUAL_FD_SLOTS as u32,
            &mut slot,
            null_mut(),
        )
    };
    found.then_some(slot)
}

/// Slot of a packed fd: through the reserved-descriptor table when it is a
/// low number, else through its tagged handle (the EMFILE fallback). Unlike
/// the tagged-only handles, a physical fd in the low range is also a
/// candidate, so the table decides; no pack state is created when none
/// exists. Callers confirm the slot under PACK_M with
/// `VirtualFdSlot::holds`.
pub(crate) fn decode_virtual_fd(fd: c_int) -> Option<u32> {
    if g_pack_state.load(Ordering::Acquire).is_null() {
        return None;
    }
    virtual_fd_slot_for(fd as u32).or_else(|| tagged_virtual_fd_slot(fd))
}

/// Drops a packed-fd mapping whose reserved descriptor the kernel has
/// handed out again. `fd` is a descriptor a physical open just returned, so
/// a slot still mapped to that number lost its `/dev/null` reservation to a
/// close the runtime did not see (a `dup2` onto it, an unhooked close such
/// as `_close` with its `AMPR_ZSTD_LIBC_HOOKS` bit cleared). Left mapped,
/// the new file would read as the old packed one. Lock-free unless mapped.
pub(crate) unsafe fn forget_stale_virtual_fd(fd: c_int) {
    if fd < 0 || decode_virtual_fd(fd).is_none() {
        return;
    }
    let _lock = PACK_M.lock();
    unsafe { forget_stale_virtual_fd_locked(g_pack_state.load(Ordering::Acquire), fd) };
}

/// `forget_stale_virtual_fd` under PACK_M. The kernel owns the number now,
/// so the slot is cleared and nothing is closed.
pub(crate) unsafe fn forget_stale_virtual_fd_locked(state: *mut PackState, fd: c_int) {
    let Some(index) = virtual_fd_slot_for(fd as u32) else {
        return;
    };
    let slot = unsafe { &mut (*state).virtual_fds[index as usize] };
    if slot.holds(fd) {
        *slot = VirtualFdSlot::EMPTY;
    }
    VIRTUAL_FD_SLOTS[fd as usize].store(0, Ordering::Release);
}

pub(crate) fn encode_virtual_directory_fd(slot: u32, generation: u16) -> c_int {
    ampr_rust_virtual_encode(VIRTUAL_KIND_DIRECTORY_FD, slot, generation) as c_int
}

pub(crate) unsafe fn decode_virtual_directory_fd(
    fd: c_int,
    slot: *mut u32,
    generation: *mut u16,
) -> bool {
    unsafe {
        ampr_rust_virtual_decode(
            VIRTUAL_KIND_DIRECTORY_FD,
            fd as u32,
            AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS as u32,
            slot,
            generation,
        )
    }
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

pub(crate) unsafe fn manifest_string(
    state: *const PackState,
    offset: u32,
    length: u32,
) -> *const c_char {
    let (offset, length) = (offset as usize, length as usize);
    if (*state).strings.is_null()
        || offset >= (*state).strings_bytes
        || length >= (*state).strings_bytes - offset
    {
        return null();
    }
    let value = unsafe { (*state).strings.add(offset) };
    if unsafe { *value.add(length) } == 0 {
        value
    } else {
        null()
    }
}

pub(crate) fn overlay_bytes(value: *const c_char) -> *const u8 {
    value as *const u8
}

pub(crate) unsafe fn overlay_manifest(state: *const PackState) -> *const u8 {
    (*state).core_view.base
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

pub(crate) unsafe fn file_record_path(state: *const PackState, file_index: u32) -> *const c_char {
    if (*state).header.is_null() || file_index as u64 >= unsafe { (*(*state).header).file_count } {
        return null();
    }
    let file = unsafe { *(*state).files.add(file_index as usize) };
    unsafe { manifest_string(state, file.path_offset, file.path_length) }
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
    if (*state).header.is_null() || (*state).files.is_null() {
        return false;
    }
    let count =
        unsafe { ampr_rust_overlay_packed_count(overlay_manifest(state), (*state).core_view.size) };
    (*state).packed_file_count = count;
    if count == 0 {
        return true;
    }
    let mut actual = 0usize;
    let bytes = count as usize * size_of::<u32>();
    let memory = unsafe {
        ampr_internal_amm_pool_alloc(
            bytes,
            &mut actual,
            c"apr.pack.directory-index".as_ptr(),
            true,
            align_of::<u32>(),
        )
    };
    if memory.is_null() || actual < bytes {
        if !memory.is_null() {
            unsafe {
                ampr_internal_amm_pool_free(memory, c"apr.pack.directory-index.short".as_ptr())
            };
        }
        return false;
    }
    (*state).packed_file_order = memory as *mut u32;
    unsafe {
        ampr_rust_overlay_build_order(
            overlay_manifest(state),
            (*state).core_view.size,
            (*state).packed_file_order,
            count,
        )
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

pub(crate) unsafe fn find_virtual_directory_range(
    state: *const PackState,
    directory: *const c_char,
    directory_length: u16,
    out_begin: *mut u32,
    out_end: *mut u32,
) -> bool {
    let (order, count) = packed_order(state);
    unsafe {
        ampr_rust_overlay_directory_range(
            overlay_manifest(state),
            (*state).core_view.size,
            order,
            count,
            overlay_bytes(directory),
            directory_length,
            out_begin,
            out_end,
        )
    }
}

/// A packed file found by `resolve_packed_file`, per pack format.
pub(crate) enum PackedFile {
    /// AMPRPAK4: the manifest file record.
    Lz4(*const AmprPackFileRecord),
    /// zstd: the resident AMPRIDX3 entry view.
    Zstd(FileEntryView),
}

/// The one-based AMPRIDX3 id of `path` and its packed file, when the id
/// names a packed file of the indexed size (for zstd: an R4 projection onto
/// a zstd file). An id without a packed record is loose (None), never an
/// error.
pub(crate) unsafe fn resolve_packed_file(
    state: *const PackState,
    path: *const c_char,
) -> Option<(u32, PackedFile)> {
    let zstd = zstd_mode();
    let mut file_id = 0u32;
    let mut indexed_size = 0usize;
    if path.is_null()
        || unsafe { ampr_index_resolve_path_to_id(path, &mut file_id, &mut indexed_size) } != 0
        || (!zstd && (*state).header.is_null())
        || !unsafe {
            ampr_rust_overlay_packed_file_matches(
                overlay_manifest(state),
                (*state).core_view.size,
                file_id,
                indexed_size as u64,
            )
        }
    {
        return None;
    }
    let file = if zstd {
        let mut entry = FileEntryView {
            path: null(),
            path_length: 0,
            size: 0,
            mtime: 0,
        };
        if unsafe { ampr_index_get_entry_view(file_id, &mut entry) } != 0 {
            return None;
        }
        PackedFile::Zstd(entry)
    } else {
        PackedFile::Lz4(unsafe { (*state).files.add(file_id as usize - 1) })
    };
    Some((file_id, file))
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
    const FIXED_PATHS: [&CStr; 5] = [
        c"/app0/ampr_emu.index",
        c"/app0/ampr_assets.index",
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
                0,
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
    if !(*state).header.is_null() && !(*state).packs.is_null() {
        let root_slash = root.last() != Some(&b'/');
        for pack_id in 0..unsafe { (*(*state).header).pack_count } {
            let record = unsafe { *(*state).packs.add(pack_id as usize) };
            let pack_name =
                unsafe { manifest_string(state, record.name_offset, record.name_length) };
            if pack_name.is_null() {
                continue;
            }
            let name_len = record.name_length as usize;
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
                core::ptr::copy_nonoverlapping(pack_name, t.add(cursor), name_len);
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

    #[test]
    fn packed_fd_lookup_is_range_and_table_based() {
        assert_eq!(virtual_fd_slot_for(250), None);

        // `slot + 1` leaves zero as "not a packed fd".
        VIRTUAL_FD_SLOTS[250].store(6, Ordering::Release);
        assert_eq!(virtual_fd_slot_for(250), Some(5));
        VIRTUAL_FD_SLOTS[250].store(0, Ordering::Release);
        assert_eq!(virtual_fd_slot_for(250), None);
        assert_eq!(virtual_fd_slot_for(AMPR_EMU_PACK_VIRTUAL_FD_LIMIT as u32), None);
    }

    #[test]
    fn virtual_fd_slot_holds_only_its_own_number() {
        let slot = VirtualFdSlot {
            real_fd: 40,
            handle: 40,
            active: true,
            ..VirtualFdSlot::EMPTY
        };
        assert!(slot.holds(40));
        // Slot reused under another number after a close: the old fd misses.
        assert!(!slot.holds(41));
        assert!(!VirtualFdSlot::EMPTY.holds(-1));
        // Tagged fallback handles compare exactly too.
        let tagged = VirtualFdSlot {
            real_fd: -1,
            handle: 0x6500_0100u32 as i32,
            generation: 1,
            active: true,
            ..VirtualFdSlot::EMPTY
        };
        assert!(tagged.holds(0x6500_0100u32 as i32));
        assert!(!tagged.holds(0x6500_0101u32 as i32));
    }
}
