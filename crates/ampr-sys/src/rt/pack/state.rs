//! PackState creation, submission admission, virtual fd/AIO id encoding,
//! clocks, pread_exact and overlay path/manifest helpers.

use super::*;

use crate::rt::index::IndexIo;
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

/// A packed file found by `resolve_packed_file`, per pack format.
pub(crate) enum PackedFile {
    /// AMPRPAK4: the manifest file record, copied out.
    Lz4(AmprPackFileRecord),
    /// zstd: the resident AMPRIDX3 entry view.
    Zstd(FileEntryView),
}

/// The one-based AMPRIDX3 id of `path` and its packed file, when the
/// index load joined that view row to a packed record of the indexed size
/// (zstd `join_zstd`, LZ4 and pkg `join_lz4`): memory only, no path or
/// manifest read. An id the join did not link is loose (`Ok(None)`); an
/// LZ4 record that failed the join is not linked either.
/// `Err(IndexIo)` when the AMPRIDX3 lookup failed to read: the file may be
/// packed and has no disk copy then, so the caller answers EIO, never
/// "not packed".
pub(crate) unsafe fn resolve_packed_file(
    state: *const PackState,
    path: *const c_char,
) -> Result<Option<(u32, PackedFile)>, IndexIo> {
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
    let Some(view) = crate::rt::index::published().and_then(|c| c.view()) else {
        return Ok(None);
    };
    if zstd_mode() {
        // The join checked the size against the zstd record; the stat
        // takes size and mtime from the view, as an entry view would.
        let size = indexed_size as u64;
        if !zstd::zstd_extent(file_id).is_some_and(|e| e.logical_size == size) {
            return Ok(None);
        }
        let entry = FileEntryView {
            path: null(),
            path_length: 0,
            size: indexed_size,
            mtime: view.mtime(file_id),
        };
        return Ok(Some((file_id, PackedFile::Zstd(entry))));
    }
    // The join linked the row to record `file_id - 1` only when its size
    // and path hash matched; the record is read from the fast table.
    if (*state).header.is_null() || !view.packed(file_id) {
        return Ok(None);
    }
    let Some(file) = (unsafe { lz4_file(state, file_id - 1) }) else {
        return Ok(None);
    };
    Ok(Some((file_id, PackedFile::Lz4(file))))
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

        // Packed numbers never decode as a directory, nor the reverse. The
        // range check alone decides this, so no live flag is set:
        // VIRTUAL_FD_LIVE is shared with packed_fd_range_and_slot_reuse,
        // which runs in parallel.
        let packed_top =
            (AMPR_EMU_PACK_VIRTUAL_FD_BASE + AMPR_EMU_PACK_VIRTUAL_FD_SLOTS - 1) as u32;
        assert_eq!(directory_fd_slot(packed_top), None);
        assert_eq!(packed_fd_slot(base), None);
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

    // ---- resident AMPRPAK4 index ----

    /// An AMPRPAK4 image of `n` empty packed files and exactly `bytes`
    /// bytes: the paths take what the records leave. No chunks, no packs.
    fn lz4_index(n: usize, bytes: usize) -> Vec<u8> {
        let strings_at = 128 + n * 48;
        let (base, extra) = ((bytes - strings_at) / n, (bytes - strings_at) % n);
        let paths: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let mut path = format!("/app0/d{:03}/f{i:07}", i % 997).into_bytes();
                path.resize(base - 1 + usize::from(i < extra), b'a');
                path
            })
            .collect();
        let b = lz4_paths_index(&paths);
        assert_eq!(b.len(), bytes);
        b
    }

    /// An AMPRPAK4 image of one empty packed file per path, in that record
    /// order. No chunks, no packs.
    fn lz4_paths_index(paths: &[Vec<u8>]) -> Vec<u8> {
        use ampr_format::{crc32, header_crc, pak_path_hash};
        const HEADER: usize = 128;
        let n = paths.len();
        let strings_at = HEADER + n * 48;
        let mut b = vec![0u8; strings_at];
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        for (i, path) in paths.iter().enumerate() {
            let at = HEADER + i * 48;
            put64(&mut b, at, pak_path_hash(path));
            let off = (b.len() - strings_at) as u32;
            put32(&mut b, at + 32, off);
            put32(&mut b, at + 36, path.len() as u32);
            put32(&mut b, at + 40, 1); // FILE_PACKED, empty: no chunks
            b[at + 44] = 14; // block_shift
            b.extend_from_slice(path);
            b.push(0);
        }
        let bytes = b.len();
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

    /// A zeroed `PackState` for a mount test; `free_test_state` frees it.
    fn test_state() -> *mut PackState {
        let layout = std::alloc::Layout::new::<PackState>();
        let state = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<PackState>();
        assert!(!state.is_null());
        state
    }

    /// File record `file_index`'s path copied into `buf` through the mounted
    /// manifest, which keeps no path: `Io` once a mount succeeded.
    unsafe fn file_record_path<'b>(
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

    fn free_test_state(state: *mut PackState) {
        unsafe { std::alloc::dealloc(state.cast(), std::alloc::Layout::new::<PackState>()) };
    }

    /// An LZ4 index read error is not a miss: the mount gives back what it
    /// took and the load is invalid (manifest.rs `load_manifest` reports
    /// absent only for an ENOENT open), so no packed file falls to a disk
    /// copy it does not have. The mount keeps the header and record
    /// sections, not the paths: the Index ledger grows by those alone and
    /// a path read through the manifest answers `Io`. With the fd closed
    /// and the read gone, the join to the view checks every record from
    /// memory, and the packed check never answers `Err(Io)`. A record
    /// whose size or path hash differs from its view row sets its mismatch
    /// bit and is not linked: an APR open of it is handled EIO, a plain
    /// open unhandled. The rest open by id with no path source.
    #[test]
    fn an_lz4_index_read_error_is_eio_not_a_miss() {
        use super::super::manifest::{drop_lz4_image, mount_lz4_file, release_manifest_storage};
        use crate::rt::index_memory as im;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = 2000u32;
        let file = lz4_index(n as usize, 128 + 2000 * 88);
        // Parts another test left mounted are given back by the first
        // mount below; count from without them.
        unsafe { drop_lz4_image() };
        let used = im::test_index_used();
        let page = |b: usize| b.next_multiple_of(SCE_KERNEL_PAGE_SIZE);
        let mut buf = [0u8; SCE_KERNEL_PATH_MAX];
        let open = ampr_lz4::manifest::Manifest::open(&file[..]).unwrap();
        let mut paths: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let f = open.file(i).unwrap();
                open.path(&f, &mut buf).unwrap().to_vec()
            })
            .collect();
        unsafe {
            let state = test_state();
            let len = file.len() as u64;
            assert!(!mount_lz4_file(state, len, |_, _| false, false));
            assert!((*state).header.is_null());
            assert_eq!(im::test_index_used(), used);
            let read = |at: u64, out: &mut [u8]| {
                let at = at as usize;
                out.copy_from_slice(&file[at..at + out.len()]);
                true
            };
            assert!(mount_lz4_file(state, len, read, false));
            // Header and records, 48 B per file; the paths are not kept.
            let kept = im::test_index_used() - used;
            assert_eq!(kept, page(128 + n as usize * 48));
            assert!(kept < page(file.len()));
            drop(file);
            let view = &raw const (*state).core_view;
            assert!((*view).manifest.is_some_and(|m| m.has_fast()));
            assert_eq!(
                file_record_path(state, 0, &mut buf),
                Err(ampr_format::Error::Io)
            );
            // id 9: another file's path in the AMPRIDX3; id 7: another size.
            paths[8].push(b'x');
            let rows: Vec<(&[u8], u64)> = paths
                .iter()
                .enumerate()
                .map(|(i, p)| (p.as_slice(), u64::from(i == 6)))
                .collect();
            let mut idx = crate::rt::index::tests::lz4_builder(&rows);
            let b = idx.compact.builder.as_mut().unwrap();
            assert!(super::super::manifest::join_lz4(state, b));
            idx.compact.finish();
            // Nothing below reads a path: the decision is the view and the bit.
            idx.compact.paths = crate::rt::index::Paths::None;
            let view = idx.compact.view().unwrap();
            for id in 1..=n {
                let bad = id == 7 || id == 9;
                let mismatch = super::super::manifest::lz4_mismatch(state, id);
                assert_eq!(mismatch, bad, "{id}");
                assert_eq!(view.packed(id), !bad, "{id}");
                let (plain, apr) = if bad {
                    (PackedCheck::Unhandled, PackedCheck::Eio)
                } else {
                    (PackedCheck::Open, PackedCheck::Open)
                };
                assert_eq!(check_packed(mismatch, 0), plain, "{id}");
                assert_eq!(check_packed(mismatch, O_NONBLOCK), apr, "{id}");
            }
            assert!(!super::super::manifest::lz4_mismatch(state, n + 1));
            release_manifest_storage(state);
            assert!((*state).header.is_null() && lz4_file(state, 0).is_none());
            assert!((*state).lz4_mismatch.is_null());
            drop_lz4_image();
            crate::rt::index::tests::drop_view(&mut idx);
            assert_eq!(im::test_index_used(), used);
            free_test_state(state);
        }
    }

    /// An LZ4 directory lists through the view as a zstd one does: every
    /// directory with a packed file below it lists, as a set, exactly the
    /// immediate packed children a walk over the joined paths finds, child
    /// directories as `DT_DIR` and packed files as `DT_REG`. A record that
    /// failed the join (size or path hash) and a loose AMPRIDX3 row list
    /// nothing, and a directory with nothing packed below it, or a file,
    /// is no packed directory.
    #[test]
    fn an_lz4_listing_lists_the_packed_children() {
        use super::super::directories::{list_next_in, packed_dir_in};
        use super::super::manifest::{
            drop_lz4_image, join_lz4, mount_lz4_file, release_manifest_storage,
        };
        use crate::rt::index_memory as im;
        use std::collections::{BTreeMap, BTreeSet};
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let packed = [
            "/app0/top.bin",
            "/app0/data/a.bin",
            "/app0/data/b.bin",
            "/app0/data/sub/c.bin",
            "/app0/data/sub/deep/d.bin",
            "/app0/z/e.bin",
            "/app0/a b/f.bin",
            "/app0/bad/size.bin",
            "/app0/hash/x.bin",
        ];
        let (bad_size, bad_hash) = (7usize, 8usize);
        let loose = [
            "/app0/eboot.bin",
            "/app0/loose/only.bin",
            "/app0/data/loose.bin",
        ];
        let records: Vec<Vec<u8>> = packed.iter().map(|p| p.as_bytes().to_vec()).collect();
        let file = lz4_paths_index(&records);
        unsafe { drop_lz4_image() };
        let used = im::test_index_used();
        let mut rows: Vec<(Vec<u8>, u64)> = records.iter().map(|p| (p.clone(), 0)).collect();
        rows[bad_size].1 = 1;
        rows[bad_hash].0 = b"/app0/hash/y.bin".to_vec();
        rows.extend(loose.iter().map(|p| (p.as_bytes().to_vec(), 1)));
        // The walk: each joined path adds its next component below every
        // ancestor directory, a directory while components follow.
        let mut want: BTreeMap<String, BTreeSet<(String, u8)>> = BTreeMap::new();
        for (i, p) in packed.iter().enumerate() {
            if i == bad_size || i == bad_hash {
                continue;
            }
            let parts: Vec<&str> = p.split('/').skip(1).collect();
            for depth in 1..parts.len() {
                let dir = format!("/{}", parts[..depth].join("/"));
                let kind = if depth + 1 < parts.len() {
                    DT_DIR
                } else {
                    DT_REG
                };
                want.entry(dir)
                    .or_default()
                    .insert((parts[depth].to_string(), kind));
            }
        }
        unsafe {
            let read = |at: u64, out: &mut [u8]| {
                let at = at as usize;
                out.copy_from_slice(&file[at..at + out.len()]);
                true
            };
            let state = test_state();
            assert!(mount_lz4_file(state, file.len() as u64, read, false));
            let entries: Vec<(&[u8], u64)> = rows.iter().map(|(p, n)| (p.as_slice(), *n)).collect();
            let mut idx = crate::rt::index::tests::lz4_builder(&entries);
            assert!(join_lz4(state, idx.compact.builder.as_mut().unwrap()));
            idx.compact.finish();
            let (view, src) = (idx.compact.view().unwrap(), &idx.compact.paths);
            let list = |dir: &[u8]| -> Option<BTreeSet<(String, u8)>> {
                let mut c = packed_dir_in(&view, src, dir).unwrap()?;
                let (mut out, mut name) = (BTreeSet::new(), [0u8; 256]);
                while let Some(child) = list_next_in(&view, src, c, &mut name).unwrap() {
                    let len = usize::from(child.len);
                    assert!(len > 0 && name[len] == 0);
                    let text = String::from_utf8(name[..len].to_vec()).unwrap();
                    assert!(out.insert((text.clone(), child.kind)), "{text} listed once");
                    c = child.next;
                }
                assert_eq!(c, Cursor::Done);
                Some(out)
            };
            for (dir, children) in &want {
                assert_eq!(list(dir.as_bytes()).as_ref(), Some(children), "{dir}");
            }
            assert_eq!(list(b"/APP0/Data"), list(b"/app0/data"));
            for miss in rows.iter().map(|(p, _)| p.as_slice()).chain([
                &b"/app0/bad"[..],
                b"/app0/hash",
                b"/app0/loose",
                b"/app0/dat",
            ]) {
                assert_eq!(list(miss), None, "{}", String::from_utf8_lossy(miss));
            }
            release_manifest_storage(state);
            drop_lz4_image();
            crate::rt::index::tests::drop_view(&mut idx);
            assert_eq!(im::test_index_used(), used);
            free_test_state(state);
        }
    }

    /// A pkg AMPRPAK4 image: `/app0/f.bin`, 1000 bytes in one KRAKEN chunk
    /// of 500 stored bytes at an offset 4 bytes past a page of pack 0 (the
    /// .pkg), which only `open_pkg` admits; packs `p0.pak` and `p1.pak`.
    fn pkg_index() -> Vec<u8> {
        use ampr_format::{crc32, pak_path_hash};
        let put = |b: &mut Vec<u8>, at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
        let path: &[u8] = b"/app0/f.bin";
        let names: [&[u8]; 2] = [b"p0.pak", b"p1.pak"];
        let mut strings = [path, &[0]].concat();
        let mut name_at = [0u32; 2];
        for (at, name) in name_at.iter_mut().zip(names) {
            *at = strings.len() as u32;
            strings.extend_from_slice(name);
            strings.push(0);
        }
        let (files_at, chunks_at) = (128u64, 128u64 + 48);
        let (packs_at, strings_at) = (chunks_at + 12, chunks_at + 12 + 64);
        let mut b = vec![0u8; strings_at as usize];
        put(&mut b, 0, b"AMPRPAK4");
        for (at, v) in [
            (8, 4u32),
            (12, 128),
            (20, 0x0102_0304),
            (56, 2),
            (60, 48),
            (64, 12),
            (68, 32),
        ] {
            put(&mut b, at, &v.to_le_bytes());
        }
        let counts = [
            (40, 1),
            (48, 1),
            (72, files_at),
            (80, chunks_at),
            (88, packs_at),
        ];
        for (at, v) in counts
            .into_iter()
            .chain([(96, strings_at), (104, strings.len() as u64)])
        {
            put(&mut b, at, &v.to_le_bytes());
        }
        // The file record: hash, size, mtime, first chunk 0, one chunk,
        // path offset 0 and length, FILE_PACKED, 16 KiB blocks.
        let f = files_at as usize;
        put(&mut b, f, &pak_path_hash(path).to_le_bytes());
        put(&mut b, f + 8, &1000u64.to_le_bytes());
        put(&mut b, f + 28, &1u32.to_le_bytes());
        put(&mut b, f + 36, &(path.len() as u32).to_le_bytes());
        put(&mut b, f + 40, &1u32.to_le_bytes());
        b[f + 44] = 14;
        // KRAKEN location: offset | even half 300 << 40 | mode 3 << 59.
        let loc = (4096 + 4) | 300u64 << 40 | 3u64 << 59;
        put(&mut b, chunks_at as usize, &loc.to_le_bytes());
        let desc = 499 | u32::from(ampr_pkg::CHUNK_KRAKEN) << 20;
        put(&mut b, chunks_at as usize + 8, &desc.to_le_bytes());
        for (i, at) in name_at.into_iter().enumerate() {
            let r = packs_at as usize + i * 32;
            put(&mut b, r, &(65536u64 - 4096).to_le_bytes());
            put(&mut b, r + 8, &65536u64.to_le_bytes());
            for (k, v) in [at, 6, ampr_lz4::PACK_IO_PAGE_LAYOUT, 4096]
                .into_iter()
                .enumerate()
            {
                put(&mut b, r + 16 + k * 4, &v.to_le_bytes());
            }
        }
        b.extend_from_slice(&strings);
        let payload = crc32(&b[128..]);
        put(&mut b, 112, &payload.to_le_bytes());
        let header = crc32(&b[..128]);
        put(&mut b, 116, &header.to_le_bytes());
        b
    }

    /// A pkg manifest mounts through `open_pkg`, which the strict `open`
    /// refuses, and answers its pack names and records with the index fd
    /// closed: the mount kept the header, the records and the pack names,
    /// and a path read answers `Io`.
    #[test]
    fn a_pkg_manifest_mounts_with_the_fd_closed() {
        use super::super::manifest::{drop_lz4_image, mount_lz4_file, release_manifest_storage};
        use crate::rt::index_memory as im;
        let _pool = im::POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let file = pkg_index();
        unsafe { drop_lz4_image() };
        let used = im::test_index_used();
        unsafe {
            let read = |at: u64, out: &mut [u8]| {
                let at = at as usize;
                out.copy_from_slice(&file[at..at + out.len()]);
                true
            };
            let state = test_state();
            let len = file.len() as u64;
            assert!(!mount_lz4_file(state, len, read, false));
            assert!((*state).header.is_null());
            assert_eq!(im::test_index_used(), used);
            assert!(mount_lz4_file(state, len, read, true));
            drop(file);
            assert_eq!({ (*(*state).header).pack_count }, 2);
            let mut buf = [0u8; SCE_KERNEL_PATH_MAX];
            for (id, name) in [&b"p0.pak"[..], b"p1.pak"].into_iter().enumerate() {
                let p = lz4_pack(state, id as u32).unwrap();
                let got = manifest_string(state, p.name_offset, p.name_length, &mut buf);
                assert_eq!(got, Some(name));
            }
            assert!(lz4_pack(state, 2).is_none());
            assert_eq!(
                file_record_path(state, 0, &mut buf),
                Err(ampr_format::Error::Io)
            );
            assert_eq!(lz4_file(state, 0).map(|f| f.logical_size), Some(1000));
            let m = (*state).core_view.manifest.unwrap();
            let (offset, pack, kraken) = ampr_pkg::pkg_chunk(m.chunk_record(0).unwrap());
            assert_eq!((offset, pack, kraken >> 19), (4100, 0, 3));
            release_manifest_storage(state);
            drop_lz4_image();
            assert_eq!(im::test_index_used(), used);
            free_test_state(state);
        }
    }
}
