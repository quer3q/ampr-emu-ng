//! Virtual AIO/fd/directory slot allocation and the indexed open entry points.

use super::*;

pub(crate) unsafe fn allocate_virtual_aio_locked(state: *mut PackState) -> u32 {
    let slots = AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32;
    for n in 0..slots {
        let index = ((*state).virtual_aio_cursor + n) % slots;
        let slot = &mut (*state).virtual_aio[index as usize];
        if slot.phase == VirtualAioPhase::Free {
            let generation = next_generation(slot.generation) as u16;
            reset_virtual_aio_slot(slot, generation, VirtualAioPhase::Reserved);
            slot.submit_ns = stats::now();
            (*state).virtual_aio_cursor = (index + 1) % slots;
            return index;
        }
    }
    INVALID_INDEX
}

pub(crate) unsafe fn free_virtual_aio_locked(state: *mut PackState, index: u32) {
    if index as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
        return;
    }
    let was_fd_waiter = (*state).virtual_aio[index as usize].phase == VirtualAioPhase::WaitingFd
        && (*state).virtual_aio[index as usize].pipeline_index != INVALID_INDEX;
    release_pipeline_locked(state, index);
    if was_fd_waiter {
        PACK_FD_WAITER_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
    let slot = &mut (*state).virtual_aio[index as usize];
    let generation = slot.generation;
    reset_virtual_aio_slot(slot, generation, VirtualAioPhase::Free);
}

pub(crate) unsafe fn lookup_virtual_aio_locked(
    state: *mut PackState,
    id: SceKernelAioSubmitId,
    out_index: *mut u32,
) -> *mut VirtualAioSlot {
    let (mut index, mut generation) = (0u32, 0u16);
    if !unsafe { decode_virtual_aio(id, &mut index, &mut generation) } {
        return null_mut();
    }
    let slot = &mut (*state).virtual_aio[index as usize];
    if slot.phase == VirtualAioPhase::Free || slot.generation != generation {
        return null_mut();
    }
    if !out_index.is_null() {
        unsafe { *out_index = index };
    }
    slot
}

pub(crate) unsafe fn allocate_virtual_aio_group_locked(state: *mut PackState) -> u32 {
    let slots = AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS as u32;
    for n in 0..slots {
        let index = ((*state).virtual_aio_group_cursor + n) % slots;
        let slot = &mut (*state).virtual_aio_groups[index as usize];
        if slot.active {
            continue;
        }
        let generation = next_generation(slot.generation) as u16;
        *slot = VirtualAioGroupSlot::EMPTY;
        slot.generation = generation;
        slot.active = true;
        (*state).virtual_aio_group_cursor = (index + 1) % slots;
        return index;
    }
    INVALID_INDEX
}

pub(crate) unsafe fn free_virtual_aio_group_locked(state: *mut PackState, index: u32) {
    if index as usize >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS {
        return;
    }
    let slot = &mut (*state).virtual_aio_groups[index as usize];
    let generation = slot.generation;
    *slot = VirtualAioGroupSlot::EMPTY;
    slot.generation = generation;
}

pub(crate) unsafe fn lookup_virtual_aio_group_locked(
    state: *mut PackState,
    id: SceKernelAioSubmitId,
    out_index: *mut u32,
) -> *mut VirtualAioGroupSlot {
    let (mut index, mut generation) = (0u32, 0u16);
    if !unsafe { decode_virtual_aio_group(id, &mut index, &mut generation) } {
        return null_mut();
    }
    let slot = &mut (*state).virtual_aio_groups[index as usize];
    if !slot.active || slot.generation != generation {
        return null_mut();
    }
    if !out_index.is_null() {
        unsafe { *out_index = index };
    }
    slot
}

/// Reserves a low OS descriptor by opening `/dev/null`, then takes a free
/// slot and publishes the fd-to-slot mapping. The reserved descriptor keeps
/// the number from being reused by another file, so an fd in the low range is
/// unambiguously either physical or mapped virtual. Returns the fd as the
/// caller's handle, or an SCE error (never a positive value).
///
/// The reservation stands in for the title's own fd, so it is not counted in
/// the runtime's open budget (rt/fd_cache.rs `BUDGET_CAP`, 50). Counted, 32
/// open packed files plus 18 open pack volumes (`OPEN_PACK_FD_CAP`) would
/// fill it, and a read needing another volume would park until the title
/// closed a file (rt/pack/leases.rs, rt/pack/worker.rs `park_on_fd_locked`).
/// Derived from the code, not seen on a console.
pub(crate) unsafe fn allocate_virtual_fd_locked(state: *mut PackState, file_id: u32) -> c_int {
    let slots = AMPR_EMU_PACK_VIRTUAL_FD_SLOTS as u32;
    let index = ((*state).virtual_fd_cursor..slots)
        .chain(0..(*state).virtual_fd_cursor)
        .find(|&i| !(*state).virtual_fds[i as usize].active);
    let Some(index) = index else {
        return SCE_KERNEL_ERROR_EMFILE;
    };
    let Some(open_fn) = (unsafe { real_open() }) else {
        return SCE_KERNEL_ERROR_EIO;
    };
    let fd = unsafe { open_fn(c"/dev/null".as_ptr(), O_RDONLY, 0) };
    if fd < 0 {
        return sce_errno_from_posix(errno());
    }
    if fd as usize >= AMPR_EMU_PACK_VIRTUAL_FD_LIMIT {
        let _ = unsafe { real_close() }.map(|close_fn| unsafe { close_fn(fd) });
        return SCE_KERNEL_ERROR_EMFILE;
    }
    // A stale slot can still name this number (see forget_stale_virtual_fd).
    forget_stale_virtual_fd_locked(state, fd);
    let slot = &mut (*state).virtual_fds[index as usize];
    *slot = VirtualFdSlot {
        file_id,
        real_fd: fd,
        ..VirtualFdSlot::EMPTY
    };
    slot.active = true;
    VIRTUAL_FD_SLOTS[fd as usize].store(index + 1, Ordering::Release);
    (*state).virtual_fd_cursor = (index + 1) % slots;
    fd
}

pub unsafe fn ampr_pack_notify_fd_budget_progress() {
    if !g_pack_state.load(Ordering::Acquire).is_null() {
        // The caller advanced the budget epoch. Pair this fence with the
        // waiter's fence after registration so a skipped wake sees that epoch.
        core::sync::atomic::fence(Ordering::SeqCst);
        if PACK_FD_WAITER_COUNT.load(Ordering::SeqCst) == 0 {
            return;
        }
        // Serialize with a worker between its budget check and its wait.
        drop(PACK_M.lock());
        QUEUE_CV.notify_all();
    }
}

pub unsafe fn ampr_pack_ensure_manifest_ready_safe() -> bool {
    // The zstd projection build inside writes the mount shutdown frees.
    let Some(_reader) = ManifestReader::enter() else {
        return false;
    };
    unsafe { ensure_manifest_ready() }
}

/// zstd: packed membership is known only once the AMPRIDX3 projection is
/// built. Hooks may run under a nonsleeping lock, so the first caller after
/// AMPRIDX3 publication builds it inline (CPU only) and a caller that finds
/// another thread building gets false instead of waiting.
/// False once shutdown starts: the inline build writes the zstd mount that
/// shutdown frees, so it runs under a `ManifestReader` (rt/pack/mod.rs).
pub unsafe fn ampr_pack_manifest_is_resident_ready() -> bool {
    let Some(_reader) = ManifestReader::enter() else {
        return false;
    };
    !g_pack_state.load(Ordering::Acquire).is_null()
        && LOAD_STATE.load(Ordering::Acquire) == PACK_LOAD_READY
        && (!zstd_mode() || unsafe { zstd::try_zstd_projection() })
}

/// Every read-only non-directory open, in both formats: a packed file has
/// no physical copy to fall back to, so a plain `O_RDONLY` open must get a
/// virtual fd too (GitHub issue #2: an Insomniac Engine title with LZ4 packs
/// failed plain opens of /app0/d/0/actor).
pub(crate) fn pack_open_flags_supported(flags: c_int) -> bool {
    (flags & O_ACCMODE) == O_RDONLY && (flags & O_DIRECTORY) == 0
}

pub(crate) unsafe fn ampr_pack_try_open_indexed_impl(
    file_id: u32,
    entry: &FileEntryView,
    flags: c_int,
    _mode: SceKernelMode,
    handled: *mut bool,
) -> c_int {
    if !handled.is_null() {
        unsafe { *handled = false };
    }
    if handled.is_null() || file_id == 0 || entry.path.is_null() {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    let handled = unsafe { &mut *handled };
    // Held from the load (and zstd projection build) through the record
    // validation and the fd allocation, all of which read the manifest.
    let Some(_reader) = ManifestReader::enter() else {
        return SCE_KERNEL_ERROR_ENOENT;
    };
    if !unsafe { ensure_manifest_ready() } {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    // An id that is not packed (no zstd record, or an LZ4 record without
    // AMPR_PACK_FILE_PACKED) is a loose file: unhandled, physical open.
    // Checked before the record validation, so a loose file whose AMPRIDX3
    // and pack records disagree still opens its physical copy instead of
    // failing with EIO, and a loose open hashes no path here.
    if !file_id_is_packed(&_reader, file_id) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    let state = unsafe { pack_state() };
    let validate_rc = unsafe {
        ampr_pack_core_validate_logical_file(
            &(*state).core_view,
            file_id,
            entry.path,
            entry.path_length as usize,
            entry.size as u64,
        )
    };
    if validate_rc != AMPR_PACK_CORE_OK {
        // The AMPRIDX3 id names a pack record of another file, e.g. a walk
        // built index whose ids follow walk order. APR opens (rt/fd_cache.rs,
        // rt/reactor/submit.rs) pass `kAprAioOpenFlags`, which has
        // O_NONBLOCK, and keep the v0.2.0 result: handled EIO. A game's
        // plain open() stays unhandled, so the physical file opens if it
        // exists on disk instead of failing here.
        if flags & O_NONBLOCK == 0 {
            return SCE_KERNEL_ERROR_ENOENT;
        }
        *handled = true;
        return SCE_KERNEL_ERROR_EIO;
    }
    *handled = true;
    if !pack_open_flags_supported(flags) {
        return sce_errno_from_posix(EACCES);
    }
    let _lock = PACK_M.lock();
    // Shutdown closes the gate before its PACK_M section that closes
    // submissions, so this check under PACK_M refuses every open that
    // would otherwise get an fd during the drain (stability S4). The result
    // is the one a refused enter gives: unhandled, as if no manifest.
    if MANIFEST_READERS.is_closed() {
        *handled = false;
        return SCE_KERNEL_ERROR_ENOENT;
    }
    allocate_virtual_fd_locked(state, file_id)
}

pub unsafe fn ampr_pack_try_open_indexed(
    file_id: u32,
    entry: *const FileEntryView,
    flags: c_int,
    mode: SceKernelMode,
    handled: *mut bool,
) -> c_int {
    unsafe { ampr_pack_try_open_indexed_impl(file_id, &*entry, flags, mode, handled) }
}

/// Prefers an immediately available slot; waits on slot mutexes only when the
/// first pass found none, so temporary contention is not EMFILE.
pub(crate) unsafe fn allocate_virtual_directory_locked(
    state: *mut PackState,
    path: *const c_char,
    path_length: u16,
    real_fd: c_int,
    range_begin: u32,
    range_end: u32,
) -> u32 {
    let slots = AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS as u32;
    for pass in 0..2 {
        for n in 0..slots {
            let index = ((*state).virtual_directory_cursor + n) % slots;
            let _guard = if pass == 0 {
                match DIRECTORY_MUTEXES[index as usize].try_lock() {
                    Some(g) => g,
                    None => continue,
                }
            } else {
                // Blocking on purpose: try_lock here would make pass 1 a
                // copy of pass 0 and turn contention into EMFILE. No path
                // takes a slot mutex and then DIRECTORY_TABLE_MUTEX, so this
                // can wait but not deadlock.
                DIRECTORY_MUTEXES[index as usize].lock()
            };
            let slot = &mut (*state).virtual_directories[index as usize];
            if slot.active {
                continue;
            }
            let generation = next_generation(slot.generation) as u16;
            *slot = VirtualDirectorySlot::EMPTY;
            slot.real_fd = real_fd;
            slot.generation = generation;
            slot.active = true;
            slot.range_begin = range_begin;
            slot.range_end = range_end;
            slot.virtual_cursor = range_begin;
            slot.path_length = path_length;
            unsafe {
                core::ptr::copy_nonoverlapping(path, slot.path.as_mut_ptr(), path_length as usize)
            };
            slot.path[path_length as usize] = 0;
            (*state).virtual_directory_cursor = (index + 1) % slots;
            return index;
        }
    }
    INVALID_INDEX
}
