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

pub(crate) unsafe fn allocate_virtual_fd_locked(state: *mut PackState, file_id: u32) -> u32 {
    let slots = AMPR_EMU_PACK_VIRTUAL_FD_SLOTS as u32;
    for n in 0..slots {
        let index = ((*state).virtual_fd_cursor + n) % slots;
        let slot = &mut (*state).virtual_fds[index as usize];
        if !slot.active {
            slot.generation = next_generation(slot.generation) as u16;
            slot.file_id = file_id;
            slot.readahead_next = 0;
            slot.cursor = 0;
            slot.active = true;
            (*state).virtual_fd_cursor = (index + 1) % slots;
            return index;
        }
    }
    INVALID_INDEX
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
    unsafe { ensure_manifest_ready() }
}

/// zstd: packed membership is known only once the AMPRIDX3 projection is
/// built. Hooks may run under a nonsleeping lock, so the first caller after
/// AMPRIDX3 publication builds it inline (CPU only) and a caller that finds
/// another thread building gets false instead of waiting.
pub unsafe fn ampr_pack_manifest_is_resident_ready() -> bool {
    !g_pack_state.load(Ordering::Acquire).is_null()
        && LOAD_STATE.load(Ordering::Acquire) == PACK_LOAD_READY
        && (!zstd_mode() || unsafe { zstd::try_zstd_projection() })
}

/// zstd accepts every read-only open: a packed file has no physical copy
/// to fall back to, so a plain `O_RDONLY` open must get a virtual fd too.
pub(crate) fn pack_open_flags_supported(flags: c_int) -> bool {
    (flags & O_ACCMODE) == O_RDONLY
        && (flags & O_DIRECTORY) == 0
        && (zstd_mode() || AMPR_EMU_PACK_INTERCEPT_ALL_READ_ONLY || (flags & O_NONBLOCK) != 0)
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
    if !unsafe { ensure_manifest_ready() } {
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
        *handled = true;
        return SCE_KERNEL_ERROR_EIO;
    }
    // zstd: the R4 projection decides; an AMPRIDX3 id without a zstd
    // record is a loose file (unhandled, physical open), not an error.
    let packed = if zstd_mode() {
        zstd::zstd_entry(file_id).is_some()
    } else {
        (unsafe { (*(*state).files.add(file_id as usize - 1)).flags } & AMPR_PACK_FILE_PACKED) != 0
    };
    if !packed {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    *handled = true;
    if !pack_open_flags_supported(flags) {
        return sce_errno_from_posix(EACCES);
    }
    let _lock = PACK_M.lock();
    let slot = allocate_virtual_fd_locked(state, file_id);
    if slot == INVALID_INDEX {
        return SCE_KERNEL_ERROR_EMFILE;
    }
    encode_virtual_fd(slot, (*state).virtual_fds[slot as usize].generation)
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
