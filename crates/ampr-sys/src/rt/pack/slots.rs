//! Virtual AIO/fd/directory slot allocation and the indexed open entry points.

use super::*;
use ampr_format::view::Builder;

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
            (*state).virtual_aio_used += 1;
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
    unsafe { mark_virtual_aio_free_locked(state, index) };
}

/// Resets slot `index` to Free and gives its count back once (a second free
/// of the same slot counts nothing). PACK_M held.
pub(crate) unsafe fn mark_virtual_aio_free_locked(state: *mut PackState, index: u32) {
    let slot = &mut (*state).virtual_aio[index as usize];
    if slot.phase != VirtualAioPhase::Free {
        (*state).virtual_aio_used -= 1;
    }
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

/// Takes a free slot and returns the synthetic packed fd `BASE + slot`.
/// No kernel descriptor is involved: the range is above the kernel's
/// effective fd table (259) and below the directory range and the strictest
/// title limit (one title rejects fd >= 1024). A closed slot is reused, so the
/// number behaves like a reused OS fd. Returns an SCE error (never a positive
/// value) when all slots are open.
pub(crate) unsafe fn allocate_virtual_fd_locked(state: *mut PackState, file_id: u32) -> c_int {
    let slots = AMPR_EMU_PACK_VIRTUAL_FD_SLOTS as u32;
    let index = ((*state).virtual_fd_cursor..slots)
        .chain(0..(*state).virtual_fd_cursor)
        .find(|&i| !(*state).virtual_fds[i as usize].active);
    let Some(index) = index else {
        #[cfg(feature = "mem_report")]
        stats::fs_event(
            b'Q',
            b'S',
            SCE_KERNEL_ERROR_EMFILE as i64,
            c"virtual-fd-slots".as_ptr(),
        );
        return SCE_KERNEL_ERROR_EMFILE;
    };
    let handle = (AMPR_EMU_PACK_VIRTUAL_FD_BASE as u32 + index) as c_int;
    let slot = &mut (*state).virtual_fds[index as usize];
    *slot = VirtualFdSlot {
        file_id,
        handle,
        ..VirtualFdSlot::EMPTY
    };
    slot.active = true;
    VIRTUAL_FD_LIVE[index as usize].store(true, Ordering::Release);
    (*state).virtual_fd_cursor = (index + 1) % slots;
    handle
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
    // A load another thread runs writes the mount shutdown frees.
    let Some(_reader) = ManifestReader::enter() else {
        return false;
    };
    unsafe { ensure_manifest_ready() }
}

/// rt/index.rs `ensure_ready_slow`, before it publishes the index: mounts
/// the pack index and joins it to the view `b` being built. Under
/// a `ManifestReader`, as the mount writes what shutdown frees.
pub(crate) unsafe fn ampr_pack_mount_and_join(b: &mut Builder<'_>) -> bool {
    let Some(_reader) = ManifestReader::enter() else {
        return false;
    };
    unsafe { mount_and_join(b) }
}

/// Whether the pack index is mounted, without loading or waiting: hooks
/// may run under a nonsleeping lock. A zstd mount is ready with its chunk
/// tables, both written before the index is published.
/// False once shutdown starts (`ManifestReader`, rt/pack/mod.rs).
pub unsafe fn ampr_pack_manifest_is_resident_ready() -> bool {
    let Some(_reader) = ManifestReader::enter() else {
        return false;
    };
    !g_pack_state.load(Ordering::Acquire).is_null()
        && LOAD_STATE.load(Ordering::Acquire) == PACK_LOAD_READY
}

/// Every read-only non-directory open, in both formats: a packed file has
/// no physical copy to fall back to, so a plain `O_RDONLY` open must get a
/// virtual fd too (an LZ4 title failed plain opens of its packed files).
pub(crate) fn pack_open_flags_supported(flags: c_int) -> bool {
    (flags & O_ACCMODE) == O_RDONLY && (flags & O_DIRECTORY) == 0
}

/// What the record check of a packed open decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackedCheck {
    /// The id's pack record is this file: open a virtual fd.
    Open,
    /// Not served here: the caller opens the physical file.
    Unhandled,
    /// Served here and failed with EIO: no disk copy to fall back to.
    Eio,
}

/// The record check of an open of a packed id, which needs no path: the
/// index load joined every id to its record (zstd by path hash and size,
/// LZ4 by size and `pak_path_hash` against record `id - 1`). `mismatch`:
/// the id's LZ4 record failed that join (manifest.rs `lz4_mismatch`).
pub(crate) fn check_packed(mismatch: bool, flags: c_int) -> PackedCheck {
    if !mismatch {
        return PackedCheck::Open;
    }
    // The AMPRIDX3 id names a pack record of another file, e.g. a walk
    // built index whose ids follow walk order. APR opens (rt/fd_cache.rs,
    // rt/reactor/submit.rs) pass `kAprAioOpenFlags`, which has O_NONBLOCK,
    // and keep the v0.2.0 result: handled EIO. A game's plain open() stays
    // unhandled, so the physical file opens if it exists on disk instead of
    // failing here.
    if flags & O_NONBLOCK == 0 {
        PackedCheck::Unhandled
    } else {
        PackedCheck::Eio
    }
}

pub(crate) unsafe fn ampr_pack_try_open_indexed_impl(
    file_id: u32,
    _entry: &FileEntryView,
    flags: c_int,
    _mode: SceKernelMode,
    handled: *mut bool,
) -> c_int {
    if !handled.is_null() {
        unsafe { *handled = false };
    }
    if handled.is_null() || file_id == 0 {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    let handled = unsafe { &mut *handled };
    // Held from the load through the record
    // validation and the fd allocation, all of which read the manifest.
    let Some(_reader) = ManifestReader::enter() else {
        return SCE_KERNEL_ERROR_ENOENT;
    };
    if !unsafe { ensure_manifest_ready() } {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    let state = unsafe { pack_state() };
    // An id that is not packed (no zstd record, or an LZ4 record without
    // AMPR_PACK_FILE_PACKED) is a loose file: unhandled, physical open, and
    // a loose open hashes no path here. An LZ4 record that failed the join
    // is not linked either, but answers as its failed check below.
    let mismatch = !zstd_mode() && unsafe { lz4_mismatch(state, file_id) };
    if !mismatch && !file_id_is_packed(&_reader, file_id) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    match check_packed(mismatch, flags) {
        PackedCheck::Open => {}
        PackedCheck::Unhandled => return SCE_KERNEL_ERROR_ENOENT,
        PackedCheck::Eio => {
            *handled = true;
            return SCE_KERNEL_ERROR_EIO;
        }
    }
    if !pack_open_flags_supported(flags) {
        // A write open stays unhandled and reaches the physical path, as in a
        // plain folder: a title that opens a packed log file for writing
        // retried an EACCES refusal ~700 times and crashed. A read-only
        // mount fails it with the FS's own error.
        // Later reads of that path still serve the packed bytes, not what
        // the game wrote; route them to the loose file if a title reads back
        // what it writes into /app0.
        return SCE_KERNEL_ERROR_ENOENT;
    }
    *handled = true;
    let _lock = PACK_M.lock();
    // Shutdown closes the gate before its PACK_M section that closes
    // submissions, so this check under PACK_M refuses every open that
    // would otherwise get an fd during the drain. The result
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
    // A null entry is "no such file", not a deref.
    let Some(entry) = (unsafe { entry.as_ref() }) else {
        if !handled.is_null() {
            unsafe { *handled = false };
        }
        return SCE_KERNEL_ERROR_ENOENT;
    };
    unsafe { ampr_pack_try_open_indexed_impl(file_id, entry, flags, mode, handled) }
}

/// Prefers an immediately available slot; waits on slot mutexes only when the
/// first pass found none, so temporary contention is not EMFILE.
pub(crate) unsafe fn allocate_virtual_directory_locked(
    state: *mut PackState,
    path: *const c_char,
    path_length: u16,
    real_fd: c_int,
    listing: Cursor,
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
            *slot = VirtualDirectorySlot::EMPTY;
            slot.real_fd = real_fd;
            slot.active = true;
            slot.listing = listing;
            slot.listing_first = listing;
            slot.path_length = path_length;
            unsafe {
                core::ptr::copy_nonoverlapping(path, slot.path.as_mut_ptr(), path_length as usize)
            };
            slot.path[path_length as usize] = 0;
            VIRTUAL_DIRECTORY_LIVE[index as usize].store(true, Ordering::Release);
            (*state).virtual_directory_cursor = (index + 1) % slots;
            return index;
        }
    }
    INVALID_INDEX
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A joined id opens with no further check; an LZ4 record that failed
    /// the join keeps the split of a failed record check: a plain open
    /// unhandled, an APR open (O_NONBLOCK) handled EIO.
    #[test]
    fn a_mismatched_record_answers_as_a_failed_check() {
        for flags in [0, O_NONBLOCK] {
            assert_eq!(check_packed(false, flags), PackedCheck::Open);
        }
        assert_eq!(check_packed(true, 0), PackedCheck::Unhandled);
        assert_eq!(check_packed(true, O_NONBLOCK), PackedCheck::Eio);
    }
}
