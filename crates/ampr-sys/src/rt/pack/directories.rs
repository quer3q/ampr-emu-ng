//! Virtual directories, synthetic dirents, stat, close and fstat of
//! virtual descriptors.

use super::*;
use crate::rt::index::IndexIo;
use ampr_lz4::overlay;

pub(crate) unsafe fn directory_physical_name_seen(
    slot: &VirtualDirectorySlot,
    name: *const c_char,
    name_length: usize,
) -> bool {
    let hash = unsafe { folded_hash(name, name_length) };
    slot.physical_name_hashes[..slot.physical_hash_count as usize].contains(&hash)
}

pub(crate) unsafe fn directory_record_physical_name(
    slot: &mut VirtualDirectorySlot,
    name: *const c_char,
    name_length: usize,
) {
    if unsafe { directory_physical_name_seen(slot, name, name_length) } {
        return;
    }
    if (slot.physical_hash_count as usize) < DIRECTORY_PHYSICAL_HASH_CAP {
        slot.physical_name_hashes[slot.physical_hash_count as usize] =
            unsafe { folded_hash(name, name_length) };
        slot.physical_hash_count += 1;
    } else {
        slot.physical_hash_overflow = true;
    }
}

/// The child at `cursor` of the slot's range, merged with the following
/// entries of the same folded name; `Ok(false)` when there is none (the
/// caller skips the entry), `Err(IndexIo)` when an index read failed (the
/// listing fails, the cursor stays).
pub(crate) unsafe fn next_virtual_child(
    state: *const PackState,
    slot: &VirtualDirectorySlot,
    cursor: u32,
    name: *mut c_char,
    name_length: *mut u8,
    type_: *mut u8,
    next_cursor: *mut u32,
) -> Result<bool, IndexIo> {
    if zstd_mode() {
        return unsafe {
            next_virtual_child_zstd(state, slot, cursor, name, name_length, type_, next_cursor)
        };
    }
    unsafe {
        if !next_cursor.is_null() {
            *next_cursor = cursor;
        }
        if name.is_null() || name_length.is_null() || type_.is_null() || cursor >= slot.range_end {
            return Ok(false);
        }
        let slot_len = slot.path_length as usize;
        let file_index = *(*state).packed_file_order.add(cursor as usize);
        let mut path_buf = [0u8; SCE_KERNEL_PATH_MAX];
        let path = match file_record_path(state, file_index, &mut path_buf) {
            Ok(path) => path,
            Err(ampr_format::Error::Io) => return Err(IndexIo),
            Err(_) => return Ok(false),
        };
        let (path, file_len) = (path.as_ptr() as *const c_char, path.len());
        if file_len <= slot_len {
            return Ok(false);
        }
        let mut relative = slot_len;
        if *path.add(relative) == b'/' as c_char {
            relative += 1;
        }
        if relative >= file_len {
            return Ok(false);
        }
        let mut end = relative;
        while end < file_len && *path.add(end) != b'/' as c_char {
            end += 1;
        }
        let child_length = end - relative;
        if child_length == 0 || child_length > 255 {
            return Ok(false);
        }
        core::ptr::copy_nonoverlapping(path.add(relative), name, child_length);
        *name.add(child_length) = 0;
        *name_length = child_length as u8;
        *type_ = if end < file_len { DT_DIR } else { DT_REG };

        let mut group_end = cursor + 1;
        while group_end < slot.range_end {
            let other_index = *(*state).packed_file_order.add(group_end as usize);
            let mut other_buf = [0u8; SCE_KERNEL_PATH_MAX];
            // A read error here would end the group early and list its
            // name twice.
            let other = match file_record_path(state, other_index, &mut other_buf) {
                Ok(other) => other,
                Err(ampr_format::Error::Io) => return Err(IndexIo),
                Err(_) => break,
            };
            let (other_path, other_len) = (other.as_ptr() as *const c_char, other.len());
            if other_len <= slot_len {
                break;
            }
            let mut other_relative = slot_len;
            if *other_path.add(other_relative) == b'/' as c_char {
                other_relative += 1;
            }
            let mut other_end = other_relative;
            while other_end < other_len && *other_path.add(other_end) != b'/' as c_char {
                other_end += 1;
            }
            if !folded_equal(
                name,
                child_length,
                other_path.add(other_relative),
                other_end - other_relative,
            ) {
                break;
            }
            if other_end < other_len {
                *type_ = DT_DIR;
            }
            group_end += 1;
        }
        if !next_cursor.is_null() {
            *next_cursor = group_end;
        }
        Ok(true)
    }
}

/// zstd `next_virtual_child`: the overlay helper walks the zstd-backed
/// directory order (`packed_order`) of the slot's range. `name` must hold
/// 256 bytes. A read error of the paged index is `Err(IndexIo)`, not no
/// child.
unsafe fn next_virtual_child_zstd(
    state: *const PackState,
    slot: &VirtualDirectorySlot,
    cursor: u32,
    name: *mut c_char,
    name_length: *mut u8,
    type_: *mut u8,
    next_cursor: *mut u32,
) -> Result<bool, IndexIo> {
    unsafe {
        if !next_cursor.is_null() {
            *next_cursor = cursor;
        }
        if name.is_null() || name_length.is_null() || type_.is_null() {
            return Ok(false);
        }
        let Some(index) = zstd::zstd_index() else {
            return Ok(false);
        };
        let (order, count) = packed_order(state);
        let order: &[u32] = if order.is_null() || count == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(order, count as usize)
        };
        let name = core::slice::from_raw_parts_mut(name.cast::<u8>(), 256);
        let child = match zstd::zstd_next_child_read(
            index,
            order,
            slot.range_end,
            usize::from(slot.path_length),
            cursor,
            name,
        ) {
            Ok(Some(child)) => child,
            Ok(None) => return Ok(false),
            Err(ampr_format::Error::Io) => return Err(IndexIo),
            Err(_) => return Ok(false),
        };
        *name_length = child.len;
        *type_ = child.kind;
        if !next_cursor.is_null() {
            *next_cursor = child.next;
        }
        Ok(true)
    }
}

/// `overlay::emit_dirent` into `buffer[output..size]`: the record size, or
/// EINVAL when it does not fit.
///
/// # Safety
/// `buffer` must name `size` writable bytes.
unsafe fn emit_synthetic_dirent(
    buffer: *mut c_char,
    size: c_int,
    output: usize,
    name: &[u8],
    type_: u8,
    inode_seed: u64,
) -> c_int {
    let Some(capacity) = usize::try_from(size)
        .ok()
        .and_then(|n| n.checked_sub(output))
    else {
        return SCE_KERNEL_ERROR_EINVAL;
    };
    if buffer.is_null() {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    // The caller's buffer need not be 4-aligned; the record is written bytewise.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer.add(output).cast::<u8>(), capacity) };
    overlay::emit_dirent(out, name, type_, inode_seed)
        .map_or(SCE_KERNEL_ERROR_EINVAL, |n| n as c_int)
}

pub(crate) fn open_failure_errno(rc: c_int) -> c_int {
    if rc >= 0 {
        return 0;
    }
    if rc == -1 {
        return errno();
    }
    // Host shims use -errno; Prospero libkernel uses 0x8002xxxx SCE values.
    if rc > -256 {
        return -rc;
    }
    posix_errno_from_sce(rc)
}

/// Closes a runtime descriptor that is not counted in the open budget (a
/// directory's physical fd).
pub(crate) unsafe fn close_real_fd(real_fd: c_int) {
    if real_fd >= 0 {
        if let Some(close_fn) = unsafe { real_close() } {
            unsafe { close_fn(real_fd) };
        }
    }
}

/// Whether an open may name a directory, so the overlay serves it: an
/// explicit `O_DIRECTORY` open, or any read-only open, which the kernel
/// accepts for a directory too. A packed directory has no physical copy to
/// fall back to: a title opened `/app0/input/` 8 times with flags 0, got
/// ENOENT every time and loaded no input map. Also the gate of the
/// rt/index.rs open hooks.
pub(crate) fn directory_open_flags(flags: c_int) -> bool {
    flags & O_DIRECTORY != 0 || flags & O_ACCMODE == O_RDONLY
}

#[inline(never)]
pub(crate) unsafe fn ampr_pack_open_directory_impl(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    allow_physical_open: bool,
    handled: *mut bool,
) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        if path.is_null() || handled.is_null() || !directory_open_flags(flags) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let mut real_fd: c_int = -1;
        if allow_physical_open {
            let Some(open_fn) = real_open() else {
                return SCE_KERNEL_ERROR_EIO;
            };
            real_fd = open_fn(path, flags, mode as c_int);
            *handled = true;
        }

        // Read-only overlay: never turn an access/permission error or a
        // writable request into a synthetic success.
        if allow_physical_open && flags & O_ACCMODE != O_RDONLY {
            return real_fd;
        }
        // A plain read-only open of a directory that really is on disk (a
        // folder install) keeps the kernel's fd and its own entries; only a
        // missing directory is served from the index.
        if allow_physical_open && flags & O_DIRECTORY == 0 && real_fd >= 0 {
            return real_fd;
        }
        if allow_physical_open && real_fd < 0 {
            let open_errno = open_failure_errno(real_fd);
            if open_errno != ENOENT && open_errno != ENOTDIR {
                return real_fd;
            }
        }

        let fallback = if allow_physical_open {
            real_fd
        } else {
            SCE_KERNEL_ERROR_ENOENT
        };
        let mut normalized = [0 as c_char; SCE_KERNEL_PATH_MAX];
        let mut normalized_length = 0u16;
        let mut range_begin = 0u32;
        let mut range_end = 0u32;
        if !normalize_overlay_path(
            path,
            normalized.as_mut_ptr(),
            normalized.len(),
            &mut normalized_length,
        ) {
            return fallback;
        }
        // Held through the range lookup and the slot allocation: both read
        // the manifest (rt/pack/mod.rs `ManifestReader`).
        let Some(_reader) = ManifestReader::enter() else {
            return fallback;
        };
        let manifest_ready = if allow_physical_open {
            ensure_manifest_ready()
        } else {
            ampr_pack_manifest_is_resident_ready()
        };
        if !manifest_ready {
            return fallback;
        }
        let state = pack_state();
        match find_virtual_directory_range(
            state,
            normalized.as_ptr(),
            normalized_length,
            &mut range_begin,
            &mut range_end,
        ) {
            Ok(true) => {}
            Ok(false) => return fallback,
            // The index could not be read, so the directory may hold
            // packed entries: EIO, never the physical fd (a listing that
            // omits them) or ENOENT.
            Err(IndexIo) => {
                *handled = true;
                close_real_fd(real_fd);
                return SCE_KERNEL_ERROR_EIO;
            }
        }
        *handled = true;
        if flags & O_ACCMODE != O_RDONLY {
            return sce_errno_from_posix(EACCES);
        }

        let _lock = DIRECTORY_TABLE_MUTEX.lock();
        if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
            close_real_fd(real_fd);
            return SCE_KERNEL_ERROR_EBADF;
        }
        let slot = allocate_virtual_directory_locked(
            state,
            normalized.as_ptr(),
            normalized_length,
            real_fd,
            range_begin,
            range_end,
        );
        if slot == INVALID_INDEX {
            close_real_fd(real_fd);
            return SCE_KERNEL_ERROR_EMFILE;
        }
        encode_virtual_directory_fd(slot, (*state).virtual_directories[slot as usize].generation)
    }
}

pub unsafe fn ampr_pack_open_directory(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    handled: *mut bool,
) -> c_int {
    unsafe { ampr_pack_open_directory_impl(path, flags, mode, true, handled) }
}

pub unsafe fn ampr_pack_open_virtual_directory(
    path: *const c_char,
    flags: c_int,
    mode: SceKernelMode,
    handled: *mut bool,
) -> c_int {
    unsafe { ampr_pack_open_directory_impl(path, flags, mode, false, handled) }
}

/// AMPRPAK4 `ampr_pack_try_stat_path` body: a packed file, else a
/// directory with a packed descendant; true when `stat` was filled,
/// `Err` when an index read failed (rt/pack/state.rs `resolve_packed_file`).
unsafe fn manifest_stat_path(
    state: *const PackState,
    path: *const c_char,
    stat: *mut SceKernelStat,
) -> Result<bool, IndexIo> {
    unsafe {
        if let Some((file_id, PackedFile::Lz4(f))) = resolve_packed_file(state, path)? {
            fill_synthetic_stat(
                stat,
                false,
                f.logical_size,
                f.mtime,
                f.path_hash ^ file_id as u64,
            );
            return Ok(true);
        }
        let mut normalized = [0 as c_char; SCE_KERNEL_PATH_MAX];
        let mut length = 0u16;
        if normalize_overlay_path(path, normalized.as_mut_ptr(), normalized.len(), &mut length) {
            let order = if (*state).packed_file_order.is_null() || (*state).packed_file_count == 0 {
                &[][..]
            } else {
                core::slice::from_raw_parts(
                    (*state).packed_file_order,
                    (*state).packed_file_count as usize,
                )
            };
            if let Some(manifest) = (*state).core_view.manifest {
                let directory =
                    core::slice::from_raw_parts(normalized.as_ptr().cast::<u8>(), length as usize);
                let exists = match overlay::directory_exists(&manifest, order, directory) {
                    Err(ampr_format::Error::Io) => return Err(IndexIo),
                    found => found == Ok(true),
                };
                if exists {
                    fill_synthetic_stat(
                        stat,
                        true,
                        0,
                        0,
                        folded_hash(normalized.as_ptr(), length as usize),
                    );
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// zstd `ampr_pack_try_stat_path` body: a packed AMPRIDX3 id (stat as the
/// resident `file_stat`: AMPRIDX3 size and mtime, `st_ino` = id), else a
/// directory with a packed descendant in the zstd directory order; `Err`
/// as `manifest_stat_path`.
unsafe fn zstd_stat_path(
    state: *const PackState,
    path: *const c_char,
    stat: *mut SceKernelStat,
) -> Result<bool, IndexIo> {
    unsafe {
        if let Some((file_id, PackedFile::Zstd(entry))) = resolve_packed_file(state, path)? {
            fill_synthetic_stat(
                stat,
                false,
                entry.size as u64,
                entry.mtime,
                u64::from(file_id),
            );
            (*stat).st_ino = file_id;
            return Ok(true);
        }
        let mut normalized = [0 as c_char; SCE_KERNEL_PATH_MAX];
        let mut length = 0u16;
        let (Some(index), true) = (
            zstd::zstd_index(),
            normalize_overlay_path(path, normalized.as_mut_ptr(), normalized.len(), &mut length),
        ) else {
            return Ok(false);
        };
        let directory =
            core::slice::from_raw_parts(normalized.as_ptr().cast::<u8>(), length as usize);
        match zstd::zstd_directory_range(index, zstd::zstd_packed_order(), directory) {
            Ok(Some(_)) => {}
            Err(ampr_format::Error::Io) => return Err(IndexIo),
            _ => return Ok(false),
        }
        fill_synthetic_stat(
            stat,
            true,
            0,
            0,
            folded_hash(normalized.as_ptr(), length as usize),
        );
        Ok(true)
    }
}

/// A packed file or packed directory of `path` into `stat` (`handled`
/// set). Unhandled, the result is ENOENT, or EIO when an index read
/// failed (the caller then tries the real call).
#[inline(never)]
pub unsafe fn ampr_pack_try_stat_path(
    path: *const c_char,
    stat: *mut SceKernelStat,
    handled: *mut bool,
) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        if path.is_null() || stat.is_null() || handled.is_null() {
            return SCE_KERNEL_ERROR_ENOENT;
        }
        let Some(_reader) = ManifestReader::enter() else {
            return SCE_KERNEL_ERROR_ENOENT;
        };
        if !ensure_manifest_ready() {
            return SCE_KERNEL_ERROR_ENOENT;
        }
        let state = pack_state();
        let found = if zstd_mode() {
            zstd_stat_path(state, path, stat)
        } else {
            manifest_stat_path(state, path, stat)
        };
        match found {
            Ok(true) => {
                *handled = true;
                0
            }
            Ok(false) => SCE_KERNEL_ERROR_ENOENT,
            // The index could not be read, so the file may be loose or
            // packed: unhandled EIO. The caller tries the real call and
            // turns only its ENOENT into EIO (rt/index.rs `io_miss`), as
            // open does for a lookup that failed to read.
            Err(IndexIo) => SCE_KERNEL_ERROR_EIO,
        }
    }
}

#[inline(never)]
pub unsafe fn ampr_pack_try_reachability(path: *const c_char, handled: *mut bool) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        let mut stat = MaybeUninit::<SceKernelStat>::zeroed();
        ampr_pack_try_stat_path(path, stat.as_mut_ptr(), handled)
    }
}

pub unsafe fn ampr_pack_is_virtual_directory_fd(fd: c_int) -> bool {
    let mut slot = 0u32;
    let mut generation = 0u16;
    unsafe {
        if !decode_virtual_directory_fd(fd, &mut slot, &mut generation) {
            return false;
        }
        let state = pack_state();
        let _lock = DIRECTORY_MUTEXES[slot as usize].lock();
        let s = &(*state).virtual_directories[slot as usize];
        s.active && s.generation == generation
    }
}

/// Copies the path of an open virtual directory fd into `out` (truncated,
/// NUL-terminated) and returns its length; None for any other fd. Debug
/// probes (rt/probe.rs) log it so `/fsfail` dedups by directory.
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn virtual_directory_fd_path(fd: c_int, out: &mut [u8]) -> Option<usize> {
    let mut slot = 0u32;
    let mut generation = 0u16;
    if out.is_empty() || !unsafe { decode_virtual_directory_fd(fd, &mut slot, &mut generation) } {
        return None;
    }
    let state = unsafe { pack_state() };
    let _lock = DIRECTORY_MUTEXES[slot as usize].lock();
    let s = unsafe { &(*state).virtual_directories[slot as usize] };
    if !s.active || s.generation != generation {
        return None;
    }
    let n = (s.path_length as usize).min(s.path.len()).min(out.len() - 1);
    for (i, b) in out[..n].iter_mut().enumerate() {
        *b = s.path[i] as u8;
    }
    out[n] = 0;
    Some(n)
}

pub unsafe fn ampr_pack_try_close_fd(fd: c_int, handled: *mut bool) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        // A tagged directory fd or an open synthetic packed fd is decided before
        // pack_state(): a physical fd (the runtime's own closes reach here
        // through libkernel's `close` -> `_close` hook) must never create or
        // wait on the pack state. tune::load inside pack_state_create once
        // hung here spinning on that state.
        let mut index = 0u32;
        let mut generation = 0u16;
        if decode_virtual_directory_fd(fd, &mut index, &mut generation) {
            if !handled.is_null() {
                *handled = true;
            }
            let state = pack_state();
            let real_fd;
            {
                // No WORKER_STOP_REQUESTED early return here: the slot array
                // lives in PackState, which shutdown never frees, and an EBADF
                // would leak `real_fd` when shutdown stops before its sweep
                // (`close_pack_and_directory_fds`, after the worker joins).
                // The slot mutex orders this close against that sweep, so
                // each real fd is closed exactly once.
                let _lock = DIRECTORY_MUTEXES[index as usize].lock();
                let slot = &mut (*state).virtual_directories[index as usize];
                if !slot.active || slot.generation != generation {
                    return SCE_KERNEL_ERROR_EBADF;
                }
                real_fd = slot.real_fd;
                let preserved_generation = slot.generation;
                // `slot = {}` in place (the slot is ~5 KiB; EMPTY is zero but realFd).
                (slot as *mut VirtualDirectorySlot).write_bytes(0, 1);
                slot.real_fd = -1;
                slot.generation = preserved_generation;
            }
            if real_fd < 0 {
                return 0;
            }
            let Some(close_fn) = real_close() else {
                return SCE_KERNEL_ERROR_EIO;
            };
            let rc = close_fn(real_fd);
            return if rc == -1 {
                sce_errno_from_posix(errno())
            } else {
                rc
            };
        }
        if let Some(index) = decode_virtual_fd(fd) {
            if !handled.is_null() {
                *handled = true;
            }
            let state = pack_state();
            let _descriptor_lock = VIRTUAL_FD_MUTEXES[index as usize].lock();
            if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            let _lock = PACK_M.lock();
            let slot = &mut (*state).virtual_fds[index as usize];
            if !slot.holds(fd) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            *slot = VirtualFdSlot::EMPTY;
            VIRTUAL_FD_LIVE[index as usize].store(false, Ordering::Release);
            return 0;
        }
        SCE_KERNEL_ERROR_EBADF
    }
}

pub unsafe fn ampr_pack_try_fstat_fd(
    fd: c_int,
    stat: *mut SceKernelStat,
    handled: *mut bool,
) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        if stat.is_null() {
            return SCE_KERNEL_ERROR_EFAULT;
        }
        // Tag decode before pack_state(), as in ampr_pack_try_close_fd.
        let mut index = 0u32;
        let mut generation = 0u16;
        if decode_virtual_directory_fd(fd, &mut index, &mut generation) {
            if !handled.is_null() {
                *handled = true;
            }
            let state = pack_state();
            let _lock = DIRECTORY_MUTEXES[index as usize].lock();
            if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            let slot = &(*state).virtual_directories[index as usize];
            if !slot.active || slot.generation != generation {
                return SCE_KERNEL_ERROR_EBADF;
            }
            fill_synthetic_stat(
                stat,
                true,
                0,
                0,
                folded_hash(slot.path.as_ptr(), slot.path_length as usize),
            );
            return 0;
        }
        if let Some(index) = decode_virtual_fd(fd) {
            if !handled.is_null() {
                *handled = true;
            }
            return fstat_virtual_fd(pack_state(), fd, index, stat);
        }
        SCE_KERNEL_ERROR_EBADF
    }
}

/// fstat of a packed virtual fd, both formats: the slot keeps its one-based
/// AMPRIDX3 id, and the result equals the resident `stat` of the path
/// (rt/index.rs `file_stat`: AMPRIDX3 size and mtime, `st_ino` = id), so
/// code that compares stat and fstat (dev/ino caches, same-file checks)
/// sees one file. The AMPRPAK4 record's own mtime and path hash are not used.
unsafe fn fstat_virtual_fd(
    state: *const PackState,
    fd: c_int,
    index: u32,
    stat: *mut SceKernelStat,
) -> c_int {
    let file_id = {
        let _lock = PACK_M.lock();
        let slot = &(*state).virtual_fds[index as usize];
        if !slot.holds(fd) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        slot.file_id
    };
    // A refused guard is EBADF, as for an fd whose slot shutdown closed.
    let Some(_reader) = ManifestReader::enter() else {
        return SCE_KERNEL_ERROR_EBADF;
    };
    let mut entry = MaybeUninit::<FileEntryView>::zeroed();
    if !file_id_is_packed(&_reader, file_id) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    // The fd is open and its file packed: a paged index that could not be
    // read is EIO, not a bad fd.
    match unsafe { ampr_index_get_entry_view(file_id, entry.as_mut_ptr()) } {
        0 => {}
        rc if rc == -EIO => return SCE_KERNEL_ERROR_EIO,
        _ => return SCE_KERNEL_ERROR_EBADF,
    }
    let entry = unsafe { entry.assume_init() };
    unsafe {
        fill_synthetic_stat(
            stat,
            false,
            entry.size as u64,
            entry.mtime,
            u64::from(file_id),
        );
        (*stat).st_ino = file_id;
    }
    0
}

/// `(d_reclen, d_namlen)` of the kernel dirent at the start of `rest`, or
/// None when the header, the name or its NUL would run past `rest`. The
/// header length is checked before `d_reclen` and `d_namlen` are read, so a
/// tail shorter than `DIRENT_NAME_OFFSET` (8 bytes) is never overread.
fn physical_dirent_bounds(rest: &[u8]) -> Option<(usize, usize)> {
    if rest.len() < DIRENT_NAME_OFFSET {
        return None;
    }
    let reclen_at = core::mem::offset_of!(Dirent, d_reclen);
    let record_size = usize::from(u16::from_ne_bytes([rest[reclen_at], rest[reclen_at + 1]]));
    let name_length = usize::from(rest[core::mem::offset_of!(Dirent, d_namlen)]);
    if record_size < DIRENT_NAME_OFFSET + 1
        || record_size > rest.len()
        || name_length + 1 > record_size - DIRENT_NAME_OFFSET
    {
        return None;
    }
    Some((record_size, name_length))
}

/// Ends a synthetic batch of `result` bytes: reports `synthetic_base` and
/// advances the slot's directory offset past it.
fn finish_synthetic(
    slot: &mut VirtualDirectorySlot,
    basep: *mut c_long,
    synthetic_base: c_long,
    result: c_int,
) -> c_int {
    if result >= 0 {
        if !basep.is_null() {
            unsafe { *basep = synthetic_base };
        }
        slot.directory_offset = overlay::advance_offset(synthetic_base, result);
    }
    result
}

/// Emits the `.` or `..` entry once (`emitted`); 0, or the emit error.
unsafe fn emit_dot(
    buffer: *mut c_char,
    size: c_int,
    output: &mut usize,
    name: &CStr,
    emitted: &mut bool,
) -> c_int {
    if *emitted {
        return 0;
    }
    let bytes = name.to_bytes();
    let rc = unsafe {
        emit_synthetic_dirent(
            buffer,
            size,
            *output,
            bytes,
            DT_DIR,
            folded_hash(name.as_ptr(), bytes.len()),
        )
    };
    if rc < 0 {
        return rc;
    }
    *output += rc as usize;
    *emitted = true;
    0
}

pub(crate) unsafe fn ampr_pack_try_directory_read_fd(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
    use_getdirentries: bool,
    handled: *mut bool,
) -> c_int {
    unsafe {
        if !handled.is_null() {
            *handled = false;
        }
        let mut index = 0u32;
        let mut generation = 0u16;
        if !decode_virtual_directory_fd(fd, &mut index, &mut generation) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        if !handled.is_null() {
            *handled = true;
        }
        if use_getdirentries && basep.is_null() {
            return SCE_KERNEL_ERROR_EFAULT;
        }
        if buffer.is_null() || size <= 0 {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let state: *const PackState = pack_state();
        let getdents_fn = real_getdents();
        let getdirentries_fn = real_getdirentries();
        let stat_fn = real_stat();
        let _lock = DIRECTORY_MUTEXES[index as usize].lock();
        if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        // The slot is guarded by its directory mutex; `state` is read alongside.
        let slot = &mut *(&raw const (*state).virtual_directories[index as usize]
            as *mut VirtualDirectorySlot);
        if !slot.active || slot.generation != generation {
            return SCE_KERNEL_ERROR_EBADF;
        }

        while !slot.real_exhausted && slot.real_fd >= 0 {
            let mut physical_base = slot.directory_offset;
            let rc = if use_getdirentries {
                let Some(f) = getdirentries_fn else {
                    return SCE_KERNEL_ERROR_EIO;
                };
                f(slot.real_fd, buffer, size, &mut physical_base)
            } else {
                let Some(f) = getdents_fn else {
                    return SCE_KERNEL_ERROR_EIO;
                };
                f(slot.real_fd, buffer, size)
            };
            if rc < 0 {
                return rc;
            }
            if use_getdirentries {
                slot.directory_offset = overlay::advance_offset(physical_base, rc);
            } else if let Some(lseek_fn) = real_lseek() {
                let current = lseek_fn(slot.real_fd, 0, SEEK_CUR);
                slot.directory_offset = if current >= 0 {
                    current as c_long
                } else {
                    overlay::advance_offset(slot.directory_offset, rc)
                };
            } else {
                slot.directory_offset = overlay::advance_offset(slot.directory_offset, rc);
            }
            if rc == 0 {
                slot.real_exhausted = true;
                break;
            }
            let total = rc as usize;
            let mut input = 0usize;
            let mut output = 0usize;
            while input < total {
                let rest =
                    core::slice::from_raw_parts(buffer.add(input) as *const u8, total - input);
                let Some((record_size, name_length)) = physical_dirent_bounds(rest) else {
                    return SCE_KERNEL_ERROR_EIO;
                };
                let d_name = buffer.add(input + DIRENT_NAME_OFFSET) as *const c_char;
                let hidden = service_name_hidden(
                    state,
                    slot.path.as_ptr(),
                    slot.path_length,
                    d_name,
                    name_length,
                );
                if !hidden {
                    directory_record_physical_name(slot, d_name, name_length);
                    if output != input {
                        core::ptr::copy(buffer.add(input), buffer.add(output), record_size);
                    }
                    output += record_size;
                }
                input += record_size;
            }
            if output != 0 {
                if !basep.is_null() {
                    *basep = physical_base;
                }
                return output as c_int;
            }
        }

        let mut output = 0usize;
        let synthetic_base = slot.directory_offset;
        if slot.real_fd < 0 {
            for (name, which) in [(c".", 0), (c"..", 1)] {
                let emitted = if which == 0 {
                    &mut slot.dot_emitted
                } else {
                    &mut slot.dot_dot_emitted
                };
                let dot_rc = emit_dot(buffer, size, &mut output, name, emitted);
                if dot_rc < 0 {
                    return if output == 0 {
                        dot_rc
                    } else {
                        finish_synthetic(slot, basep, synthetic_base, output as c_int)
                    };
                }
            }
        }

        // The slot path is fixed while the slot is open: hash it once.
        let path_hash = folded_hash(slot.path.as_ptr(), slot.path_length as usize);
        while slot.virtual_cursor < slot.range_end {
            let mut name = [0u8; 256];
            let mut name_length = 0u8;
            let mut type_ = DT_UNKNOWN;
            let mut next_cursor = slot.virtual_cursor;
            match next_virtual_child(
                state,
                slot,
                slot.virtual_cursor,
                name.as_mut_ptr().cast(),
                &mut name_length,
                &mut type_,
                &mut next_cursor,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    slot.virtual_cursor = (slot.virtual_cursor + 1).max(next_cursor);
                    continue;
                }
                // The index could not be read: fail the listing (or end
                // this batch early) with the cursor kept, so a later call
                // lists the entry instead of skipping it.
                Err(IndexIo) => {
                    return if output == 0 {
                        SCE_KERNEL_ERROR_EIO
                    } else {
                        finish_synthetic(slot, basep, synthetic_base, output as c_int)
                    };
                }
            }
            let mut duplicate =
                directory_physical_name_seen(slot, name.as_ptr().cast(), name_length as usize);
            if !duplicate && slot.physical_hash_overflow {
                if let Some(stat_fn) = stat_fn {
                    let mut child_path = [0 as c_char; SCE_KERNEL_PATH_MAX];
                    let mut stat = MaybeUninit::<SceKernelStat>::zeroed();
                    duplicate = join_directory_child(
                        slot,
                        name.as_ptr().cast(),
                        name_length as usize,
                        child_path.as_mut_ptr(),
                        child_path.len(),
                    ) && stat_fn(child_path.as_ptr(), stat.as_mut_ptr()) == 0;
                }
            }
            if duplicate {
                slot.virtual_cursor = next_cursor;
                continue;
            }
            let needed = overlay::dirent_size(name_length as usize);
            if needed == usize::MAX || needed > size as usize - output {
                if output == 0 {
                    return SCE_KERNEL_ERROR_EINVAL;
                }
                break;
            }
            let rc = emit_synthetic_dirent(
                buffer,
                size,
                output,
                &name[..usize::from(name_length)],
                type_,
                path_hash ^ folded_hash(name.as_ptr().cast(), name_length as usize),
            );
            if rc < 0 {
                return if output == 0 {
                    rc
                } else {
                    finish_synthetic(slot, basep, synthetic_base, output as c_int)
                };
            }
            output += rc as usize;
            slot.virtual_cursor = next_cursor;
        }
        finish_synthetic(slot, basep, synthetic_base, output as c_int)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(reclen: u16, namlen: u8, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        bytes[4..6].copy_from_slice(&reclen.to_ne_bytes());
        bytes[7] = namlen;
        bytes
    }

    #[test]
    fn physical_dirent_bounds_rejects_short_and_bad_records() {
        // A tail shorter than the 8-byte header is rejected before any read.
        for len in 0..DIRENT_NAME_OFFSET {
            assert_eq!(physical_dirent_bounds(&vec![0xff; len]), None);
        }
        assert_eq!(physical_dirent_bounds(&record(16, 3, 16)), Some((16, 3)));
        assert_eq!(physical_dirent_bounds(&record(16, 7, 16)), Some((16, 7)));
        // Name plus NUL past the record, record past the input, tiny record.
        assert_eq!(physical_dirent_bounds(&record(16, 8, 16)), None);
        assert_eq!(physical_dirent_bounds(&record(24, 3, 16)), None);
        assert_eq!(physical_dirent_bounds(&record(8, 0, 16)), None);
    }
}
