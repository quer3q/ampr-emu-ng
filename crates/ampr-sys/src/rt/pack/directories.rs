//! Virtual directories, synthetic dirents, stat, close and fstat of
//! virtual descriptors.

use super::*;
use crate::rt::index::IndexIo;
use ampr_format::source::{Source, PATH_BUF};
use ampr_format::view::{View, DIR_PACKED};
use ampr_format::view_list::Entry;
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

// ---- view listing -----------------------------------------------------------
//
// A packed directory is a view directory with `DIR_PACKED` set: the join
// (zstd `join_zstd`, LZ4 and pkg `join_records`) linked a file below it.
// Listings walk the view (`View::first`/`next`), child directories first,
// then the directory's packed files, in no particular order; a name is
// the last component of the stored AMPRIDX3 path, so it has the case
// lookups and opens use.

/// The published view and the source its paths are read from, once the
/// pack mount is ready. Every pack format joins its records to the view
/// before the index is published, so a ready mount has its `DIR_PACKED`.
fn listing_view() -> Option<(View<'static>, &'static crate::rt::index::Paths)> {
    if LOAD_STATE.load(Ordering::Acquire) != PACK_LOAD_READY {
        return None;
    }
    let c = crate::rt::index::published().filter(|c| c.available)?;
    Some((c.view()?, &c.paths))
}

/// The cursor at the first entry of the packed directory the normalized
/// logical `directory` names; None for a file, a miss or a directory with
/// nothing packed below it. `Err(Io)` when a path read to tell two
/// directories of one hash apart failed: the directory may be packed.
pub(crate) fn packed_dir_in<S: Source + ?Sized>(
    view: &View<'_>,
    src: &S,
    directory: &[u8],
) -> ampr_format::Result<Option<Cursor>> {
    // Directories only: a file of the same folded key (`a` beside `A/`)
    // must not hide the directory.
    match view.lookup_dir(src, directory)? {
        Some(d) if view.dir(d).flags & DIR_PACKED != 0 => Ok(Some(view.first(d))),
        _ => Ok(None),
    }
}

/// `packed_dir_in` over the published view; None before the mount is ready.
pub(crate) fn packed_dir(directory: &[u8]) -> ampr_format::Result<Option<Cursor>> {
    match listing_view() {
        Some((view, paths)) => packed_dir_in(&view, paths, directory),
        None => Ok(None),
    }
}

/// One listed child: `name[..len]` NUL-terminated, its dirent type and
/// the cursor after it. `len == 0` is an entry whose name cannot be listed
/// (empty or longer than 255 bytes): the caller skips it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ViewChild {
    pub len: u8,
    pub kind: u8,
    pub next: Cursor,
}

/// The child at cursor `c`; None at the end. The stored path is read for
/// the name, so a read error is `Err(Io)` and the caller keeps `c`; any
/// other error is an entry to skip (`len == 0`).
pub(crate) fn list_next_in<S: Source + ?Sized>(
    view: &View<'_>,
    src: &S,
    c: Cursor,
    name: &mut [u8; 256],
) -> ampr_format::Result<Option<ViewChild>> {
    let (entry, next) = view.next(c);
    let mut buf = [0u8; PATH_BUF];
    let read = match entry {
        None => return Ok(None),
        Some(Entry::Dir(d)) => view.dir_path(src, d, &mut buf).map(|p| (p, DT_DIR)),
        Some(Entry::File(id)) => view.path(src, id, &mut buf).map(|p| (p, DT_REG)),
    };
    let (path, kind) = match read {
        Ok(read) => read,
        Err(ampr_format::Error::Io) => return Err(ampr_format::Error::Io),
        // An unusable record lists nothing; the listing goes on after it.
        Err(_) => (&[][..], DT_UNKNOWN),
    };
    let leaf = path.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    let len = if leaf.is_empty() || leaf.len() > 255 {
        0
    } else {
        name[..leaf.len()].copy_from_slice(leaf);
        name[leaf.len()] = 0;
        leaf.len() as u8
    };
    Ok(Some(ViewChild { len, kind, next }))
}

/// `list_next_in` over the published view; None before the mount is ready.
pub(crate) fn list_next(c: Cursor, name: &mut [u8; 256]) -> ampr_format::Result<Option<ViewChild>> {
    match listing_view() {
        Some((view, paths)) => list_next_in(&view, paths, c, name),
        None => Ok(None),
    }
}

/// The child at the slot's view cursor (`list_next`) and the cursor after it in `next`.
/// `Ok(false)` at the end of the listing (`next` is `Done`) or for an
/// entry whose name cannot be listed (skipped); `Err(IndexIo)` when its
/// path could not be read (the cursor stays).
fn next_view_child(
    slot: &VirtualDirectorySlot,
    name: &mut [u8; 256],
    name_length: &mut u8,
    type_: &mut u8,
    next: &mut Cursor,
) -> Result<bool, IndexIo> {
    *next = slot.listing;
    let child = match list_next(slot.listing, name) {
        Ok(Some(child)) => child,
        Err(ampr_format::Error::Io) => return Err(IndexIo),
        Ok(None) | Err(_) => {
            *next = Cursor::Done;
            return Ok(false);
        }
    };
    *next = child.next;
    *name_length = child.len;
    *type_ = child.kind;
    Ok(child.len != 0)
}

/// The view cursor of the packed directory the normalized logical path
/// `directory` names (`packed_dir`), None when it is not one;
/// `Err(IndexIo)` when a path read failed (it may be one).
///
/// # Safety
/// `directory` must name `length` readable bytes.
unsafe fn view_listing(directory: *const c_char, length: u16) -> Result<Option<Cursor>, IndexIo> {
    let directory = unsafe { core::slice::from_raw_parts(directory.cast::<u8>(), length as usize) };
    match packed_dir(directory) {
        Ok(c) => Ok(c),
        Err(ampr_format::Error::Io) => Err(IndexIo),
        Err(_) => Ok(None),
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
        if !normalize_overlay_path(
            path,
            normalized.as_mut_ptr(),
            normalized.len(),
            &mut normalized_length,
        ) {
            return fallback;
        }
        // Held through the listing lookup and the slot allocation: both read
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
        let mut listing = Cursor::Done;
        let found = view_listing(normalized.as_ptr(), normalized_length).map(|c| {
            listing = c.unwrap_or(Cursor::Done);
            c.is_some()
        });
        match found {
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
            listing,
        );
        if slot == INVALID_INDEX {
            close_real_fd(real_fd);
            return SCE_KERNEL_ERROR_EMFILE;
        }
        encode_virtual_directory_fd(slot)
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

/// `ampr_pack_try_stat_path` body: a packed file (zstd: AMPRIDX3 size and
/// mtime from the view, `st_ino` = id; LZ4 and pkg: the manifest record),
/// else a view directory with a packed file below it (`DIR_PACKED`); true
/// when `stat` was filled, `Err` when an index read failed (rt/pack/
/// state.rs `resolve_packed_file`, `view_listing`).
unsafe fn packed_stat_path(
    state: *const PackState,
    path: *const c_char,
    stat: *mut SceKernelStat,
) -> Result<bool, IndexIo> {
    unsafe {
        match resolve_packed_file(state, path)? {
            Some((file_id, PackedFile::Zstd(entry))) => {
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
            Some((file_id, PackedFile::Lz4(f))) => {
                fill_synthetic_stat(
                    stat,
                    false,
                    f.logical_size,
                    f.mtime,
                    f.path_hash ^ file_id as u64,
                );
                return Ok(true);
            }
            None => {}
        }
        let mut normalized = [0 as c_char; SCE_KERNEL_PATH_MAX];
        let mut length = 0u16;
        if !normalize_overlay_path(path, normalized.as_mut_ptr(), normalized.len(), &mut length)
            || view_listing(normalized.as_ptr(), length)?.is_none()
        {
            return Ok(false);
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
        match packed_stat_path(state, path, stat) {
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
    unsafe {
        let Some(slot) = decode_virtual_directory_fd(fd) else {
            return false;
        };
        let state = pack_state();
        let _lock = DIRECTORY_MUTEXES[slot as usize].lock();
        (*state).virtual_directories[slot as usize].active
    }
}

/// Copies the path of an open virtual directory fd into `out` (truncated,
/// NUL-terminated) and returns its length; None for any other fd. Debug
/// probes (rt/probe.rs) log it so `/fsfail` dedups by directory.
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn virtual_directory_fd_path(fd: c_int, out: &mut [u8]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    let slot = decode_virtual_directory_fd(fd)?;
    let state = unsafe { pack_state() };
    let _lock = DIRECTORY_MUTEXES[slot as usize].lock();
    let s = unsafe { &(*state).virtual_directories[slot as usize] };
    if !s.active {
        return None;
    }
    let n = (s.path_length as usize)
        .min(s.path.len())
        .min(out.len() - 1);
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
        // An open synthetic directory fd or packed fd is decided before
        // pack_state(): a physical fd (the runtime's own closes reach here
        // through libkernel's `close` -> `_close` hook) must never create or
        // wait on the pack state. tune::load inside pack_state_create once
        // hung here spinning on that state.
        if let Some(index) = decode_virtual_directory_fd(fd) {
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
                if !slot.active {
                    return SCE_KERNEL_ERROR_EBADF;
                }
                real_fd = slot.real_fd;
                // `slot = {}` in place (the slot is ~5 KiB; EMPTY is zero but realFd).
                (slot as *mut VirtualDirectorySlot).write_bytes(0, 1);
                slot.real_fd = -1;
                VIRTUAL_DIRECTORY_LIVE[index as usize].store(false, Ordering::Release);
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
        // Range decode before pack_state(), as in ampr_pack_try_close_fd.
        if let Some(index) = decode_virtual_directory_fd(fd) {
            if !handled.is_null() {
                *handled = true;
            }
            let state = pack_state();
            let _lock = DIRECTORY_MUTEXES[index as usize].lock();
            if WORKER_STOP_REQUESTED.load(Ordering::Acquire) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            let slot = &(*state).virtual_directories[index as usize];
            if !slot.active {
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
    // The fd is open and its file packed: an index path that could not be
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

/// `getdents` / `getdirentries` on a virtual directory fd. The debug build
/// logs each distinct failed (directory, result) once (`note_directory_read`);
/// successful reads are not logged, as each batch size would take one of the
/// 96 `/fsfail` entries.
pub(crate) unsafe fn ampr_pack_try_directory_read_fd(
    fd: c_int,
    buffer: *mut c_char,
    size: c_int,
    basep: *mut c_long,
    use_getdirentries: bool,
    handled: *mut bool,
) -> c_int {
    let rc = unsafe { directory_read_fd(fd, buffer, size, basep, use_getdirentries, handled) };
    #[cfg(feature = "mem_report")]
    if rc < 0 && !handled.is_null() && unsafe { *handled } {
        unsafe { note_directory_read(fd, rc) };
    }
    rc
}

/// The /fsfail line "read <directory> rc=0x<8 hex>" (op `U`, lookup `d`) of a
/// failed read. Logged through `fs_note`, so every distinct result of a
/// directory is kept once and `/fsfail` counts the repeats.
#[cfg(feature = "mem_report")]
unsafe fn note_directory_read(fd: c_int, rc: c_int) {
    let mut path = [0u8; 96];
    let Some(path_len) = (unsafe { virtual_directory_fd_path(fd, &mut path) }) else {
        return;
    };
    note_directory_line(&path[..path_len], b"read ", b" rc=", rc, b'd');
}

/// The /fsfail line "realfail <directory> errno=<n>" (op `U`, lookup `x`):
/// the physical `getdents` behind a virtual directory failed with `errno`, so
/// the listing continues from the index alone (`directory_read_fd`). Called
/// with the slot's path under its mutex, which `note_directory_read` cannot take.
#[cfg(feature = "mem_report")]
fn note_directory_real_failure(path: &[c_char], errno: c_int) {
    let mut bytes = [0u8; 96];
    let n = path.len().min(bytes.len() - 1);
    for (i, b) in bytes[..n].iter_mut().enumerate() {
        *b = path[i] as u8;
    }
    note_directory_line(&bytes[..n], b"realfail ", b" errno=", errno, b'x');
}

/// `<label><path><mid><value>` as an `fs_note` line of op `U`: `value` in
/// decimal when it is not negative, else as `0x<8 hex>`.
#[cfg(feature = "mem_report")]
fn note_directory_line(path: &[u8], label: &[u8], mid: &[u8], value: c_int, how: u8) {
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    let mut push = |bytes: &[u8]| {
        for &b in bytes {
            if n + 1 >= buf.len() {
                return;
            }
            buf[n] = b;
            n += 1;
        }
    };
    push(label);
    push(path);
    push(mid);
    if value >= 0 {
        let mut digits = [0u8; 10];
        let mut count = 0usize;
        let mut v = value as u32;
        loop {
            digits[count] = b'0' + (v % 10) as u8;
            count += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            push(&[digits[count]]);
        }
    } else {
        push(b"0x");
        let v = value as u32;
        for i in (0..8).rev() {
            push(&[b"0123456789abcdef"[((v >> (i * 4)) & 0xf) as usize]]);
        }
    }
    buf[n] = 0;
    crate::rt::stats::fs_note(b'U', how, i64::from(value), buf.as_ptr().cast());
}

/// Whether a failed physical `getdents` ends the physical part of the
/// listing. EINTR and EAGAIN are the caller's to retry and go back to it;
/// anything else would give the game the same error again (a folder install
/// on the internal SSD: EINVAL on every call, 67 million calls in 92 s, while
/// the same listing on USB exFAT worked), so the physical entries are dropped
/// and the packed ones are listed instead.
fn physical_getdents_failure_is_final(errno: c_int) -> bool {
    errno != EINTR && errno != EAGAIN
}

unsafe fn directory_read_fd(
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
        let Some(index) = decode_virtual_directory_fd(fd) else {
            return SCE_KERNEL_ERROR_EBADF;
        };
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
        if !slot.active {
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
                let errno = open_failure_errno(rc);
                if !physical_getdents_failure_is_final(errno) {
                    return rc;
                }
                #[cfg(feature = "mem_report")]
                note_directory_real_failure(&slot.path[..slot.path_length as usize], errno);
                slot.real_failed = true;
                slot.real_exhausted = true;
                break;
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
            // The physical listing gives `.` and `..`; a later failure must
            // not list them again.
            slot.dot_emitted = true;
            slot.dot_dot_emitted = true;
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
        // A physical directory lists `.` and `..` itself; with none, or one
        // that failed to list, they come from here.
        if slot.real_fd < 0 || slot.real_failed {
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
        while slot.listing != Cursor::Done {
            let mut name = [0u8; 256];
            let mut name_length = 0u8;
            let mut type_ = DT_UNKNOWN;
            let mut next_listing = slot.listing;
            let child = next_view_child(
                slot,
                &mut name,
                &mut name_length,
                &mut type_,
                &mut next_listing,
            );
            match child {
                Ok(true) => {}
                Ok(false) => {
                    slot.listing = next_listing;
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
                slot.listing = next_listing;
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
            slot.listing = next_listing;
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

    /// A physical `getdents` that fails for good ends the physical
    /// listing; an interrupted or would-block one goes back to the caller.
    #[test]
    fn physical_getdents_failure_ends_the_listing_except_for_retries() {
        assert!(!physical_getdents_failure_is_final(EINTR));
        assert!(!physical_getdents_failure_is_final(EAGAIN));
        for errno in [EINVAL, EIO, ENOENT, EBADF, EFAULT] {
            assert!(physical_getdents_failure_is_final(errno), "{errno}");
        }
        // `open_failure_errno` maps the raw -1 to errno() and an SCE code to
        // its POSIX value, so a failed listing is told apart from a retry.
        assert_eq!(open_failure_errno(SCE_KERNEL_ERROR_EINVAL), EINVAL);
        assert_eq!(open_failure_errno(SCE_KERNEL_ERROR_EIO), EIO);
    }
}
