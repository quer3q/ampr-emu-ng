//! Pack volume geometry, pack paths, data header
//! validation and pack fd acquisition.

use super::super::fd_cache::{
    ampr_index_fd_cache_mark_open_pressure, ampr_index_fd_cache_release_idle_percent,
    ampr_index_fd_cache_stats, ampr_index_fd_uncached_open_count,
};
use super::*;

// ---- mounted volume geometry (AMPRPAK4 records, or the zstd index) -----------

/// Mounted pack volumes (0 while unmounted): AMPRPAK4 `pack_count`, or the
/// zstd volume count once its projection is ready.
pub(crate) unsafe fn pack_volume_count(state: *const PackState) -> u32 {
    if zstd_mode() {
        zstd::zstd_volume_count()
    } else if (*state).header.is_null() {
        0
    } else {
        unsafe { (*(*state).header).pack_count }
    }
}

/// Mounted chunk records (0 while unmounted).
pub(crate) unsafe fn pack_chunk_count(state: *const PackState) -> u64 {
    if zstd_mode() {
        u64::from(zstd::zstd_chunk_count())
    } else if (*state).header.is_null() {
        0
    } else {
        unsafe { (*(*state).header).chunk_count }
    }
}

pub(crate) unsafe fn build_pack_path(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    match pack_format() {
        PackFormat::Zstd => unsafe { build_pack_path_zstd(state, pack_id, output, output_size) },
        PackFormat::Pkg => unsafe { build_pack_path_pkg(state, pack_id, output, output_size) },
        PackFormat::Lz4 | PackFormat::Plain => unsafe {
            build_pack_path_lz4(state, pack_id, output, output_size)
        },
    }
}

unsafe fn build_pack_path_zstd(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    let mut name_buffer = [0u8; 32];
    if output.is_null() || u32::from(pack_id) >= unsafe { pack_volume_count(state) } {
        return false;
    }
    let Ok(name) = ampr_format::zstd::volume_name(u32::from(pack_id), &mut name_buffer) else {
        return false;
    };
    let name = name.as_bytes();
    let root = AMPR_EMU_PACK_ROOT_PATH.to_bytes();
    let needs_slash = !root.is_empty() && root[root.len() - 1] != b'/';
    let prefix_length = root.len() + needs_slash as usize;
    if prefix_length + name.len() + 1 > output_size {
        return false;
    }
    let out = output as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(root.as_ptr(), out, root.len());
        if needs_slash {
            *out.add(root.len()) = b'/';
        }
        core::ptr::copy_nonoverlapping(name.as_ptr(), out.add(prefix_length), name.len());
        *out.add(prefix_length + name.len()) = 0;
    }
    true
}

pub(super) unsafe fn build_pack_path_lz4(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    if output.is_null()
        || output_size == 0
        || (*state).header.is_null()
        || pack_id as u32 >= { (*(*state).header).pack_count }
    {
        return false;
    }
    let Some(record) = lz4_pack(state, u32::from(pack_id)) else {
        return false;
    };
    let mut name = [0u8; SCE_KERNEL_PATH_MAX];
    let Some(name) = manifest_string(state, record.name_offset, record.name_length, &mut name)
    else {
        return false;
    };
    let root = AMPR_EMU_PACK_ROOT_PATH.to_bytes();
    let needs_slash = !root.is_empty() && root[root.len() - 1] != b'/';
    let prefix_length = root.len() + needs_slash as usize;
    let name_length = name.len();
    if prefix_length + name_length + 1 > output_size {
        return false;
    }
    let out = output as *mut u8;
    core::ptr::copy_nonoverlapping(root.as_ptr(), out, root.len());
    if needs_slash {
        *out.add(root.len()) = b'/';
    }
    core::ptr::copy_nonoverlapping(name.as_ptr(), out.add(prefix_length), name_length);
    *out.add(prefix_length + name_length) = 0;
    true
}

/// zstd: checks the 64-byte AMPRZDT1 header against the mounted index and
/// the actual size (`file_size`, from fstat) against `Index::volume_size`.
/// Chunk offsets are absolute and exact reads stay inside the volume, so the
/// I/O range is `[0, volume size)`.
pub(crate) unsafe fn validate_data_header(
    state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    match pack_format() {
        PackFormat::Zstd => unsafe {
            validate_data_header_zstd(state, pack_id, fd, file_size, payload_begin, payload_end)
        },
        PackFormat::Pkg => unsafe {
            validate_data_header_pkg(state, pack_id, fd, file_size, payload_begin, payload_end)
        },
        PackFormat::Lz4 | PackFormat::Plain => unsafe {
            validate_data_header_lz4(state, pack_id, fd, file_size, payload_begin, payload_end)
        },
    }
}

unsafe fn validate_data_header_zstd(
    _state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    use ampr_format::zstd::VOLUME_HEADER_SIZE;
    let Some(index) = zstd::zstd_index() else {
        return false;
    };
    let volume = u32::from(pack_id);
    let Ok(volume_size) = index.volume_size(volume) else {
        return false;
    };
    if payload_begin.is_null() || payload_end.is_null() || file_size != volume_size {
        return false;
    }
    let mut header = [0u8; VOLUME_HEADER_SIZE];
    stats::add(stats::Stat::PackDiskReads, 1);
    stats::add(stats::Stat::PackDiskBytes, VOLUME_HEADER_SIZE as u64);
    if !unsafe { pread_exact(fd, header.as_mut_ptr() as *mut c_void, header.len(), 0) } {
        return false;
    }
    if ampr_format::zstd::volume_header(&header, index, volume).is_err() {
        return false;
    }
    unsafe {
        *payload_begin = 0;
        *payload_end = volume_size;
    }
    true
}

pub(super) unsafe fn validate_data_header_lz4(
    state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    let mut header = MaybeUninit::<AmprPackDataHeader>::zeroed();
    stats::add(stats::Stat::PackDiskReads, 1);
    stats::add(
        stats::Stat::PackDiskBytes,
        size_of::<AmprPackDataHeader>() as u64,
    );
    if !pread_exact(
        fd,
        header.as_mut_ptr() as *mut c_void,
        size_of::<AmprPackDataHeader>(),
        0,
    ) {
        return false;
    }
    let Some(record) = lz4_pack(state, u32::from(pack_id)) else {
        return false;
    };
    ampr_rust_volume_header_validate(
        header.as_ptr() as *const u8,
        core::ptr::addr_of!((*(*state).header).build_id) as *const u8,
        pack_id as u32,
        record.flags,
        record.file_size,
        record.payload_bytes,
        record.io_page_size,
        file_size,
        payload_begin,
        payload_end,
    ) != 0
}

// ---- stale pack fd reopen ----

/// Reopen state of a pack handle. ShadowMountPlus releases USB-backed images
/// in rest mode and remounts them on resume, so a volume fd opened before
/// suspend can fail every read. A job whose read fails on a `StaleRetry` fd
/// retries once on a reopened fd; `StaleRetry` is entered only from `Clean`,
/// and `Clean` only after a good read on a reopened fd, so a dead device
/// costs one retry per failure burst and never loops. A flapping device
/// (good reads in between) can re-arm the retry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PackFdReopen {
    Clean,
    /// First stale-fd error: reads on this fd retry; no new pins.
    StaleRetry,
    /// The fd was reopened after a stale-fd error; no good read yet.
    Reopened,
    /// Stale-fd error after a reopen: reads on this fd fail; no new pins.
    StaleReport,
}

impl PackFdReopen {
    pub(crate) fn is_stale(self) -> bool {
        matches!(self, Self::StaleRetry | Self::StaleReport)
    }

    /// State once the handle's fd is closed (stale close or eviction).
    pub(crate) fn after_close(self) -> Self {
        if self.is_stale() {
            Self::Reopened
        } else {
            self
        }
    }

    /// A finished read on this handle's fd: (error for the job, new state).
    /// EAGAIN means retry the job through the transient-error path.
    pub(crate) fn after_read(self, error: c_int) -> (c_int, Self) {
        match self {
            _ if error == 0 && self == Self::Reopened => (0, Self::Clean),
            _ if !pack_fd_error_wants_reopen(error) => (error, self),
            Self::Clean | Self::StaleRetry => (SCE_KERNEL_ERROR_EAGAIN, Self::StaleRetry),
            Self::Reopened | Self::StaleReport => (error, Self::StaleReport),
        }
    }
}

/// Read errors that may mean a stale pack fd: EBADF (fd invalidated), EIO
/// and ENXIO (backing device released or replaced). Other errors keep the fd.
pub(crate) fn pack_fd_error_wants_reopen(error: c_int) -> bool {
    error == SCE_KERNEL_ERROR_EBADF
        || error == SCE_KERNEL_ERROR_EIO
        || error == SCE_KERNEL_ERROR_ENXIO
}

/// `release_pack_fd` for a finished read on `fd`: applies `after_read` while
/// the pin still holds the handle on `fd`, and returns the job's error.
/// `read_ran`: the kernel accepted the AIO. A refused or failed submit says
/// nothing about the fd, so it keeps its state and the job its error.
pub(crate) unsafe fn release_pack_fd_after_read(
    pack_id: u16,
    fd: c_int,
    error: c_int,
    read_ran: bool,
) -> c_int {
    let state = pack_state();
    let mut result = error;
    if read_ran {
        let _lock = PACK_M.lock();
        if (pack_id as u32) < pack_volume_count(state) {
            let handle = &mut (*state).pack_handles[pack_id as usize];
            if handle.fd == fd && handle.pins != 0 {
                (result, handle.reopen) = handle.reopen.after_read(error);
            }
        }
    }
    release_pack_fd(pack_id);
    result
}

/// `open_only` (read-ahead, readahead.rs): use only an already-open handle; return
/// EAGAIN instead of evicting another handle or opening this one.
pub(crate) unsafe fn acquire_pack_fd(pack_id: u16, open_only: bool) -> c_int {
    let state = pack_state();
    let mut path = [0 as c_char; SCE_KERNEL_PATH_MAX];
    let (Some(open_fn), Some(_), Some(fstat_fn)) = (real_open(), real_close(), real_fstat()) else {
        return SCE_KERNEL_ERROR_EIO;
    };
    let id = pack_id as usize;
    let stale_fd = {
        let _lock = PACK_M.lock();
        if pack_id as u32 >= pack_volume_count(state) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let handle = &mut (*state).pack_handles[id];
        if handle.fd >= 0 && handle.reopen.is_stale() {
            // No new pins on a stale fd; the last unpin bumps
            // PACK_FD_PROGRESS_EPOCH and wakes this job to reopen it.
            if open_only || handle.pins != 0 {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            let fd = handle.fd;
            *handle = PackHandle {
                reopen: handle.reopen.after_close(),
                ..PackHandle::EMPTY
            };
            if (*state).open_pack_count == 0 {
                abort();
            }
            (*state).open_pack_count -= 1;
            stats::add(stats::Stat::PackFdReopens, 1);
            fd
        } else {
            -1
        }
    };
    // Closed outside PACK_M: a close on a released USB device may block.
    close_physical_pack_fd(stale_fd);
    let mut victim_fd = -1;
    {
        let _lock = PACK_M.lock();
        // AMPRPAK4 pack count, or the zstd volume count.
        let pack_count = pack_volume_count(state);
        if pack_id as u32 >= pack_count {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        if (*state).pack_handles[id].fd >= 0 {
            // Marked stale since the check above: no new pin, so the last
            // unpin can close it; the next attempt reopens (see above).
            if (*state).pack_handles[id].reopen.is_stale() {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            if (*state).pack_handles[id].pins == u32::MAX {
                return SCE_KERNEL_ERROR_EBUSY;
            }
            (*state).pack_handles[id].pins += 1;
            (*state).pack_handles[id].last_use = (*state).tick;
            (*state).tick += 1;
            return (*state).pack_handles[id].fd;
        }
        if open_only || (*state).pack_handles[id].opening {
            return SCE_KERNEL_ERROR_EAGAIN;
        }
        if !build_pack_path(state, pack_id, path.as_mut_ptr(), path.len()) {
            return SCE_KERNEL_ERROR_ENAMETOOLONG;
        }
        if (*state).open_pack_count + (*state).opening_pack_count >= AMPR_EMU_PACK_OPEN_PACK_FD_CAP
        {
            let mut victim = INVALID_INDEX;
            let mut oldest = u64::MAX;
            for i in 0..pack_count {
                let c = &(*state).pack_handles[i as usize];
                if c.fd >= 0 && c.pins == 0 && !c.opening && c.last_use < oldest {
                    victim = i;
                    oldest = c.last_use;
                }
            }
            if victim == INVALID_INDEX {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            let evicted = &mut (*state).pack_handles[victim as usize];
            stats::add(stats::Stat::PackFdEvictions, 1);
            victim_fd = evicted.fd;
            *evicted = PackHandle {
                reopen: evicted.reopen.after_close(),
                ..PackHandle::EMPTY
            };
            if (*state).open_pack_count == 0 {
                abort();
            }
            (*state).open_pack_count -= 1;
        }
        (*state).pack_handles[id].opening = true;
        (*state).opening_pack_count += 1;
    }

    if victim_fd >= 0 {
        close_physical_pack_fd(victim_fd);
    }
    if !ampr_index_fd_cache_release_open_fd_budget_headroom(1) {
        let _lock = PACK_M.lock();
        if !(*state).pack_handles[id].opening || (*state).opening_pack_count == 0 {
            abort();
        }
        (*state).pack_handles[id].opening = false;
        (*state).opening_pack_count -= 1;
        return SCE_KERNEL_ERROR_EAGAIN;
    }
    let open_start = stats::now();
    let mut fd = open_fn(path.as_ptr(), SCE_KERNEL_O_RDONLY | O_NONBLOCK, 0 as c_int);
    stats::add(stats::Stat::PackFdOpens, 1);
    stats::add(stats::Stat::PackFdOpenNs, stats::since(open_start));
    // A signal is not fd pressure: retry the open a few times instead of parking.
    let mut eintr_retries = 0;
    while fd == -1 && errno() == EINTR && eintr_retries < 3 {
        fd = open_fn(path.as_ptr(), SCE_KERNEL_O_RDONLY | O_NONBLOCK, 0 as c_int);
        eintr_retries += 1;
    }
    // libc open/fstat return -1 with errno.
    let mut result = if fd == -1 {
        let err = errno();
        if posix_errno_is_fd_open_pressure(err) {
            let observed = ampr_index_fd_cache_stats()
                .open
                .saturating_add(ampr_index_fd_uncached_open_count());
            ampr_index_fd_cache_mark_open_pressure(observed);
            ampr_index_fd_cache_release_idle_percent(100);
            SCE_KERNEL_ERROR_EAGAIN
        } else {
            sce_errno_from_posix(err)
        }
    } else {
        fd
    };
    if fd >= 0 {
        ampr_index_fd_pack_note_open();
    }
    let mut stat: SceKernelStat = core::mem::zeroed();
    let stat_rc = if fd >= 0 {
        let rc = fstat_fn(fd, &mut stat);
        if rc == -1 {
            sce_errno_from_posix(errno())
        } else {
            rc
        }
    } else {
        fd
    };
    let mut payload_begin = 0u64;
    let mut payload_end = 0u64;
    if fd >= 0
        && (stat_rc != 0
            || stat.st_size < 0
            || !validate_data_header(
                state,
                pack_id,
                fd,
                stat.st_size as u64,
                &mut payload_begin,
                &mut payload_end,
            ))
    {
        close_physical_pack_fd(fd);
        fd = -1;
        result = if stat_rc != 0 {
            stat_rc
        } else {
            SCE_KERNEL_ERROR_EIO
        };
    }
    let wake_workers;
    {
        let _lock = PACK_M.lock();
        if !(*state).pack_handles[id].opening || (*state).opening_pack_count == 0 {
            abort();
        }
        (*state).pack_handles[id].opening = false;
        (*state).opening_pack_count -= 1;
        if fd >= 0 {
            let tick = (*state).tick;
            (*state).tick += 1;
            let handle = &mut (*state).pack_handles[id];
            handle.fd = fd;
            handle.pins = 1;
            handle.last_use = tick;
            handle.payload_begin = payload_begin;
            handle.payload_end = payload_end;
            (*state).open_pack_count += 1;
        }
        // Any finished attempt except a pressure EAGAIN releases `opening`: wake its waiters.
        if fd >= 0 || result != SCE_KERNEL_ERROR_EAGAIN {
            PACK_FD_PROGRESS_EPOCH.fetch_add(1, Ordering::Release);
        }
        wake_workers = wake_fd_waiters_locked(state);
    }
    if wake_workers {
        QUEUE_CV.notify_all();
    }
    result
}

#[cfg(test)]
mod pack_fd_tests {
    use super::*;

    #[test]
    fn stale_pack_fd_retries_once_per_burst() {
        use PackFdReopen::*;
        // Trigger errors: EBADF, EIO, ENXIO. Others never reopen.
        for e in [
            SCE_KERNEL_ERROR_EBADF,
            SCE_KERNEL_ERROR_EIO,
            SCE_KERNEL_ERROR_ENXIO,
        ] {
            assert!(pack_fd_error_wants_reopen(e));
        }
        for e in [
            0,
            SCE_KERNEL_ERROR_EAGAIN,
            SCE_KERNEL_ERROR_ENOMEM,
            SCE_KERNEL_ERROR_EINVAL,
        ] {
            assert!(!pack_fd_error_wants_reopen(e));
            assert_eq!(Clean.after_read(e), (e, Clean));
        }
        let ebadf = SCE_KERNEL_ERROR_EBADF;
        // First failure: retry; other reads still on the old fd retry too.
        assert_eq!(
            Clean.after_read(ebadf),
            (SCE_KERNEL_ERROR_EAGAIN, StaleRetry)
        );
        assert_eq!(
            StaleRetry.after_read(ebadf),
            (SCE_KERNEL_ERROR_EAGAIN, StaleRetry)
        );
        assert_eq!(StaleRetry.after_read(0), (0, StaleRetry));
        assert_eq!(StaleRetry.after_close(), Reopened);
        // Failure on the reopened fd goes to the game; the fd is still
        // replaced, so a device that comes back later recovers.
        assert_eq!(Reopened.after_read(ebadf), (ebadf, StaleReport));
        assert_eq!(
            StaleReport.after_read(SCE_KERNEL_ERROR_EIO),
            (SCE_KERNEL_ERROR_EIO, StaleReport)
        );
        assert_eq!(StaleReport.after_close(), Reopened);
        // Only a good read on a reopened fd re-arms the retry.
        assert_eq!(Reopened.after_read(0), (0, Clean));
        assert_eq!(Reopened.after_close(), Reopened);
        assert!(StaleRetry.is_stale() && StaleReport.is_stale());
        assert!(!Clean.is_stale() && !Reopened.is_stale());
    }
}
