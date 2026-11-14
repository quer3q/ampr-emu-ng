//! Save data hooks, for the system libSceSaveData the runtime does not
//! replace:
//!
//! - sceSaveDataMount3 is passed through unchanged, a SAVE_DATA_ERROR_BUSY
//!   answer included: a game retries a BUSY mount itself. Unmounting the
//!   game's other save points and mounting again took points a title was
//!   still using, and it hung on close (8 of 11 mounts BUSY, debug /metrics).
//!   The hook only counts mounts (`save_mounts`), BUSY answers (`save_busy`)
//!   and non-zero answers (`save_mount_errors`, the last one in
//!   `save_mount_last_error`).
//! - sceSaveDataSaveIconByPath is handed the icon bytes read from the pack
//!   through sceSaveDataSaveIcon instead of a path inside it. The save
//!   service runs outside the game's mount namespace, so it cannot open
//!   /app0/images/icon0.png when that file is packed; the game then never
//!   finishes saving. A loose path goes to the original call unchanged.
//!   The bytes are read by rt/pack/mmap.rs `read_packed` into transient
//!   memory from the pool's Index ledger (rt/index_memory.rs), not a fixed
//!   pool site.
//!
//! The hooks are installed by rt/hook.rs when a loaded module exports the
//! NID (13.00 libSceSaveData.native: sceSaveDataMount3 ZP4e7rlzOUk,
//! sceSaveDataSaveIcon c88Yy54Mx0w, sceSaveDataSaveIconByPath Z7z6HXWORJY).

use super::hook::{save_original, SAVE_ICON, SAVE_ICON_PATH, SAVE_MOUNT3};
use super::pack::mmap::read_packed;
use super::stats::{self, Stat};
use super::sys::SCE_KERNEL_ERROR_ENOSYS;
use core::ffi::{c_char, c_int, c_void};

// ---- save data ABI ----------------------------------------------------------

/// SCE_SAVE_DATA_ERROR_BUSY: the save is mounted or in use.
const SAVE_DATA_ERROR_BUSY: c_int = 0x809F_0003u32 as c_int;

/// `SceSaveDataIcon` as sceSaveDataSaveIcon reads it (live 13.00 native
/// disassembly: it copies 0x38 bytes, pointer @0, buffer size @8, data size
/// @0x10, 32 reserved bytes).
#[repr(C)]
pub(crate) struct SceSaveDataIcon {
    buf: *mut c_void,
    buf_size: usize,
    data_size: usize,
    reserved: [u8; 32],
}
const _: () = assert!(core::mem::size_of::<SceSaveDataIcon>() == 0x38);

type MountFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
type SaveIconFn = unsafe extern "C" fn(*const c_void, *const SceSaveDataIcon) -> c_int;
type SaveIconByPathFn = unsafe extern "C" fn(*const c_void, *const c_char) -> c_int;

// ---- mount ------------------------------------------------------------------

/// `sceSaveDataMount3`: the original's answer, unchanged. Counts the mount and
/// a BUSY answer.
pub unsafe extern "C" fn mount3_emul(mount: *const c_void, result: *mut c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<MountFn>(SAVE_MOUNT3) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    let rc = unsafe { orig(mount, result) };
    stats::add(Stat::SaveMounts, 1);
    if rc == SAVE_DATA_ERROR_BUSY {
        stats::add(Stat::SaveBusy, 1);
    }
    if rc != 0 {
        stats::add(Stat::SaveMountErrors, 1);
        stats::set(Stat::SaveMountLastError, rc as u32 as u64);
    }
    rc
}

// ---- save icon by path ------------------------------------------------------

/// Hands the decoded bytes of a packed icon to sceSaveDataSaveIcon; returns
/// its result and the byte count, None when that entry is not hooked. The
/// bytes come from rt/pack/mmap.rs `read_packed`: a transient buffer from the
/// pool's Index ledger sized by the file, never flexible memory, freed when
/// this returns.
unsafe fn save_icon_bytes(mount_point: *const c_void, bytes: &[u8]) -> Option<(c_int, usize)> {
    let save_icon = unsafe { save_original::<SaveIconFn>(SAVE_ICON) }?;
    let icon = SceSaveDataIcon {
        buf: bytes.as_ptr() as *mut c_void,
        buf_size: bytes.len(),
        data_size: bytes.len(),
        reserved: [0; 32],
    };
    let rc = unsafe { save_icon(mount_point, &icon) };
    stats::set(Stat::SaveIconLastResult, rc as u32 as u64);
    Some((rc, bytes.len()))
}

/// Passthrough: installed so `save_original` has the real SaveIcon entry the
/// runtime calls with a packed icon buffer.
pub unsafe extern "C" fn save_icon_emul(
    mount_point: *const c_void,
    icon: *const SceSaveDataIcon,
) -> c_int {
    let Some(orig) = (unsafe { save_original::<SaveIconFn>(SAVE_ICON) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    unsafe { orig(mount_point, icon) }
}

pub unsafe extern "C" fn save_icon_by_path_emul(
    mount_point: *const c_void,
    path: *const c_char,
) -> c_int {
    let Some(orig) = (unsafe { save_original::<SaveIconByPathFn>(SAVE_ICON_PATH) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    if mount_point.is_null() || path.is_null() {
        return unsafe { forward_icon_path(orig, mount_point, path) };
    }
    // None: a loose or missing file, which the save service opens itself.
    // A packed icon that cannot be read (empty, over READ_PACKED_MAX, no
    // buffer, a failed read) or handed over is skipped and the call answers
    // 0: the service cannot open a packed path (0x809f000e), and that error
    // stalled a title's save; the icon is cosmetic.
    let rc = match unsafe { read_packed(path, |bytes| save_icon_bytes(mount_point, bytes)) } {
        None => return unsafe { forward_icon_path(orig, mount_point, path) },
        Some(Ok(Some((0, size)))) => {
            stats::add(Stat::SaveIconBytes, size as u64);
            0
        }
        Some(Ok(Some((rc, _)))) => {
            stats::add(Stat::SaveIconSkipped, 1);
            unsafe { note_icon(path, rc) };
            return 0;
        }
        Some(Ok(None)) | Some(Err(())) => {
            stats::add(Stat::SaveIconSkipped, 1);
            0
        }
    };
    unsafe { note_icon(path, rc) };
    rc
}

/// The original sceSaveDataSaveIconByPath, its answer unchanged and kept in
/// `save_icon_path_last_result`.
unsafe fn forward_icon_path(
    orig: SaveIconByPathFn,
    mount_point: *const c_void,
    path: *const c_char,
) -> c_int {
    let rc = unsafe { orig(mount_point, path) };
    stats::set(Stat::SaveIconPathLastResult, rc as u32 as u64);
    rc
}

// ---- debug event text -------------------------------------------------------

/// The /fsfail line "save icon <path> rc=0x<8 hex>".
#[cfg(feature = "mem_report")]
unsafe fn note_icon(path: *const c_char, rc: c_int) {
    let mut buf = [0u8; 128];
    let mut n = 0;
    let mut push = |bytes: &[u8]| {
        for &b in bytes {
            if n + 1 >= buf.len() {
                return;
            }
            buf[n] = b;
            n += 1;
        }
    };
    push(b"save icon ");
    for i in 0..127 {
        let b = unsafe { *path.cast::<u8>().add(i) };
        if b == 0 {
            break;
        }
        push(&[b]);
    }
    push(b" rc=0x");
    let v = rc as u32;
    for i in (0..8).rev() {
        push(&[b"0123456789abcdef"[((v >> (i * 4)) & 0xf) as usize]]);
    }
    buf[n] = 0;
    stats::fs_note(b'V', b'-', rc as i64, buf.as_ptr().cast());
}

#[cfg(not(feature = "mem_report"))]
unsafe fn note_icon(_path: *const c_char, _rc: c_int) {}
