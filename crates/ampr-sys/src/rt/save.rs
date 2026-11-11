//! Save data fixes, for the system libSceSaveData the runtime does not
//! replace:
//!
//! - A mount refused with SAVE_DATA_ERROR_BUSY is retried once after
//!   unmounting every save point the service returned earlier and the game
//!   left mounted. A title that reads its save slots at start keeps several
//!   points mounted (/savedata0, /savedata1, /savedata2); starting a new game
//!   over one of them mounts it again and the old points made that fail, so
//!   the game sat on the loading screen. A failed Mount3 does not write a
//!   result point, hence the list of points from earlier successful mounts.
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
//! sceSaveDataUmount2 uW4vfTwMQVo, sceSaveDataSaveIcon c88Yy54Mx0w,
//! sceSaveDataSaveIconByPath Z7z6HXWORJY).

use super::hook::{save_original, SAVE_ICON, SAVE_ICON_PATH, SAVE_MOUNT3, SAVE_UMOUNT2};
use super::pack::mmap::read_packed;
use super::stats::{self, Stat};
use super::sync::{SpinLock, SyncCell};
use super::sys::SCE_KERNEL_ERROR_ENOSYS;
use core::ffi::{c_char, c_int, c_void};

// ---- save data ABI ----------------------------------------------------------

/// SCE_SAVE_DATA_ERROR_BUSY: the save is mounted or in use.
const SAVE_DATA_ERROR_BUSY: c_int = 0x809F_0003u32 as c_int;
/// SCE_SAVE_DATA_ERROR_NOT_MOUNTED: that point is already gone.
const SAVE_DATA_ERROR_NOT_MOUNTED: c_int = 0x809F_0004u32 as c_int;

/// `SceSaveDataMountPoint`: char[16], e.g. "/savedata2".
const POINT_BYTES: usize = 16;
const fn default_point() -> [u8; POINT_BYTES] {
    let mut p = [0u8; POINT_BYTES];
    let name = b"/savedata0";
    let mut i = 0;
    while i < name.len() {
        p[i] = name[i];
        i += 1;
    }
    p
}

/// One save point the service returned. A game can hold several at once for
/// different save dirs, and a BUSY mount may be blocked by any of them.
const MAX_SAVE_MOUNTS: usize = 8;
#[derive(Clone, Copy)]
struct SavePoint {
    used: bool,
    point: [u8; POINT_BYTES],
}
const SAVE_POINT0: SavePoint = SavePoint {
    used: false,
    point: [0; POINT_BYTES],
};

struct SaveState {
    /// Last point the service answered, used when no point is recorded.
    last: [u8; POINT_BYTES],
    points: [SavePoint; MAX_SAVE_MOUNTS],
}
static SAVE_STATE: SyncCell<SaveState> = SyncCell::new(SaveState {
    last: default_point(),
    points: [SAVE_POINT0; MAX_SAVE_MOUNTS],
});
static SAVE_LOCK: SpinLock = SpinLock::new();

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
type Umount2Fn = unsafe extern "C" fn(u32, *const c_void) -> c_int;
type SaveIconFn = unsafe extern "C" fn(*const c_void, *const SceSaveDataIcon) -> c_int;
type SaveIconByPathFn = unsafe extern "C" fn(*const c_void, *const c_char) -> c_int;

// ---- mount busy retry -------------------------------------------------------

unsafe fn mount_common(mount: *const c_void, result: *mut c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<MountFn>(SAVE_MOUNT3) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    let mut rc = unsafe { orig(mount, result) };
    stats::add(Stat::SaveMounts, 1);
    if rc == SAVE_DATA_ERROR_BUSY {
        if let Some(retry) = unsafe { retry_busy_mount(mount, result) } {
            rc = retry;
        }
    }
    if rc == 0 {
        unsafe { remember_mount(result) };
    }
    rc
}

/// BUSY can be held by any save point the game mounted earlier. Unmount every
/// point the service returned, then mount once more.
unsafe fn retry_busy_mount(mount: *const c_void, result: *mut c_void) -> Option<c_int> {
    let mut points = [[0u8; POINT_BYTES]; MAX_SAVE_MOUNTS];
    let mut gone = [false; MAX_SAVE_MOUNTS];
    let mut n = 0usize;
    {
        let _g = SAVE_LOCK.lock();
        let st = unsafe { &*SAVE_STATE.get() };
        for p in st.points.iter() {
            if p.used {
                points[n] = p.point;
                n += 1;
            }
        }
        if n == 0 {
            points[0] = st.last;
            n = 1;
        }
    }
    stats::add(Stat::SaveBusyRetries, 1);
    if let Some(umount) = unsafe { save_original::<Umount2Fn>(SAVE_UMOUNT2) } {
        for (i, point) in points[..n].iter().enumerate() {
            let rc = unsafe { umount(0, point.as_ptr().cast()) };
            if rc == 0 {
                stats::add(Stat::SaveUmountsAnswered, 1);
            }
            gone[i] = rc == 0 || rc == SAVE_DATA_ERROR_NOT_MOUNTED;
        }
        // Give an in-flight save operation a moment to finish first.
        unsafe { super::sys::sceKernelUsleep(20_000) };
    }
    {
        let _g = SAVE_LOCK.lock();
        let st = unsafe { &mut *SAVE_STATE.get() };
        for (i, point) in points[..n].iter().enumerate() {
            if gone[i] {
                if let Some(entry) = st.points.iter_mut().find(|e| e.used && e.point == *point) {
                    entry.used = false;
                }
            }
        }
    }
    let Some(orig) = (unsafe { save_original::<MountFn>(SAVE_MOUNT3) }) else {
        return None;
    };
    let rc = unsafe { orig(mount, result) };
    if rc == 0 {
        stats::add(Stat::SaveBusyRetriesOk, 1);
    }
    Some(rc)
}

unsafe fn remember_mount(result: *mut c_void) {
    if result.is_null() {
        return;
    }
    let mut point = [0u8; POINT_BYTES];
    for (i, b) in point.iter_mut().enumerate() {
        *b = unsafe { *(result as *const u8).add(i) };
    }
    let _g = SAVE_LOCK.lock();
    let st = unsafe { &mut *SAVE_STATE.get() };
    st.last = point;
    if st.points.iter().any(|p| p.used && p.point == point) {
        return;
    }
    if let Some(free) = st.points.iter_mut().find(|p| !p.used) {
        free.used = true;
        free.point = point;
    }
}

pub unsafe extern "C" fn mount3_emul(mount: *const c_void, result: *mut c_void) -> c_int {
    unsafe { mount_common(mount, result) }
}

/// `sceSaveDataUmount2(uint32_t flags, const SceSaveDataMountPoint*)`: a
/// successful unmount drops that point, so a later BUSY does not try it again.
pub unsafe extern "C" fn umount2_emul(flags: u32, point: *const c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<Umount2Fn>(SAVE_UMOUNT2) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    let rc = unsafe { orig(flags, point) };
    if rc == 0 && !point.is_null() {
        let mut p = [0u8; POINT_BYTES];
        for (i, b) in p.iter_mut().enumerate() {
            *b = unsafe { *(point as *const u8).add(i) };
        }
        let _g = SAVE_LOCK.lock();
        let st = unsafe { &mut *SAVE_STATE.get() };
        if let Some(entry) = st.points.iter_mut().find(|e| e.used && e.point == p) {
            entry.used = false;
        }
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
    Some((unsafe { save_icon(mount_point, &icon) }, bytes.len()))
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
        return unsafe { orig(mount_point, path) };
    }
    // None: a loose or missing file, which the save service opens itself.
    // A packed icon that cannot be read (empty, over READ_PACKED_MAX, no
    // buffer, a failed read) or handed over is skipped and the call answers
    // 0: the service cannot open a packed path (0x809f000e), and that error
    // stalled a title's save; the icon is cosmetic.
    let rc = match unsafe { read_packed(path, |bytes| save_icon_bytes(mount_point, bytes)) } {
        None => return unsafe { orig(mount_point, path) },
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

// ---- debug event text -------------------------------------------------------

/// "/fsfail: save icon <path> rc=0x<8 hex>", as the shared build showed it.
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

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fallback_mount_point_has_a_terminator() {
        let p = default_point();
        assert_eq!(&p[..10], b"/savedata0");
        assert_eq!(p[10], 0);
    }

    #[test]
    fn the_icon_descriptor_matches_the_firmware_abi() {
        // sceSaveDataSaveIcon copies 0x38 bytes of this struct.
        assert_eq!(core::mem::size_of::<SceSaveDataIcon>(), 0x38);
    }
}
