//! sceSaveDataSaveIconByPath, for the system libSceSaveData the runtime does
//! not replace. The save service runs outside the game's mount namespace and
//! opens the icon path itself, so a packed icon (no physical copy) fails
//! with 0x809f000e and the game never finishes saving. A packed icon's
//! decoded bytes go to sceSaveDataSaveIcon instead (`read_icon` below, in
//! game heap memory freed right after the call). A loose or missing icon
//! goes to the original call; a loose one it answers 0x809f000e for goes
//! as bytes too: in pkg mode the service cannot see the game's /app0, and
//! a title's every save failed on it (a reporter's debug /metrics:
//! pack_format pkg, save_icon_path_last_result 0x809f000e, no failed open
//! of the icon). That retry logs the service's answer, then the hook's.
//!
//! Removing the hook made a title's save fail again; handing the service a
//! path to a decoded copy under /data/ampr_cache hung that save inside the
//! service call (debug build on a console: the call never returned and the
//! pack runtime sat idle). The bytes path is the one shipped before.
//!
//! The hooks are installed by rt/hook.rs when a loaded module exports the
//! NID (13.00 libSceSaveData.native: sceSaveDataSaveIcon c88Yy54Mx0w,
//! sceSaveDataSaveIconByPath Z7z6HXWORJY). sceSaveDataSaveIcon passes
//! through; it is hooked only for its original entry.

use super::hook::{save_original, SAVE_ICON, SAVE_ICON_PATH, SAVE_MOUNT3};
use super::heap::{libc_free, libc_malloc};
use super::index::posix_open_emul;
use super::pack::{
    ampr_pack_try_pread_fd, posix_close_emul, posix_fstat_emul, virtual_fd_file_id, SceKernelStat,
};
use super::stats::{self, Stat};
use super::sys::{
    errno, off_t, real_physical_pread, real_posix_open, EMFILE, ENFILE, ENOENT, ENOMEM,
    SCE_KERNEL_ERROR_ENOSYS,
};
use core::ffi::{c_char, c_int, c_void};

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

/// The service's answer for an icon path it could not open: a packed icon,
/// and a loose one in pkg mode, where /app0 is the game's own mount.
const ICON_PATH_REFUSED: c_int = 0x809F_000Eu32 as c_int;

type SaveIconFn = unsafe extern "C" fn(*const c_void, *const SceSaveDataIcon) -> c_int;
type SaveIconByPathFn = unsafe extern "C" fn(*const c_void, *const c_char) -> c_int;

/// Passthrough: installed so `save_original` has the real SaveIcon entry.
pub unsafe extern "C" fn save_icon_emul(
    mount_point: *const c_void,
    icon: *const SceSaveDataIcon,
) -> c_int {
    let Some(orig) = (unsafe { save_original::<SaveIconFn>(SAVE_ICON) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    unsafe { orig(mount_point, icon) }
}

/// Hands `bytes` to the original sceSaveDataSaveIcon; None when that entry
/// is not hooked.
unsafe fn save_icon_bytes(mount_point: *const c_void, bytes: &[u8]) -> Option<c_int> {
    let save_icon = unsafe { save_original::<SaveIconFn>(SAVE_ICON) }?;
    let icon = SceSaveDataIcon {
        buf: bytes.as_ptr() as *mut c_void,
        buf_size: bytes.len(),
        data_size: bytes.len(),
        reserved: [0; 32],
    };
    let rc = unsafe { save_icon(mount_point, &icon) };
    stats::set(Stat::SaveIconLastResult, rc as u32 as u64);
    if rc == 0 {
        stats::add(Stat::SaveIconBytes, bytes.len() as u64);
    }
    Some(rc)
}

pub unsafe extern "C" fn save_icon_by_path_emul(
    mount_point: *const c_void,
    path: *const c_char,
) -> c_int {
    let Some(orig) = (unsafe { save_original::<SaveIconByPathFn>(SAVE_ICON_PATH) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    #[cfg(feature = "mem_report")]
    probe::note(b"SaveIconByPath", None);
    if mount_point.is_null() || path.is_null() {
        return unsafe { forward(orig, mount_point, path) };
    }
    // A packed icon that cannot be read (no game heap memory, a failed read) or
    // handed over is skipped and the call answers 0: an error answer
    // stalled a title's save, and the icon is cosmetic.
    let icon = |bytes: &[u8]| unsafe { save_icon_bytes(mount_point, bytes) };
    let read = match unsafe { read_icon(path, false, icon) } {
        // Loose or missing: the service opens it. A loose icon it cannot see
        // goes as bytes too; a missing one keeps the service's answer.
        None => {
            let rc = unsafe { forward(orig, mount_point, path) };
            if rc != ICON_PATH_REFUSED {
                return rc;
            }
            match unsafe { read_icon(path, true, icon) } {
                // Not opened, or no SaveIcon entry: the service's answer.
                None | Some(Ok(None)) => return rc,
                Some(read) => read,
            }
        }
        Some(read) => read,
    };
    let rc = match read {
        Ok(Some(rc)) => rc,
        Ok(None) | Err(()) => -1,
    };
    if rc != 0 {
        stats::add(Stat::SaveIconSkipped, 1);
    }
    unsafe { note_icon(path, rc) };
    #[cfg(feature = "mem_report")]
    probe::note(b"SaveIconByPath", Some(0));
    0
}

/// The original call, its answer unchanged and kept in
/// `save_icon_path_last_result`.
unsafe fn forward(orig: SaveIconByPathFn, mount_point: *const c_void, path: *const c_char) -> c_int {
    let rc = unsafe { orig(mount_point, path) };
    stats::set(Stat::SaveIconPathLastResult, rc as u32 as u64);
    #[cfg(feature = "mem_report")]
    probe::note(b"SaveIconByPath", Some(rc));
    rc
}

// ---- packed icon bytes --------------------------------------------------------

/// The save service opens the icon path itself, past the path hooks: when
/// `path` opens as a packed file (or as any file, with `loose`), `use_bytes`
/// gets its decoded bytes in a
/// buffer of its size from the game's libc heap, freed as soon as
/// `use_bytes` returns: the icon is held only for the one call, outside the
/// pool, at any size (a title's /app0/images/icon0.png is 551,096 B). A
/// failed malloc or read is Some(Err) and the caller skips the icon, as is
/// an open that failed for lack of fds or memory. None for a loose or
/// missing file, or another failed open. A path handed to the save service
/// instead (a decoded copy under /data/ampr_cache) hung a title's save
/// inside the service call.
unsafe fn read_icon<R>(
    path: *const c_char,
    loose: bool,
    use_bytes: impl FnOnce(&[u8]) -> R,
) -> Option<Result<R, ()>> {
    let mut vfd = unsafe { posix_open_emul(path, 0, 0) };
    // A loose icon the index does not list answers ENOENT without the disk
    // (pkg mode, a title's sce_sys/save_data.png: debug `fs o m`, every
    // save failed on M.2 only). The service already refused its path, so
    // the disk is asked directly.
    if vfd < 0 && loose && errno() == ENOENT {
        vfd = unsafe { real_posix_open(path, 0, 0) };
    }
    if vfd < 0 {
        // Out of fds or memory: the icon may be packed, where the service
        // cannot open it (0x809f000e there stalled a title's save), so it
        // is skipped. Any other failure (missing, refused) goes to the
        // service, which opens a loose icon itself and answers the rest.
        return matches!(errno(), EMFILE | ENFILE | ENOMEM).then_some(Err(()));
    }
    let out = if loose || unsafe { virtual_fd_file_id(vfd) }.is_some() {
        Some(unsafe { read_to_heap(vfd, use_bytes) })
    } else {
        None
    };
    unsafe { posix_close_emul(vfd) };
    out
}

/// The whole decoded file behind `vfd`, in game heap memory, to `use_bytes`.
unsafe fn read_to_heap<R>(vfd: c_int, use_bytes: impl FnOnce(&[u8]) -> R) -> Result<R, ()> {
    let mut st: SceKernelStat = unsafe { core::mem::zeroed() };
    if unsafe { posix_fstat_emul(vfd, &mut st) } != 0 {
        return Err(());
    }
    let len = usize::try_from(st.st_size).ok().filter(|&n| n > 0).ok_or(())?;
    let buf = unsafe { libc_malloc(len) };
    if buf.is_null() {
        return Err(());
    }
    let out = unsafe { read_into(vfd, buf, len, use_bytes) };
    unsafe { libc_free(buf) };
    out
}

unsafe fn read_into<R>(
    vfd: c_int,
    buf: *mut u8,
    len: usize,
    use_bytes: impl FnOnce(&[u8]) -> R,
) -> Result<R, ()> {
    let mut off = 0usize;
    let mut rc = Ok(());
    while off < len {
        let mut handled = false;
        let want = len - off;
        let dst = unsafe { buf.add(off) }.cast();
        let mut n = unsafe { ampr_pack_try_pread_fd(vfd, dst, want, off as off_t, &mut handled) };
        if !handled {
            n = unsafe { real_physical_pread(vfd, dst, want, off as off_t) };
        }
        if n <= 0 || n as usize > want {
            rc = Err(());
            break;
        }
        off += n as usize;
    }
    rc.map(|()| use_bytes(unsafe { core::slice::from_raw_parts(buf, len) }))
}

// ---- mount ------------------------------------------------------------------

// A creating sceSaveDataMount3 refused for its systemBlocks. The 13.x
// libSceSaveData.native checks a mount by the SDK version the title reports
// (dumped from a game process on a 13.x console: the check is chosen at
// module offset 0x1ecc0). Creating a save (mode & 0x24) needs blocks >= 48
// and systemBlocks 0 below SDK 5.00, 0 or -1 from 5.00, -1 or -2 from
// 12.00. A title backported to firmware 4.xx reports an SDK below 5.00, but
// its save code still passes the -1 (SCE_SAVE_DATA_SYSTEM_BLOCKS_EQUAL_TO_
// BLOCKS) of the SDK it was built with: a Unity title built with SDK 11 and
// backported to 4.00 read its saves, but every creating mount answered
// 0x809F0000 and it never saved. Such a mount is sent once more with
// systemBlocks 0, the only value that check takes. Every other mount, BUSY
// included, passes through (AGENTS.md "Removed": shared save mounts).

/// SCE_SAVE_DATA_ERROR_BUSY: the save is mounted or in use.
const SAVE_DATA_ERROR_BUSY: c_int = 0x809F_0003u32 as c_int;
/// SCE_SAVE_DATA_ERROR_PARAMETER: the library refused the request itself.
const SAVE_DATA_ERROR_PARAMETER: c_int = 0x809F_0000u32 as c_int;

/// `SceSaveDataMount3` as that library checks it: userId @0, dirName* @8,
/// blocks @0x10, systemBlocks @0x18, mountMode @0x20, reserved bytes up to
/// 0x4b, 0x50 with the alignment of its u64 fields.
const MOUNT3_BYTES: usize = 0x50;
const MOUNT3_SYSTEM_BLOCKS: usize = 0x18;
const MOUNT3_MODE: usize = 0x20;
/// SCE_SAVE_DATA_MOUNT_MODE_CREATE (4) and CREATE2 (0x20): the library
/// checks the sizes only when one of them is set.
const MOUNT_MODE_CREATE: u32 = 0x24;

/// A copy of a mount request, aligned for the library's u64 reads.
#[repr(C, align(8))]
struct Mount3Req([u8; MOUNT3_BYTES]);

/// `req` with systemBlocks 0, when it creates a save and asked for another
/// value; None otherwise (nothing to change).
fn system_blocks_zeroed(req: &[u8; MOUNT3_BYTES]) -> Option<[u8; MOUNT3_BYTES]> {
    let m = MOUNT3_MODE;
    let mode = u32::from_le_bytes([req[m], req[m + 1], req[m + 2], req[m + 3]]);
    let sb = MOUNT3_SYSTEM_BLOCKS..MOUNT3_SYSTEM_BLOCKS + 8;
    if mode & MOUNT_MODE_CREATE == 0 || req[sb.clone()].iter().all(|&b| b == 0) {
        return None;
    }
    let mut out = *req;
    out[sb].fill(0);
    Some(out)
}

/// Copies the game's request into `out` with systemBlocks 0; false when it
/// is not readable or there is nothing to change.
#[inline(never)]
unsafe fn zero_system_blocks(mount: *const c_void, out: &mut Mount3Req) -> bool {
    if !readable(mount as usize, MOUNT3_BYTES) {
        return false;
    }
    let mut req = [0u8; MOUNT3_BYTES];
    unsafe { core::ptr::copy_nonoverlapping(mount.cast::<u8>(), req.as_mut_ptr(), MOUNT3_BYTES) };
    match system_blocks_zeroed(&req) {
        Some(fixed) => {
            out.0 = fixed;
            true
        }
        None => false,
    }
}

type MountFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;

/// A plausible user pointer: nonzero page, below the user address top.
fn user_ptr(p: usize) -> bool {
    (0x1_0000..0x7fff_ffff_ffff).contains(&p)
}

/// `[p, p + len)` is mapped and CPU-readable, asked of
/// sceKernelQueryMemoryProtection, which answers an error for an unmapped
/// address where a plain read would fault in the game's call. False when
/// libkernel lacks the call: nothing is then read.
fn readable(p: usize, len: usize) -> bool {
    if !user_ptr(p) {
        return false;
    }
    if cfg!(test) {
        return true;
    }
    let Some(mapping) = super::sys::query_memory_mapping(p) else {
        return false;
    };
    mapping.rc == 0
        // CPU_RW is its own bit (0x02), not READ | WRITE: a game's writable
        // memory reports it alone.
        && mapping.prot & (super::sys::SCE_KERNEL_PROT_CPU_READ | super::sys::SCE_KERNEL_PROT_CPU_RW) != 0
        && mapping.start <= p
        && p.saturating_add(len) <= mapping.end_exclusive()
}

/// sceSaveDataMount3(mount, result).
pub unsafe extern "C" fn mount3_emul(mount: *const c_void, result: *mut c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<MountFn>(SAVE_MOUNT3) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    let mut rc = unsafe { orig(mount, result) };
    // A creating mount refused for its systemBlocks goes once more with
    // systemBlocks 0. Calls the library takes are never changed.
    let mut fixed = Mount3Req([0; MOUNT3_BYTES]);
    if rc == SAVE_DATA_ERROR_PARAMETER && unsafe { zero_system_blocks(mount, &mut fixed) } {
        rc = unsafe { orig(fixed.0.as_ptr().cast(), result) };
        stats::add(Stat::SaveSystemBlocksZeroed, 1);
        #[cfg(feature = "mem_report")]
        probe::note(b"Mount3 systemBlocks 0", Some(rc));
    }
    stats::add(Stat::SaveMounts, 1);
    if rc == SAVE_DATA_ERROR_BUSY {
        stats::add(Stat::SaveBusy, 1);
    }
    #[cfg(feature = "mem_report")]
    {
        // The request's words, only once the service took the struct.
        if rc == 0 || rc == SAVE_DATA_ERROR_BUSY {
            unsafe { probe::note_mount(mount as usize) };
        }
        probe::note(b"Mount3", Some(rc));
        if rc == 0 {
            unsafe { probe::note_text(b"Mount3 point ", result as usize, 16) };
        }
    }
    rc
}

// ---- debug event text -------------------------------------------------------

/// The /fsfail line "save icon <path> rc=0x<8 hex>" (-1: not read).
#[cfg(feature = "mem_report")]
#[inline(never)]
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

// ---- debug probes -----------------------------------------------------------

/// Debug only: pass-through probes on the save and dialog calls a title
/// imports, to find the call a save hangs in. Each logs "save <name> in"
/// on entry and "save <name> rc=0x<8 hex>" on return (/metrics `fs V`
/// lines and the black box), so a call that never returns shows as an `in`
/// with no answer. Every probed call takes at most 6 integer or pointer
/// arguments, all passed through in registers. The per-frame status polls
/// (sceSaveDataDialogUpdateStatus, sceMsgDialogUpdateStatus) are left out.
#[cfg(feature = "mem_report")]
pub(crate) mod probe {
    use super::super::hook::save_original;
    use super::super::stats;
    use super::super::sys::SCE_KERNEL_ERROR_ENOSYS;
    use core::ffi::c_int;

    type Raw6 = unsafe extern "C" fn(usize, usize, usize, usize, usize, usize) -> c_int;

    /// First save hook index of the probes (rt/hook.rs `SAVE_HOOKS`).
    pub(crate) const FIRST: usize = 3;

    macro_rules! probes {
        ($($f:ident $i:literal $name:literal;)*) => {$(
            pub unsafe extern "C" fn $f(
                a: usize, b: usize, c: usize, d: usize, e: usize, f: usize,
            ) -> c_int {
                unsafe { call(FIRST + $i, $name, [a, b, c, d, e, f]) }
            }
        )*};
    }
    probes! {
        initialize3 0 b"Initialize3";
        commit 1 b"Commit";
        prepare 2 b"Prepare";
        set_param 3 b"SetParam";
        delete 4 b"Delete";
        dir_name_search 5 b"DirNameSearch";
        create_transaction 6 b"CreateTransactionResource";
        delete_transaction 7 b"DeleteTransactionResource";
        dialog_initialize 8 b"DialogInitialize";
        dialog_open 9 b"DialogOpen";
        dialog_terminate 10 b"DialogTerminate";
        msg_dialog_open 11 b"MsgDialogOpen";
        msg_dialog_terminate 12 b"MsgDialogTerminate";
    }
    /// The Umount2 probe, after the macro's: the last SAVE_HOOKS entry.
    const UMOUNT2: usize = 13;
    pub(crate) const COUNT: usize = UMOUNT2 + 1;

    /// sceSaveDataUmount2(mode, mountPoint): "save Umount2 point <point>",
    /// so a point mounted more often than unmounted shows on /fsfail.
    pub unsafe extern "C" fn umount2(
        a: usize, b: usize, c: usize, d: usize, e: usize, f: usize,
    ) -> c_int {
        unsafe { note_text(b"Umount2 point ", b, 16) };
        unsafe { call(FIRST + UMOUNT2, b"Umount2", [a, b, c, d, e, f]) }
    }

    use super::user_ptr;

    /// The first 5 words of the mount struct as hex (the mode is the low
    /// half of the 5th), and the directory
    /// name its second word points to in the PS4 Mount2 layout (userId,
    /// pad, dirName*), read only when that word is a plausible pointer.
    #[inline(never)]
    pub(crate) unsafe fn note_mount(m: usize) {
        if !super::readable(m, 40) {
            return;
        }
        let mut buf = [0u8; 112];
        let mut n = 0;
        let mut push = |bytes: &[u8]| {
            for &x in bytes {
                if n + 1 < buf.len() {
                    buf[n] = x;
                    n += 1;
                }
            }
        };
        push(b"save Mount3 arg");
        for i in 0..5 {
            let w = unsafe { core::ptr::read_unaligned((m as *const u64).add(i)) };
            push(b" ");
            for k in (0..16).rev() {
                push(&[b"0123456789abcdef"[((w >> (k * 4)) & 0xf) as usize]]);
            }
        }
        buf[n] = 0;
        stats::fs_note(b'V', b'-', 0, buf.as_ptr().cast());
        let dir = unsafe { core::ptr::read_unaligned((m as *const usize).add(1)) };
        if user_ptr(dir) {
            unsafe { note_text(b"Mount3 dir ", dir, 32) };
        }
    }

    /// "save <label><text>", `text` read from `p` up to `max` bytes or NUL,
    /// non-printable bytes as '.'.
    #[inline(never)]
    pub(crate) unsafe fn note_text(label: &[u8], p: usize, max: usize) {
        if !super::readable(p, max) {
            return;
        }
        let mut buf = [0u8; 80];
        let mut n = 0;
        for &x in b"save ".iter().chain(label) {
            buf[n] = x;
            n += 1;
        }
        for i in 0..max {
            let x = unsafe { *(p as *const u8).add(i) };
            if x == 0 || n + 1 >= buf.len() {
                break;
            }
            buf[n] = if (0x20..0x7f).contains(&x) { x } else { b'.' };
            n += 1;
        }
        buf[n] = 0;
        stats::fs_note(b'V', b'-', 0, buf.as_ptr().cast());
    }

    #[inline(never)]
    unsafe fn call(i: usize, name: &[u8], a: [usize; 6]) -> c_int {
        let Some(orig) = (unsafe { save_original::<Raw6>(i) }) else {
            return SCE_KERNEL_ERROR_ENOSYS;
        };
        note(name, None);
        let rc = unsafe { orig(a[0], a[1], a[2], a[3], a[4], a[5]) };
        note(name, Some(rc));
        rc
    }

    /// "save <name> in", or "save <name> rc=0x<8 hex>".
    #[inline(never)]
    pub(crate) fn note(name: &[u8], rc: Option<c_int>) {
        let mut buf = [0u8; 64];
        let mut n = 0;
        let mut push = |bytes: &[u8]| {
            for &b in bytes {
                if n + 1 < buf.len() {
                    buf[n] = b;
                    n += 1;
                }
            }
        };
        push(b"save ");
        push(name);
        match rc {
            None => push(b" in"),
            Some(rc) => {
                push(b" rc=0x");
                let v = rc as u32;
                for i in (0..8).rev() {
                    push(&[b"0123456789abcdef"[((v >> (i * 4)) & 0xf) as usize]]);
                }
            }
        }
        buf[n] = 0;
        stats::fs_note(b'V', b'-', rc.unwrap_or(0) as i64, buf.as_ptr().cast());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request in the 13.x layout: user 1, a dirName pointer word, 0x300
    /// blocks, the given systemBlocks and mode, a transaction resource id
    /// as a backported title created them, reserved bytes zero.
    fn mount3(system_blocks: i64, mode: u32) -> [u8; MOUNT3_BYTES] {
        let mut r = [0u8; MOUNT3_BYTES];
        r[0..4].copy_from_slice(&1u32.to_le_bytes());
        r[8..16].copy_from_slice(&0x1234_5678u64.to_le_bytes());
        r[0x10..0x18].copy_from_slice(&0x300u64.to_le_bytes());
        r[0x18..0x20].copy_from_slice(&system_blocks.to_le_bytes());
        r[0x20..0x24].copy_from_slice(&mode.to_le_bytes());
        r[0x24..0x28].copy_from_slice(&0xe401u32.to_le_bytes());
        r
    }

    #[test]
    fn a_creating_mount_gets_system_blocks_zero() {
        for (sb, mode) in [(-1i64, 0x20u32), (-1, 0x04), (-2, 0x24), (96, 0x20)] {
            let req = mount3(sb, mode);
            let fixed = system_blocks_zeroed(&req).unwrap();
            assert_eq!(fixed[0x18..0x20], [0; 8]);
            // Every other byte is the game's.
            assert_eq!(fixed[..0x18], req[..0x18]);
            assert_eq!(fixed[0x20..], req[0x20..]);
        }
        // Nothing to change: a mount that does not create, or systemBlocks 0.
        assert!(system_blocks_zeroed(&mount3(-1, 0x01)).is_none());
        assert!(system_blocks_zeroed(&mount3(-1, 0x02)).is_none());
        assert!(system_blocks_zeroed(&mount3(0, 0x20)).is_none());
    }

    #[test]
    fn zero_system_blocks_leaves_the_game_request_alone() {
        let req = Box::new(mount3(-1, 0x20));
        let mut out = Mount3Req([0xaa; MOUNT3_BYTES]);
        assert!(unsafe { zero_system_blocks(req.as_ptr().cast(), &mut out) });
        assert_eq!(out.0[0x18..0x20], [0; 8]);
        assert_eq!(out.0[0x20..], req[0x20..]);
        assert_eq!(req[0x18..0x20], (-1i64).to_le_bytes());
        // A read mount, or no struct: nothing copied, false.
        let ro = Box::new(mount3(-1, 0x01));
        let mut untouched = Mount3Req([0xaa; MOUNT3_BYTES]);
        assert!(!unsafe { zero_system_blocks(ro.as_ptr().cast(), &mut untouched) });
        assert!(!unsafe { zero_system_blocks(core::ptr::null(), &mut untouched) });
        assert!(untouched.0.iter().all(|&b| b == 0xaa));
    }
}
