//! sceSaveDataSaveIconByPath, for the system libSceSaveData the runtime does
//! not replace. The save service runs outside the game's mount namespace and
//! opens the icon path itself, so a packed icon (no physical copy) fails
//! with 0x809f000e and the game never finishes saving. A packed icon's
//! decoded bytes go to sceSaveDataSaveIcon instead (`read_packed` below, in
//! game heap memory freed right after the call). A loose or
//! missing icon goes to the original call unchanged.
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

use super::hook::{save_original, SAVE_ICON, SAVE_ICON_PATH, SAVE_MOUNT3, SAVE_UMOUNT2};
use super::heap::{libc_free, libc_malloc};
use super::index::posix_open_emul;
use super::pack::{
    ampr_pack_try_pread_fd, posix_close_emul, posix_fstat_emul, virtual_fd_file_id, SceKernelStat,
};
use super::stats::{self, Stat};
use super::sync::{SpinLock, SyncCell};
use super::sys::{errno, off_t, EMFILE, ENFILE, ENOMEM, SCE_KERNEL_ERROR_ENOSYS};
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
    let rc = match unsafe { read_packed(path, |bytes| save_icon_bytes(mount_point, bytes)) } {
        None => return unsafe { forward(orig, mount_point, path) },
        Some(Ok(Some(rc))) => rc,
        Some(Ok(None)) | Some(Err(())) => -1,
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
/// `path` opens as a packed file, `use_bytes` gets its decoded bytes in a
/// buffer of its size from the game's libc heap, freed as soon as
/// `use_bytes` returns: the icon is held only for the one call, outside the
/// pool, at any size (a title's /app0/images/icon0.png is 551,096 B). A
/// failed malloc or read is Some(Err) and the caller skips the icon, as is
/// an open that failed for lack of fds or memory. None for a loose or
/// missing file, or another failed open. A path handed to the save service
/// instead (a decoded copy under /data/ampr_cache) hung a title's save
/// inside the service call.
unsafe fn read_packed<R>(
    path: *const c_char,
    use_bytes: impl FnOnce(&[u8]) -> R,
) -> Option<Result<R, ()>> {
    let vfd = unsafe { posix_open_emul(path, 0, 0) };
    if vfd < 0 {
        // Out of fds or memory: the icon may be packed, where the service
        // cannot open it (0x809f000e there stalled a title's save), so it
        // is skipped. Any other failure (missing, refused) goes to the
        // service, which opens a loose icon itself and answers the rest.
        return matches!(errno(), EMFILE | ENFILE | ENOMEM).then_some(Err(()));
    }
    let out = if unsafe { virtual_fd_file_id(vfd) }.is_some() {
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
        let n = unsafe {
            ampr_pack_try_pread_fd(vfd, buf.add(off).cast(), want, off as off_t, &mut handled)
        };
        if n <= 0 || n as usize > want {
            rc = Err(());
            break;
        }
        off += n as usize;
    }
    rc.map(|()| use_bytes(unsafe { core::slice::from_raw_parts(buf, len) }))
}

// ---- shared mounts ------------------------------------------------------------

// A title can mount a save directory it already has mounted: one kept
// `slot2` at /savedata0, read its other slots through /savedata1, then
// mounted `slot2` again. The service answers SAVE_DATA_ERROR_BUSY, the game
// never retries, and it sits on the loading screen (debug probes on a
// console). The runtime once unmounted every point the game held and
// mounted again; a title that still used one of them hung on close, so
// BUSY was passed back, and the first title hung again. Here such a BUSY mount is answered with the point the directory
// already has, and that point counts one more owner: an unmount of a point
// with more than one owner is answered 0 without unmounting, so no point a
// title holds ever goes away under it. A BUSY mount of a directory this
// title has not mounted is passed back unchanged.
// Shared only for the same user, directory name and request words 2-3.
// Those words are the mode only if PS5 Mount3 keeps the PS4
// Mount2 layout; a full check needs
// the PS5 SceSaveDataMount3 layout (debug /metrics logs both mounts' words).

/// SCE_SAVE_DATA_ERROR_BUSY: the save is mounted or in use.
const SAVE_DATA_ERROR_BUSY: c_int = 0x809F_0003u32 as c_int;
/// SCE_SAVE_DATA_ERROR_NOT_MOUNTED: that point is already gone.
const SAVE_DATA_ERROR_NOT_MOUNTED: c_int = 0x809F_0004u32 as c_int;
/// `SceSaveDataDirName`, char[32].
const DIR_BYTES: usize = 32;
/// `SceSaveDataMountPoint`, char[16], e.g. "/savedata0".
const POINT_BYTES: usize = 16;
/// The head of `SceSaveDataMountResult` handed to a second owner: the
/// mount point, the required blocks, and the status words (PS4 layout).
const RESULT_BYTES: usize = 32;
/// A BUSY mount with nothing to share is tried again this many times,
/// BUSY_WAIT_US apart (50 ms in all): the races it covers last one service
/// call. A longer retry (1 s) did not help a mount the game itself held.
const BUSY_RETRIES: u32 = 10;
const BUSY_WAIT_US: u32 = 5_000;
/// Points held at once: /savedata0 to /savedata15.
const MOUNTS: usize = 16;

#[derive(Clone, Copy)]
struct Mounted {
    owners: u32,
    /// Which mount this is: an unmount acts only on the mount it saw, never
    /// on a later mount at the same point.
    gen: u64,
    /// Last-owner unmounts of this mount in the service: not shared while
    /// any is, or a new owner could get a point that is about to go.
    unmounting: u32,
    user: u32,
    dir: [u8; DIR_BYTES],
    /// Words 2 and 3 of the request (blocks and mode in the PS4 Mount2
    /// layout): a BUSY request is shared only when they match, so a mount
    /// asked with another mode does not get this one's point.
    req: [u64; 2],
    /// The point up to its NUL, zero after: the service reads it as a C
    /// string, so the bytes past the NUL of a game's copy do not count.
    point: [u8; POINT_BYTES],
    result: [u8; RESULT_BYTES],
    /// Pass-through unmounts of this point still in the service when the
    /// mount was recorded. Counted in `unmounting`, so not shared until all
    /// have answered: a success drops the entry, a failure counts one
    /// down. No later one can pass through while the entry holds the point
    /// (umount2_emul finds it).
    pending: u32,
}
const MOUNTED0: Mounted = Mounted {
    owners: 0,
    gen: 0,
    unmounting: 0,
    user: 0,
    dir: [0; DIR_BYTES],
    req: [0; 2],
    point: [0; POINT_BYTES],
    result: [0; RESULT_BYTES],
    pending: 0,
};
static MOUNTED: SyncCell<[Mounted; MOUNTS]> = SyncCell::new([MOUNTED0; MOUNTS]);
static MOUNT_LOCK: SpinLock = SpinLock::new();
/// The last `gen` handed out, under MOUNT_LOCK.
static MOUNT_GEN: SyncCell<u64> = SyncCell::new(0);

/// Unmounts that passed through with no table entry, newest last, under
/// MOUNT_LOCK. A mount is recorded only after its service call returns, so
/// another thread can unmount that point in between; `remember` then must
/// not record a point the service already removed, or a later BUSY mount
/// would be answered with it. Each entry is (sequence number, point, state):
/// logged before the service call as in flight, then marked done on
/// success or dropped on failure, so a failed unmount never hides a live
/// mount.
const PASSED: usize = 16;
static PASSED_UMOUNTS: SyncCell<[(u64, [u8; POINT_BYTES], Passed); PASSED]> =
    SyncCell::new([(0, [0; POINT_BYTES], Passed::Failed); PASSED]);

#[derive(Clone, Copy, PartialEq)]
enum Passed {
    InFlight,
    Done,
    Failed,
}
/// Sequence number of the last pass-through unmount, under MOUNT_LOCK.
static PASSED_SEQ: SyncCell<u64> = SyncCell::new(0);

/// The pass-through unmount sequence now: taken right before each service
/// mount call and handed to `remember`.
fn passed_seq() -> u64 {
    let _g = MOUNT_LOCK.lock();
    unsafe { *PASSED_SEQ.get() }
}

/// Logs a pass-through unmount of `point` as in flight, before its service
/// call, so a mount that races it sees it in `remember`; returns its
/// sequence for `passed_umount_done`. Caller holds MOUNT_LOCK.
unsafe fn note_passed_umount(point: [u8; POINT_BYTES]) -> u64 {
    let seq = unsafe { &mut *PASSED_SEQ.get() };
    *seq += 1;
    let ring = unsafe { &mut *PASSED_UMOUNTS.get() };
    ring[(*seq % PASSED as u64) as usize] = (*seq, point, Passed::InFlight);
    *seq
}

/// The service answered pass-through unmount `seq` of `point`: on success
/// the point is gone, so a mount recorded while it was in flight is
/// dropped; on failure the log entry goes and such a mount waits for one
/// answer less. Caller holds MOUNT_LOCK.
unsafe fn passed_umount_done(seq: u64, point: &[u8; POINT_BYTES], gone: bool) {
    let ring = unsafe { &mut *PASSED_UMOUNTS.get() };
    let e = &mut ring[(seq % PASSED as u64) as usize];
    if e.0 == seq {
        e.2 = if gone { Passed::Done } else { Passed::Failed };
    }
    for m in unsafe { &mut *MOUNTED.get() }.iter_mut() {
        if m.owners != 0 && m.pending != 0 && m.point == *point {
            if gone {
                *m = MOUNTED0;
            } else {
                m.pending -= 1;
                m.unmounting -= 1;
            }
        }
    }
}

/// What the pass-through unmounts of `point` mean for a mount whose call
/// started at sequence `since` and is recorded now: None when one that
/// started since removed the point (or more than PASSED started, so the
/// ring no longer shows them all and the mount is not recorded, as when
/// the table is full), else how many are still in the service, whenever
/// they started. Caller holds MOUNT_LOCK.
unsafe fn umount_since(since: u64, point: &[u8; POINT_BYTES]) -> Option<u32> {
    let now = unsafe { *PASSED_SEQ.get() };
    if now - since > PASSED as u64 {
        return None;
    }
    let ring = unsafe { &*PASSED_UMOUNTS.get() };
    let mut in_flight = 0;
    for (seq, p, state) in ring.iter() {
        if p == point {
            match state {
                Passed::Done if *seq > since => return None,
                Passed::InFlight => in_flight += 1,
                _ => {}
            }
        }
    }
    Some(in_flight)
}

type MountFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
type Umount2Fn = unsafe extern "C" fn(u32, *const c_void) -> c_int;

/// A plausible user pointer: nonzero page, below the user address top.
fn user_ptr(p: usize) -> bool {
    (0x1_0000..0x7fff_ffff_ffff).contains(&p)
}

/// `[p, p + len)` is mapped and CPU-readable, asked of
/// sceKernelQueryMemoryProtection, which answers an error for an unmapped
/// address where a plain read would fault in the game's call. False when
/// libkernel lacks the call: nothing is then read, and nothing is shared.
/// The PS5 Mount3 layout these reads assume is checked on one title only.
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

/// Up to `N` bytes of the C string at `p`, zero after its NUL.
unsafe fn c_name<const N: usize>(p: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = unsafe { *p.add(i) };
        if *b == 0 {
            break;
        }
    }
    out
}

/// The user id and directory name of a mount struct, as in the PS4
/// SceSaveDataMount2 layout (userId, pad, dirName*), which the debug probes
/// read as "slot2" on a console. Read only after the service took the
/// struct (it answered 0 or BUSY), so a pointer it refused is never read
/// here. None when the name pointer is not plausible or names nothing.
unsafe fn mount_dir(mount: *const c_void) -> Option<(u32, [u8; DIR_BYTES], [u64; 2])> {
    if !readable(mount as usize, 32) {
        return None;
    }
    let user = unsafe { core::ptr::read_unaligned(mount as *const u32) };
    let p = unsafe { core::ptr::read_unaligned((mount as *const usize).add(1)) };
    if !readable(p, DIR_BYTES) {
        return None;
    }
    let dir = unsafe { c_name::<DIR_BYTES>(p as *const u8) };
    let w = mount as *const u64;
    let req = unsafe { [core::ptr::read_unaligned(w.add(2)), core::ptr::read_unaligned(w.add(3))] };
    (dir[0] != 0).then_some((user, dir, req))
}

/// sceSaveDataMount3(mount, result).
pub unsafe extern "C" fn mount3_emul(mount: *const c_void, result: *mut c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<MountFn>(SAVE_MOUNT3) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    let mut since = passed_seq();
    let mut rc = unsafe { orig(mount, result) };
    // Debug: the request's words, only once the service took the struct
    // (0 or BUSY), as the release path reads it.
    #[cfg(feature = "mem_report")]
    if rc == 0 || rc == SAVE_DATA_ERROR_BUSY {
        unsafe { probe::note_mount(mount as usize) };
    }
    stats::add(Stat::SaveMounts, 1);
    if rc == SAVE_DATA_ERROR_BUSY {
        stats::add(Stat::SaveBusy, 1);
    }
    if (rc == 0 || rc == SAVE_DATA_ERROR_BUSY) && !result.is_null() {
        if let Some((user, dir, req)) = unsafe { mount_dir(mount) } {
            // A BUSY with nothing to share yet may be another thread's mount
            // of this directory not recorded yet, or an unmount of it still
            // in the service: wait for either and look again, then mount
            // again (the directory may be free now). A mount the game holds
            // is shared on the first look, so only these races wait.
            let mut tries = 0;
            let mut shared = false;
            while rc == SAVE_DATA_ERROR_BUSY {
                if unsafe { share(user, &dir, req, result) } {
                    stats::add(Stat::SaveMountsShared, 1);
                    rc = 0;
                    shared = true;
                    break;
                }
                if tries == BUSY_RETRIES {
                    break;
                }
                tries += 1;
                unsafe { super::sys::sceKernelUsleep(BUSY_WAIT_US) };
                since = passed_seq();
                rc = unsafe { orig(mount, result) };
            }
            if rc == 0 && !shared {
                unsafe { remember(user, dir, req, result, since) };
            }
        }
    }
    #[cfg(feature = "mem_report")]
    {
        probe::note(b"Mount3", Some(rc));
        if rc == 0 {
            unsafe { probe::note_text(b"Mount3 point ", result as usize, POINT_BYTES) };
        }
    }
    rc
}

/// A new mount of `dir`: its point gets one owner, replacing any entry for
/// the same point (one the service gave back without an unmount seen). With
/// 16 entries for 16 points the table fills only if unmounts were missed;
/// a mount it cannot record is then not shared, as before. Not recorded
/// either when an unmount of that point passed through since `since`
/// (`passed_seq` before the service mount): the point may already be gone.
/// Other entries of the same user and directory go: the service mounts a
/// directory once (a second mount is BUSY), so a new mount means the old one
/// was unmounted by a call this runtime does not hook, and `share`, which
/// takes the first match, must not hand out its point.
unsafe fn remember(
    user: u32,
    dir: [u8; DIR_BYTES],
    req: [u64; 2],
    result: *const c_void,
    since: u64,
) {
    let mut res = [0u8; RESULT_BYTES];
    unsafe { core::ptr::copy_nonoverlapping(result.cast::<u8>(), res.as_mut_ptr(), RESULT_BYTES) };
    let point = unsafe { c_name::<POINT_BYTES>(res.as_ptr()) };
    let _g = MOUNT_LOCK.lock();
    // None: the point is gone; else the unmounts of it still in flight.
    let Some(pending) = (unsafe { umount_since(since, &point) }) else {
        return;
    };
    let t = unsafe { &mut *MOUNTED.get() };
    for m in t.iter_mut() {
        if m.owners != 0 && m.user == user && m.dir == dir && m.point != point {
            *m = MOUNTED0;
        }
    }
    let slot = t
        .iter()
        .position(|m| m.owners != 0 && m.point == point)
        .or_else(|| t.iter().position(|m| m.owners == 0));
    if let Some(i) = slot {
        let gen = unsafe { &mut *MOUNT_GEN.get() };
        *gen = gen.wrapping_add(1);
        t[i] = Mounted {
            owners: 1,
            gen: *gen,
            unmounting: pending,
            user,
            dir,
            req,
            point,
            result: res,
            pending,
        };
    }
}

/// A BUSY mount of `dir` by `user`: when this title holds that directory,
/// writes that mount's result head into `result` and counts one more owner.
/// Only while the unmount hook is in: without it the game's unmounts would
/// not see the owner count and would take the point from the other owner.
unsafe fn share(user: u32, dir: &[u8; DIR_BYTES], req: [u64; 2], result: *mut c_void) -> bool {
    if !cfg!(test) && unsafe { save_original::<Umount2Fn>(SAVE_UMOUNT2) }.is_none() {
        return false;
    }
    let _g = MOUNT_LOCK.lock();
    let t = unsafe { &mut *MOUNTED.get() };
    let Some(m) = t
        .iter_mut()
        .find(|m| {
            m.owners != 0 && m.unmounting == 0 && m.user == user && m.dir == *dir && m.req == req
        })
    else {
        return false;
    };
    m.owners += 1;
    unsafe { core::ptr::copy_nonoverlapping(m.result.as_ptr(), result.cast::<u8>(), RESULT_BYTES) };
    true
}

/// sceSaveDataUmount2(mode, mount_point).
pub unsafe extern "C" fn umount2_emul(mode: u32, point: *const c_void) -> c_int {
    let Some(orig) = (unsafe { save_original::<Umount2Fn>(SAVE_UMOUNT2) }) else {
        return SCE_KERNEL_ERROR_ENOSYS;
    };
    #[cfg(feature = "mem_report")]
    unsafe {
        probe::note_text(b"Umount2 point ", point as usize, POINT_BYTES)
    };
    // The last owner's mount this call saw (slot, gen).
    let mut seen: Option<(usize, u64)> = None;
    // Sequence of this call in the pass-through log (0: not logged).
    let mut passed = 0;
    let mut passed_point = [0u8; POINT_BYTES];
    if readable(point as usize, POINT_BYTES) {
        let name = unsafe { c_name::<POINT_BYTES>(point.cast()) };
        let _g = MOUNT_LOCK.lock();
        let t = unsafe { &mut *MOUNTED.get() };
        if let Some(i) = t.iter().position(|m| m.owners != 0 && m.point == name) {
            let m = &mut t[i];
            if m.owners > 1 {
                m.owners -= 1;
                stats::add(Stat::SaveUmountsShared, 1);
                #[cfg(feature = "mem_report")]
                probe::note(b"Umount2 shared", Some(0));
                return 0;
            }
            seen = Some((i, m.gen));
            m.unmounting += 1;
        } else {
            passed = unsafe { note_passed_umount(name) };
            passed_point = name;
        }
    }
    let rc = unsafe { orig(mode, point) };
    if passed != 0 {
        let _g = MOUNT_LOCK.lock();
        let gone = rc == 0 || rc == SAVE_DATA_ERROR_NOT_MOUNTED;
        unsafe { passed_umount_done(passed, &passed_point, gone) };
    }
    if let Some((i, gen)) = seen {
        // Whichever unmount the service answered with success forgets the
        // mount; a failed one only leaves the in-flight count.
        let gone = rc == 0 || rc == SAVE_DATA_ERROR_NOT_MOUNTED;
        let _g = MOUNT_LOCK.lock();
        let m = unsafe { &mut (*MOUNTED.get())[i] };
        if m.owners != 0 && m.gen == gen {
            if gone {
                *m = MOUNTED0;
            } else {
                m.unmounting -= 1;
            }
        }
    }
    #[cfg(feature = "mem_report")]
    probe::note(b"Umount2", Some(rc));
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
    pub(crate) const FIRST: usize = 4;

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
    pub(crate) const COUNT: usize = 13;

    use super::user_ptr;

    /// The first 4 words of the mount struct as hex, and the directory
    /// name its second word points to in the PS4 Mount2 layout (userId,
    /// pad, dirName*), read only when that word is a plausible pointer.
    #[inline(never)]
    pub(crate) unsafe fn note_mount(m: usize) {
        if !super::readable(m, 32) {
            return;
        }
        let mut buf = [0u8; 96];
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
        for i in 0..4 {
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

    fn name<const N: usize>(s: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        out[..s.len()].copy_from_slice(s);
        out
    }

    #[test]
    fn a_busy_mount_of_a_held_dir_shares_its_point() {
        let slot2 = name::<DIR_BYTES>(b"slot2");
        let mut first = [0u8; 64];
        first[..10].copy_from_slice(b"/savedata0");
        first[16] = 7; // required blocks, handed on with the point
        let req = [0x100, 0];
        unsafe { remember(7, slot2, req, first.as_ptr().cast(), passed_seq()) };
        // Another directory is not shared: its BUSY goes back to the game.
        let mut out = [0xaau8; 64];
        assert!(!unsafe { share(7, &name(b"slot1"), req, out.as_mut_ptr().cast()) });
        // A request with other words 2-3 (another mode) is not shared.
        assert!(!unsafe { share(7, &slot2, [0x100, 1], out.as_mut_ptr().cast()) });
        // Another user's mount of the same name is not shared either.
        assert!(!unsafe { share(8, &slot2, req, out.as_mut_ptr().cast()) });
        // The held one gets the same point and one more owner; the bytes
        // past the result head are left alone.
        assert!(unsafe { share(7, &slot2, req, out.as_mut_ptr().cast()) });
        assert_eq!(&out[..RESULT_BYTES], &first[..RESULT_BYTES]);
        assert_eq!(out[RESULT_BYTES], 0xaa);
        let t = unsafe { &*MOUNTED.get() };
        let m = t.iter().find(|m| m.dir == slot2).unwrap();
        assert_eq!(m.owners, 2);
        // A new mount at the same point replaces the entry.
        unsafe { remember(7, name(b"slot3"), req, first.as_ptr().cast(), passed_seq()) };
        let t = unsafe { &*MOUNTED.get() };
        assert!(t.iter().all(|m| m.dir != slot2));
        assert_eq!(t.iter().filter(|m| m.owners != 0).count(), 1);

        // A new mount of a held directory at another point drops the old
        // entry (unmounted through a call that is not hooked).
        let mut second = first;
        second[..10].copy_from_slice(b"/savedata1");
        unsafe { remember(7, name(b"slot3"), req, second.as_ptr().cast(), passed_seq()) };
        let t = unsafe { &*MOUNTED.get() };
        let held: Vec<_> = t.iter().filter(|m| m.owners != 0).collect();
        assert_eq!(held.len(), 1);
        assert_eq!(&held[0].point[..10], b"/savedata1");

        // An unmount of the point that passed through after the mount call
        // started: the point may be gone, so the mount is not recorded.
        // One of another point does not stop it.
        let since = passed_seq();
        {
            let _g = MOUNT_LOCK.lock();
            let a = unsafe { note_passed_umount(name(b"/savedata2")) };
            let b = unsafe { note_passed_umount(name(b"/savedata0")) };
            unsafe { passed_umount_done(a, &name(b"/savedata2"), true) };
            unsafe { passed_umount_done(b, &name(b"/savedata0"), true) };
        }
        unsafe { remember(7, name(b"slot4"), req, first.as_ptr().cast(), since) };
        let t = unsafe { &*MOUNTED.get() };
        assert!(t.iter().all(|m| m.dir != name::<DIR_BYTES>(b"slot4")));
        let mut third = first;
        third[..10].copy_from_slice(b"/savedata3");
        unsafe { remember(7, name(b"slot4"), req, third.as_ptr().cast(), since) };
        let t = unsafe { &*MOUNTED.get() };
        assert!(t.iter().any(|m| m.dir == name::<DIR_BYTES>(b"slot4")));
        // More pass-through unmounts than the ring holds: not recorded.
        let since = passed_seq();
        {
            let _g = MOUNT_LOCK.lock();
            for _ in 0..=PASSED {
                unsafe { note_passed_umount(name(b"/savedata9")) };
            }
        }
        unsafe { remember(7, name(b"slot5"), req, third.as_ptr().cast(), since) };
        let t = unsafe { &*MOUNTED.get() };
        assert!(t.iter().all(|m| m.dir != name::<DIR_BYTES>(b"slot5")));
        // An unmount of the point still in the service: recorded, not shared,
        // until its answer. A failure keeps the mount; a success drops it.
        let mut fourth = first;
        fourth[..10].copy_from_slice(b"/savedata4");
        let point4: [u8; POINT_BYTES] = name(b"/savedata4");
        let slot6: [u8; DIR_BYTES] = name(b"slot6");
        for gone in [false, true] {
            let since = passed_seq();
            let seq = {
                let _g = MOUNT_LOCK.lock();
                unsafe { note_passed_umount(point4) }
            };
            unsafe { remember(7, slot6, req, fourth.as_ptr().cast(), since) };
            assert!(!unsafe { share(7, &slot6, req, out.as_mut_ptr().cast()) });
            {
                let _g = MOUNT_LOCK.lock();
                unsafe { passed_umount_done(seq, &point4, gone) };
            }
            let t = unsafe { &*MOUNTED.get() };
            let held = t.iter().any(|m| m.owners != 0 && m.dir == slot6);
            assert_eq!(held, !gone);
            if !gone {
                assert!(unsafe { share(7, &slot6, req, out.as_mut_ptr().cast()) });
                let t = unsafe { &mut *MOUNTED.get() };
                t.iter_mut().filter(|m| m.dir == slot6).for_each(|m| *m = MOUNTED0);
            }
        }
        // Two unmounts in flight, one started before the mount call: both
        // count, a failure of one leaves it unshared, a success of the
        // other drops it.
        let (old, since) = {
            let _g = MOUNT_LOCK.lock();
            (unsafe { note_passed_umount(point4) }, unsafe { *PASSED_SEQ.get() })
        };
        let new = {
            let _g = MOUNT_LOCK.lock();
            unsafe { note_passed_umount(point4) }
        };
        unsafe { remember(7, slot6, req, fourth.as_ptr().cast(), since) };
        let held = |t: &[Mounted; MOUNTS]| t.iter().any(|m| m.owners != 0 && m.dir == slot6);
        {
            let _g = MOUNT_LOCK.lock();
            unsafe { passed_umount_done(new, &point4, false) };
        }
        assert!(held(unsafe { &*MOUNTED.get() }));
        assert!(!unsafe { share(7, &slot6, req, out.as_mut_ptr().cast()) });
        {
            let _g = MOUNT_LOCK.lock();
            unsafe { passed_umount_done(old, &point4, true) };
        }
        assert!(!held(unsafe { &*MOUNTED.get() }));
    }
}
