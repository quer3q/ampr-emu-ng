//! mmap and sceKernelMmap of a packed file, LZ4 (AMPRPAK4) or zstd packs
//! (hook ids 96 and 97, installed in both builds while Makefile
//! `AMPR_PACK_MMAP` is not 0). A packed file
//! has no physical copy, so the original call fails on a virtual pack fd.
//! Every map of one goes to the disk cache: the whole file is read once
//! through the virtual pread path (rt/pack/fd_read.rs, which decodes either
//! format in rt/pack/virtual_read.rs) into an unlinked file under
//! /data/ampr_cache (the folder is removed right after the unlink), that fd
//! is kept for the session and mapped with the caller's
//! addr/len/prot/flags/offset. Any other fd goes to the original
//! unchanged. Pool use: one transient 256 KiB buffer while a cache file is
//! written; unmeasured on a console (Makefile).
//!
//! Decode on access (knob 1, its fault handler and the munmap hooks, ids
//! 98 and 99) was removed: no measured game mmapped a packed file (three
//! fully packed games on a console: mmap_virtual 0), so it never served a
//! game, and eight of its limits were unsolved. Ids 98 and 99 stay unused.

use super::super::index::{sdk_alloc, sdk_release, write_all, MEM_TRANSIENT};
use super::*;

// ---- knob ---------------------------------------------------------------------

/// Makefile `AMPR_PACK_MMAP`, for both pack formats: 0 off (not hooked), 2
/// disk cache (the Makefile default, also used when the variable is
/// absent). 1 was decode on access, removed; it fails the build.
pub(crate) const MMAP_MODE: u8 = match option_env!("AMPR_PACK_MMAP") {
    Some(s) => parse_mode(s.as_bytes()),
    None => 2,
};

const fn parse_mode(s: &[u8]) -> u8 {
    match s {
        b"0" => 0,
        b"1" => panic!("AMPR_PACK_MMAP=1 (decode on access) was removed: use 0 or 2"),
        b"2" => 2,
        _ => panic!("AMPR_PACK_MMAP: not 0 or 2"),
    }
}

// ---- hooks --------------------------------------------------------------------

const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
const MAP_SHARED: c_int = 0x1;
/// FreeBSD MAP_ANON: the fd is not mapped (it is -1 by convention, but the
/// kernel ignores it), so the map is never a packed file's.
const MAP_ANON: c_int = 0x1000;

type MmapFn = unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, off_t) -> *mut c_void;
type SceMmapFn =
    unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, off_t, *mut *mut c_void) -> c_int;

/// How one map call is served.
enum Served {
    /// The original call on the caller's fd (physical fd or virtual
    /// directory).
    Original(c_int),
    /// The original call on this dup of a cache file's fd; the caller
    /// closes it after the call (`disk_fd`).
    Cache(c_int),
    /// Failed with this POSIX errno.
    Failed(c_int),
}

/// Routes a map of `fd`. A virtual pack fd maps its disk cache file;
/// MAP_ANON and any other fd go to the original. The u8 is the debug
/// lookup letter.
unsafe fn serve(prot: c_int, flags: c_int, fd: c_int) -> (Served, u8) {
    if flags & MAP_ANON != 0 {
        return (Served::Original(fd), b'v');
    }
    let Some(file_id) = (unsafe { virtual_fd_file_id(fd) }) else {
        return (Served::Original(fd), b'v');
    };
    stats::add(stats::Stat::MmapVirtual, 1);
    // A packed virtual fd is read-only: a shared writable map of it gets
    // EACCES, as for any O_RDONLY fd, not a map of the O_RDWR cache file.
    // GPU and AMPR write bits count too: the cache fd would take them.
    const WRITE: c_int =
        SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_WRITE | SCE_KERNEL_PROT_AMPR_WRITE;
    if flags & MAP_SHARED != 0 && prot & WRITE != 0 {
        return (Served::Failed(EACCES), b'v');
    }
    match unsafe { disk_fd(fd, file_id) } {
        Ok(real) => {
            stats::add(stats::Stat::MmapDisk, 1);
            (Served::Cache(real), b'k')
        }
        Err(e) => {
            stats::add(stats::Stat::MmapDiskFailed, 1);
            (Served::Failed(e), b'v')
        }
    }
}

/// Debug: logs `op` for a virtual fd (`seen`) through `stats::fs_event`,
/// so only a failed map enters `/fsfail` (the mmap_* counters count the
/// served ones).
#[cfg(feature = "mem_report")]
fn note(op: u8, call: &[u8], seen: Option<super::super::probe::Text>, how: u8, rc: i64) {
    use super::super::probe::event_text;
    if let Some(t) = seen {
        event_text(op, how, rc, call, &t);
    }
}

pub(crate) unsafe extern "C" fn mmap_emul(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: off_t,
) -> *mut c_void {
    #[cfg(feature = "mem_report")]
    let seen = unsafe { super::super::probe::fd_path(fd) };
    let (served, _how) = unsafe { serve(prot, flags, fd) };
    let p = match served {
        Served::Original(real) | Served::Cache(real) => {
            let p = match unsafe { kernel_slot::<MmapFn>(hook::mmap) } {
                Some(f) => unsafe { f(addr, len, prot, flags, real, off) },
                None => {
                    set_errno(EIO);
                    MAP_FAILED
                }
            };
            if let Served::Cache(dup) = served {
                unsafe { close_keeping_errno(dup) };
            }
            p
        }
        Served::Failed(e) => {
            set_errno(e);
            MAP_FAILED
        }
    };
    #[cfg(feature = "mem_report")]
    {
        let rc = if p == MAP_FAILED {
            -i64::from(errno())
        } else {
            0
        };
        note(b'X', b"mmap", seen, _how, rc);
    }
    p
}

#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn sceKernelMmap_emul(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: off_t,
    res: *mut *mut c_void,
) -> c_int {
    #[cfg(feature = "mem_report")]
    let seen = unsafe { super::super::probe::fd_path(fd) };
    let (served, _how) = unsafe { serve(prot, flags, fd) };
    let rc = match served {
        Served::Original(real) | Served::Cache(real) => {
            let rc = unsafe { kernel_slot::<SceMmapFn>(hook::sceKernelMmap) }
                .map_or(SCE_KERNEL_ERROR_EIO, |f| unsafe {
                    f(addr, len, prot, flags, real, off, res)
                });
            if let Served::Cache(dup) = served {
                unsafe { close_keeping_errno(dup) };
            }
            rc
        }
        Served::Failed(e) => sce_errno(e),
    };
    #[cfg(feature = "mem_report")]
    note(b'Y', b"sceKernelMmap", seen, _how, rc.into());
    rc
}

// ---- disk cache ---------------------------------------------------------------

/// Cache directory on the console's data partition; every entry is swept
/// at module_start (`sweep_cache_dir`). It exists only while a cache file is
/// created (`remove_cache_dir`).
const CACHE_DIR: &CStr = c"/data/ampr_cache";
/// Cache files kept open at once (one fd each); the oldest is closed for a
/// new one, and a later map of it decodes it again.
const CACHE_FILES: usize = 64;
/// Largest piece read from the virtual fd and written per step.
pub(crate) const PIECE: usize = 256 * 1024;
/// "/data/ampr_cache/" + 8 hex digits + ".tmp" + NUL is 30 bytes.
const PATH_LEN: usize = 32;

/// file id -> open fd of its unlinked cache file, in insert order.
struct CacheTable<const N: usize> {
    ids: [u32; N],
    fds: [c_int; N],
    used: usize,
}

impl<const N: usize> CacheTable<N> {
    const fn new() -> Self {
        Self {
            ids: [0; N],
            fds: [-1; N],
            used: 0,
        }
    }
    fn lookup(&self, id: u32) -> Option<c_int> {
        let i = self.ids[..self.used].iter().position(|&v| v == id)?;
        Some(self.fds[i])
    }
    fn is_full(&self) -> bool {
        self.used == N
    }
    /// Removes the oldest entry and returns its fd for the caller to close.
    fn evict_oldest(&mut self) -> Option<c_int> {
        if self.used == 0 {
            return None;
        }
        let fd = self.fds[0];
        self.ids.copy_within(1..self.used, 0);
        self.fds.copy_within(1..self.used, 0);
        self.used -= 1;
        Some(fd)
    }
    /// Adds `id`; false when the table is full.
    fn insert(&mut self, id: u32, fd: c_int) -> bool {
        if self.is_full() {
            return false;
        }
        self.ids[self.used] = id;
        self.fds[self.used] = fd;
        self.used += 1;
        true
    }
}

/// NUL-terminated "/data/ampr_cache/<id as 8 hex digits>.tmp".
fn cache_path(id: u32) -> [u8; PATH_LEN] {
    let mut out = [0u8; PATH_LEN];
    let dir = CACHE_DIR.to_bytes();
    out[..dir.len()].copy_from_slice(dir);
    let mut n = dir.len();
    out[n] = b'/';
    n += 1;
    for shift in (0..8).rev() {
        out[n] = b"0123456789abcdef"[(id >> (shift * 4)) as usize & 0xf];
        n += 1;
    }
    out[n..n + 4].copy_from_slice(b".tmp");
    out
}

static CACHE: SyncCell<CacheTable<CACHE_FILES>> = SyncCell::new(CacheTable::new());
/// Guards CACHE and serializes cache file writes, so two threads mapping
/// one file write it once. A pthread mutex: a write can take a while.
static CACHE_M: Mutex = Mutex::new();
static MKDIR: LazySym = LazySym::new(c"mkdir");
static RMDIR: LazySym = LazySym::new(c"rmdir");

const O_RDWR: c_int = 0x2;
const O_CREAT: c_int = 0x200;
const O_TRUNC: c_int = 0x400;
const O_EXCL: c_int = 0x800;

// Real libkernel entries: the pre-detour slot once hooks install, else the
// dynamic symbol (the sweep runs at module_start, before any hook), so no
// call here goes through the index path hooks. The open is the `_open`
// original (`pack::libkernel::real_open`): libkernel `open` calls `_open`,
// which routes through the index by default (AMPR_PACK_LIBC_HOOKS=0xfff).
// Before any hook installs, dynamic `open` reaches the undetoured `_open`.
unsafe fn real_open_path(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    unsafe { real_open() }.map_or_else(eio, |f| unsafe { f(path, flags, mode) })
}

unsafe fn real_unlink(path: *const c_char) -> c_int {
    type F = unsafe extern "C" fn(*const c_char) -> c_int;
    unsafe { slot_or_dynamic::<F>(hook::unlink, c"unlink") }
        .map_or_else(eio, |f| unsafe { f(path) })
}

unsafe fn real_mkdir(path: *const c_char, mode: c_int) -> c_int {
    type F = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
    unsafe { MKDIR.get::<F>() }.map_or_else(eio, |f| unsafe { f(path, mode) })
}

type RmdirFn = unsafe extern "C" fn(*const c_char) -> c_int;

/// rmdir has no hook id, like mkdir: the dynamic symbol is the real call.
unsafe fn real_rmdir() -> Option<RmdirFn> {
    unsafe { RMDIR.get::<RmdirFn>() }
}

/// Removes CACHE_DIR when it is empty, so no folder stays on /data for a
/// file explorer to show. Every cache file is unlinked right after create,
/// so the folder is empty unless a crash left a named file (swept at the
/// next module_start). Runs after each create (`create_cache_file`), at
/// module_start after `sweep_cache_dir` (rt/pack/mod.rs
/// `select_pack_format`) and at pack shutdown (`close_cache`); always under
/// CACHE_M or before any map, so no create runs between its mkdir and this.
pub(crate) unsafe fn remove_cache_dir() {
    if let Some(rmdir) = unsafe { real_rmdir() } {
        unsafe { remove_dir_keeping_errno(CACHE_DIR, rmdir) };
    }
}

/// rmdir of `dir`, every error ignored (ENOENT: already gone; ENOTEMPTY: a
/// named file is left) and errno kept, so the caller still reports its own.
unsafe fn remove_dir_keeping_errno(dir: &CStr, rmdir: RmdirFn) {
    let saved = errno();
    unsafe { rmdir(dir.as_ptr()) };
    set_errno(saved);
}

/// errno of a failed real call, EIO if it left none.
fn failed_errno() -> c_int {
    match errno() {
        0 => EIO,
        e => e,
    }
}

/// Pack shutdown: closes every cached file fd, so a PRX unload in a running
/// process leaks neither fds nor their storage, and removes the folder.
/// Existing mappings stay valid; they hold the unlinked files themselves.
pub(crate) unsafe fn close_cache() {
    let _guard = CACHE_M.lock();
    let table = unsafe { &mut *CACHE.get() };
    while let Some(fd) = table.evict_oldest() {
        unsafe { real_physical_close(fd) };
    }
    unsafe { remove_cache_dir() };
}

/// A dup of `file_id`'s cache file fd, writing the file first from the
/// virtual fd `vfd` on its first map; the caller maps the dup and closes it.
/// With CACHE_FILES files cached the oldest is closed to make room: an
/// unlinked file stays alive while any mapping or dup still holds it, and
/// handing out dups means closing a table fd never pulls an fd from under a
/// map in progress.
/// Err is a POSIX errno: EMFILE when no fd is left, ENOMEM without a
/// buffer, EIO otherwise.
unsafe fn disk_fd(vfd: c_int, file_id: u32) -> Result<c_int, c_int> {
    let _guard = CACHE_M.lock();
    let table = unsafe { &mut *CACHE.get() };
    let fd = match table.lookup(file_id) {
        Some(fd) => fd,
        None => {
            // Create before evicting: a failed create then keeps the
            // oldest cached file instead of losing it for nothing.
            let fd = unsafe { create_cache_file(vfd, file_id) }?;
            if table.is_full() {
                if let Some(old) = table.evict_oldest() {
                    unsafe { real_physical_close(old) };
                }
            }
            table.insert(file_id, fd);
            fd
        }
    };
    unsafe { dup_fd(fd) }
}

/// dup(2) of a runtime-owned fd (libkernel `dup`; the debug probe on it
/// only passes through). Err EMFILE when no fd is left.
unsafe fn dup_fd(fd: c_int) -> Result<c_int, c_int> {
    type DupFn = unsafe extern "C" fn(c_int) -> c_int;
    let dup = unsafe { resolve_kernel::<DupFn>(c"dup") }.ok_or(EIO)?;
    match unsafe { dup(fd) } {
        n if n >= 0 => Ok(n),
        _ => Err(EMFILE),
    }
}

/// Closes a dup handed out by `disk_fd` without changing errno, so the
/// caller still sees the map's own error.
unsafe fn close_keeping_errno(fd: c_int) {
    let saved = errno();
    unsafe { real_physical_close(fd) };
    set_errno(saved);
}

/// Creates, unlinks and fills the cache file of `file_id`. The fd keeps the
/// data; the kernel frees it when the process exits, crash or kill too. On
/// any failure the fd is closed and no named file is left. The folder is
/// made for the create and removed right after the unlink, or on a failed
/// open or unlink, so it never stays on /data while the session runs.
unsafe fn create_cache_file(vfd: c_int, file_id: u32) -> Result<c_int, c_int> {
    if unsafe { real_mkdir(CACHE_DIR.as_ptr(), 0o700) } != 0 && errno() != EEXIST {
        return Err(EIO);
    }
    let path = cache_path(file_id);
    let p = path.as_ptr().cast::<c_char>();
    unsafe { real_unlink(p) };
    let fd = unsafe { real_open_path(p, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, 0o600) };
    if fd < 0 {
        let e = match failed_errno() {
            e @ (EMFILE | ENFILE | ENOSPC) => e,
            _ => EIO,
        };
        unsafe { remove_cache_dir() };
        return Err(e);
    }
    let unlinked = unsafe { real_unlink(p) } == 0;
    if !unlinked {
        unsafe { real_physical_close(fd) };
        unsafe { real_unlink(p) };
    }
    unsafe { remove_cache_dir() };
    if !unlinked {
        return Err(EIO);
    }
    match unsafe { copy_virtual_file(vfd, fd) } {
        Ok(bytes) => {
            stats::add(stats::Stat::MmapDiskBytes, bytes);
            Ok(fd)
        }
        Err(e) => {
            unsafe { real_physical_close(fd) };
            Err(e)
        }
    }
}

/// Writes the whole decoded file behind `vfd` into `fd` in pieces of at
/// most PIECE bytes, through the virtual pread path (rt/pack/fd_read.rs).
/// Returns the bytes written. The piece is a fixed pool site: one at a
/// time, under CACHE_M (`disk_fd`).
unsafe fn copy_virtual_file(vfd: c_int, fd: c_int) -> Result<u64, c_int> {
    unsafe { with_piece(|buf| copy_with(vfd, fd, buf)) }.unwrap_or(Err(ENOMEM))
}

/// The one PIECE buffer (a fixed pool site) for `f`; None when refused.
/// Callers hold CACHE_M, so one is out at a time.
unsafe fn with_piece<R>(f: impl FnOnce(*mut u8) -> R) -> Option<R> {
    let buf = unsafe { sdk_alloc(PIECE, MEM_TRANSIENT) }.cast::<u8>();
    if buf.is_null() {
        return None;
    }
    let r = f(buf);
    unsafe { sdk_release(buf.cast(), PIECE, MEM_TRANSIENT) };
    Some(r)
}

unsafe fn copy_with(vfd: c_int, fd: c_int, buf: *mut u8) -> Result<u64, c_int> {
    let mut off = 0u64;
    let rc = loop {
        let mut handled = false;
        let n =
            unsafe { ampr_pack_try_pread_fd(vfd, buf.cast(), PIECE, off as off_t, &mut handled) };
        if n == 0 {
            break Ok(off);
        }
        if n < 0 || n as usize > PIECE {
            break Err(EIO);
        }
        let piece = unsafe { core::slice::from_raw_parts(buf, n as usize) };
        if !unsafe { write_all(fd, piece) } {
            break Err(EIO);
        }
        off += n as u64;
    };
    rc
}

// ---- packed bytes for system services ---------------------------------------------

/// For a system service that opens a game path itself, past the path hooks
/// (the save data icon, rt/save.rs): when `path` opens as a packed file,
/// `use_bytes` gets its decoded bytes in a buffer of its size from the
/// game's libc heap, freed as soon as `use_bytes` returns: the icon is held
/// only for the one call, outside the pool, at any size (a title's
/// /app0/images/icon0.png is 551,096 B). A failed malloc or read is
/// Some(Err) and the caller skips the icon, as is an open that failed for
/// lack of fds or memory. None for a loose or missing file, or another
/// failed open. A path handed to the save service instead (a file under
/// CACHE_DIR) hung a title's save inside the service call.
pub(crate) unsafe fn read_packed<R>(
    path: *const c_char,
    use_bytes: impl FnOnce(&[u8]) -> R,
) -> Option<Result<R, ()>> {
    let vfd = unsafe { super::super::index::posix_open_emul(path, 0, 0) };
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
    let buf = unsafe { super::super::heap::libc_malloc(len) };
    if buf.is_null() {
        return Err(());
    }
    let out = unsafe { read_into(vfd, buf, len, use_bytes) };
    unsafe { super::super::heap::libc_free(buf) };
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

/// At module_start (rt/pack/mod.rs `select_pack_format`): unlinks every
/// entry of CACHE_DIR, ignoring errors. Files are unlinked right after
/// create, so only a crash between create and unlink leaves one. A pass
/// that unlinks while it lists may skip entries, so passes repeat until one
/// unlinks nothing (at most 8).
pub(crate) unsafe fn sweep_cache_dir() {
    for _ in 0..8 {
        if unsafe { sweep_pass() } == 0 {
            return;
        }
    }
}

/// One listing of CACHE_DIR; returns the entries unlinked.
unsafe fn sweep_pass() -> usize {
    let dir = unsafe { real_open_path(CACHE_DIR.as_ptr(), O_RDONLY | O_DIRECTORY, 0) };
    if dir < 0 {
        return 0;
    }
    // getdents wants room for at least one 264-byte record; u64 aligns it.
    let mut buf = [0u64; 512];
    let mut removed = 0;
    loop {
        let base = buf.as_mut_ptr().cast::<u8>();
        let n = unsafe { real_physical_getdents(dir, base.cast(), size_of_val(&buf) as c_int) };
        if n <= 0 {
            break;
        }
        let mut at = 0usize;
        while at + DIRENT_NAME_OFFSET <= n as usize {
            // Field reads, not a &Dirent: the last record may end before
            // the 264 bytes of a full struct.
            let rec = unsafe { base.add(at) };
            let fileno = unsafe { rec.cast::<u32>().read_unaligned() };
            let reclen = unsafe {
                rec.add(offset_of!(Dirent, d_reclen))
                    .cast::<u16>()
                    .read_unaligned()
            };
            let namlen = unsafe { *rec.add(offset_of!(Dirent, d_namlen)) } as usize;
            let reclen = reclen as usize;
            if reclen == 0 || at + reclen > n as usize || DIRENT_NAME_OFFSET + namlen > reclen {
                break;
            }
            let name = unsafe { core::slice::from_raw_parts(rec.add(DIRENT_NAME_OFFSET), namlen) };
            if fileno != 0 && name != b"." && name != b".." {
                let mut path = [0u8; 300];
                let dir_bytes = CACHE_DIR.to_bytes();
                path[..dir_bytes.len()].copy_from_slice(dir_bytes);
                path[dir_bytes.len()] = b'/';
                path[dir_bytes.len() + 1..][..name.len()].copy_from_slice(name);
                if unsafe { real_unlink(path.as_ptr().cast()) } == 0 {
                    removed += 1;
                }
            }
            at += reclen;
        }
    }
    unsafe { real_physical_close(dir) };
    removed
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_finds_inserted_ids_and_refuses_when_full() {
        let mut t = CacheTable::<2>::new();
        assert_eq!(t.lookup(7), None);
        assert!(t.insert(7, 30) && t.insert(9, 31));
        assert_eq!(
            (t.lookup(7), t.lookup(9), t.lookup(8)),
            (Some(30), Some(31), None)
        );
        assert!(t.is_full() && !t.insert(10, 32));
        assert_eq!(t.lookup(10), None);
        // A full table makes room by dropping its oldest entry.
        assert_eq!(t.evict_oldest(), Some(30));
        assert!(t.insert(10, 32));
        assert_eq!(
            (t.lookup(7), t.lookup(9), t.lookup(10)),
            (None, Some(31), Some(32))
        );
    }

    #[test]
    fn cache_path_is_hex_file_id_under_the_cache_dir() {
        let p = cache_path(0x00ab_12cd);
        let end = p.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&p[..end], b"/data/ampr_cache/00ab12cd.tmp");
        assert_eq!(cache_path(u32::MAX)[end], 0);
    }

    extern "C" {
        /// Host libc rmdir; the console one is resolved from libkernel.
        fn rmdir(path: *const c_char) -> c_int;
    }

    /// The create sequence on the host filesystem: make the folder, create
    /// a file, unlink it, remove the folder while the fd still reads the
    /// data. A folder holding a named file (a crash left it) stays, and a
    /// missing folder is no error; errno is kept either way.
    #[test]
    fn folder_goes_after_the_unlink_and_a_named_file_keeps_it() {
        use std::io::{Read, Seek, Write};
        let dir = std::env::temp_dir().join(format!("ampr_cache_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let c_dir = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
        let file = dir.join("00000001.tmp");
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&file)
            .unwrap();
        std::fs::remove_file(&file).unwrap();
        set_errno(EMFILE);
        unsafe { remove_dir_keeping_errno(&c_dir, rmdir) };
        assert_eq!(errno(), EMFILE);
        assert!(!dir.exists());
        f.write_all(b"kept").unwrap();
        f.rewind().unwrap();
        let mut back = String::new();
        f.read_to_string(&mut back).unwrap();
        assert_eq!(back, "kept");

        // Missing folder: ENOENT is ignored.
        set_errno(ENOSPC);
        unsafe { remove_dir_keeping_errno(&c_dir, rmdir) };
        assert_eq!(errno(), ENOSPC);

        // A named file left behind: ENOTEMPTY is ignored, the folder stays.
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&file, b"x").unwrap();
        set_errno(0);
        unsafe { remove_dir_keeping_errno(&c_dir, rmdir) };
        assert_eq!(errno(), 0);
        assert!(file.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
