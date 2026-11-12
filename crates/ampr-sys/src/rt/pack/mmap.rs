//! mmap and sceKernelMmap of a packed file, LZ4 (AMPRPAK4) or zstd packs
//! (hook ids 96 and 97, installed in both builds while Makefile
//! `AMPR_ZSTD_MMAP` is not 0; the knob keeps its zstd name), and
//! munmap/sceKernelMunmap (98 and 99, knob 1 only). A packed file has no
//! physical copy, so the original call fails on a virtual pack fd. Knob 2
//! (the default) sends every map to the disk fallback. Knob 1, opt-in and
//! unverified, decodes zstd packed files on access (rt/pack/mmap_fault.rs:
//! nothing is decoded until a page is touched); a map it cannot serve, and
//! every map of an LZ4 packed file, takes the disk fallback. The disk
//! fallback reads the whole file once through the virtual pread path
//! (rt/pack/fd_read.rs, which decodes either format in
//! rt/pack/virtual_read.rs) into an unlinked file under /data/ampr_cache,
//! keeps that fd for the session and maps it with the caller's
//! addr/len/prot/flags/offset. Any other fd goes to the original
//! unchanged. Pool use: one transient 256 KiB buffer while a cache file is
//! written; unmeasured on a console (Makefile).

use super::super::index::{
    sdk_alloc, sdk_release, title_alloc, title_free, write_all, MEM_TRANSIENT,
};
use super::*;

// ---- knob ---------------------------------------------------------------------

/// Makefile `AMPR_ZSTD_MMAP`, for both pack formats: 0 off (not hooked), 1
/// decode on access with the disk fallback (zstd packs only, opt-in,
/// unverified; LZ4 packs take the fallback), 2 disk fallback only (the
/// Makefile default, also used when the variable is absent).
pub(crate) const MMAP_MODE: u8 = match option_env!("AMPR_ZSTD_MMAP") {
    Some(s) => parse_mode(s.as_bytes()),
    None => 2,
};

const fn parse_mode(s: &[u8]) -> u8 {
    match s {
        b"0" => 0,
        b"1" => 1,
        b"2" => 2,
        _ => panic!("AMPR_ZSTD_MMAP: not 0, 1 or 2"),
    }
}

// ---- hooks --------------------------------------------------------------------

const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
pub(crate) const MAP_FIXED: c_int = 0x10;
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
    /// A decode-on-access reservation at this address.
    Reserved(*mut c_void),
    /// Failed with this POSIX errno.
    Failed(c_int),
}

/// Routes a map of `fd`. A virtual pack fd tries decode on access (knob 1,
/// zstd packs), then its disk cache file; MAP_ANON and any other fd go to
/// the original. The u8 is the debug lookup letter.
unsafe fn serve(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: off_t,
) -> (Served, u8) {
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
    // try_map reads the zstd projection and index, so it runs under a
    // ManifestReader. Refused once shutdown starts, it falls back to the
    // disk copy, whose reads take a PackSubmission instead. The guard is
    // dropped before that copy: it may wait on pack workers.
    if MMAP_MODE == 1 {
        if let Some(_reader) = ManifestReader::enter() {
            match unsafe { mmap_fault::try_map(addr, len, prot, flags, file_id, off) } {
                mmap_fault::MapResult::Mapped(p) => return (Served::Reserved(p), b'f'),
                mmap_fault::MapResult::Failed(e) => return (Served::Failed(e), b'f'),
                mmap_fault::MapResult::Fallback => {}
            }
        }
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
    let fixed = MMAP_MODE == 1 && flags & MAP_FIXED != 0;
    let span = mmap_fault::replace_len(len);
    if fixed {
        mmap_fault::begin_replace(addr as usize, span);
    }
    let (served, _how) = unsafe { serve(addr, len, prot, flags, fd, off) };
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
        Served::Reserved(p) => p,
        Served::Failed(e) => {
            set_errno(e);
            MAP_FAILED
        }
    };
    if fixed {
        mmap_fault::end_replace(addr as usize, span, p != MAP_FAILED);
    }
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
    let fixed = MMAP_MODE == 1 && flags & MAP_FIXED != 0;
    let span = mmap_fault::replace_len(len);
    if fixed {
        mmap_fault::begin_replace(addr as usize, span);
    }
    let (served, _how) = unsafe { serve(addr, len, prot, flags, fd, off) };
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
        Served::Reserved(p) => {
            if !res.is_null() {
                unsafe { *res = p };
            }
            0
        }
        Served::Failed(e) => sce_errno(e),
    };
    if fixed {
        mmap_fault::end_replace(addr as usize, span, rc == 0);
    }
    #[cfg(feature = "mem_report")]
    note(b'Y', b"sceKernelMmap", seen, _how, rc.into());
    rc
}

type MunmapFn = unsafe extern "C" fn(*mut c_void, usize) -> c_int;

/// munmap: the decode-on-access mappings in the range stop serving faults,
/// the original runs, and they are freed if it succeeded or served again if
/// it failed (`AMPR_ZSTD_MMAP=1`, rt/pack/mmap_fault.rs begin/end_replace).
pub(crate) unsafe extern "C" fn munmap_emul(addr: *mut c_void, len: usize) -> c_int {
    mmap_fault::begin_replace(addr as usize, len);
    let rc = match unsafe { kernel_slot::<MunmapFn>(hook::munmap) } {
        Some(f) => unsafe { f(addr, len) },
        None => {
            set_errno(EIO);
            -1
        }
    };
    mmap_fault::end_replace(addr as usize, len, rc == 0);
    rc
}

#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn sceKernelMunmap_emul(addr: *mut c_void, len: usize) -> c_int {
    mmap_fault::begin_replace(addr as usize, len);
    let rc = unsafe { kernel_slot::<MunmapFn>(hook::sceKernelMunmap) }
        .map_or(SCE_KERNEL_ERROR_EIO, |f| unsafe { f(addr, len) });
    mmap_fault::end_replace(addr as usize, len, rc == 0);
    rc
}

// ---- disk cache ---------------------------------------------------------------

/// Cache directory on the console's data partition; every entry is swept
/// at module_start (`sweep_cache_dir`).
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

const O_RDWR: c_int = 0x2;
const O_CREAT: c_int = 0x200;
const O_TRUNC: c_int = 0x400;
const O_EXCL: c_int = 0x800;

// Real libkernel entries: the pre-detour slot once hooks install, else the
// dynamic symbol (the sweep runs at module_start, before any hook), so no
// call here goes through the index path hooks. The open is the `_open`
// original (`pack::libkernel::real_open`): libkernel `open` calls `_open`,
// which routes through the index by default (AMPR_ZSTD_LIBC_HOOKS=0xfff).
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

/// errno of a failed real call, EIO if it left none.
fn failed_errno() -> c_int {
    match errno() {
        0 => EIO,
        e => e,
    }
}

/// Pack shutdown: closes every cached file fd, so a PRX unload in a running
/// process leaks neither fds nor their storage. Existing mappings stay
/// valid; they hold the unlinked files themselves.
pub(crate) unsafe fn close_cache() {
    let _guard = CACHE_M.lock();
    let table = unsafe { &mut *CACHE.get() };
    while let Some(fd) = table.evict_oldest() {
        unsafe { real_physical_close(fd) };
    }
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
/// any failure the fd is closed and no named file is left.
unsafe fn create_cache_file(vfd: c_int, file_id: u32) -> Result<c_int, c_int> {
    if unsafe { real_mkdir(CACHE_DIR.as_ptr(), 0o700) } != 0 && errno() != EEXIST {
        return Err(EIO);
    }
    let path = cache_path(file_id);
    let p = path.as_ptr().cast::<c_char>();
    unsafe { real_unlink(p) };
    let fd = unsafe { real_open_path(p, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, 0o600) };
    if fd < 0 {
        return Err(match failed_errno() {
            e @ (EMFILE | ENFILE | ENOSPC) => e,
            _ => EIO,
        });
    }
    if unsafe { real_unlink(p) } != 0 {
        unsafe { real_physical_close(fd) };
        unsafe { real_unlink(p) };
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
    let buf = unsafe { sdk_alloc(PIECE, MEM_TRANSIENT) }.cast::<u8>();
    if buf.is_null() {
        return Err(ENOMEM);
    }
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
    unsafe { sdk_release(buf.cast(), PIECE, MEM_TRANSIENT) };
    rc
}

/// Largest packed file `read_packed` reads whole. The buffer comes from the
/// Index ledger's free room, which can be less (the 2 MiB the page arena
/// leaves for transient buffers, rt/index_pages.rs `TRANSIENT_ROOM`): a larger icon is
/// then skipped like one over this size, counted in `save_icon_skipped`
/// without the index notice (rt/save.rs `save_icon_by_path_emul`).
pub(crate) const READ_PACKED_MAX: usize = 8 * 1024 * 1024;

/// For a system service that opens a path itself, past the path hooks (the
/// save data icon, rt/save.rs): when `path` opens as a packed file of at
/// most READ_PACKED_MAX bytes, `use_bytes` gets its decoded bytes in a
/// transient buffer from the pool's Index ledger (sized by the file, so not
/// a fixed pool site).
/// None for a loose or missing file; Some(Err) for a packed file it could
/// not read (too large, no buffer, a failed read).
pub(crate) unsafe fn read_packed<R>(
    path: *const c_char,
    use_bytes: impl FnOnce(&[u8]) -> R,
) -> Option<Result<R, ()>> {
    let vfd = unsafe { super::super::index::posix_open_emul(path, 0, 0) };
    if vfd < 0 {
        return None;
    }
    let out = if unsafe { virtual_fd_file_id(vfd) }.is_some() {
        Some(unsafe { read_whole(vfd) }.ok_or(()).map(|(buf, len)| {
            let r = use_bytes(unsafe { core::slice::from_raw_parts(buf, len) });
            unsafe { title_free(buf, c"apr.read-packed") };
            r
        }))
    } else {
        None
    };
    unsafe { posix_close_emul(vfd) };
    out
}

/// The whole decoded file behind `vfd` in an index memory buffer of its
/// size; None when refused (the save icon is then skipped, rt/save.rs).
unsafe fn read_whole(vfd: c_int) -> Option<(*mut u8, usize)> {
    let mut st: SceKernelStat = unsafe { core::mem::zeroed() };
    if unsafe { posix_fstat_emul(vfd, &mut st) } != 0 {
        return None;
    }
    let len = usize::try_from(st.st_size).ok().filter(|&n| n > 0 && n <= READ_PACKED_MAX)?;
    let buf = unsafe { title_alloc(len, c"apr.read-packed") };
    if buf.is_null() {
        return None;
    }
    let mut off = 0usize;
    while off < len {
        let mut handled = false;
        let want = (len - off).min(PIECE);
        let n = unsafe {
            ampr_pack_try_pread_fd(vfd, buf.add(off).cast(), want, off as off_t, &mut handled)
        };
        if n <= 0 || n as usize > want {
            unsafe { title_free(buf, c"apr.read-packed") };
            return None;
        }
        off += n as usize;
    }
    Some((buf, len))
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
        assert_eq!((t.lookup(7), t.lookup(9), t.lookup(10)), (None, Some(31), Some(32)));
    }

    #[test]
    fn cache_path_is_hex_file_id_under_the_cache_dir() {
        let p = cache_path(0x00ab_12cd);
        let end = p.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&p[..end], b"/data/ampr_cache/00ab12cd.tmp");
        assert_eq!(cache_path(u32::MAX)[end], 0);
    }
}
