//! Pkg mode: a title whose launcher names its .pkg in `/app0/kraken.image`
//! reads pack 0 straight from that file, with no AMPRDAT3 header. This
//! holds the runtime glue (discovery, volume check, KRAKEN chunk decode);
//! the checks and arithmetic are in `ampr-pkg` so host tests cover them.

use super::*;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{AtomicU64, AtomicU8};

// ---- .pkg path ----

/// One line, the .pkg path relative to /app0 (e.g. `kraken/x.pkg`). The
/// launcher mounts the .pkg's folder read-only at /app0/kraken: the PS5's
/// /data has no hard links or symlinks, so /app0 cannot hold the .pkg.
const KRAKEN_IMAGE: &CStr = c"/app0/kraken.image";
const APP0_PREFIX: &[u8] = b"/app0/";
/// `/app0/kraken/`, a 255-byte name (d_namlen is a u8) and the NUL.
const KRAKEN_PKG_PATH_MAX: usize = b"/app0/kraken/".len() + 256;
/// Longest `kraken.image` path that fits `KRAKEN_PKG_PATH_MAX` with the
/// prefix and the NUL.
const IMAGE_PATH_MAX: usize = KRAKEN_PKG_PATH_MAX - APP0_PREFIX.len() - 1;
/// NUL-terminated `/app0/<kraken.image>` (269 B); written once in
/// select_pack_format before any reader, opened only in pkg mode.
static mut KRAKEN_PKG_PATH: [u8; KRAKEN_PKG_PATH_MAX] = [0; KRAKEN_PKG_PATH_MAX];

/// The .pkg path with its NUL (empty slice before a valid kraken.image).
pub(crate) fn kraken_pkg_path() -> &'static [u8] {
    // Written only before the format is set, read only after.
    let buf = unsafe { &*core::ptr::addr_of!(KRAKEN_PKG_PATH) };
    match buf.iter().position(|&b| b == 0) {
        Some(n) if n > 0 => &buf[..=n],
        _ => &[],
    }
}

/// How discovery ended, for the black box line (`log_discovery`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Found {
    NoImage = 0,
    /// kraken.image unreadable, not a regular file, or its path refused
    /// (`ampr_pkg::kraken_image_path`); detail is the open errno or 0.
    BadImage,
    /// The named .pkg failed to open; detail is the errno.
    Open,
    /// The named .pkg is not a regular file.
    NotRegular,
    /// The AMPRPAK4 manifest could not be read.
    NoManifest,
    /// The .pkg size, page-aligned, is not pack 0's; detail is the size.
    Size,
    Ok,
}
static FOUND: AtomicU8 = AtomicU8::new(Found::NoImage as u8);
/// errno or .pkg size of the outcome, see `Found`.
static DETAIL: AtomicU64 = AtomicU64::new(0);

// ---- discovery ----

/// Fills `buf` from `off`; false on an error or a short file.
unsafe fn pread_full(fd: c_int, buf: &mut [u8], off: u64) -> bool {
    // pread_loop continues short reads and retries EINTR, so a signal at
    // module_start does not fail discovery.
    let out = buf.as_mut_ptr();
    super::state::pread_loop(
        buf.len(),
        off,
        AMPR_EMU_PACK_PREAD_MAX_BYTES as usize,
        |done, request, at| unsafe {
            sys::real_physical_pread(fd, out.add(done).cast(), request, at)
        },
        sys::errno,
    )
}

/// Opens read-only through `sys::real_posix_open`: the pre-detour slot, or
/// before hooks install (module_start) the libkernel `open` symbol, so the
/// call never enters the runtime's own open hook.
unsafe fn open_ro(path: *const c_char) -> c_int {
    unsafe { sys::real_posix_open(path, O_RDONLY, 0) }
}

/// Size of open `fd` when it is a regular file.
unsafe fn regular_size(fd: c_int) -> Option<u64> {
    let mut st = Stat::default();
    (unsafe { sys::real_physical_fstat(fd, (&raw mut st).cast()) } == 0 && st.is_reg())
        .then_some(st.st_size.max(0) as u64)
}

/// Pack record 0 from the AMPRPAK4 manifest.
unsafe fn manifest_identity() -> Option<ampr_pkg::ManifestIdentity> {
    let fd = unsafe { open_ro(AMPR_EMU_PACK_INDEX_PATH.as_ptr()) };
    if fd < 0 {
        return None;
    }
    let id = ampr_pkg::manifest_identity(|off, buf| unsafe { pread_full(fd, buf, off) });
    let _ = unsafe { sys::real_physical_close(fd) };
    id
}

/// Reads kraken.image and stores `/app0/<path>` in `KRAKEN_PKG_PATH`.
unsafe fn read_image() -> Result<(), (Found, u64)> {
    let fd = unsafe { open_ro(KRAKEN_IMAGE.as_ptr()) };
    if fd < 0 {
        let e = sys::errno();
        return Err(if e == ENOENT {
            (Found::NoImage, 0)
        } else {
            (Found::BadImage, e as u64)
        });
    }
    // Room for the longest path and a line end. Only the first line counts:
    // bytes past it are not read, and a first line longer than
    // IMAGE_PATH_MAX is refused.
    let mut raw = [0u8; IMAGE_PATH_MAX + 2];
    let n = unsafe { regular_size(fd) }.map(|s| s.min(raw.len() as u64) as usize);
    let read = n.is_some_and(|n| unsafe { pread_full(fd, &mut raw[..n], 0) });
    let _ = unsafe { sys::real_physical_close(fd) };
    let path = n
        .filter(|_| read)
        .and_then(|n| ampr_pkg::kraken_image_path(&raw[..n], IMAGE_PATH_MAX))
        .ok_or((Found::BadImage, 0))?;
    let out = unsafe { &mut *core::ptr::addr_of_mut!(KRAKEN_PKG_PATH) };
    out[..APP0_PREFIX.len()].copy_from_slice(APP0_PREFIX);
    out[APP0_PREFIX.len()..][..path.len()].copy_from_slice(path);
    out[APP0_PREFIX.len() + path.len()] = 0;
    Ok(())
}

/// kraken.image, then the .pkg it names: a regular file whose size,
/// page-aligned, is the manifest's pack 0 size.
unsafe fn find_pkg() -> (Found, u64) {
    if let Err(e) = unsafe { read_image() } {
        return e;
    }
    let fd = unsafe { open_ro(kraken_pkg_path().as_ptr().cast()) };
    if fd < 0 {
        return (Found::Open, sys::errno() as u64);
    }
    let size = unsafe { regular_size(fd) };
    let _ = unsafe { sys::real_physical_close(fd) };
    let Some(size) = size else {
        return (Found::NotRegular, 0);
    };
    let Some(id) = (unsafe { manifest_identity() }) else {
        return (Found::NoManifest, size);
    };
    if !ampr_pkg::pkg_size_matches(size, &id) {
        return (Found::Size, size);
    }
    (Found::Ok, size)
}

/// module_start, before hooks (`select_pack_format`): true when
/// `/app0/kraken.image` names this title's .pkg (`KRAKEN_PKG_PATH`). A
/// title without kraken.image costs one failed open.
pub(super) unsafe fn discover_pkg() -> bool {
    let (found, detail) = unsafe { find_pkg() };
    FOUND.store(found as u8, Ordering::Relaxed);
    DETAIL.store(detail, Ordering::Relaxed);
    found == Found::Ok
}

/// One black box line on how discovery ended; module_start calls it once
/// the black box is open (debug build only).
#[cfg(feature = "mem_report")]
pub(crate) fn log_discovery() {
    let how: &[u8] = match FOUND.load(Ordering::Relaxed) {
        x if x == Found::NoImage as u8 => b"noimage",
        x if x == Found::BadImage as u8 => b"badimage",
        x if x == Found::Open as u8 => b"open",
        x if x == Found::NotRegular as u8 => b"notregular",
        x if x == Found::NoManifest as u8 => b"nomanifest",
        x if x == Found::Size as u8 => b"size",
        _ => b"ok",
    };
    crate::rt::blackbox::pkg(how, DETAIL.load(Ordering::Relaxed), kraken_pkg_path());
}

// ---- pkg volume ----

/// Pack 0 is a .pkg with no AMPRDAT3 header: chunk offsets are absolute
/// .pkg byte offsets, so the payload starts at byte 0. The pack record's
/// `file_size` must be the .pkg size aligned up to `io_page_size`
/// (`ampr_pkg::pkg_payload_end`), which refuses a .pkg other than the one
/// the manifest was built from. Chunks are read with exact-size reads that
/// never pass the .pkg end, so the payload ends at its real size and a
/// chunk past it (a truncated .pkg) fails the window range check with EIO
/// (window_aio.rs `prepare_exact_window_aio`).
pub(crate) unsafe fn validate_pkg_volume(
    state: *const PackState,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    if payload_begin.is_null() || payload_end.is_null() {
        return false;
    }
    let Some(record) = (unsafe { lz4_pack(state, 0) }) else {
        return false;
    };
    if ampr_pkg::pkg_payload_end(file_size, record.io_page_size, record.file_size).is_none() {
        return false;
    }
    *payload_begin = 0;
    *payload_end = file_size;
    true
}

// ---- pack volumes ----

/// leases.rs `build_pack_path`, pkg arm: pack 0 is the .pkg itself,
/// whatever its record name says; packs 1 and up are AMPRDAT3 volumes.
pub(super) unsafe fn build_pack_path_pkg(
    state: *const PackState,
    pack_id: u16,
    output: *mut c_char,
    output_size: usize,
) -> bool {
    if pack_id != 0 {
        return unsafe { build_pack_path_lz4(state, pack_id, output, output_size) };
    }
    let path = kraken_pkg_path();
    if output.is_null()
        || (*state).header.is_null()
        || { (*(*state).header).pack_count } == 0
        || path.is_empty()
        || path.len() > output_size
    {
        return false;
    }
    unsafe { copy_nonoverlapping(path.as_ptr(), output as *mut u8, path.len()) };
    true
}

/// leases.rs `validate_data_header`, pkg arm: pack 0 gets the .pkg size
/// check (`validate_pkg_volume`), packs 1 and up the AMPRDAT3 header check.
pub(super) unsafe fn validate_data_header_pkg(
    state: *const PackState,
    pack_id: u16,
    fd: c_int,
    file_size: u64,
    payload_begin: *mut u64,
    payload_end: *mut u64,
) -> bool {
    if pack_id == 0 {
        unsafe { validate_pkg_volume(state, file_size, payload_begin, payload_end) }
    } else {
        unsafe {
            validate_data_header_lz4(state, pack_id, fd, file_size, payload_begin, payload_end)
        }
    }
}

// ---- KRAKEN chunks ----
//
// No new memory: a KRAKEN block is at most ampr_pkg::kraken::BLOCK (256 KiB) and the
// worker's decoded scratch is PACK_MAX_BLOCK_BYTES (1 MiB, Buffer ledger,
// worker.rs ensure_workers_locked), so the decoder's ampr_pkg::kraken::Scratch
// (233472 B) lives at [ampr_pkg::kraken::BLOCK, ampr_pkg::kraken::BLOCK + Scratch::SIZE) of it.
// [0, ampr_pkg::kraken::BLOCK) is the decoded chunk when the worker decodes into its
// scratch (partial reads), else the temp block of a CHUNK_KRAKEN_FULL chunk.
const _: () = assert!(
    ampr_pkg::kraken::BLOCK + ampr_pkg::kraken::Scratch::SIZE <= PACK_MAX_BLOCK_BYTES
        // Scratch sits ampr_pkg::kraken::BLOCK into the scratch, so any alignment that
        // divides BLOCK holds there (the base is checked at run time).
        && ampr_pkg::kraken::BLOCK.is_multiple_of(core::mem::align_of::<ampr_pkg::kraken::Scratch>())
);

/// One KRAKEN chunk into `destination` (`chunk.raw_size` bytes, never more).
/// A CHUNK_KRAKEN_FULL block (logical ampr_pkg::kraken::BLOCK) longer than that goes
/// through the scratch's first ampr_pkg::kraken::BLOCK bytes, then its first raw bytes
/// are copied, unless `destination` is that scratch (1 MiB, room for it).
pub(crate) unsafe fn decode_kraken_chunk(
    worker: &WorkerContext,
    chunk: &AmprPackChunkView,
    stored: *const u8,
    destination: *mut u8,
) -> c_int {
    let raw = chunk.raw_size as usize;
    let base = worker.decoded_scratch;
    if base.is_null()
        || !(base as usize).is_multiple_of(core::mem::align_of::<ampr_pkg::kraken::Scratch>())
        || worker.decoded_scratch_size < ampr_pkg::kraken::BLOCK + ampr_pkg::kraken::Scratch::SIZE
        || raw == 0
        || raw > ampr_pkg::kraken::BLOCK
    {
        return SCE_KERNEL_ERROR_EIO;
    }
    let full = chunk.flags & AMPR_PACK_CHUNK_KRAKEN_FULL != 0;
    let logical = ampr_pkg::kraken_decode_len(raw, full);
    let temp = logical > raw && destination != base;
    let (even_len, mode) = ampr_pkg::kraken_desc(chunk.kraken);
    let desc = ampr_pkg::kraken::Desc { even_len, mode };
    unsafe {
        // SAFETY: Scratch holds u16 Huffman tables (align 2): the base
        // alignment is checked above and ampr_pkg::kraken::BLOCK keeps it (const
        // assert); any bit pattern is a valid u8/u16. The worker owns its
        // scratch and decodes one chunk at a time.
        let scratch = &mut *(base.add(ampr_pkg::kraken::BLOCK) as *mut ampr_pkg::kraken::Scratch);
        let input = core::slice::from_raw_parts(stored, chunk.stored_size as usize);
        let out = if temp { base } else { destination };
        let output = core::slice::from_raw_parts_mut(out, logical);
        if ampr_pkg::kraken::decode_block(input, desc, output, scratch).is_err() {
            return SCE_KERNEL_ERROR_EIO;
        }
        if temp {
            copy_nonoverlapping(base, destination, raw);
        }
    }
    0
}
