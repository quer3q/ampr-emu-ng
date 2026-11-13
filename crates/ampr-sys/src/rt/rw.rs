//! Writable /app0: the launcher can mount /app0 read-write (a dump folder,
//! or a pkg title's cache dir). Files the game writes are never in its
//! packs, so a write only needs the real filesystem: a miss is never
//! authoritative, and a create in a packed-only directory makes its real
//! parents first. Every use is gated on `app0_writable()`; a read-only
//! /app0 pays one Relaxed load and answers as upstream.

use super::sys;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, Ordering};

// ---- mode ----

static APP0_WRITABLE: AtomicBool = AtomicBool::new(false);

/// True when /app0 took `access(W_OK)` at module_start (not a read-only mount).
#[inline(always)]
pub(crate) fn app0_writable() -> bool {
    APP0_WRITABLE.load(Ordering::Relaxed)
}

const APP0_PREFIX: &[u8] = b"/app0/";
const CREATE_MODE: sys::SceKernelMode = 0o777;

/// module_start, before the hooks: decides the mode.
pub(crate) unsafe fn init() {
    if unsafe { app0_access_writable() } {
        APP0_WRITABLE.store(true, Ordering::Relaxed);
    }
}

/// access("/app0", W_OK) succeeded: the kernel refuses W_OK with EROFS on
/// a read-only mount, the same test statfs's MNT_RDONLY would give, and
/// libkernel exports neither statfs nor fstatfs (docs/read-path-tuning.md).
/// Any error reads as read-only, today's behaviour. Resolved by name, as
/// `select_pack_format` resolves stat: no hook is installed yet, so the
/// symbol is the real call.
unsafe fn app0_access_writable() -> bool {
    type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
    const W_OK: c_int = 2;
    unsafe { sys::resolve_kernel::<AccessFn>(c"access") }
        .is_some_and(|f| unsafe { f(c"/app0".as_ptr(), W_OK) == 0 })
}

// ---- parents ----

/// Makes directory `dir` (below /app0) and any missing ancestor: a
/// packed-only directory has no real copy. `buf` is scratch.
pub(crate) unsafe fn make_dirs(dir: &[u8], buf: &mut [u8]) -> Result<(), c_int> {
    type F = unsafe extern "C" fn(*const c_char, sys::SceKernelMode) -> c_int;
    // mkdir is never hooked: the symbol is the real call. Resolved once,
    // not on every creating open.
    static MKDIR: sys::LazySym = sys::LazySym::new(c"mkdir");
    let Some(mkdir) = (unsafe { MKDIR.get::<F>() }) else {
        return Err(sys::EIO);
    };
    make_dirs_with(dir, buf, |p| {
        if unsafe { mkdir(p.as_ptr().cast(), CREATE_MODE) } == 0 {
            0
        } else {
            sys::errno()
        }
    })
}

/// Walks up from `dir` to the first level that exists or can be made
/// (EEXIST or success), then makes the levels below it, so a parent that
/// already exists costs one mkdir. `mkdir` gets a NUL-terminated path and
/// returns 0 or the errno.
fn make_dirs_with(
    dir: &[u8],
    buf: &mut [u8],
    mut mkdir: impl FnMut(&[u8]) -> c_int,
) -> Result<(), c_int> {
    if dir.len() >= buf.len() {
        return Err(sys::ENAMETOOLONG);
    }
    buf[..dir.len()].copy_from_slice(dir);
    let mut end = dir.len();
    loop {
        buf[end] = 0;
        match mkdir(&buf[..=end]) {
            0 | sys::EEXIST => break,
            sys::ENOENT => match dir[..end].iter().rposition(|&b| b == b'/') {
                // /app0 itself is never made.
                Some(c) if c >= APP0_PREFIX.len() => end = c,
                _ => return Err(sys::ENOENT),
            },
            e => return Err(e),
        }
    }
    while end < dir.len() {
        buf[end] = b'/';
        end = dir[end + 1..]
            .iter()
            .position(|&b| b == b'/')
            .map_or(dir.len(), |p| end + 1 + p);
        buf[end] = 0;
        match mkdir(&buf[..=end]) {
            0 | sys::EEXIST => {}
            e => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `make_dirs_with` over a fake FS holding `existing`; returns
    /// the result and every mkdir it made, in order.
    fn run(dir: &str, existing: &[&str]) -> (Result<(), c_int>, Vec<String>) {
        let mut fs: Vec<String> = existing.iter().map(|s| (*s).into()).collect();
        let mut calls = Vec::new();
        let mut buf = [0u8; 64];
        let r = make_dirs_with(dir.as_bytes(), &mut buf, |p| {
            let (nul, path) = p.split_last().unwrap();
            assert_eq!(*nul, 0);
            let path = String::from_utf8(path.to_vec()).unwrap();
            calls.push(path.clone());
            let parent = &path[..path.rfind('/').unwrap()];
            if fs.contains(&path) {
                sys::EEXIST
            } else if parent != "/app0" && !fs.iter().any(|d| d == parent) {
                sys::ENOENT
            } else {
                fs.push(path);
                0
            }
        });
        (r, calls)
    }

    #[test]
    fn existing_parent_costs_one_mkdir() {
        let (r, calls) = run("/app0/a/b", &["/app0/a", "/app0/a/b"]);
        assert_eq!(r, Ok(()));
        assert_eq!(calls, ["/app0/a/b"]);
    }

    #[test]
    fn missing_levels_are_made_top_down() {
        let (r, calls) = run("/app0/a/b/c", &["/app0/a"]);
        assert_eq!(r, Ok(()));
        assert_eq!(calls, ["/app0/a/b/c", "/app0/a/b", "/app0/a/b/c"]);
        let (r, calls) = run("/app0/a/b", &[]);
        assert_eq!(r, Ok(()));
        assert_eq!(calls, ["/app0/a/b", "/app0/a", "/app0/a/b"]);
    }

    #[test]
    fn too_long_or_failing_mkdir_is_reported() {
        let long = format!("/app0/{}", "x".repeat(64));
        assert_eq!(run(&long, &[]).0, Err(sys::ENAMETOOLONG));
        let mut buf = [0u8; 64];
        assert_eq!(
            make_dirs_with(b"/app0/a", &mut buf, |_| sys::EIO),
            Err(sys::EIO)
        );
    }
}
