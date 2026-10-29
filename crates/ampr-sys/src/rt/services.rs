//! The APR resolve/size/stat services, the command-buffer submit front end,
//! the libkernel `_emul` hook targets wrapping them, and the reactor's shared
//! helpers. The reactor itself is rt/reactor.
#![allow(non_snake_case)]

use super::fd_cache::FileEntryView;
use super::sys::*;
use ampr_command::SceAmprCommandBuffer;
use core::ffi::{c_char, c_int, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

type SceAprResultBuffer = SceAmmResultBuffer; // identical {int, uint32}

const RESOLVE_MAX: u32 = 1024; // SCE_AMPR_APR_RESOLVE_MAX
const FILEID_INVALID: u32 = u32::MAX; // SCE_AMPR_APR_FILEID_INVALID
const PATH_MAX: usize = 1024; // SCE_KERNEL_PATH_MAX
const PRIO_MAX: u32 = 6; // kAprPriorityMax
const HOOK_APR_WAIT: usize = 32; // kAmprLibkernelHook_sceKernelAprWaitCommandBuffer

// AprSubmitMode
const MODE_SUBMIT: u8 = 0;
const MODE_GET_RESULT: u8 = 1;
const MODE_GET_ID: u8 = 2;

/// `Job`: one reactor job record (layout shared with rt/reactor).
#[repr(C)]
struct Job {
    id: u64,
    source_buffer: *const c_void,
    source_bytes: u32,
    source_command_count: u32,
    submit_mode: u8,
    native_submit_type: c_int,
    native_prio: u32,
    apr_res: *mut SceAprResultBuffer,
}
const _: () = {
    assert!(size_of::<Job>() == 48);
    assert!(offset_of!(Job, source_bytes) == 16);
    assert!(offset_of!(Job, submit_mode) == 24);
    assert!(offset_of!(Job, native_submit_type) == 28);
    assert!(offset_of!(Job, native_prio) == 32);
    assert!(offset_of!(Job, apr_res) == 40);
};

/// FreeBSD 11 amd64 `struct stat` == `SceKernelStat` (size asserted
/// below); only the fields we fill are named.
#[repr(C)]
pub struct SceKernelStat {
    _dev_ino: [u32; 2],
    st_mode: u16,
    _pad0: [u8; 30],
    st_mtim: SceKernelTimespec,
    _ctim: SceKernelTimespec,
    st_size: i64,
    _rest: [u8; 40],
}
const _: () = {
    assert!(size_of::<SceKernelStat>() == 120);
    assert!(offset_of!(SceKernelStat, st_mode) == 8);
    assert!(offset_of!(SceKernelStat, st_mtim) == 40);
    assert!(offset_of!(SceKernelStat, st_size) == 72);
};

use super::index::{ampr_index_get_entry_view, ampr_index_resolve_path_to_id};
use super::reactor::{apr_reactor_submit, apr_reactor_wait_synthetic_submit_id};

/// Index rc (+/- posix errno) to SCE.
fn index_rc_to_sce(rc: c_int) -> c_int {
    sce_errno_from_posix(rc.wrapping_abs())
}

// ---- reactor_common ------------------------------------------------------

pub fn time_counter_now() -> u64 {
    monotonic_ns()
}

/// Raw libkernel rc (SCE error, -1 with errno, or positive posix errno) to SCE.
pub fn apr_libkernel_rc_to_sce(rc: c_int) -> c_int {
    if rc == 0 || rc as u32 & 0xFFFF_0000 == 0x8002_0000 {
        return rc;
    }
    if rc < 0 {
        let e = errno();
        return sce_errno_from_posix(if e != 0 { e } else { EIO });
    }
    sce_errno_from_posix(rc)
}

// ---- resolve services ----------------------------------------------------

type Paths = *const *const c_char;

/// `prefix` + ('/' unless it ends in a separator) + `path` into `out`; posix rc.
unsafe fn join_prefix_path(
    prefix: *const c_char,
    path: *const c_char,
    out: &mut [u8; PATH_MAX],
) -> Result<(), c_int> {
    let plen = strnlen(prefix, PATH_MAX);
    let len = strnlen(path, PATH_MAX);
    if plen == PATH_MAX || len == PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    let last = if plen != 0 {
        *prefix.add(plen - 1) as u8
    } else {
        b'/'
    };
    let fixed = plen + (last != b'/' && last != b'\\') as usize;
    if fixed >= PATH_MAX || len > PATH_MAX - fixed - 1 {
        return Err(ENAMETOOLONG);
    }
    core::ptr::copy_nonoverlapping(prefix.cast(), out.as_mut_ptr(), plen);
    out[plen] = b'/';
    core::ptr::copy_nonoverlapping(path.cast(), out.as_mut_ptr().add(fixed), len);
    out[fixed + len] = 0;
    Ok(())
}

/// One (optionally prefixed) path to (id, size); SCE rc on failure.
unsafe fn resolve_one(
    pre: Option<*const c_char>,
    path: *const c_char,
    want_size: bool,
) -> Result<(u32, usize), c_int> {
    let mut full = [0u8; PATH_MAX];
    let p = match pre {
        None => path,
        Some(prefix) => {
            join_prefix_path(prefix, path, &mut full).map_err(sce_errno_from_posix)?;
            full.as_ptr().cast()
        }
    };
    let (mut id, mut size) = (FILEID_INVALID, 0usize);
    let rc =
        ampr_index_resolve_path_to_id(p, &mut id, if want_size { &mut size } else { null_mut() });
    if rc != 0 {
        return Err(index_rc_to_sce(rc));
    }
    Ok((id, size))
}

/// Count, then prefix/outputs/path-array null checks.
unsafe fn validate(pre: Option<*const c_char>, path: Paths, num: u32, outs_ok: bool) -> c_int {
    if num == 0 || num > RESOLVE_MAX {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if pre.is_some_and(|p| p.is_null())
        || !outs_ok
        || path.is_null()
        || (0..num as usize).any(|i| (*path.add(i)).is_null())
    {
        return SCE_KERNEL_ERROR_EFAULT;
    }
    0
}

/// Stops at the first failure, reporting its index; SCE rc.
unsafe fn resolve_all(
    pre: Option<*const c_char>,
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    want_size: bool,
    err: *mut u32,
) -> c_int {
    let rc = validate(
        pre,
        path,
        num,
        !ids.is_null() && (!want_size || !sizes.is_null()),
    );
    if rc != 0 {
        return rc;
    }
    if !err.is_null() {
        *err = 0;
    }
    for i in 0..num as usize {
        match resolve_one(pre, *path.add(i), want_size) {
            Ok((id, size)) => {
                *ids.add(i) = id;
                if want_size {
                    *sizes.add(i) = size;
                }
            }
            Err(rc) => {
                if !err.is_null() {
                    *err = i as u32;
                }
                return rc;
            }
        }
    }
    0
}

/// Per-item results; returns the resolved count or a validation SCE rc.
unsafe fn resolve_each(
    pre: Option<*const c_char>,
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    want_size: bool,
    results: *mut c_int,
) -> c_int {
    let outs_ok = !ids.is_null() && !results.is_null() && (!want_size || !sizes.is_null());
    let rc = validate(pre, path, num, outs_ok);
    if rc != 0 {
        return rc;
    }
    let mut resolved = 0;
    for i in 0..num as usize {
        let r = resolve_one(pre, *path.add(i), want_size);
        let (id, size) = r.unwrap_or((FILEID_INVALID, 0));
        *results.add(i) = r.err().unwrap_or(0);
        *ids.add(i) = id;
        if want_size {
            *sizes.add(i) = size;
        }
        resolved += r.is_ok() as c_int;
    }
    resolved
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsToIds_emul(
    path: Paths,
    num: u32,
    ids: *mut u32,
    err: *mut u32,
) -> c_int {
    libkernel_return_from_sce(resolve_all(None, path, num, ids, null_mut(), false, err))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsToIdsAndFileSizes_emul(
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    err: *mut u32,
) -> c_int {
    libkernel_return_from_sce(resolve_all(None, path, num, ids, sizes, true, err))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsWithPrefixToIds_emul(
    prefix: *const c_char,
    path: Paths,
    num: u32,
    ids: *mut u32,
    err: *mut u32,
) -> c_int {
    libkernel_return_from_sce(resolve_all(
        Some(prefix),
        path,
        num,
        ids,
        null_mut(),
        false,
        err,
    ))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul(
    prefix: *const c_char,
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    err: *mut u32,
) -> c_int {
    libkernel_return_from_sce(resolve_all(Some(prefix), path, num, ids, sizes, true, err))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsToIdsForEach_emul(
    path: Paths,
    num: u32,
    ids: *mut u32,
    results: *mut c_int,
) -> c_int {
    libkernel_return_from_sce_count(resolve_each(
        None,
        path,
        num,
        ids,
        null_mut(),
        false,
        results,
    ))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul(
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    results: *mut c_int,
) -> c_int {
    libkernel_return_from_sce_count(resolve_each(None, path, num, ids, sizes, true, results))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul(
    prefix: *const c_char,
    path: Paths,
    num: u32,
    ids: *mut u32,
    results: *mut c_int,
) -> c_int {
    libkernel_return_from_sce_count(resolve_each(
        Some(prefix),
        path,
        num,
        ids,
        null_mut(),
        false,
        results,
    ))
}

pub unsafe extern "C" fn sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul(
    prefix: *const c_char,
    path: Paths,
    num: u32,
    ids: *mut u32,
    sizes: *mut usize,
    results: *mut c_int,
) -> c_int {
    libkernel_return_from_sce_count(resolve_each(
        Some(prefix),
        path,
        num,
        ids,
        sizes,
        true,
        results,
    ))
}

pub unsafe extern "C" fn sceKernelAprGetFileSize_emul(file_id: c_int, out_size: *mut u64) -> c_int {
    if out_size.is_null() {
        return libkernel_return_from_sce(SCE_KERNEL_ERROR_EFAULT);
    }
    let mut e: FileEntryView = core::mem::zeroed();
    let rc = ampr_index_get_entry_view(file_id as u32, &mut e);
    if rc != 0 {
        return libkernel_return_from_sce(index_rc_to_sce(rc));
    }
    *out_size = e.size as u64;
    0
}

pub unsafe extern "C" fn sceKernelAprGetFileStat_emul(
    file_id: c_int,
    st: *mut SceKernelStat,
) -> c_int {
    if st.is_null() {
        return libkernel_return_from_sce(SCE_KERNEL_ERROR_EFAULT);
    }
    let mut e: FileEntryView = core::mem::zeroed();
    let rc = ampr_index_get_entry_view(file_id as u32, &mut e);
    if rc != 0 {
        return libkernel_return_from_sce(index_rc_to_sce(rc));
    }
    core::ptr::write_bytes(st, 0, 1);
    (*st).st_size = e.size as i64;
    (*st).st_mode = 0o100000 | 0o777; // S_IFREG | 0777
    (*st).st_mtim.tv_sec = e.mtime;
    0
}

// ---- submit / wait -------------------------------------------------------

static NEXT_SUBMIT_ID: AtomicU64 = AtomicU64::new(1);

unsafe fn reject(res: *mut SceAprResultBuffer, rc: c_int) -> c_int {
    if !res.is_null() {
        *res = SceAprResultBuffer {
            result: rc,
            error_offset: 0,
        };
    }
    rc
}

/// Bridge + service submit: validates, snapshots the header into a Job and
/// hands it to the reactor. `test` replaces the source buffer (`_TEST`).
/// `cb` is a game AprCommandBuffer whose first member is SceAmprCommandBuffer.
unsafe fn submit(
    cb: *mut c_void,
    prio: u32,
    mode: u8,
    res: *mut SceAprResultBuffer,
    id: *mut SceAprSubmitId,
    test: Option<*const c_void>,
) -> c_int {
    if prio > PRIO_MAX {
        return reject(res, SCE_KERNEL_ERROR_EINVAL);
    }
    if cb.is_null() {
        return SCE_KERNEL_ERROR_EPERM;
    }
    let raw = cb as *const SceAmprCommandBuffer;
    let buffer = (*raw).buffer as *const c_void;
    let bytes = (*raw).offset;
    if buffer.is_null() {
        return SCE_KERNEL_ERROR_EPERM;
    }
    if bytes == 0 {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    let source = test.unwrap_or(buffer);
    let count = core::ptr::read_volatile(core::ptr::addr_of!((*raw).num));
    if source.is_null() {
        return reject(res, SCE_KERNEL_ERROR_EPERM);
    }
    if count <= 0 || bytes > (*raw).bufsize {
        return reject(res, SCE_KERNEL_ERROR_EINVAL);
    }
    let job = Job {
        id: NEXT_SUBMIT_ID.fetch_add(1, Relaxed),
        source_buffer: source,
        source_bytes: bytes,
        source_command_count: count as u32,
        submit_mode: mode,
        // cb_native_submit_type: strip scatter-gather-valid / map-active bits.
        native_submit_type: ((*raw).r#type as u32 & !0x0003_0000) as c_int,
        native_prio: prio,
        apr_res: res,
    };
    let mut submit_id: SceAprSubmitId = 0;
    let rc = apr_reactor_submit(
        (&job as *const Job).cast(),
        if id.is_null() {
            null_mut()
        } else {
            &mut submit_id
        },
    );
    if rc != 0 {
        return reject(res, rc);
    }
    if !id.is_null() {
        *id = submit_id;
    }
    0
}

pub unsafe extern "C" fn sceKernelAprSubmitCommandBuffer_emul(cb: *mut c_void, prio: u32) -> c_int {
    libkernel_return_from_sce(submit(cb, prio, MODE_SUBMIT, null_mut(), null_mut(), None))
}

pub unsafe extern "C" fn sceKernelAprSubmitCommandBuffer_TEST_emul(
    cb: *mut c_void,
    prio: u32,
    test: *mut c_void,
) -> c_int {
    libkernel_return_from_sce(submit(
        cb,
        prio,
        MODE_SUBMIT,
        null_mut(),
        null_mut(),
        Some(test),
    ))
}

pub unsafe extern "C" fn sceKernelAprSubmitCommandBufferAndGetResult_emul(
    cb: *mut c_void,
    prio: u32,
    res: *mut SceAprResultBuffer,
    id: *mut SceAprSubmitId,
) -> c_int {
    libkernel_return_from_sce(submit(cb, prio, MODE_GET_RESULT, res, id, None))
}

pub unsafe extern "C" fn sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul(
    cb: *mut c_void,
    prio: u32,
    res: *mut SceAprResultBuffer,
    id: *mut SceAprSubmitId,
    test: *mut c_void,
) -> c_int {
    libkernel_return_from_sce(submit(cb, prio, MODE_GET_RESULT, res, id, Some(test)))
}

pub unsafe extern "C" fn sceKernelAprSubmitCommandBufferAndGetId_emul(
    cb: *mut c_void,
    prio: u32,
    id: *mut SceAprSubmitId,
) -> c_int {
    libkernel_return_from_sce(submit(cb, prio, MODE_GET_ID, null_mut(), id, None))
}

/// Synthetic (reactor-owned) ids first, else the original libkernel wait.
unsafe fn wait(id: SceAprSubmitId, hook_id: usize) -> c_int {
    let mut handled = false;
    let rc = apr_reactor_wait_synthetic_submit_id(id, &mut handled);
    if handled {
        return libkernel_return_from_sce(rc);
    }
    match kernel_slot::<unsafe extern "C" fn(SceAprSubmitId) -> c_int>(hook_id) {
        Some(f) => f(id),
        None => libkernel_return_from_sce(SCE_KERNEL_ERROR_ENOSYS),
    }
}

pub unsafe extern "C" fn sceKernelAprWaitCommandBuffer_emul(id: SceAprSubmitId) -> c_int {
    wait(id, HOOK_APR_WAIT)
}

pub unsafe extern "C" fn sceKernelWaitCommandBufferCompletion_emul(id: SceAprSubmitId) -> c_int {
    wait(id, hook::sceKernelWaitCommandBufferCompletion)
}
