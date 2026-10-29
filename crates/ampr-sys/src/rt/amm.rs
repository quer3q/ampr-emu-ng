//! AMM runtime: libkernel AMM writer hooks, mapper/submit leaves, the
//! AmmCommandBuffer record writers and the measure helpers.
#![allow(non_snake_case)]

use core::ffi::{c_int, c_void};
use core::ptr::{addr_of, addr_of_mut, null_mut, read_volatile, write_volatile};

use ampr_command::SceAmprCommandBuffer;

use super::sys::{
    self, hook, off_t, LazySym, SceAmmResultBuffer, SceAmmSubmitId, SCE_KERNEL_ERROR_EBUSY,
    SCE_KERNEL_ERROR_EINVAL, SCE_KERNEL_ERROR_ENXIO, SCE_KERNEL_ERROR_EPERM,
};

use super::index::ampr_index_ensure_ready_safe;
use super::runtime_memory::ampr_internal_amm_pool_prepare_static_storage;

// ---- protection helpers -----------------------------------------------------

const CPU_READ: u64 = sys::SCE_KERNEL_PROT_CPU_READ as u64;
const CPU_RW: u64 = sys::SCE_KERNEL_PROT_CPU_RW as u64;
const CPU_ALL: u64 = sys::SCE_KERNEL_PROT_CPU_ALL as u64;
const AMPR_WRITE: u64 = sys::SCE_KERNEL_PROT_AMPR_WRITE as u64;
const AMPR_ALL: u64 = sys::SCE_KERNEL_PROT_AMPR_ALL as u64;

/// `protWithCpuRwForAmprWrite`: AMPR-write destinations publish CPU_RW.
pub(super) const fn prot_with_cpu_rw(prot: u64) -> u64 {
    if prot & AMPR_WRITE == 0 {
        prot
    } else {
        (prot & !CPU_READ) | CPU_RW
    }
}

/// `protMaskWithCpuRwForAdjustedProt`: mask also covers changed CPU bits.
const fn mask_with_cpu_rw(orig: u64, adjusted: u64, mask: u64) -> u64 {
    mask | ((orig ^ adjusted) & CPU_ALL)
}

const _: () = {
    assert!(prot_with_cpu_rw(CPU_READ | AMPR_ALL) == CPU_RW | AMPR_ALL);
    assert!(
        mask_with_cpu_rw(CPU_READ | AMPR_ALL, CPU_RW | AMPR_ALL, AMPR_ALL)
            == CPU_READ | CPU_RW | AMPR_ALL
    );
};

const RETAIL_PROT_INVALID_MASK: u32 = 0xFFFF_FC0C;

/// `ammKernelProt`.
const fn kernel_prot(prot: u32) -> u32 {
    prot | ((prot >> 1) & 0x141)
}

/// `amm_prepare_cpu_visible_kernel_prot`.
fn cpu_visible_prot(prot: c_int) -> Result<u64, c_int> {
    let raw = prot as u32;
    if raw & RETAIL_PROT_INVALID_MASK != 0 {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    Ok(kernel_prot(prot_with_cpu_rw(raw as u64) as u32) as u64)
}

/// `amm_prepare_cpu_visible_kernel_prot_pair`.
fn cpu_visible_prot_pair(prot: c_int, mask: c_int) -> Result<(u64, u64), c_int> {
    let (raw, raw_mask) = (prot as u32, mask as u32);
    if raw & RETAIL_PROT_INVALID_MASK != 0 || raw_mask & RETAIL_PROT_INVALID_MASK != 0 {
        return Err(SCE_KERNEL_ERROR_EINVAL);
    }
    let adj = prot_with_cpu_rw(raw as u64);
    let adj_mask = mask_with_cpu_rw(raw as u64, adj, raw_mask as u64);
    Ok((
        kernel_prot(adj as u32) as u64,
        kernel_prot(adj_mask as u32) as u64,
    ))
}

// ---- kernel writers (original libkernel slots) ----------------------------

/// Original slot `id`; a missing mandatory slot crashes (null call).
unsafe fn slot<F: Copy>(id: usize) -> F {
    match unsafe { sys::kernel_slot::<F>(id) } {
        Some(f) => f,
        None => sys::abort(),
    }
}

/// Defines `fn $name(dst, <u64 args>, out)` forwarding to original slot `$id`.
macro_rules! writer {
    ($name:ident, $id:ident, ($($a:ident),*)) => {
        pub unsafe fn $name(dst: *mut c_void, $($a: u64,)* out: *mut u64) -> c_int {
            type F = unsafe extern "C" fn(*mut c_void, $(writer!(@u64 $a),)* *mut u64) -> c_int;
            unsafe { slot::<F>(hook::$id)(dst, $($a,)* out) }
        }
    };
    (@u64 $a:ident) => { u64 };
}

writer!(
    ammWriteMapCommand2,
    sceKernelWriteMapCommand2,
    (va, size, ty, prot, prt)
);
writer!(
    ammWriteMapWithGpuMaskIdCommand,
    sceKernelWriteMapWithGpuMaskIdCommand,
    (va, size, ty, prot, gpu)
);
writer!(
    ammWriteMapDirectCommand,
    sceKernelWriteMapDirectCommand,
    (va, dmem, size, ty, prot)
);
writer!(
    ammWriteMapDirectWithGpuMaskIdCommand,
    sceKernelWriteMapDirectWithGpuMaskIdCommand,
    (va, dmem, size, ty, prot, gpu)
);
writer!(
    ammWriteRemapCommand,
    sceKernelWriteRemapCommand,
    (va_new, va_old, size, prot)
);
writer!(
    ammWriteRemapWithGpuMaskIdCommand,
    sceKernelWriteRemapWithGpuMaskIdCommand,
    (va_new, va_old, size, prot, gpu)
);
writer!(
    ammWriteMultiMapCommand,
    sceKernelWriteMultiMapCommand,
    (va_new, va_alias, size, prot)
);
writer!(
    ammWriteMultiMapWithGpuMaskIdCommand,
    sceKernelWriteMultiMapWithGpuMaskIdCommand,
    (va_new, va_alias, size, prot, gpu)
);
writer!(
    ammWriteModifyProtectCommand,
    sceKernelWriteModifyProtectCommand,
    (va, size, prot, mask)
);
writer!(
    ammWriteModifyProtectWithGpuMaskIdCommand,
    sceKernelWriteModifyProtectWithGpuMaskIdCommand,
    (va, size, prot, mask, gpu)
);
writer!(
    ammWriteModifyMtypeProtectCommand,
    sceKernelWriteModifyMtypeProtectCommand,
    (va, size, ty, prot, mask)
);
writer!(
    ammWriteModifyMtypeProtectWithGpuMaskIdCommand,
    sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand,
    (va, size, ty, prot, mask, gpu)
);

/// Original WriteMapCommand slot, else WriteMapCommand2 with prt = 0.
pub unsafe fn ammWriteMapCommand(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    out: *mut u64,
) -> c_int {
    type F = unsafe extern "C" fn(*mut c_void, u64, u64, u64, u64, *mut u64) -> c_int;
    match unsafe { sys::kernel_slot::<F>(hook::sceKernelWriteMapCommand) } {
        Some(f) => unsafe { f(dst, va, size, ty, prot, out) },
        None => unsafe { ammWriteMapCommand2(dst, va, size, ty, prot, 0, out) },
    }
}

pub unsafe fn ammWriteUnmapCommand(dst: *mut c_void, va: u64, size: u64, out: *mut u64) -> c_int {
    unsafe { sys::sceKernelWriteUnmapCommand(dst, va, size, out) }
}

pub unsafe fn ammWriteRemapIntoPrtCommand(
    dst: *mut u32,
    va: u64,
    remap_va: u64,
    size: u64,
    prot: c_int,
    opcode: c_int,
    out: *mut u64,
) -> c_int {
    type F = unsafe extern "C" fn(*mut u32, u64, u64, u64, c_int, c_int, *mut u64) -> c_int;
    match unsafe { sys::kernel_slot::<F>(hook::sceKernelWriteRemapIntoPrtCommand) } {
        Some(f) => unsafe { f(dst, va, remap_va, size, prot, opcode, out) },
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

static WRITE_UNMAP_TO_PRT: LazySym = LazySym::new(c"sceKernelWriteUnmapToPrtCommand");

pub unsafe fn ammWriteUnmapToPrtCommand(dst: *mut u32, va: u64, size: u64, out: *mut u64) -> c_int {
    type F = unsafe extern "C" fn(*mut u32, u64, u64, *mut u64) -> c_int;
    match unsafe { WRITE_UNMAP_TO_PRT.get::<F>() } {
        Some(f) => unsafe { f(dst, va, size, out) },
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

// ---- libkernel detour targets -----------------------------------------------

pub unsafe extern "C" fn sceKernelGetDirectMemorySize_emul() -> usize {
    unsafe {
        ampr_internal_amm_pool_prepare_static_storage(c"mem.direct.size".as_ptr());
        sys::real_get_direct_memory_size()
    }
}

pub unsafe extern "C" fn sceKernelAvailableDirectMemorySize_emul(
    start: off_t,
    end: off_t,
    align: usize,
    phys_out: *mut off_t,
    size_out: *mut usize,
) -> c_int {
    unsafe {
        ampr_internal_amm_pool_prepare_static_storage(c"mem.direct.available".as_ptr());
        sys::real_available_direct_memory_size(start, end, align, phys_out, size_out)
    }
}

pub unsafe extern "C" fn sceKernelWriteMapCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    out: *mut u64,
) -> c_int {
    unsafe { ammWriteMapCommand(dst, va, size, ty, prot_with_cpu_rw(prot), out) }
}

pub unsafe extern "C" fn sceKernelWriteMapCommand2_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    prt: u64,
    out: *mut u64,
) -> c_int {
    let prot = if prt != 0 {
        prot
    } else {
        prot_with_cpu_rw(prot)
    };
    unsafe { ammWriteMapCommand2(dst, va, size, ty, prot, prt, out) }
}

pub unsafe extern "C" fn sceKernelWriteMapWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    unsafe { ammWriteMapWithGpuMaskIdCommand(dst, va, size, ty, prot_with_cpu_rw(prot), gpu, out) }
}

pub unsafe extern "C" fn sceKernelWriteMapDirectCommand_emul(
    dst: *mut c_void,
    va: u64,
    dmem: u64,
    size: u64,
    ty: u64,
    prot: u64,
    out: *mut u64,
) -> c_int {
    unsafe { ammWriteMapDirectCommand(dst, va, dmem, size, ty, prot_with_cpu_rw(prot), out) }
}

pub unsafe extern "C" fn sceKernelWriteMapDirectWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va: u64,
    dmem: u64,
    size: u64,
    ty: u64,
    prot: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    let prot = prot_with_cpu_rw(prot);
    unsafe { ammWriteMapDirectWithGpuMaskIdCommand(dst, va, dmem, size, ty, prot, gpu, out) }
}

pub unsafe extern "C" fn sceKernelWriteRemapCommand_emul(
    dst: *mut c_void,
    va_new: u64,
    va_old: u64,
    size: u64,
    prot: u64,
    out: *mut u64,
) -> c_int {
    unsafe { ammWriteRemapCommand(dst, va_new, va_old, size, prot_with_cpu_rw(prot), out) }
}

pub unsafe extern "C" fn sceKernelWriteRemapWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va_new: u64,
    va_old: u64,
    size: u64,
    prot: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    let prot = prot_with_cpu_rw(prot);
    unsafe { ammWriteRemapWithGpuMaskIdCommand(dst, va_new, va_old, size, prot, gpu, out) }
}

pub unsafe extern "C" fn sceKernelWriteMultiMapCommand_emul(
    dst: *mut c_void,
    va_new: u64,
    va_alias: u64,
    size: u64,
    prot: u64,
    out: *mut u64,
) -> c_int {
    unsafe { ammWriteMultiMapCommand(dst, va_new, va_alias, size, prot_with_cpu_rw(prot), out) }
}

pub unsafe extern "C" fn sceKernelWriteMultiMapWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va_new: u64,
    va_alias: u64,
    size: u64,
    prot: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    let prot = prot_with_cpu_rw(prot);
    unsafe { ammWriteMultiMapWithGpuMaskIdCommand(dst, va_new, va_alias, size, prot, gpu, out) }
}

/// Adjusted (prot, mask) for the modify-protect writers.
const fn adjust_pair(prot: u64, mask: u64) -> (u64, u64) {
    let adj = prot_with_cpu_rw(prot);
    (adj, mask_with_cpu_rw(prot, adj, mask))
}

pub unsafe extern "C" fn sceKernelWriteModifyProtectCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    prot: u64,
    mask: u64,
    out: *mut u64,
) -> c_int {
    let (prot, mask) = adjust_pair(prot, mask);
    unsafe { ammWriteModifyProtectCommand(dst, va, size, prot, mask, out) }
}

pub unsafe extern "C" fn sceKernelWriteModifyProtectWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    prot: u64,
    mask: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    let (prot, mask) = adjust_pair(prot, mask);
    unsafe { ammWriteModifyProtectWithGpuMaskIdCommand(dst, va, size, prot, mask, gpu, out) }
}

pub unsafe extern "C" fn sceKernelWriteModifyMtypeProtectCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    mask: u64,
    out: *mut u64,
) -> c_int {
    let (prot, mask) = adjust_pair(prot, mask);
    unsafe { ammWriteModifyMtypeProtectCommand(dst, va, size, ty, prot, mask, out) }
}

pub unsafe extern "C" fn sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand_emul(
    dst: *mut c_void,
    va: u64,
    size: u64,
    ty: u64,
    prot: u64,
    mask: u64,
    gpu: u64,
    out: *mut u64,
) -> c_int {
    let (prot, mask) = adjust_pair(prot, mask);
    unsafe {
        ammWriteModifyMtypeProtectWithGpuMaskIdCommand(dst, va, size, ty, prot, mask, gpu, out)
    }
}

pub unsafe extern "C" fn sceKernelWriteRemapIntoPrtCommand_emul(
    dst: *mut u32,
    va: u64,
    remap_va: u64,
    size: u64,
    prot: c_int,
    opcode: c_int,
    out: *mut u64,
) -> c_int {
    let prot = prot_with_cpu_rw(prot as u32 as u64) as c_int;
    unsafe { ammWriteRemapIntoPrtCommand(dst, va, remap_va, size, prot, opcode, out) }
}

// ---- mapper / submit leaves -----------------------------------------------

/// `kAmmSubmitRetryRc`: the kernel queue is full; sleep and resubmit.
const SUBMIT_RETRY_RC: c_int = -2147352541;
const SUBMIT_RETRY_SLEEP_USEC: u32 = 0xC8;
const SUBMIT_MAX_PRIORITY: u32 = 2;

static CALL_INDIRECT_BUFFER3: LazySym = LazySym::new(c"sceKernelCallIndirectBuffer3");
static SET_PT_POOL_THRESHOLD: LazySym =
    LazySym::new(c"sceKernelMapperSetPageTablePoolOccupancyNotificationThreshold");

fn validate_submit(base: u64, prio: u32) -> c_int {
    if prio > SUBMIT_MAX_PRIORITY {
        SCE_KERNEL_ERROR_EINVAL
    } else if base == 0 {
        SCE_KERNEL_ERROR_EPERM
    } else {
        0
    }
}

fn submit_with_retry(mut submit: impl FnMut() -> c_int) -> c_int {
    loop {
        let rc = submit();
        if rc != SUBMIT_RETRY_RC {
            return rc;
        }
        unsafe { sys::sceKernelUsleep(SUBMIT_RETRY_SLEEP_USEC) };
    }
}

pub unsafe fn ammGetVirtualAddressRangesLeaf(
    va_start: *mut u64,
    va_end: *mut u64,
    mm_start: *mut u64,
    mm_end: *mut u64,
) -> c_int {
    let mut p = [0u64; 7];
    p[0] = core::mem::size_of_val(&p) as u64;
    let rc = unsafe { sys::sceKernelMapperGetParam(p.as_mut_ptr()) };
    if rc != 0 {
        return rc;
    }
    unsafe {
        *va_start = p[1];
        *va_end = p[2];
        *mm_start = p[3];
        *mm_end = p[4];
        // Title AMPR init: publish the index before the first packed open.
        ampr_index_ensure_ready_safe();
    }
    0
}

pub unsafe fn ammGiveDirectMemory(
    start: off_t,
    end: off_t,
    size: usize,
    align: usize,
    usage: c_int,
    dmem_offset: *mut off_t,
) -> c_int {
    unsafe { sys::sceKernelGiveDirectMemoryToMapper(start, end, size, align, usage, dmem_offset) }
}

/// One native attempt, no retry sleep (reactor leaf).
pub unsafe fn ammTrySubmitCommandBufferLeaf(base: u64, offset: u32, prio: u32) -> c_int {
    let rc = validate_submit(base, prio);
    if rc != 0 {
        return rc;
    }
    unsafe { sys::sceKernelCallIndirectBuffer(prio, base, offset as u64) }
}

pub unsafe fn ammSubmitCommandBufferLeaf(
    base: u64,
    offset: u32,
    prio: u32,
    id: *mut SceAmmSubmitId,
) -> c_int {
    let rc = validate_submit(base, prio);
    if rc != 0 {
        return rc;
    }
    if id.is_null() {
        return submit_with_retry(|| unsafe {
            sys::sceKernelCallIndirectBuffer(prio, base, offset as u64)
        });
    }
    type F = unsafe extern "C" fn(u32, u64, u64, *mut SceAmmSubmitId) -> c_int;
    submit_with_retry(|| match unsafe { CALL_INDIRECT_BUFFER3.get::<F>() } {
        Some(f) => unsafe { f(prio, base, offset as u64, id) },
        None => SCE_KERNEL_ERROR_ENXIO,
    })
}

pub unsafe fn ammSubmitCommandBufferAndGetResultLeaf(
    base: u64,
    offset: u32,
    prio: u32,
    res: *mut SceAmmResultBuffer,
    id: *mut SceAmmSubmitId,
) -> c_int {
    let rc = validate_submit(base, prio);
    if rc != 0 {
        return rc;
    }
    submit_with_retry(|| unsafe {
        sys::sceKernelCallIndirectBuffer2(prio, base, offset as u64, res, id)
    })
}

pub unsafe fn ammWaitCommandBufferCompletion(id: SceAmmSubmitId) -> c_int {
    unsafe { sys::sceKernelWaitCommandBufferCompletion(id) }
}

pub unsafe fn mapperGetUsageStatsData(data: *mut u64) -> c_int {
    unsafe { sys::real_mapper_get_usage_stats_data(data) }
}

pub unsafe fn mapperSetPageTablePoolOccupancyNotificationThreshold(threshold: c_int) -> c_int {
    type F = unsafe extern "C" fn(c_int) -> c_int;
    match unsafe { SET_PT_POOL_THRESHOLD.get::<F>() } {
        Some(f) => unsafe { f(threshold) },
        None => SCE_KERNEL_ERROR_ENXIO,
    }
}

// ---- AmmCommandBuffer -------------------------------------------------------

type Cb = *mut SceAmprCommandBuffer;

/// `ammCommandSizeToInt` without the out-parameter.
fn command_size_to_int(rc: c_int, bytes: u64) -> c_int {
    if rc != 0 {
        rc
    } else if bytes == 0 || bytes > u32::MAX as u64 {
        SCE_KERNEL_ERROR_EINVAL
    } else {
        bytes as u32 as c_int
    }
}

/// `cb_append_amm_kernel_record`: `write(null, &size)` measures, then
/// `write(dst, null)` emits; metadata is committed only on success.
unsafe fn append(
    cb: Cb,
    require_buffer: bool,
    write: impl Fn(*mut c_void, *mut u64) -> c_int,
) -> c_int {
    if cb.is_null() {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    unsafe {
        if require_buffer && (*cb).buffer.is_null() {
            return SCE_KERNEL_ERROR_EPERM;
        }
        let mut bytes64 = 0u64;
        let rc = write(null_mut(), &mut bytes64);
        let measured = command_size_to_int(rc, bytes64);
        if measured < 0 {
            return measured;
        }
        let bytes = if rc == 0 { bytes64 as u32 } else { 0 };
        let (old, cap) = ((*cb).offset, (*cb).bufsize);
        if bytes > cap || old > cap - bytes {
            return SCE_KERNEL_ERROR_EBUSY;
        }
        // Some writers defer the buffer check so a missing helper reports ENXIO.
        if (*cb).buffer.is_null() {
            return SCE_KERNEL_ERROR_EPERM;
        }
        let num = read_volatile(addr_of!((*cb).num));
        if num < 0 || num == i32::MAX {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        let rc = write(
            (*cb).buffer.cast::<u8>().add(old as usize).cast(),
            null_mut(),
        );
        if rc != 0 {
            return rc;
        }
        (*cb).offset = old + bytes;
        write_volatile(
            addr_of_mut!((*cb).num),
            read_volatile(addr_of!((*cb).num)) + 1,
        );
    }
    0
}

/// `amm_prevalidate_command_buffer`.
unsafe fn prevalidate(cb: Cb) -> Result<(), c_int> {
    if cb.is_null() {
        Err(SCE_KERNEL_ERROR_EINVAL)
    } else if unsafe { (*cb).buffer.is_null() } {
        Err(SCE_KERNEL_ERROR_EPERM)
    } else {
        Ok(())
    }
}

/// Prevalidated command buffer + CPU-visible prot.
unsafe fn cb_prot(cb: Cb, prot: c_int) -> Result<u64, c_int> {
    unsafe { prevalidate(cb) }?;
    cpu_visible_prot(prot)
}

/// Prevalidated command buffer + CPU-visible prot/mask pair.
unsafe fn cb_prot_pair(cb: Cb, prot: c_int, mask: c_int) -> Result<(u64, u64), c_int> {
    unsafe { prevalidate(cb) }?;
    cpu_visible_prot_pair(prot, mask)
}

/// Unwraps a prepared prot or returns its error code.
macro_rules! try_rc {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(rc) => return rc,
        }
    };
}

/// `type` truncated to u32, then widened to the writer's u64.
const fn ty64(ty: c_int) -> u64 {
    ty as u32 as u64
}

pub unsafe fn ampr_amm_cb_map(cb: Cb, va: u64, size: u64, ty: c_int, prot: c_int) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMapCommand2(d, va, size, ty64(ty), kp, 0, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_map_with_gpu_mask_id(
    cb: Cb,
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    gpu: u8,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMapWithGpuMaskIdCommand(d, va, size, ty64(ty), kp, gpu as u64, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_map_direct(
    cb: Cb,
    va: u64,
    dmem: u64,
    size: usize,
    ty: c_int,
    prot: c_int,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMapDirectCommand(d, va, dmem, size as u64, ty64(ty), kp, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_map_direct_with_gpu_mask_id(
    cb: Cb,
    va: u64,
    dmem: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    gpu: u8,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMapDirectWithGpuMaskIdCommand(d, va, dmem, size, ty64(ty), kp, gpu as u64, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_unmap(cb: Cb, va: u64, size: usize) -> c_int {
    unsafe { append(cb, true, |d, o| ammWriteUnmapCommand(d, va, size as u64, o)) }
}

pub unsafe fn ampr_amm_cb_remap(cb: Cb, va_new: u64, va_old: u64, size: u64, prot: c_int) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteRemapCommand(d, va_new, va_old, size, kp, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_remap_with_gpu_mask_id(
    cb: Cb,
    va_new: u64,
    va_old: u64,
    size: u64,
    prot: c_int,
    gpu: u8,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteRemapWithGpuMaskIdCommand(d, va_new, va_old, size, kp, gpu as u64, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_multi_map(
    cb: Cb,
    va_new: u64,
    va_alias: u64,
    size: u64,
    prot: c_int,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMultiMapCommand(d, va_new, va_alias, size, kp, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_multi_map_with_gpu_mask_id(
    cb: Cb,
    va_new: u64,
    va_alias: u64,
    size: u64,
    prot: c_int,
    gpu: u8,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteMultiMapWithGpuMaskIdCommand(d, va_new, va_alias, size, kp, gpu as u64, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_modify_protect(
    cb: Cb,
    va: u64,
    size: u64,
    prot: c_int,
    mask: c_int,
) -> c_int {
    let (kp, km) = try_rc!(unsafe { cb_prot_pair(cb, prot, mask) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteModifyProtectCommand(d, va, size, kp, km, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_modify_protect_with_gpu_mask_id(
    cb: Cb,
    va: u64,
    size: u64,
    prot: c_int,
    mask: c_int,
    gpu: u8,
) -> c_int {
    let (kp, km) = try_rc!(unsafe { cb_prot_pair(cb, prot, mask) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteModifyProtectWithGpuMaskIdCommand(d, va, size, kp, km, gpu as u64, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_modify_mtype_protect(
    cb: Cb,
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    mask: c_int,
) -> c_int {
    let (kp, km) = try_rc!(unsafe { cb_prot_pair(cb, prot, mask) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteModifyMtypeProtectCommand(d, va, size, ty64(ty), kp, km, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_modify_mtype_protect_with_gpu_mask_id(
    cb: Cb,
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    mask: c_int,
    gpu: u8,
) -> c_int {
    let (kp, km) = try_rc!(unsafe { cb_prot_pair(cb, prot, mask) });
    unsafe {
        append(cb, true, |d, o| {
            ammWriteModifyMtypeProtectWithGpuMaskIdCommand(
                d,
                va,
                size,
                ty64(ty),
                kp,
                km,
                gpu as u64,
                o,
            )
        })
    }
}

pub unsafe fn ampr_amm_cb_map_as_prt(cb: Cb, va: u64, size: u64) -> c_int {
    unsafe {
        append(cb, false, |d, o| {
            ammWriteMapCommand2(d, va, size, 0, 0, 1, o)
        })
    }
}

/// Retail mask for allocatePaForPrt's modify-mtype-protect record.
const ALLOCATE_PA_FOR_PRT_MASK: u64 = 1019;

pub unsafe fn ampr_amm_cb_allocate_pa_for_prt(
    cb: Cb,
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
) -> c_int {
    // No prevalidation: the buffer check is deferred into `append`.
    let kp = try_rc!(cpu_visible_prot(prot));
    unsafe {
        append(cb, false, |d, o| {
            ammWriteModifyMtypeProtectCommand(
                d,
                va,
                size,
                ty64(ty),
                kp,
                ALLOCATE_PA_FOR_PRT_MASK,
                o,
            )
        })
    }
}

/// Default opcode for remapIntoPrt when the caller passes 0.
const REMAP_INTO_PRT_DEFAULT_OPCODE: u32 = 1011;

pub unsafe fn ampr_amm_cb_remap_into_prt(
    cb: Cb,
    va_prt: u64,
    va_old: u64,
    size: u64,
    prot: c_int,
    opcode: u32,
) -> c_int {
    let kp = try_rc!(unsafe { cb_prot(cb, prot) }) as c_int;
    let op = if opcode != 0 {
        opcode
    } else {
        REMAP_INTO_PRT_DEFAULT_OPCODE
    } as c_int;
    unsafe {
        append(cb, true, |d, o| {
            ammWriteRemapIntoPrtCommand(d.cast(), va_prt, va_old, size, kp, op, o)
        })
    }
}

pub unsafe fn ampr_amm_cb_unmap_to_prt(cb: Cb, va: u64, size: u64) -> c_int {
    unsafe {
        append(cb, true, |d, o| {
            ammWriteUnmapToPrtCommand(d.cast(), va, size, o)
        })
    }
}

// ---- measure helpers --------------------------------------------------------

/// `measureAmmKernelRecord`: size of one record (raw prot, no adjustment).
fn measure(write: impl FnOnce(*mut u64) -> c_int) -> c_int {
    let mut bytes = 0u64;
    let rc = write(&mut bytes);
    if rc < 0 {
        rc
    } else if bytes == 0 || bytes > u32::MAX as u64 {
        SCE_KERNEL_ERROR_EINVAL
    } else {
        bytes as u32 as c_int
    }
}

/// `int` reinterpreted as u32, then widened to u64.
const fn u(v: c_int) -> u64 {
    v as u32 as u64
}

const NUL: *mut c_void = null_mut();

pub unsafe fn measureAmmMap(va: u64, size: u64, ty: c_int, prot: c_int) -> c_int {
    measure(|o| unsafe { ammWriteMapCommand(NUL, va, size, u(ty), u(prot), o) })
}

pub unsafe fn measureAmmMapWithGpuMaskId(
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteMapWithGpuMaskIdCommand(NUL, va, size, u(ty), u(prot), gpu as u64, o)
    })
}

pub unsafe fn measureAmmMapDirect(
    va: u64,
    dmem: u64,
    size: usize,
    ty: c_int,
    prot: c_int,
) -> c_int {
    measure(|o| unsafe { ammWriteMapDirectCommand(NUL, va, dmem, size as u64, u(ty), u(prot), o) })
}

pub unsafe fn measureAmmMapDirectWithGpuMaskId(
    va: u64,
    dmem: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteMapDirectWithGpuMaskIdCommand(NUL, va, dmem, size, u(ty), u(prot), gpu as u64, o)
    })
}

pub unsafe fn measureAmmUnmap(va: u64, size: usize) -> c_int {
    measure(|o| unsafe { ammWriteUnmapCommand(NUL, va, size as u64, o) })
}

pub unsafe fn measureAmmRemap(va_new: u64, va_old: u64, size: u64, prot: c_int) -> c_int {
    measure(|o| unsafe { ammWriteRemapCommand(NUL, va_new, va_old, size, u(prot), o) })
}

pub unsafe fn measureAmmRemapWithGpuMaskId(
    va_new: u64,
    va_old: u64,
    size: u64,
    prot: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteRemapWithGpuMaskIdCommand(NUL, va_new, va_old, size, u(prot), gpu as u64, o)
    })
}

pub unsafe fn measureAmmMultiMap(va_new: u64, va_alias: u64, size: u64, prot: c_int) -> c_int {
    measure(|o| unsafe { ammWriteMultiMapCommand(NUL, va_new, va_alias, size, u(prot), o) })
}

pub unsafe fn measureAmmMultiMapWithGpuMaskId(
    va_new: u64,
    va_alias: u64,
    size: u64,
    prot: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteMultiMapWithGpuMaskIdCommand(NUL, va_new, va_alias, size, u(prot), gpu as u64, o)
    })
}

pub unsafe fn measureAmmModifyProtect(va: u64, size: u64, prot: c_int, mask: c_int) -> c_int {
    measure(|o| unsafe { ammWriteModifyProtectCommand(NUL, va, size, u(prot), u(mask), o) })
}

pub unsafe fn measureAmmModifyProtectWithGpuMaskId(
    va: u64,
    size: u64,
    prot: c_int,
    mask: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteModifyProtectWithGpuMaskIdCommand(NUL, va, size, u(prot), u(mask), gpu as u64, o)
    })
}

pub unsafe fn measureAmmModifyMtypeProtect(
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    mask: c_int,
) -> c_int {
    measure(|o| unsafe {
        ammWriteModifyMtypeProtectCommand(NUL, va, size, u(ty), u(prot), u(mask), o)
    })
}

pub unsafe fn measureAmmModifyMtypeProtectWithGpuMaskId(
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
    mask: c_int,
    gpu: u8,
) -> c_int {
    measure(|o| unsafe {
        ammWriteModifyMtypeProtectWithGpuMaskIdCommand(
            NUL,
            va,
            size,
            u(ty),
            u(prot),
            u(mask),
            gpu as u64,
            o,
        )
    })
}

pub unsafe fn measureAmmMapAsPrt(va: u64, size: u64) -> c_int {
    measure(|o| unsafe { ammWriteMapCommand2(NUL, va, size, 0, 0, 1, o) })
}

pub unsafe fn measureAmmAllocatePaForPrt(va: u64, size: u64, ty: c_int, prot: c_int) -> c_int {
    measure(|o| unsafe {
        ammWriteModifyMtypeProtectCommand(
            NUL,
            va,
            size,
            u(ty),
            u(prot),
            ALLOCATE_PA_FOR_PRT_MASK,
            o,
        )
    })
}
