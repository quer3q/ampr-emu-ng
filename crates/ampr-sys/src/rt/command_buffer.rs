//! Command packing, the SceAmprCommandBuffer append path and the
//! CommandBuffer/AprCommandBuffer method bodies. Packed op layout/words come
//! from ampr-command.
#![allow(non_snake_case)]

use super::sys::{
    strlen, SceAprFileId, SceKernelEqueue, SCE_KERNEL_ERROR_EBUSY as EBUSY,
    SCE_KERNEL_ERROR_EINVAL as EINVAL, SCE_KERNEL_ERROR_EPERM as EPERM,
};
use ampr_command::{
    decode_packed_op, op_type::*, DecodeError, OpRecord, SceAmprCommandBuffer as Cb,
};
use core::ffi::{c_char, c_int, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{self, addr_of, addr_of_mut, null_mut};

const VA_MAX: u64 = 0xF000_0000_0000;
const BUFFER_MAX: u32 = 64 * 1024 * 1024;
/// `kAprScatterGatherValidTypeMask` / `kAprMapActiveTypeMask` command-buffer type bits.
const SG_VALID: u32 = 0x0001_0000;
const MAP_ACTIVE: u32 = 0x0002_0000;

const _: () = {
    assert!(size_of::<Cb>() == 24);
    assert!(offset_of!(Cb, r#type) == 0 && offset_of!(Cb, offset) == 4 && offset_of!(Cb, num) == 8);
    assert!(offset_of!(Cb, bufsize) == 12 && offset_of!(Cb, buffer) == 16);
};

/// `sce::Ampr::PackedOpLayout`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PackedOpLayout {
    bytes: u32,
    command_count: u32,
}
const _: () = assert!(size_of::<PackedOpLayout>() == 8);

use super::amm::{ammWriteMapCommand2, ammWriteMapDirectCommand};
use super::equeue::apr_equeue_note_command_buffer_event;

// ---- packing ----------------------------------------------------------------

fn op(op_type: u8) -> OpRecord {
    OpRecord {
        op_type,
        ..OpRecord::default()
    }
}

fn layout_of(op: &OpRecord) -> Result<PackedOpLayout, c_int> {
    op.layout()
        .map(|l| PackedOpLayout {
            bytes: l.bytes,
            command_count: l.command_count,
        })
        .map_err(|_| EINVAL)
}

pub fn ampr_valid_wait_flush(flush: u8) -> bool {
    flush < 2
}

/// # Safety
/// `op` is a writable `Op`; `text` is null or NUL-terminated and outlives the op.
pub unsafe fn ampr_set_marker_text(op: *mut OpRecord, text: *const c_char) -> bool {
    if text.is_null() {
        return false;
    }
    let len = unsafe { strlen(text) };
    if len >= u32::MAX as usize {
        return false;
    }
    let op = unsafe { &mut *op };
    op.text = text as u64;
    op.text_length = len as u32;
    true
}

/// # Safety
/// `op` is a readable `Op`; `out` is null or writable.
pub unsafe fn ampr_op_layout_checked(op: *const OpRecord, out: *mut PackedOpLayout) -> c_int {
    if out.is_null() {
        return EINVAL;
    }
    let (rc, l) = match layout_of(unsafe { &*op }) {
        Ok(l) => (0, l),
        Err(rc) => (rc, PackedOpLayout::default()),
    };
    unsafe { out.write(l) };
    rc
}

/// # Safety
/// `op` is a readable `Op`; `out` is null or writable.
pub unsafe fn ampr_op_size_bytes_checked(op: *const OpRecord, out: *mut u32) -> c_int {
    if out.is_null() {
        return EINVAL;
    }
    let mut l = PackedOpLayout::default();
    let rc = unsafe { ampr_op_layout_checked(op, &mut l) };
    unsafe { out.write(l.bytes) };
    rc
}

/// Data-nop payload after the header word (`ampr_write_nop_payload`).
unsafe fn write_nop_payload(cb: &Cb, off: u32, op: &OpRecord) {
    let payload = op.u32a.wrapping_mul(4);
    if payload == 0 || off as u64 + 4 + payload as u64 > cb.bufsize as u64 {
        return;
    }
    let out = unsafe { cb.buffer.cast::<u8>().add(off as usize + 4) };
    let mut cursor = 0u32;
    if op.u8a != 0 {
        unsafe { out.cast::<u32>().write_unaligned(op.u64b as u32) };
        cursor = 4;
    }
    if op.cptr == 0 {
        return;
    }
    let typed = op.u32c != 0 || op.u8a != 0 || op.u64a != 0;
    let copy = if typed {
        op.u64a as u32
    } else {
        payload - cursor
    };
    if copy == 0 || cursor >= payload {
        return;
    }
    let n = copy.min(payload - cursor);
    unsafe { ptr::copy_nonoverlapping(op.cptr as *const u8, out.add(cursor as usize), n as usize) };
    cursor += n;
    let pad = ((cursor + 3) & !3) - cursor;
    if pad != 0 && cursor + pad <= payload {
        unsafe { ptr::write_bytes(out.add(cursor as usize), 0, pad as usize) };
    }
}

/// # Safety
/// `cb` is null or a valid header whose buffer spans `bufsize` writable bytes;
/// `op` and `layout` are readable; marker text and nop payload pointers are valid.
pub unsafe fn ampr_write_op_with_layout(
    cb: *mut Cb,
    off: u32,
    op: *const OpRecord,
    layout: *const PackedOpLayout,
) -> c_int {
    let (op, l) = unsafe { (&*op, *layout) };
    if l.bytes == 0 || l.command_count == 0 {
        return EINVAL;
    }
    let Some(cb) = (unsafe { cb.as_ref() }).filter(|cb| !cb.buffer.is_null()) else {
        return EPERM;
    };
    if l.bytes > cb.bufsize || off > cb.bufsize - l.bytes {
        return EBUSY;
    }
    let dst = unsafe { cb.buffer.cast::<u8>().add(off as usize) };
    if matches!(op.op_type, MARKER_SET | MARKER_PUSH) {
        // layout() already rejected null text and text_length == u32::MAX.
        let text = unsafe {
            core::slice::from_raw_parts(op.text as *const u8, op.text_length as usize + 1)
        };
        let out = unsafe { core::slice::from_raw_parts_mut(dst, l.bytes as usize) };
        return if op.encode_marker(text, out).is_ok() {
            0
        } else {
            EINVAL
        };
    }
    let Ok((words, count)) = op.encode_words() else {
        return EINVAL;
    };
    let bytes = count as u32 * 4;
    if count != 0 && off as u64 + bytes as u64 <= cb.bufsize as u64 {
        unsafe { ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), dst, bytes as usize) };
    }
    if op.op_type == NOP && op.u32b != 0 {
        unsafe { write_nop_payload(cb, off, op) };
    }
    0
}

/// # Safety
/// As for `ampr_write_op_with_layout`.
pub unsafe fn ampr_strict_write_op(
    cb: *mut Cb,
    off: u32,
    op: *const OpRecord,
    bytes: u32,
) -> c_int {
    match layout_of(unsafe { &*op }) {
        Ok(l) if bytes != 0 && bytes == l.bytes => unsafe {
            ampr_write_op_with_layout(cb, off, op, &l)
        },
        _ => EINVAL,
    }
}

/// # Safety
/// `buffer` is null or spans `bytes` readable bytes; outputs are null or writable.
pub unsafe fn ampr_decode_packed_op(
    buffer: *const c_void,
    bytes: u32,
    off: u32,
    out_op: *mut OpRecord,
    out_bytes: *mut u32,
    error_offset: *mut u32,
) -> c_int {
    if !error_offset.is_null() {
        unsafe { error_offset.write(0) };
    }
    if buffer.is_null() || out_op.is_null() || bytes & 3 != 0 || off & 3 != 0 || off >= bytes {
        return EINVAL;
    }
    let buf = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), bytes as usize) };
    match decode_packed_op(buf, off) {
        Ok((op, size)) => {
            unsafe { out_op.write(op) };
            if !out_bytes.is_null() {
                unsafe { out_bytes.write(size) };
            }
            0
        }
        Err(e) => {
            if e == DecodeError::InvalidAt && !error_offset.is_null() {
                unsafe { error_offset.write(off) };
            }
            EINVAL
        }
    }
}

/// # Safety
/// As for `ampr_decode_packed_op`.
pub unsafe fn ampr_decode_apr_packed_op(
    buffer: *const c_void,
    bytes: u32,
    off: u32,
    out_op: *mut OpRecord,
    out_bytes: *mut u32,
    error_offset: *mut u32,
) -> c_int {
    unsafe { ampr_decode_packed_op(buffer, bytes, off, out_op, out_bytes, error_offset) }
}

// ---- command-buffer append ---------------------------------------------------

pub fn ampr_valid_wait_compare_04_00(c: u8) -> bool {
    c <= 6
}
pub fn ampr_valid_wait_compare_modern(c: u8) -> bool {
    c < 4
}
pub fn ampr_valid_u64_wait_addr(addr: u64) -> bool {
    addr & 7 == 0 && addr <= VA_MAX && 8 <= VA_MAX - addr
}
pub fn ampr_valid_u64_wait_addr_04_00(addr: u64) -> bool {
    addr != 0 && ampr_valid_u64_wait_addr(addr)
}
pub fn ampr_valid_u64_write_addr(addr: u64) -> bool {
    addr != 0 && ampr_valid_u64_wait_addr(addr)
}
pub fn ampr_valid_counter_index_signed7(index: u8) -> bool {
    index & 0x80 == 0
}
pub fn ampr_valid_wait_counter_04_00(width: u8, cmp: u8, extra: u8, flush: u8) -> bool {
    width < 8 && ampr_valid_wait_compare_04_00(cmp) && extra < 2 && ampr_valid_wait_flush(flush)
}
pub fn ampr_valid_wait_counter_modern(index: u8, cmp: u8, flush: u8) -> bool {
    ampr_valid_counter_index_signed7(index)
        && ampr_valid_wait_compare_modern(cmp)
        && ampr_valid_wait_flush(flush)
}
pub fn ampr_valid_write_counter_04_00(index: u8, width: u8, mode: u8) -> bool {
    ampr_valid_counter_index_signed7(index) && width < 8 && mode < 5
}

/// `cb_append_with_type_mask`: packs `op` at the current offset, then commits
/// offset/num and applies the type masks.
unsafe fn append_masked(cb: *mut Cb, mut op: OpRecord, set: u32, clear: u32) -> c_int {
    let Some(cb) = (unsafe { cb.as_mut() }) else {
        return EINVAL;
    };
    if cb.buffer.is_null() {
        return EPERM;
    }
    let l = match layout_of(&op) {
        Ok(l) => l,
        Err(rc) => return rc,
    };
    let off = cb.offset;
    op.buf_offset_bytes = off;
    if l.bytes > cb.bufsize || off > cb.bufsize - l.bytes {
        return EBUSY;
    }
    let num = unsafe { addr_of!(cb.num).read_volatile() };
    let count = l.command_count;
    if num < 0 || count > i32::MAX as u32 || num > (i32::MAX as u32 - count) as i32 {
        return EINVAL;
    }
    let rc = unsafe { ampr_write_op_with_layout(cb, off, &op, &l) };
    if rc != 0 {
        return rc;
    }
    unsafe { addr_of_mut!(cb.num).write_volatile(num + count as i32) };
    cb.offset = off + l.bytes;
    cb.r#type = ((cb.r#type as u32 | set) & !clear) as i32;
    0
}

unsafe fn append(cb: *mut Cb, op: OpRecord) -> c_int {
    unsafe { append_masked(cb, op, 0, 0) }
}

/// `ampr_reject_completion_write_in_apr_map`: completion writes are illegal
/// between APR mapBegin/mapEnd.
unsafe fn in_apr_map(cb: *const Cb, at_sop: bool) -> bool {
    !at_sop && unsafe { has_mask(cb, MAP_ACTIVE) }
}

unsafe fn has_mask(cb: *const Cb, mask: u32) -> bool {
    unsafe { cb.as_ref() }.is_some_and(|cb| cb.r#type as u32 & mask != 0)
}

/// # Safety (all `ampr_cb_*`)
/// `cb` is the `m_commandBuffer` header of a live CommandBuffer; pointer
/// arguments follow the matching SDK method contract.
pub unsafe fn ampr_cb_set_buffer(cb: *mut Cb, buffer: *mut c_void, size: u32) -> c_int {
    let cb = unsafe { &mut *cb };
    if buffer.is_null() {
        return EINVAL;
    }
    if !cb.buffer.is_null() {
        return EBUSY;
    }
    if buffer as usize & 3 != 0 || size == 0 || size & 3 != 0 || size > BUFFER_MAX {
        return EINVAL;
    }
    cb.buffer = buffer;
    cb.bufsize = size;
    0
}

pub unsafe fn ampr_cb_clear_buffer(cb: *mut Cb) -> *mut c_void {
    let cb = unsafe { &mut *cb };
    if cb.bufsize == 0 || cb.buffer.is_null() {
        return null_mut();
    }
    let p = cb.buffer;
    cb.buffer = null_mut();
    cb.bufsize = 0;
    p
}

pub unsafe fn ampr_cb_reset(cb: *mut Cb) -> c_int {
    let cb = unsafe { &mut *cb };
    if cb.buffer.is_null() {
        return EPERM;
    }
    cb.offset = 0;
    unsafe { addr_of_mut!(cb.num).write_volatile(0) };
    0
}

unsafe fn wait_on_address(
    cb: *mut Cb,
    addr: *mut u64,
    reference: u64,
    cmp: u8,
    flush: u8,
) -> c_int {
    let mut o = op(WAIT_ON_ADDRESS);
    o.ptra = addr as u64;
    o.u64a = reference;
    o.u32a = cmp as u32;
    o.u32c = flush as u32;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_wait_on_address(
    cb: *mut Cb,
    addr: *mut u64,
    reference: u64,
    cmp: u8,
    flush: u8,
) -> c_int {
    if !ampr_valid_u64_wait_addr(addr as u64)
        || !ampr_valid_wait_compare_modern(cmp)
        || !ampr_valid_wait_flush(flush)
    {
        return EINVAL;
    }
    unsafe { wait_on_address(cb, addr, reference, cmp, flush) }
}

pub unsafe fn ampr_cb_wait_on_address_04_00(
    cb: *mut Cb,
    addr: *mut u64,
    reference: u64,
    cmp: u8,
    flush: u8,
) -> c_int {
    if !ampr_valid_u64_wait_addr_04_00(addr as u64)
        || !ampr_valid_wait_compare_04_00(cmp)
        || !ampr_valid_wait_flush(flush)
    {
        return EINVAL;
    }
    unsafe { wait_on_address(cb, addr, reference, cmp, flush) }
}

pub unsafe fn ampr_cb_wait_on_counter_04_00(
    cb: *mut Cb,
    index: u8,
    width: u8,
    reference: u64,
    cmp: u8,
    extra: u8,
    extra_value: u64,
    flush: u8,
) -> c_int {
    if !ampr_valid_wait_counter_04_00(width, cmp, extra, flush) {
        return EINVAL;
    }
    let mut o = op(WAIT_ON_COUNTER);
    o.u8a = index;
    o.u8b = width;
    o.u32a = reference as u32;
    o.u64a = reference;
    o.u64b = extra_value;
    o.u32b = cmp as u32;
    o.u32c = (flush as u32 & 1) | ((extra as u32 & 3) << 8);
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_wait_on_counter(
    cb: *mut Cb,
    index: u8,
    reference: u32,
    cmp: u8,
    flush: u8,
) -> c_int {
    if !ampr_valid_wait_counter_modern(index, cmp, flush) {
        return EINVAL;
    }
    let mut o = op(WAIT_ON_COUNTER);
    o.u8a = index;
    o.u8b = 1;
    o.u32a = reference;
    o.u64a = reference as u64;
    o.u32b = cmp as u32;
    o.u32c = flush as u32 & 1;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_write_address_04_00(
    cb: *mut Cb,
    addr: *mut u64,
    value: u64,
    at_sop: bool,
) -> c_int {
    if !ampr_valid_u64_write_addr(addr as u64) {
        return EINVAL;
    }
    if unsafe { in_apr_map(cb, at_sop) } {
        return EPERM;
    }
    let mut o = op(WRITE_ADDRESS);
    o.ptra = addr as u64;
    o.u64a = value;
    o.u8a = at_sop as u8;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_write_counter_04_00(
    cb: *mut Cb,
    index: u8,
    width: u8,
    value: u64,
    mode: u8,
    at_sop: bool,
) -> c_int {
    if !ampr_valid_write_counter_04_00(index, width, mode) {
        return EINVAL;
    }
    if unsafe { in_apr_map(cb, at_sop) } {
        return EPERM;
    }
    let mut o = op(WRITE_COUNTER);
    o.u8a = index;
    o.u8b = width;
    o.u64a = value;
    o.u32a = value as u32;
    o.u32b = mode as u32;
    o.u32c = at_sop as u32;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_write_kernel_event_queue_04_00(
    cb: *mut Cb,
    eq: SceKernelEqueue,
    id: i32,
    data: u64,
    at_sop: bool,
) -> c_int {
    if eq.is_null() {
        return EINVAL;
    }
    if unsafe { in_apr_map(cb, at_sop) } {
        return EPERM;
    }
    let mut o = op(WRITE_EQUEUE);
    o.u64b = eq as u64;
    o.u32b = id as u32;
    o.u64a = data;
    o.u8a = at_sop as u8;
    let rc = unsafe { append(cb, o) };
    if rc == 0 {
        // The header is the first member, so its address is the object's `this`.
        unsafe { apr_equeue_note_command_buffer_event(cb.cast(), eq) };
    }
    rc
}

/// Shared body of the WriteAddressFrom{Time,}Counter{,Pair} records.
unsafe fn write_address_from(
    cb: *mut Cb,
    op_type: u8,
    addr: *mut u64,
    index: u8,
    at_sop: bool,
) -> c_int {
    if unsafe { in_apr_map(cb, at_sop) } {
        return EPERM;
    }
    let mut o = op(op_type);
    o.ptra = addr as u64;
    o.u8a = index;
    o.u8b = at_sop as u8;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_write_address_from_time_counter_04_00(
    cb: *mut Cb,
    addr: *mut u64,
    at_sop: bool,
) -> c_int {
    if !ampr_valid_u64_write_addr(addr as u64) {
        return EINVAL;
    }
    unsafe { write_address_from(cb, WRITE_ADDRESS_FROM_TIME_COUNTER, addr, 0, at_sop) }
}

pub unsafe fn ampr_cb_write_address_from_counter_04_00(
    cb: *mut Cb,
    addr: *mut u64,
    index: u8,
    at_sop: bool,
) -> c_int {
    if !ampr_valid_u64_write_addr(addr as u64) || !ampr_valid_counter_index_signed7(index) {
        return EINVAL;
    }
    unsafe { write_address_from(cb, WRITE_ADDRESS_FROM_COUNTER, addr, index, at_sop) }
}

pub unsafe fn ampr_cb_write_address_from_counter_pair_04_00(
    cb: *mut Cb,
    addr: *mut u64,
    index: u8,
    at_sop: bool,
) -> c_int {
    // Retail accepts only even 7-bit counter starts.
    if !ampr_valid_u64_write_addr(addr as u64) || index & 0x81 != 0 {
        return EINVAL;
    }
    unsafe { write_address_from(cb, WRITE_ADDRESS_FROM_COUNTER_PAIR, addr, index, at_sop) }
}

pub unsafe fn ampr_cb_nop(cb: *mut Cb, num_u32: u32) -> c_int {
    if num_u32 == 0 || num_u32 > 16 {
        return EINVAL;
    }
    let mut o = op(NOP);
    o.u32a = num_u32;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_nop_with_data(cb: *mut Cb, num_u32: u32, data: *const u32) -> c_int {
    if num_u32 > 15 {
        return EINVAL;
    }
    let mut o = op(NOP);
    o.u32a = num_u32;
    o.u32b = 1;
    o.cptr = data as u64;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_construct_nop(
    cb: *mut Cb,
    nop_type: u32,
    payload: *const c_void,
    size: u32,
    opt_word: *const u32,
) -> c_int {
    let has_opt = !opt_word.is_null();
    if size > if has_opt { 56 } else { 60 } {
        return EINVAL;
    }
    let mut o = op(NOP);
    o.u32a = ((size + 3) >> 2) + has_opt as u32;
    o.u32b = 1;
    o.u32c = nop_type;
    o.u64a = size as u64;
    o.u64b = if has_opt {
        u64::from(unsafe { opt_word.read() })
    } else {
        0
    };
    o.u8a = has_opt as u8;
    o.cptr = payload as u64;
    unsafe { append(cb, o) }
}

/// Set/Push marker with optional color.
pub unsafe fn ampr_cb_marker(
    cb: *mut Cb,
    push: bool,
    msg: *const c_char,
    color: u32,
    with_color: bool,
) -> c_int {
    let mut o = op(if push { MARKER_PUSH } else { MARKER_SET });
    if !unsafe { ampr_set_marker_text(&mut o, msg) } {
        return EINVAL;
    }
    if with_color {
        o.u32a = color;
        o.u32b = 1;
    }
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_cb_pop_marker(cb: *mut Cb) -> c_int {
    unsafe { append(cb, op(MARKER_POP)) }
}

// ---- APR command buffer -----------------------------------------------------

/// FreeBSD amd64 `PAGE_SIZE` from the payload SDK sysroot.
/// The kernel map writers enforce the 16 KiB AMPR granularity themselves.
const PAGE_SIZE: u64 = 4096;
const MAX_READ_LENGTH: u64 = 0x1_0000_0000;
const MAX_READ_OFFSET: u64 = 0x100_0000_0000;

fn rc_if(bad: bool) -> c_int {
    if bad {
        EINVAL
    } else {
        0
    }
}

fn validate_user_range(va: u64, size: u64) -> c_int {
    rc_if(va > VA_MAX || size > VA_MAX - va)
}

fn validate_map_shape(va: u64, size: u64) -> c_int {
    if size == 0 || (va | size) % PAGE_SIZE != 0 || va.wrapping_add(size) < va {
        return EINVAL;
    }
    validate_user_range(va, size)
}

pub fn aprValidateReadLength(length: u64) -> c_int {
    rc_if(length == 0 || length > MAX_READ_LENGTH)
}

pub fn aprValidateReadOffset(offset: u64) -> c_int {
    rc_if(offset >= MAX_READ_OFFSET)
}

pub fn aprValidateReadArgs(buffer: *const c_void, length: u64, offset: u64) -> c_int {
    let mut rc = aprValidateReadLength(length);
    if rc == 0 {
        rc = validate_user_range(buffer as u64, length);
    }
    if rc == 0 {
        aprValidateReadOffset(offset)
    } else {
        rc
    }
}

/// Measure-only call into the kernel map writer validates type/prot.
pub fn aprValidateMapBeginArgs(va: u64, size: u64, ty: c_int, prot: c_int) -> c_int {
    let rc = validate_map_shape(va, size);
    if rc != 0 {
        return rc;
    }
    let mut ignored = 0u64;
    let rc = unsafe {
        ammWriteMapCommand2(
            null_mut(),
            va,
            size,
            ty as u32 as u64,
            prot as u32 as u64,
            0,
            &mut ignored,
        )
    };
    rc.min(0)
}

pub fn aprValidateMapDirectBeginArgs(
    va: u64,
    dmem: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
) -> c_int {
    let rc = if dmem % PAGE_SIZE != 0 {
        EINVAL
    } else {
        validate_map_shape(va, size)
    };
    if rc != 0 {
        return rc;
    }
    let mut ignored = 0u64;
    let rc = unsafe {
        ammWriteMapDirectCommand(
            null_mut(),
            va,
            dmem,
            size,
            ty as u32 as u64,
            prot as u32 as u64,
            &mut ignored,
        )
    };
    rc.min(0)
}

/// `protWithCpuRwForAmprWrite`: AMPR-write targets map CPU_RW.
fn command_map_prot(prot: c_int) -> c_int {
    use super::sys::{
        SCE_KERNEL_PROT_AMPR_WRITE, SCE_KERNEL_PROT_CPU_READ, SCE_KERNEL_PROT_CPU_RW,
    };
    if prot & SCE_KERNEL_PROT_AMPR_WRITE == 0 {
        prot
    } else {
        (prot & !SCE_KERNEL_PROT_CPU_READ) | SCE_KERNEL_PROT_CPU_RW
    }
}

/// # Safety (all `ampr_apr_cb_*`)
/// `cb` is the header of a live AprCommandBuffer.
pub unsafe fn ampr_apr_cb_read_file(
    cb: *mut Cb,
    file_id: SceAprFileId,
    buffer: *mut c_void,
    length: u64,
    offset: u64,
) -> c_int {
    if aprValidateReadArgs(buffer, length, offset) != 0 {
        return EINVAL;
    }
    let mut o = op(APR_READ_FILE);
    o.u32a = file_id;
    o.ptra = buffer as u64;
    o.u64a = length;
    o.u64b = offset;
    unsafe { append_masked(cb, o, SG_VALID, 0) }
}

/// Gather/scatter reads need a prior ReadFile in this buffer.
unsafe fn append_sg_read(
    cb: *mut Cb,
    op_type: u8,
    buffer: *mut c_void,
    length: u64,
    offset: u64,
) -> c_int {
    if !unsafe { has_mask(cb, SG_VALID) } {
        return EINVAL;
    }
    let mut o = op(op_type);
    o.ptra = buffer as u64;
    o.u64a = length;
    o.u64b = offset;
    unsafe { append(cb, o) }
}

pub unsafe fn ampr_apr_cb_read_file_gather(cb: *mut Cb, length: u64, offset: u64) -> c_int {
    if aprValidateReadLength(length) != 0 || aprValidateReadOffset(offset) != 0 {
        return EINVAL;
    }
    unsafe { append_sg_read(cb, APR_READ_GATHER, null_mut(), length, offset) }
}

pub unsafe fn ampr_apr_cb_read_file_scatter(
    cb: *mut Cb,
    buffer: *mut c_void,
    length: u64,
) -> c_int {
    if aprValidateReadArgs(buffer, length, 0) != 0 {
        return EINVAL;
    }
    unsafe { append_sg_read(cb, APR_READ_SCATTER, buffer, length, 0) }
}

pub unsafe fn ampr_apr_cb_read_file_gather_scatter(
    cb: *mut Cb,
    buffer: *mut c_void,
    length: u64,
    offset: u64,
) -> c_int {
    if aprValidateReadArgs(buffer, length, offset) != 0 {
        return EINVAL;
    }
    unsafe { append_sg_read(cb, APR_READ_GATHER_SCATTER, buffer, length, offset) }
}

pub unsafe fn ampr_apr_cb_reset_gather_scatter_state(cb: *mut Cb) -> c_int {
    unsafe { append_masked(cb, op(APR_RESET_GATHER_SCATTER), 0, SG_VALID) }
}

pub unsafe fn ampr_apr_cb_map_begin(
    cb: *mut Cb,
    va: u64,
    size: u64,
    ty: c_int,
    prot: c_int,
) -> c_int {
    let rc = aprValidateMapBeginArgs(va, size, ty, prot);
    if rc != 0 {
        return rc;
    }
    if unsafe { has_mask(cb, MAP_ACTIVE) } {
        return EPERM;
    }
    let mut o = op(APR_MAP_BEGIN);
    o.u64a = va;
    o.u64b = size;
    o.u64c = ty as u32 as u64;
    o.u32a = command_map_prot(prot) as u32;
    o.u32b = ty as u32;
    unsafe { append_masked(cb, o, MAP_ACTIVE, 0) }
}

pub unsafe fn ampr_apr_cb_map_direct_begin(
    cb: *mut Cb,
    va: u64,
    dmem: u64,
    size: usize,
    ty: c_int,
    prot: c_int,
) -> c_int {
    let rc = aprValidateMapDirectBeginArgs(va, dmem, size as u64, ty, prot);
    if rc != 0 {
        return rc;
    }
    if unsafe { has_mask(cb, MAP_ACTIVE) } {
        return EPERM;
    }
    let mut o = op(APR_MAP_DIRECT_BEGIN);
    o.u64a = va;
    o.u64b = dmem;
    o.u64c = size as u64;
    o.u32a = ty as u32;
    o.u32b = command_map_prot(prot) as u32;
    unsafe { append_masked(cb, o, MAP_ACTIVE, 0) }
}

pub unsafe fn ampr_apr_cb_map_end(cb: *mut Cb) -> c_int {
    if !unsafe { has_mask(cb, MAP_ACTIVE) } {
        return EPERM;
    }
    unsafe { append_masked(cb, op(APR_MAP_END), 0, MAP_ACTIVE) }
}
