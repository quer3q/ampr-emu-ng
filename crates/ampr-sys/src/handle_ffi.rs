//! Scalar C ABI for virtual handle encoding (`src/ampr_emu_pack.cpp`
//! `encode_virtual_*` / `decode_virtual_*` shims). Called on every fd/AIO op.

use ampr_format::handles::{self, Kind};

pub fn ampr_rust_virtual_next_generation(current: u16) -> u32 {
    handles::next_generation(current)
}

/// Returns 0 for an unknown `kind`.
pub fn ampr_rust_virtual_encode(kind: u32, slot: u32, generation: u16) -> u32 {
    Kind::from_u32(kind).map_or(0, |k| handles::encode(k, slot, generation))
}

/// # Safety
/// `slot` and `generation` are each null or point to a writable value.
pub unsafe fn ampr_rust_virtual_decode(
    kind: u32,
    value: u32,
    slot_limit: u32,
    slot: *mut u32,
    generation: *mut u16,
) -> bool {
    let Some((s, g)) = Kind::from_u32(kind).and_then(|k| handles::decode(k, value, slot_limit))
    else {
        return false;
    };
    if !slot.is_null() {
        unsafe { slot.write(s) };
    }
    if !generation.is_null() {
        unsafe { generation.write(g) };
    }
    true
}
