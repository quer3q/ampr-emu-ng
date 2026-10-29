use core::ffi::c_void;
use core::mem::{align_of, offset_of, size_of};

/// Retail `SceAmprCommandBuffer` from `include/ampr.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SceAmprCommandBuffer {
    pub r#type: i32,
    pub offset: u32,
    /// C declares this field `volatile int32_t`; volatile access belongs at the FFI edge.
    pub num: i32,
    pub bufsize: u32,
    pub buffer: *mut c_void,
}

const _: () = {
    assert!(size_of::<SceAmprCommandBuffer>() == 24);
    assert!(align_of::<SceAmprCommandBuffer>() == 8);
    assert!(offset_of!(SceAmprCommandBuffer, r#type) == 0);
    assert!(offset_of!(SceAmprCommandBuffer, offset) == 4);
    assert!(offset_of!(SceAmprCommandBuffer, num) == 8);
    assert!(offset_of!(SceAmprCommandBuffer, bufsize) == 12);
    assert!(offset_of!(SceAmprCommandBuffer, buffer) == 16);
};

/// Mask/shift view of the x86_64 `__SceAprMapState` bitfield in `include/ampr.h`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AprMapState(u64);

impl AprMapState {
    const PAGES_MASK: u64 = (1 << 21) - 1;
    const VA_MASK: u64 = (1 << 34) - 1;

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn new(in_map_begin: bool, num_pages_16k: u32, va_map_b14_47: u64) -> Option<Self> {
        if num_pages_16k as u64 > Self::PAGES_MASK || va_map_b14_47 > Self::VA_MASK {
            return None;
        }
        Some(Self(
            (in_map_begin as u64) | ((num_pages_16k as u64) << 1) | (va_map_b14_47 << 22),
        ))
    }
}

const _: () = assert!(size_of::<AprMapState>() == 8);
