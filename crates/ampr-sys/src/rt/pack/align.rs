//! Alignment helpers for sizes and u64 offsets.

pub(crate) fn align_up_size(value: usize, alignment: usize) -> usize {
    if !alignment.is_power_of_two() || value > usize::MAX - (alignment - 1) {
        return usize::MAX;
    }
    (value + alignment - 1) & !(alignment - 1)
}

pub(crate) fn align_down_u64(value: u64, alignment: u64) -> u64 {
    value & !alignment.wrapping_sub(1)
}

pub(crate) unsafe fn align_up_u64(value: u64, alignment: u64, out: *mut u64) -> bool {
    if out.is_null() || !alignment.is_power_of_two() || value > u64::MAX - (alignment - 1) {
        return false;
    }
    *out = (value + alignment - 1) & !(alignment - 1);
    true
}
