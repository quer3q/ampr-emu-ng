//! Alignment helper for sizes.

pub(crate) fn align_up_size(value: usize, alignment: usize) -> usize {
    if !alignment.is_power_of_two() || value > usize::MAX - (alignment - 1) {
        return usize::MAX;
    }
    (value + alignment - 1) & !(alignment - 1)
}
