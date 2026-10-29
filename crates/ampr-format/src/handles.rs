//! Virtual handle encoding: fds, directory fds,
//! AIO submit ids and AIO group ids share one 32-bit layout,
//! `tag(8) | generation(16) | slot(8)`.

/// Handle kinds; the discriminant is the C ABI value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Kind {
    Fd = 0,
    Aio = 1,
    DirectoryFd = 2,
    AioGroup = 3,
}

pub const TAG_MASK: u32 = 0xff00_0000;
pub const GENERATION_MASK: u32 = 0xffff;

impl Kind {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Fd,
            1 => Self::Aio,
            2 => Self::DirectoryFd,
            3 => Self::AioGroup,
            _ => return None,
        })
    }

    /// High-byte tag of this handle kind.
    pub fn tag(self) -> u32 {
        match self {
            Self::Fd => 0x6500_0000,
            Self::Aio => 0x6600_0000,
            Self::DirectoryFd => 0x6700_0000,
            Self::AioGroup => 0x6800_0000,
        }
    }
}

/// Next handle generation: increments within 16 bits, skipping zero.
pub fn next_generation(current: u16) -> u32 {
    match (u32::from(current) + 1) & GENERATION_MASK {
        0 => 1,
        g => g,
    }
}

/// Encodes a handle. The slot is OR-ed in unmasked.
pub fn encode(kind: Kind, slot: u32, generation: u16) -> u32 {
    kind.tag() | (u32::from(generation) << 8) | slot
}

/// Decodes a handle: `(slot, generation)` when the tag matches and the
/// low-byte slot is below `slot_limit`.
pub fn decode(kind: Kind, value: u32, slot_limit: u32) -> Option<(u32, u16)> {
    if value & TAG_MASK != kind.tag() {
        return None;
    }
    let slot = value & 0xff;
    if slot >= slot_limit {
        return None;
    }
    Some((slot, ((value >> 8) & GENERATION_MASK) as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_checks_tag_slot_limit_and_generation_wrap() {
        assert_eq!(next_generation(0xffff), 1);
        assert_eq!(next_generation(7), 8);
        let fd = encode(Kind::Fd, 3, 0xbeef);
        assert_eq!(fd, 0x65be_ef03);
        assert_eq!(decode(Kind::Fd, fd, 256), Some((3, 0xbeef)));
        assert_eq!(decode(Kind::Fd, fd, 3), None);
        assert_eq!(decode(Kind::Aio, fd, 256), None);
        let group = encode(Kind::AioGroup, 255, 1);
        assert_eq!(decode(Kind::AioGroup, group, 256), Some((255, 1)));
        assert_eq!(
            decode(Kind::DirectoryFd, 0x6700_0000 | 9, 256),
            Some((9, 0))
        );
    }
}
