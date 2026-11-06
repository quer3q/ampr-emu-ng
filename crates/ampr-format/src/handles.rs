//! Directory fds, AIO submit ids and AIO group ids use
//! `tag(8) | generation(16) | slot(8)`. Virtual packed-file fds use numeric
//! fds: the runtime reserves a real descriptor in the low range on open, so
//! the number is valid for the kernel too and cannot collide with another
//! file. A reused number names the new file, like any OS fd.

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
/// High bound of the low descriptor range used for packed files.
pub const FD_LIMIT: u32 = 256;

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

    /// High-byte tag of a tagged handle kind; packed fds have no tag.
    pub fn tag(self) -> u32 {
        match self {
            Self::Fd => 0,
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

/// Encodes a handle. For packed fds `slot` is the reserved descriptor number.
pub fn encode(kind: Kind, slot: u32, generation: u16) -> u32 {
    if kind == Kind::Fd {
        debug_assert!(slot < FD_LIMIT);
        return slot;
    }
    kind.tag() | (u32::from(generation) << 8) | slot
}

/// Decodes a handle: `(slot, generation)` when the tag matches and the
/// low-byte slot is below `slot_limit`; for a packed fd `slot` is the number.
pub fn decode(kind: Kind, value: u32, slot_limit: u32) -> Option<(u32, u16)> {
    if kind == Kind::Fd {
        return (value < slot_limit && value < FD_LIMIT).then_some((value, 0));
    }
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
        assert_eq!(fd, 3);
        assert_eq!(decode(Kind::Fd, fd, 256), Some((3, 0)));
        assert_eq!(decode(Kind::Fd, fd, 3), None);
        assert_eq!(decode(Kind::Aio, fd, 256), None);
        let group = encode(Kind::AioGroup, 255, 1);
        assert_eq!(decode(Kind::AioGroup, group, 256), Some((255, 1)));
        assert_eq!(encode(Kind::Fd, 255, 99), 255);
        assert_eq!(decode(Kind::Fd, 255, 256), Some((255, 0)));
        assert_eq!(decode(Kind::Fd, 256, 256), None);
        assert_eq!(
            decode(Kind::DirectoryFd, 0x6700_0000 | 9, 256),
            Some((9, 0))
        );
    }
}
