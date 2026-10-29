const USER_VA_MAX: u64 = 0xF000_0000_0000;
const READ_LENGTH_MAX: u64 = 0x1_0000_0000;
const READ_OFFSET_MAX: u64 = 0x100_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    NoGatherState,
    Full,
}

/// Addresses are encoded as numbers; this crate never dereferences game memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    ReadFile {
        file_id: u32,
        address: u64,
        length: u64,
        offset: u64,
    },
    ReadGather {
        length: u64,
        offset: u64,
    },
}

impl Command {
    /// Packed size from `ampr_fixed_op_size_bytes`.
    pub fn measure(self) -> Result<usize, Error> {
        match self {
            Self::ReadFile {
                address,
                length,
                offset,
                ..
            } => {
                valid_read(length, offset)?;
                if address > USER_VA_MAX || length > USER_VA_MAX - address {
                    return Err(Error::InvalidArgument);
                }
                Ok(if offset >> 32 != 0 { 24 } else { 20 })
            }
            Self::ReadGather { length, offset } => {
                valid_read(length, offset)?;
                Ok(if offset >= 0x40000 { 12 } else { 8 })
            }
        }
    }

    /// Encode one validated command into little-endian host words.
    /// Only the first `measure() / 4` words are part of the record.
    pub fn encode_words(self) -> Result<([u32; 6], usize), Error> {
        let dwords = self.measure()? / 4;
        let mut words = [0u32; 6];
        match self {
            Self::ReadFile {
                file_id,
                address,
                length,
                offset,
            } => {
                words[0] = ((offset as u32) << 12 & 0x3fff_f000)
                    | ((((dwords as u32) << 8) + 1792) & 0x700)
                    | 40;
                words[1] = (length - 1) as u32;
                words[2] = file_id & 0x7fff_ffff;
                words[3] = address as u32;
                words[4] = ((address >> 32) as u32 & 0xffff) | (offset as u32 & 0xfffc_0000);
                if dwords == 6 {
                    words[5] = (offset >> 32) as u32 & 0xff;
                }
            }
            Self::ReadGather { length, offset } => {
                words[0] = ((offset as u32) << 12 & 0x3fff_f000)
                    | ((((dwords as u32) << 8) + 768) & 0x300)
                    | 41;
                words[1] = (length - 1) as u32;
                if dwords == 3 {
                    words[2] = (offset >> 18) as u32 & 0x3f_ffff;
                }
            }
        }
        Ok((words, dwords))
    }
}

fn valid_read(length: u64, offset: u64) -> Result<(), Error> {
    if length == 0 || length > READ_LENGTH_MAX || offset >= READ_OFFSET_MAX {
        Err(Error::InvalidArgument)
    } else {
        Ok(())
    }
}
