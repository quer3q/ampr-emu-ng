//! Bounded APR command encoding for the first AMPR command-buffer ABI slice.
#![no_std]
#![forbid(unsafe_code)]

mod command;
mod decode;
mod header;
mod op;
pub use command::{Command, Error};
pub use decode::{decode_packed_op, DecodeError};
pub use header::{AprMapState, SceAmprCommandBuffer};
pub use op::{op_type, Layout, OpRecord, Words};

const BUFFER_MAX: usize = 64 * 1024 * 1024;
const SCATTER_GATHER_VALID: i32 = 0x0001_0000;

/// Owns an aligned byte slice and keeps its ABI header bound to that slice.
pub struct CommandBuffer<'a> {
    header: SceAmprCommandBuffer,
    bytes: &'a mut [u8],
}

impl<'a> CommandBuffer<'a> {
    /// Checks the buffer size limit and 4-byte alignment.
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, Error> {
        if bytes.is_empty()
            || bytes.len() > BUFFER_MAX
            || bytes.len() & 3 != 0
            || (bytes.as_ptr() as usize) & 3 != 0
        {
            return Err(Error::InvalidArgument);
        }
        let header = SceAmprCommandBuffer {
            r#type: 0,
            offset: 0,
            num: 0,
            bufsize: bytes.len() as u32,
            buffer: bytes.as_mut_ptr().cast(),
        };
        Ok(Self { header, bytes })
    }

    pub fn header(&self) -> &SceAmprCommandBuffer {
        &self.header
    }
    pub fn encoded(&self) -> &[u8] {
        &self.bytes[..self.header.offset as usize]
    }

    pub fn append(&mut self, command: Command) -> Result<(), Error> {
        let size = command.measure()?;
        if matches!(command, Command::ReadGather { .. })
            && self.header.r#type & SCATTER_GATHER_VALID == 0
        {
            return Err(Error::NoGatherState);
        }
        let start = self.header.offset as usize;
        let end = start.checked_add(size).ok_or(Error::Full)?;
        if end > self.bytes.len() {
            return Err(Error::Full);
        }
        let next_count = self
            .header
            .num
            .checked_add(1)
            .ok_or(Error::InvalidArgument)?;
        let (words, dwords) = command.encode_words()?;
        for (chunk, word) in self.bytes[start..end]
            .chunks_exact_mut(4)
            .zip(words[..dwords].iter())
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        self.header.offset = end as u32;
        self.header.num = next_count;
        if matches!(command, Command::ReadFile { .. }) {
            self.header.r#type |= SCATTER_GATHER_VALID;
        }
        Ok(())
    }
}
