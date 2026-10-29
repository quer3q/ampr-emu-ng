//! Layout and word encoding for the `OpRecord` op record.
//! `u32` wrap in the bit layouts is kept explicit.

use core::mem::{align_of, offset_of, size_of};

use crate::{Command, Error};

/// Op type discriminants (`u8`).
pub mod op_type {
    pub const WAIT_ON_ADDRESS: u8 = 0;
    pub const WAIT_ON_COUNTER: u8 = 1;
    pub const WRITE_ADDRESS: u8 = 2;
    pub const WRITE_COUNTER: u8 = 3;
    pub const WRITE_EQUEUE: u8 = 4;
    pub const WRITE_ADDRESS_FROM_TIME_COUNTER: u8 = 5;
    pub const WRITE_ADDRESS_FROM_COUNTER: u8 = 6;
    pub const WRITE_ADDRESS_FROM_COUNTER_PAIR: u8 = 7;
    pub const NOP: u8 = 8;
    pub const MARKER_SET: u8 = 9;
    pub const MARKER_PUSH: u8 = 10;
    pub const MARKER_POP: u8 = 11;
    // AMM ops: decoded here, packed elsewhere.
    pub const AMM_MAP: u8 = 12;
    pub const AMM_MAP_DIRECT: u8 = 13;
    pub const AMM_UNMAP: u8 = 14;
    pub const AMM_REMAP: u8 = 15;
    pub const AMM_MULTI_MAP: u8 = 16;
    pub const AMM_MODIFY_PROTECT: u8 = 17;
    pub const AMM_MODIFY_MTYPE_PROTECT: u8 = 18;
    pub const AMM_MAP_AS_PRT: u8 = 19;
    pub const AMM_ALLOC_PA_FOR_PRT: u8 = 20;
    pub const AMM_REMAP_INTO_PRT: u8 = 21;
    pub const AMM_UNMAP_TO_PRT: u8 = 22;
    pub const APR_READ_FILE: u8 = 23;
    pub const APR_READ_GATHER: u8 = 24;
    pub const APR_READ_SCATTER: u8 = 25;
    pub const APR_READ_GATHER_SCATTER: u8 = 26;
    pub const APR_RESET_GATHER_SCATTER: u8 = 27;
    pub const APR_MAP_BEGIN: u8 = 28;
    pub const APR_MAP_DIRECT_BEGIN: u8 = 29;
    pub const APR_MAP_END: u8 = 30;
}
use op_type::*;

/// Unpacked op record with a fixed 64-bit `repr(C)` layout. Pointer fields are carried as
/// integers; this crate never dereferences them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpRecord {
    pub op_type: u8,
    pub buf_offset_bytes: u32,
    pub u64a: u64,
    pub u64b: u64,
    pub u64c: u64,
    pub u32a: u32,
    pub u32b: u32,
    pub u32c: u32,
    pub u8a: u8,
    pub u8b: u8,
    pub ptra: u64,
    pub cptr: u64,
    pub text: u64,
    pub text_length: u32,
}

const _: () = {
    assert!(size_of::<OpRecord>() == 80);
    assert!(align_of::<OpRecord>() == 8);
    assert!(offset_of!(OpRecord, op_type) == 0);
    assert!(offset_of!(OpRecord, buf_offset_bytes) == 4);
    assert!(offset_of!(OpRecord, u64a) == 8);
    assert!(offset_of!(OpRecord, u64b) == 16);
    assert!(offset_of!(OpRecord, u64c) == 24);
    assert!(offset_of!(OpRecord, u32a) == 32);
    assert!(offset_of!(OpRecord, u32b) == 36);
    assert!(offset_of!(OpRecord, u32c) == 40);
    assert!(offset_of!(OpRecord, u8a) == 44);
    assert!(offset_of!(OpRecord, u8b) == 45);
    assert!(offset_of!(OpRecord, ptra) == 48);
    assert!(offset_of!(OpRecord, cptr) == 56);
    assert!(offset_of!(OpRecord, text) == 64);
    assert!(offset_of!(OpRecord, text_length) == 72);
};

/// Packed size of an op: bytes and command count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Layout {
    pub bytes: u32,
    pub command_count: u32,
}

/// Up to 8 packed words; only the first `count` belong to the record.
pub type Words = ([u32; 8], usize);

impl OpRecord {
    /// `ampr_op_layout_checked`.
    pub fn layout(&self) -> Result<Layout, Error> {
        if self.is_marker_text() {
            let (dwords, count) = self.marker_layout()?;
            return Ok(Layout {
                bytes: (dwords * 4) as u32,
                command_count: count as u32,
            });
        }
        match self.fixed_size_bytes() {
            0 => Err(Error::InvalidArgument),
            bytes => Ok(Layout {
                bytes,
                command_count: 1,
            }),
        }
    }

    fn is_marker_text(&self) -> bool {
        matches!(self.op_type, MARKER_SET | MARKER_PUSH)
    }

    fn marker_type(&self) -> u32 {
        let with_color = self.u32b != 0;
        match (self.op_type == MARKER_SET, with_color) {
            (true, true) => 5,
            (true, false) => 1,
            (false, true) => 6,
            (false, false) => 2,
        }
    }

    /// `ampr_marker_layout_fits_native`: (dwords, command count).
    fn marker_layout(&self) -> Result<(u64, u64), Error> {
        if self.text == 0 || self.text_length == u32::MAX {
            return Err(Error::InvalidArgument);
        }
        let (dwords, count) = marker_layout(self.marker_type(), self.text_length as u64 + 1);
        if dwords == 0 || dwords > (u32::MAX / 4) as u64 || count == 0 || count > i32::MAX as u64 {
            return Err(Error::InvalidArgument);
        }
        Ok((dwords, count))
    }

    /// `ampr_fixed_op_size_bytes`; zero means unsupported.
    fn fixed_size_bytes(&self) -> u32 {
        match self.op_type {
            WAIT_ON_ADDRESS => wait_address_dwords(self.u64a) * 4,
            WAIT_ON_COUNTER => {
                wait_counter_dwords(self.u8b, self.u64a, self.wait_extra_flag(), self.u64b) * 4
            }
            WRITE_ADDRESS => write_address_dwords(self.u64a) * 4,
            WRITE_COUNTER => write_counter_dwords(self.u64a, self.u8b, self.u32b as u8) * 4,
            WRITE_EQUEUE => 20,
            WRITE_ADDRESS_FROM_TIME_COUNTER => write_address_dwords(0) * 4,
            WRITE_ADDRESS_FROM_COUNTER | WRITE_ADDRESS_FROM_COUNTER_PAIR => {
                write_address_dwords(self.u8a as u64) * 4
            }
            NOP if self.u32b != 0 => self.u32a.wrapping_add(1).wrapping_mul(4),
            NOP => self.u32a.wrapping_mul(4),
            MARKER_POP | APR_RESET_GATHER_SCATTER | APR_MAP_END => 4,
            APR_READ_FILE => {
                if self.u64b >> 32 != 0 {
                    24
                } else {
                    20
                }
            }
            APR_READ_GATHER => {
                if self.u64b >= 0x40000 {
                    12
                } else {
                    8
                }
            }
            APR_READ_SCATTER | APR_MAP_BEGIN => 12,
            APR_READ_GATHER_SCATTER => {
                if self.u64b >> 32 != 0 {
                    20
                } else {
                    16
                }
            }
            APR_MAP_DIRECT_BEGIN => 16,
            _ => 0,
        }
    }

    fn wait_extra_flag(&self) -> u8 {
        ((self.u32c >> 8) & 3) as u8
    }
}

fn marker_layout(marker_type: u32, len_with_nul: u64) -> (u64, u64) {
    let color = (marker_type >= 5) as u64;
    let first_payload = 4 * (marker_type < 5) as u64 + 56;
    if len_with_nul <= first_payload {
        return (((len_with_nul + 3) >> 2) + color + 1, 1);
    }
    let remaining = len_with_nul - first_payload;
    let (full, tail) = (remaining / 60, remaining % 60);
    let mut dwords = (first_payload >> 2) + color + 1 + full * 16;
    let mut count = 1 + full;
    if tail != 0 {
        dwords += ((tail + 3) >> 2) + 1;
        count += 1;
    }
    (dwords, count)
}

fn wait_address_dwords(reference: u64) -> u32 {
    match reference {
        0 => 2,
        r if r >> 32 == 0 => 3,
        _ => 4,
    }
}

fn write_address_dwords(value: u64) -> u32 {
    if value < 4 {
        2
    } else if value < 0x4_0000_0000 {
        3
    } else {
        4
    }
}

fn counter_value_width(value_width: u8) -> u32 {
    match value_width {
        0 => 64,
        1 => 32,
        2 | 3 => 16,
        _ => 8,
    }
}

fn mask_counter_value(value: u64, value_width: u8) -> u64 {
    match counter_value_width(value_width) {
        64 => value,
        bits => value & ((1u64 << bits) - 1),
    }
}

fn write_counter_dwords(value: u64, value_width: u8, mode: u8) -> u32 {
    let masked = mask_counter_value(value, value_width);
    let wide = if masked >> 32 != 0 { 3 } else { 2 };
    if (((value_width as u32 & 7) ^ 1) | (mode as u32 & 7)) != 0 || masked >= 0x1000 {
        wide
    } else {
        1
    }
}

fn wait_counter_dwords(value_width: u8, reference: u64, extra: u8, extra_value: u64) -> u32 {
    if value_width == 1 && reference <= 0xff && extra == 0 {
        return 1;
    }
    if reference > 0xffff {
        if reference >> 32 != 0 || (extra_value >> 32 != 0 && extra != 0) {
            return 2 * (extra != 0) as u32 + 3;
        }
        return if extra != 0 { 3 } else { 2 };
    }
    if extra == 0 || extra_value < 0x10000 {
        2
    } else if extra_value >> 32 != 0 {
        5
    } else {
        3
    }
}

/// Length nibble shared by most opcodes: `((dwords << 8) + 3840) & mask`.
fn len_bits(dwords: u32, mask: u32) -> u32 {
    ((dwords << 8).wrapping_add(3840)) & mask
}

impl OpRecord {
    /// Per-op words from `ampr_write_op_with_layout` for every op except markers with
    /// text (`encode_marker`). A data `Nop` yields only its header word; the payload
    /// bytes are copied by the caller. A zero-length plain `Nop` yields no words.
    pub fn encode_words(&self) -> Result<Words, Error> {
        let mut w = [0u32; 8];
        let count = match self.op_type {
            WAIT_ON_ADDRESS => {
                let (addr, reference) = (self.ptra, self.u64a);
                let dwords = wait_address_dwords(reference);
                w[0] = ((addr >> 16) & 0xffff_0000) as u32
                    | len_bits(dwords, 0xef00)
                    | (self.u32a & 7) << 13
                    | (self.u32c & 1) << 12
                    | 1;
                w[1] = addr as u32;
                if reference != 0 {
                    w[2] = reference as u32;
                    if dwords == 4 {
                        w[3] = (reference >> 32) as u32;
                    }
                }
                dwords
            }
            WAIT_ON_COUNTER => pack_wait_counter(
                &mut w,
                self.u8a,
                self.u8b,
                self.u64a,
                (self.u32b & 7) as u8,
                self.wait_extra_flag(),
                self.u64b,
                (self.u32c & 1) as u8,
            ),
            WRITE_ADDRESS => pack_write_address(&mut w, self.ptra, self.u64a, 0, self.u8a != 0),
            WRITE_ADDRESS_FROM_TIME_COUNTER => {
                pack_write_address(&mut w, self.ptra, 0, 1, self.u8b != 0)
            }
            WRITE_ADDRESS_FROM_COUNTER => {
                pack_write_address(&mut w, self.ptra, self.u8a as u64, 2, self.u8b != 0)
            }
            WRITE_ADDRESS_FROM_COUNTER_PAIR => {
                pack_write_address(&mut w, self.ptra, self.u8a as u64, 3, self.u8b != 0)
            }
            WRITE_COUNTER => pack_write_counter(
                &mut w,
                self.u8a,
                self.u8b,
                self.u64a,
                self.u32b as u8,
                self.u32c != 0,
            ),
            WRITE_EQUEUE => {
                let (eq, data) = (self.u64b, self.u64a);
                let opcode = if self.u8a != 0 { 1144 } else { 1032 };
                w[0] = opcode | ((eq >> 16) & 0xffff_0000) as u32;
                w[1] = eq as u32;
                w[2] = self.u32b;
                w[3] = data as u32;
                w[4] = (data >> 32) as u32;
                5
            }
            NOP => {
                let n = self.u32a;
                if self.u32b != 0 {
                    w[0] = (self.u32c & 0xf) << 12 | (n & 0xf) << 8 | 0x5452_000f;
                    1
                } else if n == 0 {
                    0
                } else {
                    w[0] = (n.wrapping_mul(4).wrapping_sub(4) << 6) | 0x5452_000f;
                    1
                }
            }
            MARKER_POP => {
                w[0] = 0x5452_300f;
                1
            }
            APR_READ_FILE => {
                let command = Command::ReadFile {
                    file_id: self.u32a,
                    address: self.ptra,
                    length: self.u64a,
                    offset: self.u64b,
                };
                return command_words(command);
            }
            APR_READ_GATHER => {
                return command_words(Command::ReadGather {
                    length: self.u64a,
                    offset: self.u64b,
                });
            }
            _ => return self.encode_apr_words(),
        };
        Ok((w, count as usize))
    }

    fn encode_apr_words(&self) -> Result<Words, Error> {
        let mut w = [0u32; 8];
        let buffer = self.ptra;
        let count = match self.op_type {
            APR_READ_SCATTER => {
                w[0] = ((buffer >> 20) & 0x0fff_f000) as u32 | 0x22a;
                w[1] = self.u64a.wrapping_sub(1) as u32;
                w[2] = buffer as u32;
                3
            }
            APR_READ_GATHER_SCATTER => {
                let offset = self.u64b;
                let dwords: u32 = if offset >> 32 != 0 { 5 } else { 4 };
                w[0] = ((offset as u32) << 12 & 0x3fff_f000)
                    | ((dwords << 8).wrapping_add(1792) & 0x700)
                    | 43;
                w[1] = self.u64a.wrapping_sub(1) as u32;
                w[2] = buffer as u32;
                w[3] = ((buffer >> 32) as u32 & 0xffff) | (offset as u32 & 0xfffc_0000);
                if dwords == 5 {
                    w[4] = ((offset >> 32) & 0xff) as u32;
                }
                dwords
            }
            APR_RESET_GATHER_SCATTER => {
                w[0] = 47;
                1
            }
            APR_MAP_BEGIN => {
                let (va, size) = (self.u64a, self.u64b);
                let (map_type, prot) = (self.u64c as u32, self.u32a);
                w[0] = ((prot << 12) & 0x07ff_f000) | map_type << 27 | 557;
                w[1] = (va >> 14) as u32;
                w[2] = (((va >> 46) & 3) | ((size >> 12) & 0x1fff_fffc)) as u32;
                3
            }
            APR_MAP_DIRECT_BEGIN => {
                let (va, dmem_offset, size) = (self.u64a, self.u64b, self.u64c);
                let (map_type, prot) = (self.u32a, self.u32b);
                w[0] = ((prot << 12) & 0x07ff_f000) | map_type << 27 | 813;
                w[1] = (va >> 14) as u32;
                w[2] = (((va >> 46) & 3) | ((size >> 12) & 0x1fff_fffc) | 0x8000_0000) as u32;
                w[3] = ((dmem_offset >> 14) & 0x03ff_ffff) as u32;
                4
            }
            APR_MAP_END => {
                w[0] = 46;
                1
            }
            _ => return Err(Error::InvalidArgument),
        };
        Ok((w, count as usize))
    }
}

fn command_words(command: Command) -> Result<Words, Error> {
    let (words, count) = command.encode_words()?;
    let mut w = [0u32; 8];
    w[..count].copy_from_slice(&words[..count]);
    Ok((w, count))
}

#[allow(clippy::too_many_arguments)]
fn pack_wait_counter(
    w: &mut [u32; 8],
    counter_index: u8,
    value_width: u8,
    reference: u64,
    compare: u8,
    extra: u8,
    extra_value: u64,
    flush: u8,
) -> u32 {
    let dwords = wait_counter_dwords(value_width, reference, extra, extra_value);
    w[0] = (reference as u8 as u32) << 16
        | len_bits(dwords, 0xf00)
        | (compare as u32 & 7) << 13
        | (flush as u32 & 1) << 12
        | (counter_index as u32) << 24
        | 2;
    if dwords < 2 {
        return dwords;
    }
    w[1] =
        (reference as u32) >> 8 | ((value_width as u32 & 7) ^ 1) << 24 | (extra as u32 & 3) << 28;
    if reference <= 0xffff {
        if extra == 0 {
            return dwords;
        }
        if extra_value < 0x10000 {
            w[1] |= ((extra_value << 8) as u32) & 0x00ff_ff00;
            return dwords;
        }
    }
    // With dwords == 3 and an extra value, w[3] is computed but not emitted.
    w[2] = (reference >> 32) as u32;
    if extra != 0 {
        w[3] = extra_value as u32;
        if dwords >= 5 {
            w[4] = (extra_value >> 32) as u32;
        }
    }
    dwords
}

fn pack_write_address(w: &mut [u32; 8], address: u64, value: u64, class: u8, at_sop: bool) -> u32 {
    let dwords = write_address_dwords(value);
    let opcode = if at_sop { 117 } else { 5 };
    let length_bits = (dwords << 14).wrapping_add(0x8000) as u16 as u32;
    w[0] = ((address >> 16) & 0xffff_0000) as u32
        | len_bits(dwords, 0xf00)
        | opcode
        | ((value & 3) as u32) << 12
        | length_bits;
    w[1] = (address & 0xffff_fff8) as u32 | (class as u32 & 7);
    if value >= 4 {
        w[2] = (value >> 2) as u32;
        if value - 4 >= 0x3_ffff_fffc {
            w[3] = (value >> 34) as u32;
        }
    }
    dwords
}

fn pack_write_counter(
    w: &mut [u32; 8],
    counter_index: u8,
    value_width: u8,
    value: u64,
    mode: u8,
    at_sop: bool,
) -> u32 {
    let masked = mask_counter_value(value, value_width);
    let dwords = write_counter_dwords(value, value_width, mode);
    let opcode = if at_sop { 118 } else { 6 };
    w[0] = opcode
        | len_bits(dwords, 0xf00)
        | (counter_index as u32) << 24
        | ((masked as u32) << 12 & 0x00ff_f000);
    if dwords >= 2 {
        w[1] =
            (masked >> 12) as u32 | ((value_width as u32 & 7) ^ 1) << 20 | (mode as u32 & 7) << 24;
        if dwords != 2 {
            w[2] = (masked >> 32) as u32;
        }
    }
    dwords
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

impl OpRecord {
    /// Marker Set/Push records from `ampr_write_op_with_layout`. `text_with_nul` holds
    /// `text_length + 1` bytes ending in NUL. Zeroes all of `out`, which must hold at
    /// least `layout().bytes`; returns the bytes written.
    pub fn encode_marker(&self, text_with_nul: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !self.is_marker_text() {
            return Err(Error::InvalidArgument);
        }
        let bytes = self.layout()?.bytes as usize;
        let len = self.text_length as usize + 1;
        if text_with_nul.len() != len || out.len() < bytes {
            return Err(Error::InvalidArgument);
        }
        out.fill(0);
        let marker_type = self.marker_type();
        let with_color = marker_type >= 5;
        let first_payload = 4 * (marker_type < 5) as usize + 56;
        let first = len.min(first_payload);
        let first_dwords = ((first + 3) >> 2) as u32 + with_color as u32;
        put_word(
            out,
            0,
            0x5452_000f | (marker_type & 0xffff) << 12 | (first_dwords & 0xf) << 8,
        );
        let mut cursor = 4;
        if with_color {
            put_word(out, cursor, self.u32a);
            cursor += 4;
        }
        out[cursor..cursor + first].copy_from_slice(&text_with_nul[..first]);
        cursor += align4(first);
        let mut consumed = first;
        while consumed < len {
            let chunk = (len - consumed).min(60);
            put_word(
                out,
                cursor,
                0x5452_400f | ((((chunk + 3) >> 2) as u32) & 0xf) << 8,
            );
            cursor += 4;
            out[cursor..cursor + chunk].copy_from_slice(&text_with_nul[consumed..consumed + chunk]);
            cursor += align4(chunk);
            consumed += chunk;
        }
        Ok(cursor)
    }
}

fn put_word(out: &mut [u8], at: usize, word: u32) {
    out[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
