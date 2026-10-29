//! Bounded x86-64 instruction decoder for the libkernel hooks.
//!
//! A thin safe wrapper over iced-x86 that fills the subset of the old
//! Hacker Disassembler Engine 64 (`hde64s`) result that
//! src/ampr_libkernel_hook.cpp reads. Decoding reads at most
//! `MAX_INSN_LEN` bytes of the slice it is given.
#![no_std]
#![forbid(unsafe_code)]

use iced_x86::{Decoder, DecoderOptions, OpKind, Register};

/// Architectural maximum x86 instruction length.
pub const MAX_INSN_LEN: usize = 15;

pub const F_MODRM: u32 = 0x0000_0001;
pub const F_SIB: u32 = 0x0000_0002;
pub const F_IMM8: u32 = 0x0000_0004;
pub const F_IMM16: u32 = 0x0000_0008;
pub const F_IMM32: u32 = 0x0000_0010;
pub const F_IMM64: u32 = 0x0000_0020;
pub const F_DISP8: u32 = 0x0000_0040;
pub const F_DISP16: u32 = 0x0000_0080;
pub const F_DISP32: u32 = 0x0000_0100;
pub const F_RELATIVE: u32 = 0x0000_0200;
pub const F_RIP_RELATIVE: u32 = 0x0000_0400;
pub const F_ERROR: u32 = 0x0000_1000;
pub const F_ERROR_OPCODE: u32 = 0x0000_2000;
pub const F_PREFIX_REPNZ: u32 = 0x0100_0000;
pub const F_PREFIX_REPX: u32 = 0x0200_0000;
pub const F_PREFIX_66: u32 = 0x0400_0000;
pub const F_PREFIX_67: u32 = 0x0800_0000;
pub const F_PREFIX_LOCK: u32 = 0x1000_0000;
pub const F_PREFIX_SEG: u32 = 0x2000_0000;
pub const F_PREFIX_REX: u32 = 0x4000_0000;

pub const PREFIX_SEGMENT_CS: u8 = 0x2e;

pub const META_NONE: u8 = 0;
pub const META_REL_CALL: u8 = 1;
pub const META_REL_JMP: u8 = 2;
pub const META_REL_JCC: u8 = 3;
pub const META_RIP_REL: u8 = 4;
pub const META_RIP_REL_LEA64: u8 = 5;
pub const META_RIP_REL_MOV_R64_PTR: u8 = 6;
pub const META_RIP_REL_CMP_PTR_R64: u8 = 7;

/// Decode result, field for field the C `hde64s`. `imm` and `disp` hold the
/// little-endian bytes of the C unions: a narrower write replaces only the
/// low bytes, exactly as the C union member store did.
///
/// Unlike the C decoder, `rex` holds the REX byte for legacy encodings (the
/// C code left it 0). Its only reader, clear_rex_b_for_copied_instruction,
/// then clears REX.B when a RIP-relative operand is rewritten to
/// `[scratch+0]`, where REX.B would otherwise select r8-r15 as the base.
/// VEX encodings leave all `rex*` fields 0, as the C decoder did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hde64 {
    pub len: u8,
    pub p_rep: u8,
    pub p_lock: u8,
    pub p_seg: u8,
    pub p_66: u8,
    pub p_67: u8,
    pub rex: u8,
    pub rex_w: u8,
    pub rex_r: u8,
    pub rex_x: u8,
    pub rex_b: u8,
    pub opcode: u8,
    pub opcode2: u8,
    pub modrm: u8,
    pub modrm_mod: u8,
    pub modrm_reg: u8,
    pub modrm_rm: u8,
    pub sib: u8,
    pub sib_scale: u8,
    pub sib_index: u8,
    pub sib_base: u8,
    pub imm: u64,
    pub disp: u32,
    pub imm_offset: u8,
    pub disp_offset: u8,
    pub operand_reg: u8,
    pub branch_opcode: u8,
    pub meta: u8,
    pub flags: u32,
}

/// Size in bytes of the decoded immediate (or relative displacement).
pub fn imm_size(hs: &Hde64) -> usize {
    if hs.flags & F_IMM64 != 0 {
        8
    } else if hs.flags & F_IMM32 != 0 {
        4
    } else if hs.flags & F_IMM16 != 0 {
        2
    } else if hs.flags & F_IMM8 != 0 {
        1
    } else {
        0
    }
}

fn load_i32(code: &[u8], offset: usize) -> Option<i32> {
    let bytes = code.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Branch target of a rel8/rel32 instruction decoded from `code` at `ip`.
pub fn relative_target(code: &[u8], ip: usize, hs: &Hde64) -> Option<usize> {
    if hs.flags & F_RELATIVE == 0 || hs.imm_offset == 0 {
        return None;
    }
    let offset = usize::from(hs.imm_offset);
    let rel = match imm_size(hs) {
        1 => isize::from(*code.get(offset)? as i8),
        4 => load_i32(code, offset)? as isize,
        _ => return None,
    };
    Some(
        ip.wrapping_add(usize::from(hs.len))
            .wrapping_add_signed(rel),
    )
}

/// Absolute address referenced by a RIP-relative instruction at `ip`.
pub fn rip_absolute(code: &[u8], ip: usize, hs: &Hde64) -> Option<usize> {
    if hs.flags & F_RIP_RELATIVE == 0 || hs.disp_offset == 0 {
        return None;
    }
    let disp = load_i32(code, usize::from(hs.disp_offset))? as isize;
    Some(
        ip.wrapping_add(usize::from(hs.len))
            .wrapping_add_signed(disp),
    )
}

enum Encoding {
    Legacy,
    Vex,
    Other,
}

fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67
    )
}

fn read_le(code: &[u8], offset: usize, size: usize) -> u64 {
    let mut value = 0u64;
    for i in (0..size).rev() {
        value = (value << 8) | u64::from(code.get(offset + i).copied().unwrap_or(0));
    }
    value
}

/// Decode one 64-bit instruction from the start of `code` (at most
/// `MAX_INSN_LEN` bytes are read). Any failure sets `F_ERROR`; callers must
/// check it, as with the C decoder.
pub fn decode(code: &[u8]) -> Hde64 {
    let code = &code[..code.len().min(MAX_INSN_LEN)];
    let mut hs = Hde64::default();
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    let instr = decoder.decode();
    hs.len = instr.len() as u8;
    if instr.is_invalid() || hs.len == 0 {
        hs.flags = F_ERROR | F_ERROR_OPCODE;
        if hs.len == 0 {
            hs.len = code.len().max(1) as u8;
        }
        return hs;
    }
    let len = usize::from(hs.len);

    // Legacy prefixes, last one in each group wins; a REX only counts when
    // it is the last byte before the opcode (iced/CPU semantics).
    let mut p = 0usize;
    let mut rex = 0u8;
    while p < len {
        let b = code[p];
        match b {
            0xf2 => {
                hs.p_rep = b;
                hs.flags |= F_PREFIX_REPNZ;
            }
            0xf3 => {
                hs.p_rep = b;
                hs.flags |= F_PREFIX_REPX;
            }
            0xf0 => {
                hs.p_lock = b;
                hs.flags |= F_PREFIX_LOCK;
            }
            0x66 => {
                hs.p_66 = b;
                hs.flags |= F_PREFIX_66;
            }
            0x67 => {
                hs.p_67 = b;
                hs.flags |= F_PREFIX_67;
            }
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                hs.p_seg = b;
                hs.flags |= F_PREFIX_SEG;
            }
            0x40..=0x4f => rex = b,
            _ => break,
        }
        if is_legacy_prefix(b) {
            rex = 0;
        }
        p += 1;
    }

    // iced accepted the instruction, so the first byte after the prefixes
    // identifies the encoding (C4/C5/62 are never LES/LDS/BOUND in 64-bit).
    let kind = match code[p] {
        0xc4 | 0xc5 => Encoding::Vex,
        0x62 => Encoding::Other,
        0x8f if code.get(p + 1).is_some_and(|b| b & 0x1f >= 8) => Encoding::Other,
        _ => Encoding::Legacy,
    };
    let opcode_end = match kind {
        Encoding::Legacy => {
            if rex != 0 {
                hs.flags |= F_PREFIX_REX;
                hs.rex = rex;
                hs.rex_w = (rex >> 3) & 1;
                hs.rex_r = (rex >> 2) & 1;
                hs.rex_x = (rex >> 1) & 1;
                hs.rex_b = rex & 1;
            }
            hs.opcode = code[p];
            if hs.opcode == 0x0f {
                hs.opcode2 = code.get(p + 1).copied().unwrap_or(0);
                match hs.opcode2 {
                    0x38 | 0x3a => p + 3,
                    0x0f => return error(hs), // 3DNow!
                    _ => p + 2,
                }
            } else {
                p + 1
            }
        }
        // Match the C VEX path: opcode is the byte after the VEX prefix and
        // the rex_* fields stay zero.
        Encoding::Vex => {
            let vex_len = if code[p] == 0xc5 { 2 } else { 3 };
            hs.opcode = code.get(p + vex_len).copied().unwrap_or(0);
            p + vex_len + 1
        }
        // EVEX/XOP: the C decoder did not support them; refuse.
        Encoding::Other => return error(hs),
    };

    let offsets = decoder.get_constant_offsets(&instr);
    let disp_size = usize::from(offsets.displacement_size());
    let imm_size = usize::from(offsets.immediate_size());
    let disp_off = usize::from(offsets.displacement_offset());
    let imm_off = usize::from(offsets.immediate_offset());
    let after_modrm = if disp_size != 0 {
        disp_off
    } else if imm_size != 0 {
        imm_off
    } else {
        len
    };
    if after_modrm < opcode_end || after_modrm - opcode_end > 2 {
        return error(hs);
    }
    if after_modrm > opcode_end {
        let modrm = code[opcode_end];
        hs.flags |= F_MODRM;
        hs.modrm = modrm;
        hs.modrm_mod = modrm >> 6;
        hs.modrm_reg = (modrm >> 3) & 7;
        hs.modrm_rm = modrm & 7;
        let has_sib = hs.modrm_mod != 3 && hs.modrm_rm == 4;
        if has_sib != (after_modrm - opcode_end == 2) {
            return error(hs);
        }
        if has_sib {
            let sib = code[opcode_end + 1];
            hs.flags |= F_SIB;
            hs.sib = sib;
            hs.sib_scale = sib >> 6;
            hs.sib_index = (sib >> 3) & 7;
            hs.sib_base = sib & 7;
        }
    }

    match disp_size {
        0 => {}
        1 => hs.flags |= F_DISP8,
        2 => hs.flags |= F_DISP16,
        4 => hs.flags |= F_DISP32,
        // moffs (A0-A3): the C decoder reported the 64-bit address as imm64.
        8 => hs.flags |= F_IMM64,
        _ => return error(hs),
    }
    if disp_size == 8 {
        hs.imm_offset = disp_off as u8;
        hs.imm = read_le(code, disp_off, 8);
    } else if disp_size != 0 {
        hs.disp_offset = disp_off as u8;
        hs.disp = read_le(code, disp_off, disp_size) as u32;
    }

    if imm_size != 0 {
        hs.flags |= match imm_size {
            1 => F_IMM8,
            2 => F_IMM16,
            4 => F_IMM32,
            _ => F_IMM64,
        };
        hs.imm_offset = imm_off as u8;
        hs.imm = read_le(code, imm_off, imm_size);
    }
    let is_branch = (0..instr.op_count()).any(|i| {
        matches!(
            instr.op_kind(i),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    });
    if is_branch {
        hs.flags |= F_RELATIVE;
    }
    if instr.memory_base() == Register::RIP && disp_size == 4 {
        hs.flags |= F_RIP_RELATIVE;
    }
    fill_meta(&mut hs);
    hs
}

fn error(mut hs: Hde64) -> Hde64 {
    hs.flags |= F_ERROR | F_ERROR_OPCODE;
    hs
}

/// Port of `hde64_fill_meta` from the removed src/hde64.cpp.
fn fill_meta(hs: &mut Hde64) {
    if hs.flags & F_RELATIVE != 0 {
        if hs.opcode == 0xe8 && hs.flags & F_IMM32 != 0 {
            hs.meta = META_REL_CALL;
        } else if (hs.opcode == 0xe9 && hs.flags & F_IMM32 != 0)
            || (hs.opcode == 0xeb && hs.flags & F_IMM8 != 0)
        {
            hs.meta = META_REL_JMP;
        } else if (0x70..=0x7f).contains(&hs.opcode) && hs.flags & F_IMM8 != 0 {
            hs.meta = META_REL_JCC;
            hs.branch_opcode = hs.opcode;
        } else if hs.opcode == 0x0f
            && (0x80..=0x8f).contains(&hs.opcode2)
            && hs.flags & F_IMM32 != 0
        {
            hs.meta = META_REL_JCC;
            hs.branch_opcode = 0x70 + (hs.opcode2 & 0x0f);
        }
    }
    if hs.flags & F_RIP_RELATIVE == 0 {
        return;
    }
    if hs.meta == META_NONE {
        hs.meta = META_RIP_REL;
    }
    let no_size_prefixes = hs.p_66 == 0 && hs.p_lock == 0 && hs.p_rep == 0;
    let seg_ok = hs.p_seg == 0 || hs.p_seg == PREFIX_SEGMENT_CS;
    let reg = hs.modrm_reg + if hs.rex_r != 0 { 8 } else { 0 };
    if hs.rex_w == 0 || !no_size_prefixes {
        return;
    }
    if hs.opcode == 0x8d && hs.p_seg == 0 {
        hs.operand_reg = reg;
        hs.meta = META_RIP_REL_LEA64;
    } else if hs.opcode == 0x8b && seg_ok {
        hs.operand_reg = reg;
        hs.meta = META_RIP_REL_MOV_R64_PTR;
    } else if hs.opcode == 0x39 && seg_ok {
        hs.operand_reg = reg;
        hs.meta = META_RIP_REL_CMP_PTR_R64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hook_relevant_forms() {
        // lea rax, [rip+0x10] at ip 0x1000
        let lea = [0x48, 0x8d, 0x05, 0x10, 0, 0, 0];
        let hs = decode(&lea);
        assert_eq!(
            (hs.len, hs.flags & F_ERROR, hs.meta),
            (7, 0, META_RIP_REL_LEA64)
        );
        assert_eq!((hs.disp_offset, hs.operand_reg, hs.rex), (3, 0, 0x48));
        assert_eq!(rip_absolute(&lea, 0x1000, &hs), Some(0x1017));

        // mov r9, [rip-4]
        let mov = [0x4c, 0x8b, 0x0d, 0xfc, 0xff, 0xff, 0xff];
        let hs = decode(&mov);
        assert_eq!(
            (hs.meta, hs.operand_reg, hs.rex_r),
            (META_RIP_REL_MOV_R64_PTR, 9, 1)
        );
        assert_eq!(rip_absolute(&mov, 0x1000, &hs), Some(0x1003));

        // jmp rel32 / jne rel32 / jb rel8
        let jmp = [0xe9, 0x00, 0x01, 0, 0];
        let hs = decode(&jmp);
        assert_eq!((hs.len, hs.meta, hs.imm_offset), (5, META_REL_JMP, 1));
        assert_eq!(relative_target(&jmp, 0x1000, &hs), Some(0x1105));
        let hs = decode(&[0x0f, 0x85, 0, 0, 0, 0]);
        assert_eq!((hs.meta, hs.branch_opcode), (META_REL_JCC, 0x75));
        let jb = [0x72, 0xfe];
        let hs = decode(&jb);
        assert_eq!((hs.meta, hs.branch_opcode), (META_REL_JCC, 0x72));
        assert_eq!(relative_target(&jb, 0x1000, &hs), Some(0x1000));

        // syscall; mov eax, imm32; push rbp; mov rbp, rsp; garbage
        let hs = decode(&[0x0f, 0x05]);
        assert_eq!(
            (hs.len, hs.opcode, hs.opcode2, hs.flags & F_ERROR),
            (2, 0x0f, 0x05, 0)
        );
        let hs = decode(&[0xb8, 1, 0, 0, 0]);
        assert_eq!(
            (hs.len, hs.flags & (F_IMM32 | F_RELATIVE | F_RIP_RELATIVE)),
            (5, F_IMM32)
        );
        assert_eq!(decode(&[0x55]).len, 1);
        let hs = decode(&[0x48, 0x89, 0xe5]);
        assert_eq!((hs.len, hs.modrm_mod, hs.flags & F_MODRM), (3, 3, F_MODRM));
        assert_ne!(decode(&[0x0f, 0xff]).flags & F_ERROR, 0);
        assert_ne!(decode(&[0xe9, 0]).flags & F_ERROR, 0);

        // inc qword [rip+0]; vmovdqu ymm0, [rip+8]
        let hs = decode(&[0x48, 0xff, 0x05, 0, 0, 0, 0]);
        assert_eq!(
            (hs.meta, hs.modrm_reg, hs.disp_offset),
            (META_RIP_REL, 0, 3)
        );
        let hs = decode(&[0xc5, 0xfe, 0x6f, 0x05, 8, 0, 0, 0]);
        assert_eq!(
            (hs.len, hs.opcode, hs.meta, hs.disp_offset),
            (8, 0x6f, META_RIP_REL, 4)
        );
    }
}
