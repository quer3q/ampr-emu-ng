//! Decodes packed op words back into an `OpRecord`.

use crate::op::op_type::*;
use crate::OpRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The error offset stays zero.
    Invalid,
    /// The error offset is the record offset.
    InvalidAt,
}
use DecodeError::*;

struct Rec<'a> {
    buf: &'a [u8],
    off: u32,
    bytes: u32,
}

impl Rec<'_> {
    /// Word `i` of the record; callers check `need` first, so the fallback is unreachable.
    fn w(&self, i: u32) -> u32 {
        let at = self.off as usize + 4 * i as usize;
        self.buf
            .get(at..at + 4)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn w64(&self, i: u32) -> u64 {
        self.w(i) as u64
    }
    fn need(&self, dwords: u32) -> Result<(), DecodeError> {
        let bytes = dwords.wrapping_mul(4);
        if dwords == 0 || bytes > self.bytes || self.off > self.bytes - bytes {
            Err(InvalidAt)
        } else {
            Ok(())
        }
    }
    fn need_range(&self, dwords: u32, min: u32, max: u32) -> Result<(), DecodeError> {
        if dwords < min || dwords > max {
            return Err(InvalidAt);
        }
        self.need(dwords)
    }
}

fn packed_addr(high: u32, low: u32) -> u64 {
    ((high & 0xffff_0000) as u64) << 16 | low as u64
}

/// Decodes the record at `off`; returns the op and its byte size.
pub fn decode_packed_op(buf: &[u8], off: u32) -> Result<(OpRecord, u32), DecodeError> {
    let bytes = u32::try_from(buf.len()).map_err(|_| Invalid)?;
    if bytes & 3 != 0 || off & 3 != 0 || off >= bytes {
        return Err(Invalid);
    }
    let r = Rec { buf, off, bytes };
    let w0 = r.w(0);
    let (opcode8, opcode12) = (w0 & 0xff, w0 & 0xfff);
    let mut op = OpRecord {
        buf_offset_bytes: off,
        ..Default::default()
    };
    let dwords;
    if opcode8 == 1 {
        dwords = ((w0 >> 8) & 0xf) + 1;
        r.need_range(dwords, 2, 4)?;
        op.op_type = WAIT_ON_ADDRESS;
        op.ptra = packed_addr(w0, r.w(1));
        op.u32a = (w0 >> 13) & 7;
        op.u32c = (w0 >> 12) & 1;
        if dwords >= 3 {
            op.u64a = r.w64(2);
            if dwords >= 4 {
                op.u64a |= r.w64(3) << 32;
            }
        }
    } else if opcode8 == 2 {
        dwords = ((w0 >> 8) & 0xf) + 1;
        if r.need_range(dwords, 1, 5).is_err() || dwords == 4 {
            return Err(InvalidAt);
        }
        op.op_type = WAIT_ON_COUNTER;
        op.u8a = (w0 >> 24) as u8;
        op.u32b = (w0 >> 13) & 7;
        op.u32c = (w0 >> 12) & 1;
        op.u64a = ((w0 >> 16) & 0xff) as u64;
        op.u8b = 1;
        if dwords >= 2 {
            wait_counter_extra(&r, dwords, &mut op);
        }
    } else if opcode8 == 5 || opcode8 == 117 {
        dwords = ((w0 >> 8) & 3) + 1;
        r.need_range(dwords, 2, 4)?;
        let w1 = r.w(1);
        let at_sop = (opcode8 == 117) as u8;
        let mut value = ((w0 >> 12) & 3) as u64;
        if dwords >= 3 {
            value |= r.w64(2) << 2;
            if dwords >= 4 {
                value |= r.w64(3) << 34;
            }
        }
        match w1 & 7 {
            1 => {
                op.op_type = WRITE_ADDRESS_FROM_TIME_COUNTER;
                op.u8b = at_sop;
            }
            class @ (2 | 3) => {
                op.op_type = if class == 2 {
                    WRITE_ADDRESS_FROM_COUNTER
                } else {
                    WRITE_ADDRESS_FROM_COUNTER_PAIR
                };
                op.u8a = value as u8;
                op.u8b = at_sop;
            }
            _ => {
                op.op_type = WRITE_ADDRESS;
                op.u64a = value;
                op.u8a = at_sop;
            }
        }
        op.ptra = packed_addr(w0, w1 & 0xffff_fff8);
    } else if opcode8 == 6 || opcode8 == 118 {
        dwords = ((w0 >> 8) & 0xf) + 1;
        r.need_range(dwords, 1, 3)?;
        op.op_type = WRITE_COUNTER;
        op.u8a = (w0 >> 24) as u8;
        op.u32c = (opcode8 == 118) as u32;
        op.u64a = ((w0 >> 12) & 0xfff) as u64;
        op.u8b = 1;
        if dwords >= 2 {
            let w1 = r.w(1);
            op.u64a |= ((w1 & 0xf_ffff) as u64) << 12;
            op.u8b = (((w1 >> 20) & 7) ^ 1) as u8;
            op.u32b = (w1 >> 24) & 7;
            if dwords >= 3 {
                op.u64a |= r.w64(2) << 32;
            }
        }
    } else if opcode12 == 1032 || opcode12 == 1144 {
        dwords = 5;
        r.need(dwords)?;
        op.op_type = WRITE_EQUEUE;
        op.u8a = (opcode12 == 1144) as u8;
        op.u64b = packed_addr(w0, r.w(1));
        op.u32b = r.w(2);
        op.u64a = r.w64(3) | r.w64(4) << 32;
    } else {
        return decode_marker_or_apr(&r, w0, op);
    }
    Ok((op, dwords * 4))
}

fn wait_counter_extra(r: &Rec<'_>, dwords: u32, op: &mut OpRecord) {
    let w1 = r.w(1);
    let extra = (w1 >> 28) & 3;
    op.u8b = (((w1 >> 24) & 7) ^ 1) as u8;
    op.u32c |= extra << 8;
    let ref_low8 = op.u64a & 0xff;
    if extra != 0 {
        if dwords == 2 {
            op.u64a = ref_low8 | ((w1 & 0xff) as u64) << 8;
            op.u64b = ((w1 >> 8) & 0xffff) as u64;
            return;
        }
        let compact = (w1 & 0x00ff_ff00) == 0 && (dwords < 5 || r.w(2) == 0);
        if compact {
            op.u64a = ref_low8 | ((w1 & 0xff) as u64) << 8;
            if dwords == 3 {
                op.u64b = r.w64(2);
            } else if dwords >= 5 {
                op.u64b = r.w64(3) | r.w64(4) << 32;
            }
            return;
        }
    }
    op.u64a = ref_low8 | ((w1 & 0x00ff_ffff) as u64) << 8;
    if dwords >= 3 {
        let w2 = r.w64(2);
        if extra == 0 {
            op.u64a |= w2 << 32;
        } else if dwords >= 5 {
            op.u64a |= w2 << 32;
            op.u64b = r.w64(3) | r.w64(4) << 32;
        } else {
            op.u64b = w2;
        }
    }
}

fn decode_marker_or_apr(
    r: &Rec<'_>,
    w0: u32,
    mut op: OpRecord,
) -> Result<(OpRecord, u32), DecodeError> {
    let (opcode8, opcode12) = (w0 & 0xff, w0 & 0xfff);
    let mut dwords;
    if (w0 & 0xffff_000f) == 0x5452_000f {
        let marker_type = (w0 >> 12) & 0xf;
        dwords = ((w0 >> 8) & 0xf) + 1;
        r.need(dwords)?;
        if w0 == 0x5452_300f {
            op.op_type = MARKER_POP;
            dwords = 1;
        } else if marker_type == 1 || marker_type == 5 {
            op.op_type = MARKER_SET;
        } else if marker_type == 2 || marker_type == 6 {
            op.op_type = MARKER_PUSH;
        } else {
            op.op_type = NOP;
            op.u32a = dwords;
        }
    } else if opcode8 == 40 {
        dwords = ((w0 >> 8) & 7) + 1;
        r.need_range(dwords, 5, 6)?;
        let w4 = r.w(4);
        op.op_type = APR_READ_FILE;
        op.u64a = r.w64(1) + 1;
        op.u32a = r.w(2) & 0x7fff_ffff;
        op.ptra = r.w64(3) | ((w4 & 0xffff) as u64) << 32;
        op.u64b = (((w0 >> 12) & 0x3_ffff) | (w4 & 0xfffc_0000)) as u64;
        if dwords >= 6 {
            op.u64b |= ((r.w(5) & 0xff) as u64) << 32;
        }
    } else if opcode8 == 41 {
        dwords = ((w0 >> 8) & 3) + 1;
        r.need_range(dwords, 2, 3)?;
        op.op_type = APR_READ_GATHER;
        op.u64a = r.w64(1) + 1;
        op.u64b = ((w0 >> 12) & 0x3_ffff) as u64;
        if dwords >= 3 {
            op.u64b |= ((r.w(2) & 0x3f_ffff) as u64) << 18;
        }
    } else if opcode12 == 0x22a {
        dwords = 3;
        r.need(dwords)?;
        op.op_type = APR_READ_SCATTER;
        op.u64a = r.w64(1) + 1;
        op.ptra = r.w64(2) | (((w0 >> 12) & 0xffff) as u64) << 32;
    } else if opcode8 == 43 {
        dwords = ((w0 >> 8) & 7) + 1;
        r.need_range(dwords, 4, 5)?;
        let w3 = r.w(3);
        op.op_type = APR_READ_GATHER_SCATTER;
        op.u64a = r.w64(1) + 1;
        op.ptra = r.w64(2) | ((w3 & 0xffff) as u64) << 32;
        op.u64b = (((w0 >> 12) & 0x3_ffff) | (w3 & 0xfffc_0000)) as u64;
        if dwords >= 5 {
            op.u64b |= ((r.w(4) & 0xff) as u64) << 32;
        }
    } else if w0 == 47 {
        dwords = 1;
        op.op_type = APR_RESET_GATHER_SCATTER;
    } else if opcode12 == 557 {
        dwords = 3;
        r.need(dwords)?;
        let (w1, w2) = (r.w(1), r.w(2));
        op.op_type = APR_MAP_BEGIN;
        op.u32a = (w0 >> 12) & 0x7fff;
        op.u32b = (w0 >> 27) & 0x1f;
        op.u64c = op.u32b as u64;
        op.u64a = (w1 as u64) << 14 | ((w2 & 3) as u64) << 46;
        op.u64b = ((w2 & 0x1fff_fffc) as u64) << 12;
    } else if opcode12 == 813 {
        dwords = 4;
        r.need(dwords)?;
        let (w1, w2) = (r.w(1), r.w(2));
        op.op_type = APR_MAP_DIRECT_BEGIN;
        op.u32b = (w0 >> 12) & 0x7fff;
        op.u32a = (w0 >> 27) & 0x1f;
        op.u64a = (w1 as u64) << 14 | ((w2 & 3) as u64) << 46;
        op.u64c = ((w2 & 0x1fff_fffc) as u64) << 12;
        op.u64b = ((r.w(3) & 0x03ff_ffff) as u64) << 14;
    } else if w0 == 46 {
        dwords = 1;
        op.op_type = APR_MAP_END;
    } else {
        return decode_amm(r, w0, op);
    }
    Ok((op, dwords * 4))
}

fn amm_va(low: u32, high_bits: u32, shift: u32) -> u64 {
    (low as u64) << 14 | (((high_bits >> shift) & 3) as u64) << 46
}

fn amm_prot(w0: u32) -> u32 {
    (w0 >> 12) & 0x7fff
}

fn amm_prot_without_prt_flag(w0: u32) -> u32 {
    ((w0 & !0x8000) >> 12) & 0x7fff
}

/// `ampr_decode_amm_packed_op`.
fn decode_amm(r: &Rec<'_>, w0: u32, mut op: OpRecord) -> Result<(OpRecord, u32), DecodeError> {
    let opcode12 = w0 & 0xfff;
    let mtype_bits = (w0 >> 27) & 0x1f;
    let dwords = match opcode12 {
        0x221 | 0x321 => {
            let dwords = if opcode12 == 0x321 { 4 } else { 3 };
            r.need(dwords)?;
            let (w1, w2) = (r.w(1), r.w(2));
            let prt = w0 & 0x8000 != 0;
            let prot = amm_prot_without_prt_flag(w0);
            op.op_type = if prt && prot == 0 && mtype_bits == 0 {
                AMM_MAP_AS_PRT
            } else {
                AMM_MAP
            };
            op.u64a = amm_va(w1, w2, 0);
            op.u64b = ((w2 & 0x1fff_fffc) as u64) << 12;
            op.u32a = prot;
            op.u32b = mtype_bits;
            op.u32c = prt as u32;
            dwords
        }
        0x325 | 0x425 => {
            let dwords = if opcode12 == 0x425 { 5 } else { 4 };
            r.need(dwords)?;
            let (w1, w2, w3) = (r.w(1), r.w(2), r.w(3));
            op.op_type = AMM_MAP_DIRECT;
            op.u64a = amm_va(w1, w2, 0);
            op.u64b = ((w3 & 0x03ff_ffff) as u64) << 14;
            op.u64c = ((w2 & 0xffff_fffc) as u64) << 9;
            op.u32a = amm_prot(w0);
            op.u32b = mtype_bits;
            dwords
        }
        0x222 | 0x228 => {
            r.need(3)?;
            let (w1, w2) = (r.w(1), r.w(2));
            op.op_type = if opcode12 == 0x228 {
                AMM_UNMAP_TO_PRT
            } else {
                AMM_UNMAP
            };
            op.u64a = amm_va(w1, w2, 0);
            op.u64b = ((w2 & 0xffff_fffc) as u64) << 9;
            3
        }
        0x323 | 0x423 | 0x324 | 0x424 | 0x327 => {
            let dwords = if matches!(opcode12, 0x423 | 0x424) {
                5
            } else {
                4
            };
            r.need(dwords)?;
            let (w1, w2, w3) = (r.w(1), r.w(2), r.w(3));
            if opcode12 == 0x327 {
                op.op_type = AMM_REMAP_INTO_PRT;
                op.u32a = amm_prot_without_prt_flag(w0);
                op.u32b = 1011;
            } else {
                op.op_type = if matches!(opcode12, 0x324 | 0x424) {
                    AMM_MULTI_MAP
                } else {
                    AMM_REMAP
                };
                op.u32a = amm_prot(w0);
            }
            op.u64a = amm_va(w1, w3, 0);
            op.u64b = amm_va(w2, w3, 2);
            op.u64c = ((w3 & 0xffff_fff0) as u64) << 9;
            dwords
        }
        0x326 | 0x426 => {
            let dwords = if opcode12 == 0x426 { 5 } else { 4 };
            r.need(dwords)?;
            let (w1, w2, w3) = (r.w(1), r.w(2), r.w(3));
            let mtype = (w2 & 0x4000_0000) != 0 || mtype_bits != 0;
            op.op_type = match (mtype, w3 == 1019 && opcode12 == 0x326) {
                (false, _) => AMM_MODIFY_PROTECT,
                (true, true) => AMM_ALLOC_PA_FOR_PRT,
                (true, false) => AMM_MODIFY_MTYPE_PROTECT,
            };
            op.u64a = amm_va(w1, w2, 0);
            op.u64b = ((w2 & 0x1fff_fffc) as u64) << 12;
            op.u32a = amm_prot(w0);
            if mtype {
                op.u32b = mtype_bits;
                op.u32c = w3 & 0x7fff;
            } else {
                op.u32b = w3 & 0x7fff;
            }
            dwords
        }
        _ => return Err(InvalidAt),
    };
    // Five-dword (0x4xx) and 0x321 forms carry a trailing submit-flag word.
    if matches!(opcode12, 0x321 | 0x425 | 0x423 | 0x424 | 0x426) {
        op.u8a = r.w(dwords - 1) as u8;
        op.u8b = 1;
    }
    Ok((op, dwords * 4))
}
