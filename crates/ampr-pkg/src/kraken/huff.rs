//! Kraken's Huffman-coded arrays (array type 2), decode side (`kraken/huff.rs:261-462`).
//! Codes are canonical, lengths 1..=11, and must fill the 2048-entry table exactly. The body is
//! the code-length table, a LE16 split, then streams A | C | B-reversed (symbol i from i % 3).

use crate::kraken::lz::Msb;
use crate::kraken::{err, Error};

const MAX_LEN: u32 = 11;
pub(crate) const LUT: usize = 1 << MAX_LEN;

/// The table header's gamma code. `zeros` looks 56 bits ahead where the original looked at
/// 24 to 32; both refuse anything past 7 zeros, so they agree.
fn get_gamma(r: &mut Msb) -> Result<usize, Error> {
    let lz = r.zeros();
    if lz > 7 {
        return err("kraken: bad Huffman table run");
    }
    Ok(r.get(2 * (lz + 1)) as usize - 1)
}

/// An LSB-first reader over `src[start..end)`, forward or (stream B, `BACK`) backward; reads
/// past its range see zeros. `acc` holds `n` valid bits at the bottom. Every byte the reader
/// has passed (`next` moved over it) was put into `acc` (zeros past the range included, see
/// `pad`), so the bits consumed are `8 * passed + 8 * pad - n`.
struct LsbReader<'a, const BACK: bool> {
    src: &'a [u8],
    start: usize,
    end: usize,
    /// Forward: the next byte; backward: one past it.
    next: usize,
    acc: u64,
    n: u32,
    /// Zero bytes fed past the range.
    pad: usize,
}

impl<'a, const BACK: bool> LsbReader<'a, BACK> {
    #[inline(always)]
    fn new(src: &'a [u8], start: usize, end: usize) -> Self {
        Self { src, start, end, next: if BACK { end } else { start }, acc: 0, n: 0, pad: 0 }
    }

    /// Bytes not yet passed.
    #[inline(always)]
    fn left(&self) -> usize {
        if BACK { self.next - self.start } else { self.end - self.next }
    }

    /// Top `acc` up to at least 56 bits from the next eight bytes; needs `left() >= 8`.
    /// Branch-free: it ORs in all eight bytes shifted by `n`. Bits past the `k` bytes it counts
    /// are the following stream bytes at their final positions, so a later refill ORs the same
    /// values over them; they are inside the range (`left() >= 8`), as the slow path would see.
    #[inline(always)]
    fn refill_fast(&mut self) {
        debug_assert!(self.left() >= 8 && self.n < 64);
        // SAFETY: `left() >= 8` and `start <= next <= end <= src.len()`: forward, bytes
        // `next..next + 8` are in `src`; backward, bytes `next - 8..next` are.
        let word = unsafe {
            if BACK {
                u64::from_be(core::ptr::read_unaligned(self.src.as_ptr().add(self.next - 8) as *const u64))
            } else {
                u64::from_le(core::ptr::read_unaligned(self.src.as_ptr().add(self.next) as *const u64))
            }
        };
        self.acc |= word << self.n;
        let k = ((63 - self.n) >> 3) as usize;
        self.n |= 56;
        if BACK {
            self.next -= k;
        } else {
            self.next += k;
        }
    }

    /// One symbol with no refill: needs `n >= 11`.
    #[inline(always)]
    fn sym(&mut self, lut: &[u16; LUT]) -> u8 {
        // One load: the code length in the low byte, the symbol in the high one. The length
        // is below 64, so the shift by the whole entry (taken mod 64) shifts by the length.
        let e = lut[self.acc as usize & (LUT - 1)];
        self.acc = self.acc.wrapping_shr(u32::from(e));
        self.n -= u32::from(e as u8);
        (e >> 8) as u8
    }

    #[inline]
    fn peek(&mut self) -> usize {
        if self.n < MAX_LEN && self.left() >= 8 {
            self.refill_fast();
        }
        while self.n < MAX_LEN {
            let byte = if self.left() == 0 {
                self.pad += 1;
                0
            } else if BACK {
                self.next -= 1;
                self.src[self.next]
            } else {
                self.next += 1;
                self.src[self.next - 1]
            };
            self.acc |= u64::from(byte) << self.n;
            self.n += 8;
        }
        self.acc as usize
    }

    #[inline(always)]
    fn skip(&mut self, bits: u32) {
        self.acc >>= bits;
        self.n -= bits;
    }

    fn bytes_used(&self) -> usize {
        let passed = if BACK { self.end - self.next } else { self.next - self.start };
        (8 * (passed + self.pad) - self.n as usize).div_ceil(8)
    }
}

/// Decode a type-2 array body into all of `out`, building the table in `lut`.
pub(crate) fn decode(src: &[u8], out: &mut [u8], lut: &mut [u16; LUT]) -> Result<(), Error> {
    let mut r = Msb::new(src, 0, src.len(), false);
    if r.get(1) != 0 {
        return err("kraken: unsupported Huffman table form");
    }
    // (symbol, code length) in table order; at most 256 (new form) or 255 (old form) entries.
    let mut syms = [(0u8, 0u8); 256];
    let mut count = 0usize;
    if r.get(1) == 1 {
        let fb = r.get(2);
        let limit = 20 >> fb;
        let mut skip = r.get(1) == 1;
        let (mut sym, mut avg) = (0usize, 32i32);
        while sym != 256 {
            if skip {
                skip = false;
            } else {
                sym += get_gamma(&mut r)?;
                if sym >= 256 {
                    break;
                }
            }
            let run = get_gamma(&mut r)?;
            if sym + run > 256 {
                return err("kraken: Huffman table overruns");
            }
            for _ in 0..run {
                // `limit <= 20`: a 24-bit window of zeros and a 56-bit one both exceed it.
                let lz = r.zeros();
                if lz > limit {
                    return err("kraken: bad Huffman code length");
                }
                // The `lz` zeros, the 1 and `fb` bits in one read (`lz + 1 + fb <= 24` of the
                // 56 bits `zeros` made valid): the value is `lz << fb | low fb bits`.
                let w = r.take(lz + 1 + fb);
                let v = (lz << fb | (w & ((1 << fb) - 1))) as i32;
                let l = (-(v & 1) ^ (v >> 1)) + ((avg + 2) >> 2);
                if !(1..=MAX_LEN as i32).contains(&l) {
                    return err("kraken: bad Huffman code length");
                }
                avg = l + ((3 * avg + 2) >> 2);
                syms[count] = (sym as u8, l as u8);
                count += 1;
                sym += 1;
            }
        }
        if sym != 256 || count < 2 {
            return err("kraken: bad Huffman table");
        }
    } else {
        let n = r.get(8) as usize;
        if n == 0 {
            return err("kraken: empty Huffman table");
        }
        if n == 1 {
            let symbol = r.get(8) as u8;
            if r.seam() != src.len() as isize {
                return err("kraken: single-symbol Huffman table has the wrong size");
            }
            out.fill(symbol);
            return Ok(());
        }
        let cb = r.get(3);
        if cb > 4 {
            return err("kraken: bad Huffman table");
        }
        for _ in 0..n {
            let s = r.get(8) as u8;
            let l = r.get(cb) as usize + 1;
            if l > MAX_LEN as usize {
                return err("kraken: bad Huffman code length");
            }
            syms[count] = (s, l as u8);
            count += 1;
        }
    }
    timed!(3, 1, build_lut(&syms[..count], lut))?;
    streams(src, r.seam() as usize, out, lut)
}

/// The decoder's table, built for the next `bits` bits (the longest code length), then repeated:
/// each code fills 2^(bits - len) slots, indexed by the reversed bits; shortest codes first,
/// symbols of one length in table order. A short-code table is built and read in fewer slots;
/// with every length scaled by the same 2^(11 - bits), the fill checks agree with 2048 slots.
fn build_lut(syms: &[(u8, u8)], lut: &mut [u16; LUT]) -> Result<(), Error> {
    // Stable counting sort by length (lengths are 1..=11, checked by the caller).
    let mut start = [0usize; MAX_LEN as usize + 2];
    for &(_, l) in syms {
        start[l as usize + 1] += 1;
    }
    for l in 1..start.len() {
        start[l] += start[l - 1];
    }
    let mut order = [(0u8, 0u8); 256];
    for &e in syms {
        order[start[e.1 as usize]] = e;
        start[e.1 as usize] += 1;
    }
    let bits = syms.iter().map(|e| u32::from(e.1)).max().unwrap_or(1);
    let size = 1usize << bits;
    let mut slot = 0usize;
    // A code of length l at reversed index `base` (below 2^l) fills every slot congruent to
    // `base` mod 2^l. Built by doubling: once all codes up to length `cur` are placed, the
    // first 2^cur slots are final for them, and copying them up doubles the prefix to the
    // next length. Slots not yet covered hold copies that a longer code overwrites later
    // (all are covered when the code is complete, checked below).
    let mut cur = 0u32;
    for &(s, l) in &order[..syms.len()] {
        let l32 = u32::from(l);
        let step = 1usize << (bits - l32);
        if slot + step > size {
            return err("kraken: oversubscribed Huffman code");
        }
        while cur < l32 {
            let h = 1usize << cur;
            lut.copy_within(0..h, h);
            cur += 1;
        }
        // The code (`slot >> (bits - l)`) reversed in l bits: `slot`'s low bits - l bits are 0.
        let base = (slot as u32).reverse_bits() as usize >> (32 - bits);
        lut[base] = u16::from(l) | u16::from(s) << 8;
        slot += step;
    }
    if slot != size {
        return err("kraken: incomplete Huffman code");
    }
    // Repeat the 2^bits slots up to the whole table, so the decoder masks with a constant.
    while cur < MAX_LEN {
        let h = 1usize << cur;
        lut.copy_within(0..h, h);
        cur += 1;
    }
    Ok(())
}

/// The split and the three streams after the table at `start`, decoded into `out`.
fn streams(src: &[u8], start: usize, out: &mut [u8], lut: &[u16; LUT]) -> Result<(), Error> {
    let (split, a0, mut sa, mut sb, mut sc) = readers(src, start)?;
    // Fast path: 15 symbols (5 per stream, at most 55 bits each) per refill of all three
    // streams, while each still has 8 unread bytes in range. Same bits, same order as below.
    // A refill passes at most 7 bytes, so a stream with `left` bytes stays at 8 or more for
    // `(left - 1) / 7` refills: the passes are counted ahead and the loop has no range test.
    let mut i = 0usize;
    loop {
        let room = |l: usize| if l >= 8 { (l - 1) / 7 } else { 0 };
        let passes = ((out.len() - i) / 15).min(room(sa.left())).min(room(sb.left())).min(room(sc.left()));
        if passes == 0 {
            break;
        }
        for o in out[i..i + 15 * passes].as_chunks_mut::<15>().0 {
            sa.refill_fast();
            sb.refill_fast();
            sc.refill_fast();
            o[0] = sa.sym(lut);
            o[1] = sb.sym(lut);
            o[2] = sc.sym(lut);
            o[3] = sa.sym(lut);
            o[4] = sb.sym(lut);
            o[5] = sc.sym(lut);
            o[6] = sa.sym(lut);
            o[7] = sb.sym(lut);
            o[8] = sc.sym(lut);
            o[9] = sa.sym(lut);
            o[10] = sb.sym(lut);
            o[11] = sc.sym(lut);
            o[12] = sa.sym(lut);
            o[13] = sb.sym(lut);
            o[14] = sc.sym(lut);
        }
        i += 15 * passes;
    }
    tail(&mut sa, out, i, lut);
    tail(&mut sb, out, i + 1, lut);
    tail(&mut sc, out, i + 2, lut);
    meet(src, split, a0, &sa, &sb, &sc)
}

/// The rest of one stream, one symbol at a time, into `out[i]`, `out[i + 3]`, ...
fn tail<const BACK: bool>(s: &mut LsbReader<BACK>, out: &mut [u8], mut i: usize, lut: &[u16; LUT]) {
    while i < out.len() {
        let e = lut[s.peek() & (LUT - 1)];
        let (sym, l) = ((e >> 8) as u8, e as u8);
        s.skip(u32::from(l));
        out[i] = sym;
        i += 3;
    }
}

type Readers<'a> = (usize, usize, LsbReader<'a, false>, LsbReader<'a, true>, LsbReader<'a, false>);

/// The split after the table at `start`: (split, first stream byte, readers A, B, C).
#[inline(always)]
fn readers(src: &[u8], start: usize) -> Result<Readers<'_>, Error> {
    if start + 3 > src.len() {
        return err("kraken: truncated Huffman array");
    }
    let split = usize::from(u16::from_le_bytes([src[start], src[start + 1]]));
    let a0 = start + 2;
    if a0 + split > src.len() {
        return err("kraken: bad Huffman split");
    }
    Ok((
        split,
        a0,
        LsbReader::new(src, a0, a0 + split),
        LsbReader::new(src, a0 + split, src.len()),
        LsbReader::new(src, a0 + split, src.len()),
    ))
}

/// The streams used exactly their bytes.
fn meet(src: &[u8], split: usize, a0: usize, a: &LsbReader<false>, b: &LsbReader<true>, c: &LsbReader<false>) -> Result<(), Error> {
    if a.bytes_used() != split || b.bytes_used() + c.bytes_used() != src.len() - a0 - split {
        return err("kraken: Huffman streams do not meet");
    }
    Ok(())
}
