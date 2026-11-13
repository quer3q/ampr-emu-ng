//! Bit streams, arrays and the LZ half decoder (`kraken.rs` decoder section).

use core::hint::select_unpredictable;
use core::ops::Range;

use crate::kraken::{err, huff, Error, Scratch};

const SEED: usize = 8;
/// The closest a match may reference.
const MIN_DISTANCE: usize = 8;

/// The MSB-first bit reader (Huffman table headers, LZ offsets, length escapes) over
/// `[start, end)`, forward or backward, zeros past the range: the original's 24-bit
/// `BitReader` bits, with a 64-bit accumulator refilled eight bytes at a time. `acc` holds `n`
/// valid bits at the top; `fed` counts the bits put in (zero padding past the range included),
/// so `fed - n` are the bits consumed.
pub(crate) struct Msb<'a> {
    src: &'a [u8],
    /// Forward: the next byte; backward: one past it.
    next: usize,
    left: usize,
    back: bool,
    acc: u64,
    n: u32,
    fed: usize,
    start: usize,
    end: usize,
}

impl<'a> Msb<'a> {
    pub(crate) fn new(src: &'a [u8], start: usize, end: usize, back: bool) -> Self {
        let next = if back { end } else { start };
        Self { src, next, left: end - start, back, acc: 0, n: 0, fed: 0, start, end }
    }

    /// At least 56 valid bits. With 8 bytes left it is branch-free (`n <= 63` always holds:
    /// a refill leaves `n + 8 * k <= 63`, so `k` is 0 when `n >= 56` and nothing changes).
    #[inline(always)]
    pub(crate) fn refill(&mut self) {
        if self.left >= 8 {
            // SAFETY: `left >= 8`: forward, `next..next + 8` is inside `start..end`, which is
            // inside `src` (checked in `decode_half`); backward, `next - 8..next` is.
            let w = unsafe {
                if self.back {
                    u64::from_le(core::ptr::read_unaligned(self.src.as_ptr().add(self.next - 8) as *const u64))
                } else {
                    u64::from_be(core::ptr::read_unaligned(self.src.as_ptr().add(self.next) as *const u64))
                }
            };
            // The bytes past the `k` counted are the next in-range bytes at their final
            // positions; a later refill ORs the same bits over them.
            self.acc |= w >> self.n;
            let k = ((63 - self.n) >> 3) as usize;
            self.n += 8 * k as u32;
            self.fed += 8 * k;
            self.left -= k;
            if self.back {
                self.next -= k;
            } else {
                self.next += k;
            }
            return;
        }
        if self.n >= 56 {
            return;
        }
        while self.n <= 56 {
            let byte = if self.left == 0 {
                0
            } else {
                self.left -= 1;
                if self.back {
                    self.next -= 1;
                    self.src[self.next]
                } else {
                    self.next += 1;
                    self.src[self.next - 1]
                }
            };
            self.acc |= u64::from(byte) << (56 - self.n);
            self.n += 8;
            self.fed += 8;
        }
    }

    /// The zero bits before the next 1, looking at least 56 bits ahead (past the range: zeros).
    #[inline(always)]
    pub(crate) fn zeros(&mut self) -> u32 {
        self.refill();
        self.acc.leading_zeros()
    }

    /// `nb <= 32` bits, no refill: needs `n >= nb`.
    #[inline(always)]
    pub(crate) fn take(&mut self, nb: u32) -> u32 {
        debug_assert!(self.n >= nb && nb <= 32);
        let v = ((self.acc >> 1) >> (63 - nb)) as u32;
        self.acc <<= nb;
        self.n -= nb;
        v
    }

    /// `nb <= 32` bits.
    #[inline(always)]
    pub(crate) fn get(&mut self, nb: u32) -> u32 {
        self.refill();
        let v = ((self.acc >> 1) >> (63 - nb)) as u32;
        self.acc <<= nb;
        self.n -= nb;
        v
    }

    #[inline]
    fn get_length(&mut self) -> Result<u32, Error> {
        self.refill();
        // At least 56 valid bits, so the first 13 are real, as in the original's 24-bit window.
        let zeros = self.acc.leading_zeros();
        if zeros > 12 {
            return err("kraken: bad length code");
        }
        self.get(zeros);
        Ok(self.get(zeros + 7) - 64)
    }

    pub(crate) fn seam(&self) -> isize {
        let used = (self.fed - self.n as usize).div_ceil(8);
        if self.back { self.end as isize - used as isize } else { (self.start + used) as isize }
    }
}

/// Where a decoded array lives: borrowed from the chunk (raw, type 0) or the first `n` bytes
/// of the output buffer it was given (Huffman, type 2).
pub(crate) enum Arr {
    Src(Range<usize>),
    Buf(usize),
}

impl Arr {
    pub(crate) fn len(&self) -> usize {
        match self {
            Arr::Src(r) => r.len(),
            Arr::Buf(n) => *n,
        }
    }
    fn view<'x>(&self, src: &'x [u8], buf: &'x [u8]) -> &'x [u8] {
        match self {
            Arr::Src(r) => &src[r.clone()],
            Arr::Buf(n) => &buf[..*n],
        }
    }
    /// Output-buffer bytes it takes.
    fn taken(&self) -> usize {
        match self {
            Arr::Src(_) => 0,
            Arr::Buf(n) => *n,
        }
    }
}

/// An array at `at`, raw (type 0) or Huffman (type 2, decoded into `out`):
/// `(where, header + payload length)`. `max` bounds the decoded size.
pub(crate) fn get_array(
    src: &[u8],
    at: usize,
    end: usize,
    max: usize,
    out: &mut [u8],
    lut: &mut [u16; huff::LUT],
) -> Result<(Arr, usize), Error> {
    if end < at + 2 {
        return err("kraken: truncated array");
    }
    let b0 = src[at];
    match (b0 >> 4) & 7 {
        0 => {
            let (n, h) = if b0 >= 0x80 {
                ((((b0 as usize) << 8) | src[at + 1] as usize) & 0xFFF, 2)
            } else {
                if end < at + 3 {
                    return err("kraken: truncated array");
                }
                let n = ((b0 as usize) << 16) | ((src[at + 1] as usize) << 8) | src[at + 2] as usize;
                if n & !0x3FFFF != 0 {
                    return err("kraken: bad array size");
                }
                (n, 3)
            };
            if n > max || at + h + n > end {
                return err("kraken: array overruns its chunk");
            }
            Ok((Arr::Src(at + h..at + h + n), h + n))
        }
        2 => {
            let (src_size, dst_size, h) = if b0 >= 0x80 {
                if end < at + 3 {
                    return err("kraken: truncated array");
                }
                let v = (usize::from(b0) << 16) | (usize::from(src[at + 1]) << 8) | usize::from(src[at + 2]);
                let s = v & 0x3FF;
                (s, s + ((v >> 10) & 0x3FF) + 1, 3)
            } else {
                if end < at + 5 {
                    return err("kraken: truncated array");
                }
                let v = u32::from_be_bytes([src[at + 1], src[at + 2], src[at + 3], src[at + 4]]) as usize;
                let s = v & 0x3FFFF;
                let d = (((v >> 18) | (usize::from(b0) << 14)) & 0x3FFFF) + 1;
                (s, d, 5)
            };
            if src_size >= dst_size || dst_size > max || at + h + src_size > end {
                return err("kraken: bad Huffman array size");
            }
            // Only a stream the original refuses anyway is larger than its scratch region.
            if dst_size > out.len() {
                return err("kraken: array larger than a valid half allows");
            }
            huff::decode(&src[at + h..at + h + src_size], &mut out[..dst_size], lut)?;
            Ok((Arr::Buf(dst_size), h + src_size))
        }
        _ => err("kraken: unsupported array type"),
    }
}

#[inline(always)]
unsafe fn copy16(from: *const u8, to: *mut u8) {
    to.cast::<[u8; 16]>().write_unaligned(from.cast::<[u8; 16]>().read_unaligned());
}

#[inline(always)]
unsafe fn copy8(from: *const u8, to: *mut u8) {
    to.cast::<[u8; 8]>().write_unaligned(from.cast::<[u8; 8]>().read_unaligned());
}

/// `d[..8] = s[..8] + b[..8]` bytewise, wrapping: SSE2 / NEON 64-bit add, else SWAR. `b..b + 8` must not
/// overlap `d..d + 8` past `d` (it is read first anyway).
#[inline(always)]
unsafe fn add8(d: *mut u8, s: *const u8, b: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::*;
        let v = _mm_add_epi8(_mm_loadl_epi64(s.cast()), _mm_loadl_epi64(b.cast()));
        _mm_storel_epi64(d.cast(), v);
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;
        vst1_u8(d, vadd_u8(vld1_u8(s), vld1_u8(b)));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    add8_swar(d, s, b);
}

/// [`add8`] in plain integer code (SWAR on one u64).
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), allow(dead_code))]
#[inline(always)]
unsafe fn add8_swar(d: *mut u8, s: *const u8, b: *const u8) {
    let x = u64::from_ne_bytes(s.cast::<[u8; 8]>().read_unaligned());
    let y = u64::from_ne_bytes(b.cast::<[u8; 8]>().read_unaligned());
    const H: u64 = 0x8080_8080_8080_8080;
    let v = ((x & !H) + (y & !H)) ^ ((x ^ y) & H);
    d.cast::<[u8; 8]>().write_unaligned(v.to_ne_bytes());
}

/// `d[..16] = s[..16] + b[..16]` bytewise, wrapping: one SSE2 / NEON add (both baseline).
#[inline(always)]
unsafe fn add16(d: *mut u8, s: *const u8, b: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::*;
        _mm_storeu_si128(d.cast(), _mm_add_epi8(_mm_loadu_si128(s.cast()), _mm_loadu_si128(b.cast())));
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;
        vst1q_u8(d, vaddq_u8(vld1q_u8(s), vld1q_u8(b)));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        add8(d, s, b);
        add8(d.add(8), s.add(8), b.add(8));
    }
}

/// Literals `lits[at..at + n]` into `out[dst..dst + n]`, delta-coded against the byte `last`
/// back when `delta`. `end` is the half's end.
///
/// SAFETY (caller): `at + n <= lits.len()`, `dst + n <= end <= out.len()`, and with `delta`,
/// `MIN_DISTANCE <= last <= dst`. Bytes of `out[dst + n..end]` may be overwritten: the half
/// writes them later, in order, before anything reads them.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn put_literals(out: *mut u8, dst: usize, end: usize, lits: &[u8], at: usize, n: usize, delta: bool, last: usize) {
    let s = lits.as_ptr().add(at);
    let d = out.add(dst);
    let mut k = 0;
    // Wide path: whole 16-byte chunks stay inside `lits` and below `end` (`n + 16` spare).
    if at + n + 16 <= lits.len() && dst + n + 16 <= end {
        if !delta {
            while k < n {
                copy16(s.add(k), d.add(k));
                k += 16;
            }
        } else if last >= 16 {
            // The base chunk ends at or before `d + k`: already written.
            while k < n {
                add16(d.add(k), s.add(k), d.add(k).sub(last));
                k += 16;
            }
        } else {
            // `8 <= last < 16`: eight bytes at a time, each base word written before.
            while k < n {
                add8(d.add(k), s.add(k), d.add(k).sub(last));
                k += 8;
            }
        }
        return;
    }
    if delta {
        while k + 8 <= n {
            add8(d.add(k), s.add(k), d.add(k).sub(last));
            k += 8;
        }
        while k < n {
            *d.add(k) = (*s.add(k)).wrapping_add(*d.add(k).sub(last));
            k += 1;
        }
    } else {
        core::ptr::copy_nonoverlapping(s, d, n);
    }
}

/// `out[dst..dst + len] = out[dst - dist..]`, byte by byte in effect. `end` is the half's end.
///
/// SAFETY (caller): `MIN_DISTANCE <= dist <= dst` and `dst + len <= end <= out.len()`. Each
/// chunk is at most `dist` bytes (16 when `dist >= 16`, else 8 as `dist >= 8`), so it reads
/// only bytes already written. Over-copy (only when `end - dst >= len + 16`) stays below `end`.
#[inline(always)]
unsafe fn copy_match(out: *mut u8, dst: usize, end: usize, dist: usize, len: usize) {
    let d = out.add(dst);
    let s = d.sub(dist);
    let mut k = 0;
    if end - dst >= len + 16 {
        // `len >= 1`, so the first chunk is always due.
        if dist >= 16 {
            loop {
                copy16(s.add(k), d.add(k));
                k += 16;
                if k >= len {
                    break;
                }
            }
        } else {
            loop {
                copy8(s.add(k), d.add(k));
                k += 8;
                if k >= len {
                    break;
                }
            }
        }
        return;
    }
    while k + 8 <= len {
        copy8(s.add(k), d.add(k));
        k += 8;
    }
    while k < len {
        *d.add(k) = *s.add(k);
        k += 1;
    }
}

/// Offsets decoded per batch.
const OB: usize = 64;

/// New offsets, read from the two main streams (code k from stream k % 2) a batch at a time,
/// so the command loop reads the next one without a branch.
struct Offsets<'a> {
    codes: &'a [u8],
    /// Codes decoded so far.
    k: usize,
    scaled: bool,
    a: Msb<'a>,
    b: Msb<'a>,
    buf: [u32; OB],
    /// Next unused `buf` entry and the number filled.
    bi: usize,
    bn: usize,
    /// The codes ran out: `buf[0]` is a sentinel no match accepts.
    missing: bool,
}

/// One new offset from code `c` and its stream `r`, which must hold the bits (at most 26).
#[inline(always)]
fn offset(scaled: bool, c: u8, r: &mut Msb) -> Result<u32, Error> {
    if scaled {
        let nb = u32::from(c >> 3);
        if nb > 26 {
            return err("kraken: bad offset code");
        }
        Ok((((8 + u32::from(c & 7)) << nb) | r.take(nb)) - 8)
    } else {
        if c >= 0xF0 {
            return err("kraken: offset beyond a block");
        }
        let n = u32::from(c >> 4) + 4;
        Ok((((1u32 << n) | r.take(n)) << 4) + u32::from(c & 0xF) - 248)
    }
}

impl Offsets<'_> {
    /// Decode the next batch into `buf` (called when it is used up).
    #[inline(never)]
    fn fill(&mut self) -> Result<(), Error> {
        let n = (self.codes.len() - self.k).min(OB);
        if n == 0 {
            self.buf[0] = u32::MAX;
            self.missing = true;
            (self.bi, self.bn) = (0, 1);
            return Ok(());
        }
        // Code k (overall) is from stream k % 2; batches start at multiples of OB (even).
        debug_assert!(self.k.is_multiple_of(2));
        let codes = &self.codes[self.k..self.k + n];
        let (scaled, a, b, buf) = (self.scaled, &mut self.a, &mut self.b, &mut self.buf);
        let mut j = 0;
        // A refill leaves at least 56 bits: two offsets (at most 26 bits each) per stream.
        while j + 4 <= n {
            a.refill();
            b.refill();
            buf[j] = offset(scaled, codes[j], a)?;
            buf[j + 1] = offset(scaled, codes[j + 1], b)?;
            buf[j + 2] = offset(scaled, codes[j + 2], a)?;
            buf[j + 3] = offset(scaled, codes[j + 3], b)?;
            j += 4;
        }
        while j < n {
            let r = if j % 2 == 0 { &mut *a } else { &mut *b };
            r.refill();
            buf[j] = offset(scaled, codes[j], r)?;
            j += 1;
        }
        self.k += n;
        (self.bi, self.bn) = (0, n);
        Ok(())
    }

    /// Codes consumed by the commands so far.
    fn used(&self) -> usize {
        if self.missing { self.codes.len() } else { self.k - (self.bn - self.bi) }
    }
}

/// Lengths (value + 3), a 255 escaping to the excess streams (escape k from stream k % 2).
struct Lengths<'a> {
    lens: &'a [u8],
    k: usize,
    esc: usize,
    ea: Msb<'a>,
    eb: Msb<'a>,
}

impl Lengths<'_> {
    #[inline(always)]
    fn next(&mut self) -> Result<usize, Error> {
        let Some(&v) = self.lens.get(self.k) else { return err("kraken: length missing") };
        self.k += 1;
        if v != 255 {
            return Ok(3 + v as usize);
        }
        let r = if self.esc.is_multiple_of(2) { &mut self.ea } else { &mut self.eb };
        self.esc += 1;
        Ok(3 + 255 + r.get_length()? as usize)
    }
}

/// Length byte `k` of `lens` without taking it; 255 (the escape) past the end, so the caller's
/// slow path calls [`Lengths::next`], which reports it.
#[inline(always)]
fn peek(lens: &[u8], k: usize) -> usize {
    match lens.get(k) {
        Some(&v) => v as usize,
        None => 255,
    }
}

/// The length at `lens[lk]`, an escape (255) or a missing byte, through [`Lengths::next`]:
/// `(add + length, the next lk)`. Out of line: it is rare, and inline it costs the hot loop
/// registers.
#[cold]
#[inline(never)]
fn escape(lens: &mut Lengths, lk: usize, add: usize) -> Result<(usize, usize), Error> {
    lens.k = lk;
    let v = lens.next()?;
    Ok((add + v, lens.k))
}

/// The command loop of [`decode_half`] for `out` (as a pointer: `end <= out.len()`, checked by
/// the caller) from `dst`: returns where it stopped, the literals used and the recent offsets.
#[inline(always)]
fn commands<const DELTA: bool>(
    op: *mut u8,
    mut dst: usize,
    end: usize,
    cmds: &[u8],
    lits: &[u8],
    offs: &mut Offsets,
    lens: &mut Lengths,
) -> Result<(usize, usize, [usize; 3]), Error> {
    let mut lit_at = 0usize;
    // Recent offsets, most recent first, kept in registers: taking slot `kind` (3: the next
    // new one) moves it to the front and shifts the slots before it back by one, with
    // conditional moves (the kind is unpredictable).
    let (mut r0, mut r1, mut r2) = (8usize, 8usize, 8usize);
    // The hot indices live in locals: `lens` and `offs` go by reference to out-of-line slow
    // paths, so their fields would stay in memory, a store-to-load round trip per command.
    let lb = lens.lens;
    let mut lk = lens.k;
    let (mut bi, mut bn) = (offs.bi, offs.bn);
    for &f in cmds {
        let kind = (f >> 6) as usize;
        let code = ((f >> 2) & 0xF) as usize;
        // Run length without a branch on its form (unpredictable): 3 takes 3 + the next length
        // byte. 258 is only that with 255, the escape or a missing byte: the slow way.
        let l3 = f & 3 == 3;
        let mut lit = select_unpredictable(l3, 3 + peek(lb, lk), usize::from(f & 3));
        lk += usize::from(l3);
        if lit == 258 {
            (lit, lk) = escape(lens, lk - 1, 0)?;
        }
        let lit = if !DELTA && lit <= 64 && lit_at + 64 <= lits.len() && dst + 64 <= end {
            // Plain runs up to 64 as four 16-byte chunks whatever their length: runs of 32..63
            // are common there, and a branch on the length would be unpredictable.
            // SAFETY: `lit_at + 64 <= lits.len()` and `dst + 64 <= end <= out.len()` (caller).
            unsafe {
                let (s, d) = (lits.as_ptr().add(lit_at), op.add(dst));
                for k in [0, 16, 32, 48] {
                    copy16(s.add(k), d.add(k));
                }
            }
            lit
        } else if lit <= 16 && lit_at + 16 <= lits.len() && dst + 16 <= end {
            // Short run: one 16-byte chunk, its tail rewritten later in order.
            // SAFETY: `lit_at + 16 <= lits.len()`, `dst + 16 <= end <= out.len()` (caller);
            // `8 <= r0 <= dst` (every match checks its distance), so each 8-byte base word
            // ends at or before the bytes being written: it is already written.
            unsafe {
                let (s, d) = (lits.as_ptr().add(lit_at), op.add(dst));
                if DELTA {
                    add8(d, s, d.sub(r0));
                    // The second chunk always, so there is no branch on the length: for runs
                    // up to 8 it is slack, and its base moves to the first's (written before)
                    // so that it does not wait on the chunk just stored.
                    let b2 = select_unpredictable(lit > 8, d.add(8).sub(r0), d.sub(r0));
                    add8(d.add(8), s.add(8), b2);
                } else {
                    copy16(s, d);
                }
            }
            lit
        } else if DELTA && lit <= 64 && lit_at + 64 <= lits.len() && dst + 64 <= end {
            // Medium delta run: whole chunks up to 64 bytes, no loop (a loop's exit is a
            // mispredicted branch on Zen 2).
            // SAFETY: as for the short run, with 64 bytes of room; a 16-byte chunk only when
            // `r0 >= 16`, so each base chunk ends at or before the bytes being written.
            unsafe {
                let (s, d) = (lits.as_ptr().add(lit_at), op.add(dst));
                if r0 >= 16 {
                    for k in [0, 16, 32, 48] {
                        add16(d.add(k), s.add(k), d.add(k).sub(r0));
                    }
                } else {
                    for k in [0, 8, 16, 24, 32, 40, 48, 56] {
                        add8(d.add(k), s.add(k), d.add(k).sub(r0));
                    }
                }
            }
            lit
        } else {
            if lit_at + lit > lits.len() || dst + lit > end {
                return err("kraken: literal run overruns");
            }
            // SAFETY: checked above: `lit_at + lit <= lits.len()`, `dst + lit <= end`; `end <=
            // out.len()` (caller) and `8 <= r0 <= dst` (every match checks its distance).
            unsafe { put_literals(op, dst, end, lits, lit_at, lit, DELTA, r0) };
            lit
        };
        dst += lit;
        lit_at += lit;
        // Recent offsets: kind 0..=2 reuses slot `kind` and moves it to the front; 3 pushes a
        // new one. Either way slots below `kind` (all three for 3) shift back by one. The next
        // new offset is read every time and consumed only when kind is 3.
        if bi == bn {
            offs.bi = bi;
            offs.fill()?;
            (bi, bn) = (offs.bi, offs.bn);
        }
        let new = offs.buf[bi & (OB - 1)] as usize;
        let k1 = kind & 1 != 0;
        let lo = select_unpredictable(k1, r1, r0);
        let hi = select_unpredictable(k1, new, r2);
        let dist = select_unpredictable(kind >= 2, hi, lo);
        r2 = select_unpredictable(kind >= 2, r1, r2);
        r1 = select_unpredictable(kind >= 1, r0, r1);
        r0 = dist;
        bi += usize::from(kind == 3);
        // As for the run: 15 takes 17 + the next length byte, and 272 is the escape.
        let c15 = code == 15;
        let mut mlen = select_unpredictable(c15, 17 + peek(lb, lk), code + 2);
        lk += usize::from(c15);
        if mlen == 17 + 255 {
            (mlen, lk) = escape(lens, lk - 1, 14)?;
        }
        if dist < MIN_DISTANCE || dist > dst || dst + mlen > end {
            if kind == 3 && offs.missing {
                return err("kraken: offset missing");
            }
            return err("kraken: match out of bounds");
        }
        if mlen <= 32 && dst + 32 <= end {
            // Four 8-byte chunks whatever the length, so there is no branch on it: chunk k
            // reads up to `dst + k + 8 - dist <= dst + k`, written before. For a match up to
            // 16 the last two are slack (rewritten later) and read from the first's source
            // instead, so that they do not wait on the chunks just stored.
            // SAFETY: `MIN_DISTANCE <= dist <= dst` (checked) and `dst + 32 <= end`.
            unsafe {
                let d = op.add(dst);
                let s = d.sub(dist);
                let long = mlen > 16;
                copy8(s, d);
                copy8(s.add(8), d.add(8));
                copy8(select_unpredictable(long, s.add(16), s), d.add(16));
                copy8(select_unpredictable(long, s.add(24), s), d.add(24));
            }
        } else if mlen <= 16 && dst + 16 <= end {
            // `mlen <= 16`: two 8-byte chunks; the second reads at most to `dst + 16 - dist <=
            // dst + 8`, written by the first. Bytes past `dst + mlen` are rewritten later.
            // SAFETY: `MIN_DISTANCE <= dist <= dst` (checked) and `dst + 16 <= end`.
            unsafe {
                let d = op.add(dst);
                copy8(d.sub(dist), d);
                copy8(d.add(8).sub(dist), d.add(8));
            }
        } else {
            // SAFETY: just checked `MIN_DISTANCE <= dist <= dst` and `dst + mlen <= end`.
            unsafe { copy_match(op, dst, end, dist, mlen) };
        }
        dst += mlen;
    }
    (lens.k, offs.bi) = (lk, bi);
    Ok((dst, lit_at, [r0, r1, r2]))
}

/// Decode one LZ half into `out[at..at + len]`; `out[..at]` is the block's history. `delta`
/// selects literal mode 0.
pub(crate) fn decode_half(src: &[u8], out: &mut [u8], at: usize, len: usize, delta: bool, s: &mut Scratch) -> Result<(), Error> {
    let end = at + len;
    if end > out.len() {
        return err("kraken: half overruns the block");
    }
    let mut p = 0usize;
    let mut dst = at;
    if at == 0 {
        if src.len() < SEED || len < SEED {
            return err("kraken: truncated seed");
        }
        out[..SEED].copy_from_slice(&src[..SEED]);
        p = SEED;
        dst = SEED;
    }
    if src.len() < p + 13 {
        return err("kraken: chunk too short");
    }
    let flag = src[p];
    if flag & 0xC0 != 0x80 {
        return err("kraken: expected the excess framing");
    }
    p += 1;
    let mut excess = (flag & 0x3F) as usize;
    if excess > 0x1F {
        excess += src[p] as usize * 0x20;
        p += 1;
    }
    if excess > src.len() - p {
        return err("kraken: excess overruns the chunk");
    }
    let main_end = src.len() - excess;
    let Scratch { a, b, lut } = s;
    let (lits, n) = timed!(0, 0, get_array(src, p, main_end, len, &mut a[..], lut))?;
    p += n;
    let (cmds, n) = timed!(1, 0, get_array(src, p, main_end, len, &mut a[lits.taken()..], lut))?;
    p += n;
    if p >= main_end {
        return err("kraken: truncated offsets");
    }
    // `0x80` marks the scaled offset code; anything else starts the traditional offsets array.
    let scaled = src[p] == 0x80;
    if scaled {
        p += 1;
    }
    #[cfg(feature = "phase_timing")]
    let t0 = crate::kraken::timing::phase::now();
    let (offs, n) = get_array(src, p, main_end, cmds.len(), &mut b[..], lut)?;
    p += n;
    let (lens, n) = get_array(src, p, main_end, len / 4, &mut b[offs.taken()..], lut)?;
    p += n;
    #[cfg(feature = "phase_timing")]
    crate::kraken::timing::phase::add(2, t0, offs.taken() + lens.taken());
    #[cfg(feature = "phase_timing")]
    {
        crate::kraken::timing::phase::C[0].fetch_add(lits.taken() as u64, core::sync::atomic::Ordering::Relaxed);
        crate::kraken::timing::phase::C[1].fetch_add(cmds.taken() as u64, core::sync::atomic::Ordering::Relaxed);
        crate::kraken::timing::phase::C[8].fetch_add(cmds.len() as u64, core::sync::atomic::Ordering::Relaxed);
    }

    let (a_lits, a_cmds) = a.split_at(lits.taken());
    let (b_offs, b_lens) = b.split_at(offs.taken());
    let lits = lits.view(src, a_lits);
    let cmds = cmds.view(src, a_cmds);
    let mut offs = Offsets {
        codes: offs.view(src, b_offs),
        k: 0,
        scaled,
        a: Msb::new(src, p, main_end, false),
        b: Msb::new(src, p, main_end, true),
        buf: [0; OB],
        bi: 0,
        bn: 0,
        missing: false,
    };
    let mut lens = Lengths {
        lens: lens.view(src, b_lens),
        k: 0,
        esc: 0,
        ea: Msb::new(src, main_end, src.len(), false),
        eb: Msb::new(src, main_end, src.len(), true),
    };

    let op = out.as_mut_ptr();
    // Two copies of the command loop, so the literal mode is not tested per command.
    let (dst, lit_at, recent) = if delta {
        timed!(5, end - dst, commands::<true>(op, dst, end, cmds, lits, &mut offs, &mut lens))?
    } else {
        timed!(4, end - dst, commands::<false>(op, dst, end, cmds, lits, &mut offs, &mut lens))?
    };
    #[cfg(feature = "phase_timing")]
    let t0 = crate::kraken::timing::phase::now();
    if lits.len() - lit_at != end - dst {
        return err("kraken: trailing literals do not fill the half");
    }
    // SAFETY: `lits.len() - lit_at == end - dst`, just checked; `recent[0]` as in the loop.
    unsafe { put_literals(op, dst, end, lits, lit_at, end - dst, delta, recent[0]) };
    if offs.used() != offs.codes.len() || lens.k != lens.lens.len() {
        return err("kraken: unused offsets or lengths");
    }
    if offs.a.seam() != offs.b.seam() {
        return err("kraken: offset streams do not meet");
    }
    if lens.ea.seam() != lens.eb.seam() {
        return err("kraken: excess streams do not meet");
    }
    #[cfg(feature = "phase_timing")]
    crate::kraken::timing::phase::add(6, t0, 0);
    Ok(())
}
