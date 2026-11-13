//! Decoder for the Kraken blocks of a PS5 package's inner image (`pfs_image.dat`), `no_std` and
//! allocation-free: every buffer comes from a caller-provided [`Scratch`].
//!
//! Port of the decode half of ps5upload-fpkg (GPL-3.0-or-later): `kraken.rs` (BitReader,
//! get_array, put_literals, copy_match, decode_half, decode_entropy_half, decode_parts),
//! `kraken/huff.rs` (get_gamma, LsbReader, decode) and `kraken_image.rs::decode_described`.
//! Differences: raw arrays are borrowed from `src` instead of copied, and the offsets and
//! length escapes are read from their bit streams as the commands need them instead of into
//! vectors first. Both accept and refuse exactly the streams the original does.
//!
//! A block is at most 256 KiB, read as two halves of at most 128 KiB, each raw bytes, a bare
//! entropy array, or an LZ chunk body. See the original's module docs for the format.

#[macro_use]
mod timing;
mod huff;
mod lz;

#[cfg(feature = "phase_timing")]
pub use timing::phase;

/// A half's logical size.
pub const HALF: usize = 0x2_0000;
/// A block's largest logical size.
pub const BLOCK: usize = 0x4_0000;

/// A malformed or unsupported block. The message is fixed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

pub(crate) fn err<T>(msg: &'static str) -> Result<T, Error> {
    Err(Error(msg))
}

/// What a block's layout record says about how it is stored (the fields `decode_described`
/// reads from a `DescribedBlock`, besides its offsets and lengths).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Desc {
    /// Stored bytes of the even (first) half; the odd half is the rest of `src`.
    pub even_len: u32,
    /// The record's bits 32..=36: bit 0 even delta literals, 1 even LZ, 2 odd_reset (ignored),
    /// 3 odd delta literals, 4 odd LZ.
    pub mode: u8,
}

impl Desc {
    fn even_lz(&self) -> bool {
        self.mode & 0b10 != 0
    }
    fn odd_lz(&self) -> bool {
        self.mode & 0b1_0000 != 0
    }
}

/// Working memory for [`decode_block`]: 228 KiB (`Scratch::SIZE` = 233472 bytes), reused for
/// both halves. All-zero is a valid value, so it can live in `.bss`
/// (`static mut S: Scratch = Scratch::new();`) or on the heap ([`Scratch::new_boxed`]).
/// Keep it off a small stack.
#[repr(C)]
pub struct Scratch {
    /// Literals, then commands (a valid half has `literals + 2 * commands <= half`).
    pub(crate) a: [u8; HALF],
    /// Offset codes (at most one per command, so `half / 2`), then lengths (at most `half / 4`).
    pub(crate) b: [u8; HALF / 2 + HALF / 4],
    /// The Huffman decode table: code length | symbol << 8 per index of up to 11 bits.
    pub(crate) lut: [u16; huff::LUT],
}

impl Scratch {
    /// Its size in bytes.
    pub const SIZE: usize = core::mem::size_of::<Scratch>();

    /// A zeroed Scratch, by value (228 KiB): for a `static`, not for the stack.
    pub const fn new() -> Self {
        Self { a: [0; HALF], b: [0; HALF / 2 + HALF / 4], lut: [0; huff::LUT] }
    }

    /// A zeroed Scratch on the heap, never built on the stack.
    #[cfg(feature = "alloc")]
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        // SAFETY: Scratch is plain integer arrays, so all-zero is valid; a null pointer is
        // reported through handle_alloc_error before Box takes it.
        unsafe {
            let p = alloc::alloc::alloc_zeroed(layout) as *mut Self;
            if p.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            alloc::boxed::Box::from_raw(p)
        }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode one unshuffled block stored as `src` (its `stored_len` bytes) into `dst`, whose
/// length is the block's logical length (1..=256 KiB). Returns `dst.len()`.
///
/// As `decode_described` with shuffle 0: an empty `src` with a zero `desc` is a sparse block
/// (zeros). A byte shuffle is not handled here; the caller refuses or undoes it.
pub fn decode_block(src: &[u8], desc: Desc, dst: &mut [u8], scratch: &mut Scratch) -> Result<usize, Error> {
    let len = dst.len();
    if len == 0 || len > BLOCK {
        return err("a block of this length is not a Kraken block");
    }
    if src.is_empty() {
        if desc != Desc::default() {
            return err("a block stored in no bytes is not a sparse block");
        }
        dst.fill(0);
        return Ok(len);
    }
    let even_len = desc.even_len as usize;
    if src.len() > 2 * BLOCK || even_len > src.len() {
        return err("a block's stored span is not a Kraken block");
    }
    let (e, o) = src.split_at(even_len);
    let even_logical = len.min(HALF);
    half(e, dst, 0, even_logical, desc.even_lz(), desc.mode & 1 != 0, scratch)?;
    if len > HALF {
        half(o, dst, HALF, len - HALF, desc.odd_lz(), desc.mode & 0b1000 != 0, scratch)?;
    } else if !o.is_empty() {
        return err("kraken: unexpected odd half");
    }
    Ok(len)
}

/// One half into `dst[at..at + len]`: LZ, an exact-size raw copy, or a bare entropy array.
fn half(src: &[u8], dst: &mut [u8], at: usize, len: usize, lz: bool, delta: bool, s: &mut Scratch) -> Result<(), Error> {
    if lz {
        lz::decode_half(src, dst, at, len, delta, s)
    } else {
        timed!(7, len, raw_or_entropy(src, dst, at, len, s))
    }
}

fn raw_or_entropy(src: &[u8], dst: &mut [u8], at: usize, len: usize, s: &mut Scratch) -> Result<(), Error> {
    if src.len() == len {
        dst[at..at + len].copy_from_slice(src);
        Ok(())
    } else {
        // decode_entropy_half: the whole of `src` is one array of exactly `len` bytes.
        let out = &mut dst[at..at + len];
        let (arr, used) = lz::get_array(src, 0, src.len(), len, out, &mut s.lut)?;
        if used != src.len() || arr.len() != len {
            return err("kraken: entropy half has the wrong length or trailing bytes");
        }
        if let lz::Arr::Src(r) = arr {
            out.copy_from_slice(&src[r]);
        }
        Ok(())
    }
}
