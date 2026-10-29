//! Bounded decoding of one independent zstd chunk.

use crate::Error;
use zstd_sys::{
    ZSTD_DCtx, ZSTD_DCtx_setParameter, ZSTD_createDCtx, ZSTD_dParameter, ZSTD_decompressDCtx,
    ZSTD_findFrameCompressedSize, ZSTD_freeDCtx, ZSTD_getFrameContentSize, ZSTD_isError,
};

pub const ZSTD_MAX_CHUNK_SIZE: usize = 1 << 18;
pub const ZSTD_CODEC_RAW: u8 = 0;
pub const ZSTD_CODEC_ZSTD: u8 = 1;
/// A stored chunk is never larger than its raw size (the writer stores a
/// chunk raw when zstd is not smaller), so 256 KiB bounds both codecs.
const MAX_STORED_SIZE: usize = 1 << 18;
/// Content size of `WARM_UP_FRAME`.
const WARM_UP_RAW_SIZE: usize = 1 << 16;

/// 64 KiB of `i % 7`, zstd level 19 with content size and checksum.
const WARM_UP_FRAME: [u8; 29] = [
    40, 181, 47, 253, 100, 0, 255, 125, 0, 0, 56, 0, 1, 2, 3, 4, 5, 6, 1, 0, 246, 127, 233, 197, 8,
    18, 247, 254, 55,
];

/// Decode exactly one zstd chunk with a one-off decoder; see `ZstdDecoder`.
pub fn decode_zstd_chunk(
    codec: u8,
    raw_size: usize,
    stored: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    ZstdDecoder::new().decode(codec, raw_size, stored, output)
}

/// A reusable zstd chunk decoder over one libzstd `ZSTD_DCtx` (native C
/// zstd: ~10x ruzstd's speed on the console). Its buffers are allocated by
/// the first zstd chunk and reused by every later one, so a long-lived
/// decoder does not allocate per chunk. Not shareable: one per decoding
/// thread.
pub struct ZstdDecoder {
    /// Null when libzstd could not allocate it; every zstd decode then fails.
    dctx: *mut ZSTD_DCtx,
}

// The context is owned and only used through `&mut self`.
unsafe impl Send for ZstdDecoder {}

impl Drop for ZstdDecoder {
    fn drop(&mut self) {
        if !self.dctx.is_null() {
            unsafe { ZSTD_freeDCtx(self.dctx) };
        }
    }
}

impl Default for ZstdDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdDecoder {
    pub fn new() -> Self {
        let dctx = unsafe { ZSTD_createDCtx() };
        // A frame may not need a window past one chunk (2^18). The frame
        // checksum is not verified (ZSTD_d_forceIgnoreChecksum): a few percent
        // of decode time; corrupt data still fails libzstd's own decoding
        // checks, but a corruption that decodes cleanly is no longer caught.
        let set =
            |param, value| unsafe { ZSTD_isError(ZSTD_DCtx_setParameter(dctx, param, value)) };
        if !dctx.is_null()
            && (set(
                ZSTD_dParameter::ZSTD_d_windowLogMax,
                ZSTD_MAX_CHUNK_SIZE.trailing_zeros() as i32,
            ) != 0
                // ZSTD_d_forceIgnoreChecksum: skip the per-chunk XXH64 check.
                || set(ZSTD_dParameter::ZSTD_d_experimentalParam3, 1) != 0)
        {
            unsafe { ZSTD_freeDCtx(dctx) };
            return Self {
                dctx: core::ptr::null_mut(),
            };
        }
        Self { dctx }
    }

    /// Decodes a built-in 64 KiB frame into `scratch`, so the decoder's
    /// fixed buffers exist before the first real chunk. Callers pass the
    /// scratch they decode real chunks into, which must hold
    /// `ZSTD_MAX_CHUNK_SIZE` (256 KiB) bytes; warm-up itself writes only
    /// the first 64 KiB. Buffers that track block content and window size
    /// still grow, to a bounded size, on the first larger chunks.
    pub fn warm_up(&mut self, scratch: &mut [u8]) -> Result<(), Error> {
        self.decode(ZSTD_CODEC_ZSTD, WARM_UP_RAW_SIZE, &WARM_UP_FRAME, scratch)
    }

    /// Decode exactly one zstd chunk into the first `raw_size` bytes of `output`.
    ///
    /// Zstd input must be a single frame with a declared content size and
    /// checksum, without a dictionary. The frame checksum is not verified
    /// (`ZSTD_d_forceIgnoreChecksum`, for decode speed); the frame structure
    /// and the decoded size are.
    pub fn decode(
        &mut self,
        codec: u8,
        raw_size: usize,
        stored: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        if raw_size == 0
            || raw_size > ZSTD_MAX_CHUNK_SIZE
            || stored.is_empty()
            || stored.len() > MAX_STORED_SIZE
            || output.len() < raw_size
        {
            return Err(Error::InvalidArgument);
        }

        let raw = &mut output[..raw_size];
        match codec {
            ZSTD_CODEC_RAW => {
                if stored.len() != raw_size {
                    return Err(Error::InvalidFormat);
                }
                raw.copy_from_slice(stored);
            }
            ZSTD_CODEC_ZSTD => decode_zstd(self.dctx, stored, raw)?,
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
}

fn decode_zstd(dctx: *mut ZSTD_DCtx, stored: &[u8], raw: &mut [u8]) -> Result<(), Error> {
    if dctx.is_null() {
        return Err(Error::Unsupported);
    }
    // The frame descriptor is byte 4, after the four-byte zstd magic. The
    // archive requires a checksum, explicit content size, and no dictionary.
    if stored.len() < 6 || stored[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(Error::InvalidFormat);
    }
    let descriptor = stored[4];
    if descriptor & 0x04 == 0
        || descriptor & 0x03 != 0
        || descriptor & 0x08 != 0
        || descriptor & 0xc0 == 0 && descriptor & 0x20 == 0
    {
        return Err(Error::InvalidFormat);
    }
    let src = stored.as_ptr().cast();
    // Exactly one frame, filling `stored`, declaring `raw.len()` bytes.
    if unsafe { ZSTD_getFrameContentSize(src, stored.len()) } != raw.len() as u64
        || unsafe { ZSTD_findFrameCompressedSize(src, stored.len()) } != stored.len()
    {
        return Err(Error::InvalidFormat);
    }
    // The checksum is ignored (see `ZstdDecoder::new`); libzstd still fails
    // on truncated input and on data its decoder rejects.
    let n =
        unsafe { ZSTD_decompressDCtx(dctx, raw.as_mut_ptr().cast(), raw.len(), src, stored.len()) };
    if unsafe { ZSTD_isError(n) } != 0 || n != raw.len() {
        return Err(Error::InvalidFormat);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: [u8; 29] = WARM_UP_FRAME;

    #[test]
    fn reused_decoder_ignores_checksums_but_rejects_bad_frames() {
        let mut decoder = ZstdDecoder::new();
        let mut out = [0u8; ZSTD_MAX_CHUNK_SIZE];
        decoder.warm_up(&mut out).unwrap();
        let raw = WARM_UP_RAW_SIZE;
        let mut bad_sum = FRAME;
        bad_sum[28] ^= 1; // the last checksum byte
        for _ in 0..3 {
            out.fill(0xff);
            decoder
                .decode(ZSTD_CODEC_ZSTD, raw, &FRAME, &mut out)
                .unwrap();
            assert!(out[..raw]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 7) as u8));
            // A wrong checksum is not verified any more.
            decoder
                .decode(ZSTD_CODEC_ZSTD, raw, &bad_sum, &mut out)
                .unwrap();
            // Truncation and a wrong declared size still fail.
            assert!(decoder
                .decode(ZSTD_CODEC_ZSTD, raw, &FRAME[..20], &mut out)
                .is_err());
            assert!(decoder
                .decode(ZSTD_CODEC_ZSTD, raw - 1, &FRAME, &mut out)
                .is_err());
        }
    }
}
