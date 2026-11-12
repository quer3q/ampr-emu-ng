//! Bounded decoding of one independent zstd chunk.

use crate::Error;
use zstd_sys::{
    ZSTD_DCtx, ZSTD_DCtx_setParameter, ZSTD_dParameter, ZSTD_decompressDCtx,
    ZSTD_findFrameCompressedSize, ZSTD_getFrameContentSize, ZSTD_initStaticDCtx, ZSTD_isError,
};

pub const ZSTD_MAX_CHUNK_SIZE: usize = 1 << 18;
pub const ZSTD_CODEC_RAW: u8 = 0;
pub const ZSTD_CODEC_ZSTD: u8 = 1;
/// A stored chunk is never larger than its raw size (the writer stores a
/// chunk raw when zstd is not smaller), so 256 KiB bounds both codecs.
const MAX_STORED_SIZE: usize = 1 << 18;
/// Content size of `WARM_UP_FRAME`: a full chunk, so warm-up meets the
/// largest content size and window (256 KiB) a real chunk can have.
const WARM_UP_RAW_SIZE: usize = ZSTD_MAX_CHUNK_SIZE;

/// 256 KiB of `i % 7`, `zstd -19 -C` (content size and checksum): two
/// 128 KiB blocks, a 256 KiB window: warm-up decodes the largest frame a
/// real chunk can be, so a workspace too small for it fails at setup, not on
/// a game read (the decode-on-access fault handler, ampr-sys
/// rt/pack/mmap_fault.rs, decodes inside a signal handler).
const WARM_UP_FRAME: [u8; 42] = [
    40, 181, 47, 253, 164, 0, 0, 4, 0, 124, 0, 0, 56, 0, 1, 2, 3, 4, 5, 6, 1, 0, 246, 255, 202,
    139, 17, 69, 0, 0, 0, 1, 0, 253, 255, 202, 11, 16, 147, 29, 0, 1,
];

/// Bytes of the workspace `ZstdDecoder::init_in` takes: the decoder, then a
/// static libzstd DCtx in the rest. `ZSTD_estimateDCtxSize()` is 95968 B for
/// zstd 1.5.7 (host test below); 112 KiB is seven 16 KiB pages, the unit the
/// runtime pool hands out, and leaves 18 KiB of slack for a later 1.5.x.
pub const ZSTD_DECODER_WORKSPACE: usize = 112 << 10;
/// The decoder's own bytes at the workspace start; the DCtx follows, 64 B
/// aligned.
const DECODER_HEADER: usize = 64;
const _: () = assert!(core::mem::size_of::<ZstdDecoder>() <= DECODER_HEADER);
const _: () = assert!(core::mem::align_of::<ZstdDecoder>() <= DECODER_HEADER);

/// A reusable zstd chunk decoder over one static libzstd `ZSTD_DCtx` (native
/// C zstd: ~10x ruzstd's speed on the console). The decoder and its DCtx live
/// in a caller-provided workspace (`init_in`), so libzstd never allocates:
/// single-shot `ZSTD_decompressDCtx` needs no buffers past the DCtx. Not
/// shareable: one per decoding thread. Nothing to free: the workspace owner
/// frees the workspace (a static DCtx refuses `ZSTD_freeDCtx`).
pub struct ZstdDecoder {
    dctx: *mut ZSTD_DCtx,
}

// The context is owned and only used through `&mut self`.
unsafe impl Send for ZstdDecoder {}

impl ZstdDecoder {
    /// Places a decoder at `workspace`, `len` bytes, at least
    /// `ZSTD_DECODER_WORKSPACE` and 64 B aligned; null when it is too small
    /// or misaligned, or libzstd refused the DCtx or a parameter.
    ///
    /// # Safety
    /// `workspace` is writable for `len` bytes and outlives the decoder; the
    /// caller uses it for nothing else until it frees it.
    pub unsafe fn init_in(workspace: *mut u8, len: usize) -> *mut ZstdDecoder {
        if workspace.is_null()
            || len < ZSTD_DECODER_WORKSPACE
            || workspace as usize % DECODER_HEADER != 0
        {
            return core::ptr::null_mut();
        }
        let dctx = unsafe {
            ZSTD_initStaticDCtx(workspace.add(DECODER_HEADER).cast(), len - DECODER_HEADER)
        };
        if dctx.is_null() {
            return core::ptr::null_mut();
        }
        // A frame may not need a window past one chunk (2^18). The frame
        // checksum is not verified (ZSTD_d_forceIgnoreChecksum): a few percent
        // of decode time; corrupt data still fails libzstd's own decoding
        // checks, but a corruption that decodes cleanly is no longer caught.
        let set =
            |param, value| unsafe { ZSTD_isError(ZSTD_DCtx_setParameter(dctx, param, value)) };
        if set(
            ZSTD_dParameter::ZSTD_d_windowLogMax,
            ZSTD_MAX_CHUNK_SIZE.trailing_zeros() as i32,
        ) != 0
            // ZSTD_d_forceIgnoreChecksum: skip the per-chunk XXH64 check.
            || set(ZSTD_dParameter::ZSTD_d_experimentalParam3, 1) != 0
        {
            return core::ptr::null_mut();
        }
        let decoder = workspace.cast::<ZstdDecoder>();
        unsafe { decoder.write(Self { dctx }) };
        decoder
    }

    /// Turns the frame checksum check (XXH64, written by the packer) on or
    /// off; off after `init_in`. On costs a few percent of decode time and
    /// fails a chunk whose decoded bytes do not match. False when libzstd
    /// refused the setting. Call between frames.
    pub fn set_verify_checksum(&mut self, on: bool) -> bool {
        let rc = unsafe {
            ZSTD_DCtx_setParameter(
                self.dctx,
                ZSTD_dParameter::ZSTD_d_experimentalParam3,
                i32::from(!on),
            )
        };
        unsafe { ZSTD_isError(rc) == 0 }
    }

    /// Decodes a built-in full-size (256 KiB, 256 KiB window) frame into
    /// `scratch`, so a decoder that cannot decode the largest real chunk
    /// fails here, before the first one. Callers pass the scratch they
    /// decode real chunks into, which must hold `ZSTD_MAX_CHUNK_SIZE`
    /// (256 KiB) bytes.
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
    // The checksum is ignored (see `ZstdDecoder::init_in`); libzstd still fails
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

    const FRAME: [u8; 42] = WARM_UP_FRAME;

    #[repr(C, align(64))]
    struct Workspace([u8; ZSTD_DECODER_WORKSPACE + DECODER_HEADER]);

    #[test]
    fn workspace_holds_the_dctx() {
        // 95968 B for zstd 1.5.7 on the host.
        let need = unsafe { zstd_sys::ZSTD_estimateDCtxSize() };
        assert!(need + DECODER_HEADER <= ZSTD_DECODER_WORKSPACE, "{need}");
        assert_eq!(ZSTD_DECODER_WORKSPACE % (16 << 10), 0);
        let mut ws = Workspace([0; ZSTD_DECODER_WORKSPACE + DECODER_HEADER]);
        let base = ws.0.as_mut_ptr();
        // Too small or misaligned: refused.
        let small = ZSTD_DECODER_WORKSPACE - 1;
        assert!(unsafe { ZstdDecoder::init_in(base, small) }.is_null());
        let off = unsafe { base.add(8) };
        assert!(unsafe { ZstdDecoder::init_in(off, ZSTD_DECODER_WORKSPACE) }.is_null());
        // A DCtx of just the estimate decodes a full chunk: decode needs
        // no memory past it.
        let dctx = unsafe { ZSTD_initStaticDCtx(base.add(DECODER_HEADER).cast(), need) };
        let mut tight = ZstdDecoder { dctx };
        assert!(!dctx.is_null());
        let mut out = [0u8; ZSTD_MAX_CHUNK_SIZE];
        tight.warm_up(&mut out).unwrap();
        assert!(tight.set_verify_checksum(true));
        tight.warm_up(&mut out).unwrap();
    }

    #[test]
    fn reused_decoder_ignores_checksums_but_rejects_bad_frames() {
        let mut ws = Workspace([0; ZSTD_DECODER_WORKSPACE + DECODER_HEADER]);
        let decoder = unsafe { ZstdDecoder::init_in(ws.0.as_mut_ptr(), ZSTD_DECODER_WORKSPACE) };
        let decoder = unsafe { decoder.as_mut() }.unwrap();
        let mut out = [0u8; ZSTD_MAX_CHUNK_SIZE];
        decoder.warm_up(&mut out).unwrap();
        let raw = WARM_UP_RAW_SIZE;
        let mut bad_sum = FRAME;
        bad_sum[FRAME.len() - 1] ^= 1; // the last checksum byte
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
        // With the check on, the wrong checksum fails and the good frame
        // still decodes; off again, the wrong one passes.
        assert!(decoder.set_verify_checksum(true));
        assert!(decoder
            .decode(ZSTD_CODEC_ZSTD, raw, &bad_sum, &mut out)
            .is_err());
        decoder
            .decode(ZSTD_CODEC_ZSTD, raw, &FRAME, &mut out)
            .unwrap();
        assert!(decoder.set_verify_checksum(false));
        decoder
            .decode(ZSTD_CODEC_ZSTD, raw, &bad_sum, &mut out)
            .unwrap();
    }
}
