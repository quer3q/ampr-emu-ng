//! Borrowed, bounded zstd chunk decoding and shared codec errors.
#![no_std]
// deny, not forbid: the zstd module wraps libzstd's C API.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod zstd;
pub use zstd::{
    decode_zstd_chunk, ZstdDecoder, ZSTD_CODEC_RAW, ZSTD_CODEC_ZSTD, ZSTD_MAX_CHUNK_SIZE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    InvalidFormat,
    Unsupported,
}
