//! Borrowed AMPRPAK4 readers, read planning and LZ4 chunk decoding.
#![no_std]
#![forbid(unsafe_code)]

pub mod manifest;
pub mod overlay;
pub mod plan;

pub use ampr_codec::Error as CodecError;
pub use ampr_format::{
    crc32, crc32_parts, crc32_seeded, folded, header_crc, i64_at, logical_path, pak_path_hash,
    range, safe_components, section, terminated_string, u16_at, u32_at, u64_at, CoreError,
    CoreResult, Error, Result, ENDIAN_MARKER,
};

pub const PAK_MAGIC: &[u8; 8] = b"AMPRPAK4";
pub const DAT_MAGIC: &[u8; 8] = b"AMPRDAT3";
pub const PAK_HEADER: usize = 128;
pub const FILE_RECORD: usize = 48;
pub const CHUNK_RECORD: usize = 12;
pub const PACK_RECORD: usize = 32;
pub const DAT_HEADER: usize = 64;
pub const PAK_PAYLOAD_CRC_AT: usize = 112;
pub const PAK_HEADER_CRC_AT: usize = 116;
pub const DAT_HEADER_CRC_AT: usize = 56;
pub const FILE_PACKED: u32 = 1;
pub const FILE_STORE_ONLY: u32 = 2;
pub const FILE_STREAMING: u32 = 4;
pub const FILE_RANDOM_ACCESS: u32 = 16;
pub const CHUNK_RAW: u8 = 0;
pub const CHUNK_LZ4: u8 = 1;
pub const CHUNK_STREAMING: u8 = 2;
pub const CHUNK_PAGE_CONTAINED: u8 = 4;
pub const CHUNK_PAGE_ALIGNED: u8 = 8;
pub const PACK_STRIPED: u32 = 1;
pub const PACK_IO_PAGE_LAYOUT: u32 = 2;

pub const MAX_CHUNK_SIZE: usize = 1 << 20;
pub const CODEC_RAW: u8 = 0;
pub const CODEC_LZ4: u8 = 1;
const KNOWN_FLAGS: u8 = 0x0f;

/// Decode one AMPR chunk into the first `raw_size` bytes of `output`.
///
/// The caller supplies the exact stored bytes; metadata and payload CRCs are
/// validated elsewhere. A trailing output capacity remains untouched.
pub fn decode_chunk(
    codec: u8,
    flags: u8,
    raw_size: usize,
    stored: &[u8],
    output: &mut [u8],
) -> core::result::Result<(), CodecError> {
    if raw_size == 0
        || raw_size > MAX_CHUNK_SIZE
        || stored.is_empty()
        || stored.len() > MAX_CHUNK_SIZE
        || output.len() < raw_size
        || flags & !KNOWN_FLAGS != 0
    {
        return Err(CodecError::InvalidArgument);
    }

    let raw = &mut output[..raw_size];
    match codec {
        CODEC_RAW => {
            if stored.len() != raw_size {
                return Err(CodecError::InvalidFormat);
            }
            raw.copy_from_slice(stored);
        }
        CODEC_LZ4 => {
            let decoded = lz4_flex::block::decompress_into(stored, raw)
                .map_err(|_| CodecError::InvalidFormat)?;
            if decoded != raw_size {
                return Err(CodecError::InvalidFormat);
            }
        }
        _ => return Err(CodecError::Unsupported),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_decode_matches_boundary() {
        let mut output = [0xcc; 18];
        // LZ4 block: "abc", a nine-byte match at offset 3, then five literals.
        let compressed = [
            0x35, b'a', b'b', b'c', 3, 0, 0x50, b'X', b'Y', b'Z', b'W', b'Q',
        ];
        decode_chunk(CODEC_LZ4, KNOWN_FLAGS, 17, &compressed, &mut output).unwrap();
        assert_eq!(&output[..17], b"abcabcabcabcXYZWQ");
        assert_eq!(output[17], 0xcc);

        assert_eq!(decode_chunk(CODEC_RAW, 0, 3, b"raw", &mut output), Ok(()));
        assert_eq!(&output[..3], b"raw");
        assert_eq!(
            decode_chunk(CODEC_RAW, 0, 4, b"raw", &mut output),
            Err(CodecError::InvalidFormat)
        );
        assert_eq!(
            decode_chunk(CODEC_LZ4, 0, 18, &compressed, &mut output),
            Err(CodecError::InvalidFormat)
        );
        assert_eq!(
            decode_chunk(CODEC_LZ4, 0, 17, &compressed[..5], &mut output),
            Err(CodecError::InvalidFormat)
        );
        assert_eq!(
            decode_chunk(2, 0, 1, b"x", &mut output),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            decode_chunk(CODEC_RAW, 0x10, 1, b"x", &mut output),
            Err(CodecError::InvalidArgument)
        );
        assert_eq!(
            decode_chunk(CODEC_RAW, 0, 0, b"x", &mut output),
            Err(CodecError::InvalidArgument)
        );
        assert_eq!(
            decode_chunk(CODEC_RAW, 0, MAX_CHUNK_SIZE + 1, b"x", &mut output),
            Err(CodecError::InvalidArgument)
        );
        assert_eq!(
            decode_chunk(CODEC_RAW, 0, 1, b"", &mut output),
            Err(CodecError::InvalidArgument)
        );
        assert_eq!(
            decode_chunk(CODEC_RAW, 0, 19, b"x", &mut output),
            Err(CodecError::InvalidArgument)
        );
    }
}
