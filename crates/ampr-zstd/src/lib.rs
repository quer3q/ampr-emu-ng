//! The zstd pack format the runtime reads: `ampr_zstd.index` and volume
//! constants, magics, layout, names, chunk records and the validating volume
//! header decoder. Decode side only; the packs are built outside this project
//! (see docs/zstd-format.md).
#![no_std]

mod volume;

pub use volume::{VolumeHeader, decode_volume_header, write_volume_name};

pub const INDEX_MAGIC: &[u8; 8] = b"AMPRZPK1";
pub const VOLUME_MAGIC: &[u8; 8] = b"AMPRZDT1";
/// The format version at byte 8 of the index and of each volume header.
pub const FORMAT_VERSION: u32 = 1;
/// The index file at the game root.
pub const INDEX_NAME: &str = "ampr_zstd.index";
/// Volume `id` is `VOLUME_PREFIX` + the id (three digits at least) + `VOLUME_SUFFIX`.
pub const VOLUME_PREFIX: &str = "ampr_zstd-";
pub const VOLUME_SUFFIX: &str = ".pak";
/// log2 of `CHUNK_SIZE`, stored at index header byte 16.
pub const CHUNK_SHIFT: u8 = 18;
pub const CHUNK_SIZE: u64 = 1 << CHUNK_SHIFT;
/// 4 GiB less 64 KiB (4,294,901,760 bytes), as the LZ4 packs: the largest
/// volume whose every offset fits the u32 chunk offset, and under FAT32's
/// 4 GiB file limit.
pub const VOLUME_LIMIT: u64 = (1 << 32) - (1 << 16);
pub const INDEX_HEADER_SIZE: usize = 128;
pub const VOLUME_HEADER_SIZE: usize = 64;
pub const MAX_VOLUMES: usize = 1 << 12;
/// The index's zstd level (header byte 17) is one of these.
pub const ZSTD_LEVELS: core::ops::RangeInclusive<u8> = 1..=22;
/// Index table record sizes: file, chunk, volume size.
pub const FILE_RECORD_SIZE: usize = 32;
pub const CHUNK_RECORD_SIZE: usize = 8;
pub const VOLUME_RECORD_SIZE: usize = 8;
/// Index header: CRC-32 of the payload (everything after the header) at 112,
/// CRC-32 of the header with bytes 112..120 zeroed at 116.
pub const INDEX_PAYLOAD_CRC_AT: usize = 112;
pub const INDEX_HEADER_CRC_AT: usize = 116;
/// Volume header: CRC-32 of the header with bytes 60..64 zeroed at 60.
pub const VOLUME_CRC_AT: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(what) => write!(f, "invalid zstd pack {what}"),
        }
    }
}

impl core::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

fn invalid<T>(what: &'static str) -> Result<T> {
    Err(Error::Invalid(what))
}

fn read<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Invalid("offset"))?)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Invalid("length"))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read(bytes, at)?))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read(bytes, at)?))
}

fn crc_zeroed<const N: usize>(bytes: &[u8], at: usize, len: usize) -> Result<u32> {
    let header = bytes.get(..len).ok_or(Error::Invalid("header length"))?;
    let end = at.checked_add(N).ok_or(Error::Invalid("CRC offset"))?;
    if end > len {
        return invalid("CRC offset");
    }
    let mut crc = crc32fast::Hasher::new();
    crc.update(&header[..at]);
    crc.update(&[0; N]);
    crc.update(&header[end..]);
    Ok(crc.finalize())
}

/// FNV-1a 64 over the exact UTF-8 relative path bytes (case is preserved).
pub fn path_hash_bytes(path: &[u8]) -> u64 {
    path.iter().fold(14695981039346656037, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
    })
}

pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0'])
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Raw,
    Zstd,
}

/// Absolute location and stored length of one independently decoded chunk.
/// Packed as a u64: bits 0..31 offset, 32..43 volume id, 44..61
/// `stored_size - 1`, 62..63 codec (0 raw, 1 zstd).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub offset: u32,
    pub volume_id: u16,
    pub stored_size: u32,
    pub codec: Codec,
}

impl Chunk {
    pub fn pack(self) -> Result<u64> {
        if self.volume_id as usize >= MAX_VOLUMES
            || self.stored_size == 0
            || u64::from(self.stored_size) > CHUNK_SIZE
            || self.offset < VOLUME_HEADER_SIZE as u32
            || u64::from(self.offset) + u64::from(self.stored_size) > VOLUME_LIMIT
        {
            return invalid("chunk descriptor");
        }
        let codec = match self.codec {
            Codec::Raw => 0,
            Codec::Zstd => 1u64,
        };
        Ok(u64::from(self.offset)
            | (u64::from(self.volume_id) << 32)
            | (u64::from(self.stored_size - 1) << 44)
            | (codec << 62))
    }

    pub fn unpack(word: u64) -> Result<Self> {
        if word >> 62 > 1 {
            return invalid("chunk codec");
        }
        let chunk = Self {
            offset: word as u32,
            volume_id: ((word >> 32) & 0xfff) as u16,
            stored_size: (((word >> 44) & 0x3ffff) + 1) as u32,
            codec: if word >> 62 == 0 {
                Codec::Raw
            } else {
                Codec::Zstd
            },
        };
        chunk.pack()?;
        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::encode_volume_header;

    /// A named way to break a valid value.
    type Case<T> = (&'static str, fn(&mut T));

    #[test]
    fn chunk_record_layout() {
        let chunk = Chunk {
            offset: 0x1234_5678,
            volume_id: 0xabc,
            stored_size: CHUNK_SIZE as u32,
            codec: Codec::Zstd,
        };
        let word = chunk.pack().unwrap();
        assert_eq!(word & 0xffff_ffff, 0x1234_5678);
        assert_eq!((word >> 32) & 0xfff, 0xabc);
        assert_eq!((word >> 44) & 0x3ffff, CHUNK_SIZE - 1);
        assert_eq!(word >> 62, 1);
        assert_eq!(Chunk::unpack(word).unwrap(), chunk);
        let raw = Chunk {
            stored_size: 1,
            codec: Codec::Raw,
            ..chunk
        };
        assert_eq!(Chunk::unpack(raw.pack().unwrap()).unwrap(), raw);
    }

    #[test]
    fn chunk_record_rejects() {
        let base = Chunk {
            offset: VOLUME_HEADER_SIZE as u32,
            volume_id: 0,
            stored_size: 100,
            codec: Codec::Zstd,
        }
        .pack()
        .unwrap();
        for codec in [2u64, 3] {
            let word = (base & !(3 << 62)) | (codec << 62);
            assert!(Chunk::unpack(word).is_err());
        }
        let oversized = Chunk {
            offset: VOLUME_HEADER_SIZE as u32,
            volume_id: 0,
            stored_size: CHUNK_SIZE as u32 + 1,
            codec: Codec::Raw,
        };
        assert!(oversized.pack().is_err());
    }

    #[test]
    fn volume_limit_is_4_gib_less_64_kib() {
        assert_eq!(VOLUME_LIMIT, 4_294_901_760);
        // The last chunk may end exactly at the limit; its offset fits u32.
        let size = CHUNK_SIZE as u32;
        let last = |offset: u64| Chunk {
            offset: offset as u32,
            volume_id: 0,
            stored_size: size,
            codec: Codec::Raw,
        };
        let at_end = VOLUME_LIMIT - u64::from(size);
        let word = last(at_end).pack().unwrap();
        assert_eq!(Chunk::unpack(word).unwrap().offset as u64, at_end);
        assert!(last(at_end + 1).pack().is_err());
    }

    #[test]
    fn written_volume_name_matches_volume_name() {
        let mut buf = [0u8; 24];
        for (id, name) in [
            (0, "ampr_zstd-000.pak"),
            (1, "ampr_zstd-001.pak"),
            (7, "ampr_zstd-007.pak"),
            (999, "ampr_zstd-999.pak"),
            (1000, "ampr_zstd-1000.pak"),
            (4095, "ampr_zstd-4095.pak"),
            (u32::MAX, "ampr_zstd-4294967295.pak"),
        ] {
            assert_eq!(write_volume_name(id, &mut buf).unwrap(), name);
        }
        assert!(write_volume_name(7, &mut [0u8; 16]).is_err());
    }

    #[test]
    fn volume_header_round_trip_and_rejects() {
        let header = VolumeHeader {
            id: 2,
            count: 3,
            archive_id: [4; 16],
            payload_bytes: 1234,
        };
        let good = encode_volume_header(header).unwrap();
        assert_eq!(decode_volume_header(&good).unwrap(), header);
        let last = VolumeHeader {
            id: MAX_VOLUMES as u32 - 1,
            count: MAX_VOLUMES as u32,
            payload_bytes: VOLUME_LIMIT - VOLUME_HEADER_SIZE as u64,
            ..header
        };
        let bytes = encode_volume_header(last).unwrap();
        assert_eq!(decode_volume_header(&bytes).unwrap(), last);
        let cases: &[Case<[u8; VOLUME_HEADER_SIZE]>] = &[
            ("magic", |b| b[0] ^= 1),
            ("version", |b| b[8] = 2),
            ("header size", |b| b[12] = 65),
            ("id == count", |b| b[16] = 3),
            ("count 0", |b| b[16..24].fill(0)),
            ("count > MAX_VOLUMES", |b| {
                b[20..24].copy_from_slice(&(MAX_VOLUMES as u32 + 1).to_le_bytes())
            }),
            ("reserved 48", |b| b[48] = 1),
            ("reserved 59", |b| b[59] = 1),
            ("payload past the limit", |b| {
                b[40..48].copy_from_slice(&(VOLUME_LIMIT - 63).to_le_bytes())
            }),
        ];
        for (name, break_it) in cases {
            let mut bytes = good;
            break_it(&mut bytes);
            let crc = crc_zeroed::<4>(&bytes, 60, VOLUME_HEADER_SIZE).unwrap();
            bytes[60..64].copy_from_slice(&crc.to_le_bytes());
            assert!(decode_volume_header(&bytes).is_err(), "{name}");
        }
        let mut bytes = good;
        bytes[30] ^= 1;
        assert!(decode_volume_header(&bytes).is_err(), "CRC");
        assert!(decode_volume_header(&good[..VOLUME_HEADER_SIZE - 1]).is_err());
        for (id, count) in [(3, 3), (0, 0), (0, MAX_VOLUMES as u32 + 1)] {
            let bad = VolumeHeader {
                id,
                count,
                ..header
            };
            assert!(encode_volume_header(bad).is_err(), "{id} of {count}");
        }
    }
}
