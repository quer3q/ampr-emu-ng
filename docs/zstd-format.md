# zstd packs (ampr_zstd.index + ampr_zstd-NNN.pak)

The ampr-emu-ng zstd pack format: an `AMPRZPK1` index plus `AMPRZDT1`
volumes. Packs are built by
[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge); this repo only
decodes them: `crates/ampr-zstd` holds the format and the runtime
(`crates/ampr-sys`) mounts it. Not AMPRPAK4: a new,
general container. One runtime reads zstd and LZ4 (AMPRPAK4) packs, picked at
load by whether `/app0/ampr_zstd.index` exists.

All integers little-endian. CRC = CRC-32 (IEEE, as `crc32fast`).
Path hash = FNV-1a 64 (basis 14695981039346656037, prime 1099511628211) over
the UTF-8 path relative to the game root, `/` separators, no leading slash,
case kept (e.g. `data/level1.bin`).

## Files on disk

- `ampr_zstd.index`: loose, at the game root. Whole archive index.
- `ampr_zstd-000.pak`, `ampr_zstd-001.pak`, ...: volumes, three digits at
  least (more past 999), as LZ4's `ampr_assets-NNN.pak`. Volume id 0 is
  `ampr_zstd-000.pak`. Each volume file is at most
  4 GiB less 64 KiB (4,294,901,760 bytes, as the LZ4 packs), header
  included: every chunk offset stays below 2^32 (the u32 chunk offset), and
  a volume stays under FAT32's 4 GiB file limit. Volume count does not affect
  read speed (23 fd-budget waits in a whole session).
- `ampr_emu.index` (AMPRIDX3) stays as the dump tooling writes it: it lists every
  game file (loose and packed) so AMPR path ids keep working.

## ampr_zstd.index

Header, 128 bytes:

| off | type | field |
|---|---|---|
| 0 | [8] | magic `AMPRZPK1` |
| 8 | u32 | version = 1 |
| 12 | u32 | header size = 128 |
| 16 | u8 | chunk_shift = 18 (256 KiB); readers reject any other value |
| 17 | u8 | zstd level used (info only) |
| 18 | u16 | reserved 0 |
| 20 | u32 | volume_count |
| 24 | [16] | archive_id (random; repeated in every volume header) |
| 40 | u64 | file_count |
| 48 | u64 | chunk_count |
| 56 | u64 | files_off (= 128) |
| 64 | u64 | chunks_off |
| 72 | u64 | volumes_off |
| 80 | u64 | strings_off |
| 88 | u64 | strings_len (index file ends at strings_off + strings_len) |
| 96 | u64 | total logical bytes of packed files |
| 104 | u64 | reserved 0 |
| 112 | u32 | CRC of bytes [128, end) |
| 116 | u32 | CRC of the header with bytes 112..120 zeroed |
| 120 | u64 | reserved 0 |

File record, 32 bytes, sorted by (path_hash, path bytes) for binary search:

| off | type | field |
|---|---|---|
| 0 | u64 | path_hash |
| 8 | u64 | logical_size |
| 16 | u32 | first_chunk (chunk_count = ceil(size / 256 KiB); 0 for empty files) |
| 20 | u32 | path_off (into strings) |
| 24 | u16 | path_len (bytes, no NUL) |
| 26 | u16 | flags: bit0 = store-only (all chunks raw) |
| 28 | u32 | reserved 0 |

Chunk record, 8 bytes (u64), one per 256 KiB of a file, flat array:

| bits | field |
|---|---|
| 0..31 | byte offset inside the volume (absolute, from file start) |
| 32..43 | volume id (12 bits) |
| 44..61 | stored_size - 1 (18 bits, so stored_size <= 256 KiB) |
| 62..63 | codec: 0 = raw, 1 = zstd; 2 and 3 are invalid |

Volume record, 8 bytes: u64 file size of that volume.

Strings: path bytes, back to back.

Chunk `i` of a file decodes to `min(262144, size - i * 262144)` bytes. A raw
chunk has stored_size equal to that; a zstd chunk is strictly smaller (the
pack builder stores a chunk raw when zstd is not smaller), so stored_size never
exceeds the raw size. A zstd chunk is exactly one zstd frame:
content size in the frame header, frame checksum ON (written by the packer; the runtime skips verifying it for speed),
no dictionary, window at most 256 KiB (the runtime decoder's limit).

Indexes written with 64 KiB chunks (chunk_shift 16, older test builds) keep
version 1 but fail to mount: repack them.

## Volume file

Header, 64 bytes: magic `AMPRZDT1` (8), u32 version = 1, u32 header size =
64, u32 volume id, u32 volume_count, [16] archive_id, u64 payload bytes,
[12] reserved 0, u32 CRC of the header with this field zeroed (at 60).
Chunks follow from offset 64, back to back, no padding, in index order
(files in file-record order, chunks in file order). A file may continue in
the next volume.

## Parallel reads

Every chunk is independent (own frame, absolute offset, O(1) lookup by
index). Readers split any chunk range into batches: contiguous chunks are a
contiguous byte range in one volume, so a batch is one large pread, then the
chunks decode in parallel (decode workers in the runtime).

## What is packed

Loose, as the pack builder decides: eboot.bin, `*.elf`, `*.self`, `*.prx`,
`*.sprx`, `sce_sys/`, `sce_module/`, `fakelib*/`, plus
`ampr_zstd.index`, `ampr_zstd-*.pak`, `ampr_emu.index`. Everything else is packed:
video, audio, configs too. No traces, no profile, no keep-loose list.

Per file: compress every 256 KiB chunk with zstd at the chosen level
(1..=22, default 5). A chunk whose frame is not smaller than raw is stored
raw. If the file's total stored bytes save less than 1% of its size
(`stored * 100 > size * 99`), the whole file is store-only.

## Runtime test build

`./ps5/build-docker.sh` builds `libSceAmpr.sprx` from `crates/ampr-sys`: with
`/app0/ampr_zstd.index` present it mounts that in place of
`ampr_assets.index`, opens `ampr_zstd-NNN.pak` volumes, decodes zstd
(libzstd, `ampr-codec`), and serves plain `read`/`pread`/`readv`/
`preadv` (+ `sceKernel*`) on packed virtual fds, not only AMPR/APR reads.
