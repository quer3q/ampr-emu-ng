# zstd packs (ampr_zstd.index + ampr_zstd-NNN.pak)

ampr-emu-ng zstd packs are an `AMPRZPK1` index plus `AMPRZDT1` volumes,
separate from AMPRPAK4.
[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds them;
this repo only decodes them (`crates/ampr-zstd`: constants, layout, volume
header; `crates/ampr-format/src/zstd.rs`: index reader). When
`/app0/ampr_zstd.index` exists, `libSceAmpr.sprx` mounts it instead of the
LZ4 `ampr_assets.index`, decodes with libzstd (`ampr-codec`) and serves
AMPR/APR reads and the file calls under What is packed. The mount reads
the index file once, sequentially, through two 64 KiB windows from the
Index ledger (80 MiB, `rt/index_memory.rs`): it checks the whole file, CRC
included, fills the chunk and volume tables (8 B per chunk and per volume)
into one Index block, joins every file record to the compiled index view
of `ampr_emu.index` (`join_zstd`, `crates/ampr-format/src/view_join.rs`)
and closes the file. The view then holds each packed file's first chunk
and size, so opens and read jobs read memory only; a lookup reads at most
the stored path of a hash hit from `ampr_emu.index`. The header alone
sizes the tables, so an index whose tables and windows do not fit the
room left is refused with the index notice before the file is read, and
no packed file is served. Measured on the host from a 242,409-file index:
21.74 MiB for the view and the tables, 10.22 MiB of it chunk and volume
tables; no console run has measured it. The loader refuses an index file
over 512 MiB (`AMPR_EMU_PACK_INDEX_MAX_BYTES`, `rt/pack/mod.rs`): that
bounds the full CRC read at mount for a corrupt file.
Every path must be shorter than 1024 bytes, the PS5 path limit.

Integers are little-endian. CRC is CRC-32 (IEEE, as in `crc32fast`). The
path hash is FNV-1a 64 (basis 14695981039346656037, prime 1099511628211)
over the UTF-8 path relative to the game root: `/` separators, no leading
slash, case kept (`data/level1.bin`), no `\`, NUL, or empty, `.` or `..`
component.

## Files on disk

- `ampr_zstd.index`: the archive index, loose at the game root.
- `ampr_zstd-000.pak`, `ampr_zstd-001.pak`, ...: up to 4096
  volumes, id 0 first, numbered with at least three digits. A volume is at most 4 GiB less
  64 KiB (4,294,901,760 bytes, as for LZ4 packs) with its header, so chunk
  offsets fit a u32 and volumes fit FAT32. The volume count does not affect
  read speed (23 fd-budget waits in a whole session).
- `ampr_emu.index` (AMPRIDX3) stays as the dump tooling writes it. It
  lists every file, loose and packed, so AMPR path ids keep working.

## What the runtime needs from ampr_emu.index

A packed file is reachable only through its AMPRIDX3 id. At mount the
runtime joins each `ampr_zstd.index` record to the view row whose path,
`/app0/` plus the record's path and folded to lower case, has the same hash
(`join_zstd`, `crates/ampr-format/src/view_join.rs`). A packer has to keep
these rules, or the game cannot open the files it packed:

- Every packed file needs a record in `ampr_emu.index` with the same path,
  up to ASCII case. A file that is in `ampr_zstd.index` but not in
  `ampr_emu.index` has no id and is not served. Of two zstd records that
  differ only in case, the first is joined and the second is not served.
  A path whose hash another `ampr_emu.index` file shares stays loose
  (expected never to happen with a 64-bit hash).
- The size in the record must equal `logical_size` of the file in
  `ampr_zstd.index`. A difference makes the mount invalid, and then no
  packed file is served.
- `ampr_emu.index` has to pass its own checks (`Index::check`,
  `crates/ampr-format/src/index.rs`). Every path starts with `/app0/`, is
  shorter than 1024 bytes, has no name part over 255 bytes
  (`kernel_path_limits`) and no empty, `.` or `..` part, holds no NUL or
  `\`, and is followed by a NUL in the path blob (`checked_path`). No two
  records have paths that are equal after folding `A`-`Z` to `a`-`z`. One
  bad record makes the whole file invalid, not only that record.
  A title without packs then gets an index rebuilt from the folder. With
  packs the rebuilt index stays in memory and is made from a walk of the
  folder, which cannot contain the packed files because they are gone from
  `/app0`, so none of them is served (`ensure_ready_slow`, `rt/index.rs`).

## ampr_zstd.index

Header, 128 bytes:

| off | type | field |
|---|---|---|
| 0 | [8] | magic `AMPRZPK1` |
| 8 | u32 | version = 1 |
| 12 | u32 | header size = 128 |
| 16 | u8 | chunk_shift = 18 (256 KiB); readers reject any other value |
| 17 | u8 | zstd level used, 1..=22; readers reject other values |
| 18 | u16 | reserved 0 |
| 20 | u32 | volume_count |
| 24 | [16] | archive_id (random; repeated in every volume header) |
| 40 | u64 | file_count |
| 48 | u64 | chunk_count (at most 2^32 - 1) |
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

The tables follow back to back in this order with no gaps; chunk_count and
volume_count are both 0 or both non-zero.

File record, 32 bytes, sorted by (path_hash, path bytes) for binary search:

| off | type | field |
|---|---|---|
| 0 | u64 | path_hash |
| 8 | u64 | logical_size |
| 16 | u32 | first_chunk: the chunks of all earlier records (chunk_count = ceil(size / 256 KiB), 0 for an empty file) |
| 20 | u32 | path_off (into strings) |
| 24 | u16 | path_len (bytes, no NUL; below 1024, the PS5 path limit, or the index is refused) |
| 26 | u16 | flags: bit0 = store-only (all chunks raw); other bits 0 |
| 28 | u32 | reserved 0 |

Chunk record, 8 bytes (u64), one per 256 KiB of a file, flat array:

| bits | field |
|---|---|
| 0..31 | byte offset inside the volume (absolute, from file start) |
| 32..43 | volume id (12 bits) |
| 44..61 | stored_size - 1 (18 bits, so stored_size <= 256 KiB) |
| 62..63 | codec: 0 = raw, 1 = zstd; 2 and 3 are invalid |

Volume record, 8 bytes: u64 file size of that volume.

Strings: path bytes back to back, in file-record order. The tables follow
the header in this order with no gaps; chunk_count and volume_count are
both 0 or both non-zero.

Chunk `i` decodes to `min(262144, size - i * 262144)` bytes. A raw chunk
stores exactly that; a zstd chunk is strictly smaller, since the builder
stores raw any chunk zstd does not shrink. A zstd chunk is one frame with
the content size in its header, the checksum on (release skips
checking it; the debug build checks it, knob `zstd_verify`), no dictionary and a window of at most 256 KiB (the decoder's
limit). Indexes with 64 KiB chunks (chunk_shift 16, older test builds)
fail to mount; repack them.

## Volume file

The 64-byte header: magic `AMPRZDT1` (8), u32 version = 1, u32 header size
= 64, u32 volume id, u32 volume_count, [16] archive_id, u64 payload bytes
(volume size less 64), [12] reserved 0, and at 60 a u32 CRC of the header
with that field zeroed. Chunks follow from offset 64 without padding, in
index order (files in record order, chunks in file order), filling each
volume to its recorded size. A file may continue in the next volume.

## Parallel reads

Each chunk has its own frame and absolute offset, found in O(1).
Contiguous chunks are one byte range in one volume, so a batch is one
pread whose chunks the decode workers decode in parallel. The pread is
exact-size: it covers the chunks' stored bytes, not rounded to pages, and
never past the volume's end. Read bytes are not cached; decoded chunks go
to the decoded cache, the rest of the runtime pool (32 MiB release at
the mount, then grown into the Index ledger's idle room once the index is
built: 103 MiB debug on a title using 5.6 MiB of Index). A game read spanning several chunks is split
into chunk-aligned child jobs (`rt/pack/pack_split.rs`).

## What is packed

The builder (ps5-dump-forge) picks the packed files. Always loose, since
the system loads executables and modules itself: `eboot.bin`, `*.elf`,
`*.self`, `*.prx`, `*.sprx`, `sce_sys/`, `sce_module/`, `fakelib*/`, and
`ampr_zstd.index`, `ampr_zstd-*.pak` and `ampr_emu.index`. Forge's
built-in strategy also keeps loose the files a game reads with plain file
calls. Each 256 KiB chunk is compressed at the chosen level (1..=22,
default 5) and stored raw if the frame is not smaller. A file saving less
than 1% (`stored * 100 > size * 99`) is stored raw whole (store-only).

`[pack] default_action = "compress"` packs everything outside the
always-loose list, and the runtime serves such a game. The
hooks below serve zstd and LZ4 packs alike (the knobs keep their zstd
names) and install only when the zstd index or the LZ4 manifest is in
`/app0`; a title without packs keeps the v0.2.0 hook set (`hook_enabled`,
`rt/hook.rs`). Served:

- `open`/`read`/`pread`/`readv`/`preadv`/`lseek`/`fstat`/`close`, `stat`,
  `getdents`/`getdirentries` and their `sceKernel*` forms on virtual pack
  fds and indexed directories.
- Virtual pack fds are synthetic numbers `448 + slot` in `448..768` (320
  slots), with no kernel descriptor behind them, so the title keeps its
  whole fd table. The kernel table tops out at 259 on two measured titles
  (248 `open("/dev/null")` calls succeeded, highest fd 258, despite
  `RLIMIT_NOFILE` 13,952). One title rejects fd >= 1024 (base 1000 failed
  at fd 1024; 768 and 512 boot); another accepted 170 packed fds at
  1024..1193. Holding a `/dev/null` fd per packed fd, as an earlier design did,
  left one title ~49 of 259 descriptors, and its own `/dev/urandom`, ACM
  device and save opens failed with EMFILE. Closed slots are reused:
  320 packed files can be open at once, including up to 45 held by the APR
  fd cache (`rt/fd_cache.rs`). A retail title holds at most 259 handles of
  any kind, so 259 plus the 45 cached ones is 304 at worst; the most seen
  open at once was 220.
- Virtual directory fds are plain numbers `768 + slot` in `768..1024` (256
  slots), above the packed range and under the same 1024 limit. They were
  tagged values near 1.7 billion before. A number has no generation, so a
  closed slot's number is reused like a kernel fd, and a number with no open
  slot goes to the kernel. AIO submit and group ids stay tagged: a submit id
  never passes a title's fd check.
- A read-only open of an indexed directory, with or without
  `O_DIRECTORY`, gets the virtual directory. One packed install opened
  `/app0/input/` 8 times with flags 0, got ENOENT before this, and loaded
  no input map. A directory that exists on disk keeps its own fd and
  entries.
- libc stdio and dirent (`fopen`, `fread`, `opendir`, ...) through the
  libkernel internal-entry hooks `_open` .. `sceKernelFcntl`, all on by
  default (Makefile `AMPR_PACK_LIBC_HOOKS = 0xfff`).
- Not served: `mmap`/`sceKernelMmap` of a packed file fails (below).
- The game's own kernel AIO (`sceKernelAioSubmitReadCommands*`, poll,
  wait, delete, cancel) on a packed file, by the runtime's AIO emulation
  (`rt/pack/aio.rs`, `rt/pack/aio_wait.rs`); other fds go to the kernel.
  The debug build lists these submits in `/fsfail` (op `I`, once per
  file).

## Measurements

Three fully packed zstd games ran on a console with release and debug
builds (boot, video, load, save, play) with 0 errors. Two fully packed LZ4
games (UE3, UE5) ran on an earlier debug build (128 MiB pool, 32 MiB
physical + 16 MiB decoded caches) and play and save with 0 job, decode or
address errors; see README.md [Performance](../README.md#performance).
Debug `/metrics` for the zstd games, with the profile above, on a build
before the 16 MiB decoded cache:

| Engine | Install | Level | Run | Wait/read | Pack job | Disk read |
|---|---|---|---|---|---|---|
| RE Engine | folder | 5 | 18 min | 1.72 ms | 1.42 ms | 0.49 ms |
| UE5 | folder | 5 | 102 s | 1.82 ms | 1.54 ms | 0.81 ms |
| UE5 | .exfat image | 5 | 103 s | 3.84 ms | 3.11 ms | 2.59 ms |
| Northlight | folder | 1 | 216 s | 8.68 ms | 6.50 ms | 1.46 ms |

On the earlier build (debug, 128 MiB pool, 32 + 16 MiB caches, folder
installs, about 75 s after launch) a REDengine title read through virtual
fds: pack job 0.36 ms, disk read 0.47 ms, 59.6% decoded cache hits, pool
peak 95.6 of 128 MiB, 7.6 MiB index. An RE Engine title through APR: wait
per read 1.35 ms, pack job 1.11 ms, disk read 0.50 ms, 20.9% decoded cache
hits, pool peak 90.7 MiB, 2.6 MiB index. Those index sizes are from
before the compiled index view; no console run has measured index memory
since.

The RE Engine title is 90.6 GB unpacked, 38.4 GB packed, served 85.6 GB
from 41.5 GB of disk reads. The .exfat image mount caps at about
350 MB/s. The Northlight title opened 371 virtual fds and has no unpacked
baseline.

## mmap of packed files

A packed file has no physical copy, so mmap of its virtual fd fails.
The runtime does not serve it: no measured game mmapped a packed file
(`mmap_virtual` 0 on three fully packed games). The release build does
not hook mmap; the debug build installs mmap and `sceKernelMmap` (ids 96
and 97) as pass-through probes that log such a map in `/fsfail` (op `X`
or `Y`, lookup `v`) and count it in `mmap_virtual` (`rt/probe.rs`).

Both earlier fixes are removed: decode on access (zstd packed files
decoded in a SIGSEGV/SIGBUS handler on first touch; munmap hooks ids 98
and 99, unused since) and the disk cache (`AMPR_PACK_MMAP=2`, a decoded
copy under `/data/ampr_cache`, ids 96 and 97 in release). The Makefile
refuses `AMPR_PACK_MMAP`. module_start in every title removes a
`/data/ampr_cache` an older build left (`remove_old_cache_dir` in
`rt/pack/mod.rs`); when the folder does not open it does nothing more.
