# zstd packs (ampr_zstd.index + ampr_zstd-NNN.pak)

ampr-emu-ng zstd packs are an `AMPRZPK1` index plus `AMPRZDT1` volumes,
separate from AMPRPAK4.
[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds them;
this repo only decodes them (`crates/ampr-zstd`: constants, layout, volume
header; `crates/ampr-format/src/zstd.rs`: index reader). When
`/app0/ampr_zstd.index` exists, `libSceAmpr.sprx` mounts it instead of the
LZ4 `ampr_assets.index`, decodes with libzstd (`ampr-codec`) and serves
AMPR/APR reads and the file calls under What is packed. An index file
that fits the Index ledger (64 MiB, `rt/index_memory.rs`) with its tables
is read whole and used as is. A larger one is read on demand through a
page cache of 16 KiB pages (an arena of at least 16 MiB, shared with the
LZ4 manifest and `ampr_emu.index`; `crates/ampr-sys/src/rt/index_pages.rs`)
and gets a fast table, one sequential pass at mount: the file hashes and
logical sizes, every chunk record and the volume sizes, 8 B each (16 B
per file), held in memory, so lookups read only the path of a record
whose hash matches and read jobs read no index pages (a job takes the
chunk span from the projection and the size from the fast table). The fast table and the tables built from the index
(projection 16 B per AMPRIDX3 id, order 4 B per packed file) count
against 48 MiB of lookup tables (`INDEX_LOOKUP_MAX`); a paged index whose
tables do not fit is not served. The loader refuses an index file over
512 MiB (`AMPR_EMU_PACK_INDEX_MAX_BYTES`, `rt/pack/mod.rs`): that bounds
its page table (2 B per 16 KiB page) and the full CRC read at mount for a
corrupt file.
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
pread whose chunks the decode workers decode in parallel. A game read
spanning several chunks is split into chunk-aligned child jobs
(`rt/pack/zstd_split.rs`).

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
- Virtual pack fds are synthetic numbers `512 + slot` in `512..1024` (512
  slots), with no kernel descriptor behind them, so the title keeps its
  whole fd table. The kernel table tops out at 259 on two measured titles
  (248 `open("/dev/null")` calls succeeded, highest fd 258, despite
  `RLIMIT_NOFILE` 13,952). One title rejects fd >= 1024 (base 1000 failed
  at fd 1024; 768 and 512 boot); another accepted 170 packed fds at
  1024..1193. Holding a `/dev/null` fd per packed fd, as an earlier design did,
  left one title ~49 of 259 descriptors, and its own `/dev/urandom`, ACM
  device and save opens failed with EMFILE. Closed slots are reused:
  512 packed files can be open at once, including up to 45 held by the APR
  fd cache (`rt/fd_cache.rs`).
- A read-only open of an indexed directory, with or without
  `O_DIRECTORY`, gets the virtual directory. One packed install opened
  `/app0/input/` 8 times with flags 0, got ENOENT before this, and loaded
  no input map. A directory that exists on disk keeps its own fd and
  entries.
- libc stdio and dirent (`fopen`, `fread`, `opendir`, ...) through the
  libkernel internal-entry hooks `_open` .. `sceKernelFcntl`, all on by
  default (Makefile `AMPR_ZSTD_LIBC_HOOKS = 0xfff`).
- `mmap`/`sceKernelMmap` (below).
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
hits, pool peak 90.7 MiB, 2.6 MiB index.

The RE Engine title is 90.6 GB unpacked, 38.4 GB packed, served 85.6 GB
from 41.5 GB of disk reads. The .exfat image mount caps at about
350 MB/s. The Northlight title opened 371 virtual fds and has no unpacked
baseline.

## mmap of packed files

A packed file has no physical copy, so mmap of its virtual fd fails on
its own. Makefile `AMPR_ZSTD_MMAP` picks the fix; 0 leaves the call
unhooked. MAP_ANON maps and other fds go to the original. At 1 and 2 a
MAP_SHARED map with PROT_WRITE fails with EACCES, as for any O_RDONLY fd.

2 (default, also when the variable is absent): disk cache, for zstd and
LZ4 packs. The first map decodes the whole file once, inside that mmap
call and under one lock, in 256 KiB pieces into a temp file under
`/data/ampr_cache` (`/data` needs the decoded size free). The file is
unlinked, its fd kept, and a dup of it mapped with the caller's arguments;
later maps reuse it. Up to 64 cache files stay open; a 65th closes the
oldest, whose data lives while mapped, and a later map decodes it again.
mprotect, write faults and thread stacks behave as for any file mapping.
Memory: one transient 256 KiB pool buffer per write. The
directory is emptied at module_start when the knob is not 0 in a title
with packs (`select_pack_format`, `rt/pack/mod.rs`; `rt/pack/mmap.rs`).

1 (opt-in, never run on a console): zstd packed files decode on access;
LZ4 ones take the disk cache, since the fault path reads zstd chunk
records. The range is reserved PROT_NONE and nothing decodes until a page
is touched. A SIGSEGV/SIGBUS handler then decodes the 256 KiB chunks
behind the page and opens it with the caller's prot
(`rt/pack/mmap_fault.rs`). A page partly past EOF gets a zero tail; a
fault wholly past EOF goes to the previous handler, as SIGBUS would. A
write or exec on an open page retries once, then goes to the previous
handler. The disk cache takes maps this path cannot serve: GPU prot, an
offset not 4 KiB aligned, more volumes than its volume fds, a full table,
over 512 MiB, or no sigaction. No measured game mmapped a packed file
(`mmap_virtual` 0), so it has never served one. Cost: 2 MiB of Index
ledger scratch (4 x 512 KiB), 4 x 112 KiB decoder workspaces in the Buffer ledger, one pool
byte per mapped chunk. Unsolved: a syscall given an untouched page gets
EFAULT, mprotect on the range is not tracked, the handler runs on the
faulting thread's stack, ranges replaced by unhooked VM calls stay
registered, and the handler stays installed after module_stop.
