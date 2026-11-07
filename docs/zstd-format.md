# zstd packs (ampr_zstd.index + ampr_zstd-NNN.pak)

The ampr-emu-ng zstd pack format is an `AMPRZPK1` index plus `AMPRZDT1`
volumes. It is a general container of its own, separate from AMPRPAK4.
[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds the packs
and this repo only decodes them: `crates/ampr-zstd` (constants, layout, volume header) and
`crates/ampr-format/src/zstd.rs` (index reader) hold the format, and
the runtime (`crates/ampr-sys`) mounts it. The same runtime also reads LZ4
(AMPRPAK4) packs and picks the format at load by whether
`/app0/ampr_zstd.index` exists.

All integers are little-endian. CRC means CRC-32 (IEEE, as in `crc32fast`).
The path hash is FNV-1a 64 (basis 14695981039346656037, prime
1099511628211) over the UTF-8 path relative to the game root, with `/`
separators, no leading slash and case kept (for example `data/level1.bin`).

## Files on disk

- `ampr_zstd.index` is the index of the whole archive, loose at the game
  root.
- `ampr_zstd-000.pak`, `ampr_zstd-001.pak`, ... are the volumes, numbered
  with at least three digits (more past 999), like LZ4's
  `ampr_assets-NNN.pak`. Volume id 0 is `ampr_zstd-000.pak`. A volume file
  is at most 4 GiB less 64 KiB (4,294,901,760 bytes, the same as the LZ4
  packs), header included. That keeps every chunk offset below 2^32 (the
  u32 chunk offset) and every volume under FAT32's 4 GiB file limit. The
  number of volumes does not affect read speed (23 fd-budget waits in a
  whole session).
- `ampr_emu.index` (AMPRIDX3) stays as the dump tooling writes it. It lists
  every game file, loose and packed, so AMPR path ids keep working.

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
| 16 | u32 | first_chunk: the chunks of all earlier records (chunk_count = ceil(size / 256 KiB), 0 for an empty file) |
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
chunk has a stored_size equal to that. A zstd chunk is strictly smaller,
because the pack builder stores a chunk raw when zstd does not shrink it, so
stored_size never exceeds the raw size. A zstd chunk is exactly one zstd
frame with the content size in the frame header, the frame checksum on, no
dictionary and a window of at most 256 KiB (the runtime decoder's limit).
The packer writes the checksum; the runtime skips verifying it for speed.

Indexes written with 64 KiB chunks (chunk_shift 16, from older test builds)
keep version 1 but fail to mount. Repack them.

## Volume file

The header is 64 bytes: magic `AMPRZDT1` (8), u32 version = 1, u32 header
size = 64, u32 volume id, u32 volume_count, [16] archive_id, u64 payload
bytes, [12] reserved 0, and at 60 a u32 CRC of the header with that field
zeroed. Chunks follow from offset 64, back to back with no padding, in index
order: files in file-record order, chunks in file order. A file may
continue in the next volume.

## Parallel reads

Every chunk is independent: it has its own frame and an absolute offset, and
the index finds it in O(1). Readers split a chunk range into batches.
Contiguous chunks are a contiguous byte range in one volume, so a batch is
one large pread, after which the runtime's decode workers decode the chunks
in parallel.

## What is packed

The pack builder (ps5-dump-forge) decides which files go into the pack.
These always stay loose: `eboot.bin`, `*.elf`, `*.self`, `*.prx`, `*.sprx`,
`sce_sys/`, `sce_module/`, `fakelib*/`, and the pack's own
`ampr_zstd.index`, `ampr_zstd-*.pak` and `ampr_emu.index`. The system loads
executables and modules itself, outside the runtime. Forge's built-in
strategy also keeps the files a game reads with plain file calls loose.

Per file, the builder compresses every 256 KiB chunk with zstd at the chosen
level (1..=22, default 5) and stores raw any chunk whose frame is not
smaller than the raw data. If a file's stored bytes save less than 1% of its
size (`stored * 100 > size * 99`), the whole file is stored raw
(store-only).

A profile with `[pack] default_action = "compress"` packs every file outside
the always-loose list, and the runtime serves such a fully packed game. The
hooks below install for zstd and LZ4 (`AMPRPAK4`) packs alike, so a plain
open of a packed file gets a virtual fd in either format; the knobs keep
their zstd names. They install only in a title that ships packs (the zstd
index or the LZ4 manifest is in `/app0`); a title with no packs gets the
v0.2.0 hook set (`hook_enabled` in `crates/ampr-sys/src/rt/hook.rs`). For a
fully packed game the runtime serves:

- plain `open`/`read`/`pread`/`readv`/`preadv`/`lseek`/`fstat`/`close`,
  `stat`, `getdents`/`getdirentries` and their `sceKernel*` forms on
  virtual pack fds and indexed directories;
- a virtual pack fd is a synthetic number in `512..1024` (`512 + slot`, 512
  slots), not a kernel descriptor. The range is above the kernel's effective
  fd table (259 measured on PPSA03671 and PPSA30601: 248 `open("/dev/null")`
  calls succeeded, highest fd 258, despite `RLIMIT_NOFILE` 13,952) and below
  the strictest title limit: PPSA30601 rejects fd >= 1024 (base 1000 failed
  on `CHARACTERS_STRUCTURE.PS5.PCK` at fd 1024, while base 768 and 512 boot),
  and PPSA03671 accepted 170 packed fds at 1024..1193. Because no kernel
  descriptor is used, the title keeps its whole fd table for real files; a
  previous design reserved one `/dev/null` descriptor per packed fd, which
  left PPSA03671 only ~49 of its 259 descriptors and made its own
  `/dev/urandom`, ACM device and save opens fail with EMFILE. A closed slot
  is reused, so the slot count is the number of packed files open at once
  (512, shared with the runtime's cached packed opens in `rt/fd_cache.rs`),
  not a lifetime limit. The runtime serves reads, seeks, fstat, close, AIO
  and mmap on the synthetic number;
- a read-only open of an indexed directory, with or without `O_DIRECTORY`,
  gets the virtual directory. The kernel accepts a read-only open of a
  directory, and a title that scans a packed directory can pass plain
  read-only flags: a measured packed install opened `/app0/input/` 8 times
  with flags 0 and got ENOENT before this, and loaded no input map. A
  physical directory that really exists (a folder install) keeps its own
  fd and entries;
- libc stdio and dirent (`fopen`, `fread`, `opendir`, ...) through the
  libkernel internal-entry hooks `_open` .. `sceKernelFcntl`, all routing
  by default (Makefile `AMPR_ZSTD_LIBC_HOOKS = 0xfff`);
- `mmap`/`sceKernelMmap`, through the disk cache or decoded on access (see
  below).

The game's own kernel AIO (`sceKernelAioSubmitReadCommands*`) on a packed
file is not served. The debug build only logs it (`rt/probe.rs`, `/fsfail`).

Three fully packed zstd games were tested on a console with release and
debug builds: boot, video, load, save and play, with 0 errors. Two fully
packed LZ4 games (a UE3 and a UE5 title) were tested with the debug build
and the current cache defaults (16 MiB decoded cache) on the 128 MiB
release pool size: both play
and save with 0 job, decode or address errors; README.md
[Performance](../README.md#performance) has their numbers. The debug build's
`/metrics` gave these numbers for the zstd games, with the profile above and
an earlier build (before the 16 MiB decoded cache):

| Engine | Install | Level | Run | Wait/read | Pack job | Disk read |
|---|---|---|---|---|---|---|
| RE Engine | folder | 5 | 18 min | 1.72 ms | 1.42 ms | 0.49 ms |
| UE5 | folder | 5 | 102 s | 1.82 ms | 1.54 ms | 0.81 ms |
| UE5 | .exfat image | 5 | 103 s | 3.84 ms | 3.11 ms | 2.59 ms |
| Northlight | folder | 1 | 216 s | 8.68 ms | 6.50 ms | 1.46 ms |

With the current cache defaults (debug build with the 128 MiB release
pool, folder installs, `/metrics` about 75 s after launch), a REDengine title read through virtual fds: pack job
0.36 ms, disk read 0.47 ms, 59.6% decoded cache hits, pool peak 95.6 MiB of
128 MiB with a 7.6 MiB index. An RE Engine title read through APR: game
wait per read 1.35 ms, pack job 1.11 ms, disk read 0.50 ms, 20.9% decoded
cache hits, pool peak 90.7 MiB with a 2.6 MiB index.

The RE Engine title takes 90.6 GB on disk unpacked and 38.4 GB packed, and
it was served 85.6 GB from 41.5 GB of disk reads. The .exfat image mount
caps at about 350 MB/s. The Northlight title opened 371 virtual fds and has
no unpacked baseline.

## mmap of packed files

A packed file has no physical copy, so `mmap`/`sceKernelMmap` of its
virtual fd would fail on its own. The Makefile knob `AMPR_ZSTD_MMAP` picks
how the runtime serves it; 0 leaves the call unhooked. A map with MAP_ANON
set, or of any other fd, goes to the original unchanged. A packed file is
read-only, so at 1 and 2 a MAP_SHARED map of it with PROT_WRITE fails with
EACCES, as it would for any O_RDONLY fd.

At 2, the default and the value used when the variable is absent, the
runtime uses a disk cache. On the first map of a packed file it decodes the
whole file once, inside that mmap call and under one lock, into a temp file
under `/data/ampr_cache`, in 256 KiB pieces. That needs as much free space on
`/data` as the file's decoded size. The runtime then unlinks the temp file,
keeps its fd open and maps it with the caller's arguments. Later maps of the
same file reuse that fd. Up to 64 cache files stay open at once; mapping a
65th closes the oldest, whose data lives on while it is still mapped, and a
later map of that file decodes it again. Because this is a kernel file
mapping, mprotect, write faults and thread stacks behave as they do for any
file. The only memory it takes is one transient 256 KiB pool buffer while
the file is written. The disk cache serves LZ4 packed files too. The
directory is emptied at module_start while `AMPR_ZSTD_MMAP` is not 0, in a
title with packs of either format (`select_pack_format` in
`crates/ampr-sys/src/rt/pack/mod.rs`, `crates/ampr-sys/src/rt/pack/mmap.rs`).

At 1, which is opt-in and has not run on a console, a map of a zstd packed
file is served by decode on access; a map of an LZ4 packed file takes the
disk cache, since the fault path reads zstd chunk records. The range is
reserved as anonymous PROT_NONE memory and nothing is decoded until a page
is touched. A SIGSEGV/SIGBUS handler then reads the 256 KiB chunks behind the
faulting page, decodes them and opens their pages with the caller's prot
(`crates/ampr-sys/src/rt/pack/mmap_fault.rs`). A page partly past the end of
the file opens with a zero tail. A fault on a page wholly past the end goes
to the previous handler, as SIGBUS would for a real file mapping. Maps the
fault path cannot serve (GPU prot, an offset not 4 KiB aligned, a full
mapping table, or no sigaction) take the disk cache instead. None of the
three measured games mmapped a packed file (`mmap_virtual` 0), so this path
has never served a game. It adds 2 MiB of persistent pool scratch. A
disallowed access, such as a write or exec on an open page, retries once
and then goes to the previous handler.

These limits are not solved: a syscall given an untouched page gets EFAULT,
mprotect on the range is not tracked, the handler runs on the faulting
thread's stack, ranges replaced by VM calls the runtime does not hook stay
registered, and the handler stays installed after module_stop.

## Runtime

`./ps5/build-docker.sh` builds `libSceAmpr.sprx` from `crates/ampr-sys`.
When `/app0/ampr_zstd.index` is present, that build mounts it in place of
`ampr_assets.index`, opens the `ampr_zstd-NNN.pak` volumes, decodes zstd
(libzstd, `ampr-codec`), and serves AMPR/APR reads plus the plain file
calls listed under What is packed.
