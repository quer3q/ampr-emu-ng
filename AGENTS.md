# AGENTS.md

Notes for coding agents working on ampr-emu-ng (version 0.5.0, GPL-3.0-or-later).

## Project

ampr-emu-ng is a `no_std` Rust rewrite of drakmor/ampr_emu: the PS5 fakelib
`libSceAmpr.sprx`, which emulates the AMPR/APR file APIs for games run from
dumps. One runtime has four modes (`PackFormat` in
`crates/ampr-sys/src/rt/pack/mod.rs`), picked once at module_start by
`select_pack_format` in this order: pkg when `/app0/kraken.image` (one
line from the launcher: the .pkg path relative to /app0, e.g.
`kraken/x.pkg`; the launcher mounts the .pkg's folder read-only at
`/app0/kraken/`) names a regular file whose size, aligned to pack 0's
page, is pack 0's `file_size` in the manifest (no title id, name or mtime
match); zstd packs
(`AMPRZPK1` index, `AMPRZDT1` volumes) when `/app0/ampr_zstd.index`
exists; LZ4 packs (`AMPRPAK4`) when `/app0/ampr_assets.index` exists;
plain (no packs) otherwise. Pkg shares the `AMPRPAK4` manifest format,
read planner, caches and pipelines with LZ4 and reads pack 0 straight from
the .pkg; pkg-specific steps dispatch to `rt/pack/pkg.rs`. A
kraken.image path that is absolute or has an empty, `.` or `..` component
(`safe_components`) is refused; it is
trimmed at the first `\n` or `\r`. A writable /app0 is
separate and applies to any title: when `access("/app0", W_OK)` succeeds at
module_start (libkernel has no statfs), no index miss is authoritative,
loose hits answer from the filesystem, `access(W_OK)` returns 0 on a
directory and EROFS on a packed file, and a miss under an indexed
directory uses that directory's indexed spelling, a creating open first
making it if it exists only in the pack (`rt/rw.rs`, docs/writable-app0.md).
Files a game writes are never packed, so packed files stay read-only.
Every such change is gated on `app0_writable()`; a read-only /app0
behaves as upstream. The exception: an APR resolve of a loose file stats
it in every mode (`live_loose_resolve` in `rt/index.rs`), so a file the
index lists but the disk lacks resolves to ENOENT, not an id whose read
fails (a zstd title on a read-only exFAT image aborted on that read; the
image answered `access("/app0", W_OK)` with EPERM, not EROFS).

## Layout

- `crates/ampr-sys`: PRX runtime (staticlib). Runtime code is in `src/rt/`
  (pack, reactor, hooks, stats, tune, exports). The PRX exports 137 symbols:
  118 sceAmpr* (`rt/exports.rs`, found by `EXPORT_RE`) and 19 libc/libc++
  symbols that retail libSceAmpr re-exports (`rt/libc_exports.rs`, listed in
  `EXTRA_EXPORTS` in `tools/generate_payload_exports.py`).
- `crates/ampr-format`: shared index readers, byte helpers, overlay utilities
  and the exact-read run planner (`src/run.rs`). Its CRC-32 is `crc32fast`
  (pinned, `default-features = false`), already linked for ampr-zstd.
- `crates/ampr-codec`: zstd decode.
- `crates/ampr-lz4`: AMPRPAK4 manifest, AMPRDAT3 header, read planning and LZ4 decode.
- `crates/ampr-command`, `ampr-hook`: APR command encoding and x86 hook decoding.
- `crates/ampr-zstd`: zstd pack format, decode side only (`no_std`).
- `crates/ampr-pkg`: pkg mode, a new format that depends on `ampr-lz4`, which
  stays as upstream: the `kraken.image` path and .pkg size checks, the
  manifest rules `open_pkg` and chunk split `pkg_chunk`, .pkg volume size
  and the KRAKEN chunk descriptor. Runtime glue in `rt/pack/pkg.rs`. Keep
  pkg-only logic in these two; format-neutral logic goes to
  `ampr-format` or the runtime.
  Its `kraken` module (`src/kraken/`) is the KRAKEN block decoder, to be
  replaced; the only `unsafe` code in the crate is there.
- Index view: every title, packed or not, answers path lookups from one
  compiled index view built from its AMPRIDX3 index. `ampr-format`
  holds the format side: `src/view.rs` builds the per-file rows (32 B),
  the zstd chunk column, hash slots and directory records into caller
  memory and looks keys up, hashing with `view_hash` (8 bytes a step, not
  the byte-serial FNV `idx_path_hash` that AMPRIDX3 and AMPRPAK4 store),
  `src/view_join.rs` joins a zstd or AMPRPAK4 pack index to it at mount
  by hash, and `src/view_list.rs` lists packed directories from it. The
  runtime side is `rt/index_view.rs` (the view's Index ledger blocks and
  the build retry on directory capacity) and `rt/index_file.rs` (the
  sources the build and later path reads go through: windows over the
  index file, the kept fd, or the walk-built path blob).
- `ps5/`: Dockerfile, `build-docker.sh`, target spec, PRX linker script.
- `tools/`: Python PRX post-processing and `verify_payload_prx.py`.
- `docs/zstd-format.md`: the zstd pack format. Keep it in sync with
  `crates/ampr-zstd` and `crates/ampr-format/src/zstd.rs`.
- `docs/writable-app0.md`: writable /app0. Keep it in sync with
  `rt/rw.rs` and the routing in `rt/index.rs`.
- `docs/debug-build.md`: the debug build (metrics server, tune file, op
  letters, black box).

## Build and test

```sh
cargo test --workspace                         # host tests
./ps5/build-docker.sh                          # make dist: release + debug .sprx, verified
./ps5/build-docker.sh verify                   # release build + verifier only
./ps5/build-docker.sh dist AMPR_PACK_WORKERS=8 # override a Makefile knob
./ps5/build-docker.sh clean                    # remove out/
```

Knobs and their defaults are at the top of the `Makefile`
(`AMPR_INTERNAL_POOL_SIZE`, `AMPR_DEBUG_POOL_SIZE`, `AMPR_PACK_WORKERS`,
`AMPR_PACK_PIPELINES`, `AMPR_PACK_LIBC_HOOKS`, `AMPR_MEM_REPORT`). A knob
change rebuilds through `out/*/obj/build-config.txt`. The Makefile refuses
`AMPR_PACK_MMAP` (removed with the mmap disk cache) and the old
`AMPR_ZSTD_*` names. `AMPR_PACK_LIBC_HOOKS` (formerly
`AMPR_ZSTD_LIBC_HOOKS`) applies to
every pack format, as do `rt/pack/pack_libc.rs` and `rt/pack/pack_split.rs`
(formerly `zstd_*`); zstd names stay on zstd-only code. Hook ids 55..=63
(the removed equeue queue classification, `UNUSED_EQUEUE_IDS`) and 98 and
99 (munmap) are unused and never install; ids 96 and 97 (mmap,
sceKernelMmap) install only in the debug build, as pass-through probes;
the ids are not renumbered. Those hooks (hook ids 78 and up) and the pack
manifest load apply only to a title that ships packs, zstd, LZ4 or pkg
(`packs_present` in `rt/pack/mod.rs`, `hook_enabled` in `rt/hook.rs`); a
title with no packs gets the shared ids 0..=77 less 55..=63. A shipped
`ampr_emu.index` loads at module_start in every title, and module_start
removes a `/data/ampr_cache` an older build left (`remove_old_cache_dir`;
one failed open when it is absent). Among the pack hooks,
ids 100..=109 route the game's own kernel AIO (`sceKernelAioSubmitReadCommands*`,
poll, wait, delete, cancel) to the runtime's AIO emulation
(`rt/pack/aio.rs`, `rt/pack/aio_wait.rs`); the runtime's own native AIO
calls the pre-detour slot (`real_aio_*` in `rt/pack/libkernel.rs`), never
the symbol by name, which would re-enter the hook. The exception is ids
110..=111 (`scePthreadCreate`, `pthread_create`, `rt/thread_hooks.rs`):
they install in every title, packs or not. A game thread creation that
fails with EAGAIN makes the runtime give threads back and is retried; the
runtime-wide budget of 16 worker threads is cut and regrows by one per
5 s quiet. The groups are capped at 4 decode workers (`AMPR_PACK_WORKERS`;
an LZ4 or pkg title's `ampr_assets.index.runtime` profile can ask for up to 16,
`AMPR_EMU_PACK_WORKER_CAPACITY`; the worker start cuts workers until
each has a pipeline in the Buffer ledger, 9 and 9 at 16, `buffer_split`
in `rt/pack/worker.rs`),
and 6 disk read threads (`tune::RELEASE_PREAD_THREADS`). A packed POSIX
read (read, pread, readv, preadv, libc `_read`/`_readv` on a virtual pack
fd) queues its pack jobs and waits on the caller's own thread
(`read_on_workers` in `rt/pack/fd_read.rs`); there are no fd read threads.
A pack worker queues its window read to the pread pool itself
(`queue_pack_pread` in `rt/reactor/pread_pool.rs`) and the pool thread
requeues the job; the reactor only sees pack reads the pool refuses. Lock
order: PACK_M before preadMutex and the pool's `m`, never the reverse.
Runtime threads are not created under PACK_M or on the reactor thread for
pack work, with two exceptions: the first decode worker of a mount starts
under PACK_M (once per mount), and loose-read pool growth runs on the
reactor thread, the only thread free to start one when every pool thread
is busy.
Runtime threads run on 16 KiB-page stacks carved from one 2 MiB pool block
(`rt/thread_stack.rs`), each with a no-access 16 KiB guard page below it,
up to 128 KiB a stack; the slot is freed after `scePthreadJoin` (a wrapper
in `rt/reactor/mod.rs`). A larger stack, a full block or a missing or
refused `scePthreadAttrSetstack` falls back to libkernel's stack.
A runtime thread, once started, stays: threads start when work queues,
up to the group caps (reactor, 4 decode workers, 6 pool threads: 11, 12
with the debug metrics thread), and leave only under pressure (load
retirement was removed, see "Removed"). That EAGAIN starts pressure mode: idle threads leave at once, each group runs at most
one thread while it has work and none without (decode workers never go
below one, `LoadGroup::floor`), until 5 s pass with no new failure
(`LoadGroup`, `pressure` in `rt/thread_hooks.rs`). A failed
`scePthreadJoin` of a pool thread or decode worker frees its slot (a
retry could join a reused handle) and leaves its pool stack reserved
(debug `thread_join_failed`). The idle spin
(`spin_us`, decode workers and pool threads) is 100 us in release
(`SPIN_US_DEFAULT`, was 0): on a pkg title game wait per read fell
2,427-2,492 to 2,268 us and on a zstd title 327 to 316 us, workers
picking up a queued job 25-47% sooner, and both played much smoother
(one run each, debug /metrics; its CPU cost is not measured). Pool
threads run at the decode workers' priority and cores (384, CPUs 0-5,
`rt/pack/mod.rs`), below the reactor's 256 (they ran at 256 before;
`rt/reactor/pread_pool.rs`). Ids 96 and 97 (mmap)
and 112..=119 (dup, dup2, poll, select, openat, fstatat, faccessat,
readlink) exist only in the debug build, as pass-through probes in titles
with packs (`rt/probe.rs`).
Pkg mode and a writable /app0 add no hook ids; the hook ids are as
upstream. The
runtime creates its own threads through `create_internal`
(the pre-detour slot). Save data (`rt/save.rs`) is hooked by NID in a
loaded `libSceSaveData` module, not through the libkernel table, in every
title (the loader observer finds it outside `sceKernelGetModuleList`), 4
hooks: `sceSaveDataSaveIconByPath` hands a packed icon to
`sceSaveDataSaveIcon` as bytes in a game libc heap buffer of its size,
freed after the call (the save service cannot open a packed path, and a
path to a decoded copy under /data/ampr_cache hung the service call);
`sceSaveDataMount3` answers a BUSY mount of a directory the game already
has mounted with that mount's point (same blocks and systemBlocks, and
never a read-only point to a mount that writes), and
`sceSaveDataUmount2` counts its owners, so only the last owner's unmount reaches the service. An
interrupted save left a slot the game kept mounted and mounted again: BUSY
there hung the load forever when passed back, and unmounting the game's
other points instead made another title hang on close. A creating
`sceSaveDataMount3` the library refuses (0x809F0000) with a nonzero
systemBlocks is sent once more with systemBlocks 0: below SDK 5.00 the
library takes only 0, and a title backported to 4.xx still passes the -1
of its own SDK, so it never saved. Every other mount and unmount passes
through. The debug build adds pass-through probes on 13
more save and dialog calls (`probe` in `rt/save.rs`, `fs V` lines).
CI (`.github/workflows/build.yml`) runs the same commands; a pushed `v*` tag creates a draft release with both `.sprx` and `SHA256SUMS`.

## Conventions

- Runtime crates are `no_std` (`ampr-sys` is `no_std` outside tests). Do not
  pull `std` into them.
- No new dependencies without a stated reason. Runtime dependencies use
  `default-features = false`, and `lz4_flex`, `zstd-sys`, `iced-x86` are
  pinned (`=x.y.z`); follow that.
- Memory budget: runtime memory is in the PRX's static .bss pool;
  nothing comes from the game's direct or flexible memory (the pool did not
  lower the game's free direct memory, direct allocations did; flexible
  memory had 0-28 MiB free during play). The Rust global allocator
  (`LibcAlloc` in `lib.rs`, iced-x86 only) takes a 384 KiB bump block in
  the pool (`rt/heap.rs`; iced-x86 peaked at 190,276 B on the host and its
  bump top reached 246,688 B on a console; `realloc` grows or shrinks
  the last block in place) and
  falls back to the game's libc heap only past it (debug `heap_libc_bytes`).
  The one other use of the game's libc heap is a packed save icon
  (`read_packed` in `rt/save.rs`): a buffer of the icon's size for the
  one sceSaveDataSaveIcon call, freed when it returns (551,096 B on one
  title; a failed malloc skips the icon). Keep it to these two; zstd decoders use a static DCtx
  in a pool workspace (`ZstdDecoder::init_in` in `crates/ampr-codec`).
  Ledgers (`rt/index_memory.rs`):
  Index 80 MiB (the compiled index view, the pack index tables kept
  after the mount, the walk build, the 64 KiB build windows), Buffer
  28.44 MiB (4 x 1 MiB decode + 12 x 2 MiB I/O windows + 4 x 112 KiB zstd
  decoder workspaces, one per live zstd worker, taken at its start and
  freed when it retires), and Cache, the rest of the pool
  (`CACHE_MEMORY_MAX` = pool - Index - Buffer - sites budget - stack
  block, rounded down to 16 KiB; 32.00 MiB release, 30.64 MiB debug).
  The cache is one decoded chunk cache carved at the pack mount and carved
  again, still empty, once the index view is finished: the Index cap's idle
  room above 2 MiB (`INDEX_KEPT_ROOM`, 4 MiB before) moves to the Cache cap and the cache
  takes it in one block (`grow_cache_from_index` in `rt/pack/manifest.rs`,
  debug `cache_grown_bytes`; 76-80 MiB more on three titles, 103-107 MiB
  of debug cache in all, debug /metrics). Nothing may allocate from the Index ledger after startup beyond
  that kept room; its two uses are the 64 KiB getdents listing window
  (`take_listing_window` in `rt/pack/directories.rs`, taken once on the
  first listing of a packed directory when names are read from the kept
  fd, and only while 64 KiB of room is left) and the debug /bench buffer.
  The cache holds at most 16384 entries (`AMPR_EMU_PACK_CACHE_ENTRY_CAP`
  in `rt/pack/mod.rs`, 8192 before, 56 B each in .bss outside the pool;
  debug `cache_cap_evictions` counts the evictions the cap forces while
  page room is free). Pack chunks are
  read with exact-size reads, the only read path, and no read pages are
  cached. It keeps a protected segment: the 3rd hit (`cache_protect_hits`)
  protects an entry, and the clock skips protected entries while they hold
  at most 50% of the cache (`cache_protect_pct`), so a scan does not evict
  the hot set; a partial-chunk read is admitted on its first touch, a
  full-chunk read on its second. Outside the ledgers: the 2 MiB thread
  stack block (`STACK_MEMORY_MAX`, `rt/thread_stack.rs`) and a 1.75 MiB
  budget (`POOL_SITES_BUDGET`; 2 MiB before the mmap disk cache's 256 KiB
  piece went to the cache) for the fixed sites listed at
  `STATIC_POOL_SIZE` in `rt/runtime_memory.rs` (1.69 MiB used,
  `POOL_SITES_MAX`, the heap block included; a host
  test fails on a new pool call). A build-time assert checks that the
  caps plus the budget fit the pool. The release pool is the fixed
  caps plus a 32 MiB cache, 144.19 MiB (`AMPR_INTERNAL_POOL_SIZE`
  `0x9030000`), and both PRX builds load to its total, 150.89 MiB (PT_LOAD
  memsz), within a 16 KiB page, with no padding: the debug pool is
  142.83 MiB (`AMPR_DEBUG_POOL_SIZE` `0x8ED4000`), the gap being the debug
  build's larger non-pool part (8.06 vs 6.70 MiB; totals 158,221,826 and
  158,219,474 B, 2,352 B apart, from `dist`). Against the 192 MiB pool it
  lost no game wait per read on three titles (debug /metrics, one run
  each; Makefile comment). `dist` fails when the two totals differ by more than 64 KiB or
  exceed 256 MiB (`PRX_TOTAL_LIMIT` in `tools/verify_payload_prx.py
  --prx-totals`); then recompute the debug pool, (release total - debug
  non-pool) rounded down to 16 KiB, and update the Makefile comment,
  `DEFAULT_POOL_SIZE` and the host test `cache_is_the_pool_remainder`.
  Before: 198.70 MiB totals, pools `0xC000000` and `0xBEA4000`, caches
  79.81 and 78.45 MiB at the mount; 256 MiB totals, pools `0xf948000` and
  `0xf7ec000`, caches 137.09 and 135.73 MiB; before that, 184.44 MiB totals, a 64 MiB
  cache, pools `0xafd4000` and `0xae78000`. A refused allocation degrades
  (index: one notice, packs unserved; cache off). Every I/O window is taken at the
  worker start, after the decode buffers, and the pipeline count is the
  windows granted: there is no slow path for a read without one. A title
  has one compiled index view, built at module_start in one pass over
  `ampr_emu.index` through two 64 KiB windows and kept until shutdown:
  a 32 B row per file (hash, size, mtime, path offset, packed chain;
  one aligned row, so a stat hit touches two cache lines), 4 B more with
  zstd packs (the chunk column), 4 B hash slots at 1.5 to 3 per
  file, 32 B per directory plus its slots, and 4 B per file (12 B with
  LZ4 or pkg packs) of build columns given back after the build
  (`layout` in `rt/index_view.rs`). The pack index is read once at mount
  through two windows, its file closed after, and joined to the view by
  hash, so an open finds a packed file by its view id with no path
  compare. The mount keeps only what reads need: zstd its chunk and
  volume tables (8 B per chunk and per volume); AMPRPAK4 (LZ4 and pkg)
  its header, record sections (48 B per file, 12 B per chunk) and pack
  names (32 B per pack plus the name), plus one mismatch bit per view id
  for records the join refused (`LZ4_IMAGE`, `join_lz4` in
  `rt/pack/manifest.rs`). Measured on the host from a 242,409-file zstd
  index: 21.74 MiB resident (columns 8.32, file slots 2.00, directories
  1.21 allocated, chunk and volume tables 10.22); 80 MiB holds a zstd
  title of about 870,000 files at 5.5 chunks per file (computed). All of
  it is under the one Index cap; an index that does not fit is refused
  with the notice. Paths stay in the index file, on an fd kept open for
  the module's life (`KEPT_FD` in `rt/index.rs`; the close hooks,
  sceKernelClose, close and `_close`, refuse it with EBADF): a hook reads one with a pread on its own thread only
  to confirm a hash hit, never waiting on another thread. A loose hit
  calls the game's own spelling first, and a stat, access or resolve of a
  hit reads no path. A read error is never an authoritative ENOENT
  (`index_lookup_io`). The pack
  index is capped only by the loader's 512 MiB fstat check
  (`AMPR_EMU_PACK_INDEX_MAX_BYTES`; paths must be shorter than 1024
  bytes). A title without `ampr_emu.index` builds its AMPRIDX3 whole in
  the Index ledger (walk build, 104-124 B per file at 48-byte paths),
  writes it and builds the view from the file; when it cannot be
  written, the view is built from the image and its path blob is copied
  into the ledger (`adopt_compact_index` in `rt/index.rs`). Pool peak
  outside the ledgers was 0.56 MiB on a zstd title before the compiled
  index view; no console run has measured it, or a title's index
  memory, since. Pkg and rw mode add .bss statics outside
  the pool, in both builds: `KRAKEN_PKG_PATH` (269 B) and
  two atomics (9 B) in `rt/pack/pkg.rs`, `PACK_FORMAT` (1 B) in
  `rt/pack/mod.rs` and `APP0_WRITABLE` (1 B) in `rt/rw.rs`. The pool
  stacks and heap add `STACKS` in `rt/thread_stack.rs` (24 records and a
  128-bit page map, about 1 KiB, computed) and `HEAP` in `rt/heap.rs`
  (about 48 B). Two .bss tables outside the pool run at a quarter of
  their old size, with no live peak measured yet: the equeue overlay
  (`OV` in `rt/equeue.rs`, `TABLE_BASE` 1024: 1024 queues, 4096
  registrations, 1024 extras, 5120 pending nodes; 376,896 B, was
  1,507,392, host size_of), whose full table leaves a queue or
  registration native, never an error to the game (debug `/queues`
  `eqpeak` prints the live peaks against these caps). A queue is tracked
  from its first `sceKernelAddAmprEvent`, not from its creation; a wait on
  a queue sharing none of 256 buckets with a tracked one goes to the kernel
  without the overlay lock (`bypass_wait`, two 256-entry atomic tables,
  2 KiB of .bss), and a first AMPR add that finds such a waiter wakes its
  queue once through the hidden wake. Tracking stays on: a build without
  ids 50..=54 hung a title's load, its 109,089 completions posted natively
  to one AMPR id (debug `/queues` `eqtarget`); and
  `POOL_COPY` in `rt/hook.rs`, 4 pages (64 KiB, 2048 entries of 32 B, was
  64 pages), past which `sceKernelMemoryPoolBatch` passes the caller's
  array unadjusted. Any change
  that grows runtime memory needs a measurement and an updated Makefile
  comment.
- Comments: plain prose `//!` and `///`, saying why, with the measured numbers
  and the source they come from (e.g. `rt/stats.rs`). Large files group items under
  `// ---- topic ----` section lines; keep that style.
- Naming: the zstd format is "zstd packs" and the project is "ampr-emu-ng".
  Do not use other names for the format or the project in code, docs or
  file names.
- Markdown: ASCII punctuation, no emoji.

## Verifying a change

1. `cargo test --workspace` passes on the host.
2. `./ps5/build-docker.sh verify` (or `dist`) passes; it runs
   `tools/verify_payload_prx.py` on the linked PRX and SPRX, and
   `tools/check_stack_frames.py`, which fails when a hook-path function's
   stack frame passes its budget (hooks run on the game's own small
   stacks; v0.4.0 overflowed a save thread's), and when any function in
   the PRX has a frame of 16 KiB (0x4000) or more, a guard page's size
   (no stack probes). It also sums four chains
   against 0x1000 each: the packed open (0xcc8 release, 0x940 debug), the
   packed POSIX read on the caller's thread (`READ_CHAIN`, 0x720 release,
   0x720 debug), and the save icon's packed read under the icon hook
   (`ICON_READ_CHAIN`, 0xb78 release, 0x7e8 debug), and the module loader
   hook (`LOADER_CHAIN`, `load_resolved` and `observe_loaded` in
   `rt/hook.rs`; 0x640 release, 0x800 debug, was 0xe50 and 0xfe0 before
   the split). A change
   that grows one moves the cold code out of line instead of raising the
   budget.
3. Runtime behavior changes need a run on a console with
   `libSceAmpr-debug.sprx`: read `http://<ps5-ip>:9090/metrics` before and
   after and compare game wait per read, pack job and disk read time
   ([docs/debug-build.md](docs/debug-build.md#comparing-runs-and-installs)).

## Debugging on a console

`docs/debug-build.md` covers the debug build: the pages on port 9090
(`/metrics`, `/set`, `/bench`, `/fsfail`, `/modules`, `/queues`,
`/threads`), the tune file, the op letters and the black box
`/data/ampr_emu_trace.txt`. Keep it in sync with `serve` in
`rt/exports.rs`, `FsEvents` in `rt/stats.rs`, `KNOBS` in `rt/tune.rs` and
`rt/blackbox.rs`. When one install works and another does not, run the
same debug build on both and diff `/fsfail` and `/modules`.

Folder installs on the internal SSD are case-sensitive; retail pfs and
exFAT are not, and games depend on that (e.g. a plugin loaded as
`AkSineTone.prx`, stored `aksinetone.prx`). Paths that reach the
filesystem without the index (unhooked libc calls) fail there only. The
system module loader opens files itself, so it is routed through the index
in `rt/hook.rs` (`sceKernelLoadStartModule_observer`).

## Benchmark data

Performance numbers in `README.md` and the Makefile comments come from
on-console runs read from the debug build's `/metrics` page. Raw run data is
not kept in the repo; state the game, build and settings next to new numbers.

## Removed

Removed in the 256 MiB change. Do not rebuild one without new evidence.
The save data hooks were removed too and came back: without them the title
that needs the icon hook hung on its first save.

- mmap decode on access (`rt/pack/mmap_fault.rs`, 1210 lines,
  `AMPR_ZSTD_MMAP=1`, hook ids 98 and 99, 4 x 112 KiB Buffer workspaces,
  2 MiB Index scratch). Three fully packed games on a console never mmapped
  a packed file (`mmap_virtual` 0), and eight known limits were unsolved.
  The mmap disk cache (mode 2) went after it (below).
- Read-ahead (`rt/pack/readahead.rs`, knobs
  `AMPR_PACK_READAHEAD_CHUNKS` and `..._MAX_DISK_INFLIGHT`, debug `ra`,
  `ra_gate`). Off by default; with the pread pool it gave 1.62 vs 1.60 ms
  per read, a worst read of 36.2 vs 26.7 ms, and on a second title doubled
  disk bytes (1.69 vs 0.78 per game byte).
- Lane EOP overlap (`rt/reactor/lane_overlap.rs`, 612 lines, knob
  `lane_eop_overlap`). Off in both builds; 7.7 vs 6.1 ms per job at 32
  pread threads on loose files.
- Equeue user-space local wait (knob `equeue_local`). Off in both builds;
  when on it missed native events from paths the overlay does not hook.
  Queue tracking stays.
- Upstream stubs never enabled: cross-EOP read-ahead
  (`rt/reactor/backoff.rs`) and full-file fd promotion
  (`rt/reactor/software.rs`, `rt/reactor/submit.rs`).
- fd read threads (`READ_THREADS` in `rt/pack/fd_read.rs`, 4 threads of
  128 KiB stack, their queue and load group). They existed because the AIO
  path needed about 32 KB of the caller's stack (a game's video I/O thread
  hit its guard page); the sync read on the caller's thread needs 0x758 B.

Removed after the 256 MiB change, by the owner's decision from code
reading and earlier console runs. The build without them ran on two pkg
titles and a zstd title against v0.4.1 with no regression:

- Load retirement (the `LoadGroup` ring, histogram and streak in
  `rt/thread_hooks.rs`, `LOAD_SAMPLES`, `RETIRE_STREAK`, `LOAD_BUCKETS`,
  debug knob `retire_load`, metrics `<group>_busy_peak` and
  `<group>_retired_load`). Off by default since the 256 MiB change; the
  rule was retuned three times for decode worker churn (164 retirements
  in 120 s, 509 in 159 s, 217 in 147 s, debug /metrics), and with it off
  the rings were still sampled on every job. Pressure mode stays.
- mmap disk cache (`rt/pack/mmap.rs`, 683 lines, `AMPR_PACK_MMAP=2`, ids
  96 and 97 in release, a 64-fd table, a 256 KiB pool piece, files under
  /data/ampr_cache). `mmap_virtual` 0 on three fully packed games; the
  path never ran on a console. A map of a packed file now fails. Stays:
  the debug probes on ids 96 and 97 (`mmap_probe` in `rt/probe.rs`, op
  letters X and Y, `mmap_virtual`), the module_start removal of an old
  /data/ampr_cache, and `read_packed`, moved to `rt/save.rs`. The 256 KiB
  went to the cache (fixed sites budget 2 to 1.75 MiB).
- Loose read classes (`AmprLooseReadClass`, `readClass`, `classActive`,
  the latency escape slots and the class admission limit in the
  reactor). The reactor only ever saw the default (balanced) class;
  upstream's classifier was never ported and its gain is unknown. The
  balanced chain chunk limit stays (`ampr_loose_chain_chunk_limit`).
- Equeue queue classification (hook ids 55..=63, the external producer
  hooks `sceAgcDriverAddEqEvent` and `sceVideoOutAdd*Event`, the AMM
  queue hash and command-buffer registry, 128 KiB of .bss and 32 KiB of
  `OV`). Its ampr, mixed and amm flags were read only by the debug
  `/queues` page (flag bits 1, 2, 4), and a failed install of one of
  those hooks, or more than 256 modules, turned queue tracking off. Ids
  62 and 63 set a registration control no publish looked up. The ids
  keep their numbers and never install; queue tracking (ids 50..=54) and
  the hidden wake stay.
- Tune `PROFILES` (`profile=low|medium|high` in `rt/tune.rs`). They
  predate the 256 MiB layout: `high` was cut to the cap and `medium`
  shrank the default cache. A tune file `profile=` line is skipped and
  `/set?profile=` is refused.
- Grouped external AIO (`ExternalAioGroupBatch`, `flush_group_external`,
  `accept_external_aio_group`): no caller; the one external submitter,
  the pack, passes one request. `ExternalAioRead` keeps one request.
- Speculative-issue arguments of `issue_software_read` and adjacent loose
  read coalescing: constant at the one caller, and coalescing never ran
  (one command a chain).
- `CACHE_CVS` (64 condvars, the blocking wait in `cache_acquire`): its one
  caller never waited (`wait_for_loader` false). Pending entries and the
  publication epoch stay.
- Pack telemetry timestamps (`pack_telemetry_usecs`, the `queued_at_usec`
  arguments): constant 0, never ported.
- A timer tick (debug knob `tick_us`, never committed): one thread
  sleeping in a loop at priority 256 on CPUs 0-5, as an older release's
  last pread pool thread did on its 1 us idle timeout until that was
  fixed, to test whether that loop made games smoother. A 10 us sleep took
  about 110 us on the console (about 9,000 wakeups a second, worst
  3.9-7.3 ms late), so the old loop woke at that rate too. With the 100 us idle spin on, it
  changed nothing beyond noise on two pkg titles (-4% and none), and a
  zstd title waited 14% longer per read (360 vs 316 us, disk read +20%,
  debug /metrics, one run each). The idle spin (`SPIN_US_DEFAULT` 100)
  gave the smoothness without it.
- A single 1 ms safety poll for packed APR reads in place of the 10 us
  doubling to 100 us poll ladder (`rt/reactor/backoff.rs`), relying on
  the pack's completion notify. Tried and reverted: on a zstd title with
  69% cache hits, game wait per read went from 262 to 390 us (pack job
  277 vs 268 us) and the gap between a read's last two polls from 42 to
  264 us; with the ladder back it measured 259 us. On a pkg title with
  1.3 ms pack jobs it changed nothing measurable. Reads that finish in
  tens of us need the short first poll.

## Do not commit

Build outputs: `*.sprx`, `out/`, `target/` (all in `.gitignore`). Do not add
binaries or game data to the repo.
