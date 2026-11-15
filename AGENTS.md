# AGENTS.md

Notes for coding agents working on ampr-emu-ng (version 0.4.0, GPL-3.0-or-later).

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
behaves as upstream.

## Layout

- `crates/ampr-sys`: PRX runtime (staticlib). Runtime code is in `src/rt/`
  (pack, reactor, hooks, stats, tune, exports). The PRX exports 137 symbols:
  118 sceAmpr* (`rt/exports.rs`, found by `EXPORT_RE`) and 19 libc/libc++
  symbols that retail libSceAmpr re-exports (`rt/libc_exports.rs`, listed in
  `EXTRA_EXPORTS` in `tools/generate_payload_exports.py`).
- `crates/ampr-format`: shared index readers, byte helpers, overlay utilities
  and the exact-read run planner (`src/run.rs`).
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
  holds the format side: `src/view.rs` builds the per-file columns, hash
  slots and directory records into caller memory and looks keys up,
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
`AMPR_PACK_PIPELINES`, read-ahead,
`AMPR_ZSTD_LIBC_HOOKS`, `AMPR_ZSTD_MMAP`, `AMPR_MEM_REPORT`). A knob change
rebuilds through `out/*/obj/build-config.txt`. The two `AMPR_ZSTD_*` knobs
keep their zstd names but apply to LZ4 and pkg titles too; only `AMPR_ZSTD_MMAP=1`
(decode on access) is zstd only. Those hooks (hook ids 78 and up), the
eager index load and the mmap cache sweep apply only to a title that ships
packs, zstd, LZ4 or pkg (`packs_present` in `rt/pack/mod.rs`, `hook_enabled` in
`rt/hook.rs`); a title with no packs gets the shared ids 0..=77. Among them,
ids 100..=109 route the game's own kernel AIO (`sceKernelAioSubmitReadCommands*`,
poll, wait, delete, cancel) to the runtime's AIO emulation
(`rt/pack/aio.rs`, `rt/pack/aio_wait.rs`); the runtime's own native AIO
calls the pre-detour slot (`real_aio_*` in `rt/pack/libkernel.rs`), never
the symbol by name, which would re-enter the hook. The exception is ids
110..=111 (`scePthreadCreate`, `pthread_create`, `rt/thread_hooks.rs`):
they install in every title, packs or not. A game thread creation that
fails with EAGAIN makes the runtime give threads back and is retried; the
runtime-wide budget of 16 worker threads is cut and regrows by one per
10 s quiet. The groups are capped at 4 decode workers (`AMPR_PACK_WORKERS`;
an LZ4 or pkg title's `ampr_assets.index.runtime` profile can ask for up to 16,
`AMPR_EMU_PACK_WORKER_CAPACITY`; the worker start cuts workers until
each has a pipeline in the Buffer ledger, 9 and 9 at 16, `buffer_split`
in `rt/pack/worker.rs`),
6 disk read threads (`tune::RELEASE_PREAD_THREADS`) and 4 fd read threads
(`READ_THREADS` in `rt/pack/fd_read.rs`). Runtime threads retire by load,
not by idle time (no idle timer): each group keeps its last 8192
busy-thread counts (`LOAD_SAMPLES`), and a thread that finishes its work
leaves after 8 such finishes in a row with more live than one above the load
target (ceil(median x 1.5) + 1, at least 1). That EAGAIN
starts pressure mode: idle threads leave at once, each group runs at most
one thread while it has work and none without (decode workers never go
below one, `LoadGroup::floor`), until 10 s pass with no new failure
(`LoadGroup`, `pressure` in `rt/thread_hooks.rs`). Ids 112..=119 (dup,
dup2, poll, select, openat, fstatat, faccessat, readlink) exist only in the
debug build, as pass-through probes in titles with packs (`rt/probe.rs`).
Pkg mode and a writable /app0 add no hook ids; the hook ids are as
upstream. The
runtime creates its own threads through `create_internal`
(the pre-detour slot). Save data (`rt/save.rs`) is hooked by NID in a loaded
`libSceSaveData` module, not through the libkernel table, in every title
(the loader observer finds it outside `sceKernelGetModuleList`):
`sceSaveDataMount3` passes every answer back to the game, a BUSY one
included, and only counts the mounts and the BUSY answers, and
`sceSaveDataSaveIconByPath` hands a packed icon to `sceSaveDataSaveIcon` as
bytes.
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
  memory had 0-28 MiB free during play). The one exception is the Rust
  global allocator (`LibcAlloc` in `lib.rs`), which uses the game's libc
  heap: iced-x86 only. Keep it to that; zstd decoders use a static DCtx
  in a pool workspace (`ZstdDecoder::init_in` in `crates/ampr-codec`).
  Ledgers (`rt/index_memory.rs`):
  Index 80 MiB (the compiled index view, the pack index tables kept
  after the mount, the walk build, the 64 KiB build windows, the save
  icon buffer), Cache 64 MiB (one decoded chunk cache, carved at
  startup; pack chunks are read with exact-size reads, the only read
  path, and no read pages are cached), Buffer 28.44 MiB (4 x 1 MiB decode +
  12 x 2 MiB I/O windows + 4 x 112 KiB zstd decoder workspaces, one per
  live zstd worker, taken at its start and freed when it retires; with
  `AMPR_ZSTD_MMAP=1` 4 more for the decode-on-access slots), plus a 2 MiB budget for the fixed sites
  listed at `STATIC_POOL_SIZE` in `rt/runtime_memory.rs` (1.56 MiB used; a
  host test fails on a new pool call). A build-time assert checks that the
  caps plus the budget fit the pool. Both PRX builds load to the same
  184.44 MiB (PT_LOAD memsz, below 192 MiB; v0.3.4 loaded at 200.7 MiB):
  the release pool is 175.83 MiB
  (`AMPR_INTERNAL_POOL_SIZE` `0xafd4000`), the debug one 174.47 MiB
  (`AMPR_DEBUG_POOL_SIZE` `0xae78000`), the gap being the debug build's
  larger non-pool part (9.97 vs 8.61 MiB). `AMPR_ZSTD_MMAP=1` grows both
  pools by 448 KiB (184.88 MiB, computed). `dist` fails when the two totals
  differ by more than 64 KiB or reach 192 MiB (`PRX_TOTAL_LIMIT` in
  `tools/verify_payload_prx.py --prx-totals`); then update the gap in the
  Makefile. A refused allocation degrades (index: one notice, packs
  unserved; cache off; icon skipped). Every I/O window is taken at the
  worker start, after the decode buffers, and the pipeline count is the
  windows granted: there is no slow path for a read without one. A title
  has one compiled index view, built at module_start in one pass over
  `ampr_emu.index` through two 64 KiB windows and kept until shutdown:
  28 B of columns per file (hash, size, mtime, path offset), 4 B more
  with packs and 4 B more with zstd packs, 4 B hash slots at 1.5 to 3 per
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
  the module's life: a hook reads one with a pread on its own thread only
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
  `rt/pack/mod.rs` and `APP0_WRITABLE` (1 B) in `rt/rw.rs`. Any change
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
   `tools/verify_payload_prx.py` on the linked PRX and SPRX.
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
in `rt/hook.rs` (`sceKernelLoadStartModule_equeue_observer`).

## Benchmark data

Performance numbers in `README.md` and the Makefile comments come from
on-console runs read from the debug build's `/metrics` page. Raw run data is
not kept in the repo; state the game, build and settings next to new numbers.

## Do not commit

Build outputs: `*.sprx`, `out/`, `target/` (all in `.gitignore`). Do not add
binaries or game data to the repo.
