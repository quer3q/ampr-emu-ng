# AGENTS.md

Notes for coding agents working on ampr-emu-ng (version 0.3.5, GPL-3.0-or-later).

## Project

ampr-emu-ng is a `no_std` Rust rewrite of drakmor/ampr_emu: the PS5 fakelib
`libSceAmpr.sprx`, which emulates the AMPR/APR file APIs for games run from
dumps. One runtime serves LZ4 packs (`AMPRPAK4`) and zstd packs (`AMPRZPK1`
index, `AMPRZDT1` volumes), picked at load by whether
`/app0/ampr_zstd.index` exists (`crates/ampr-sys/src/rt/pack/mod.rs`).

## Layout

- `crates/ampr-sys`: PRX runtime (staticlib). Runtime code is in `src/rt/`
  (pack, reactor, hooks, stats, tune, exports). The PRX exports 137 symbols:
  118 sceAmpr* (`rt/exports.rs`, found by `EXPORT_RE`) and 19 libc/libc++
  symbols that retail libSceAmpr re-exports (`rt/libc_exports.rs`, listed in
  `EXTRA_EXPORTS` in `tools/generate_payload_exports.py`).
- `crates/ampr-format`: shared index readers, byte helpers and overlay utilities.
- `crates/ampr-codec`: zstd decode.
- `crates/ampr-lz4`: AMPRPAK4 manifest, AMPRDAT3 header, read planning and LZ4 decode.
- `crates/ampr-command`, `ampr-hook`: APR command encoding and x86 hook decoding.
- `crates/ampr-zstd`: zstd pack format, decode side only (`no_std`).
- `ps5/`: Dockerfile, `build-docker.sh`, target spec, PRX linker script.
- `tools/`: Python PRX post-processing and `verify_payload_prx.py`.
- `docs/zstd-format.md`: the zstd pack format. Keep it in sync with
  `crates/ampr-zstd` and `crates/ampr-format/src/zstd.rs`.
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
keep their zstd names but apply to LZ4 packs too; only `AMPR_ZSTD_MMAP=1`
(decode on access) is zstd only. Those hooks (hook ids 78 and up), the
eager index load and the mmap cache sweep apply only to a title that ships
packs, zstd or LZ4 (`packs_present` in `rt/pack/mod.rs`, `hook_enabled` in
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
an LZ4 title's `ampr_assets.index.runtime` profile can ask for up to 16,
`AMPR_EMU_PACK_WORKER_CAPACITY`, within the Buffer ledger),
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
debug build, as pass-through probes in titles with packs (`rt/probe.rs`). The
runtime creates its own threads through `create_internal`
(the pre-detour slot). Save data (`rt/save.rs`) is hooked by NID in a loaded
`libSceSaveData` module, not through the libkernel table, in every title
(the loader observer finds it outside `sceKernelGetModuleList`):
`sceSaveDataMount3` retries a BUSY mount once after unmounting every save
point the service returned earlier, and `sceSaveDataSaveIconByPath` hands a
packed icon to `sceSaveDataSaveIcon` as bytes.
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
  Index 64 MiB (index files, lookup tables, walk build buffers, the save
  icon buffer), Cache 32 MiB (16 MiB physical +
  16 MiB decoded, carved at startup), Buffer 28.44 MiB (4 x 1 MiB decode +
  12 x 2 MiB I/O windows + 4 x 112 KiB zstd decoder workspaces, one per
  live zstd worker, taken at its start and freed when it retires; with
  `AMPR_ZSTD_MMAP=1` 4 more for the decode-on-access slots), plus a 2 MiB budget for the fixed sites
  listed at `STATIC_POOL_SIZE` in `rt/runtime_memory.rs` (1.56 MiB used; a
  host test fails on a new pool call). A build-time assert checks that the
  caps plus the budget fit the pool. Both PRX builds load to the same
  136.5 MiB (PT_LOAD memsz, below 192 MiB; v0.3.4 loaded at 200.7 MiB):
  the release pool is 127.83 MiB
  (`AMPR_INTERNAL_POOL_SIZE` `0x7fd4000`), the debug one 126.47 MiB
  (`AMPR_DEBUG_POOL_SIZE` `0x7e78000`), the gap being the debug build's
  larger non-pool part (10.04 vs 8.69 MiB). `AMPR_ZSTD_MMAP=1` grows both
  pools by 448 KiB (136.95 MiB). `dist` fails when the two totals
  differ by more than 64 KiB or reach 192 MiB (`PRX_TOTAL_LIMIT` in
  `tools/verify_payload_prx.py --prx-totals`); then update the gap in the
  Makefile. A refused allocation degrades (index: one notice, packs
  unserved; cache off; window slow path; icon skipped). Each index file
  (AMPRZPK1, AMPRPAK4, AMPRIDX3), in mount order, is read whole into
  index memory when it fits the room left with its tables
  (`IndexSource::Resident`, `rt/index_pages.rs`); else it is read in
  16 KiB pages through a page arena of at least 16 MiB
  (`INDEX_ARENA_MIN`), taken by the first paged file and grown by
  `grow_arena` to the room the tables leave. A paged file gets a fast
  table, built by one sequential pass at mount and resident until
  shutdown, so lookups and read jobs run from memory and a path is read
  only to confirm a hash match: zstd 16 B per file (hash, logical size),
  8 B per chunk and volume;
  AMPRIDX3 12 B per file (hash, id); LZ4 its record sections, 48 B per
  file, 12 B per chunk, 32 B per pack (`fill_fast` in each reader). It is
  mandatory: there is no paged-lookup fallback. Lookup tables (fast
  tables first, at mount, then 16 B of projection per AMPRIDX3 id and 4 B
  of order per packed file) are capped at 48 MiB (`INDEX_LOOKUP_MAX`); an
  index whose tables do not fit, or that would leave the arena below
  16 MiB, is refused with the notice. A paged AMPRIDX3 must be sorted
  (the runtime builder writes it sorted): an unsorted one is served only
  read whole, else refused with the notice. Its header is checked
  before it takes the arena, and the arena goes back to the ledger when
  no paged file is left (a failed or replaced load). Hooks never wait on another thread
  for a page: a page another thread is loading, or a miss with no
  evictable slot, is read from the index file by the hook's thread, like
  the open() it replaces; a read error there is never an authoritative
  ENOENT (`index_lookup_io`). The pack
  index is capped only by the loader's 512 MiB fstat check
  (`AMPR_EMU_PACK_INDEX_MAX_BYTES`; paths must be shorter than 1024
  bytes). 48 MiB holds the lookup tables of about 1.6 million zstd files
  with 100 GB of chunks (computed). A title without
  `ampr_emu.index` builds its AMPRIDX3 whole in the Index ledger (walk
  build, 104-124 B per file at 48-byte paths) before writing and paging
  it. Pool peak outside the ledgers 0.56 MiB on a zstd title; the largest
  index measured is 25.2 MiB. Any change that grows runtime memory needs a measurement and an updated Makefile comment.
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
