# AGENTS.md

Notes for coding agents working on ampr-emu-ng (version 0.3.2, GPL-3.0-or-later).

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

## Build and test

```sh
cargo test --workspace                         # host tests
./ps5/build-docker.sh                          # make dist: release + debug .sprx, verified
./ps5/build-docker.sh verify                   # release build + verifier only
./ps5/build-docker.sh dist AMPR_PACK_WORKERS=8 # override a Makefile knob
./ps5/build-docker.sh clean                    # remove out/
```

Knobs and their defaults are at the top of the `Makefile`
(`AMPR_INTERNAL_POOL_SIZE`, `AMPR_PACK_WORKERS`, read-ahead,
`AMPR_ZSTD_LIBC_HOOKS`, `AMPR_ZSTD_MMAP`, `AMPR_MEM_REPORT`). A knob change
rebuilds through `out/*/obj/build-config.txt`. The two `AMPR_ZSTD_*` knobs
keep their zstd names but apply to LZ4 packs too; only `AMPR_ZSTD_MMAP=1`
(decode on access) is zstd only. Those hooks (hook ids 78 and up), the
eager index load and the mmap cache sweep apply only to a title that ships
packs, zstd or LZ4 (`packs_present` in `rt/pack/mod.rs`, `hook_enabled` in
`rt/hook.rs`); a title with no packs keeps the v0.2.0 hook set.
CI (`.github/workflows/build.yml`) runs the same commands; a pushed `v*` tag creates a draft release with both `.sprx` and `SHA256SUMS`.

## Conventions

- Runtime crates are `no_std` (`ampr-sys` is `no_std` outside tests). Do not
  pull `std` into them.
- No new dependencies without a stated reason. Runtime dependencies use
  `default-features = false`, and `lz4_flex`, `zstd-sys`, `iced-x86` are
  pinned (`=x.y.z`); follow that.
- Memory budget: the release pool is 128 MiB (`0x8000000`); the debug
  build's is 256 MiB (`AMPR_DEBUG_POOL_SIZE`). With the current defaults
  (32 MiB physical and 16 MiB decoded cache, debug build at the 128 MiB
  release pool, ~75 s after launch) the measured peaks are 113.6 MiB (a fully packed LZ4
  UE3 title, 25.2 MiB index), 93.2 MiB (a fully packed LZ4 UE5 title),
  95.6 MiB (a REDengine title, zstd) and 90.7 MiB (an RE Engine title,
  zstd). The peak grows with the index; the UE3 title leaves 14.4 MiB free.
  Release runtime memory (PRX segments) is 136.7 MiB. Any change that grows
  runtime memory needs a measurement and an updated Makefile comment.
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
   after and compare game wait per read, pack job and disk read latency.

## Debugging on a console

- The debug build's `/fsfail` lists failed calls (path hooks, the runtime's
  own loose opens `L`, APR resolves `R`, APR jobs `E`, module loads `K`,
  gather/scatter retry mismatches `G`, the upstream #7 wrong-file class) and
  `/modules` lists loaded modules; the op letters are documented at
  `FsEvents` in `rt/stats.rs`. When one install of a game works and another
  does not, run the same build on both and diff the two outputs.
  The debug build also logs (op letters `I D W T F C N`, and `O A a l`
  with how `p`/`d` when an `AMPR_ZSTD_LIBC_HOOKS` bit is cleared) when a
  packed file (zstd or LZ4) or a virtual fd reaches an API the runtime does
  not serve; `X`/`Y` log mmap of a virtual fd (how `k` disk cache, `f`
  decode on access, `F` failed decode-on-access fill, `v` other failure).
- When the game dies before `:9090` answers, read the debug build's black
  box `/data/ampr_emu_trace.txt` (`rt/blackbox.rs`): the loaded modules with
  segment addresses (at start and after each module load), to map a crash
  RIP to a module, and every failed file event plus module loads. It is
  rewritten at each start, so copy it off before relaunching.
- Folder installs on the internal SSD are case-sensitive; retail pfs and
  exFAT are not, and games depend on that (e.g. Wwise plugins loaded as
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
