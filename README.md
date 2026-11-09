# ampr-emu-ng

A hard fork of [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu) that is designed for maximum performance and stability running zstd, LZ4 or plain games.

The runtime reads both pack formats and picks one at load: zstd packs
(`AMPRZPK1` index, `AMPRZDT1` volumes) when `/app0/ampr_zstd.index` exists,
otherwise LZ4 packs (`AMPRPAK4`). This repo only reads packs; see
[Make packs](#make-packs). The zstd format is described in
[docs/zstd-format.md](docs/zstd-format.md).

## Performance

Measured on one game and one level, several runs per runtime, from launch
until the level is loaded, read from the debug build's `/metrics`.
"Original" is the C++ ampr_emu.

| Speed | Original C++ | ampr-emu-ng LZ4 | ampr-emu-ng zstd |
| --- | --- | --- | --- |
| Start of load (~1.2 GB read): game wait per read | 19.76 ms | 0.79 ms (-96%) | 0.89 ms (-95%) |
| Start of load: pack job | 2.22 ms | 1.27 ms (-43%) | 1.25 ms (-44%) |
| Start of load: disk read | 2.01 ms | 0.79 ms (-61%) | 0.59 ms (-71%) |
| Level loaded (~8.8 GB read): game wait per read | 10.26 ms | 1.30 ms (-87%) | 1.27 ms (-88%) |
| Level loaded: pack job | 3.35 ms | 1.73 ms (-48%) | 1.40 ms (-58%) |
| Level loaded: disk read | 3.38 ms | 1.23 ms (-64%) | 0.68 ms (-80%) |
| Level loaded: disk bytes read | 4.98 GB | 4.97 GB | 3.48 GB (-30%) |

| Memory and size | Original C++ | ampr-emu-ng LZ4 | ampr-emu-ng zstd |
| --- | --- | --- | --- |
| Pool size / peak (ampr-emu-ng: highest peak, measured with the earlier 32 + 16 MiB caches) | 384 / 267.9 MiB | 192 / 113.6 MiB (-50% / -58%) | 192 / 95.6 MiB (-50% / -64%) |
| Runtime memory (release, PRX segments) | 397.2 MiB | 200.7 MiB (-49%) | 200.7 MiB (-49%) |
| Pack on disk | 32.43 GiB (LZ4) | 32.43 GiB (LZ4) | 23.61 GiB (zstd level 5, -27%) |

## How to

### Use

Copy `libSceAmpr.sprx` into the game's `fakelib/`, mount the game with
ShadowMountPlus and turn off fakelib updates in its settings. At launch the
console shows `ampr-emu-ng: vx.x.x (zstd) running`. The mode in that line is
`zstd` for zstd packs, `lz4` for LZ4 packs, or `plain` when the game has no
packs and only loose files. A plain game gets the v0.2.0 hook set: the
virtual-fd, libc and mmap hooks install only when the game ships
packs.

### Make packs

[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds both zstd
and LZ4 packs.

### Build

The build needs Docker. The first run builds the toolchain image
`ampr-emu-ng-ps5:latest` from `ps5/Dockerfile` (Rust 1.99.0, LLVM 19,
ps5-payload-sdk v0.43). Set `AMPR_PS5_IMAGE` to use a different image.

```sh
./ps5/build-docker.sh            # make dist
```

`dist` builds and verifies the PRX (`tools/verify_payload_prx.py`), then
copies two files to the project root:

- `libSceAmpr.sprx`, the release build;
- `libSceAmpr-debug.sprx`, the same runtime plus the metrics endpoint
  described below, with a 256 MiB pool instead of 128 MiB, so its pool
  peak shows the memory at the default cache sizes (release shrinks its
  caches when its pool is short).

### Debug build metrics

`libSceAmpr-debug.sprx` serves plain text on TCP port 9090, one client at a
time. `/metrics` starts with a `build` line that names the git revision and
flavor of the running PRX, for example
`build ampr-emu-ng x.x.x f3494d4-dirty debug`.

- `curl http://<ps5-ip>:9090/metrics` returns pool usage and the
  `rt/stats.rs` counters since load: disk reads, pack jobs, decodes, cache
  hits and misses, read-ahead and errors. The `*_max` values reset on each
  scrape.
- `curl http://<ps5-ip>:9090/bench` measures the raw read speed of pack
  volume 0. Run it while the game is idle.
- `curl 'http://<ps5-ip>:9090/set?k=v'` changes `rt/tune.rs` knobs; without
  arguments it lists them. The values are saved to `/data/ampr_emu_tune.txt`,
  and startup knobs apply on the next launch. Release builds ignore this
  file. The file stores every knob, defaults included, so a file saved by an
  older build keeps that build's values (for example `decoded_mib=0`, which
  keeps the decoded cache off); delete it to get the current defaults.
  Older debug builds hung titles with packs on their loading screen while
  this file existed; `real_physical_close` in `rt/sys.rs` fixes that.
- `curl http://<ps5-ip>:9090/fsfail` lists every distinct failed call since
  load, with its result and count. It covers path hooks, the runtime's own
  opens of loose files, APR path resolves, failed APR jobs, module loads, and
  gather/scatter retries that re-resolved to another file or offset. Misses
  that the index answers by itself and `/download0` probes are left out. The
  debug build also logs when a packed file (zstd or LZ4) or a virtual fd
  reaches an API the runtime does not serve (op letters `D W T F C N`,
  plus `O A a l` with how `p`/`d` when an `AMPR_ZSTD_LIBC_HOOKS` bit is
  cleared), and `I` when a game's own AIO submit on a packed file is
  served. It logs
  `X`/`Y` when an mmap of a packed file fails, with how `k` for the disk
  cache, `f` for decode on access, `F` for a failed decode-on-access fill
  and `v` for any other failure. See `AMPR_ZSTD_MMAP` in the `Makefile`.
  `Q` reports packed-fd/open failures: how `H` the raw SCE error of a
  failed packed open, `R` the errno of a failed physical open (in the
  `/metrics` event ring only, not `/fsfail`), and `S` the
  512-slot synthetic packed-fd table full.
- `curl http://<ps5-ip>:9090/modules` lists the modules the game loaded, with
  name, segment size and fingerprint. To find a module that failed to load,
  run the same build on two installs and diff the two lists.

## Thanks

- [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu), the original C++
  AMPR emulator that this project ports.
- [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk), the PS5
  toolchain and libraries the PRX is built with.
- [AnyPS5](https://github.com/boykopovar/AnyPS5), for its libSceAmpr
  implementation and its notes on the libc exports that retail libSceAmpr
  carries.

## License

GPL-3.0-or-later, the same as upstream (`LICENSE`).
