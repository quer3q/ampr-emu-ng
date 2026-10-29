# ampr-emu-ng

Hard fork of [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu) designed to achieve maximum performance and stability to run **zstd** and **LZ4** converted games.

One runtime reads two pack formats, picked at load: zstd packs (`AMPRZPK1`
index, `AMPRZDT1` volumes) when `/app0/ampr_zstd.index` exists, else LZ4 packs
(`AMPRPAK4`). This repo only reads packs; see [Make packs](#make-packs). The
zstd format is in [docs/zstd-format.md](docs/zstd-format.md).

## Performance

One game, same level, multiple
runs per runtime, launch to level loaded. Original is the C++ ampr_emu.

| Speed | Original C++ | ampr-emu-ng LZ4 | ampr-emu-ng zstd |
| --- | --- | --- | --- |
| Start of load (~1.2 GB read): game wait per read | 19.76 ms | 0.79 ms (**-96%**) | 0.89 ms (**-95%**) |
| Start of load: pack job | 2.22 ms | 1.27 ms (**-43%**) | 1.25 ms (**-44%**) |
| Start of load: disk read | 2.01 ms | 0.79 ms (**-61%**) | 0.59 ms (**-71%**) |
| Level loaded (~8.8 GB read): game wait per read | 10.26 ms | 1.30 ms (**-87%**) | 1.27 ms (**-88%**) |
| Level loaded: pack job | 3.35 ms | 1.73 ms (**-48%**) | 1.40 ms (**-58%**) |
| Level loaded: disk read | 3.38 ms | 1.23 ms (**-64%**) | 0.68 ms (**-80%**) |
| Level loaded: disk bytes read | 4.98 GB | 4.97 GB | 3.48 GB (**-30%**) |

| Memory and size | Original C++ | ampr-emu-ng LZ4 | ampr-emu-ng zstd |
| --- | --- | --- | --- |
| Pool size / peak | 384 / 267.9 MiB | 88 / 79.9 MiB (**-77%** / **-70%**) | 82 / 73.3 MiB (**-79%** / **-73%**) |
| Runtime memory (release, PRX segments) | 397.2 MiB | 96.4 MiB (**-76%**) | 90.7 MiB (**-77%**) |
| Pack on disk | 32.43 GiB (LZ4) | 32.43 GiB (LZ4) | 23.61 GiB (zstd level 5, **-27%**) |

## How to

### Use

Copy `libSceAmpr.sprx` into the game's `fakelib/` and mount the game with
ShadowMountPlus. Disable fakelib update in settings.

### Make packs

zstd and LZ4 packs are built by
[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge). This repo has no
encoder: `crates/ampr-zstd` holds only the zstd pack format the runtime decodes.

### Build

Needs Docker. The first run builds the toolchain image `ampr-emu-ng-ps5:latest`
from `ps5/Dockerfile` (Rust 1.99.0, LLVM 19, ps5-payload-sdk v0.43); set
`AMPR_PS5_IMAGE` to use another image.

```sh
./ps5/build-docker.sh            # make dist
```

`dist` builds, verifies (`tools/verify_payload_prx.py`) and copies two files to
the project root:

- `libSceAmpr.sprx`: release build.
- `libSceAmpr-debug.sprx`: same runtime plus the metrics endpoint (below).

### Debug build metrics

`libSceAmpr-debug.sprx` serves plain text on TCP port 9090, one client at a
time:

- `curl http://<ps5-ip>:9090/metrics`: pool usage and the `rt/stats.rs`
  counters since load (disk reads, pack jobs, decodes, cache hits and misses,
  read-ahead, read extension, errors). `*_max` values reset on each scrape.
- `curl http://<ps5-ip>:9090/bench`: raw read speed of pack volume 0; run it
  while the game is idle.
- `curl 'http://<ps5-ip>:9090/set?k=v'`: change `rt/tune.rs` knobs (no
  arguments lists them). Saved to `/data/ampr_emu_tune.txt`; startup knobs
  apply on the next launch. Release builds ignore this file.

## Thanks

- [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu): the original C++
  AMPR emulator this project ports.
- [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk): the PS5 toolchain
  and libraries the PRX is built with.

## License

GPL-3.0-or-later, as upstream (`LICENSE`).
