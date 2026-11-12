# ampr-emu-ng

A hard fork of [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu), built for speed and stability on zstd, LZ4 and plain games.

At load the runtime picks zstd packs (`AMPRZPK1` index, `AMPRZDT1` volumes)
if `/app0/ampr_zstd.index` exists, otherwise LZ4 packs (`AMPRPAK4`). It only
reads packs; to make them see [Make packs](#make-packs). The zstd format is in
[docs/zstd-format.md](docs/zstd-format.md).

## Performance

One game, one level, several runs per runtime, from launch until the level
loaded, read from the debug build's `/metrics`. "Original" is the C++
ampr_emu.

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
| Pool size (release) | 384 MiB | 159.83 MiB (-58%) | 159.83 MiB (-58%) |
| Pool peak (ampr-emu-ng: highest, measured with an earlier build: 128 MiB pool, 32 + 16 MiB caches) | 267.9 MiB | 113.6 MiB (-58%) | 95.6 MiB (-64%) |
| Runtime memory (PRX segments, release and debug) | 397.2 MiB | 167.94 MiB (-58%) | 167.94 MiB (-58%) |
| Pack on disk | 32.43 GiB (LZ4) | 32.43 GiB (LZ4) | 23.61 GiB (zstd level 5, -27%) |

## How to

### Use

Copy `libSceAmpr.sprx` into the game's `fakelib/`, mount the game with
ShadowMountPlus and turn off fakelib updates in its settings. At launch the
console shows `ampr-emu-ng: vx.x.x (zstd) running`, where the mode is `zstd`,
`lz4`, or `plain` for a game with only loose files. The virtual-fd, libc,
mmap and game AIO hooks install only in a game with packs; the thread
creation and save data hooks install in every game.

### Make packs

[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds zstd and
LZ4 packs.

### Build

The build needs Docker. The first run builds the toolchain image
`ampr-emu-ng-ps5:latest` from `ps5/Dockerfile` (Rust 1.99.0, LLVM 19,
ps5-payload-sdk v0.43); `AMPR_PS5_IMAGE` picks another image.

```sh
./ps5/build-docker.sh            # make dist
```

`dist` builds the PRX, checks it with `tools/verify_payload_prx.py` and
copies two files to the project root:

- `libSceAmpr.sprx`, the release build;
- `libSceAmpr-debug.sprx`, the same runtime plus metrics, tuning and
  failure logs, for testing ([docs/debug-build.md](docs/debug-build.md)).

## Thanks

- [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu), the C++ AMPR
  emulator this project ports.
- [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk), the PS5
  toolchain and libraries.
- [AnyPS5](https://github.com/boykopovar/AnyPS5), for its libSceAmpr
  implementation and notes on the libc exports of retail libSceAmpr.

## License

GPL-3.0-or-later, the same as upstream (`LICENSE`).
