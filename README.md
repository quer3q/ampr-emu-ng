# ampr-emu-ng

A hard fork of [drakmor/ampr_emu](https://github.com/drakmor/ampr_emu), built for speed and stability on PKG, zstd, LZ4 and plain games.

It only reads packs; to make them see [Make packs](#make-packs).

## How to

### Use

Copy `libSceAmpr.sprx` into the game's `fakelib/`, mount the game with
ShadowMountPlus and turn off fakelib updates in its settings. At launch the
console shows `ampr-emu-ng: vx.x.x (zstd) running`, where the mode is `zstd`,
`pkg`, `lz4`, or `plain` for a game with only loose files. The virtual-fd, libc,
mmap and game AIO hooks install only in a game with packs; the thread
creation and save data hooks install in every game.

A PKG game runs through [kraken-mount](https://github.com/quer3q/kraken-mount),
the PKG launcher: it mounts the folder holding the .pkg at `/app0/kraken/`,
names the .pkg in `/app0/kraken.image` and copies `libSceAmpr.sprx` from
`/data/krakenmount/ampr/` into the game's `fakelib/`.

### Make packs

[ps5-dump-forge](https://github.com/quer3q/ps5-dump-forge) builds zstd and
LZ4 packs. A PKG game needs no packing:
[kraken-mount](https://github.com/quer3q/kraken-mount) builds its manifest
from the .pkg.

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
