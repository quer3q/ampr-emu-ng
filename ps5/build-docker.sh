#!/usr/bin/env bash
# Builds libSceAmpr.sprx and libSceAmpr-debug.sprx into the project root.
# Extra args go to make, e.g. `./ps5/build-docker.sh verify AMPR_PACK_WORKERS=4`.
# One runtime reads LZ4 and zstd packs. Copy libSceAmpr.sprx into
# the game's fakelib/ directory.
set -euo pipefail

cd "$(dirname "$0")/.."
image="${AMPR_PS5_IMAGE:-ampr-emu-ng-ps5:latest}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -t "$image" ps5
fi

if [ "$#" -eq 0 ]; then
  set -- dist
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/work/out/cargo-home \
  -v "$PWD:/work" \
  -w /work \
  "$image" make "$@"
