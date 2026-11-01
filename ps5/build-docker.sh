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

# Build identity for the debug build's /metrics. git runs here on the
# host: the image has no git. Untracked files do not count as dirty.
rev=unknown
if command -v git >/dev/null 2>&1 && short=$(git rev-parse --short=7 HEAD 2>/dev/null); then
  rev=$short
  git update-index -q --refresh >/dev/null 2>&1 || true
  if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    rev="$rev-dirty"
  fi
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/work/out/cargo-home \
  -v "$PWD:/work" \
  -w /work \
  "$image" make "AMPR_GIT_REV=$rev" "$@"
