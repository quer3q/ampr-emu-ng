#!/usr/bin/env python3
"""Fails the build when a hook-path function's stack frame passes its budget.

The hooks run on the game's own threads, whose stacks the game sized for
itself. In v0.4.0 the manifest load was inlined into `ensure_manifest_ready`,
whose frame went from 0xa8 to 0x12d8 bytes on every packed open, and the
open chain of a packed save icon (about 1.6 KB in v0.3.5) took 7.7 KB: a
game's Save Thread overflowed its stack at the call in that prologue. Nothing
failed in the build, so a user found it.

A frame is the first `sub $N, %rsp` of a function in the linked PRX's
disassembly. Frames are measured in the release and debug PRX; the budgets
leave room for the difference between them and are raised on purpose, not
to make a build pass: move the cold code out of line instead.

Usage: check_stack_frames.py PRX [--objdump llvm-objdump]
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# (name regex, max frame bytes, must exist, measured release / debug).
# `must exist` is for names that cannot be inlined away; one renamed would
# make its budget match nothing, so it fails and this table is updated.
# Names are legacy-mangled Rust paths: `<len><name>`.
FRAME_BUDGETS = [
    # The load state check every packed open makes. Inlined into callers.
    (r"ensure_manifest_ready", 0x100, False, "inlined / inlined"),
    (r"ensure_manifest_loaded", 0x100, True, "0x18 / 0x18"),
    (r"4save22save_icon_by_path_emul", 0x600, True, "0x448 (open inlined) / 0xa8"),
    # The open hooks: open_with is inlined into posix_open_emul in release.
    (r"5index(9open_with|15posix_open_emul)", 0x600, True, "0x430 / 0x438"),
    (r"5index13open_resolved$", 0x600, True, "0x428 / 0x428"),
    (r"5index15lookup_resident$", 0x600, True, "0x470 / 0x470"),
]

# Frames summed along the packed save icon open chain, each function once
# (the release build counts the inlined open twice, so this is an upper
# bound there). 0xcb8 release, 0x920 debug today; v0.3.5 about 0x630.
CHAIN = [
    r"4save22save_icon_by_path_emul",
    r"5index(9open_with|15posix_open_emul)",
    r"5index13open_resolved$",
    r"ensure_manifest_loaded",
]
CHAIN_BUDGET = 0x1000

# Large frames kept as they are, pinned so they cannot grow unnoticed. The
# AIO emulation holds arrays for 128 requests (rt/pack/fd_read.rs
# `READ_STACK`); they are reached only for a call on a packed fd, and
# `read_on_workers` also runs on the caller's thread when no read thread can
# start.
PINNED = [
    (r"7fd_read15read_on_workers", 0x3000, True, "0x2e58"),
    (r"3aio38sceKernelAioSubmitReadCommandsMultiple$", 0x3800, True, "0x2b00 / 0x3600"),
    (r"3aio20publish_virtual_jobs", 0x800, True, "0x18 / 0x728"),
]

SUB_RSP = re.compile(r"subq\s+\$0x([0-9a-f]+), %rsp")
HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:")


def frames(objdump: str, prx: Path) -> dict[str, int]:
    out = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(prx)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    result: dict[str, int] = {}
    current = None
    for line in out.splitlines():
        header = HEADER.match(line)
        if header:
            current = header.group(1)
            continue
        found = SUB_RSP.search(line)
        if found and current and current not in result:
            result[current] = int(found.group(1), 16)
    return result


def biggest(table: dict[str, int], pattern: str) -> int | None:
    rule = re.compile(pattern)
    sizes = [size for name, size in table.items() if rule.search(name)]
    return max(sizes) if sizes else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("prx", type=Path)
    parser.add_argument("--objdump", default=None)
    args = parser.parse_args()
    objdump = args.objdump or shutil.which("llvm-objdump") or "objdump"
    table = frames(objdump, args.prx)
    if not table:
        print(f"no frames found in {args.prx}", file=sys.stderr)
        return 1

    failures = []
    for pattern, limit, must_exist, _measured in FRAME_BUDGETS + PINNED:
        size = biggest(table, pattern)
        if size is None:
            if must_exist:
                failures.append(f"{pattern}: not found (renamed? update tools/check_stack_frames.py)")
            continue
        if size > limit:
            failures.append(f"{pattern}: frame 0x{size:x} over budget 0x{limit:x}")
    chain = sum(biggest(table, pattern) or 0 for pattern in CHAIN)
    if chain > CHAIN_BUDGET:
        failures.append(f"save icon open chain: 0x{chain:x} over budget 0x{CHAIN_BUDGET:x}")

    if failures:
        print(f"stack frame budget exceeded in {args.prx}:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"stack frames ok: {args.prx} (open chain 0x{chain:x} of 0x{CHAIN_BUDGET:x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
