#!/usr/bin/env python3
"""Fails the build when a hook-path function's stack frame grows past its budget.

The hooks run on the game's own threads, whose stacks the game sized for
itself (a save thread's held about 7 KB below the hook). In v0.4.0 the
manifest load was inlined into `ensure_manifest_ready`, whose frame went
from 0xa8 to 0x12d8 bytes on every packed open, and a new game crashed at
the call in its prologue. Frames are read from the linked PRX's
disassembly: the first `sub $N, %rsp` of each function.

Usage: check_stack_frames.py PRX [--objdump llvm-objdump]
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# (name substring, max frame bytes, must exist). A function inlined away has
# no frame and passes; `must exist` guards the budgets against a rename that
# would make them match nothing. Measured in the release and debug PRX
# (debug first where they differ).
FRAME_BUDGETS = [
    # Every packed open. Inlined in the release build.
    ("ensure_manifest_ready", 0x100, False),
    ("save_icon_by_path_emul", 0x100, True),  # 0xa8
    ("5index9open_with", 0x600, True),  # 0x478 (v0.3.5 0x438)
    ("5slots26ampr_pack_try_open_indexed", 0x600, True),  # 0x498 (1 KiB path buffer)
]

# Frames summed along the save icon open chain, which overflowed.
CHAIN = [
    "save_icon_by_path_emul",
    "5index9open_with",
    "5slots26ampr_pack_try_open_indexed",
    "ensure_manifest_ready",
]
CHAIN_BUDGET = 0xC00  # 0x9b8 now; v0.3.5 ~0x630, v0.4.0 0x1e20.

# Known large frames on game threads, pinned so they cannot grow unnoticed:
# the AIO emulation holds arrays for 128 requests (rt/pack/fd_read.rs
# `READ_STACK`), and a read falls back to the caller's thread when no read
# thread can start. They are reached only for a call on a packed fd.
PINNED = [
    ("7fd_read15read_on_workers", 0x3000, True),  # 0x2e58
    ("3aio38sceKernelAioSubmitReadCommandsMultiple", 0x3800, True),  # 0x3600
    ("3aio20publish_virtual_jobs", 0x800, True),  # 0x718 (debug)
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


def biggest(table: dict[str, int], needle: str) -> int | None:
    sizes = [size for name, size in table.items() if needle in name]
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
    for needle, limit, must_exist in FRAME_BUDGETS + PINNED:
        size = biggest(table, needle)
        if size is None:
            if must_exist:
                failures.append(f"{needle}: not found (renamed? update tools/check_stack_frames.py)")
            continue
        if size > limit:
            failures.append(f"{needle}: frame 0x{size:x} over budget 0x{limit:x}")
    chain = sum(biggest(table, needle) or 0 for needle in CHAIN)
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
