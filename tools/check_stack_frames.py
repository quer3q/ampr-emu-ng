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

No function anywhere in the PRX may have a frame of 16 KiB (0x4000) or
more: the target has no stack probes, so such a frame would step over a
runtime thread stack's 16 KiB guard page (rt/thread_stack.rs) without a
fault. The largest frame is 0x26d8 (the pinned AIO submit below).

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
# Names are v0-mangled Rust paths, each segment `<len><name>`.
FRAME_BUDGETS = [
    # The load state check every packed open makes. Inlined into callers.
    (r"ensure_manifest_ready", 0x100, False, "inlined / inlined"),
    (r"ensure_manifest_loaded", 0x100, True, "0x18 / 0x18"),
    (r"4save22save_icon_by_path_emul", 0x600, True, "0x458 (open inlined) / 0xc8"),
    # The open hooks: open_with is inlined into posix_open_emul in release.
    (r"5index(9open_with|15posix_open_emul)", 0x600, True, "0x430 / 0x438"),
    (r"5index13open_resolved$", 0x600, True, "0x428 / 0x428"),
    (r"5index15lookup_resident$", 0x600, True, "0x470 / 0x470"),
]

# Frames summed along the packed save icon open chain, each function once
# (the release build counts the inlined open twice, so this is an upper
# bound there). 0xcc8 release, 0x940 debug today; v0.3.5 about 0x630.
CHAIN = [
    r"4save22save_icon_by_path_emul",
    r"5index(9open_with|15posix_open_emul)",
    r"5index13open_resolved$",
    r"ensure_manifest_loaded",
]
CHAIN_BUDGET = 0x1000

# Frames summed along a packed POSIX read (read, pread, readv, preadv),
# which queues its pack jobs and waits on the caller's own thread
# (rt/pack/fd_read.rs `read_on_workers`), each function once. 0x720
# release, 0x720 debug, with `ensure_workers_locked` counted (the first
# worker now starts at startup, rt/pack/worker.rs `start_first_worker`). Before,
# a read thread took the call because the AIO API path needed about 32 KB.
READ_CHAIN = [
    r"7fd_read(12virtual_read|13virtual_pread)$",
    r"7fd_read12read_slot_at$",
    r"7fd_read15read_on_workers$",
    # The submit and the wait run one after the other under read_on_workers;
    # both are counted, so the sum is an upper bound. A frame the compiler
    # inlined is in its caller's and matches nothing here.
    r"7fd_read11submit_sync$",
    r"7fd_read18submit_sync_locked$",
    r"7fd_read9wait_sync$",
    r"3aio30prepare_virtual_request_locked$",
    r"10pack_split25split_virtual_read_locked$",
    r"6worker21ensure_workers_locked$",
    r"8schedule17queue_push_locked$",
]
READ_CHAIN_BUDGET = 0x1000

# The save icon hook reads a packed icon (rt/save.rs `read_packed`):
# after the open returns, a packed read runs on the game's save thread
# under the hook's own frames, each function once.
ICON_READ_CHAIN = [
    r"4save22save_icon_by_path_emul",
    r"4save11read_packed",
    r"4save12read_to_heap",
] + READ_CHAIN
FRAME_BUDGETS += [
    (r"7fd_read15read_on_workers$", 0x600, True, "0x2e8 / 0x2e8"),
    (r"3aio30prepare_virtual_request_locked$", 0x400, True, "0x218 / 0x208"),
]

# Frames summed under a module loader hook (rt/hook.rs `load_observe`),
# which runs on the game thread that loads a module, when it installs the
# save data hooks the module brings, each function once. The load with its
# 1 KiB path buffer (`load_resolved`) returns before the install starts, so
# it is budgeted alone. The iced-x86 table setup runs on the first decode,
# at module_start in practice; it is counted, so the sum is an upper bound.
# Before the split and the static module list: 0xe50 release, 0xfe0 debug
# (load_observe 0x428 / 0x5c8, install_external 0x428, install 0x488).
LOADER_CHAIN = [
    r"4hook12load_observe$",
    r"4hook14observe_loaded$",
    r"4hook19install_save_listed$",
    r"4hook12install_save$",
    r"4hook7install$",
    r"4hook16install_writable$",
    r"8iced_x867decoder8table_de.*13read_handlers$",
    r"17TableDeserializer11deserialize$",
    r"17TableDeserializer29read_handler_or_null_instance$",
]
LOADER_CHAIN_BUDGET = 0x1000
FRAME_BUDGETS += [
    (r"4hook13load_resolved$", 0x600, True, "0x428 / 0x428"),
    (r"4hook14observe_loaded$", 0x100, True, "0x0 / 0x0"),
    (r"4hook7install$", 0x600, True, "0x488 / 0x488"),
]

# Large frames kept as they are, pinned so they cannot grow unnoticed. The
# AIO emulation holds arrays for 128 requests; it is reached for the game's
# own AIO calls on a packed fd and the reactor's APR submits (reactor/mod.rs,
# reactor/flush.rs), never for a POSIX read.
PINNED = [
    (r"3aio38sceKernelAioSubmitReadCommandsMultiple$", 0x3800, True, "0x26d8 / 0x26d8"),
    (r"3aio20publish_virtual_jobs", 0x800, True, "0x18 / 0x18"),
]

# Any frame this size or larger fails: it would step over a 16 KiB guard
# page (no stack probes on the target).
GUARD_FRAME = 0x4000

SUB_RSP = re.compile(r"subq\s+\$0x([0-9a-f]+), %rsp")
HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:")


def frames(objdump: str, prx: Path) -> dict[str, int]:
    out = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(prx)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # A function that only pushes registers has no `sub` and a frame of 0
    # here; it is still listed, so a must-exist name like that is found.
    result: dict[str, int] = {}
    measured: set[str] = set()
    current = None
    for line in out.splitlines():
        header = HEADER.match(line)
        if header:
            current = header.group(1)
            result.setdefault(current, 0)
            continue
        found = SUB_RSP.search(line)
        if found and current and current not in measured:
            measured.add(current)
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
    for name, size in sorted(table.items()):
        if size >= GUARD_FRAME:
            failures.append(f"{name}: frame 0x{size:x} reaches the guard page size 0x{GUARD_FRAME:x}")
    chain = sum(biggest(table, pattern) or 0 for pattern in CHAIN)
    if chain > CHAIN_BUDGET:
        failures.append(f"packed open chain: 0x{chain:x} over budget 0x{CHAIN_BUDGET:x}")
    read_chain = sum(biggest(table, pattern) or 0 for pattern in READ_CHAIN)
    if read_chain > READ_CHAIN_BUDGET:
        failures.append(
            f"packed read chain: 0x{read_chain:x} over budget 0x{READ_CHAIN_BUDGET:x}"
        )

    icon_chain = sum(biggest(table, pattern) or 0 for pattern in ICON_READ_CHAIN)
    if icon_chain > READ_CHAIN_BUDGET:
        failures.append(
            f"save icon read chain: 0x{icon_chain:x} over budget 0x{READ_CHAIN_BUDGET:x}"
        )

    loader_chain = sum(biggest(table, pattern) or 0 for pattern in LOADER_CHAIN)
    if loader_chain > LOADER_CHAIN_BUDGET:
        failures.append(
            f"module loader chain: 0x{loader_chain:x} over budget 0x{LOADER_CHAIN_BUDGET:x}"
        )

    if failures:
        print(f"stack frame budget exceeded in {args.prx}:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"stack frames ok: {args.prx} (open chain 0x{chain:x} of 0x{CHAIN_BUDGET:x}, "
        f"read chain 0x{read_chain:x} of 0x{READ_CHAIN_BUDGET:x}, "
        f"icon read chain 0x{icon_chain:x} of 0x{READ_CHAIN_BUDGET:x}, "
        f"loader chain 0x{loader_chain:x} of 0x{LOADER_CHAIN_BUDGET:x})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
