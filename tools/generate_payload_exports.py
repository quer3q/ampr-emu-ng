#!/usr/bin/env python3
"""Generate pre-link NID names and import providers for the Linux PRX link."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import struct
from pathlib import Path


NID_SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
EXPORT_RE = re.compile(r"sceAmpr[A-Za-z0-9_]+\Z")

# Retail libSceAmpr.sprx also exports 19 libc/libc++ symbols that it links
# statically, and titles can import them from libSceAmpr (list taken from
# AnyPS5 core/libs/prx/libSceAmpr/Export.cpp). The Rust symbol cannot reuse
# the libc name, so each is defined under its own name in
# crates/ampr-sys/src/rt/libc_exports.rs and exported under the libc NID.
# Rust symbol -> exported (NID source) name.
EXTRA_EXPORTS = {
    "ampr_libc_localeconv": "localeconv",
    "ampr_libc_udivti3": "__udivti3",
    "ampr_libc_sinh": "_Sinh",
    "ampr_libc_strtok_s": "strtok_s",
    "ampr_libc_ctime_s": "ctime_s",
    "ampr_libc_wcscpy_s": "wcscpy_s",
    "ampr_libc_set_constraint_handler_s": "set_constraint_handler_s",
    "ampr_libc_fltrounds": "_Fltrounds",
    "ampr_libc_ignore_handler_s": "ignore_handler_s",
    "ampr_libc_wcstombs_s": "wcstombs_s",
    "ampr_libc_mbstowcs": "mbstowcs",
    "ampr_libc_asctime_s": "asctime_s",
    "ampr_libc_fpclassifyd": "__fpclassifyd",
    "ampr_libc_lock_shared_ptr_spin_lock": "_Lock_shared_ptr_spin_lock",
    "ampr_libc_unlock_shared_ptr_spin_lock": "_Unlock_shared_ptr_spin_lock",
    "ampr_libc_cnd_init_with_name": "_Cnd_init_with_name",
    "ampr_libc_time_get_get":
        "_ZNKSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE3get"
        "ES3_S3_RSt8ios_baseRNSt5_IosbIiE8_IostateEP2tmPKcSE_",
    "ampr_libc_time_get_getcat":
        "_ZNSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE7_Getcat"
        "EPPKNSt6locale5facetEPKS5_",
    "ampr_libc_cxa_call_unexpected": "__cxa_call_unexpected",
}

LIBC_IMPORTS = {
    "__cxa_atexit",
    "__cxa_finalize",
    "__cxa_guard_acquire",
    "__cxa_guard_release",
    "abort",
    "calloc",
    "free",
    "gmtime_r",
    "malloc",
    "memchr",
    "memcmp",
    "memcpy",
    "memmove",
    "memset",
    "snprintf",
    "strftime",
    "strlen",
    "strnlen",
    "vsnprintf",
}

KERNEL_IMPORTS = {
    "__error",
    # BSD sockets for the debug metrics endpoint (AMPR_MEM_REPORT=1 builds).
    "accept",
    "bind",
    "listen",
    "recv",
    "send",
    "setsockopt",
    "socket",
}

METADATA_SYMBOLS = (
    "libSceLibcInternal",
    "libkernel",
    "libSceAmpr",
    "libSceAmpr.prx",
)

CRT_PROVIDED_SYMBOLS = {
    "__dso_handle",
    # Defined by the PRX linker script; referenced by the Rust CRT (crt.rs).
    "__CTOR_LIST__",
    "__CTOR_END__",
    "__DTOR_LIST__",
    "__DTOR_END__",
    "__start__Zpreinit_array",
    "__stop__Zpreinit_array",
}


def name_to_nid(name: str) -> str:
    digest = hashlib.sha1(name.encode("utf-8") + NID_SALT).digest()
    value = struct.unpack("<Q", digest[:8])[0]
    return base64.b64encode(
        value.to_bytes(8, "big"), altchars=b"+-"
    ).rstrip(b"=").decode("ascii")


def is_libc_import(name: str) -> bool:
    if name in LIBC_IMPORTS:
        return True
    if name in KERNEL_IMPORTS or name.startswith(("sceKernel", "scePthread")):
        return False
    raise ValueError(f"unclassified PRX import: {name}")


def defined_export_symbols(path: Path) -> dict[str, str]:
    """Map exported name -> Rust symbol for the nm list of the combined object."""
    defined = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    exports = {name: name for name in defined if EXPORT_RE.fullmatch(name)}
    if not exports:
        raise ValueError(f"no AMPR exports defined in {path}")
    missing = sorted(set(EXTRA_EXPORTS) - defined)
    if missing:
        raise ValueError(f"extra exports not defined in {path}: {missing}")
    for symbol, name in EXTRA_EXPORTS.items():
        exports[name] = symbol
    return dict(sorted(exports.items()))


def defined_exports(path: Path) -> list[str]:
    """Exported names (the NID sources) defined by the combined Rust object."""
    return list(defined_export_symbols(path))


def render_response(names: list[str]) -> str:
    exports = "".join(
        f'"--export-dynamic-symbol={name_to_nid(name)}#D#A"\n'
        for name in names
    )
    metadata = "".join(
        f'"--export-dynamic-symbol={name}"\n' for name in METADATA_SYMBOLS
    )
    return exports + metadata


def render_version_script(names: list[str]) -> str:
    symbols = [
        *(f"{name_to_nid(name)}#D#A" for name in names),
        *METADATA_SYMBOLS,
    ]
    globals_ = "".join(f'    "{name}";\n' for name in symbols)
    return "{\n  global:\n" + globals_ + "  local: *;\n};\n"


def render_rename_map(exports: dict[str, str], imports: list[str]) -> str:
    lines = [
        f'"--redefine-sym={symbol}={name_to_nid(name)}#D#A"'
        for name, symbol in exports.items()
    ]
    for name in imports:
        suffix = "#A#B" if is_libc_import(name) else "#B#C"
        lines.append(f'"--redefine-sym={name}={name_to_nid(name)}{suffix}"')
    return "\n".join(lines) + "\n"


def render_stub_assembly(imports: list[str], suffix: str) -> str:
    lines = ["/* Auto-generated NID import provider. */", ".text"]
    for name in imports:
        symbol = f"{name_to_nid(name)}{suffix}"
        lines.extend(
            [
                f'.globl "{symbol}"',
                f'.type "{symbol}", @function',
                f'"{symbol}":',
                "    ret",
                f'.size "{symbol}", .-"{symbol}"',
            ]
        )
    lines.append('.section .note.GNU-stack,"",@progbits')
    return "\n".join(lines) + "\n"


def render_metadata_assembly() -> str:
    lines = ["/* Auto-generated link-only SCE dynamic string markers. */", ".data"]
    for name in METADATA_SYMBOLS:
        lines.extend(
            [
                f'.globl "{name}"',
                f'.protected "{name}"',
                f'.type "{name}", @object',
                f'"{name}":',
                "    .byte 0",
                f'.size "{name}", 1',
            ]
        )
    lines.extend(['.section .note.GNU-stack,"",@progbits', ""])
    return "\n".join(lines)


def write_if_changed(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == data:
        return
    path.write_text(data, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--defined", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--version-script", type=Path, required=True)
    parser.add_argument("--undefined", type=Path, required=True)
    parser.add_argument("--rename-map", type=Path, required=True)
    parser.add_argument("--libc-asm", type=Path, required=True)
    parser.add_argument("--libc-list", type=Path, required=True)
    parser.add_argument("--kernel-asm", type=Path, required=True)
    parser.add_argument("--kernel-list", type=Path, required=True)
    parser.add_argument("--metadata-asm", type=Path, required=True)
    args = parser.parse_args()

    export_symbols = defined_export_symbols(args.defined)
    names = list(export_symbols)
    undefined_names = {
        line.strip()
        for line in args.undefined.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    imports = sorted(
        (undefined_names - set(export_symbols.values()) - CRT_PROVIDED_SYMBOLS)
        | {"__cxa_finalize"}
    )
    if not imports:
        raise ValueError("no unresolved PRX imports found")
    libc_imports = []
    kernel_imports = []
    for name in imports:
        (libc_imports if is_libc_import(name) else kernel_imports).append(name)
    write_if_changed(args.response, render_response(names))
    write_if_changed(args.version_script, render_version_script(names))
    write_if_changed(args.rename_map, render_rename_map(export_symbols, imports))
    write_if_changed(args.libc_asm, render_stub_assembly(libc_imports, "#A#B"))
    write_if_changed(args.libc_list, "\n".join(libc_imports) + "\n")
    write_if_changed(args.kernel_asm, render_stub_assembly(kernel_imports, "#B#C"))
    write_if_changed(args.kernel_list, "\n".join(kernel_imports) + "\n")
    write_if_changed(args.metadata_asm, render_metadata_assembly())
    print(
        f"generated NIDs: exports={len(names)} "
        f"libc_imports={len(libc_imports)} kernel_imports={len(kernel_imports)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
