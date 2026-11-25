"""Reading and writing Ghidra-style function exports.

Ghidra (``ghidra_scripts/ExportToCompile.java``) and ``binary-comp export-asm``
write one file per original function, named ``FUN_XXXXXXXX.disassembled.txt``
with the entry address as eight upper-case hex digits::

    Function: <name, or FUN_XXXXXXXX when Ghidra has none>
    Address: 0xXXXXXXXX
    <blank line>
    <one instruction per line; "LAB_XXXXXXXX:" lines mark internal branch
     targets and gaps between body ranges>

Ghidra also writes ``FUN_XXXXXXXX.decompiled.txt`` with the same header.

These files are used as a function-boundary and name inventory only.
Operand-level semantics must come from disassembling the binary itself.
Change the format here and in the Java script together.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass


EXPORT_SUFFIX = ".disassembled.txt"
DECOMPILED_SUFFIX = ".decompiled.txt"
EXPORT_GLOB = f"FUN_*{EXPORT_SUFFIX}"
HEADER_LINES = 3
HEADER_PREFIXES = ("Function:", "Address:")

FUN_DISASSEMBLY_RE = re.compile(r"FUN_([0-9A-Fa-f]+)\.disassembled\.txt$")
_ADDRESS_HEADER_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]+)")
_FUNCTION_HEADER_RE = re.compile(r"Function:\s*(.+?)\s*$")


@dataclass(frozen=True)
class ExportHeader:
    name: str | None
    address: int | None


def export_filename(address: int, suffix: str = EXPORT_SUFFIX) -> str:
    return f"FUN_{address:08X}{suffix}"


def export_path(code_dir: str, address: int) -> str:
    """Where the export for ``address`` is written; it may not exist yet."""
    return os.path.join(code_dir, export_filename(address))


def find_export(code_dir: str | None, address: int) -> str | None:
    """The existing export for ``address``, or None.

    Ghidra pads to eight digits, but hand-made and older exports use six
    digits, no padding, or lower case, so all of those are accepted.
    """
    if not code_dir:
        return None
    seen: set[str] = set()
    for digits in (f"{address:08X}", f"{address:06X}", f"{address:X}"):
        for spelling in (digits, digits.lower()):
            name = f"FUN_{spelling}{EXPORT_SUFFIX}"
            if name in seen:
                continue
            seen.add(name)
            path = os.path.join(code_dir, name)
            if os.path.exists(path):
                return path
    return None


def resolve_export(code_dir: str | None, address: int) -> str | None:
    """The existing export for ``address``, else where it would be written."""
    if not code_dir:
        return None
    return find_export(code_dir, address) or export_path(code_dir, address)


def address_from_filename(path: str) -> int | None:
    match = FUN_DISASSEMBLY_RE.search(os.path.basename(path))
    return int(match.group(1), 16) if match else None


def iter_exports(code_dir: str | None) -> list[tuple[int, str]]:
    """Every ``FUN_*.disassembled.txt`` export as (address, path), by filename."""
    if not code_dir or not os.path.isdir(code_dir):
        return []
    exports = []
    for path in sorted(glob.glob(os.path.join(code_dir, EXPORT_GLOB))):
        address = address_from_filename(path)
        if address is not None:
            exports.append((address, path))
    return exports


def function_starts_from_export_dir(code_dir: str | None) -> list[int]:
    return sorted({address for address, _ in iter_exports(code_dir)})


def read_export_header(path: str) -> ExportHeader:
    """The ``Function:`` and ``Address:`` header lines; missing parts are None."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = [f.readline() for _ in range(HEADER_LINES)]
    except OSError:
        return ExportHeader(None, None)
    name = None
    address = None
    for line in head:
        if name is None and (match := _FUNCTION_HEADER_RE.match(line)):
            name = match.group(1).strip()
        if address is None and (match := _ADDRESS_HEADER_RE.match(line)):
            address = int(match.group(1), 16)
    return ExportHeader(name, address)


def export_address(path: str) -> int | None:
    """The original address of an export: from its filename, else its header."""
    address = address_from_filename(path)
    if address is not None:
        return address
    return read_export_header(path).address


def read_export_body(path: str) -> list[str]:
    """The lines after the three-line header, or [] if the file is unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().splitlines()[HEADER_LINES:]
    except OSError:
        return []


def render_export_header(name: str | None, address: int) -> list[str]:
    return [
        f"Function: {name or export_filename(address, '')}",
        f"Address: 0x{address:08X}",
        "",
    ]
