"""MSVC linker map parsing."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class MapEntry:
    va: int
    symbol: str
    object_file: str


@dataclass(frozen=True)
class EncodedAddressMapEntry:
    original_va: int
    rebuilt_va: int
    symbol: str
    object_file: str | None


@dataclass(frozen=True)
class MapSymbol:
    """A single ``segment:offset symbol va [f] [object]`` map line."""

    segment: int
    va: int
    symbol: str
    is_function: bool
    object_file: str | None


ENCODED_ADDRESS_SUFFIX_RE = re.compile(
    r"_([0-9a-fA-F]{6,8})(?:@@\S*)?$"
)
ANY_SEGMENT_SYMBOL_LINE_RE = re.compile(
    r"^\s*(?P<segment>[0-9a-fA-F]{4}):[0-9a-fA-F]+\s+(?P<symbol>\S+)\s+(?P<va>[0-9a-fA-F]{8})(?P<rest>.*)$"
)


@dataclass(frozen=True)
class _MapLine:
    """One ``ssss:oooooooo symbol va [flags] [object]`` line, as written."""

    segment: int
    va: int
    symbol: str
    rest: tuple[str, ...]


def _read_msvc_map(map_path: str) -> tuple[_MapLine, ...]:
    """Every symbol line of an MSVC map in file order; empty if it is missing.

    Several analyzers ask for the same map in one run, so the parse is cached
    and only redone when the file changes (for example after a rebuild).
    """
    try:
        stat = os.stat(map_path)
    except OSError:
        return ()
    return _read_msvc_map_cached(map_path, stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=8)
def _read_msvc_map_cached(map_path: str, _mtime_ns: int, _size: int) -> tuple[_MapLine, ...]:
    lines: list[_MapLine] = []
    with open(map_path, "r", encoding="latin1", errors="ignore") as f:
        for line in f:
            match = ANY_SEGMENT_SYMBOL_LINE_RE.match(line)
            if not match:
                continue
            lines.append(_MapLine(
                segment=int(match.group("segment"), 16),
                va=int(match.group("va"), 16),
                symbol=match.group("symbol"),
                rest=tuple(match.group("rest").split()),
            ))
    return tuple(lines)


def parse_msvc_map_by_obj(map_path: str) -> dict[str, list[MapEntry]]:
    """Code symbols by object file: segment 0001 lines written ``f <name>.obj``.

    Lines with more flags (``f i <name>.obj`` for inline functions) are left
    out, as they always have been.
    """
    entries_by_obj: dict[str, list[MapEntry]] = {}
    for line in _read_msvc_map(map_path):
        if line.segment != 1 or len(line.rest) < 2 or line.rest[0] != "f":
            continue
        object_file = line.rest[1]
        if len(object_file) <= len(".obj") or not object_file.endswith(".obj"):
            continue
        entries_by_obj.setdefault(object_file, []).append(MapEntry(line.va, line.symbol, object_file))

    for entries in entries_by_obj.values():
        entries.sort(key=lambda entry: entry.va)
    return entries_by_obj


def function_starts_from_map(entries_by_obj: dict[str, list[MapEntry]]) -> list[int]:
    starts = {entry.va for entries in entries_by_obj.values() for entry in entries}
    return sorted(starts)


def parse_msvc_map_symbols(map_path: str) -> list[MapSymbol]:
    """All map symbols across every segment, sorted by address.

    ``parse_msvc_map_by_obj`` only reports code symbols from segment 0001.
    Vtables live in the CONST segment, so the vtable checks need the wider
    view. Returns an empty list when the map is missing.
    """
    symbols = [
        MapSymbol(
            segment=line.segment,
            va=line.va,
            symbol=line.symbol,
            is_function=bool(line.rest) and line.rest[0] == "f",
            object_file=next((token for token in line.rest if token.endswith(".obj")), None),
        )
        for line in _read_msvc_map(map_path)
    ]
    symbols.sort(key=lambda entry: (entry.va, entry.symbol))
    return symbols


def parse_encoded_address_map(map_path: str) -> dict[int, int]:
    """Map original encoded-address symbol suffixes to rebuilt addresses.

    Reimplementation projects often preserve the original address in global
    names, for example ``g_Table_00402000``. MSVC map output then provides the
    rebuilt VA for that symbol. This parser is intentionally narrow: it only
    returns symbols whose names contain a 6-8 digit hex suffix.
    """
    mapping: dict[int, int] = {}
    for entry in parse_encoded_address_symbols(map_path):
        mapping[entry.original_va] = entry.rebuilt_va
    return mapping


def parse_encoded_address_symbols(map_path: str) -> list[EncodedAddressMapEntry]:
    """Return rebuilt map symbols whose names encode an original address.

    ``object_file`` is the first token after the address, which is the ``f``
    flag rather than the object for function symbols.
    """
    entries: list[EncodedAddressMapEntry] = []
    for line in _read_msvc_map(map_path):
        address_match = ENCODED_ADDRESS_SUFFIX_RE.search(line.symbol)
        if not address_match:
            continue
        entries.append(EncodedAddressMapEntry(
            original_va=int(address_match.group(1), 16),
            rebuilt_va=line.va,
            symbol=line.symbol,
            object_file=line.rest[0] if line.rest else None,
        ))

    entries.sort(key=lambda entry: (entry.original_va, entry.symbol, entry.rebuilt_va))
    return entries


WATCOM_MODULE_RE = re.compile(r"^Module:\s+(\S+)", re.IGNORECASE)
# The map flags each symbol in place: `*` unreferenced, `+` referenced only
# within its own module.  Both sit against the address, not the name.
WATCOM_SYMBOL_RE = re.compile(
    r"^(?P<segment>[0-9a-fA-F]{4}):(?P<offset>[0-9a-fA-F]{8})[*+]?\s+(?P<symbol>\S+)")


def parse_watcom_map_symbols(map_path: str, segment_bases: dict[int, int]) -> list[MapSymbol]:
    """Read code and data symbols using the linked image's object bases."""
    if not os.path.isfile(map_path):
        return []
    symbols: list[MapSymbol] = []
    current = None
    with open(map_path, encoding="latin1") as handle:
        for line in handle:
            module = WATCOM_MODULE_RE.match(line.strip())
            if module:
                current = module.group(1).split("(")[0].replace("\\", "/")
                continue
            hit = WATCOM_SYMBOL_RE.match(line.strip())
            if current is None or hit is None:
                continue
            segment = int(hit.group("segment"), 16)
            if segment in segment_bases:
                symbols.append(MapSymbol(segment, segment_bases[segment] + int(hit.group("offset"), 16),
                                         hit.group("symbol"), segment == 1, current))
    return symbols


def parse_watcom_map_by_obj(
    map_path: str,
    segment_bases: dict[int, int],
    code_segment: int = 1,
) -> dict[str, list[MapEntry]]:
    """Parse a Watcom linker map into per-object symbol lists.

    Watcom writes `Module: DIR\\NAME.OBJ(source)` headers followed by
    `ssss:oooooooo symbol` lines, where the segment number indexes the image's
    object table.  Only the code segment carries functions, so the rest is
    skipped; `segment_bases` supplies the load address each segment gets.
    """
    entries_by_obj: dict[str, list[MapEntry]] = {}
    if not os.path.exists(map_path):
        return entries_by_obj

    current: str | None = None
    with open(map_path, "r", encoding="latin1", errors="ignore") as handle:
        for line in handle:
            module = WATCOM_MODULE_RE.match(line.strip())
            if module:
                name = module.group(1).split("(")[0]
                current = os.path.basename(name.replace("\\", "/")).lower()
                continue
            if current is None:
                continue
            hit = WATCOM_SYMBOL_RE.match(line.strip())
            if not hit:
                continue
            segment = int(hit.group("segment"), 16)
            if segment != code_segment:
                continue
            base = segment_bases.get(segment)
            if base is None:
                continue
            entries_by_obj.setdefault(current, []).append(MapEntry(
                va=base + int(hit.group("offset"), 16),
                symbol=hit.group("symbol"),
                object_file=current,
            ))
    return entries_by_obj
