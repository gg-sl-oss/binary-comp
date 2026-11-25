"""Function inventory and source-to-map matching."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Iterator

from binary_comp.core.mapfile import MapEntry, parse_msvc_map_by_obj
from binary_comp.core.symbols import normalize_compiled, symbol_matches, symbol_patterns_for_function

from .cpp import SourceFunctionGroup, parse_source_function_groups

if TYPE_CHECKING:
    from binary_comp.config import ProjectTarget

SOURCE_EXTENSIONS = (".cpp", ".c", ".C", ".asm")
C_SOURCE_EXTENSIONS = (".cpp", ".c", ".C")


@dataclass(frozen=True)
class FunctionGroup:
    source_path: str
    name: str
    line: int
    original_addrs: tuple[int, ...]
    rebuilt_addr: int
    rebuilt_symbol: str


def iter_source_files(
    source_dirs: Iterable[str | None],
    extensions: tuple[str, ...] = SOURCE_EXTENSIONS,
    *,
    map_skip: str | None = None,
    source_excludes: Iterable[str] = (),
    ignore_case: bool = False,
) -> Iterator[str]:
    """Files under ``source_dirs`` with one of ``extensions``, in sorted order.

    Directories whose path contains ``map_skip`` are skipped, and so are
    the files listed in ``source_excludes``. Missing directories are ignored.
    """
    excluded = {os.path.normcase(os.path.abspath(path)) for path in source_excludes}
    suffixes = tuple(extension.lower() for extension in extensions) if ignore_case else extensions
    for source_dir in source_dirs:
        if not source_dir or not os.path.isdir(source_dir):
            continue
        for root, dirs, files in os.walk(source_dir):
            dirs.sort()
            if map_skip and map_skip in root:
                continue
            for filename in sorted(files):
                name = filename.lower() if ignore_case else filename
                if not name.endswith(suffixes):
                    continue
                path = os.path.join(root, filename)
                if excluded and os.path.normcase(os.path.abspath(path)) in excluded:
                    continue
                yield path


def source_object_name(source_path: str) -> str:
    """The object file a source compiles to: ``src/door.cpp`` -> ``door.obj``."""
    return os.path.splitext(os.path.basename(source_path))[0] + ".obj"


def load_source_groups(
    source_dirs: tuple[str, ...],
    map_skip: str | None = None,
    source_excludes: tuple[str, ...] = (),
    signature_names: frozenset[str] = frozenset(),
) -> dict[str, list[SourceFunctionGroup]]:
    groups_by_source: dict[str, list[SourceFunctionGroup]] = {}
    for path in iter_source_files(source_dirs, map_skip=map_skip, source_excludes=source_excludes):
        groups = parse_source_function_groups(
            path, include_no_assembly=False, signature_names=signature_names
        )
        if groups:
            groups_by_source[path] = groups
    return groups_by_source


def object_member_name(object_file: str) -> str:
    """Return the object a map line names: `lib:dir\\member.obj` -> `member.obj`."""
    return re.split(r"[:\\/]", object_file)[-1]


def map_source_groups(
    groups_by_source: dict[str, list[SourceFunctionGroup]],
    map_path: str,
    signature_names: frozenset[str] = frozenset(),
    entries_by_obj: dict[str, list[MapEntry]] | None = None,
    toolchain: str = "msvc",
) -> tuple[list[FunctionGroup], list[tuple[str, SourceFunctionGroup]], dict[str, list[MapEntry]]]:
    if entries_by_obj is None:
        entries_by_obj = parse_msvc_map_by_obj(map_path)
    mapped: list[FunctionGroup] = []
    missing: list[tuple[str, SourceFunctionGroup]] = []

    # Map files do not agree on case: MSVC echoes the object path as the build
    # spelled it, Watcom upper-cases it, and a library member is listed as
    # `library:member.obj`.  Match on the folded member name, pooling every
    # object of that name; the function names tell them apart.
    entries_by_member: dict[str, list[MapEntry]] = {}
    for key, value in entries_by_obj.items():
        entries_by_member.setdefault(object_member_name(key).lower(), []).extend(value)
    for entries in entries_by_member.values():
        entries.sort(key=lambda entry: entry.va)

    for source_path in sorted(groups_by_source):
        obj = source_object_name(source_path)
        obj_entries = entries_by_member.get(obj.lower(), [])
        used: set[int] = set()

        for group in groups_by_source[source_path]:
            hit = None
            # Overloads are parsed with a parameter signature in the name
            # (e.g. "Foo::Bar(SpriteAction*)"). Match the map entry whose
            # demangled signature is identical, so the greedy name-only fallback
            # below never pairs an overload's source with the wrong rebuilt entry.
            if "(" in group.name:
                for idx, entry in enumerate(obj_entries):
                    if idx in used:
                        continue
                    if normalize_compiled(entry.symbol, signature_names) == group.name:
                        hit = (idx, entry)
                        break

            if hit is None:
                patterns = symbol_patterns_for_function(group.name, toolchain)
                # The loose match accepts any symbol a pattern is a prefix of,
                # which is what finds a decorated name, but it also lets a
                # routine claim the entry of one whose name merely extends it:
                # `stores_` matches `stores_ctrl_`.  Look for a symbol a
                # pattern names outright first, and fall back only when the
                # object has none.
                for exact_only in (True, False):
                    for idx, entry in enumerate(obj_entries):
                        if idx in used:
                            continue
                        if (entry.symbol in patterns if exact_only
                                else symbol_matches(entry.symbol, patterns)):
                            hit = (idx, entry)
                            break
                    if hit is not None:
                        break
            if hit is None:
                missing.append((source_path, group))
                continue

            idx, entry = hit
            used.add(idx)
            original_addrs = tuple(int(addr, 16) for addr in group.addresses)
            mapped.append(FunctionGroup(
                source_path=source_path,
                name=group.name,
                line=group.line,
                original_addrs=original_addrs,
                rebuilt_addr=entry.va,
                rebuilt_symbol=entry.symbol,
            ))

    return mapped, missing, entries_by_obj


def build_source_function_address_map(
    target: ProjectTarget,
    function_addresses: dict | None = None,
) -> dict[int, int]:
    """Map each annotated original function address to its rebuilt address."""
    if target.kind in ("dos32-omf", "le"):
        from binary_comp.config import parse_int
        from binary_comp.core.le import LEImage
        from binary_comp.core.mapfile import parse_watcom_map_symbols
        from binary_comp.source.cpp import parse_source_functions

        image = LEImage(target.rebuilt_exe)
        symbols: dict[str, set[int]] = {}
        for entry in parse_watcom_map_symbols(target.map_path, image.segment_bases()):
            symbols.setdefault(entry.symbol, set()).add(entry.va)
        mapping: dict[int, int] = {}
        for path in iter_source_files(target.source_dirs, (".c", ".cc", ".cpp", ".cxx"), ignore_case=True):
            for function in parse_source_functions(path):
                names = (function.name, function.name + "_", "_" + function.name, function.name.upper())
                matches = set().union(*(symbols.get(name, set()) for name in names))
                if len(matches) == 1:
                    mapping[int(function.address, 16)] = next(iter(matches))
        for name, address in (function_addresses or {}).items():
            names = (name, name + "_", "_" + name, name.upper())
            matches = set().union(*(symbols.get(symbol, set()) for symbol in names))
            if len(matches) == 1:
                mapping[parse_int(address, f"globals.function_addresses.{name}")] = next(iter(matches))
        return mapping
    groups_by_source = load_source_groups(
        target.source_dirs,
        target.map_skip,
        target.source_excludes,
    )
    mapped_groups, _, _ = map_source_groups(groups_by_source, target.map_path)
    mapping: dict[int, int] = {}
    for group in mapped_groups:
        for address in group.original_addrs:
            mapping[address] = group.rebuilt_addr
    return mapping
