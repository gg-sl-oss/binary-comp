#!/usr/bin/env python3
"""Generate small Ghidra-style disassembly exports for the MSVC example."""

from __future__ import annotations

import argparse
from pathlib import Path

from binary_comp.core.disasm import disassemble_x86
from binary_comp.core.mapfile import function_starts_from_map, parse_msvc_map_by_obj
from binary_comp.core.pe import PEImage


PADDING_MNEMONICS = frozenset({"nop", "int3"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", help="Original PE executable")
    parser.add_argument("map", help="Original linker map")
    parser.add_argument("out_dir", help="Directory for FUN_*.disassembled.txt exports")
    parser.add_argument(
        "--object",
        default="original.obj",
        help="Object file whose public functions should be exported",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    image = PEImage(args.exe)
    entries_by_obj = parse_msvc_map_by_obj(args.map)
    starts = function_starts_from_map(entries_by_obj)
    selected = [
        entry
        for entries in entries_by_obj.values()
        for entry in entries
        if entry.object_file.lower() == args.object.lower()
    ]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old_file in out_dir.glob("FUN_*.disassembled.txt"):
        old_file.unlink()

    for entry in selected:
        instructions = disassemble_x86(
            image,
            entry.va,
            starts,
            max_bytes=0x10000,
            padding_mnemonics=PADDING_MNEMONICS,
            trim_msvc_seh=False,
            remove_jump_tables=True,
        )
        path = out_dir / f"FUN_{entry.va:08X}.disassembled.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(f"Function: FUN_{entry.va:08X}\n")
            f.write(f"Address: 0x{entry.va:08X}\n\n")
            for instruction in instructions:
                f.write(f"{instruction.raw}\n")

    print(f"wrote {len(selected)} code exports to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
