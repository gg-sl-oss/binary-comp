"""Function boundaries and disassembly for the values analyzer."""

from __future__ import annotations

import os

from binary_comp.core.disasm import (
    Instruction,
    disassemble_x86,
    is_branch_or_call,
    next_boundary,
    switch_jump_table_ranges,
    trim_leading_stack_probe,
    unsigned32,
)
from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy
from binary_comp.source.functions import FunctionGroup


def load_boundary_file(path: str | None) -> set[int]:
    """Read a plain list of original function addresses.

    A Ghidra export supplies boundaries for projects that have one; a project
    that located its functions some other way can hand over the addresses
    directly.  One address per line, `#` starts a comment, anything else on the
    line is ignored so a locator report can be filtered into it unchanged."""
    starts: set[int] = set()
    if not path or not os.path.exists(path):
        return starts
    with open(path, "r", encoding="latin1", errors="ignore") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                starts.add(int(line.split()[0], 16))
            except ValueError:
                continue
    return starts


def load_original_boundary_starts(
    code_dir: str | None,
    function_groups: list[FunctionGroup],
    boundary_file: str | None = None,
) -> list[int]:
    starts = set(function_starts_from_export_dir(code_dir))
    starts |= load_boundary_file(boundary_file)
    for group in function_groups:
        starts.update(group.original_addrs)
    return sorted(starts)


def leading_successor_switch_table_start(
    image: PEImage,
    start: int,
    starts: set[int],
    policy: VerifierPolicy,
) -> int | None:
    """Find a jump table emitted immediately before its owning function.

    Watcom can place a function's switch table before the public function
    symbol.  Without recognizing that ownership, the table is decoded as the
    tail of the preceding function and can look like valid control flow by
    accident.  The successor's own indirect jump and in-successor case targets
    provide evidence for moving the comparison boundary to the table start.
    """
    ordered = sorted(starts)
    successor_start = next_boundary(ordered, start)
    if successor_start is None:
        return None

    section_end = image.section_end_for_va(successor_start)
    if section_end is None:
        return None
    successor_end = next_boundary(ordered, successor_start)
    if successor_end is None or successor_end > section_end:
        successor_end = section_end
    successor_end = min(successor_end, successor_start + policy.max_disassembly_bytes)
    if successor_end <= successor_start:
        return None

    successor_instrs = disassemble_x86(
        image,
        successor_start,
        ordered,
        max_bytes=policy.max_disassembly_bytes,
        padding_mnemonics=policy.padding_mnemonics,
    )
    ranges = switch_jump_table_ranges(
        image,
        successor_instrs,
        successor_start,
        successor_end,
        table_bounds=(start, successor_start),
    )
    return min((lo for lo, _ in ranges), default=None)


def disassemble(image: PEImage, start: int, starts: list[int], policy: VerifierPolicy) -> list[Instruction]:
    boundaries = set(starts)
    leading_table = leading_successor_switch_table_start(image, start, boundaries, policy)
    if leading_table is not None:
        boundaries.add(leading_table)
    for _ in range(8):
        instructions = disassemble_x86(
            image,
            start,
            sorted(boundaries),
            max_bytes=policy.max_disassembly_bytes,
            padding_mnemonics=policy.padding_mnemonics,
        )
        instructions = trim_leading_stack_probe(instructions)
        fragment = contiguous_tail_fragment_start(instructions, boundaries)
        if fragment is None:
            return instructions
        boundaries.remove(fragment)
    return instructions


def contiguous_tail_fragment_start(
    instructions: list[Instruction],
    boundaries: set[int],
) -> int | None:
    """Find a Ghidra-split continuation immediately following a function.

    Some optimized class predicates branch into a contiguous shared tail that
    Ghidra exported as a second function.  Treat that target as part of the
    caller when the current fragment both reaches it directly and ends exactly
    at the boundary.  This does not merge an ordinary adjacent function merely
    because it follows in address order.
    """
    if not instructions:
        return None
    end = max(instr.address + instr.size for instr in instructions)
    if end not in boundaries:
        return None
    for instr in instructions:
        if (
            is_branch_or_call(instr.mnemonic)
            and instr.mnemonic != "call"
            and instr.operands
            and instr.operands[0].kind == "imm"
            and unsigned32(instr.operands[0].imm) == end
        ):
            return end
    return None
