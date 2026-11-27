"""Align two instruction streams before comparing operands."""

from __future__ import annotations

from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import Instruction
from binary_comp.core.pe import PEImage
from binary_comp.analyzers.values.model import CompareContext
from binary_comp.analyzers.values.operands import (
    immediate_operands,
    immediate_string,
    member_displacement,
    memory_operands,
    normalize_string_for_compare,
    small_numeric_immediate,
)


MIN_ALIGNED_RUN = 3


def matches_in_aligned_runs(
    matches: list[tuple[int, int]],
    minimum: int = MIN_ALIGNED_RUN,
) -> list[tuple[int, int]]:
    """Keep only pairs sitting inside a run of consecutive aligned instructions.

    An aligner asked to line up two streams that have diverged will still pair
    isolated instructions across the gap, because a lone `mov` matches any other
    `mov`.  Comparing the operands of such a pair reports a difference between
    two instructions that have nothing to do with each other.  Requiring both
    sides to step forward together for a few instructions is what distinguishes
    a real correspondence from a coincidence.
    """
    if not matches:
        return matches
    kept: list[tuple[int, int]] = []
    run = [matches[0]]
    for previous, current in zip(matches, matches[1:]):
        if current[0] == previous[0] + 1 and current[1] == previous[1] + 1:
            run.append(current)
            continue
        if len(run) >= minimum:
            kept.extend(run)
        run = [current]
    if len(run) >= minimum:
        kept.extend(run)
    return kept


def instruction_value_anchor(
    instr: Instruction,
    image: PEImage,
    context: CompareContext,
) -> tuple:
    """Build an exact-value token used only to disambiguate mnemonic ties."""
    values: list[tuple] = []
    for operand_index, operand in immediate_operands(instr):
        string = immediate_string(image, operand, context.policy)
        if string is not None:
            values.append(("string", operand_index, normalize_string_for_compare(string)))
        elif small_numeric_immediate(operand, context.policy):
            values.append(("imm", operand_index, operand.imm))
    for operand_index, operand in memory_operands(instr):
        if (
            member_displacement(operand.disp, context.policy)
            and (
                context.include_stack_locals
                or operand.base not in context.policy.stack_registers
            )
        ):
            values.append(("disp", operand_index, operand.disp))
    return (instr.mnemonic, *values)


def value_aware_align(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    context: CompareContext,
) -> list[tuple[int, int]]:
    """Prefer exact-value anchors, then align mnemonic-only gaps.

    Plain mnemonic LCS has many equally optimal solutions in switch-heavy
    functions.  It can consequently compare a call argument's load with an
    unrelated load from another case even when exact counterparts for both
    exist.  Exact tokens
    select stable anchors; mnemonic alignment inside the gaps still exposes a
    genuinely changed value instead of dropping it from comparison.
    """
    compiled_tokens = [
        instruction_value_anchor(instr, compiled_image, context)
        for instr in compiled_instrs
    ]
    original_tokens = [
        instruction_value_anchor(instr, original_image, context)
        for instr in original_instrs
    ]
    anchors = lcs_align(compiled_tokens, original_tokens)
    matches: list[tuple[int, int]] = []
    previous_c = -1
    previous_o = -1
    for anchor_c, anchor_o in [*anchors, (len(compiled_instrs), len(original_instrs))]:
        c_start = previous_c + 1
        o_start = previous_o + 1
        gap_matches = lcs_align(
            [instr.mnemonic for instr in compiled_instrs[c_start:anchor_c]],
            [instr.mnemonic for instr in original_instrs[o_start:anchor_o]],
        )
        matches.extend((c_start + ci, o_start + oi) for ci, oi in gap_matches)
        if anchor_c < len(compiled_instrs) and anchor_o < len(original_instrs):
            matches.append((anchor_c, anchor_o))
        previous_c = anchor_c
        previous_o = anchor_o
    return matches
