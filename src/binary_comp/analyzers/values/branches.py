"""Conditional-branch layout and integer comparison relations."""

from __future__ import annotations

from binary_comp.core.disasm import Instruction, signed32, unsigned32
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.calls import call_signature
from binary_comp.analyzers.values.operands import (
    immediate_operands,
    is_conditional_branch_mnemonic,
    member_displacement,
    mnemonic_sequence_similarity,
)
from binary_comp.analyzers.values.stream import instruction_positions


def following_flag_branch_mnemonic(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 5,
) -> str | None:
    """Find the branch consuming flags while allowing flag-neutral scheduling."""
    flag_neutral = {"mov", "lea", "push", "pop", "nop", "xchg"}
    for instr in instrs[idx + 1:idx + 1 + max_steps]:
        if is_conditional_branch_mnemonic(instr.mnemonic):
            return instr.mnemonic
        if instr.mnemonic not in flag_neutral:
            return None
    return None


def complemented_branch_mnemonic(mnemonic: str) -> str | None:
    complements = {
        "jz": "jnz",
        "jnz": "jz",
        "jc": "jnc",
        "jnc": "jc",
        "ja": "jbe",
        "jbe": "ja",
        "jnle": "jng",
        "jng": "jnle",
        "jnl": "jnge",
        "jnge": "jnl",
        "jo": "jno",
        "jno": "jo",
        "js": "jns",
        "jns": "js",
        "jp": "jnp",
        "jnp": "jp",
    }
    return complements.get(mnemonic)


def branch_successor_mnemonics(
    instrs: list[Instruction],
    branch_idx: int,
    taken: bool,
    max_instructions: int = 24,
) -> list[str]:
    if branch_idx < 0 or branch_idx >= len(instrs):
        return []
    branch = instrs[branch_idx]
    by_addr = instruction_positions(instrs)
    if taken:
        if not branch.operands or branch.operands[0].kind != "imm":
            return []
        pos = by_addr.get(unsigned32(branch.operands[0].imm))
    else:
        pos = branch_idx + 1

    result: list[str] = []
    seen: set[int] = set()
    while pos is not None and 0 <= pos < len(instrs) and len(result) < max_instructions:
        if pos in seen:
            break
        seen.add(pos)
        instr = instrs[pos]
        if instr.mnemonic == "jmp" and instr.operands and instr.operands[0].kind == "imm":
            pos = by_addr.get(unsigned32(instr.operands[0].imm))
            continue

        result.append(instr.mnemonic)
        if instr.mnemonic == "ret" or is_conditional_branch_mnemonic(instr.mnemonic):
            break
        pos += 1
    return result


def branch_successor_effects(
    instrs: list[Instruction],
    branch_idx: int,
    taken: bool,
    policy: VerifierPolicy,
    max_instructions: int = 24,
) -> list[tuple]:
    """Describe stable side effects along one branch edge.

    Register allocation and loop-tail scheduling make mnemonic sequences a
    weak signal for an inverted layout.  Member stores and calls survive those
    changes and identify which edge performs the work.
    """
    if branch_idx < 0 or branch_idx >= len(instrs):
        return []
    branch = instrs[branch_idx]
    by_addr = instruction_positions(instrs)
    if taken:
        if not branch.operands or branch.operands[0].kind != "imm":
            return []
        pos = by_addr.get(unsigned32(branch.operands[0].imm))
    else:
        pos = branch_idx + 1

    result: list[tuple] = []
    seen: set[int] = set()
    steps = 0
    while pos is not None and 0 <= pos < len(instrs) and steps < max_instructions:
        if pos in seen:
            break
        seen.add(pos)
        steps += 1
        instr = instrs[pos]
        if instr.mnemonic == "jmp" and instr.operands and instr.operands[0].kind == "imm":
            pos = by_addr.get(unsigned32(instr.operands[0].imm))
            continue
        if instr.mnemonic == "call":
            signature = call_signature(instr)
            if signature is not None:
                result.append(("call", signature))
        elif instr.operands and instr.operands[0].kind == "mem":
            destination = instr.operands[0]
            if member_displacement(destination.disp, policy):
                result.append(("write", destination.disp, destination.size))
        if instr.mnemonic == "ret" or is_conditional_branch_mnemonic(instr.mnemonic):
            break
        pos += 1
    return result


def equivalent_reordered_branch_layout(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_branch_idx: int,
    original_branch_idx: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = compiled_instrs[compiled_branch_idx]
    original = original_instrs[original_branch_idx]
    c_taken = branch_successor_mnemonics(compiled_instrs, compiled_branch_idx, True)
    c_fallthrough = branch_successor_mnemonics(compiled_instrs, compiled_branch_idx, False)
    o_taken = branch_successor_mnemonics(original_instrs, original_branch_idx, True)
    o_fallthrough = branch_successor_mnemonics(original_instrs, original_branch_idx, False)

    cross_scores = (
        mnemonic_sequence_similarity(c_taken, o_fallthrough),
        mnemonic_sequence_similarity(c_fallthrough, o_taken),
    )
    same_scores = (
        mnemonic_sequence_similarity(c_taken, o_taken),
        mnemonic_sequence_similarity(c_fallthrough, o_fallthrough),
    )
    required_margin = (
        0.35 if complemented_branch_mnemonic(compiled.mnemonic) == original.mnemonic else 0.15
    )
    if (
        max(cross_scores) >= 0.85
        and sum(cross_scores) >= sum(same_scores) + required_margin
    ):
        return True

    if complemented_branch_mnemonic(compiled.mnemonic) != original.mnemonic:
        return False
    c_taken_effects = branch_successor_effects(compiled_instrs, compiled_branch_idx, True, policy)
    c_fallthrough_effects = branch_successor_effects(compiled_instrs, compiled_branch_idx, False, policy)
    o_taken_effects = branch_successor_effects(original_instrs, original_branch_idx, True, policy)
    o_fallthrough_effects = branch_successor_effects(original_instrs, original_branch_idx, False, policy)
    cross_effect_match = (
        bool(c_taken_effects)
        and c_taken_effects == o_fallthrough_effects
    ) or (
        bool(c_fallthrough_effects)
        and c_fallthrough_effects == o_taken_effects
    )
    same_effect_match = (
        bool(c_taken_effects)
        and c_taken_effects == o_taken_effects
    ) or (
        bool(c_fallthrough_effects)
        and c_fallthrough_effects == o_fallthrough_effects
    )
    return cross_effect_match and not same_effect_match


def comparison_relation(mnemonic: str) -> str | None:
    aliases = {
        "je": "eq",
        "jz": "eq",
        "jne": "ne",
        "jnz": "ne",
        "jl": "lt",
        "jnge": "lt",
        "jle": "le",
        "jng": "le",
        "jg": "gt",
        "jnle": "gt",
        "jge": "ge",
        "jnl": "ge",
        "jb": "ltu",
        "jnae": "ltu",
        "jbe": "leu",
        "jna": "leu",
        "ja": "gtu",
        "jnbe": "gtu",
        "jae": "geu",
        "jnb": "geu",
    }
    return aliases.get(mnemonic.lower())


def reverse_comparison_relation(relation: str) -> str:
    return {
        "eq": "eq",
        "ne": "ne",
        "lt": "gt",
        "le": "ge",
        "gt": "lt",
        "ge": "le",
        "ltu": "gtu",
        "leu": "geu",
        "gtu": "ltu",
        "geu": "leu",
    }[relation]


def integer_comparison_interval(
    relation: str,
    value: int,
) -> tuple[int, int] | None:
    """Return the inclusive integer interval selected by a comparison branch."""
    if relation.endswith("u"):
        minimum, maximum = 0, 0xFFFFFFFF
        value = unsigned32(value)
        relation = relation[:-1]
    else:
        minimum, maximum = -0x80000000, 0x7FFFFFFF
        value = signed32(value)

    if relation == "eq":
        return value, value
    if relation == "lt":
        return minimum, value - 1
    if relation == "le":
        return minimum, value
    if relation == "gt":
        return value + 1, maximum
    if relation == "ge":
        return value, maximum
    return None


def complementary_integer_intervals(
    left: tuple[int, int],
    right: tuple[int, int],
) -> bool:
    return (
        left[0] == right[1] + 1
        and right[0] in {0, -0x80000000}
        and left[1] in {0x7FFFFFFF, 0xFFFFFFFF}
    ) or (
        right[0] == left[1] + 1
        and left[0] in {0, -0x80000000}
        and right[1] in {0x7FFFFFFF, 0xFFFFFFFF}
    )


def same_cmp_immediate_values(compiled: Instruction, original: Instruction) -> bool:
    c_imms = dict(immediate_operands(compiled))
    o_imms = dict(immediate_operands(original))
    if not c_imms or set(c_imms) != set(o_imms):
        return False
    return all(c_imms[idx].imm == o_imms[idx].imm for idx in c_imms)
