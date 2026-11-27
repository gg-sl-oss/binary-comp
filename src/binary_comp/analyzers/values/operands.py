"""Operand and instruction predicates the value checks are built on."""

from __future__ import annotations

from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import (
    Instruction,
    Operand,
    full_register_name,
    has_msvc_seh_frame,
    is_branch_or_call,
    unsigned32,
)
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy


def normalize_string(value: str) -> str:
    value = value.replace("\\\\", "\\")
    value = value.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    return value


def normalize_string_for_compare(value: str | None) -> str | None:
    if value is None:
        return None
    value = normalize_string(value)
    value = value.strip().strip('"').strip("\\").strip('"')
    return value


def looks_like_literal_string(value: str, policy: VerifierPolicy) -> bool:
    """Reject common false positives from decoding pointers as text."""
    for rejected in policy.rejected_string_substrings:
        if rejected in value:
            return False
    if len(value) == 1:
        return value in policy.allowed_one_char_strings
    if len(value) <= 3:
        if "%" in value:
            return True
        if value.isalpha() and (value.islower() or value.isupper()):
            return True
        return False
    return any(ch.isalpha() for ch in value)


def relocated_displacement(instr: Instruction, sites: frozenset[int]) -> bool:
    """Is this instruction's memory displacement one the loader patches?

    Then it is a global's address, not a struct member offset, and the two
    images can never agree on it.  An instruction can carry a relocated
    displacement and an honest immediate at once -- `test byte [global], 4` --
    so the two fields have to be asked about separately.
    """
    return bool(sites) and instr.disp_offset > 0 and \
        (instr.address + instr.disp_offset) in sites


def relocated_immediate(instr: Instruction, sites: frozenset[int]) -> bool:
    """Is this instruction's immediate one the loader patches?

    Then it is an unresolved address rather than a value the source chose.
    """
    return bool(sites) and instr.imm_offset > 0 and \
        (instr.address + instr.imm_offset) in sites


def operand_signature(operand: Operand) -> tuple:
    if operand.kind == "reg":
        return ("reg", operand.reg)
    if operand.kind == "mem":
        return ("mem", operand.base, operand.index, operand.scale)
    return (operand.kind,)


def comparable_lhs(
    left: Operand,
    right: Operand,
    policy: VerifierPolicy,
    include_stack_locals: bool = False,
) -> bool:
    if left.kind != right.kind:
        return False
    if left.kind == "reg":
        return left.reg == right.reg
    if left.kind != "mem":
        return False
    if left.base != right.base or left.index != right.index or left.scale != right.scale:
        return False
    if left.base in policy.stack_registers and not include_stack_locals:
        return False
    if not left.base:
        return False
    return True


def comparable_operands(compiled: Instruction, original: Instruction) -> bool:
    if len(compiled.operands) != len(original.operands):
        return False
    for c_op, o_op in zip(compiled.operands, original.operands):
        if c_op.kind == "imm" or o_op.kind == "imm":
            if c_op.kind != o_op.kind:
                return False
            continue
        if operand_signature(c_op) != operand_signature(o_op):
            return False
    return True


def immediate_operands(instr: Instruction) -> list[tuple[int, Operand]]:
    return [(idx, op) for idx, op in enumerate(instr.operands) if op.kind == "imm"]


def memory_operands(instr: Instruction) -> list[tuple[int, Operand]]:
    return [(idx, op) for idx, op in enumerate(instr.operands) if op.kind == "mem"]


def immediate_string(image: PEImage, operand: Operand, policy: VerifierPolicy) -> str | None:
    return image.c_string_at(unsigned32(operand.imm), predicate=lambda value: looks_like_literal_string(value, policy))


def small_numeric_immediate(operand: Operand, policy: VerifierPolicy) -> bool:
    value = operand.imm
    return policy.small_immediate_min <= value < policy.small_immediate_max


def has_pointer_immediate(instr: Instruction) -> bool:
    return any(unsigned32(operand.imm) >= 0x400000 for _, operand in immediate_operands(instr))


def member_displacement(value: int, policy: VerifierPolicy) -> bool:
    return -policy.max_member_displacement < value < policy.max_member_displacement


def lhs_is_stack_memory(instr: Instruction, policy: VerifierPolicy) -> bool:
    if not instr.operands:
        return False
    operand = instr.operands[0]
    return operand.kind == "mem" and operand.base in policy.stack_registers


def has_stack_memory_operand(instr: Instruction, policy: VerifierPolicy) -> bool:
    return any(op.kind == "mem" and op.base in policy.stack_registers for op in instr.operands)


def nearby_immediate_values(instrs: list[Instruction], idx: int, policy: VerifierPolicy) -> set[int]:
    values: set[int] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    for j in range(start, end):
        for _, operand in immediate_operands(instrs[j]):
            if small_numeric_immediate(operand, policy):
                values.add(operand.imm)
    return values


def nearby_strings(instrs: list[Instruction], image: PEImage, idx: int, policy: VerifierPolicy) -> set[str | None]:
    values: set[str | None] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    for j in range(start, end):
        for _, operand in immediate_operands(instrs[j]):
            string = immediate_string(image, operand, policy)
            if string is not None:
                values.add(normalize_string_for_compare(string))
    return values


def nearby_calls_target(instrs: list[Instruction], idx: int, targets: frozenset[int], window: int = 8) -> bool:
    if not targets:
        return False
    end = min(len(instrs), idx + window + 1)
    for j in range(idx + 1, end):
        instr = instrs[j]
        if instr.mnemonic != "call":
            continue
        for _, operand in immediate_operands(instr):
            if unsigned32(operand.imm) in targets:
                return True
    return False


def writes_register(instr: Instruction, reg: str) -> bool:
    if not instr.operands:
        return False
    operand = instr.operands[0]
    return operand.kind == "reg" and operand.reg == reg


def is_control_flow_boundary(instr: Instruction) -> bool:
    return instr.mnemonic == "ret" or is_branch_or_call(instr.mnemonic)


def next_instruction(instrs: list[Instruction], idx: int) -> Instruction | None:
    if idx + 1 >= len(instrs):
        return None
    return instrs[idx + 1]


def is_conditional_branch_mnemonic(mnemonic: str) -> bool:
    return mnemonic.startswith("j") and mnemonic != "jmp"


def mnemonic_sequence_similarity(left: list[str], right: list[str]) -> float:
    if not left or not right:
        return 0.0
    return len(lcs_align(left, right)) / max(len(left), len(right))


def is_stack_adjustment(instr: Instruction) -> bool:
    if instr.mnemonic not in {"add", "sub"} or len(instr.operands) < 2:
        return False
    return instr.operands[0].kind == "reg" and instr.operands[0].reg == "esp"


def is_stack_probe_size_load(instrs: list[Instruction], idx: int) -> bool:
    if idx < 0 or idx >= len(instrs):
        return False
    instr = instrs[idx]
    if instr.mnemonic != "mov" or len(instr.operands) < 2:
        return False
    dst, src = instr.operands[0], instr.operands[1]
    return (
        idx <= 6
        and dst.kind == "reg"
        and full_register_name(dst.reg) == "eax"
        and src.kind == "imm"
        and any(
            candidate.mnemonic == "call"
            for candidate in instrs[idx + 1:min(len(instrs), idx + 4)]
        )
        and (
            instrs[idx + 1].mnemonic == "call"
            or has_msvc_seh_frame(instrs)
        )
    )


def direct_jump_target(instr: Instruction) -> int | None:
    if instr.mnemonic != "jmp" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind != "imm":
        return None
    return unsigned32(operand.imm)
