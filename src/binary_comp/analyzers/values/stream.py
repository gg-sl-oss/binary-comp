"""One function's instructions, with whole-function indexes computed once.

The suppressors ask the same whole-function questions for every aligned
pair: where an address sits in the stream, whether it is a branch target,
what the registers hold before an instruction.  Rebuilding those answers
per question made the check quadratic in the function length, so
``disassemble`` returns an ``InstructionStream`` that keeps them.

Every helper also accepts a plain list, for which it computes the answer
afresh; that keeps the predicates usable on hand-built instruction lists.
"""

from __future__ import annotations

from functools import cached_property

from binary_comp.core.disasm import Instruction, is_branch_or_call, unsigned32


class InstructionStream(list):
    """A disassembled function.  Do not modify it after construction: the
    cached indexes would no longer describe it."""

    @cached_property
    def positions(self) -> dict[int, int]:
        return build_positions(self)

    @cached_property
    def branch_targets(self) -> frozenset[int]:
        return build_branch_targets(self)

    @cached_property
    def affine_states(self) -> list:
        """Register states before each instruction, filled in on demand by
        ``dataflow.affine_registers_at``."""
        return []


def build_positions(instrs: list[Instruction]) -> dict[int, int]:
    return {instr.address: pos for pos, instr in enumerate(instrs)}


def build_branch_targets(instrs: list[Instruction]) -> frozenset[int]:
    return frozenset(
        unsigned32(instr.operands[0].imm)
        for instr in instrs
        if is_branch_or_call(instr.mnemonic)
        and instr.mnemonic != "call"
        and instr.operands
        and instr.operands[0].kind == "imm"
    )


def instruction_positions(instrs: list[Instruction]) -> dict[int, int]:
    """Map each address to its position in ``instrs``.  Treat as read-only."""
    if isinstance(instrs, InstructionStream):
        return instrs.positions
    return build_positions(instrs)


def direct_branch_targets(instrs: list[Instruction]) -> frozenset[int]:
    """Addresses that a direct jump or conditional branch in ``instrs`` targets."""
    if isinstance(instrs, InstructionStream):
        return instrs.branch_targets
    return build_branch_targets(instrs)
