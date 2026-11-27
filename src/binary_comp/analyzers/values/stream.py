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


_CACHED_INDEXES = ("positions", "branch_targets", "affine_states")


def _invalidating(name: str):
    method = getattr(list, name)

    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        self._drop_cached_indexes()
        return self if result is self else result

    wrapper.__name__ = name
    wrapper.__doc__ = method.__doc__
    return wrapper


class InstructionStream(list):
    """A disassembled function.

    Changing the stream in place drops the cached indexes, so they are
    rebuilt on the next query.  Copies and unpickled streams start with no
    cached indexes rather than sharing them.
    """

    def _drop_cached_indexes(self) -> None:
        for name in _CACHED_INDEXES:
            self.__dict__.pop(name, None)

    def __copy__(self) -> InstructionStream:
        return InstructionStream(self)

    def copy(self) -> InstructionStream:
        return InstructionStream(self)

    def __reduce__(self):
        return (InstructionStream, (list(self),))

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


for _name in (
    "__setitem__", "__delitem__", "__iadd__", "__imul__",
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
):
    setattr(InstructionStream, _name, _invalidating(_name))
del _name


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
