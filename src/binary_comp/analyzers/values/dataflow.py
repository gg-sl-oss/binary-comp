"""Backward dataflow over a straight-line instruction window.

Register aliases, affine register values, stack-argument origins and the
other facts the suppressors ask about one instruction's inputs.
"""

from __future__ import annotations

from binary_comp.core.disasm import (
    Instruction,
    Operand,
    full_register_name,
    is_branch_or_call,
    signed32,
    unsigned32,
)
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.operands import (
    is_conditional_branch_mnemonic,
    is_control_flow_boundary,
    member_displacement,
    memory_operands,
    writes_register,
)
from binary_comp.analyzers.values.stream import InstructionStream, instruction_positions


def nearby_memory_displacements(
    instrs: list[Instruction],
    idx: int,
    policy: VerifierPolicy,
    mnemonic: str | None = None,
) -> set[int]:
    values: set[int] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    aliases: dict[str, Operand] = {}
    for j in range(start, end):
        instr = instrs[j]
        if mnemonic is None or instr.mnemonic == mnemonic:
            for _, operand in memory_operands(instr):
                if member_displacement(operand.disp, policy):
                    values.add(operand.disp)
                alias = aliases.get(operand.base)
                if alias is not None and not operand.index:
                    effective_disp = alias.disp + operand.disp
                    if member_displacement(effective_disp, policy):
                        values.add(effective_disp)

        update_register_aliases(aliases, instr, policy)

    return values


def stack_slot_key(operand: Operand, policy: VerifierPolicy) -> tuple[str, int] | None:
    if operand.kind != "mem" or operand.base not in policy.stack_registers or operand.index:
        return None
    return (operand.base, operand.disp)


def stack_slot_alias(operand: Operand, policy: VerifierPolicy) -> Operand | None:
    key = stack_slot_key(operand, policy)
    if key is None:
        return None
    return Operand("mem", "", base=f"stack:{key[0]}:{key[1]}", scale=1)


def update_register_aliases(
    aliases: dict[str, Operand],
    instr: Instruction,
    policy: VerifierPolicy,
    stack_aliases: dict[tuple[str, int], Operand] | None = None,
) -> None:
    if instr.mnemonic == "call":
        for reg in ("eax", "ecx", "edx"):
            aliases.pop(reg, None)
        return

    if instr.mnemonic == "mov" and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "mem":
            key = stack_slot_key(src, policy)
            if key is not None:
                if stack_aliases is not None and key in stack_aliases:
                    aliases[dst.reg] = stack_aliases[key]
                else:
                    alias = stack_slot_alias(src, policy)
                    if alias is not None:
                        aliases[dst.reg] = alias
                return
        if dst.kind == "mem" and src.kind == "reg":
            key = stack_slot_key(dst, policy)
            if stack_aliases is not None and key is not None:
                alias = aliases.get(src.reg)
                if alias is None:
                    stack_aliases.pop(key, None)
                else:
                    stack_aliases[key] = alias
                return

    if instr.mnemonic == "lea" and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "mem":
            if src.base and src.base not in policy.stack_registers and member_displacement(src.disp, policy):
                aliases[dst.reg] = src
            else:
                aliases.pop(dst.reg, None)
        return

    if instr.mnemonic in {"add", "sub"} and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "imm" and member_displacement(src.imm, policy):
            current = aliases.get(dst.reg, Operand("mem", "", base=dst.reg, scale=1))
            delta = src.imm if instr.mnemonic == "add" else -src.imm
            aliases[dst.reg] = Operand(
                "mem",
                "",
                base=current.base,
                index=current.index,
                scale=current.scale,
                disp=current.disp + delta,
            )
            return

    register_write_mnemonics = {
        "mov", "xor", "or", "and", "imul",
        "shl", "shr", "sar", "inc", "dec",
    }
    if instr.mnemonic in register_write_mnemonics and instr.operands and instr.operands[0].kind == "reg":
        aliases.pop(instr.operands[0].reg, None)


def recent_pointer_alias(
    instrs: list[Instruction],
    idx: int,
    reg: str,
    policy: VerifierPolicy,
    max_window: int = 8,
) -> Operand | None:
    start = max(0, idx - max_window)
    for j in range(idx - 1, start - 1, -1):
        instr = instrs[j]
        if instr.mnemonic == "call" or is_branch_or_call(instr.mnemonic):
            return None
        if not writes_register(instr, reg):
            continue
        if instr.mnemonic == "lea" and len(instr.operands) >= 2:
            src = instr.operands[1]
            if src.kind != "mem" or not src.base or src.base in policy.stack_registers:
                return None
            if not member_displacement(src.disp, policy):
                return None
            return src
        if instr.mnemonic in {"add", "sub"} and len(instr.operands) >= 2:
            src = instr.operands[1]
            if src.kind != "imm" or not member_displacement(src.imm, policy):
                return None
            delta = src.imm if instr.mnemonic == "add" else -src.imm
            return Operand("mem", "", base=reg, scale=1, disp=delta)
        return None
    return None


def register_alias_at(instrs: list[Instruction], idx: int, reg: str, policy: VerifierPolicy) -> Operand | None:
    aliases: dict[str, Operand] = {}
    stack_aliases: dict[tuple[str, int], Operand] = {}
    for j in range(0, idx):
        update_register_aliases(aliases, instrs[j], policy, stack_aliases)
    return aliases.get(reg)


def append_unique_alias(aliases: list[Operand], alias: Operand | None) -> None:
    if alias is None:
        return
    key = (alias.kind, alias.base, alias.index, alias.scale, alias.disp)
    if key in {(item.kind, item.base, item.index, item.scale, item.disp) for item in aliases}:
        return
    aliases.append(alias)


def pointer_aliases_at(instrs: list[Instruction], idx: int, reg: str, policy: VerifierPolicy) -> list[Operand]:
    aliases: list[Operand] = []
    append_unique_alias(aliases, recent_pointer_alias(instrs, idx, reg, policy))
    append_unique_alias(aliases, register_alias_at(instrs, idx, reg, policy))
    return aliases


def equivalent_alias_displacement(
    c_alias: Operand | None,
    o_alias: Operand | None,
    c_disp: int,
    o_disp: int,
) -> bool:
    if c_alias is None and o_alias is None:
        return False
    if c_alias is not None and o_alias is not None:
        if c_alias.base != o_alias.base or c_alias.index != o_alias.index or c_alias.scale != o_alias.scale:
            return False
        return c_alias.disp + c_disp == o_alias.disp + o_disp
    if c_alias is not None:
        return c_alias.disp + c_disp == o_disp
    return c_disp == o_alias.disp + o_disp


def affine_add(
    left: tuple[dict[str, int], int],
    right: tuple[dict[str, int], int],
    scale: int = 1,
) -> tuple[dict[str, int], int]:
    coefficients = dict(left[0])
    for name, coefficient in right[0].items():
        coefficients[name] = coefficients.get(name, 0) + coefficient * scale
        if coefficients[name] == 0:
            del coefficients[name]
    return coefficients, left[1] + right[1] * scale


AffineValue = tuple[dict[str, int], int]
StackKey = tuple[tuple[tuple[str, int], ...], int]
AFFINE_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def affine_entry_registers() -> dict[str, AffineValue]:
    return {name: ({name: 1}, 0) for name in AFFINE_REGISTERS}


def affine_stack_address(operand: Operand, registers: dict[str, AffineValue]) -> StackKey | None:
    address = affine_memory_address(operand, registers)
    if address is None:
        return None
    coefficients, _constant = address
    if coefficients != (("esp", 1),):
        return None
    return address


def affine_step(
    instr: Instruction,
    registers: dict[str, AffineValue],
    stack_values: dict[StackKey, AffineValue],
) -> None:
    """Apply one instruction to the affine register and stack-slot state.

    Every update replaces a register's value with a new tuple and never
    mutates one in place, so a shallow copy of ``registers`` is a snapshot.
    """
    def stack_address(operand: Operand):
        return affine_stack_address(operand, registers)

    operands = instr.operands
    if instr.mnemonic == "call":
        for name in ("eax", "ecx", "edx"):
            registers[name] = ({name: 1}, 0)
        return
    if instr.mnemonic == "push":
        registers["esp"] = (
            dict(registers["esp"][0]),
            registers["esp"][1] - 4,
        )
        return
    if instr.mnemonic == "pop":
        if operands and operands[0].kind == "reg":
            dst = full_register_name(operands[0].reg)
            registers[dst] = ({dst: 1}, 0)
        registers["esp"] = (
            dict(registers["esp"][0]),
            registers["esp"][1] + 4,
        )
        return
    if instr.mnemonic == "leave":
        registers["esp"] = (
            dict(registers["ebp"][0]),
            registers["ebp"][1] + 4,
        )
        registers["ebp"] = ({"ebp": 1}, 0)
        return
    if not operands:
        return

    if instr.mnemonic == "mov" and len(operands) >= 2 and operands[0].kind == "mem":
        destination = stack_address(operands[0])
        if destination is not None:
            src = operands[1]
            if src.kind == "reg":
                value = registers.get(full_register_name(src.reg))
                if value is not None:
                    stack_values[destination] = (dict(value[0]), value[1])
                else:
                    stack_values.pop(destination, None)
            elif src.kind == "imm":
                stack_values[destination] = ({}, src.imm)
            else:
                stack_values.pop(destination, None)
        return

    if operands[0].kind != "reg":
        return

    dst = full_register_name(operands[0].reg)
    if dst not in registers:
        return
    if instr.mnemonic == "mov" and len(operands) >= 2:
        source = operands[1]
        if source.kind == "reg":
            src = full_register_name(source.reg)
            if src not in registers:
                registers[dst] = ({dst: 1}, 0)
                return
            registers[dst] = (dict(registers[src][0]), registers[src][1])
            return
        if source.kind == "imm":
            registers[dst] = ({}, source.imm)
            return
        if source.kind == "mem":
            source_address = stack_address(source)
            if source_address is None:
                registers[dst] = ({dst: 1}, 0)
                return
            stored = stack_values.get(source_address)
            if stored is not None:
                registers[dst] = (dict(stored[0]), stored[1])
                return
            token = f"stack-value:{source_address!r}"
            registers[dst] = ({token: 1}, 0)
            return
    if instr.mnemonic == "lea" and len(operands) >= 2 and operands[1].kind == "mem":
        src = operands[1]
        value: tuple[dict[str, int], int] = ({}, src.disp)
        if src.base:
            base = full_register_name(src.base)
            if base not in registers:
                registers[dst] = ({dst: 1}, 0)
                return
            value = affine_add(value, registers[base])
        if src.index:
            index = full_register_name(src.index)
            if index not in registers:
                registers[dst] = ({dst: 1}, 0)
                return
            value = affine_add(
                value,
                registers[index],
                src.scale,
            )
        registers[dst] = value
        return
    if instr.mnemonic in {"add", "sub"} and len(operands) >= 2 and operands[1].kind == "imm":
        delta = operands[1].imm if instr.mnemonic == "add" else -operands[1].imm
        registers[dst] = (dict(registers[dst][0]), registers[dst][1] + delta)
        return
    if instr.mnemonic in {"add", "sub"} and len(operands) >= 2 and operands[1].kind == "reg":
        src = full_register_name(operands[1].reg)
        if src not in registers:
            registers[dst] = ({dst: 1}, 0)
            return
        scale = 1 if instr.mnemonic == "add" else -1
        registers[dst] = affine_add(registers[dst], registers[src], scale)
        return
    if instr.mnemonic in {"inc", "dec"}:
        delta = 1 if instr.mnemonic == "inc" else -1
        registers[dst] = (dict(registers[dst][0]), registers[dst][1] + delta)
        return
    if (
        instr.mnemonic == "shl"
        and len(operands) >= 2
        and operands[1].kind == "imm"
        and 0 <= operands[1].imm < 8
    ):
        scale = 1 << operands[1].imm
        registers[dst] = (
            {name: coefficient * scale for name, coefficient in registers[dst][0].items()},
            registers[dst][1] * scale,
        )
        return
    if (
        instr.mnemonic == "xor"
        and len(operands) >= 2
        and operands[1].kind == "reg"
        and full_register_name(operands[1].reg) == dst
    ):
        registers[dst] = ({}, 0)
        return

    registers[dst] = ({dst: 1}, 0)


def affine_registers_at(
    instrs: list[Instruction],
    idx: int,
) -> dict[str, AffineValue]:
    """Affine value of each general register just before ``instrs[idx]``.

    Each value is linear in the registers' values at function entry.  For an
    ``InstructionStream`` the states are replayed once and kept, so asking
    about every instruction of a function costs one pass, not one per index.
    """
    if not isinstance(instrs, InstructionStream) or not 0 <= idx <= len(instrs):
        registers = affine_entry_registers()
        stack_values: dict[StackKey, AffineValue] = {}
        for instr in instrs[:idx]:
            affine_step(instr, registers, stack_values)
        return registers

    states = instrs.affine_states
    if not states:
        states.append((affine_entry_registers(), {}))
    while len(states) <= idx:
        registers, stack_values = states[-1]
        registers = dict(registers)
        stack_values = dict(stack_values)
        affine_step(instrs[len(states) - 1], registers, stack_values)
        states.append((registers, stack_values))
    return dict(states[idx][0])


def affine_memory_address(
    operand: Operand,
    registers: dict[str, tuple[dict[str, int], int]],
) -> tuple[tuple[tuple[str, int], ...], int] | None:
    if operand.kind != "mem" or not operand.base:
        return None
    base = full_register_name(operand.base)
    if base not in registers:
        return None
    value: tuple[dict[str, int], int] = ({}, operand.disp)
    value = affine_add(value, registers[base])
    if operand.index:
        index = full_register_name(operand.index)
        if index not in registers:
            return None
        value = affine_add(
            value,
            registers[index],
            operand.scale,
        )
    return tuple(sorted(value[0].items())), value[1]


def register_has_literal_pointer_origin(
    instrs: list[Instruction],
    idx: int,
    register: str,
) -> bool:
    """Return whether a register currently derives from a pointer literal.

    MSVC sometimes chooses a different element of a global array as its loop
    base, then compensates every indexed access by the same displacement.  The
    original binary may also spill that base to a stack slot while the
    reconstruction keeps it in a register, so follow those simple spills.
    """
    origins: dict[str, bool] = {}
    stack_origins: dict[tuple[str, int], bool] = {}

    for instr in instrs[:idx]:
        operands = instr.operands
        if instr.mnemonic == "call":
            for name in ("eax", "ecx", "edx"):
                origins.pop(name, None)
            continue
        if not operands:
            continue

        dst = operands[0]
        if instr.mnemonic == "mov" and len(operands) >= 2:
            src = operands[1]
            if dst.kind == "reg":
                dst_reg = full_register_name(dst.reg)
                if src.kind == "imm":
                    origins[dst_reg] = unsigned32(src.imm) >= 0x400000
                elif src.kind == "reg":
                    origins[dst_reg] = origins.get(full_register_name(src.reg), False)
                elif src.kind == "mem" and not src.index and src.base in {"esp", "ebp"}:
                    origins[dst_reg] = stack_origins.get((src.base, src.disp), False)
                else:
                    origins.pop(dst_reg, None)
                continue
            if dst.kind == "mem" and not dst.index and dst.base in {"esp", "ebp"}:
                key = (dst.base, dst.disp)
                if src.kind == "imm":
                    stack_origins[key] = unsigned32(src.imm) >= 0x400000
                elif src.kind == "reg":
                    stack_origins[key] = origins.get(full_register_name(src.reg), False)
                else:
                    stack_origins.pop(key, None)
                continue

        if dst.kind == "reg":
            dst_reg = full_register_name(dst.reg)
            if instr.mnemonic not in {"add", "sub", "inc", "dec"}:
                origins.pop(dst_reg, None)

    return origins.get(full_register_name(register), False)


def recent_register_memory_source(
    instrs: list[Instruction],
    idx: int,
    register: str,
    max_steps: int = 8,
) -> Operand | None:
    """Return the memory operand most recently loaded into ``register``."""
    register = full_register_name(register)
    for candidate in reversed(instrs[max(0, idx - max_steps):idx]):
        if is_control_flow_boundary(candidate):
            return None
        if not candidate.operands:
            continue
        destination = candidate.operands[0]
        if destination.kind != "reg" or full_register_name(destination.reg) != register:
            continue
        if candidate.mnemonic == "mov" and len(candidate.operands) >= 2:
            source = candidate.operands[1]
            if source.kind == "mem":
                return source
        return None
    return None


def same_expression_object(
    instrs: list[Instruction],
    first_idx: int,
    first: Operand,
    second_idx: int,
    second: Operand,
) -> bool:
    if not first.base or not second.base:
        return False
    if full_register_name(first.base) == full_register_name(second.base):
        register = full_register_name(first.base)
        lower_idx, upper_idx = sorted((first_idx, second_idx))
        for instr in instrs[lower_idx:upper_idx]:
            if is_control_flow_boundary(instr):
                return False
            if (
                instr.operands
                and instr.operands[0].kind == "reg"
                and full_register_name(instr.operands[0].reg) == register
            ):
                return False
        return True
    first_source = recent_register_memory_source(instrs, first_idx, first.base)
    second_source = recent_register_memory_source(instrs, second_idx, second.base)
    if first_source is None or second_source is None:
        return False
    return (
        first_source.base,
        first_source.index,
        first_source.scale,
        first_source.disp,
        first_source.size,
    ) == (
        second_source.base,
        second_source.index,
        second_source.scale,
        second_source.disp,
        second_source.size,
    )


def sign_step_outputs(instrs: list[Instruction], idx: int) -> tuple[int, int] | None:
    """Evaluate MSVC's branchless ``delta < 0 ? -1 : 1`` idiom.

    VC6 emits this either as ``setl; dec; and 2; dec`` or as the complementary
    ``setge; dec; and -2; inc`` sequence.  The mask literals differ even though
    both forms produce the same step for non-negative and negative deltas.
    """
    if idx < 3 or idx + 1 >= len(instrs):
        return None
    current = instrs[idx]
    if current.mnemonic != "and" or len(current.operands) < 2:
        return None
    destination, mask_operand = current.operands[0], current.operands[1]
    if destination.kind != "reg" or mask_operand.kind != "imm":
        return None
    register = full_register_name(destination.reg)

    def writes_full_register(instr: Instruction) -> bool:
        return bool(
            instr.operands
            and instr.operands[0].kind == "reg"
            and full_register_name(instr.operands[0].reg) == register
        )

    previous_writes = [
        instr for instr in reversed(instrs[max(0, idx - 8):idx])
        if writes_full_register(instr)
    ]
    following_writes = [
        instr for instr in instrs[idx + 1:min(len(instrs), idx + 9)]
        if writes_full_register(instr)
    ]
    if len(previous_writes) < 2 or not following_writes:
        return None
    decrement = previous_writes[0]
    set_condition = previous_writes[1]
    adjustment = following_writes[0]
    set_index = instrs.index(set_condition, max(0, idx - 8), idx)
    test = instrs[set_index - 1] if set_index > 0 else None
    if (
        decrement.mnemonic != "dec"
        or not decrement.operands
        or decrement.operands[0].kind != "reg"
        or full_register_name(decrement.operands[0].reg) != register
        or set_condition.mnemonic not in {"setl", "setnge", "setge", "setnl"}
        or not set_condition.operands
        or set_condition.operands[0].kind != "reg"
        or full_register_name(set_condition.operands[0].reg) != register
        or test is None
        or test.mnemonic != "test"
        or adjustment.mnemonic not in {"inc", "dec"}
        or not adjustment.operands
        or adjustment.operands[0].kind != "reg"
        or full_register_name(adjustment.operands[0].reg) != register
    ):
        return None

    outputs = []
    mask = mask_operand.imm & 0xFFFFFFFF
    for negative in (False, True):
        if set_condition.mnemonic in {"setl", "setnge"}:
            value = int(negative)
        else:
            value = int(not negative)
        value = ((value - 1) & mask) & 0xFFFFFFFF
        value = (value + (1 if adjustment.mnemonic == "inc" else -1)) & 0xFFFFFFFF
        outputs.append(signed32(value))
    return tuple(outputs)


def masked_register_only_stored_as_word(
    instrs: list[Instruction],
    idx: int,
    register: str,
    max_steps: int = 12,
) -> bool:
    full_register = full_register_name(register)
    for instr in instrs[idx + 1:idx + 1 + max_steps]:
        if instr.mnemonic == "call":
            return False
        for operand_idx, operand in enumerate(instr.operands):
            if operand.kind == "mem" and (
                full_register_name(operand.base) == full_register
                or full_register_name(operand.index) == full_register
            ):
                return False
            if operand.kind != "reg" or full_register_name(operand.reg) != full_register:
                continue
            if (
                instr.mnemonic == "mov"
                and operand_idx > 0
                and operand.size <= 2
                and instr.operands[0].kind == "mem"
                and instr.operands[0].size <= 2
            ):
                return True
            if operand_idx == 0 and instr.mnemonic in {"and", "or", "xor", "add", "sub"}:
                continue
            if operand.size > 2:
                return False
        if instr.mnemonic == "ret":
            return False
    return False


def nearby_register_shift(
    instrs: list[Instruction],
    idx: int,
    register: str,
    direction: int,
    max_steps: int = 3,
) -> int | None:
    register = full_register_name(register)
    for step in range(1, max_steps + 1):
        candidate_idx = idx + direction * step
        if candidate_idx < 0 or candidate_idx >= len(instrs):
            break
        candidate = instrs[candidate_idx]
        if is_control_flow_boundary(candidate):
            break
        if (
            candidate.mnemonic == "sar"
            and len(candidate.operands) >= 2
            and candidate.operands[0].kind == "reg"
            and full_register_name(candidate.operands[0].reg) == register
            and candidate.operands[1].kind == "imm"
        ):
            return candidate.operands[1].imm
        if writes_register(candidate, register):
            break
    return None


def stack_argument_origin_at(
    instrs: list[Instruction],
    idx: int,
    register: str,
) -> int | None:
    """Resolve a forwarded register to an entry-stack argument.

    Follow control flow so an early-return epilogue cannot corrupt the stack
    delta or overwrite a register on a path that never reaches the push being
    checked.  An origin is returned only when every reachable state agrees.
    """
    if idx < 0 or idx >= len(instrs):
        return None
    if idx > 512:
        return None

    target_register = full_register_name(register)
    by_addr = instruction_positions(instrs)
    # position, ESP delta from function entry, EBP frame delta, origins
    initial = (0, 0, None, ())
    worklist = [initial]
    seen: set[tuple] = set()
    target_origins: set[int | None] = set()

    while worklist and len(seen) < 2000:
        pos, stack_delta, frame_delta, packed_origins = worklist.pop()
        state_key = (pos, stack_delta, frame_delta, packed_origins)
        if state_key in seen or pos < 0 or pos >= len(instrs):
            continue
        seen.add(state_key)
        origins = dict(packed_origins)
        if pos == idx:
            target_origins.add(origins.get(target_register))
            continue

        instr = instrs[pos]
        operands = instr.operands
        next_stack = stack_delta
        next_frame = frame_delta
        next_origins = dict(origins)

        if instr.mnemonic == "call":
            for volatile in ("eax", "ecx", "edx"):
                next_origins.pop(volatile, None)
        elif instr.mnemonic == "mov" and len(operands) >= 2:
            dst, src = operands[0], operands[1]
            if dst.kind == "reg":
                dst_reg = full_register_name(dst.reg)
                src_reg = full_register_name(src.reg) if src.kind == "reg" else None
                if dst_reg == "ebp" and src_reg == "esp":
                    next_frame = stack_delta
                    next_origins.pop(dst_reg, None)
                elif dst_reg == "esp" and src_reg == "ebp":
                    if frame_delta is None:
                        continue
                    next_stack = frame_delta
                    next_origins.pop(dst_reg, None)
                else:
                    origin = None
                    if src.kind == "reg":
                        origin = origins.get(src_reg)
                    elif src.kind == "mem" and not src.index:
                        base = full_register_name(src.base)
                        if base == "esp":
                            origin = stack_delta + src.disp
                        elif base == "ebp" and frame_delta is not None:
                            origin = frame_delta + src.disp
                    if origin is not None and origin >= 4:
                        next_origins[dst_reg] = origin
                    else:
                        next_origins.pop(dst_reg, None)
        elif operands and operands[0].kind == "reg":
            written = full_register_name(operands[0].reg)
            if instr.mnemonic in {
                "pop", "lea", "add", "sub", "xor", "or", "and", "imul",
                "shl", "shr", "sar", "inc", "dec", "movzx", "movsx",
            }:
                next_origins.pop(written, None)

        if instr.mnemonic == "push":
            next_stack -= 4
        elif instr.mnemonic == "pop":
            next_stack += 4
        elif instr.mnemonic in {"add", "sub"} and len(operands) >= 2:
            dst, src = operands[0], operands[1]
            if (
                dst.kind == "reg"
                and full_register_name(dst.reg) == "esp"
                and src.kind == "imm"
            ):
                next_stack += src.imm if instr.mnemonic == "add" else -src.imm
        elif instr.mnemonic == "leave":
            if frame_delta is None:
                continue
            next_stack = frame_delta + 4
            next_frame = None
            next_origins.pop("ebp", None)
        elif instr.mnemonic in {"enter", "pushal", "popal"}:
            continue

        packed_next_origins = tuple(sorted(next_origins.items()))
        fallthrough = pos + 1
        successors: list[int] = []
        if instr.mnemonic == "ret":
            successors = []
        elif instr.mnemonic == "jmp":
            if operands and operands[0].kind == "imm":
                target = by_addr.get(unsigned32(operands[0].imm))
                if target is not None:
                    successors.append(target)
        elif is_conditional_branch_mnemonic(instr.mnemonic):
            if fallthrough < len(instrs):
                successors.append(fallthrough)
            if operands and operands[0].kind == "imm":
                target = by_addr.get(unsigned32(operands[0].imm))
                if target is not None:
                    successors.append(target)
        elif fallthrough < len(instrs):
            successors.append(fallthrough)

        for successor in successors:
            worklist.append((
                successor,
                next_stack,
                next_frame,
                packed_next_origins,
            ))

    if len(target_origins) != 1:
        return None
    origin = next(iter(target_origins))
    return origin if origin is not None and 4 <= origin <= 0x100 else None
