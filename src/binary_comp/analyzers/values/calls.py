"""Call and pushed-argument context around an instruction."""

from __future__ import annotations

from binary_comp.core.disasm import (
    Instruction,
    Operand,
    full_register_name,
    is_branch_or_call,
    unsigned32,
)
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.model import CompareContext
from binary_comp.analyzers.values.operands import (
    direct_jump_target,
    immediate_operands,
    immediate_string,
    normalize_string_for_compare,
)


def call_signature(instr: Instruction, direct_targets: dict[int, str] | None = None) -> tuple | None:
    if instr.mnemonic != "call" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind == "mem":
        return ("mem", operand.index, operand.scale, operand.disp)
    if operand.kind == "imm":
        if direct_targets:
            target_name = direct_targets.get(unsigned32(operand.imm))
            if target_name is not None:
                return ("direct", target_name)
        return ("direct",)
    return None


def following_call_signature(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 48,
    direct_targets: dict[int, str] | None = None,
) -> tuple | None:
    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    seen: set[int] = set()
    pos = idx + 1
    steps = 0
    while 0 <= pos < len(instrs) and steps < max_steps:
        if pos in seen:
            return None
        seen.add(pos)
        steps += 1

        instr = instrs[pos]
        signature = call_signature(instr, direct_targets)
        if signature is not None:
            return signature
        if instr.mnemonic == "ret":
            return None
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return None
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return None
        pos += 1
    return None


def following_call_context(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 48,
    direct_targets: dict[int, str] | None = None,
) -> tuple[tuple, int] | None:
    """Return the destination and argument position for a pushed value.

    Optimized switch bodies are frequently emitted in a different order even
    when their calls and arguments are identical.  The plain mnemonic LCS can
    consequently align a PUSH from one case with a PUSH from another.  Track
    the call reached by the push, including simple tail merges, and count the
    later pushes so values can be reconciled at the same argument position.
    """
    if idx < 0 or idx >= len(instrs) or instrs[idx].mnemonic != "push":
        return None

    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    seen: set[int] = set()
    pos = idx + 1
    steps = 0
    later_pushes = 0
    while 0 <= pos < len(instrs) and steps < max_steps:
        if pos in seen:
            return None
        seen.add(pos)
        steps += 1

        instr = instrs[pos]
        signature = call_signature(instr, direct_targets)
        if signature is not None:
            return signature, later_pushes
        if instr.mnemonic == "push":
            later_pushes += 1
        if instr.mnemonic == "ret":
            return None
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return None
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return None
        pos += 1
    return None


def loaded_value_call_context(
    instrs: list[Instruction],
    idx: int,
    direct_targets: dict[int, str] | None = None,
    max_steps: int = 5,
) -> tuple[tuple, int] | None:
    """Resolve a register load to the call argument that consumes it."""
    if idx < 0 or idx >= len(instrs):
        return None
    instr = instrs[idx]
    if instr.mnemonic != "mov" or len(instr.operands) < 2:
        return None
    destination = instr.operands[0]
    if destination.kind != "reg":
        return None
    register = full_register_name(destination.reg)

    for pos in range(idx + 1, min(len(instrs), idx + 1 + max_steps)):
        candidate = instrs[pos]
        if candidate.mnemonic == "push" and candidate.operands:
            pushed = candidate.operands[0]
            if pushed.kind == "reg" and full_register_name(pushed.reg) == register:
                return following_call_context(
                    instrs, pos, direct_targets=direct_targets
                )
        if candidate.mnemonic == "ret" or is_branch_or_call(candidate.mnemonic):
            return None
        if (
            candidate.operands
            and candidate.operands[0].kind == "reg"
            and full_register_name(candidate.operands[0].reg) == register
        ):
            return None
    return None


def block_literal_anchors(
    instrs: list[Instruction],
    image: PEImage,
    idx: int,
    policy: VerifierPolicy,
) -> frozenset[str]:
    """Literal strings in the straight-line region containing ``idx``.

    A nearby unique string literal is a stable semantic anchor for the small
    constant values surrounding it.  Calls remain inside the region, while
    control-flow boundaries prevent unrelated switch cases from lending each
    other anchors.
    """
    branch_targets = {
        unsigned32(instr.operands[0].imm)
        for instr in instrs
        if is_branch_or_call(instr.mnemonic)
        and instr.mnemonic != "call"
        and instr.operands
        and instr.operands[0].kind == "imm"
    }

    lo = idx
    steps = 0
    while lo > 0 and steps < 64:
        previous = instrs[lo - 1]
        if previous.mnemonic == "ret" or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        if instrs[lo].address in branch_targets:
            break
        lo -= 1
        steps += 1

    hi = idx + 1
    steps = 0
    while hi < len(instrs) and steps < 64:
        if instrs[hi].address in branch_targets:
            break
        previous = instrs[hi - 1]
        if previous.mnemonic == "ret" or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        hi += 1
        steps += 1

    anchors: set[str] = set()
    for instr in instrs[lo:hi]:
        for _, operand in immediate_operands(instr):
            value = immediate_string(image, operand, policy)
            if value is not None:
                anchors.add(normalize_string_for_compare(value).lower())
    return frozenset(anchors)


def pushed_operand_fingerprint(
    operand: Operand,
    image: PEImage,
    policy: VerifierPolicy,
) -> tuple:
    if operand.kind == "imm":
        value = immediate_string(image, operand, policy)
        if value is not None:
            return ("string", normalize_string_for_compare(value).lower())
        return ("imm", operand.imm)
    return (operand.kind,)


def push_argument_fingerprint(
    instrs: list[Instruction],
    image: PEImage,
    idx: int,
    policy: VerifierPolicy,
) -> tuple:
    """Describe the other pushed operands belonging to the same call."""
    if idx < 0 or idx >= len(instrs) or instrs[idx].mnemonic != "push":
        return ()

    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    branch_targets = {
        unsigned32(instr.operands[0].imm)
        for instr in instrs
        if is_branch_or_call(instr.mnemonic)
        and instr.mnemonic != "call"
        and instr.operands
        and instr.operands[0].kind == "imm"
    }

    lo = idx
    while lo > 0:
        previous = instrs[lo - 1]
        if previous.mnemonic in {"call", "ret"} or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        if instrs[lo].address in branch_targets:
            break
        lo -= 1

    path = list(range(lo, idx + 1))
    seen = set(path)
    pos = idx + 1
    steps = 0
    while 0 <= pos < len(instrs) and steps < 48:
        if pos in seen:
            return ()
        seen.add(pos)
        steps += 1
        instr = instrs[pos]
        if instr.mnemonic == "call":
            break
        if instr.mnemonic == "ret":
            return ()
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return ()
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return ()
        path.append(pos)
        pos += 1
    else:
        return ()

    pushes = [pos for pos in path if instrs[pos].mnemonic == "push"]
    if idx not in pushes:
        return ()
    current_ordinal = len(pushes) - pushes.index(idx) - 1
    result: list[tuple] = []
    for push_index, push_pos in enumerate(pushes):
        ordinal = len(pushes) - push_index - 1
        if ordinal == current_ordinal:
            continue
        push = instrs[push_pos]
        if not push.operands:
            continue
        result.append((
            ordinal,
            pushed_operand_fingerprint(push.operands[0], image, policy),
        ))
    return tuple(result)


def push_has_contextual_value(
    instrs: list[Instruction],
    image: PEImage,
    wanted_value: int | str,
    wanted_context: tuple[tuple, int],
    wanted_anchors: frozenset[str],
    wanted_fingerprint: tuple,
    context: CompareContext,
    direct_targets: dict[int, str],
) -> bool:
    for idx, instr in enumerate(instrs):
        if instr.mnemonic != "push" or not instr.operands:
            continue
        operand = instr.operands[0]
        if operand.kind != "imm":
            continue

        if isinstance(wanted_value, str):
            candidate = immediate_string(image, operand, context.policy)
            if candidate is None or normalize_string_for_compare(candidate) != wanted_value:
                continue
        else:
            if operand.imm != wanted_value:
                continue
            if immediate_string(image, operand, context.policy) is not None:
                continue

        candidate_context = following_call_context(
            instrs, idx, direct_targets=direct_targets
        )
        if candidate_context != wanted_context:
            continue
        candidate_anchors = block_literal_anchors(
            instrs, image, idx, context.policy
        )
        candidate_fingerprint = push_argument_fingerprint(
            instrs, image, idx, context.policy
        )
        if wanted_anchors & candidate_anchors:
            return True
        if wanted_fingerprint and candidate_fingerprint == wanted_fingerprint:
            return True
    return False


def contextual_push_value_counts(
    instrs: list[Instruction],
    image: PEImage,
    wanted_context: tuple[tuple, int],
    wanted_values: frozenset[int | str],
    context: CompareContext,
    direct_targets: dict[int, str],
) -> dict[int | str, int]:
    counts = {value: 0 for value in wanted_values}
    for idx, instr in enumerate(instrs):
        if instr.mnemonic != "push" or not instr.operands:
            continue
        operand = instr.operands[0]
        if operand.kind != "imm":
            continue
        candidate_context = following_call_context(
            instrs, idx, direct_targets=direct_targets
        )
        if candidate_context != wanted_context:
            continue
        string = immediate_string(image, operand, context.policy)
        if string is None:
            value: int | str = operand.imm
        else:
            value = normalize_string_for_compare(string)
        if value in counts:
            counts[value] += 1
    return counts
