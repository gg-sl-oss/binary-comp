"""x87 floating-point comparisons and status-word tests."""

from __future__ import annotations

from binary_comp.core.disasm import Instruction, Operand, unsigned32
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.branches import equivalent_reordered_branch_layout
from binary_comp.analyzers.values.operands import is_control_flow_boundary, next_instruction


def x87_status_test_mask(instrs: list[Instruction], idx: int) -> int | None:
    """Return the x87 condition-code mask consumed by a status-word test."""
    if idx < 2 or idx >= len(instrs):
        return None
    instr = instrs[idx]
    if instr.mnemonic != "test" or len(instr.operands) < 2:
        return None
    status, mask = instr.operands[0], instr.operands[1]
    if status.kind != "reg" or status.reg != "ah" or mask.kind != "imm":
        return None
    previous = instrs[idx - 1]
    if (
        previous.mnemonic != "fnstsw"
        or not previous.operands
        or previous.operands[0].kind != "reg"
        or previous.operands[0].reg != "ax"
    ):
        return None
    if not any(
        candidate.mnemonic.startswith("fcom")
        or candidate.mnemonic.startswith("fucom")
        for candidate in instrs[max(0, idx - 4):idx - 1]
    ):
        return None
    return mask.imm


def x87_memory_fingerprint(
    operand: Operand,
    image: PEImage,
    policy: VerifierPolicy,
) -> tuple | None:
    if operand.kind != "mem":
        return None
    if operand.base in policy.stack_registers:
        return ("stack", operand.size)
    if not operand.base and not operand.index:
        size = operand.size or 8
        reader = getattr(image, "read", None)
        data = reader(unsigned32(operand.disp), size) if reader is not None else None
        if data is None:
            return None
        return ("absolute", size, data)
    return ("member", operand.disp, operand.size)


def x87_expression_signature(
    instrs: list[Instruction],
    start: int,
    end: int,
    image: PEImage,
    policy: VerifierPolicy,
) -> tuple | None:
    operations = [
        instr
        for instr in instrs[start:end]
        if instr.mnemonic.startswith("f")
        and instr.mnemonic not in {"fnstsw", "fwait"}
    ]
    if not operations or operations[0].mnemonic not in {"fld", "fild", "fld1", "fldz"}:
        return None
    if any(instr.mnemonic in {"fxch", "fstp", "fistp"} for instr in operations):
        return None

    def memory(instr: Instruction) -> tuple | None:
        for operand in instr.operands:
            if operand.kind == "mem":
                return x87_memory_fingerprint(operand, image, policy)
        return None

    loaded = memory(operations[0])
    if operations[0].mnemonic in {"fld1", "fldz"}:
        loaded = (operations[0].mnemonic,)
    if loaded is None:
        return None
    if len(operations) == 1:
        return ("value", loaded)
    if len(operations) == 2 and operations[1].mnemonic in {"fadd", "fmul"}:
        other = memory(operations[1])
        if other is None:
            return None
        return (
            "commutative",
            operations[1].mnemonic,
            tuple(sorted((loaded, other), key=repr)),
        )
    signature = []
    for instr in operations:
        signature.append((instr.mnemonic, memory(instr)))
    return ("ordered", tuple(signature))


def x87_comparison_operands(
    instrs: list[Instruction],
    test_idx: int,
    image: PEImage,
    policy: VerifierPolicy,
) -> tuple[tuple, tuple] | None:
    compare_idx = None
    for idx in range(test_idx - 2, max(-1, test_idx - 6), -1):
        if is_control_flow_boundary(instrs[idx]):
            return None
        if instrs[idx].mnemonic in {"fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp"}:
            compare_idx = idx
            break
    if compare_idx is None:
        return None
    compare = instrs[compare_idx]
    window_start = max(0, compare_idx - 24)
    for idx in range(compare_idx - 1, window_start - 1, -1):
        if is_control_flow_boundary(instrs[idx]):
            window_start = idx + 1
            break
    load_indices = [
        idx
        for idx in range(window_start, compare_idx)
        if instrs[idx].mnemonic in {"fld", "fild", "fld1", "fldz"}
    ]
    if compare.mnemonic.endswith("pp"):
        if len(load_indices) < 2:
            return None
        first_idx, second_idx = load_indices[-2:]
        first = x87_expression_signature(
            instrs, first_idx, second_idx, image, policy
        )
        second = x87_expression_signature(
            instrs, second_idx, compare_idx, image, policy
        )
        if first is None or second is None:
            return None
        return second, first

    memory_operand = next(
        (operand for operand in compare.operands if operand.kind == "mem"),
        None,
    )
    if memory_operand is None or not load_indices:
        return None
    left = x87_expression_signature(
        instrs, load_indices[-1], compare_idx, image, policy
    )
    right_memory = x87_memory_fingerprint(memory_operand, image, policy)
    if left is None or right_memory is None:
        return None
    return left, ("value", right_memory)


def x87_taken_relation(mask: int, branch: str) -> str | None:
    branch = branch.lower()
    if mask == 1:
        if branch in {"jne", "jnz"}:
            return "lt"
        if branch in {"je", "jz"}:
            return "ge"
    if mask == 0x41:
        if branch in {"jne", "jnz"}:
            return "le"
        if branch in {"je", "jz"}:
            return "gt"
    return None


def reverse_relation(relation: str) -> str:
    return {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le"}[relation]


def complementary_relation(relation: str) -> str:
    return {"lt": "ge", "le": "gt", "gt": "le", "ge": "lt"}[relation]


def equivalent_reversed_x87_comparison(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    policy: VerifierPolicy,
) -> bool:
    c_mask = x87_status_test_mask(compiled_instrs, ci)
    o_mask = x87_status_test_mask(original_instrs, oi)
    if {c_mask, o_mask} != {1, 0x41}:
        return False
    c_branch = next_instruction(compiled_instrs, ci)
    o_branch = next_instruction(original_instrs, oi)
    if c_branch is None or o_branch is None:
        return False
    c_relation = x87_taken_relation(c_mask, c_branch.mnemonic)
    o_relation = x87_taken_relation(o_mask, o_branch.mnemonic)
    if c_relation is None or o_relation is None:
        return False
    c_operands = x87_comparison_operands(
        compiled_instrs, ci, compiled_image, policy
    )
    o_operands = x87_comparison_operands(
        original_instrs, oi, original_image, policy
    )
    if c_operands is None or o_operands is None:
        return False
    reversed_operands = (
        c_operands[0] == o_operands[1]
        and c_operands[1] == o_operands[0]
    )
    same_order = c_operands == o_operands
    if not reversed_operands or same_order:
        return False
    normalized_original = reverse_relation(o_relation)
    if c_relation == normalized_original:
        return True
    if c_relation != complementary_relation(normalized_original):
        return False
    return equivalent_reordered_branch_layout(
        compiled_instrs,
        original_instrs,
        ci + 1,
        oi + 1,
        policy,
    )


def equivalent_reordered_x87_status_masks(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    """Recognize strict/inclusive x87 tests paired across reordered regions.

    A mnemonic LCS cannot distinguish repeated geometric tests after VC6 lays
    their blocks out in a different order.  Only reconcile a mismatched pair
    when both complete functions contain the same multiset of x87 status masks
    and each disputed mask occurs elsewhere.  A real one-off ``<``/``<=``
    change therefore remains visible.
    """
    compiled_mask = x87_status_test_mask(compiled_instrs, ci)
    original_mask = x87_status_test_mask(original_instrs, oi)
    if compiled_mask is None or original_mask is None or compiled_mask == original_mask:
        return False

    compiled_masks = [
        mask
        for idx in range(len(compiled_instrs))
        if (mask := x87_status_test_mask(compiled_instrs, idx)) is not None
    ]
    original_masks = [
        mask
        for idx in range(len(original_instrs))
        if (mask := x87_status_test_mask(original_instrs, idx)) is not None
    ]
    if sorted(compiled_masks) != sorted(original_masks):
        return False
    return (
        compiled_masks.count(compiled_mask) > 1
        and compiled_masks.count(original_mask) > 1
    )
