"""Equivalences that explain away an operand difference.

Each ``equivalent_*``/``same_*`` predicate recognises one way the compiler
can produce a different immediate or displacement for the same source."""

from __future__ import annotations

from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import Instruction, Operand, full_register_name, signed32, unsigned32
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.branches import (
    comparison_relation,
    complementary_integer_intervals,
    equivalent_reordered_branch_layout,
    following_flag_branch_mnemonic,
    integer_comparison_interval,
    reverse_comparison_relation,
)
from binary_comp.analyzers.values.calls import (
    block_literal_anchors,
    contextual_push_value_counts,
    following_call_context,
    loaded_value_call_context,
    push_argument_fingerprint,
    push_has_contextual_value,
)
from binary_comp.analyzers.values.dataflow import (
    affine_memory_address,
    affine_registers_at,
    equivalent_alias_displacement,
    masked_register_only_stored_as_word,
    nearby_register_shift,
    pointer_aliases_at,
    register_has_literal_pointer_origin,
    same_expression_object,
    sign_step_outputs,
)
from binary_comp.analyzers.values.model import CompareContext
from binary_comp.analyzers.values.operands import (
    comparable_operands,
    immediate_operands,
    is_control_flow_boundary,
    member_displacement,
    memory_operands,
    mnemonic_sequence_similarity,
    next_instruction,
    writes_register,
)


def same_effective_lea_displacement(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_op: Operand,
    o_op: Operand,
    policy: VerifierPolicy,
) -> bool:
    c_aliases = pointer_aliases_at(compiled_instrs, ci, c_op.base, policy)
    o_aliases = pointer_aliases_at(original_instrs, oi, o_op.base, policy)
    if not c_aliases and not o_aliases:
        return False

    for c_alias in c_aliases or [None]:
        for o_alias in o_aliases or [None]:
            if equivalent_alias_displacement(c_alias, o_alias, c_op.disp, o_op.disp):
                return True
    return False


def same_affine_memory_address(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_op: Operand,
    o_op: Operand,
) -> bool:
    compiled_registers = affine_registers_at(compiled_instrs, ci)
    original_registers = affine_registers_at(original_instrs, oi)
    compiled_address = affine_memory_address(c_op, compiled_registers)
    original_address = affine_memory_address(o_op, original_registers)
    return compiled_address is not None and compiled_address == original_address


def same_effective_register_immediate(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_imm: int,
    o_imm: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic not in {"add", "sub"} or original.mnemonic != compiled.mnemonic:
        return False
    if len(compiled.operands) < 2 or len(original.operands) < 2:
        return False
    c_dst = compiled.operands[0]
    o_dst = original.operands[0]
    if c_dst.kind != "reg" or o_dst.kind != "reg" or c_dst.reg != o_dst.reg:
        return False

    c_aliases = pointer_aliases_at(compiled_instrs, ci, c_dst.reg, policy)
    o_aliases = pointer_aliases_at(original_instrs, oi, o_dst.reg, policy)
    if not c_aliases and not o_aliases:
        return False

    c_delta = c_imm if compiled.mnemonic == "add" else -c_imm
    o_delta = o_imm if original.mnemonic == "add" else -o_imm
    for c_alias in c_aliases or [None]:
        for o_alias in o_aliases or [None]:
            if equivalent_alias_displacement(c_alias, o_alias, c_delta, o_delta):
                return True
    return False


def shifted_memory_sequence_match_count(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    delta: int,
    policy: VerifierPolicy,
) -> int:
    def displacements(instrs: list[Instruction], center: int) -> list[int]:
        result: list[int] = []
        start = max(0, center - policy.nearby_window)
        end = min(len(instrs), center + policy.nearby_window + 1)
        source = instrs[center]
        source_op = source.operands[operand_idx]
        for instr in instrs[start:end]:
            if instr.mnemonic != source.mnemonic or operand_idx >= len(instr.operands):
                continue
            operand = instr.operands[operand_idx]
            if operand.kind != "mem":
                continue
            if (
                operand.base != source_op.base
                or operand.index != source_op.index
                or operand.scale != source_op.scale
                or not member_displacement(operand.disp, policy)
            ):
                continue
            result.append(operand.disp)
        return result

    compiled_values = [value - delta for value in displacements(compiled_instrs, ci)]
    original_values = displacements(original_instrs, oi)
    return len(lcs_align(compiled_values, original_values))


def equivalent_shifted_literal_pointer_base(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    c_op: Operand,
    o_op: Operand,
    policy: VerifierPolicy,
) -> bool:
    if not c_op.base or not o_op.base:
        return False
    if not register_has_literal_pointer_origin(compiled_instrs, ci, c_op.base):
        return False
    if not register_has_literal_pointer_origin(original_instrs, oi, o_op.base):
        return False
    delta = c_op.disp - o_op.disp
    return shifted_memory_sequence_match_count(
        compiled_instrs,
        original_instrs,
        ci,
        oi,
        operand_idx,
        delta,
        policy,
    ) >= 2


def immediate_window_similarity(
    left: list[Instruction],
    left_idx: int,
    right: list[Instruction],
    right_idx: int,
    radius: int = 8,
) -> tuple[float, float]:
    left_before = [instr.mnemonic for instr in left[max(0, left_idx - radius):left_idx]]
    right_before = [instr.mnemonic for instr in right[max(0, right_idx - radius):right_idx]]
    left_after = [instr.mnemonic for instr in left[left_idx + 1:left_idx + 1 + radius]]
    right_after = [instr.mnemonic for instr in right[right_idx + 1:right_idx + 1 + radius]]
    return (
        mnemonic_sequence_similarity(left_before, right_before),
        mnemonic_sequence_similarity(left_after, right_after),
    )


def has_structurally_relocated_immediate(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_value: int,
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_immediates = dict(immediate_operands(target))
        if operand_idx not in target_immediates or target_immediates[operand_idx].imm != wanted_value:
            continue
        before_score, after_score = immediate_window_similarity(
            source_instrs, source_idx, target_instrs, target_idx
        )
        if max(before_score, after_score) >= 0.8 and before_score + after_score >= 1.25:
            return True
    return False


def equivalent_structurally_reordered_immediates(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    compiled_value: int,
    original_value: int,
) -> bool:
    bidirectional = has_structurally_relocated_immediate(
        compiled_instrs, ci, original_instrs, operand_idx, compiled_value
    ) and has_structurally_relocated_immediate(
        original_instrs, oi, compiled_instrs, operand_idx, original_value
    )
    if bidirectional:
        return True

    def has_much_better_exact_match(
        source_instrs: list[Instruction],
        source_idx: int,
        paired_instrs: list[Instruction],
        paired_idx: int,
        wanted_value: int,
    ) -> bool:
        source = source_instrs[source_idx]
        current_scores = immediate_window_similarity(
            source_instrs, source_idx, paired_instrs, paired_idx
        )
        for candidate_idx, candidate in enumerate(paired_instrs):
            if candidate.mnemonic != source.mnemonic or not comparable_operands(source, candidate):
                continue
            candidate_immediates = dict(immediate_operands(candidate))
            if (
                operand_idx not in candidate_immediates
                or candidate_immediates[operand_idx].imm != wanted_value
            ):
                continue
            candidate_scores = immediate_window_similarity(
                source_instrs, source_idx, paired_instrs, candidate_idx
            )
            if (
                max(candidate_scores) >= 0.75
                and candidate_scores[0] >= current_scores[0]
                and candidate_scores[1] >= current_scores[1]
                and sum(candidate_scores) >= sum(current_scores) + 0.25
            ):
                return True
        return False

    return has_much_better_exact_match(
        compiled_instrs,
        ci,
        original_instrs,
        oi,
        compiled_value,
    ) or has_much_better_exact_match(
        original_instrs,
        oi,
        compiled_instrs,
        ci,
        original_value,
    )


def has_structurally_relocated_displacement(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_displacement: int,
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_memory = dict(memory_operands(target))
        if operand_idx not in target_memory or target_memory[operand_idx].disp != wanted_displacement:
            continue
        before_score, after_score = immediate_window_similarity(
            source_instrs, source_idx, target_instrs, target_idx
        )
        if max(before_score, after_score) >= 0.8 and before_score + after_score >= 1.25:
            return True
    return False


def equivalent_structurally_reordered_displacements(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    compiled_displacement: int,
    original_displacement: int,
) -> bool:
    bidirectional = has_structurally_relocated_displacement(
        compiled_instrs,
        ci,
        original_instrs,
        operand_idx,
        compiled_displacement,
    ) and has_structurally_relocated_displacement(
        original_instrs,
        oi,
        compiled_instrs,
        operand_idx,
        original_displacement,
    )
    if bidirectional:
        return True

    def has_much_better_exact_match(
        source_instrs: list[Instruction],
        source_idx: int,
        paired_instrs: list[Instruction],
        paired_idx: int,
        wanted_displacement: int,
    ) -> bool:
        source = source_instrs[source_idx]
        current_scores = immediate_window_similarity(
            source_instrs, source_idx, paired_instrs, paired_idx
        )
        for candidate_idx, candidate in enumerate(paired_instrs):
            if candidate.mnemonic != source.mnemonic or not comparable_operands(source, candidate):
                continue
            candidate_memory = dict(memory_operands(candidate))
            if (
                operand_idx not in candidate_memory
                or candidate_memory[operand_idx].disp != wanted_displacement
            ):
                continue
            candidate_scores = immediate_window_similarity(
                source_instrs, source_idx, paired_instrs, candidate_idx
            )
            if (
                max(candidate_scores) >= 0.75
                and candidate_scores[0] >= current_scores[0]
                and candidate_scores[1] >= current_scores[1]
                and sum(candidate_scores) >= sum(current_scores) + 0.25
            ):
                return True
        return False

    return has_much_better_exact_match(
        compiled_instrs,
        ci,
        original_instrs,
        oi,
        compiled_displacement,
    ) or has_much_better_exact_match(
        original_instrs,
        oi,
        compiled_instrs,
        ci,
        original_displacement,
    )


def nearby_commutative_member_expressions(
    instrs: list[Instruction],
    center: int,
    policy: VerifierPolicy,
    radius: int = 6,
) -> set[tuple[str, tuple[tuple[int, int], tuple[int, int]]]]:
    """Describe two-field same-object additions/multiplications near ``center``."""
    expressions: set[
        tuple[str, tuple[tuple[int, int], tuple[int, int]]]
    ] = set()
    first_start = max(0, center - radius)
    for first_idx in range(first_start, min(center + 1, len(instrs))):
        first_instr = instrs[first_idx]
        if first_instr.mnemonic != "mov" or len(first_instr.operands) < 2:
            continue
        accumulator, first = first_instr.operands[:2]
        if accumulator.kind != "reg" or first.kind != "mem":
            continue
        if first.base in policy.stack_registers or not member_displacement(first.disp, policy):
            continue
        accumulator_name = full_register_name(accumulator.reg)
        end = min(len(instrs), first_idx + radius + 1)
        for second_idx in range(first_idx + 1, end):
            second_instr = instrs[second_idx]
            if len(second_instr.operands) >= 2:
                destination, second = second_instr.operands[:2]
                if (
                    second_instr.mnemonic in {"add", "imul"}
                    and destination.kind == "reg"
                    and full_register_name(destination.reg) == accumulator_name
                    and second.kind == "mem"
                    and second.base not in policy.stack_registers
                    and member_displacement(second.disp, policy)
                    and center in {first_idx, second_idx}
                    and same_expression_object(
                        instrs, first_idx, first, second_idx, second
                    )
                ):
                    expressions.add((
                        second_instr.mnemonic,
                        tuple(sorted((
                            (first.disp, first.size),
                            (second.disp, second.size),
                        ))),
                    ))
            if writes_register(second_instr, accumulator.reg):
                break
    return expressions


def equivalent_commutative_member_expression(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = nearby_commutative_member_expressions(compiled_instrs, ci, policy)
    if not compiled:
        return False
    original = nearby_commutative_member_expressions(original_instrs, oi, policy)
    return bool(compiled & original)


def equivalent_integer_compare_conditions(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    compiled_value: int,
    original_value: int,
    policy: VerifierPolicy,
) -> bool:
    """Recognize adjacent-bound spellings of the same integer condition."""
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "cmp" or original.mnemonic != "cmp":
        return False
    if len(compiled.operands) < 2 or len(original.operands) < 2:
        return False
    if compiled.operands[1].kind != "imm" or original.operands[1].kind != "imm":
        return False
    c_branch = next_instruction(compiled_instrs, ci)
    o_branch = next_instruction(original_instrs, oi)
    if c_branch is None or o_branch is None:
        return False
    c_relation = comparison_relation(c_branch.mnemonic)
    o_relation = comparison_relation(o_branch.mnemonic)
    if c_relation is None or o_relation is None:
        return False
    if c_relation.endswith("u") != o_relation.endswith("u"):
        return False
    c_interval = integer_comparison_interval(c_relation, compiled_value)
    o_interval = integer_comparison_interval(o_relation, original_value)
    if c_interval is None or o_interval is None:
        return False
    if c_interval == o_interval:
        return True
    if not complementary_integer_intervals(c_interval, o_interval):
        return False
    return equivalent_reordered_branch_layout(
        compiled_instrs,
        original_instrs,
        ci + 1,
        oi + 1,
        policy,
    )


def loaded_member_before_compare(
    instrs: list[Instruction],
    compare_idx: int,
    register: str,
    policy: VerifierPolicy,
    max_steps: int = 6,
) -> tuple[int, Operand] | None:
    register = full_register_name(register)
    for idx in range(compare_idx - 1, max(-1, compare_idx - max_steps - 1), -1):
        instr = instrs[idx]
        if is_control_flow_boundary(instr):
            return None
        if not instr.operands:
            continue
        destination = instr.operands[0]
        if destination.kind != "reg" or full_register_name(destination.reg) != register:
            continue
        if instr.mnemonic == "mov" and len(instr.operands) >= 2:
            source = instr.operands[1]
            if (
                source.kind == "mem"
                and source.base not in policy.stack_registers
                and member_displacement(source.disp, policy)
            ):
                return idx, source
        return None
    return None


def nearby_same_object_member_comparisons(
    instrs: list[Instruction],
    center: int,
    policy: VerifierPolicy,
    radius: int = 6,
) -> set[tuple[tuple[tuple[int, int], tuple[int, int]], str]]:
    comparisons: set[
        tuple[tuple[tuple[int, int], tuple[int, int]], str]
    ] = set()
    start = max(0, center - radius)
    end = min(len(instrs), center + radius + 1)
    for compare_idx in range(start, end):
        compare = instrs[compare_idx]
        if compare.mnemonic != "cmp" or len(compare.operands) < 2:
            continue
        left, right = compare.operands[:2]
        if (
            left.kind != "mem"
            or left.base in policy.stack_registers
            or not member_displacement(left.disp, policy)
            or right.kind != "reg"
        ):
            continue
        loaded = loaded_member_before_compare(
            instrs, compare_idx, right.reg, policy
        )
        if loaded is None:
            continue
        load_idx, right_member = loaded
        if not same_expression_object(
            instrs, compare_idx, left, load_idx, right_member
        ):
            continue
        branch = next_instruction(instrs, compare_idx)
        if branch is None:
            continue
        relation = comparison_relation(branch.mnemonic)
        if relation is None:
            continue
        left_field = (left.disp, left.size)
        right_field = (right_member.disp, right_member.size)
        fields = tuple(sorted((left_field, right_field)))
        if left_field != fields[0]:
            relation = reverse_comparison_relation(relation)
        if center in {load_idx, compare_idx}:
            comparisons.add((fields, relation))
    return comparisons


def equivalent_same_object_member_comparison(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = nearby_same_object_member_comparisons(
        compiled_instrs, ci, policy
    )
    if not compiled:
        return False
    original = nearby_same_object_member_comparisons(
        original_instrs, oi, policy
    )
    return bool(compiled & original)


def has_structurally_relocated_effective_address(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_address: tuple[tuple[tuple[str, int], ...], int],
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_memory = dict(memory_operands(target))
        if operand_idx not in target_memory:
            continue
        target_address = affine_memory_address(
            target_memory[operand_idx], affine_registers_at(target_instrs, target_idx)
        )
        if target_address != wanted_address:
            continue
        return True
    return False


def equivalent_structurally_reordered_effective_addresses(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    c_op: Operand,
    o_op: Operand,
) -> bool:
    compiled_address = affine_memory_address(
        c_op, affine_registers_at(compiled_instrs, ci)
    )
    original_address = affine_memory_address(
        o_op, affine_registers_at(original_instrs, oi)
    )
    if compiled_address is None or original_address is None:
        return False
    return has_structurally_relocated_effective_address(
        compiled_instrs, ci, original_instrs, operand_idx, compiled_address
    ) and has_structurally_relocated_effective_address(
        original_instrs, oi, compiled_instrs, operand_idx, original_address
    )


def equivalent_integer_threshold(
    c_imm: int,
    o_imm: int,
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    c_next = following_flag_branch_mnemonic(compiled_instrs, ci)
    o_next = following_flag_branch_mnemonic(original_instrs, oi)
    if c_next is None or o_next is None:
        return False

    if (c_next, o_next) in (("jnl", "jnle"), ("jnc", "ja")):
        return c_imm == o_imm + 1
    if (c_next, o_next) in (("jnle", "jnl"), ("ja", "jnc")):
        return o_imm == c_imm + 1
    if (c_next, o_next) in (("jnge", "jng"), ("jc", "jbe")):
        return c_imm == o_imm + 1
    if (c_next, o_next) in (("jng", "jnge"), ("jbe", "jc")):
        return o_imm == c_imm + 1
    return False


def equivalent_sign_step_masks(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    compiled_outputs = sign_step_outputs(compiled_instrs, ci)
    original_outputs = sign_step_outputs(original_instrs, oi)
    return compiled_outputs is not None and compiled_outputs == original_outputs


def starts_boolean_mask_after_cmp(instrs: list[Instruction], idx: int) -> bool:
    if idx + 2 >= len(instrs):
        return False

    mov_instr = instrs[idx + 1]
    adc_instr = instrs[idx + 2]
    if mov_instr.mnemonic != "mov" or adc_instr.mnemonic != "adc":
        return False
    if len(mov_instr.operands) < 2 or len(adc_instr.operands) < 2:
        return False

    mov_dst = mov_instr.operands[0]
    mov_src = mov_instr.operands[1]
    adc_dst = adc_instr.operands[0]
    adc_src = adc_instr.operands[1]
    return (
        mov_dst.kind == "reg"
        and mov_src.kind == "imm"
        and mov_src.imm == 0
        and adc_dst.kind == "reg"
        and adc_dst.reg == mov_dst.reg
        and adc_src.kind == "imm"
        and adc_src.imm == -1
    )


def equivalent_boolean_zero_test(
    c_imm: int,
    o_imm: int,
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    if {c_imm, o_imm} != {0, 1}:
        return False
    return starts_boolean_mask_after_cmp(compiled_instrs, ci) or starts_boolean_mask_after_cmp(original_instrs, oi)


def equivalent_low_word_mask(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    compiled_value: int,
    original_value: int,
) -> bool:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "and" or original.mnemonic != "and":
        return False
    if (compiled_value & 0xFFFF) != (original_value & 0xFFFF):
        return False
    if not compiled.operands or not original.operands:
        return False
    c_dst = compiled.operands[0]
    o_dst = original.operands[0]
    if c_dst.kind != "reg" or o_dst.kind != "reg":
        return False
    if full_register_name(c_dst.reg) != full_register_name(o_dst.reg):
        return False
    return masked_register_only_stored_as_word(
        compiled_instrs, ci, c_dst.reg
    ) and masked_register_only_stored_as_word(
        original_instrs, oi, o_dst.reg
    )


def equivalent_mask_moved_across_arithmetic_shift(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    compiled_value: int,
    original_value: int,
) -> bool:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "and" or original.mnemonic != "and":
        return False
    if not compiled.operands or not original.operands:
        return False
    c_dst = compiled.operands[0]
    o_dst = original.operands[0]
    if c_dst.kind != "reg" or o_dst.kind != "reg":
        return False
    if full_register_name(c_dst.reg) != full_register_name(o_dst.reg):
        return False

    c_before = nearby_register_shift(compiled_instrs, ci, c_dst.reg, -1)
    o_after = nearby_register_shift(original_instrs, oi, o_dst.reg, 1)
    if c_before is not None and c_before == o_after:
        shifted = unsigned32(signed32(original_value) >> c_before)
        if shifted == unsigned32(compiled_value):
            return True

    c_after = nearby_register_shift(compiled_instrs, ci, c_dst.reg, 1)
    o_before = nearby_register_shift(original_instrs, oi, o_dst.reg, -1)
    if c_after is not None and c_after == o_before:
        shifted = unsigned32(signed32(compiled_value) >> c_after)
        return shifted == unsigned32(original_value)
    return False


def equivalent_reordered_push_values(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    compiled_value: int | str,
    original_value: int | str,
    context: CompareContext,
) -> bool:
    """Recognize values paired with the wrong reordered switch case.

    Reconciliation is deliberately bidirectional and requires the same call,
    argument position, and a shared literal anchor on both sides.  A genuinely
    changed argument next to the same string therefore remains reportable;
    only values that can each be placed in their matching semantic region are
    ignored.
    """
    compiled_call = following_call_context(
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    original_call = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    if compiled_call is None or original_call is None or compiled_call != original_call:
        return False

    compiled_anchors = block_literal_anchors(
        compiled_instrs, compiled_image, ci, context.policy
    )
    original_anchors = block_literal_anchors(
        original_instrs, original_image, oi, context.policy
    )
    compiled_fingerprint = push_argument_fingerprint(
        compiled_instrs, compiled_image, ci, context.policy
    )
    original_fingerprint = push_argument_fingerprint(
        original_instrs, original_image, oi, context.policy
    )
    compiled_relocated = push_has_contextual_value(
        original_instrs,
        original_image,
        compiled_value,
        compiled_call,
        compiled_anchors,
        compiled_fingerprint,
        context,
        context.original_call_targets,
    )
    original_relocated = push_has_contextual_value(
        compiled_instrs,
        compiled_image,
        original_value,
        original_call,
        original_anchors,
        original_fingerprint,
        context,
        context.compiled_call_targets,
    )
    if compiled_relocated and original_relocated:
        return True

    # One compiler may split the other side of the LCS pair into an unlabelled
    # tail-merge block.  The anchored value alone still proves the current pair
    # is wrong; retain the warning when both sides have competing anchors so a
    # genuinely changed argument is not hidden.
    if compiled_anchors and not original_anchors and compiled_relocated:
        return True
    if original_anchors and not compiled_anchors and original_relocated:
        return True

    # Large switch functions can share common tails without leaving a
    # literal in each individual basic block.  In that case compare the value
    # multiplicities for the same call and argument position.  Values that are
    # fully accounted for on both sides are merely paired with the wrong case
    # by the mnemonic LCS; an added, removed, or changed argument still has an
    # unmatched count and remains reportable.
    wanted_values = frozenset((compiled_value, original_value))
    compiled_counts = contextual_push_value_counts(
        compiled_instrs,
        compiled_image,
        compiled_call,
        wanted_values,
        context,
        context.compiled_call_targets,
    )
    original_counts = contextual_push_value_counts(
        original_instrs,
        original_image,
        original_call,
        wanted_values,
        context,
        context.original_call_targets,
    )
    return (
        compiled_counts[compiled_value] <= original_counts[compiled_value]
        and original_counts[original_value] <= compiled_counts[original_value]
    )


def different_following_call(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> bool:
    c_context = following_call_context(
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    o_context = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    return (
        c_context is not None
        and o_context is not None
        and c_context != o_context
    )


def different_loaded_value_call_context(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> bool:
    compiled_call = loaded_value_call_context(
        compiled_instrs, ci, context.compiled_call_targets
    )
    original_call = loaded_value_call_context(
        original_instrs, oi, context.original_call_targets
    )
    return (
        compiled_call is not None
        and original_call is not None
        and compiled_call != original_call
    )
