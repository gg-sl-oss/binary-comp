"""Compare the operands of one aligned instruction pair."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from binary_comp.core.disasm import (
    Instruction,
    Operand,
    full_register_name,
    has_msvc_seh_frame,
    is_branch_or_call,
)
from binary_comp.core.pe import PEImage
from binary_comp.policy import VerifierPolicy
from binary_comp.analyzers.values.branches import (
    equivalent_reordered_branch_layout,
    same_cmp_immediate_values,
)
from binary_comp.analyzers.values.calls import block_literal_anchors, following_call_context
from binary_comp.analyzers.values.dataflow import (
    nearby_memory_displacements,
    stack_argument_origin_at,
)
from binary_comp.analyzers.values.model import CompareContext, ValueWarning
from binary_comp.analyzers.values.operands import (
    comparable_lhs,
    comparable_operands,
    has_pointer_immediate,
    has_stack_memory_operand,
    immediate_operands,
    immediate_string,
    is_conditional_branch_mnemonic,
    is_stack_adjustment,
    is_stack_probe_size_load,
    lhs_is_stack_memory,
    member_displacement,
    memory_operands,
    nearby_calls_target,
    nearby_immediate_values,
    nearby_strings,
    next_instruction,
    normalize_string_for_compare,
    relocated_displacement,
    relocated_immediate,
    small_numeric_immediate,
)
from binary_comp.analyzers.values.suppressors import (
    different_following_call,
    different_loaded_value_call_context,
    equivalent_boolean_zero_test,
    equivalent_commutative_member_expression,
    equivalent_integer_compare_conditions,
    equivalent_integer_threshold,
    equivalent_low_word_mask,
    equivalent_mask_moved_across_arithmetic_shift,
    equivalent_reordered_push_values,
    equivalent_same_object_member_comparison,
    equivalent_shifted_literal_pointer_base,
    equivalent_sign_step_masks,
    equivalent_structurally_reordered_displacements,
    equivalent_structurally_reordered_effective_addresses,
    equivalent_structurally_reordered_immediates,
    same_affine_memory_address,
    same_effective_lea_displacement,
    same_effective_register_immediate,
)
from binary_comp.analyzers.values.x87 import (
    equivalent_reordered_x87_status_masks,
    equivalent_reversed_x87_comparison,
)


def is_msvc_eh_state_slot(operand: Operand) -> bool:
    return operand.kind == "mem" and operand.base == "ebp" and not operand.index and operand.disp == -4


def writes_msvc_eh_state(instr: Instruction) -> bool:
    if not instr.operands:
        return False
    return is_msvc_eh_state_slot(instr.operands[0])


@dataclass(frozen=True)
class PairContext:
    """One aligned instruction pair, with the streams and images around it.

    Suppressors look backwards and forwards from the pair, so each needs both
    instruction lists and the index of the pair in each.
    """

    compiled_instrs: list[Instruction]
    original_instrs: list[Instruction]
    compiled_image: PEImage
    original_image: PEImage
    ci: int
    oi: int
    context: CompareContext

    @property
    def compiled(self) -> Instruction:
        return self.compiled_instrs[self.ci]

    @property
    def original(self) -> Instruction:
        return self.original_instrs[self.oi]

    @property
    def policy(self) -> VerifierPolicy:
        return self.context.policy

    def skips_stack_store(self) -> bool:
        """A store to a stack local, which is only compared on request."""
        return (
            not self.context.include_stack_locals
            and self.compiled.mnemonic != "push"
            and lhs_is_stack_memory(self.compiled, self.policy)
        )


def compare_targets_msvc_eh_state(pair: PairContext) -> bool:
    if not pair.context.include_stack_locals:
        return False
    if not (writes_msvc_eh_state(pair.compiled) or writes_msvc_eh_state(pair.original)):
        return False
    return has_msvc_seh_frame(pair.compiled_instrs) or has_msvc_seh_frame(pair.original_instrs)


def should_compare_values(compiled: Instruction, original: Instruction, context: CompareContext) -> bool:
    if compiled.mnemonic in context.policy.value_mnemonics:
        return True
    return (
        context.include_stack_locals
        and compiled.mnemonic == "lea"
        and (
            has_stack_memory_operand(compiled, context.policy)
            or has_stack_memory_operand(original, context.policy)
        )
    )


def report_cmp_branch_condition_mismatch(pair: PairContext) -> ValueWarning | None:
    if "immediates" not in pair.context.enabled_kinds:
        return None

    compiled = pair.compiled
    original = pair.original
    if compiled.mnemonic != "cmp" or original.mnemonic != "cmp":
        return None
    if not same_cmp_immediate_values(compiled, original):
        return None

    c_next = next_instruction(pair.compiled_instrs, pair.ci)
    o_next = next_instruction(pair.original_instrs, pair.oi)
    if c_next is None or o_next is None:
        return None
    if not (is_conditional_branch_mnemonic(c_next.mnemonic) and is_conditional_branch_mnemonic(o_next.mnemonic)):
        return None
    if c_next.mnemonic == o_next.mnemonic:
        return None
    if equivalent_reordered_branch_layout(
        pair.compiled_instrs, pair.original_instrs, pair.ci + 1, pair.oi + 1, pair.policy
    ):
        return None
    return ValueWarning("branch", c_next.mnemonic, o_next.mnemonic, c_next, o_next)


def report_stack_argument_origin_mismatch(pair: PairContext) -> ValueWarning | None:
    context = pair.context
    if "offsets" not in context.enabled_kinds:
        return None

    compiled = pair.compiled
    original = pair.original
    if compiled.mnemonic != "push" or original.mnemonic != "push":
        return None
    if len(compiled.operands) != 1 or len(original.operands) != 1:
        return None

    c_op = compiled.operands[0]
    o_op = original.operands[0]
    if c_op.kind != "reg" or o_op.kind != "reg":
        return None
    if full_register_name(c_op.reg) == full_register_name(o_op.reg):
        return None

    c_call = following_call_context(
        pair.compiled_instrs, pair.ci, direct_targets=context.compiled_call_targets
    )
    o_call = following_call_context(
        pair.original_instrs, pair.oi, direct_targets=context.original_call_targets
    )
    if c_call is None or o_call is None or c_call != o_call:
        return None

    c_origin = stack_argument_origin_at(pair.compiled_instrs, pair.ci, c_op.reg)
    o_origin = stack_argument_origin_at(pair.original_instrs, pair.oi, o_op.reg)
    if c_origin is None or o_origin is None or c_origin == o_origin:
        return None
    return ValueWarning("arg", c_origin, o_origin, compiled, original)


def image_strings(instrs: list[Instruction], image: PEImage, policy: VerifierPolicy) -> set[str | None]:
    """Every literal string an instruction stream refers to, normalised."""
    return {
        normalize_string_for_compare(value)
        for instr in instrs
        for _, operand in immediate_operands(instr)
        if (value := immediate_string(image, operand, policy)) is not None
    }


def report_string_mismatch(pair: PairContext, c_str: str | None, o_str: str | None) -> ValueWarning | None:
    context = pair.context
    if c_str is None or o_str is None:
        return None
    c_norm = normalize_string_for_compare(c_str)
    o_norm = normalize_string_for_compare(o_str)
    if c_norm == o_norm:
        return None
    if c_norm is not None and o_norm is not None:
        if (
            o_norm in image_strings(pair.compiled_instrs, pair.compiled_image, pair.policy)
            and c_norm in image_strings(pair.original_instrs, pair.original_image, pair.policy)
        ):
            return None
        if (
            o_norm in nearby_strings(pair.compiled_instrs, pair.compiled_image, pair.ci, pair.policy)
            and c_norm in nearby_strings(pair.original_instrs, pair.original_image, pair.oi, pair.policy)
        ):
            return None
        if equivalent_reordered_push_values(
            pair.compiled_instrs, pair.original_instrs,
            pair.compiled_image, pair.original_image,
            pair.ci, pair.oi, c_norm, o_norm, context,
        ):
            return None
    if (
        nearby_calls_target(pair.compiled_instrs, pair.ci, context.compiled_diagnostic_targets)
        and nearby_calls_target(pair.original_instrs, pair.oi, context.original_diagnostic_targets)
    ):
        return None
    if relocated_immediate(pair.compiled, context.compiled_relocated) or \
            relocated_immediate(pair.original, context.original_relocated):
        return None
    return ValueWarning("string", c_str, o_str, pair.compiled, pair.original)


# An operand suppressor receives the pair, the operand index and the two
# differing operands, and returns True when the difference is not worth
# reporting: either the operands are not values the check compares, or a known
# compiler transformation explains the difference.
OperandSuppressor = Callable[[PairContext, int, Operand, Operand], bool]


def _stack_local_store(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return pair.skips_stack_store()


def _stack_adjustment(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return is_stack_adjustment(pair.compiled) and is_stack_adjustment(pair.original)


def _stack_probe_size(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return (
        not pair.context.include_stack_locals
        and is_stack_probe_size_load(pair.compiled_instrs, pair.ci)
        and is_stack_probe_size_load(pair.original_instrs, pair.oi)
    )


def _not_small_numeric(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return not small_numeric_immediate(c_op, pair.policy) or not small_numeric_immediate(o_op, pair.policy)


def _cmp_integer_threshold(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return pair.compiled.mnemonic == "cmp" and equivalent_integer_threshold(
        c_op.imm, o_op.imm, pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi
    )


def _cmp_boolean_zero_test(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return pair.compiled.mnemonic == "cmp" and equivalent_boolean_zero_test(
        c_op.imm, o_op.imm, pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi
    )


def _low_word_mask(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_low_word_mask(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op.imm, o_op.imm
    )


def _mask_across_shift(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_mask_moved_across_arithmetic_shift(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op.imm, o_op.imm
    )


def _integer_compare_conditions(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_integer_compare_conditions(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op.imm, o_op.imm, pair.policy
    )


def _sign_step_masks(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_sign_step_masks(pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi)


def _x87_status_masks(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_reordered_x87_status_masks(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi
    )


def _x87_reversed_comparison(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_reversed_x87_comparison(
        pair.compiled_instrs, pair.original_instrs,
        pair.compiled_image, pair.original_image,
        pair.ci, pair.oi, pair.policy,
    )


def _same_effective_register_value(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return same_effective_register_immediate(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op.imm, o_op.imm, pair.policy
    )


def _push_in_unrelated_literal_block(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    if pair.compiled.mnemonic != "push":
        return False
    c_anchors = block_literal_anchors(pair.compiled_instrs, pair.compiled_image, pair.ci, pair.policy)
    o_anchors = block_literal_anchors(pair.original_instrs, pair.original_image, pair.oi, pair.policy)
    return bool(c_anchors and o_anchors and c_anchors.isdisjoint(o_anchors))


def _swapped_nearby_immediates(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return (
        o_op.imm in nearby_immediate_values(pair.compiled_instrs, pair.ci, pair.policy)
        and c_op.imm in nearby_immediate_values(pair.original_instrs, pair.oi, pair.policy)
    )


def _reordered_push_values(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return pair.compiled.mnemonic == "push" and equivalent_reordered_push_values(
        pair.compiled_instrs, pair.original_instrs,
        pair.compiled_image, pair.original_image,
        pair.ci, pair.oi, c_op.imm, o_op.imm, pair.context,
    )


def _structurally_reordered_immediates(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return pair.compiled.mnemonic != "push" and equivalent_structurally_reordered_immediates(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, idx, c_op.imm, o_op.imm
    )


def _relocated_immediate(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return (
        relocated_immediate(pair.compiled, pair.context.compiled_relocated)
        or relocated_immediate(pair.original, pair.context.original_relocated)
    )


# Checked in order for a numeric immediate that differs; the first match wins.
IMMEDIATE_SUPPRESSORS: tuple[OperandSuppressor, ...] = (
    _stack_local_store,
    _stack_adjustment,
    _stack_probe_size,
    _not_small_numeric,
    _cmp_integer_threshold,
    _cmp_boolean_zero_test,
    _low_word_mask,
    _mask_across_shift,
    _integer_compare_conditions,
    _sign_step_masks,
    _x87_status_masks,
    _x87_reversed_comparison,
    _same_effective_register_value,
    _push_in_unrelated_literal_block,
    _swapped_nearby_immediates,
    _reordered_push_values,
    _structurally_reordered_immediates,
    _relocated_immediate,
)


def _not_member_displacement(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return not member_displacement(c_op.disp, pair.policy) or not member_displacement(o_op.disp, pair.policy)


def _incomparable_base(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return not comparable_lhs(c_op, o_op, pair.policy, pair.context.include_stack_locals)


def _loaded_for_different_call(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return different_loaded_value_call_context(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, pair.context
    )


def _swapped_nearby_displacements(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    c_near = nearby_memory_displacements(pair.compiled_instrs, pair.ci, pair.policy, pair.compiled.mnemonic)
    o_near = nearby_memory_displacements(pair.original_instrs, pair.oi, pair.policy, pair.original.mnemonic)
    return o_op.disp in c_near and c_op.disp in o_near


def _same_effective_lea(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return same_effective_lea_displacement(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op, o_op, pair.policy
    )


def _same_affine_address(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return same_affine_memory_address(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, c_op, o_op
    )


def _structurally_reordered_addresses(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_structurally_reordered_effective_addresses(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, idx, c_op, o_op
    )


def _commutative_member_expression(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_commutative_member_expression(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, pair.policy
    )


def _same_object_member_comparison(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_same_object_member_comparison(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, pair.policy
    )


def _shifted_literal_pointer_base(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_shifted_literal_pointer_base(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, idx, c_op, o_op, pair.policy
    )


def _structurally_reordered_displacements(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return equivalent_structurally_reordered_displacements(
        pair.compiled_instrs, pair.original_instrs, pair.ci, pair.oi, idx, c_op.disp, o_op.disp
    )


def _zero_displacement_with_pointer(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    return (c_op.disp == 0 or o_op.disp == 0) and (
        has_pointer_immediate(pair.compiled) or has_pointer_immediate(pair.original)
    )


def _relocated_displacement(pair: PairContext, idx: int, c_op: Operand, o_op: Operand) -> bool:
    # A displacement the loader relocates is a global's address used as an
    # index base, not a struct member offset.
    return (
        relocated_displacement(pair.compiled, pair.context.compiled_relocated)
        or relocated_displacement(pair.original, pair.context.original_relocated)
    )


# Checked in order for a memory displacement that differs; the first match wins.
DISPLACEMENT_SUPPRESSORS: tuple[OperandSuppressor, ...] = (
    _not_member_displacement,
    _incomparable_base,
    _loaded_for_different_call,
    _swapped_nearby_displacements,
    _same_effective_lea,
    _same_affine_address,
    _structurally_reordered_addresses,
    _commutative_member_expression,
    _same_object_member_comparison,
    _shifted_literal_pointer_base,
    _structurally_reordered_displacements,
    _zero_displacement_with_pointer,
    _relocated_displacement,
)


def suppressed(
    suppressors: tuple[OperandSuppressor, ...],
    pair: PairContext,
    idx: int,
    c_op: Operand,
    o_op: Operand,
) -> bool:
    return any(suppressor(pair, idx, c_op, o_op) for suppressor in suppressors)


def compare_instruction_pair(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    context: CompareContext,
) -> list[ValueWarning]:
    pair = PairContext(compiled_instrs, original_instrs, compiled_image, original_image, ci, oi, context)
    compiled = pair.compiled
    original = pair.original
    warnings: list[ValueWarning] = []

    if compiled.mnemonic != original.mnemonic:
        return warnings
    if is_branch_or_call(compiled.mnemonic):
        return warnings
    if not should_compare_values(compiled, original, context):
        return warnings
    argument_warning = report_stack_argument_origin_mismatch(pair)
    if argument_warning is not None:
        warnings.append(argument_warning)
    if not comparable_operands(compiled, original):
        return warnings
    if compiled.mnemonic == "push" and different_following_call(
        compiled_instrs, original_instrs, ci, oi, context
    ):
        return warnings
    if compare_targets_msvc_eh_state(pair):
        return warnings
    branch_warning = report_cmp_branch_condition_mismatch(pair)
    if branch_warning is not None:
        warnings.append(branch_warning)

    warnings.extend(compare_immediates(pair))
    if "offsets" in context.enabled_kinds:
        warnings.extend(compare_displacements(pair))
    return warnings


def compare_immediates(pair: PairContext) -> list[ValueWarning]:
    """Report immediates that differ: string literals first, then numbers."""
    context = pair.context
    warnings: list[ValueWarning] = []
    c_imms = dict(immediate_operands(pair.compiled))
    o_imms = dict(immediate_operands(pair.original))
    for idx in sorted(set(c_imms) & set(o_imms)):
        c_op = c_imms[idx]
        o_op = o_imms[idx]
        if c_op.imm == o_op.imm:
            continue
        c_str = immediate_string(pair.compiled_image, c_op, pair.policy)
        o_str = immediate_string(pair.original_image, o_op, pair.policy)
        if c_str is not None or o_str is not None:
            if "strings" not in context.enabled_kinds or pair.skips_stack_store():
                continue
            warning = report_string_mismatch(pair, c_str, o_str)
            if warning is not None:
                warnings.append(warning)
            continue

        if "immediates" not in context.enabled_kinds:
            continue
        if suppressed(IMMEDIATE_SUPPRESSORS, pair, idx, c_op, o_op):
            continue
        warnings.append(ValueWarning("imm", c_op.imm, o_op.imm, pair.compiled, pair.original))
    return warnings


def compare_displacements(pair: PairContext) -> list[ValueWarning]:
    """Report member displacements that differ."""
    warnings: list[ValueWarning] = []
    c_mems = dict(memory_operands(pair.compiled))
    o_mems = dict(memory_operands(pair.original))
    for idx in sorted(set(c_mems) & set(o_mems)):
        c_op = c_mems[idx]
        o_op = o_mems[idx]
        if c_op.disp == o_op.disp:
            continue
        if suppressed(DISPLACEMENT_SUPPRESSORS, pair, idx, c_op, o_op):
            continue
        warnings.append(ValueWarning("offset", c_op.disp, o_op.disp, pair.compiled, pair.original))
    return warnings
