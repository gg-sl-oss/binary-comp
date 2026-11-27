"""Compare the operands of one aligned instruction pair."""

from __future__ import annotations

from binary_comp.core.disasm import (
    Instruction,
    Operand,
    full_register_name,
    has_msvc_seh_frame,
    is_branch_or_call,
)
from binary_comp.core.pe import PEImage
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


def compare_targets_msvc_eh_state(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled: Instruction,
    original: Instruction,
    context: CompareContext,
) -> bool:
    if not context.include_stack_locals:
        return False
    if not (writes_msvc_eh_state(compiled) or writes_msvc_eh_state(original)):
        return False
    return has_msvc_seh_frame(compiled_instrs) or has_msvc_seh_frame(original_instrs)


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


def report_cmp_branch_condition_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> ValueWarning | None:
    if "immediates" not in context.enabled_kinds:
        return None

    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "cmp" or original.mnemonic != "cmp":
        return None
    if not same_cmp_immediate_values(compiled, original):
        return None

    c_next = next_instruction(compiled_instrs, ci)
    o_next = next_instruction(original_instrs, oi)
    if c_next is None or o_next is None:
        return None
    if not (is_conditional_branch_mnemonic(c_next.mnemonic) and is_conditional_branch_mnemonic(o_next.mnemonic)):
        return None
    if c_next.mnemonic == o_next.mnemonic:
        return None
    if equivalent_reordered_branch_layout(
        compiled_instrs, original_instrs, ci + 1, oi + 1, context.policy
    ):
        return None
    return ValueWarning("branch", c_next.mnemonic, o_next.mnemonic, c_next, o_next)


def report_stack_argument_origin_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> ValueWarning | None:
    if "offsets" not in context.enabled_kinds:
        return None

    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
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
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    o_call = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    if c_call is None or o_call is None or c_call != o_call:
        return None

    c_origin = stack_argument_origin_at(compiled_instrs, ci, c_op.reg)
    o_origin = stack_argument_origin_at(original_instrs, oi, o_op.reg)
    if c_origin is None or o_origin is None or c_origin == o_origin:
        return None
    return ValueWarning("arg", c_origin, o_origin, compiled, original)


def report_string_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    c_str: str | None,
    o_str: str | None,
    context: CompareContext,
):
    if c_str is None or o_str is None:
        return None
    c_norm = normalize_string_for_compare(c_str)
    o_norm = normalize_string_for_compare(o_str)
    if c_norm == o_norm:
        return None
    if c_norm is not None and o_norm is not None:
        compiled_strings = {
            normalize_string_for_compare(value)
            for idx in range(len(compiled_instrs))
            for _, operand in immediate_operands(compiled_instrs[idx])
            if (value := immediate_string(compiled_image, operand, context.policy)) is not None
        }
        original_strings = {
            normalize_string_for_compare(value)
            for idx in range(len(original_instrs))
            for _, operand in immediate_operands(original_instrs[idx])
            if (value := immediate_string(original_image, operand, context.policy)) is not None
        }
        if o_norm in compiled_strings and c_norm in original_strings:
            return None
        if (
            o_norm in nearby_strings(compiled_instrs, compiled_image, ci, context.policy)
            and c_norm in nearby_strings(original_instrs, original_image, oi, context.policy)
        ):
            return None
        if equivalent_reordered_push_values(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            c_norm,
            o_norm,
            context,
        ):
            return None
    if (
        nearby_calls_target(compiled_instrs, ci, context.compiled_diagnostic_targets)
        and nearby_calls_target(original_instrs, oi, context.original_diagnostic_targets)
    ):
        return None
    compiled, original = compiled_instrs[ci], original_instrs[oi]
    if relocated_immediate(compiled, context.compiled_relocated) or \
            relocated_immediate(original, context.original_relocated):
        return None
    return ValueWarning("string", c_str, o_str, compiled, original)


def compare_instruction_pair(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    context: CompareContext,
) -> list[ValueWarning]:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    warnings: list[ValueWarning] = []

    if compiled.mnemonic != original.mnemonic:
        return warnings
    if is_branch_or_call(compiled.mnemonic):
        return warnings
    if not should_compare_values(compiled, original, context):
        return warnings
    argument_warning = report_stack_argument_origin_mismatch(
        compiled_instrs, original_instrs, ci, oi, context
    )
    if argument_warning is not None:
        warnings.append(argument_warning)
    if not comparable_operands(compiled, original):
        return warnings
    if compiled.mnemonic == "push" and different_following_call(
        compiled_instrs, original_instrs, ci, oi, context
    ):
        return warnings
    if compare_targets_msvc_eh_state(compiled_instrs, original_instrs, compiled, original, context):
        return warnings
    branch_warning = report_cmp_branch_condition_mismatch(compiled_instrs, original_instrs, ci, oi, context)
    if branch_warning is not None:
        warnings.append(branch_warning)

    c_imms = dict(immediate_operands(compiled))
    o_imms = dict(immediate_operands(original))
    for idx in sorted(set(c_imms) & set(o_imms)):
        c_op = c_imms[idx]
        o_op = o_imms[idx]
        if c_op.imm == o_op.imm:
            continue
        c_str = immediate_string(compiled_image, c_op, context.policy)
        o_str = immediate_string(original_image, o_op, context.policy)
        if c_str is not None or o_str is not None:
            if "strings" not in context.enabled_kinds:
                continue
            if (
                not context.include_stack_locals
                and compiled.mnemonic != "push"
                and lhs_is_stack_memory(compiled, context.policy)
            ):
                continue
            warning = report_string_mismatch(
                compiled_instrs, original_instrs,
                compiled_image, original_image,
                ci, oi, c_str, o_str, context,
            )
            if warning is not None:
                warnings.append(warning)
            continue

        if "immediates" not in context.enabled_kinds:
            continue
        if (
            not context.include_stack_locals
            and compiled.mnemonic != "push"
            and lhs_is_stack_memory(compiled, context.policy)
        ):
            continue
        if is_stack_adjustment(compiled) and is_stack_adjustment(original):
            continue
        if (
            not context.include_stack_locals
            and is_stack_probe_size_load(compiled_instrs, ci)
            and is_stack_probe_size_load(original_instrs, oi)
        ):
            continue
        if not small_numeric_immediate(c_op, context.policy) or not small_numeric_immediate(o_op, context.policy):
            continue
        if compiled.mnemonic == "cmp" and equivalent_integer_threshold(
            c_op.imm, o_op.imm, compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if compiled.mnemonic == "cmp" and equivalent_boolean_zero_test(
            c_op.imm, o_op.imm, compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if equivalent_low_word_mask(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
        ):
            continue
        if equivalent_mask_moved_across_arithmetic_shift(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
        ):
            continue
        if equivalent_integer_compare_conditions(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
            context.policy,
        ):
            continue
        if equivalent_sign_step_masks(compiled_instrs, original_instrs, ci, oi):
            continue
        if equivalent_reordered_x87_status_masks(
            compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if equivalent_reversed_x87_comparison(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            context.policy,
        ):
            continue
        if same_effective_register_immediate(
            compiled_instrs, original_instrs, ci, oi, c_op.imm, o_op.imm, context.policy
        ):
            continue
        if compiled.mnemonic == "push":
            c_anchors = block_literal_anchors(
                compiled_instrs, compiled_image, ci, context.policy
            )
            o_anchors = block_literal_anchors(
                original_instrs, original_image, oi, context.policy
            )
            if c_anchors and o_anchors and c_anchors.isdisjoint(o_anchors):
                continue
        if (
            o_op.imm in nearby_immediate_values(compiled_instrs, ci, context.policy)
            and c_op.imm in nearby_immediate_values(original_instrs, oi, context.policy)
        ):
            continue
        if compiled.mnemonic == "push" and equivalent_reordered_push_values(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
            context,
        ):
            continue
        if compiled.mnemonic != "push" and equivalent_structurally_reordered_immediates(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            idx,
            c_op.imm,
            o_op.imm,
        ):
            continue
        if relocated_immediate(compiled, context.compiled_relocated) or \
                relocated_immediate(original, context.original_relocated):
            continue
        warnings.append(ValueWarning("imm", c_op.imm, o_op.imm, compiled, original))

    c_mems = dict(memory_operands(compiled))
    o_mems = dict(memory_operands(original))
    if "offsets" in context.enabled_kinds:
        for idx in sorted(set(c_mems) & set(o_mems)):
            c_op = c_mems[idx]
            o_op = o_mems[idx]
            if c_op.disp == o_op.disp:
                continue
            if not member_displacement(c_op.disp, context.policy) or not member_displacement(o_op.disp, context.policy):
                continue
            if not comparable_lhs(c_op, o_op, context.policy, context.include_stack_locals):
                continue
            if different_loaded_value_call_context(
                compiled_instrs, original_instrs, ci, oi, context
            ):
                continue
            c_near = nearby_memory_displacements(compiled_instrs, ci, context.policy, compiled.mnemonic)
            o_near = nearby_memory_displacements(original_instrs, oi, context.policy, original.mnemonic)
            if o_op.disp in c_near and c_op.disp in o_near:
                continue
            if same_effective_lea_displacement(compiled_instrs, original_instrs, ci, oi, c_op, o_op, context.policy):
                continue
            if same_affine_memory_address(
                compiled_instrs, original_instrs, ci, oi, c_op, o_op
            ):
                continue
            if equivalent_structurally_reordered_effective_addresses(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op,
                o_op,
            ):
                continue
            if equivalent_commutative_member_expression(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                context.policy,
            ):
                continue
            if equivalent_same_object_member_comparison(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                context.policy,
            ):
                continue
            if equivalent_shifted_literal_pointer_base(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op,
                o_op,
                context.policy,
            ):
                continue
            if equivalent_structurally_reordered_displacements(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op.disp,
                o_op.disp,
            ):
                continue
            if (c_op.disp == 0 or o_op.disp == 0) and (has_pointer_immediate(compiled) or has_pointer_immediate(original)):
                continue
            # A displacement the loader relocates is a global's address used as
            # an index base, not a struct member offset.
            if relocated_displacement(compiled, context.compiled_relocated) or \
                    relocated_displacement(original, context.original_relocated):
                continue
            warnings.append(ValueWarning("offset", c_op.disp, o_op.disp, compiled, original))

    return warnings
