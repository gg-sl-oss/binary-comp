"""Run the values check over every mapped function."""

from __future__ import annotations

import os

from binary_comp.build import maybe_build
from binary_comp.config import ProjectTarget
from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import Instruction
from binary_comp.core.le import LEImage
from binary_comp.core.mapfile import function_starts_from_map, parse_watcom_map_by_obj
from binary_comp.core.pe import PEImage
from binary_comp.core.symbols import canonical_function_name
from binary_comp.policy import VerifierPolicy
from binary_comp.source.functions import FunctionGroup, load_source_groups, map_source_groups
from binary_comp.analyzers.values.align import matches_in_aligned_runs, value_aware_align
from binary_comp.analyzers.values.compare import compare_instruction_pair
from binary_comp.analyzers.values.disassembly import disassemble, load_original_boundary_starts
from binary_comp.analyzers.values.model import (
    CheckResult,
    CompareContext,
    ValuesOptions,
    ValuesSummary,
)


def build_diagnostic_targets(function_groups: list[FunctionGroup], policy: VerifierPolicy) -> tuple[frozenset[int], frozenset[int]]:
    original_targets: set[int] = set()
    rebuilt_targets: set[int] = set()
    for group in function_groups:
        if canonical_function_name(group.name) not in policy.diagnostic_functions:
            continue
        original_targets.update(group.original_addrs)
        rebuilt_targets.add(group.rebuilt_addr)
    return frozenset(original_targets), frozenset(rebuilt_targets)


def build_call_target_names(function_groups: list[FunctionGroup]) -> tuple[dict[int, str], dict[int, str]]:
    original_targets: dict[int, str] = {}
    rebuilt_targets: dict[int, str] = {}
    for group in function_groups:
        name = canonical_function_name(group.name)
        for address in group.original_addrs:
            original_targets[address] = name
        rebuilt_targets[group.rebuilt_addr] = name
    return original_targets, rebuilt_targets


def check_candidate(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    context: CompareContext,
) -> tuple[float, tuple]:
    c_mnemonics = [instr.mnemonic for instr in compiled_instrs]
    o_mnemonics = [instr.mnemonic for instr in original_instrs]
    if not c_mnemonics or not o_mnemonics:
        return 0.0, ()

    similarity_matches = lcs_align(c_mnemonics, o_mnemonics)
    similarity = 100.0 * len(similarity_matches) / max(len(c_mnemonics), len(o_mnemonics))
    matches = value_aware_align(
        compiled_instrs,
        original_instrs,
        compiled_image,
        original_image,
        context,
    )

    matches = matches_in_aligned_runs(matches)

    warnings: list[tuple] = []
    for ci, oi in matches:
        warnings.extend(compare_instruction_pair(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            context,
        ))
    return similarity, tuple(warnings)


def check_function(
    group: FunctionGroup,
    original_image: PEImage,
    rebuilt_image: PEImage,
    original_starts: list[int],
    rebuilt_starts: list[int],
    context: CompareContext,
) -> CheckResult | None:
    rebuilt_instrs = disassemble(rebuilt_image, group.rebuilt_addr, rebuilt_starts, context.policy)
    if not rebuilt_instrs:
        return None

    results: list[CheckResult] = []
    for original_addr in group.original_addrs:
        original_instrs = disassemble(original_image, original_addr, original_starts, context.policy)
        if not original_instrs:
            continue
        similarity, warnings = check_candidate(
            rebuilt_instrs,
            original_instrs,
            rebuilt_image,
            original_image,
            context,
        )
        results.append(CheckResult(
            original_addr=original_addr,
            rebuilt_addr=group.rebuilt_addr,
            similarity=similarity,
            original_count=len(original_instrs),
            rebuilt_count=len(rebuilt_instrs),
            warnings=warnings,
        ))

    if not results:
        return None
    return sorted(results, key=lambda result: (result.similarity, -len(result.warnings)), reverse=True)[0]


def check_values(target: ProjectTarget, policy: VerifierPolicy, options: ValuesOptions) -> ValuesSummary:
    maybe_build(target, options.build)

    for path, label in (
        (target.original_exe, "original executable"),
        (target.rebuilt_exe, "rebuilt executable"),
        (target.map_path, "linker map"),
    ):
        if not os.path.exists(path):
            raise FileNotFoundError(f"missing {label}: {path}")

    # A linear executable carries an object table rather than PE sections, and
    # Watcom writes a different map, but everything downstream only needs bytes
    # at a virtual address and a symbol's address, so the two formats are
    # interchangeable behind these three lookups.
    linear = target.kind == "dos32-le-omf"
    if linear:
        original_image = LEImage(target.original_exe)
        rebuilt_image = LEImage(target.rebuilt_exe)
        toolchain = "watcom"
        entries = parse_watcom_map_by_obj(target.map_path, rebuilt_image.segment_bases())
    else:
        original_image = PEImage(target.original_exe)
        rebuilt_image = PEImage(target.rebuilt_exe)
        toolchain = "msvc"
        entries = None

    groups_by_source = load_source_groups(target.source_dirs, target.map_skip, target.source_excludes)
    mapped_groups, missing_groups, entries_by_obj = map_source_groups(
        groups_by_source, target.map_path, entries_by_obj=entries, toolchain=toolchain)
    original_call_targets, rebuilt_call_targets = build_call_target_names(mapped_groups)

    if options.file_filter:
        mapped_groups = [
            group for group in mapped_groups
            if options.file_filter in os.path.basename(group.source_path) or options.file_filter in group.name
        ]

    original_starts = load_original_boundary_starts(
        target.code_dir, mapped_groups, target.original_boundaries)
    rebuilt_starts = function_starts_from_map(entries_by_obj)
    boundary_inventory = {}
    if options.boundary_report:
        boundary_inventory = {
            "source_function_groups": sum(len(groups) for groups in groups_by_source.values()),
            "mapped_groups": len(mapped_groups),
            "original_marker_candidates": sum(len(group.original_addrs) for group in mapped_groups),
            "original_boundary_starts": len(original_starts),
            "rebuilt_boundary_starts": len(rebuilt_starts),
            "missing_map_groups": len(missing_groups),
        }

    original_diag_targets, rebuilt_diag_targets = build_diagnostic_targets(mapped_groups, policy)
    context = CompareContext(
        enabled_kinds=options.enabled_kinds,
        policy=policy,
        include_stack_locals=options.include_stack_locals,
        compiled_diagnostic_targets=rebuilt_diag_targets,
        original_diagnostic_targets=original_diag_targets,
        compiled_call_targets=rebuilt_call_targets,
        original_call_targets=original_call_targets,
        compiled_relocated=rebuilt_image.relocated_sites() if linear else frozenset(),
        original_relocated=original_image.relocated_sites() if linear else frozenset(),
    )

    total = 0
    with_mismatches = 0
    total_warnings = 0
    skipped_below_threshold = 0
    skipped_no_bytes = 0
    reports: list[tuple[FunctionGroup, CheckResult]] = []

    similarity: list[tuple[str, float]] = []
    for group in mapped_groups:
        total += 1
        result = check_function(group, original_image, rebuilt_image, original_starts, rebuilt_starts, context)
        if result is None:
            skipped_no_bytes += 1
            continue
        similarity.append((group.source_path, result.similarity))
        if not result.warnings:
            continue
        if result.similarity < options.min_similarity:
            skipped_below_threshold += 1
            continue

        with_mismatches += 1
        total_warnings += len(result.warnings)
        reports.append((group, result))

    return ValuesSummary(
        functions_checked=total,
        with_value_mismatches=with_mismatches,
        total_mismatches=total_warnings,
        skipped_no_bytes=skipped_no_bytes,
        skipped_below_threshold=skipped_below_threshold,
        unmapped_source_groups=len(missing_groups),
        boundary_inventory=boundary_inventory,
        reports=tuple(reports),
        similarity=tuple(similarity),
    )
