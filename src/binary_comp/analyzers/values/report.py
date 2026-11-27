"""Text output for the values check."""

from __future__ import annotations

import os

from binary_comp.analyzers.values.model import ValuesSummary


def format_warning(warning: tuple) -> str:
    kind, compiled_value, original_value, compiled, original = warning
    if kind == "string":
        return (
            f"    STRING compiled {compiled_value!r} vs original {original_value!r}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "imm":
        return (
            f"    IMM {compiled_value} vs {original_value}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "offset":
        return (
            f"    OFFSET 0x{compiled_value & 0xFFFFFFFF:X} vs 0x{original_value & 0xFFFFFFFF:X}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "branch":
        return (
            f"    BRANCH compiled {compiled_value} vs original {original_value}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "arg":
        return (
            f"    ARG STACK+0x{compiled_value:X} vs STACK+0x{original_value:X}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    return str(warning)


def warning_kind_counts(warnings: tuple) -> dict[str, int]:
    counts = {"imm": 0, "string": 0, "offset": 0, "branch": 0, "arg": 0}
    for warning in warnings:
        if not warning:
            continue
        kind = warning[0]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def format_kind_counts(counts: dict[str, int]) -> str:
    labels = (
        ("imm", "IMM"),
        ("string", "STRING"),
        ("offset", "OFFSET"),
        ("branch", "BRANCH"),
        ("arg", "ARG"),
    )
    parts = [f"{label} {counts[kind]}" for kind, label in labels if counts.get(kind, 0)]
    return ", ".join(parts) if parts else "none"


def format_summary(summary: ValuesSummary, min_similarity: float = 0.0,
                   show_similarity: bool = False) -> str:
    lines: list[str] = []
    if summary.boundary_inventory:
        inventory = summary.boundary_inventory
        lines.extend([
            "--- Boundary Inventory ---",
            f"Source function groups: {inventory['source_function_groups']}",
            f"Mapped groups: {inventory['mapped_groups']}",
            f"Original marker candidates in mapped groups: {inventory['original_marker_candidates']}",
            f"Original boundary starts: {inventory['original_boundary_starts']}",
            f"Rebuilt boundary starts from map: {inventory['rebuilt_boundary_starts']}",
            f"Missing map groups: {inventory['missing_map_groups']}",
            "",
        ])

    for group, result in summary.reports:
        lines.append(
            f"\n{group.name} "
            f"(orig 0x{result.original_addr:X}, rebuilt 0x{result.rebuilt_addr:X}, "
            f"{result.similarity:.1f}%) - {len(result.warnings)} mismatch(es):"
        )
        for warning in result.warnings:
            lines.append(format_warning(warning))

    if lines:
        lines.append("")
    if summary.total_mismatches:
        total_counts: dict[str, int] = {}
        for _, result in summary.reports:
            for kind, count in warning_kind_counts(result.warnings).items():
                total_counts[kind] = total_counts.get(kind, 0) + count

        lines.extend([
            "--- Mismatch Breakdown ---",
            f"By kind: {format_kind_counts(total_counts)}",
            "Top functions:",
        ])
        top_reports = sorted(summary.reports, key=lambda item: len(item[1].warnings), reverse=True)[:10]
        for group, result in top_reports:
            lines.append(
                f"  {group.name}: {len(result.warnings)} "
                f"({format_kind_counts(warning_kind_counts(result.warnings))}; {result.similarity:.1f}%)"
            )
        lines.append("")

    lines.extend([
        "--- Summary ---",
        f"Functions checked: {summary.functions_checked}",
        f"With value mismatches: {summary.with_value_mismatches}",
        f"Total mismatches: {summary.total_mismatches}",
        f"Skipped (no bytes/disassembly): {summary.skipped_no_bytes}",
    ])
    if min_similarity > 0:
        lines.append(f"Skipped (similarity < {min_similarity:.1f}%): {summary.skipped_below_threshold}")
    if summary.unmapped_source_groups:
        lines.append(f"Unmapped source groups: {summary.unmapped_source_groups}")
    if show_similarity and summary.similarity:
        lines.extend(["", format_similarity_breakdown(summary)])
    return "\n".join(lines)


def format_similarity_breakdown(summary: ValuesSummary) -> str:
    """Report instruction similarity per source file.

    One run then answers how close the whole project is as well as which
    values are wrong.
    """
    by_source: dict[str, list[float]] = {}
    for source_path, value in summary.similarity:
        by_source.setdefault(os.path.basename(source_path), []).append(value)
    rows = sorted(
        ((name, len(values), sum(values) / len(values)) for name, values in by_source.items()),
        key=lambda row: (row[2] * row[1] - 100.0 * row[1]),
    )
    lines = ["--- Similarity ---", f"{'source':<20}{'funcs':>7}{'average':>10}{'deficit':>10}"]
    for name, count, average in rows:
        if average >= 100.0:
            continue
        lines.append(f"{name:<20}{count:>7}{average:>9.2f}%{(100.0 - average) * count:>10.1f}")
    total = sum(len(values) for values in by_source.values())
    overall = sum(sum(values) for values in by_source.values()) / total
    lines.append(f"\nfunctions {total}   weighted average {overall:.2f}%")
    return "\n".join(lines)
