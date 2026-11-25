"""Whole-project function similarity reporting."""

from __future__ import annotations

import csv
import os
import re
from bisect import bisect_right
from dataclasses import dataclass, field

from binary_comp.analyzers.function_compare import (
    FunctionCompareError,
    FunctionComparer,
    disassemble_exported_function,
    instruction_mnemonics,
    load_disassembly_policy,
    mnemonic_similarity,
)
from binary_comp.analyzers.byte_compare import ByteComparison, compare_function_bytes
from binary_comp.analyzers.calls import asm_path_for_source as calls_asm_path_for_source
from binary_comp.build import maybe_build
from binary_comp.config import ProjectTarget
from binary_comp.core.disasm import normalize_mnemonic
from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.mapfile import function_starts_from_map
from binary_comp.core.pe import PEImage
from binary_comp.source.functions import load_source_groups


@dataclass(frozen=True)
class SimilarityReportOptions:
    build: bool = True
    canonical_aliases: dict[str, str] | None = None
    file_filter: str | None = None
    signature_overloads: frozenset[str] = frozenset()
    compare_bytes: bool = False


@dataclass(frozen=True)
class SimilarityReportRow:
    source_file: str
    function_name: str
    address: int
    similarity: float | None
    status: str
    bytes: ByteComparison | None = None


@dataclass(frozen=True)
class SimilarityReport:
    rows: tuple[SimilarityReportRow, ...]
    compared: int
    similarity_sum: float
    at_100: int
    above_90: int
    below_90: int
    errors: int
    missing_asm: int
    asm_fallbacks: int


def disassembly_path(target: ProjectTarget, address: int) -> str | None:
    if not target.code_dir:
        return None
    candidates = (
        os.path.join(target.code_dir, f"FUN_{address:08X}.disassembled.txt"),
        os.path.join(target.code_dir, f"FUN_{address:06X}.disassembled.txt"),
        os.path.join(target.code_dir, f"FUN_{address:X}.disassembled.txt"),
    )
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def asm_path_for_source(target: ProjectTarget, source_path: str) -> str | None:
    if not target.asm_dir:
        return None
    return calls_asm_path_for_source(target, source_path)


def asm_line_mnemonic(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.endswith(":"):
        return None
    if stripped.startswith(";") or stripped.startswith("?"):
        return None
    if re.search(r"\b(SEGMENT|ENDS|END|PROC|ENDP|PUBLIC|EXTRN|COMDAT)\b", stripped):
        return None
    if "=" in stripped and not stripped.lower().startswith(("cmp", "test")):
        return None

    code = stripped.split(";", 1)[0].strip()
    if not code:
        return None
    parts = code.split()
    if not parts:
        return None

    mnemonic = parts[0].lower()
    if mnemonic in {"db", "dd", "dq", "dt", "dw", "npad"}:
        return None
    if mnemonic in {"rep", "repe", "repne", "repnz", "lock"} and len(parts) > 1:
        mnemonic = f"{mnemonic} {parts[1].lower()}"
    return normalize_mnemonic(mnemonic)


def extract_asm_mnemonics(
    asm_path: str,
    function_name: str,
    occurrence_index: int,
) -> list[str]:
    try:
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    current_index = -1
    in_function = False
    mnemonics: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not in_function:
            if "PROC" not in stripped:
                continue
            if "; " not in stripped:
                continue
            comment = stripped.split("; ", 1)[1].strip()
            if comment.endswith(", COMDAT"):
                comment = comment[:-len(", COMDAT")].strip()
            if comment != function_name:
                continue
            current_index += 1
            if current_index != occurrence_index:
                continue
            in_function = True
            continue

        if re.search(r"\bENDP\b", stripped):
            break
        mnemonic = asm_line_mnemonic(stripped)
        if mnemonic is not None:
            mnemonics.append(mnemonic)

    return mnemonics


def compare_asm_fallback(
    target: ProjectTarget,
    original_image: PEImage,
    source_path: str,
    function_name: str,
    occurrence_index: int,
    original_addr: int,
    disasm_path: str,
    max_bytes: int,
    padding_mnemonics: frozenset[str],
) -> float | None:
    asm_path = asm_path_for_source(target, source_path)
    if asm_path is None:
        return None
    compiled_mnemonics = extract_asm_mnemonics(asm_path, function_name, occurrence_index)
    if not compiled_mnemonics:
        return None

    original = disassemble_exported_function(
        original_image,
        disasm_path,
        original_addr,
        max_bytes,
        padding_mnemonics,
    )
    original_mnemonics = instruction_mnemonics(original.instructions)
    if not original_mnemonics:
        return None
    return mnemonic_similarity(compiled_mnemonics, original_mnemonics)


# A score at or above this counts as a perfect match (the 100% bucket).
EXACT_MATCH_SIMILARITY = 99.99
# Scores below this are listed with their recorded reasons.
HIGH_SIMILARITY = 90.0
# Original pieces of one source function this alike, each at least this
# many instructions long, are duplicate instances rather than SEH chunks.
DUPLICATE_INSTANCE_SIMILARITY = 80.0
MIN_DUPLICATE_INSTANCE_MNEMONICS = 8

_COMPARE_ERRORS = (FunctionCompareError, FileNotFoundError, RuntimeError, ValueError)


@dataclass
class _Tally:
    """Rows and running totals for a similarity report."""

    rows: list[SimilarityReportRow] = field(default_factory=list)
    compared: int = 0
    similarity_sum: float = 0.0
    at_100: int = 0
    above_90: int = 0
    below_90: int = 0
    errors: int = 0
    missing_asm: int = 0
    asm_fallbacks: int = 0

    def add_score(
        self,
        source_file: str,
        function_name: str,
        address: int,
        similarity: float,
        byte_comparison: ByteComparison | None = None,
    ) -> None:
        self.compared += 1
        self.similarity_sum += similarity
        if similarity >= EXACT_MATCH_SIMILARITY:
            self.at_100 += 1
        if similarity >= HIGH_SIMILARITY:
            self.above_90 += 1
        else:
            self.below_90 += 1
        self.rows.append(SimilarityReportRow(
            source_file,
            function_name,
            address,
            similarity,
            f"{similarity:.2f}%",
            byte_comparison,
        ))

    def add_not_found(self, source_file: str, function_name: str, address: int) -> None:
        self.errors += 1
        self.rows.append(SimilarityReportRow(source_file, function_name, address, None, "NOT FOUND"))

    def add_missing_asm(self, source_file: str, function_name: str, address: int) -> None:
        self.missing_asm += 1
        self.rows.append(SimilarityReportRow(source_file, function_name, address, None, "MISSING ASM"))

    def report(self) -> SimilarityReport:
        return SimilarityReport(
            rows=tuple(self.rows),
            compared=self.compared,
            similarity_sum=self.similarity_sum,
            at_100=self.at_100,
            above_90=self.above_90,
            below_90=self.below_90,
            errors=self.errors,
            missing_asm=self.missing_asm,
            asm_fallbacks=self.asm_fallbacks,
        )


class _ReportBuilder:
    """Compares each annotated source function and records the results."""

    def __init__(self, target: ProjectTarget, options: SimilarityReportOptions):
        self.target = target
        self.options = options
        self.comparer = FunctionComparer(
            target,
            canonical_aliases=options.canonical_aliases,
            signature_overloads=options.signature_overloads,
        )
        self.original_image = PEImage(target.original_exe)
        self.max_bytes, self.padding_mnemonics = load_disassembly_policy(target)
        self.original_starts = function_starts_from_export_dir(target.code_dir) if options.compare_bytes else []
        self.rebuilt_starts = (
            function_starts_from_map(self.comparer.map_entries()) if options.compare_bytes else []
        )
        self.tally = _Tally()

    def byte_comparison(self, comparison) -> ByteComparison | None:
        if (
            not self.options.compare_bytes
            or not comparison.original.instructions
            or not comparison.rebuilt.instructions
        ):
            return None
        original_last = max(instr.address for instr in comparison.original.instructions)
        rebuilt_last = max(instr.address for instr in comparison.rebuilt.instructions)
        return compare_function_bytes(
            self.original_image,
            comparison.original.instructions,
            self.comparer.pe_image(self.target.rebuilt_exe),
            comparison.rebuilt.instructions,
            original_end=_next_start(self.original_starts, original_last),
            rebuilt_end=_next_start(self.rebuilt_starts, rebuilt_last),
        )

    def add_comparison(self, source_file: str, function_name: str, address: int, comparison) -> None:
        self.tally.add_score(
            source_file,
            function_name,
            address,
            comparison.similarity,
            self.byte_comparison(comparison),
        )

    def compare_group(self, source_path: str, group, occurrence_index: int) -> None:
        source_file = os.path.basename(source_path)
        # A group with several addresses is compared as a whole when every
        # piece has an export; otherwise each address gets its own row.
        if len(group.addresses) > 1 and self.compare_multi_address_group(source_file, group):
            return
        for address_text in group.addresses:
            self.compare_address(source_path, group, occurrence_index, int(address_text, 16))

    def compare_multi_address_group(self, source_file: str, group) -> bool:
        """Compare a group with several original addresses; False if a piece is missing.

        MSVC SEH functions are exported by Ghidra as several contiguous chunks
        (a short FS-frame prologue + the body), each carrying its own "Function
        start:" annotation, so a single source function ends up with multiple
        original addresses. The rebuilt binary has ONE function, so compare it
        once against the concatenated chunks instead of measuring each chunk
        separately (which makes the prologue chunk a spurious ~5% row that also
        drags the average down).

        The other case is N duplicate instances of the same function (e.g.
        identical non-COMDAT methods emitted once per class/TU); each of those
        gets its own row.
        """
        chunk_paths: list[str] = []
        for address_text in group.addresses:
            path = disassembly_path(self.target, int(address_text, 16))
            if path is None or not os.path.exists(path):
                return False
            chunk_paths.append(path)

        if self.are_duplicate_instances(group.addresses, chunk_paths):
            for address_text, path in zip(group.addresses, chunk_paths):
                address = int(address_text, 16)
                try:
                    comparison = self.comparer.compare(group.name, path, build=False)
                except _COMPARE_ERRORS:
                    self.tally.add_not_found(source_file, group.name, address)
                    continue
                self.add_comparison(source_file, group.name, address, comparison)
            return True

        entry_address = min(int(address_text, 16) for address_text in group.addresses)
        try:
            comparison = self.comparer.compare_combined(group.name, chunk_paths, build=False)
        except _COMPARE_ERRORS:
            self.tally.add_not_found(source_file, group.name, entry_address)
        else:
            self.add_comparison(source_file, group.name, entry_address, comparison)
        return True

    def are_duplicate_instances(self, addresses: list[str], chunk_paths: list[str]) -> bool:
        """Whether the original pieces are copies of one function, not SEH chunks.

        Chunks of an SEH split look nothing alike, while duplicate instances
        share the same mnemonic stream, so compare the pieces pairwise.
        """
        chunk_mnemonics: list[list[str]] = []
        for address_text, path in zip(addresses, chunk_paths):
            try:
                piece = disassemble_exported_function(
                    self.original_image,
                    path,
                    int(address_text, 16),
                    self.max_bytes,
                    self.padding_mnemonics,
                )
            except (FileNotFoundError, RuntimeError, ValueError):
                return False
            chunk_mnemonics.append(instruction_mnemonics(piece.instructions))
        return (
            all(len(mnemonics) >= MIN_DUPLICATE_INSTANCE_MNEMONICS for mnemonics in chunk_mnemonics)
            and all(
                mnemonic_similarity(chunk_mnemonics[0], mnemonics) >= DUPLICATE_INSTANCE_SIMILARITY
                for mnemonics in chunk_mnemonics[1:]
            )
        )

    def compare_address(self, source_path: str, group, occurrence_index: int, address: int) -> None:
        source_file = os.path.basename(source_path)
        path = disassembly_path(self.target, address)
        if path is None or not os.path.exists(path):
            self.tally.add_missing_asm(source_file, group.name, address)
            return

        try:
            comparison = self.comparer.compare(group.name, path, build=False)
        except _COMPARE_ERRORS:
            similarity = compare_asm_fallback(
                self.target,
                self.original_image,
                source_path,
                group.name,
                occurrence_index,
                address,
                path,
                self.max_bytes,
                self.padding_mnemonics,
            )
            if similarity is None:
                self.tally.add_not_found(source_file, group.name, address)
                return
            self.tally.asm_fallbacks += 1
            self.tally.add_score(source_file, group.name, address, similarity)
            return
        self.add_comparison(source_file, group.name, address, comparison)


def _next_start(starts: list[int], address: int) -> int | None:
    index = bisect_right(starts, address)
    return starts[index] if index < len(starts) else None


def _groups_matching_filter(source_path: str, groups: list, file_filter: str | None) -> list:
    """All groups when the file matches ``file_filter``, else those whose name does."""
    source_file = os.path.basename(source_path)
    if file_filter and file_filter not in source_file and file_filter not in source_path:
        return [group for group in groups if file_filter in group.name]
    return groups


def generate_similarity_report(
    target: ProjectTarget,
    options: SimilarityReportOptions = SimilarityReportOptions(),
) -> SimilarityReport:
    maybe_build(target, options.build)

    builder = _ReportBuilder(target, options)
    groups_by_source = load_source_groups(target.source_dirs, target.map_skip, target.source_excludes)
    for source_path in sorted(groups_by_source):
        occurrences: dict[str, int] = {}
        for group in _groups_matching_filter(source_path, groups_by_source[source_path], options.file_filter):
            occurrence_index = occurrences.get(group.name, 0)
            occurrences[group.name] = occurrence_index + 1
            builder.compare_group(source_path, group, occurrence_index)
    return builder.tally.report()


def load_similarity_reasons(path: str) -> dict[int, str]:
    """Load manual review notes keyed by original address, independently of scores."""
    reasons: dict[int, str] = {}
    with open(path, newline="", encoding="utf-8-sig") as source:
        rows = csv.DictReader(source, strict=True)
        fields = rows.fieldnames or []
        reason_field = "reason" if "reason" in fields else "evidence_and_likely_cause"
        if "original_address" not in fields or reason_field not in fields:
            raise ValueError(f"{path}: expected CSV columns original_address and reason "
                             "(or evidence_and_likely_cause)")
        for row in rows:
            try:
                address = int(row["original_address"], 16)
            except (TypeError, ValueError):
                raise ValueError(f"{path}:{rows.line_num}: invalid original_address") from None
            if address in reasons:
                raise ValueError(f"{path}:{rows.line_num}: duplicate address 0x{address:08X}")
            reasons[address] = " ".join((row[reason_field] or "").split())
    return reasons


def format_similarity_report(
    report: SimilarityReport,
    reasons: dict[int, str] | None = None,
) -> str:
    lines = ["", "--- Similarity Report ---"]
    current_file = None
    for row in report.rows:
        if row.source_file != current_file:
            lines.extend(["", f"=== {row.source_file} ==="])
            current_file = row.source_file
        line = f"  {row.function_name:45s} 0x{row.address:06X}  {row.status}"
        if row.bytes is not None:
            line = f"{line:<70s} {row.bytes.label}"
        lines.append(line)

    average = report.similarity_sum / report.compared if report.compared else 0.0
    lines.extend([
        "",
        "--- Summary ---",
        f"Total compared: {report.compared}",
        f"  100%: {report.at_100}",
        f"  >=90%: {report.above_90}",
        f"  <90%: {report.below_90}",
        f"  Errors/NOT FOUND: {report.errors}",
        f"  Missing disassembly exports: {report.missing_asm}",
        f"  ASM fallback: {report.asm_fallbacks}",
        f"  Average similarity: {average:.2f}%",
    ])
    compared_bytes = [row.bytes for row in report.rows if row.bytes is not None]
    if compared_bytes:
        exact = sum(1 for item in compared_bytes if item.exact)
        same_size = sum(1 for item in compared_bytes if item.same_size and not item.exact)
        resized = [item for item in compared_bytes if not item.same_size]
        delta = sum(item.rebuilt_size - item.original_size for item in resized)
        lines.extend([
            f"Byte comparison: {len(compared_bytes)}",
            f"  Exact: {exact}",
            f"  Same size, different bytes: {same_size}",
            f"  Different size: {len(resized)} (net {delta:+d} bytes)",
        ])
    if reasons is not None:
        lines.extend(["", "--- Recorded reasons for similarity below 90% ---"])
        below = sorted(
            (row for row in report.rows if row.similarity is not None and row.similarity < HIGH_SIMILARITY),
            key=lambda row: (row.similarity, row.address, row.function_name),
        )
        for row in below:
            reason = reasons.get(row.address) or "Review needed: no reason recorded."
            lines.append(f"  {row.similarity:6.2f}% {row.function_name}: {reason}")
        if not below:
            lines.append("  None in the current report.")
    return "\n".join(lines)
