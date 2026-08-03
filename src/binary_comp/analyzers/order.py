"""Compilation-unit order and boundary hints for reconstructed PE projects.

The final PE does not retain normal C/C++ translation-unit boundaries.  This
analyzer combines weaker, observable signals instead: original function order,
source annotations, alignment/padding, current object ownership, small helper
clusters, direct calls, shared data references, frame-mode runs, and
initializer-like pointer tables.  Its output is deliberately phrased as hints;
controlled recompilation remains the deciding test.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass

from binary_comp.analyzers.function_compare import maybe_build
from binary_comp.analyzers.report import (
    SimilarityReportOptions,
    disassembly_path,
    generate_similarity_report,
)
from binary_comp.config import ProjectTarget
from binary_comp.core.mapfile import parse_msvc_map_by_obj
from binary_comp.core.pe import EXECUTABLE_FLAG, PEImage
from binary_comp.source.functions import load_source_groups


WRITABLE_FLAG = 0x80000000
ADDRESS_RE = re.compile(r"0x[0-9A-Fa-f]+")


@dataclass(frozen=True)
class OrderOptions:
    build: bool = True
    include_similarity: bool = True
    alignment: int = 16
    limit: int = 30
    file_filter: str | None = None
    show_runs: bool = False
    show_all: bool = False
    fail_on_inversions: bool = False
    canonical_aliases: dict[str, str] | None = None
    signature_overloads: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SourceLabel:
    source_path: str
    source_file: str
    function_name: str
    line: int
    definition_index: int
    group_id: str
    multi_address: bool


@dataclass(frozen=True)
class SourceDefinition:
    address: int
    function_name: str
    line: int


@dataclass(frozen=True)
class SourceOrderSummary:
    source_path: str
    source_file: str
    definitions: tuple[SourceDefinition, ...]
    run_count: int
    inversion_count: int
    rebuilt_object_start: int | None

    @property
    def min_address(self) -> int:
        return min((definition.address for definition in self.definitions), default=0)

    @property
    def max_address(self) -> int:
        return max((definition.address for definition in self.definitions), default=0)


@dataclass(frozen=True)
class OrderEntry:
    address: int
    export_name: str
    instruction_count: int
    has_frame_pointer: bool | None
    direct_targets: frozenset[int]
    data_references: frozenset[int]
    labels: tuple[SourceLabel, ...]
    similarity: float | None

    @property
    def source_files(self) -> tuple[str, ...]:
        return tuple(sorted({label.source_file for label in self.labels}))

    @property
    def display_name(self) -> str:
        names = []
        for label in self.labels:
            if label.function_name not in names:
                names.append(label.function_name)
        if names:
            return " / ".join(names)
        return self.export_name or f"FUN_{self.address:08X}"

    @property
    def display_source(self) -> str:
        files = self.source_files
        if not files:
            return "<unmapped>"
        return "/".join(files)


@dataclass(frozen=True)
class BoundaryHint:
    previous: OrderEntry
    following: OrderEntry
    evidence_score: int
    classification: str
    padding_bytes: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SourceRun:
    index: int
    source_files: tuple[str, ...]
    start: int
    end: int
    function_count: int

    @property
    def source_file(self) -> str:
        return "/".join(self.source_files)


@dataclass(frozen=True)
class InitializerPointerRun:
    section: str
    start: int
    end: int
    targets: tuple[int, ...]


@dataclass(frozen=True)
class OrderReport:
    target_name: str
    alignment: int
    entries: tuple[OrderEntry, ...]
    boundary_hints: tuple[BoundaryHint, ...]
    source_summaries: tuple[SourceOrderSummary, ...]
    source_runs: tuple[SourceRun, ...]
    initializer_runs: tuple[InitializerPointerRun, ...]
    aligned_count: int
    unaligned_count: int
    mapped_count: int
    unmapped_count: int
    options: OrderOptions


@dataclass(frozen=True)
class _ExportFacts:
    name: str
    instruction_count: int
    has_frame_pointer: bool | None
    direct_targets: frozenset[int]
    data_references: frozenset[int]


def _address_in_ranges(address: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= address <= end for start, end in ranges)


def _parse_export_address(path: str) -> int | None:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as source:
            for _ in range(6):
                line = source.readline()
                if not line:
                    break
                if line.startswith("Address:"):
                    match = ADDRESS_RE.search(line)
                    return int(match.group(0), 16) if match else None
    except OSError:
        return None
    return None


def _export_addresses(code_dir: str | None) -> set[int]:
    addresses: set[int] = set()
    if not code_dir or not os.path.isdir(code_dir):
        return addresses
    for filename in os.listdir(code_dir):
        if not filename.startswith("FUN_") or not filename.endswith(".disassembled.txt"):
            continue
        address = _parse_export_address(os.path.join(code_dir, filename))
        if address is not None:
            addresses.add(address)
    return addresses


def _parse_instruction_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("Function:", "Address:")):
        return None
    parts = stripped.split(None, 1)
    mnemonic = parts[0].lower()
    if not mnemonic.isalpha() and not mnemonic.startswith("j"):
        return None
    operands = parts[1] if len(parts) > 1 else ""
    return mnemonic, operands


def _load_export_facts(path: str | None, image: PEImage) -> _ExportFacts:
    if not path or not os.path.exists(path):
        return _ExportFacts("", 0, None, frozenset(), frozenset())

    name = ""
    instructions: list[tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as source:
            for line in source:
                if line.startswith("Function:"):
                    name = line.split(":", 1)[1].strip()
                    continue
                parsed = _parse_instruction_line(line)
                if parsed is not None:
                    instructions.append(parsed)
    except OSError:
        return _ExportFacts("", 0, None, frozenset(), frozenset())

    direct_targets: set[int] = set()
    data_references: set[int] = set()
    for mnemonic, operands in instructions:
        values = [int(match.group(0), 16) for match in ADDRESS_RE.finditer(operands)]
        if (mnemonic == "call" or mnemonic.startswith("j")) and values:
            direct_targets.add(values[0])
        for value in values:
            section = image.section_for_va(value)
            if section is not None and not (section.flags & EXECUTABLE_FLAG):
                data_references.add(value)

    has_frame_pointer: bool | None = None
    if instructions:
        first = [(mnemonic, operands.replace(" ", "").lower()) for mnemonic, operands in instructions[:8]]
        has_frame_pointer = any(
            mnemonic == "push" and operands == "ebp"
            for mnemonic, operands in first[:4]
        ) and any(
            mnemonic == "mov" and operands == "ebp,esp"
            for mnemonic, operands in first[:6]
        )

    return _ExportFacts(
        name=name,
        instruction_count=len(instructions),
        has_frame_pointer=has_frame_pointer,
        direct_targets=frozenset(direct_targets),
        data_references=frozenset(data_references),
    )


def _source_inventory(target: ProjectTarget, signature_names: frozenset[str]):
    groups_by_source = load_source_groups(
        target.source_dirs,
        target.map_skip,
        target.source_excludes,
        signature_names,
    )
    labels_by_address: dict[int, list[SourceLabel]] = {}
    definitions_by_source: dict[str, list[SourceDefinition]] = {}

    for source_path, groups in groups_by_source.items():
        source_file = os.path.basename(source_path)
        definitions: list[SourceDefinition] = []
        for definition_index, group in enumerate(groups):
            addresses = tuple(int(address, 16) for address in group.addresses)
            if not addresses:
                continue
            definitions.append(SourceDefinition(addresses[0], group.name, group.line))
            group_id = f"{os.path.abspath(source_path)}:{group.line}:{group.name}"
            for address in addresses:
                labels_by_address.setdefault(address, []).append(SourceLabel(
                    source_path=source_path,
                    source_file=source_file,
                    function_name=group.name,
                    line=group.line,
                    definition_index=definition_index,
                    group_id=group_id,
                    multi_address=len(addresses) > 1,
                ))
        definitions_by_source[source_path] = definitions

    return groups_by_source, labels_by_address, definitions_by_source


def _rebuilt_object_starts(target: ProjectTarget) -> dict[str, int]:
    starts: dict[str, int] = {}
    for object_name, entries in parse_msvc_map_by_obj(target.map_path).items():
        if not entries:
            continue
        basename = re.split(r"[:\\/]", object_name)[-1]
        starts[basename.lower()] = min(entry.va for entry in entries)
    return starts


def _source_runs(labels_by_address: dict[int, list[SourceLabel]]) -> tuple[SourceRun, ...]:
    mapped = []
    for address in sorted(labels_by_address):
        files = tuple(sorted({label.source_file for label in labels_by_address[address]}))
        mapped.append((address, files))

    runs: list[SourceRun] = []
    current_files = None
    current_start = 0
    current_end = 0
    count = 0
    for address, source_files in mapped:
        if source_files != current_files:
            if current_files is not None:
                runs.append(SourceRun(len(runs) + 1, current_files, current_start, current_end, count))
            current_files = source_files
            current_start = address
            count = 0
        current_end = address
        count += 1
    if current_files is not None:
        runs.append(SourceRun(len(runs) + 1, current_files, current_start, current_end, count))
    return tuple(runs)


def _source_summaries(
    definitions_by_source: dict[str, list[SourceDefinition]],
    runs: tuple[SourceRun, ...],
    object_starts: dict[str, int],
) -> tuple[SourceOrderSummary, ...]:
    run_counts: dict[str, int] = {}
    for run in runs:
        for source_file in run.source_files:
            run_counts[source_file] = run_counts.get(source_file, 0) + 1

    summaries: list[SourceOrderSummary] = []
    for source_path, definitions in definitions_by_source.items():
        if not definitions:
            continue
        source_file = os.path.basename(source_path)
        inversion_count = sum(
            1
            for previous, following in zip(definitions, definitions[1:])
            if following.address < previous.address
        )
        object_name = os.path.splitext(source_file)[0].lower() + ".obj"
        summaries.append(SourceOrderSummary(
            source_path=source_path,
            source_file=source_file,
            definitions=tuple(definitions),
            run_count=run_counts.get(source_file, 0),
            inversion_count=inversion_count,
            rebuilt_object_start=object_starts.get(object_name),
        ))
    summaries.sort(key=lambda summary: (summary.min_address, summary.source_file))
    return tuple(summaries)


def _padding_before(image: PEImage, previous: int, following: int, maximum: int = 64) -> int:
    start = max(previous, following - maximum)
    data = image.read(start, following - start)
    if not data:
        return 0
    count = 0
    for value in reversed(data):
        if value not in (0x90, 0xCC):
            break
        count += 1
    return count


def _initializer_pointer_runs(image: PEImage) -> tuple[InitializerPointerRun, ...]:
    runs: list[InitializerPointerRun] = []
    for section in image.sections:
        if section.flags & EXECUTABLE_FLAG or not (section.flags & WRITABLE_FLAG):
            continue
        size = section.rawsize - (section.rawsize % 4)
        data = image.read(section.start, size)
        if not data:
            continue
        values = struct.unpack(f"<{len(data) // 4}I", data)
        index = 0
        while index < len(values):
            target_section = image.section_for_va(values[index])
            if target_section is None or not (target_section.flags & EXECUTABLE_FLAG):
                index += 1
                continue
            begin = index
            targets = []
            while index < len(values):
                target_section = image.section_for_va(values[index])
                if target_section is None or not (target_section.flags & EXECUTABLE_FLAG):
                    break
                targets.append(values[index])
                index += 1
            before_zero = begin > 0 and values[begin - 1] == 0
            after_zero = index < len(values) and values[index] == 0
            if len(set(targets)) >= 2 and before_zero and after_zero:
                runs.append(InitializerPointerRun(
                    section=section.name,
                    start=section.start + begin * 4,
                    end=section.start + index * 4,
                    targets=tuple(targets),
                ))
    return tuple(runs)


def _stable_frame_transition(entries: list[OrderEntry], boundary_index: int) -> bool:
    left = [
        entry.has_frame_pointer
        for entry in entries[max(0, boundary_index - 2):boundary_index + 1]
        if entry.has_frame_pointer is not None and entry.instruction_count > 3
    ]
    right = [
        entry.has_frame_pointer
        for entry in entries[boundary_index + 1:boundary_index + 4]
        if entry.has_frame_pointer is not None and entry.instruction_count > 3
    ]
    return (
        len(left) >= 2
        and len(right) >= 2
        and len(set(left)) == 1
        and len(set(right)) == 1
        and left[0] != right[0]
    )


def _unique_source_file(entry: OrderEntry) -> str | None:
    files = entry.source_files
    return files[0] if len(files) == 1 else None


def _boundary_hint(
    image: PEImage,
    entries: list[OrderEntry],
    index: int,
    alignment: int,
    initializer_targets: frozenset[int],
) -> BoundaryHint:
    previous = entries[index]
    following = entries[index + 1]
    padding = _padding_before(image, previous.address, following.address)
    score = 0
    reasons: list[str] = []

    unaligned = following.address % alignment != 0
    if unaligned:
        score -= 6
        reasons.append(f"successor is not {alignment}-byte aligned")
    else:
        score += 1
        reasons.append(f"successor is {alignment}-byte aligned")
        if padding >= 4:
            score += 1
            reasons.append(f"{padding} padding byte(s) before successor")

    previous_file = _unique_source_file(previous)
    following_file = _unique_source_file(following)
    if previous_file and following_file:
        if previous_file == following_file:
            reasons.append(f"both entries map to {previous_file}")
            previous_lines = [label.line for label in previous.labels if label.source_file == previous_file]
            following_lines = [label.line for label in following.labels if label.source_file == following_file]
            if previous_lines and following_lines and min(following_lines) < min(previous_lines):
                score += 1
                reasons.append("current source order disagrees with original address order")
        else:
            score += 1
            reasons.append(f"current source file changes {previous_file} -> {following_file}")
    else:
        reasons.append("one or both entries lack an unambiguous source mapping")

    previous_groups = {label.group_id for label in previous.labels}
    following_groups = {label.group_id for label in following.labels}
    if previous_groups & following_groups:
        score -= 5
        reasons.append("both starts belong to one annotated source definition")

    if previous.instruction_count and previous.instruction_count <= 3:
        score -= 1
        reasons.append("predecessor is a tiny helper/thunk candidate")
    if following.instruction_count and following.instruction_count <= 3:
        score -= 1
        reasons.append("successor is a tiny helper/thunk candidate")

    if following.address in previous.direct_targets or previous.address in following.direct_targets:
        score -= 1
        reasons.append("the adjacent entries directly call or jump to each other")

    shared_data = previous.data_references & following.data_references
    if shared_data:
        score -= 1
        reasons.append(f"adjacent entries share {len(shared_data)} data reference(s)")

    if following.address in initializer_targets:
        score += 1
        reasons.append("successor is referenced by an initializer-like pointer table")

    if _stable_frame_transition(entries, index):
        score += 1
        reasons.append("persistent frame-pointer mode changes across the gap")

    if unaligned or previous_groups & following_groups or score <= -2:
        classification = "boundary unlikely"
    elif score >= 3:
        classification = "boundary candidate"
    else:
        classification = "uncertain"

    return BoundaryHint(
        previous=previous,
        following=following,
        evidence_score=score,
        classification=classification,
        padding_bytes=padding,
        reasons=tuple(reasons),
    )


def generate_order_report(
    target: ProjectTarget,
    options: OrderOptions = OrderOptions(),
) -> OrderReport:
    if target.kind != "pe":
        raise ValueError("the order analyzer currently supports PE targets only")
    if options.alignment <= 0 or options.alignment & (options.alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    if options.limit < 0:
        raise ValueError("limit must be non-negative")

    if options.include_similarity:
        similarity_report = generate_similarity_report(
            target,
            SimilarityReportOptions(
                build=options.build,
                canonical_aliases=options.canonical_aliases,
                signature_overloads=options.signature_overloads,
            ),
        )
        similarities: dict[int, float] = {}
        for row in similarity_report.rows:
            if row.similarity is not None:
                similarities[row.address] = max(similarities.get(row.address, 0.0), row.similarity)
    else:
        maybe_build(target, options.build)
        similarities = {}

    image = PEImage(target.original_exe)
    _, labels_by_address, definitions_by_source = _source_inventory(
        target,
        options.signature_overloads,
    )

    # `src/map` is the densest inventory in many projects, while source markers
    # and exports fill the gaps for projects that do not keep such a directory.
    from binary_comp.analyzers.exe import original_function_addresses

    starts = set(original_function_addresses(target))
    starts.update(labels_by_address)
    starts.update(_export_addresses(target.code_dir))
    starts = {
        address
        for address in starts
        if (section := image.section_for_va(address)) is not None
        and section.flags & EXECUTABLE_FLAG
        and not _address_in_ranges(address, target.library_ranges)
    }

    entries: list[OrderEntry] = []
    for address in sorted(starts):
        path = disassembly_path(target, address)
        facts = _load_export_facts(path, image)
        entries.append(OrderEntry(
            address=address,
            export_name=facts.name or f"FUN_{address:08X}",
            instruction_count=facts.instruction_count,
            has_frame_pointer=facts.has_frame_pointer,
            direct_targets=facts.direct_targets,
            data_references=facts.data_references,
            labels=tuple(labels_by_address.get(address, ())),
            similarity=similarities.get(address),
        ))

    initializer_runs = _initializer_pointer_runs(image)
    initializer_targets = frozenset(
        target_address
        for run in initializer_runs
        for target_address in run.targets
    )
    hints = tuple(
        _boundary_hint(image, entries, index, options.alignment, initializer_targets)
        for index in range(max(0, len(entries) - 1))
    )

    runs = _source_runs(labels_by_address)
    summaries = _source_summaries(
        definitions_by_source,
        runs,
        _rebuilt_object_starts(target),
    )
    aligned = sum(1 for entry in entries if entry.address % options.alignment == 0)
    mapped = sum(1 for entry in entries if entry.labels)
    return OrderReport(
        target_name=target.name,
        alignment=options.alignment,
        entries=tuple(entries),
        boundary_hints=hints,
        source_summaries=summaries,
        source_runs=runs,
        initializer_runs=initializer_runs,
        aligned_count=aligned,
        unaligned_count=len(entries) - aligned,
        mapped_count=mapped,
        unmapped_count=len(entries) - mapped,
        options=options,
    )


def _entry_matches(entry: OrderEntry, value: str | None) -> bool:
    if not value:
        return True
    wanted = value.lower()
    fields = [
        entry.display_name,
        entry.display_source,
        f"0x{entry.address:X}",
        f"{entry.address:X}",
    ]
    return any(wanted in field.lower() for field in fields)


def _summary_matches(summary: SourceOrderSummary, value: str | None) -> bool:
    if not value:
        return True
    wanted = value.lower()
    if wanted in summary.source_file.lower() or wanted in summary.source_path.lower():
        return True
    return any(wanted in definition.function_name.lower() for definition in summary.definitions)


def _hint_label(entry: OrderEntry) -> str:
    similarity = f" {entry.similarity:.2f}%" if entry.similarity is not None else ""
    return f"0x{entry.address:08X} {entry.display_name} [{entry.display_source}]{similarity}"


def _limited(items: list, limit: int) -> list:
    return items if limit == 0 else items[:limit]


def _address_sequence(definitions: list[SourceDefinition] | tuple[SourceDefinition, ...]) -> str:
    addresses = [f"0x{definition.address:08X}" for definition in definitions]
    if len(addresses) > 16:
        addresses = addresses[:16] + [f"... (+{len(addresses) - 16})"]
    return " -> ".join(addresses)


def inverted_source_files(report: OrderReport) -> tuple[SourceOrderSummary, ...]:
    """Source files whose definition order disagrees with original address order.

    Projects that keep definitions sorted by original address can treat a
    non-empty result as a failure: the compiler emits in source order, so an
    inversion guarantees a layout the original cannot have had.
    """
    options = report.options
    return tuple(
        summary
        for summary in report.source_summaries
        if summary.inversion_count and _summary_matches(summary, options.file_filter)
    )


def format_order_report(report: OrderReport) -> str:
    options = report.options
    lines = [
        "Compilation-unit order and boundary hints",
        f"Target: {report.target_name}",
        "",
        f"Observed original-code starts: {len(report.entries)}",
        f"  Source-mapped:            {report.mapped_count}",
        f"  Unmapped/generated:       {report.unmapped_count}",
        f"  With disassembly facts:   {sum(entry.instruction_count > 0 for entry in report.entries)}",
        f"  {report.alignment}-byte aligned:          {report.aligned_count}",
        f"  Unaligned:                {report.unaligned_count}",
        f"Source files:               {len(report.source_summaries)}",
        f"Original-address file runs: {len(report.source_runs)}",
        f"Boundary candidates:        {sum(hint.classification == 'boundary candidate' for hint in report.boundary_hints)}",
        "",
        "Hints are not recovered debug metadata. Confirm candidates with controlled split/join builds",
        "and a whole-project regression gate.",
    ]

    if report.initializer_runs:
        lines.extend(["", "Initializer-like pointer tables"])
        for run in _limited(list(report.initializer_runs), options.limit):
            preview = ", ".join(f"0x{target:08X}" for target in run.targets[:8])
            if len(run.targets) > 8:
                preview += f", ... (+{len(run.targets) - 8})"
            lines.append(
                f"  {run.section} 0x{run.start:08X}-0x{run.end:08X}: "
                f"{len(run.targets)} executable target(s): {preview}"
            )

    ordered_summaries = [
        (index, summary)
        for index, summary in enumerate(report.source_summaries, 1)
        if _summary_matches(summary, options.file_filter)
    ]
    lines.extend([
        "",
        "Source-file order hints",
        "  U rows are ordered by each file's first mapped original start; interleaved runs mean",
        "  that a current source file is not evidence of one historical compilation unit.",
    ])
    if not ordered_summaries:
        lines.append("  (none)")
    for index, summary in _limited(ordered_summaries, options.limit):
        rebuilt = (
            f" rebuilt@0x{summary.rebuilt_object_start:08X}"
            if summary.rebuilt_object_start is not None
            else ""
        )
        lines.append(
            f"  U{index:03d} 0x{summary.min_address:08X}-0x{summary.max_address:08X} "
            f"{summary.source_file} ({len(summary.definitions)} definition(s), "
            f"{summary.run_count} run(s)){rebuilt}"
        )

    summaries = [
        summary
        for summary in report.source_summaries
        if _summary_matches(summary, options.file_filter)
        and (summary.run_count > 1 or summary.inversion_count > 0 or options.show_all)
    ]
    summaries.sort(key=lambda summary: (-summary.run_count, -summary.inversion_count, summary.source_file))
    lines.extend(["", "Source files needing order review"])
    if not summaries:
        lines.append("  (none)")
    for summary in _limited(summaries, options.limit):
        rebuilt = (
            f" rebuilt@0x{summary.rebuilt_object_start:08X}"
            if summary.rebuilt_object_start is not None
            else ""
        )
        lines.append(
            f"  {summary.source_file}: {len(summary.definitions)} definition(s), "
            f"{summary.run_count} original-address run(s), "
            f"{summary.inversion_count} source-order inversion(s), "
            f"0x{summary.min_address:08X}-0x{summary.max_address:08X}{rebuilt}"
        )
        if summary.inversion_count and (
            options.file_filter or options.show_all or options.fail_on_inversions
        ):
            source_order = _address_sequence(summary.definitions)
            address_order = _address_sequence(sorted(summary.definitions, key=lambda item: item.address))
            lines.append(f"    source:  {source_order}")
            lines.append(f"    address: {address_order}")

    hints = [
        hint
        for hint in report.boundary_hints
        if _entry_matches(hint.previous, options.file_filter)
        or _entry_matches(hint.following, options.file_filter)
    ]
    candidates = [hint for hint in hints if hint.classification == "boundary candidate"]
    if options.show_all:
        candidates.extend(hint for hint in hints if hint.classification == "uncertain")
    candidates.sort(key=lambda hint: (
        -hint.evidence_score,
        hint.following.similarity if hint.following.similarity is not None else 101.0,
        hint.following.address,
    ))

    lines.extend([
        "",
        "Boundary candidates",
        "  B scores rank accumulated evidence; they are not probabilities or proof.",
    ])
    if not candidates:
        lines.append("  (none at the current evidence threshold)")
    for hint in _limited(candidates, options.limit):
        lines.append(
            f"  B{hint.evidence_score:+d}  {_hint_label(hint.previous)}"
            f"\n       -> {_hint_label(hint.following)}"
        )
        lines.append(f"       {'; '.join(hint.reasons)}")

    unlikely = [hint for hint in hints if hint.classification == "boundary unlikely"]
    unlikely.sort(key=lambda hint: (
        hint.evidence_score,
        hint.following.similarity if hint.following.similarity is not None else 101.0,
        hint.following.address,
    ))
    lines.extend(["", "Strongest same-context / boundary-unlikely hints"])
    if not unlikely:
        lines.append("  (none)")
    for hint in _limited(unlikely, min(options.limit, 12) if options.limit else 0):
        lines.append(
            f"  B{hint.evidence_score:+d}  {_hint_label(hint.previous)}"
            f"\n       -> {_hint_label(hint.following)}"
        )
        lines.append(f"       {'; '.join(hint.reasons)}")

    if options.show_runs:
        runs = [
            run for run in report.source_runs
            if not options.file_filter or options.file_filter.lower() in run.source_file.lower()
        ]
        lines.extend(["", "Original-address source-file runs"])
        if not runs:
            lines.append("  (none)")
        for run in _limited(runs, options.limit):
            lines.append(
                f"  R{run.index:03d} 0x{run.start:08X}-0x{run.end:08X} "
                f"{run.source_file} ({run.function_count} mapped start(s))"
            )

    return "\n".join(lines)
