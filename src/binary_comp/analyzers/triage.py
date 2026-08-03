"""Separate functions whose remaining gap is register/slot churn from those
with a real structural difference.

A near-miss function is worth working on only if its source can still change
the output. Two instruction streams that differ solely in which register the
allocator picked, which stack slot a local landed in, or where a symbol was
relocated are *not* source-reachable: the source already says the right thing
and the compiler chose differently. Streams that differ in a mnemonic, an
immediate, or in how many instructions there are describe different code, and
that is a source defect.

This analyzer normalises both streams -- registers to a placeholder, stack
displacements to a placeholder, and any absolute address inside the image to a
placeholder -- then aligns them with difflib so an inserted or deleted
instruction does not misreport everything after it as a substitution. What
survives normalisation is classified, and each function gets a verdict:

  churn      every difference is register / slot / relocation
  structural at least one mnemonic, immediate or instruction-count difference

Ranking the structural list by how many instructions are actually in question
gives a work queue -- and the cheap end of it is the useful end, because a
function whose whole gap is one instruction is usually one source line, while
one with hundreds needs a reconstruction. The churn list is what to stop
looking at.
"""
from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field

from binary_comp.analyzers.function_compare import (
    FunctionCompareError,
    FunctionComparer,
    load_disassembly_policy,
    maybe_build,
)
from binary_comp.analyzers.report import disassembly_path
from binary_comp.source.functions import load_source_groups
from binary_comp.config import ProjectTarget
from binary_comp.core.disasm import Instruction

REGISTERS = (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
)
_REGISTER_RE = re.compile(r"\b(" + "|".join(REGISTERS) + r")\b")
# Capstone prints small displacements in decimal and larger ones in hex.
_STACK_RE = re.compile(r"\b(ebp|esp)\s*([+-])\s*(?:0x[0-9a-f]+|\d+)")
_HEX_RE = re.compile(r"0x[0-9a-f]+")

# Any operand naming a location inside the loaded image is a relocation: the
# rebuilt binary puts the same symbol somewhere else, which says nothing about
# the source.  Immediates outside that window are real constants and stay.
DEFAULT_IMAGE_RANGE = (0x00400000, 0x00800000)


@dataclass(frozen=True)
class TriageOptions:
    build: bool = True
    file_filter: str | None = None
    max_similarity: float = 99.999
    min_similarity: float = 0.0
    limit: int = 0
    show_diffs: int = 0
    largest_first: bool = False
    image_range: tuple[int, int] = DEFAULT_IMAGE_RANGE
    canonical_aliases: dict[str, str] | None = None
    signature_overloads: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TriageDiff:
    """One aligned region where the two streams disagree."""
    kind: str                 # mnemonic | immediate | operand | extra | missing
    ours: tuple[str, ...]
    orig: tuple[str, ...]


@dataclass(frozen=True)
class TriageRow:
    function_name: str
    source_file: str
    original_addr: int
    similarity: float
    total: int                # aligned instruction pairs considered
    matched: int              # identical after normalisation
    register: int             # differ only in register choice
    slot: int                 # differ only in stack displacement
    relocation: int           # differ only in an in-image address
    mnemonic: int             # different instruction
    immediate: int            # same instruction, different constant
    extra: int                # instructions we emit that the original lacks
    missing: int              # instructions the original has that we lack
    diffs: tuple[TriageDiff, ...] = field(default=())

    @property
    def structural(self) -> int:
        return self.mnemonic + self.immediate + self.extra + self.missing

    @property
    def churn(self) -> int:
        return self.register + self.slot + self.relocation

    @property
    def verdict(self) -> str:
        return "structural" if self.structural else "churn"


@dataclass(frozen=True)
class TriageReport:
    options: TriageOptions
    rows: tuple[TriageRow, ...]
    skipped: tuple[tuple[str, str], ...] = field(default=())

    @property
    def structural_rows(self) -> tuple[TriageRow, ...]:
        return tuple(row for row in self.rows if row.verdict == "structural")

    @property
    def churn_rows(self) -> tuple[TriageRow, ...]:
        return tuple(row for row in self.rows if row.verdict == "churn")


def _is_image_address(value: int, image_range: tuple[int, int]) -> bool:
    return image_range[0] <= value < image_range[1]


def normalise(text: str, image_range: tuple[int, int]) -> str:
    """Canonical form: registers, stack displacements and relocations erased."""
    # Stack displacements first, so their hex is not mistaken for a relocation.
    text = _STACK_RE.sub(r"\1+D", text)

    def _hex(match: re.Match[str]) -> str:
        value = int(match.group(0), 16)
        return "A" if _is_image_address(value, image_range) else match.group(0)

    text = _HEX_RE.sub(_hex, text)
    return _REGISTER_RE.sub("R", text)


def _image_addresses(text: str, image_range: tuple[int, int]) -> list[int]:
    return [
        value for value in (int(h, 16) for h in _HEX_RE.findall(text))
        if _is_image_address(value, image_range)
    ]


def _classify(ours: str, orig: str, image_range: tuple[int, int]) -> str:
    """Why two instructions that normalise the same still differ textually.

    Relocations are checked before registers and slots because a differing
    in-image address is the one difference that says nothing at all about the
    build, whereas a register or displacement at least tells you the allocator
    made a different choice.  A pair that differs in both a register and a
    displacement is reported as a slot difference, the more diagnostic of the
    two.
    """
    if _mnemonic_of(ours) != _mnemonic_of(orig):
        return "mnemonic"
    if _image_addresses(ours, image_range) != _image_addresses(orig, image_range):
        return "relocation"
    if _STACK_RE.sub(r"\1+D", ours) == _STACK_RE.sub(r"\1+D", orig):
        return "slot"
    if _REGISTER_RE.sub("R", ours) == _REGISTER_RE.sub("R", orig):
        return "register"
    return "slot"


def _mnemonic_of(text: str) -> str:
    parts = text.split()
    return parts[0] if parts else ""


def _replace_kind(ours: str, orig: str, image_range: tuple[int, int]) -> str:
    """Classify a substitution the aligner produced.

    The aligner works on normalised text, but its block boundaries can still
    pull a churn-only pair into a replace region, so re-check normalisation
    first rather than trusting the block.
    """
    if normalise(ours, image_range) == normalise(orig, image_range):
        return _classify(ours, orig, image_range)
    if _mnemonic_of(ours) != _mnemonic_of(orig):
        return "mnemonic"
    return "immediate"


def _text(instruction: Instruction) -> str:
    return f"{instruction.mnemonic} {instruction.op_str}".strip()


def triage_comparison(
    function_name: str,
    source_file: str,
    original_addr: int,
    similarity: float,
    ours: list[Instruction],
    orig: list[Instruction],
    options: TriageOptions,
) -> TriageRow:
    ours_text = [_text(i) for i in ours]
    orig_text = [_text(i) for i in orig]
    ours_norm = [normalise(t, options.image_range) for t in ours_text]
    orig_norm = [normalise(t, options.image_range) for t in orig_text]

    counts = dict(matched=0, register=0, slot=0, relocation=0,
                  mnemonic=0, immediate=0, extra=0, missing=0)
    diffs: list[TriageDiff] = []

    matcher = difflib.SequenceMatcher(None, ours_norm, orig_norm, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                a, b = ours_text[i1 + k], orig_text[j1 + k]
                if a == b:
                    counts["matched"] += 1
                else:
                    counts[_classify(a, b, options.image_range)] += 1
            continue
        if tag == "delete":
            counts["extra"] += i2 - i1
            diffs.append(TriageDiff("extra", tuple(ours_text[i1:i2]), ()))
            continue
        if tag == "insert":
            counts["missing"] += j2 - j1
            diffs.append(TriageDiff("missing", (), tuple(orig_text[j1:j2])))
            continue
        # replace: pair them up positionally inside the block
        span = min(i2 - i1, j2 - j1)
        for k in range(span):
            a, b = ours_text[i1 + k], orig_text[j1 + k]
            kind = _replace_kind(a, b, options.image_range)
            counts[kind] += 1
            if kind in ("mnemonic", "immediate"):
                diffs.append(TriageDiff(kind, (a,), (b,)))
        if i2 - i1 > span:
            counts["extra"] += (i2 - i1) - span
            diffs.append(TriageDiff("extra", tuple(ours_text[i1 + span:i2]), ()))
        if j2 - j1 > span:
            counts["missing"] += (j2 - j1) - span
            diffs.append(TriageDiff("missing", (), tuple(orig_text[j1 + span:j2])))

    keep = options.show_diffs if options.show_diffs > 0 else 0
    return TriageRow(
        function_name=function_name,
        source_file=source_file,
        original_addr=original_addr,
        similarity=similarity,
        total=max(len(ours_text), len(orig_text)),
        diffs=tuple(diffs[:keep]),
        **counts,
    )


def generate_triage_report(
    target: ProjectTarget,
    options: TriageOptions = TriageOptions(),
) -> TriageReport:
    maybe_build(target, options.build)

    comparer = FunctionComparer(
        target,
        canonical_aliases=options.canonical_aliases,
        signature_overloads=options.signature_overloads,
    )
    load_disassembly_policy(target)
    groups_by_source = load_source_groups(target.source_dirs, target.map_skip, target.source_excludes)

    rows: list[TriageRow] = []
    skipped: list[tuple[str, str]] = []
    for source_path in sorted(groups_by_source):
        source_file = os.path.basename(source_path)
        for group in groups_by_source[source_path]:
            if options.file_filter and (
                options.file_filter not in source_file
                and options.file_filter not in source_path
                and options.file_filter not in group.name
            ):
                continue
            if len(group.addresses) != 1:
                continue          # SEH splits and duplicate instances: not triageable
            original_addr = int(group.addresses[0], 16)
            path = disassembly_path(target, original_addr)
            if path is None or not os.path.exists(path):
                continue
            try:
                comparison = comparer.compare(group.name, path, build=False)
            except (FunctionCompareError, RuntimeError, ValueError) as error:
                skipped.append((group.name, str(error)))
                continue
            if not (options.min_similarity <= comparison.similarity <= options.max_similarity):
                continue
            rows.append(triage_comparison(
                group.name,
                source_file,
                original_addr,
                comparison.similarity,
                list(comparison.rebuilt.instructions),
                list(comparison.original.instructions),
                options,
            ))

    # Cheapest first by default: one differing instruction is a source line,
    # hundreds is a reconstruction, and the queue is worked from the cheap end.
    if options.largest_first:
        rows.sort(key=lambda row: (-row.structural, -row.similarity))
    else:
        rows.sort(key=lambda row: (row.structural, row.churn, -row.similarity))
    if options.limit > 0:
        rows = rows[: options.limit]
    return TriageReport(options=options, rows=tuple(rows), skipped=tuple(skipped))


def format_triage_report(report: TriageReport) -> str:
    structural = report.structural_rows
    churn = report.churn_rows
    lines = [
        "Structural triage",
        "",
        "Normalisation erases register choice, stack displacements and in-image",
        "addresses, then the streams are aligned so an inserted instruction does not",
        "misreport the rest as substitutions.  A `churn` verdict means no source edit",
        "can close the gap; it is not a claim that the function is correct.",
        "",
        f"Functions triaged:        {len(report.rows)}",
        f"  structural:             {len(structural)}",
        f"  churn only:             {len(churn)}",
    ]
    if report.skipped:
        lines.append(f"  skipped (no compare):   {len(report.skipped)}")

    if structural:
        order = "most first" if report.options.largest_first else "fewest first"
        lines += [
            "",
            f"Structural — instructions in question, {order}",
            f"  {'function':<40}{'addr':>9}{'sim':>8}{'mnem':>6}{'imm':>5}"
            f"{'extra':>7}{'miss':>6}{'reg':>5}{'slot':>6}  file",
        ]
        for row in structural:
            lines.append(
                f"  {row.function_name:<40}{row.original_addr:>9X}{row.similarity:>8.2f}"
                f"{row.mnemonic:>6}{row.immediate:>5}{row.extra:>7}{row.missing:>6}"
                f"{row.register:>5}{row.slot:>6}  {row.source_file}"
            )
            for diff in row.diffs:
                for text in diff.ours:
                    lines.append(f"        ours: {text}")
                for text in diff.orig:
                    lines.append(f"        orig: {text}")

    if churn:
        lines += [
            "",
            "Churn only — no source edit reaches these",
            f"  {'function':<40}{'addr':>9}{'sim':>8}{'reg':>5}{'slot':>6}{'reloc':>7}  file",
        ]
        for row in churn:
            lines.append(
                f"  {row.function_name:<40}{row.original_addr:>9X}{row.similarity:>8.2f}"
                f"{row.register:>5}{row.slot:>6}{row.relocation:>7}  {row.source_file}"
            )

    return "\n".join(lines)
