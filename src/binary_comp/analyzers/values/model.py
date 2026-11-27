"""Records shared by the values analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from binary_comp.core.disasm import Instruction
from binary_comp.policy import VerifierPolicy
from binary_comp.source.functions import FunctionGroup

# Report label for each warning kind, in report order.
WARNING_LABELS: dict[str, str] = {
    "imm": "IMM",
    "string": "STRING",
    "offset": "OFFSET",
    "branch": "BRANCH",
    "arg": "ARG",
}


class ValueWarning(NamedTuple):
    """One value that differs between a rebuilt and an original instruction.

    ``kind`` is a key of ``WARNING_LABELS``.  The two values are what each side
    has: an immediate or displacement for ``imm`` and ``offset``, the decoded
    literal (or None) for ``string``, the conditional-branch mnemonic for
    ``branch`` and the stack offset an argument was loaded from for ``arg``.
    ``compiled`` and ``original`` are the instructions the values sit on.
    """

    kind: str
    compiled_value: int | str | None
    original_value: int | str | None
    compiled: Instruction
    original: Instruction


@dataclass(frozen=True)
class CheckResult:
    original_addr: int
    rebuilt_addr: int
    similarity: float
    original_count: int
    rebuilt_count: int
    warnings: tuple[ValueWarning, ...]


@dataclass(frozen=True)
class CompareContext:
    enabled_kinds: frozenset[str]
    policy: VerifierPolicy
    include_stack_locals: bool
    compiled_diagnostic_targets: frozenset[int]
    original_diagnostic_targets: frozenset[int]
    compiled_call_targets: dict[int, str] = field(default_factory=dict)
    original_call_targets: dict[int, str] = field(default_factory=dict)
    # Addresses whose trailing operand a loader relocates.  An immediate
    # sitting on one is a link-time placeholder for an address, not a value the
    # source chose, so the two images can never agree on it.
    compiled_relocated: frozenset[int] = frozenset()
    original_relocated: frozenset[int] = frozenset()


@dataclass(frozen=True)
class ValuesOptions:
    file_filter: str | None = None
    min_similarity: float = 0.0
    build: bool = True
    enabled_kinds: frozenset[str] = frozenset({"strings", "immediates", "offsets"})
    boundary_report: bool = False
    include_stack_locals: bool = False


@dataclass(frozen=True)
class ValuesSummary:
    functions_checked: int
    with_value_mismatches: int
    total_mismatches: int
    skipped_no_bytes: int
    skipped_below_threshold: int
    unmapped_source_groups: int
    boundary_inventory: dict[str, int]
    reports: tuple[tuple[FunctionGroup, CheckResult], ...]
    # Every function compared, not only the ones that differ, so a single run
    # answers "how close is the whole project" as well as "what is wrong".
    similarity: tuple[tuple[str, float], ...] = ()
