"""Records shared by the values analyzer."""

from __future__ import annotations

from binary_comp.policy import VerifierPolicy
from binary_comp.source.functions import FunctionGroup
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CheckResult:
    original_addr: int
    rebuilt_addr: int
    similarity: float
    original_count: int
    rebuilt_count: int
    warnings: tuple


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
