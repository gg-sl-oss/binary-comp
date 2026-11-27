"""Capstone-backed operand value verification.

The check aligns each rebuilt function with its original counterpart and
compares the values inside matching instructions: string literals,
small immediates, member displacements, branch conditions and stack-argument
origins.  The modules are layered, each importing only from those above it:

- ``model``: options, context and result records.
- ``operands``: predicates over one instruction or operand.
- ``disassembly``: function boundaries and disassembly.
- ``dataflow``: backward facts about an instruction's inputs (aliases,
  affine register values, stack-argument origins).
- ``calls``: call and pushed-argument context.
- ``branches`` and ``x87``: comparison relations and branch layout.
- ``suppressors``: equivalences that explain an operand difference away.
- ``compare``: the per-pair comparison that applies them.
- ``align``: instruction alignment.
- ``check``: the whole-project driver.
- ``report``: text output.
"""

from binary_comp.analyzers.values.check import check_values
from binary_comp.analyzers.values.model import (
    CheckResult,
    CompareContext,
    ValueWarning,
    ValuesOptions,
    ValuesSummary,
)
from binary_comp.analyzers.values.report import format_summary

__all__ = [
    "CheckResult",
    "CompareContext",
    "ValueWarning",
    "ValuesOptions",
    "ValuesSummary",
    "check_values",
    "format_summary",
]
