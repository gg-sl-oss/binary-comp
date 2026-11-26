"""Finding one function in an MSVC ``/FA`` assembly listing.

A function in the listing looks like::

    _TEXT   SEGMENT
    ?score@ScoreTable@@QAEHH@Z PROC NEAR                  ; ScoreTable::score, COMDAT
            push    ebp
            ...
    _TEXT   ENDS
    text$x  SEGMENT
    __unwindfunclet$?score@...$0:                          ; EH funclets, if any
            ...
    text$x  ENDS
    ?score@ScoreTable@@QAEHH@Z ENDP

With synchronous C++ exception handling MSVC closes the function's code
segment and emits the unwind funclets in ``text$x`` before the final ``ENDP``.
Those funclets are cleanup paths driven by EH metadata, not part of the
function body, so callers comparing the body stop at the first ``ENDS``.
"""

from __future__ import annotations

import re
from typing import Iterable

from binary_comp.core.symbols import normalize_compiled


_SEGMENT_END_RE = re.compile(r"\S+\s+ENDS\b", re.IGNORECASE)
_PROC_END_RE = re.compile(r"\bENDP\b")


def proc_line_matches(
    stripped: str,
    function_name: str,
    *,
    match_symbol: bool = True,
    signature_names: frozenset[str] = frozenset(),
) -> bool:
    """Whether a ``PROC`` line opens ``function_name``.

    The ``; name`` comment MSVC writes after ``PROC`` is checked first; with
    ``match_symbol`` the demangled symbol before ``PROC`` is also accepted.
    """
    if "PROC" not in stripped:
        return False
    if "; " in stripped:
        comment = stripped.split("; ", 1)[1].strip()
        if comment.endswith(", COMDAT"):
            comment = comment[:-len(", COMDAT")].strip()
        if comment == function_name:
            return True
    if not match_symbol:
        return False
    symbol = stripped.split(None, 1)[0]
    return normalize_compiled(symbol, signature_names) == function_name


def function_lines_from(
    lines: Iterable[str],
    function_name: str,
    occurrence_index: int = 0,
    *,
    match_symbol: bool = True,
    signature_names: frozenset[str] = frozenset(),
    stop_at_segment_end: bool = True,
) -> list[str]:
    """The stripped lines of the ``occurrence_index``-th ``function_name`` body.

    Counting occurrences handles a source function compiled more than once
    in the same listing (templates, duplicated statics). The body ends at
    ``ENDP``, or, with ``stop_at_segment_end``, at the first ``ENDS`` so
    trailing EH funclets are left out.
    """
    body: list[str] = []
    current_index = -1
    in_function = False
    for line in lines:
        stripped = line.strip()
        if not in_function:
            if not proc_line_matches(
                stripped,
                function_name,
                match_symbol=match_symbol,
                signature_names=signature_names,
            ):
                continue
            current_index += 1
            if current_index == occurrence_index:
                in_function = True
            continue
        if stop_at_segment_end and _SEGMENT_END_RE.match(stripped):
            break
        if _PROC_END_RE.search(stripped):
            break
        body.append(stripped)
    return body


def function_lines(
    asm_path: str,
    function_name: str,
    occurrence_index: int = 0,
    *,
    match_symbol: bool = True,
    signature_names: frozenset[str] = frozenset(),
    stop_at_segment_end: bool = True,
) -> list[str]:
    """``function_lines_from`` on a listing file; [] if it cannot be read."""
    try:
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    return function_lines_from(
        lines,
        function_name,
        occurrence_index,
        match_symbol=match_symbol,
        signature_names=signature_names,
        stop_at_segment_end=stop_at_segment_end,
    )
