from __future__ import annotations

import pytest

from binary_comp.analyzers.exe import (
    ExeCompareOptions,
    compare_executable,
    format_executable_comparison,
)
from binary_comp.config import BuildConfig, ProjectTarget


def test_compare_executable_sections_and_functions(fixture_root, sample_binaries):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(fixture_root / "code"),
        build=BuildConfig(),
    )

    comparison = compare_executable(target, ExeCompareOptions(include_functions=True))
    text = format_executable_comparison(comparison)

    assert all(section.matches for section in comparison.sections)
    assert comparison.functions is not None
    assert comparison.functions.total == 1
    assert comparison.functions.correct_address == 1
    assert comparison.functions.rows[0].raw_match_percent == 100.0
    assert ".text" in text
    assert "Total functions: 1" in text
