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


def test_map_directory_addresses_skip_asm_stub_and_inactive_annotations(tmp_path):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    from binary_comp.analyzers.exe import original_function_addresses_from_map_dirs

    map_dir = tmp_path / "map"
    map_dir.mkdir()
    (map_dir / "inventory.cpp").write_text(
        "/* Function start: 0x00401000 */\n"
        "/* Function start: 0x00401010 */ /* ASM */\n"
        "/* Function start: 0x00401020 */ /* STUB */\n"
        "/* Function start: 0x00401030 */\n"
        "void rebuilt() {}\n",
        encoding="utf-8",
    )

    # The regex used to count the ASM and STUB entries as well.
    assert original_function_addresses_from_map_dirs((str(map_dir),)) == (0x401000, 0x401030)
