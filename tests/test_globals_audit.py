from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.globals import GlobalsAuditOptions, audit_globals, format_report
from binary_comp.config import ProjectTarget


pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_cpp")


def make_target(fixture_root, original) -> ProjectTarget:
    return ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        globals_source=str(fixture_root / "src" / "globals.cpp"),
    )


def test_globals_audit_accepts_matching_source_globals(fixture_root, sample_binaries):
    original, _rebuilt = sample_binaries

    summary = audit_globals(
        {},
        make_target(fixture_root, original),
        GlobalsAuditOptions(min_address=0x402000, no_auto_complete_global_effects=True),
    )

    assert summary.total_defs == 3
    assert summary.issues == []
    assert summary.address_warnings == []
    assert "No suspicious global initializer/layout issues found." in format_report(summary)


def test_globals_audit_reports_initializer_mismatch(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x10: struct.pack("<I", 9)})

    summary = audit_globals(
        {},
        make_target(fixture_root, original),
        GlobalsAuditOptions(min_address=0x402000, no_auto_complete_global_effects=True),
    )

    assert [issue.category for issue in summary.issues] == ["INIT_MISMATCH"]
    assert summary.issues[0].name == "g_Number_00402010"
    assert "INIT_MISMATCH" in format_report(summary)


def test_globals_audit_uses_configured_define_headers(fixture_root, sample_binaries, tmp_path):
    original, _rebuilt = sample_binaries
    globals_source = tmp_path / "globals.cpp"
    constants = tmp_path / "constants.h"
    globals_source.write_text("int g_Array_00402018[SAMPLE_COUNT];\n", encoding="utf-8")
    constants.write_text("#define SAMPLE_COUNT 2\n", encoding="utf-8")
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(tmp_path),),
        globals_source=str(globals_source),
        define_headers=(str(constants),),
    )

    summary = audit_globals(
        {},
        target,
        GlobalsAuditOptions(min_address=0x402000, no_auto_complete_global_effects=True),
    )

    assert summary.issues == []
