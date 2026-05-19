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


def test_globals_audit_filters_code_globals_by_address_and_kind(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    code_globals = tmp_path / "code_globals.h"
    write_tiny_pe(
        original,
        data_overrides={
            0x10: struct.pack("<I", 9),
            0x1C: struct.pack("<I", 0x12345678),
            0x24: struct.pack("<I", 0x87654321),
        },
    )
    code_globals.write_text(
        "undefined4 DAT_0040201c = { /* 4 bytes */ };\n"
        "undefined4 DAT_00402024 = { /* 4 bytes */ };\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        globals_source=str(fixture_root / "src" / "globals.cpp"),
        code_globals_header=str(code_globals),
    )

    summary = audit_globals(
        {},
        target,
        GlobalsAuditOptions(
            min_address=0x402000,
            max_address=0x402020,
            issue_kinds=("code-global-not-in-src",),
            include_code_globals=True,
            no_auto_complete_global_effects=True,
        ),
    )

    assert [(issue.category, issue.address) for issue in summary.issues] == [
        ("CODE_GLOBAL_NOT_IN_SRC", 0x40201C),
    ]


def test_globals_audit_discovers_crt_initializer_global_writes(fixture_root, tmp_path):
    pytest.importorskip("capstone")
    from conftest import DATA_VA, TEXT_VA, write_tiny_pe

    original = tmp_path / "original.exe"
    code = bytearray(b"\x90" * 0x50)
    code[0:5] = b"\x68" + struct.pack("<I", DATA_VA + 0x0C)
    code[5:10] = b"\x68" + struct.pack("<I", DATA_VA + 0x08)
    code[10:15] = b"\xE8" + struct.pack("<i", (TEXT_VA + 0x20) - (TEXT_VA + 15))
    code[15] = 0xC3
    code[0x20] = 0xC3
    code[0x30:0x3B] = b"\xC7\x05" + struct.pack("<I", DATA_VA + 0x10) + struct.pack("<I", 42) + b"\xC3"
    write_tiny_pe(
        original,
        function_bytes=bytes(code),
        data_overrides={0x08: struct.pack("<I", TEXT_VA + 0x30)},
    )

    summary = audit_globals(
        {},
        make_target(fixture_root, original),
        GlobalsAuditOptions(min_address=0x402000),
    )

    assert summary.issues == []
    assert [(entry.address, [fact.category for fact in facts]) for entry, facts in summary.auto_results] == [
        (TEXT_VA + 0x30, ["DIRECT_WRITE"]),
    ]
    assert summary.unreviewed_auto_complete_count == 1
    report = format_report(summary)
    assert "CRT initializer table 0x00402008..0x0040200c" in report
    assert "g_Number_00402010" in report


def test_globals_audit_verifies_runtime_initializer_copy_source(fixture_root, sample_binaries, tmp_path):
    original, _rebuilt = sample_binaries
    globals_source = tmp_path / "globals.cpp"
    globals_source.write_text(
        "int g_Source_00402010 = 7;\n"
        "int g_Target_00402018 = g_Source_00402010;\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(tmp_path),),
        globals_source=str(globals_source),
    )

    summary = audit_globals(
        {"globals": {"runtime_initializer_copies": {"0x00402018": "0x00402010"}}},
        target,
        GlobalsAuditOptions(min_address=0x402000, no_auto_complete_global_effects=True),
    )

    assert summary.issues == []

    globals_source.write_text(
        "int g_Source_00402010 = 7;\n"
        "int g_Target_00402018 = 0;\n",
        encoding="utf-8",
    )

    summary = audit_globals(
        {"globals": {"runtime_initializer_copies": {"0x00402018": "0x00402010"}}},
        target,
        GlobalsAuditOptions(min_address=0x402000, no_auto_complete_global_effects=True),
    )

    assert [issue.category for issue in summary.issues] == ["RUNTIME_INIT_SOURCE_MISMATCH"]
