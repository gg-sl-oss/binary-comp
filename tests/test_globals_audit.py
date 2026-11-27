from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.globals import (
    GlobalDecl, GlobalsAuditOptions, audit_globals, format_report, globals_types,
    numeric_array_bytes, strip_comments, symbolic_struct_array_bytes,
)
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


def test_globals_audit_reports_original_direct_access_spanning_adjacent_global(tmp_path):
    from conftest import DATA_VA, write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x10: b"\0\0\0\0"})
    src_dir = tmp_path / "src"
    code_dir = tmp_path / "code"
    src_dir.mkdir()
    code_dir.mkdir()
    globals_source = src_dir / "globals.cpp"
    globals_source.write_text(
        "short g_PairX_00402010;\n"
        "short g_PairY_00402012;\n",
        encoding="utf-8",
    )
    (code_dir / "FUN_00401000.disassembled.txt").write_text(
        "Function: FUN_00401000\n"
        "Address: 0x00401000\n\n"
        "MOV EAX,[0x00402010]\n",
        encoding="utf-8",
    )

    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(tmp_path / "empty.map"),
        source_dirs=(str(src_dir),),
        globals_source=str(globals_source),
        code_dir=str(code_dir),
    )
    (tmp_path / "empty.map").write_text("", encoding="utf-8")

    summary = audit_globals(
        {},
        target,
        GlobalsAuditOptions(
            min_address=DATA_VA,
            check_rebuilt_layout=True,
            no_auto_complete_global_effects=True,
        ),
    )

    assert [(issue.category, issue.name) for issue in summary.issues] == [
        ("ORIGINAL_DIRECT_GLOBAL_SPAN", "g_PairX_00402010"),
    ]


def test_globals_audit_reports_casted_address_of_adjacent_split(tmp_path):
    from conftest import DATA_VA, write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x10: b"\0\0\0\0"})
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    globals_source = src_dir / "globals.cpp"
    globals_source.write_text(
        "short g_PairX_00402010;\n"
        "short g_PairY_00402012;\n",
        encoding="utf-8",
    )
    (src_dir / "use.cpp").write_text(
        "int read_pair(void) { return *(unsigned int *)&g_PairX_00402010; }\n",
        encoding="utf-8",
    )
    rebuilt_map = tmp_path / "rebuilt.map"
    rebuilt_map.write_text(
        " 0003:00000000       _g_PairX_00402010 00500000     <common>\n"
        " 0003:00000010       _g_PairY_00402012 00500010     <common>\n",
        encoding="utf-8",
    )

    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(rebuilt_map),
        source_dirs=(str(src_dir),),
        globals_source=str(globals_source),
    )

    summary = audit_globals(
        {},
        target,
        GlobalsAuditOptions(
            min_address=DATA_VA,
            check_rebuilt_layout=True,
            no_auto_complete_global_effects=True,
        ),
    )

    assert [(issue.category, issue.name) for issue in summary.issues] == [
        ("REBUILT_LAYOUT_ADJACENT_SPLIT", "g_PairX_00402010"),
    ]


def test_globals_audit_reports_reviewed_layout_dependency_separately(tmp_path):
    from conftest import DATA_VA, write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x10: b"\0\0\0\0"})
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    globals_source = src_dir / "globals.cpp"
    globals_source.write_text(
        "short g_PairX_00402010;\n"
        "short g_PairY_00402012;\n",
        encoding="utf-8",
    )
    (src_dir / "use.cpp").write_text(
        "int read_pair(void) { return *(unsigned int *)&g_PairX_00402010; }\n",
        encoding="utf-8",
    )
    rebuilt_map = tmp_path / "rebuilt.map"
    rebuilt_map.write_text(
        " 0003:00000000       _g_PairX_00402010 00500000     <common>\n"
        " 0003:00000010       _g_PairY_00402012 00500010     <common>\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(rebuilt_map),
        source_dirs=(str(src_dir),),
        globals_source=str(globals_source),
    )
    config = {
        "globals": {
            "reviewed_layout_issues": {
                "full": {
                    "REBUILT_LAYOUT_ADJACENT_SPLIT:0x00402010":
                        "The source intentionally loads the packed pair."
                }
            }
        }
    }

    summary = audit_globals(
        config,
        target,
        GlobalsAuditOptions(
            min_address=DATA_VA,
            check_rebuilt_layout=True,
            no_auto_complete_global_effects=True,
        ),
    )

    assert summary.issues == []
    assert [(issue.category, issue.name, review) for issue, review in summary.layout_reviewed] == [
        (
            "REBUILT_LAYOUT_ADJACENT_SPLIT",
            "g_PairX_00402010",
            "The source intentionally loads the packed pair.",
        )
    ]
    report = format_report(summary)
    assert "reviewed layout dependencies: 1" in report
    assert "Reviewed layout dependencies" in report
    assert "The source intentionally loads the packed pair." in report


def test_globals_audit_reports_rebuilt_asm_access_spanning_source_global(tmp_path):
    from conftest import DATA_VA, write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x10: b"\0\0\0\0"})
    src_dir = tmp_path / "src"
    asm_dir = tmp_path / "out"
    src_dir.mkdir()
    asm_dir.mkdir()
    globals_source = src_dir / "globals.cpp"
    globals_source.write_text(
        "short g_PairX_00402010;\n"
        "short g_PairY_00402012;\n",
        encoding="utf-8",
    )
    (asm_dir / "sample.asm").write_text(
        "_TEXT SEGMENT\n"
        "_Run PROC NEAR ; Run\n"
        "    mov eax, DWORD PTR _g_PairX_00402010\n"
        "_Run ENDP\n"
        "_TEXT ENDS\n",
        encoding="utf-8",
    )

    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(original),
        map_path=str(tmp_path / "empty.map"),
        source_dirs=(str(src_dir),),
        globals_source=str(globals_source),
        asm_dir=str(asm_dir),
    )
    (tmp_path / "empty.map").write_text("", encoding="utf-8")

    summary = audit_globals(
        {},
        target,
        GlobalsAuditOptions(
            min_address=DATA_VA,
            check_rebuilt_layout=True,
            no_auto_complete_global_effects=True,
        ),
    )

    assert [(issue.category, issue.name) for issue in summary.issues] == [
        ("REBUILT_GLOBAL_SYMBOL_SPAN", "g_PairX_00402010"),
    ]


def test_symbolic_struct_array_packs_byte_fields():
    types = globals_types({"symbolic_struct_arrays": {"Entry": {"fields": [
        {"kind": "uint8"}, {"kind": "uint16"}, {"kind": "uint8"},
    ]}}})
    decl = GlobalDecl(
        address=0x1000, name="entries", statement="", line=1, type_text="Entry",
        dims=["2"], has_initializer=True,
        initializer="{{1, 0x203, 0x1ff}, {(unsigned char)4, 5, 6}}",
    )

    data, note = symbolic_struct_array_bytes(decl, {}, {}, {}, types=types)

    assert note == ""
    assert data == bytes([1, 0x03, 0x02, 0xFF, 4, 5, 0, 6])


def test_eval_int_expr_uses_c_semantics():
    from binary_comp.analyzers.globals import eval_int_expr

    assert eval_int_expr("-7 / 2", {}) == -3  # truncates toward zero
    assert eval_int_expr("-7 % 2", {}) == -1
    assert eval_int_expr("010", {}) == 8  # octal
    assert eval_int_expr("'A' + 1", {}) == 66
    assert eval_int_expr("0x10u << 2", {}) == 64
    assert eval_int_expr("(COUNT > 4 ? COUNT : 4) ^ 1", {"COUNT": 6}) == 7
    assert eval_int_expr("5 * 25 * 15", {}) == 1875
    with pytest.raises(ValueError):
        eval_int_expr("UNKNOWN_NAME + 1", {})
    with pytest.raises(ValueError):
        eval_int_expr("1 / 0", {})
    with pytest.raises(ValueError):
        eval_int_expr("sizeof(int)", {})


def test_strip_comments_keeps_comment_markers_inside_literals():
    assert strip_comments('"http://x"; // url') == '"http://x"; '
    assert strip_comments("'/' /* slash */ + 1") == "'/'  + 1"
    # An escaped quote does not end the literal, so "/*b*/" is not a comment.
    assert strip_comments(r'"a\"/*b*/c"') == r'"a\"/*b*/c"'


def test_string_array_with_a_url_initializer_is_encoded():
    decl = GlobalDecl(
        address=0x00405000,
        name="g_Url_00405000",
        statement='char g_Url_00405000[] = "http://x";',
        line=1,
        type_text="char",
        dims=[""],
        has_initializer=True,
        initializer='"http://x"',
    )
    # strip_comments used to cut the string at "//" and parsing then raised.
    assert numeric_array_bytes(decl, {}, types=globals_types({})) == (b"http://x\0", "")


def test_c_literals_decode_with_c_escapes_and_one_byte_per_character():
    from binary_comp.analyzers.globals import parse_c_char_value, parse_c_string_bytes

    assert parse_c_string_bytes('"a\\?b"') == b"a?b"
    assert parse_c_string_bytes('"\\101\\0\\12x\\777"') == b"A\x00\nx\xff"
    assert parse_c_string_bytes('"\\x41\\x4142\\q"') == b"ABq"  # a hex escape takes every hex digit after it
    assert parse_c_string_bytes('"tab\\there" "\\\\\\""') == b"tab\there\\\""
    # Outside ASCII: Windows-1252 where it has the character, else the low byte.
    assert parse_c_string_bytes('"h\u00e9 5\u20ac \u0101"') == b"h\xe9 5\x80 \x01"
    assert parse_c_char_value("'\\?'") == ord("?")
    assert parse_c_char_value("'\u00e9'") == 0xE9
    assert parse_c_char_value("'\\x7f'") == 0x7F
    with pytest.raises(ValueError):
        parse_c_char_value("'ab'")
    with pytest.raises(ValueError):
        parse_c_string_bytes("no quotes")
