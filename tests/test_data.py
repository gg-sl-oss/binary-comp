from __future__ import annotations

import struct

from binary_comp.analyzers.data import (
    DataOptions,
    compare_address,
    compare_global_data,
    find_missing_globals,
    format_comparison,
    format_missing_globals,
)
from binary_comp.analyzers.globals import GlobalDecl as AuditGlobalDecl, build_rebuilt_layout_issues
from binary_comp.core.mapfile import parse_encoded_address_symbols
from binary_comp.source.globals import parse_globals_source


def test_parse_global_declarations(fixture_root):
    globals_list = parse_globals_source(str(fixture_root / "src" / "globals.cpp"))

    assert [item.name for item in globals_list] == [
        "g_Text_00402000",
        "g_Number_00402010",
        "g_CommentAddress",
    ]
    assert globals_list[0].address == 0x402000
    assert globals_list[0].size == 6
    assert globals_list[1].size == 4
    assert globals_list[2].address == 0x402018


def test_parse_pointer_declarations_with_adjacent_star(tmp_path):
    globals_path = tmp_path / "globals.cpp"
    globals_path.write_text(
        "char *g_Buffer_00402020 = 0;\n"
        "char* g_Text_00402024 = 0;\n"
        "static const unsigned int g_Count_00402028 = 1;\n",
        encoding="utf-8",
    )

    globals_list = parse_globals_source(str(globals_path))

    assert [item.address for item in globals_list] == [0x402020, 0x402024, 0x402028]
    assert [item.size for item in globals_list] == [4, 4, 4]


def test_parse_global_declarations_with_multiline_initializer(tmp_path):
    globals_path = tmp_path / "globals.cpp"
    globals_path.write_text(
        "int g_Table_00402030[3] = {\n"
        "    1,\n"
        "    2,\n"
        "    3,\n"
        "};\n",
        encoding="utf-8",
    )

    globals_list = parse_globals_source(str(globals_path))

    assert len(globals_list) == 1
    assert globals_list[0].address == 0x402030
    assert globals_list[0].size == 12


def test_compare_global_data_matches(fixture_root, sample_binaries):
    original, rebuilt = sample_binaries

    summary = compare_global_data(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        str(fixture_root / "src" / "globals.cpp"),
        DataOptions(),
    )

    assert summary.global_count == 3
    assert summary.matches == 2
    assert summary.mismatches == 0
    assert summary.missing_symbols == 1
    assert "Summary: 2 matches, 0 mismatches, 1 not in rebuilt map" in format_comparison(summary)


def test_compare_global_data_reports_mismatch(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    rebuilt = tmp_path / "rebuilt.exe"
    write_tiny_pe(original)
    write_tiny_pe(rebuilt, data_overrides={0x10: struct.pack("<I", 9)})

    summary = compare_global_data(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        str(fixture_root / "src" / "globals.cpp"),
        DataOptions(),
    )

    assert summary.matches == 1
    assert summary.mismatches == 1
    assert [item.status for item in summary.comparisons] == ["OK", "MISMATCH", "NO_SYMBOL"]
    assert "Original value: 0x00000007 (7)" in format_comparison(summary)
    assert "Rebuilt value:  0x00000009 (9)" in format_comparison(summary)


def test_compare_one_address_uses_map(fixture_root, sample_binaries):
    original, rebuilt = sample_binaries
    comparison = compare_address(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        0x402010,
        4,
    )

    assert comparison.matches
    assert comparison.rebuilt_address == 0x402010


def test_parse_encoded_address_symbols_keeps_symbol_names(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       ?g_Text_00402000@@3PADA 00402000     globals.obj\n"
        " 0003:0004ff20       _g_Block_00488158      004b5f20     <common>\n",
        encoding="utf-8",
    )

    entries = parse_encoded_address_symbols(str(map_path))

    assert [(entry.original_va, entry.rebuilt_va, entry.symbol) for entry in entries] == [
        (0x402000, 0x402000, "?g_Text_00402000@@3PADA"),
        (0x488158, 0x4B5F20, "_g_Block_00488158"),
    ]


def test_rebuilt_layout_check_reports_split_overlapping_globals(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _g_Block_00402000      00406000     <common>\n"
        " 0003:00000010       _g_Field_00402004      00406100     <common>\n",
        encoding="utf-8",
    )
    block = AuditGlobalDecl(0x402000, "g_Block_00402000", "", 1, "char", ["16"], False, None, 16)
    field = AuditGlobalDecl(0x402004, "g_Field_00402004", "", 2, "int", [], False, None, 4)

    issues = build_rebuilt_layout_issues([block, field], str(map_path), 0)

    assert len(issues) == 1
    assert issues[0].category == "REBUILT_LAYOUT_ALIAS_SPLIT"
    assert "expected 0x00406004" in issues[0].detail


def test_rebuilt_layout_check_reports_split_adjacent_globals_used_as_layout_base(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00402000      00406000     <common>\n"
        " 0003:00000010       _DAT_00402002      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern short DAT_00402000;\n"
        "int f(int offset) { return *(short *)((char *)&DAT_00402000 + offset); }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x402000, "DAT_00402000", "", 1, "short", [], False, None, 2)
    second = AuditGlobalDecl(0x402002, "DAT_00402002", "", 2, "short", [], False, None, 2)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert len(issues) == 1
    assert issues[0].category == "REBUILT_LAYOUT_ADJACENT_SPLIT"
    assert "activity.cpp:2" in issues[0].detail
    assert "expected 0x00406002" in issues[0].detail


def test_rebuilt_layout_check_reports_split_adjacent_array_used_as_pointer_base(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00482780      00406000     <common>\n"
        " 0003:00000010       _DAT_00482790      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern short DAT_00482780[8];\n"
        "void f(void) { short *p; int i; p = DAT_00482780; i = 3; do { p = p + 4; i = i + -1; } while (i != 0); }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x482780, "DAT_00482780", "", 1, "short", ["8"], False, None, 16)
    second = AuditGlobalDecl(0x482790, "DAT_00482790", "", 2, "short", ["4"], False, None, 8)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert len(issues) == 1
    assert issues[0].category == "REBUILT_LAYOUT_ADJACENT_SPLIT"
    assert "activity.cpp:2" in issues[0].detail
    assert "expected 0x00406010" in issues[0].detail


def test_rebuilt_layout_check_ignores_split_adjacent_globals_without_layout_use(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00402000      00406000     <common>\n"
        " 0003:00000010       _DAT_00402002      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern short DAT_00402000;\n"
        "extern short DAT_00402002;\n"
        "int f(void) { return DAT_00402000 + DAT_00402002; }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x402000, "DAT_00402000", "", 1, "short", [], False, None, 2)
    second = AuditGlobalDecl(0x402002, "DAT_00402002", "", 2, "short", [], False, None, 2)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert issues == []


def test_rebuilt_layout_check_ignores_in_bounds_array_subscript(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00402000      00406000     <common>\n"
        " 0003:00000010       _DAT_00402010      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern short DAT_00402000[8];\n"
        "int f(void) { return DAT_00402000[1]; }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x402000, "DAT_00402000", "", 1, "short", ["8"], False, None, 16)
    second = AuditGlobalDecl(0x402010, "DAT_00402010", "", 2, "short", ["4"], False, None, 8)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert issues == []


def test_rebuilt_layout_check_ignores_in_bounds_array_pointer_walk(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00402000      00406000     <common>\n"
        " 0003:00000010       _DAT_00402034      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern unsigned int DAT_00402000[13];\n"
        "void f(void) { unsigned int *p; int i; p = DAT_00402000; i = 13; do { p++; i = i + -1; } while (i != 0); }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x402000, "DAT_00402000", "", 1, "unsigned int", ["13"], False, None, 52)
    second = AuditGlobalDecl(0x402034, "DAT_00402034", "", 2, "short", [], False, None, 2)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert issues == []


def test_rebuilt_layout_check_ignores_pointer_global_element_address(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _g_Items_00402000      00406000     <common>\n"
        " 0003:00000010       _g_Timer_00402004      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "struct Item { int value; };\n"
        "extern struct Item *g_Items_00402000;\n"
        "void render(int i) { draw(&g_Items_00402000[i]); }\n",
        encoding="utf-8",
    )
    items = AuditGlobalDecl(0x402000, "g_Items_00402000", "", 1, "struct Item*", [], False, None, 4)
    timer = AuditGlobalDecl(0x402004, "g_Timer_00402004", "", 2, "int", [], False, None, 4)

    issues = build_rebuilt_layout_issues([items, timer], str(map_path), 0, (str(source_dir),))

    assert issues == []


def test_rebuilt_layout_check_ignores_constant_in_bounds_field_access(tmp_path):
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0003:00000000       _DAT_00402000      00406000     <common>\n"
        " 0003:00000010       _DAT_00402004      00406100     <common>\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "activity.cpp").write_text(
        "extern int DAT_00402000;\n"
        "void f(void) { ((short *)&DAT_00402000)[1] = 7; }\n",
        encoding="utf-8",
    )
    first = AuditGlobalDecl(0x402000, "DAT_00402000", "", 1, "int", [], False, None, 4)
    second = AuditGlobalDecl(0x402004, "DAT_00402004", "", 2, "int", [], False, None, 4)

    issues = build_rebuilt_layout_issues([first, second], str(map_path), 0, (str(source_dir),))

    assert issues == []


def test_find_missing_globals_reports_uncovered_dwords(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x1C: struct.pack("<I", 0x12345678)})

    summary = find_missing_globals(
        str(original),
        str(fixture_root / "src" / "globals.cpp"),
    )

    assert summary.known_globals == 3
    assert [candidate.address for candidate in summary.candidates] == [0x40201C]
    assert "0x0040201c" in format_missing_globals(summary)
