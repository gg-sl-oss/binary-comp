from __future__ import annotations

import json
import struct

import pytest

from binary_comp.analyzers.vtables import VtableOptions, check_vtables, parse_header_metadata
from binary_comp.config import load_project_target

from conftest import DATA_VA, TEXT_VA, write_tiny_pe


pytest.importorskip("capstone")
pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_cpp")


def test_vtable_checker_on_generated_fixture_project(tmp_path):
    original = tmp_path / "original.exe"
    function_bytes = b"\xC7\x01" + struct.pack("<I", DATA_VA) + b"\xC3"
    write_tiny_pe(
        original,
        function_bytes=function_bytes,
        data_overrides={0: struct.pack("<I", TEXT_VA + 0x10)},
    )

    (tmp_path / "rebuilt.exe").write_bytes(original.read_bytes())
    (tmp_path / "rebuilt.map").write_text("", encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.h").write_text(
        """
/* Constructor: 0x00401000, vtable 0x00402000. */
class Sample {
public:
    virtual ~Sample();
};
""",
        encoding="utf-8",
    )
    (src / "sample.cpp").write_text(
        """
#include "sample.h"

/* Function start: 0x00401010 */
Sample::~Sample() {}
""",
        encoding="utf-8",
    )

    code = tmp_path / "code"
    code.mkdir()
    (code / "FUN_00401000.disassembled.txt").write_text("", encoding="utf-8")
    (code / "FUN_00401010.disassembled.txt").write_text("", encoding="utf-8")

    config_path = tmp_path / "binary-comp.json"
    config_path.write_text(
        json.dumps({
            "targets": {
                "full": {
                    "original_exe": "original.exe",
                    "rebuilt_exe": "rebuilt.exe",
                    "map": "rebuilt.map",
                    "source_dirs": ["src"],
                    "code_export_dir": "code",
                }
            },
            "vtables": {
                "rdata_range": [hex(DATA_VA), hex(DATA_VA + 0x20)]
            },
        }),
        encoding="utf-8",
    )

    config, target = load_project_target(config_path, "full")
    summary = check_vtables(config, target, VtableOptions())

    assert summary.totals["slots"] == 1
    assert summary.totals["implemented"] == 1
    assert summary.totals["missing_real"] == 0
    assert summary.totals["symbol_mismatch"] == 0
    assert not summary.has_failures


def test_declared_parent_without_vtable_info_is_not_invalid(tmp_path):
    original = tmp_path / "original.exe"
    function_bytes = b"\xC7\x01" + struct.pack("<I", DATA_VA) + b"\xC3"
    write_tiny_pe(
        original,
        function_bytes=function_bytes,
        data_overrides={0: struct.pack("<I", TEXT_VA + 0x10)},
    )

    (tmp_path / "rebuilt.exe").write_bytes(original.read_bytes())
    (tmp_path / "rebuilt.map").write_text("", encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.h").write_text(
        """
class Base {
public:
    virtual void f();
};

/* Constructor: 0x00401000, vtable 0x00402000. */
class Child : public Base {
public:
    virtual void f();
};
""",
        encoding="utf-8",
    )
    (src / "sample.cpp").write_text(
        """
#include "sample.h"

/* Function start: 0x00401010 */
void Child::f() {}
""",
        encoding="utf-8",
    )

    code = tmp_path / "code"
    code.mkdir()
    (code / "FUN_00401000.disassembled.txt").write_text("", encoding="utf-8")
    (code / "FUN_00401010.disassembled.txt").write_text("", encoding="utf-8")

    config_path = tmp_path / "binary-comp.json"
    config_path.write_text(
        json.dumps({
            "targets": {
                "full": {
                    "original_exe": "original.exe",
                    "rebuilt_exe": "rebuilt.exe",
                    "map": "rebuilt.map",
                    "source_dirs": ["src"],
                    "code_export_dir": "code",
                }
            },
            "vtables": {
                "rdata_range": [hex(DATA_VA), hex(DATA_VA + 0x20)]
            },
        }),
        encoding="utf-8",
    )

    config, target = load_project_target(config_path, "full")
    summary = check_vtables(config, target, VtableOptions())

    assert summary.invalid_parents == ()
    assert summary.parents_without_vtable_info == (("Child", "Base"),)


def test_trailing_class_vtable_comment_is_parsed(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.h").write_text(
        """
class Trailing {
public:
    virtual ~Trailing();
};  /* vtable 0x00402000 */
""",
        encoding="utf-8",
    )

    _, _, _, explicit_vtables, _ = parse_header_metadata((str(src),), None)

    assert explicit_vtables["Trailing"] == DATA_VA


def test_class_metadata_does_not_leak_from_previous_class(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.h").write_text(
        """
/* Constructor: 0x00401000, vtable 0x00402000. */
class First {
public:
    virtual ~First();
};

class Second {
public:
    virtual ~Second();
};  /* vtable 0x00402004 */
""",
        encoding="utf-8",
    )

    _, _, _, explicit_vtables, constructors = parse_header_metadata((str(src),), None)

    assert explicit_vtables["First"] == DATA_VA
    assert constructors["First"] == TEXT_VA
    assert explicit_vtables["Second"] == DATA_VA + 4
    assert "Second" not in constructors
