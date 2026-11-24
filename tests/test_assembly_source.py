from __future__ import annotations

import pytest

from binary_comp.source.assembly import parse_assembly_function_comments
from binary_comp.source.cpp import parse_source_function_groups, parse_source_function_markers
from binary_comp.source.functions import load_source_groups


RASTER = """\
        .386
        .model  flat, c
        public  CopyName, Install

        .code

; Function start: 0x00439C40
; Copies the driver name; the ';' in 'a;b' is not a comment.
CopyName proc
        mov eax, offset szName
L439C54:
        ret
CopyName endp

; Function start: 0x00439C69
        align 4
Install proc near
        ret
Install endp

; Function start: 0x00439C88
        db 0CCh
Orphan proc
        ret
Orphan endp

; Function start: 0x00439CA0
Entry:
        ret

; Function start: 0x00439CB0
Table   label   near
        ret

        .data
szName  db 'MCGA.DLL', 0
        end
"""


def write(tmp_path, name: str = "raster.asm"):
    path = tmp_path / name
    path.write_text(RASTER)
    return path


def test_assembly_markers_name_the_procedure_that_follows(tmp_path):
    path = write(tmp_path)

    markers = parse_source_function_markers(str(path))

    assert [(marker.address, marker.name, marker.line) for marker in markers] == [
        ("00439C40", "CopyName", 7),
        ("00439C69", "Install", 15),
        ("00439CA0", "Entry", 27),
        ("00439CB0", "Table", 31),
    ]


def test_assembly_groups_are_inventoried_with_the_c_sources(tmp_path):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    write(tmp_path)
    (tmp_path / "screens.c").write_text("/* Function start: 0x00439C10 */\nvoid FillBytes(void)\n{\n}\n")
    (tmp_path / "notes.txt").write_text("; Function start: 0x00439000\nIgnored proc\n")

    groups = load_source_groups((str(tmp_path),))

    assert {name.rsplit("/", 1)[-1]: [group.name for group in found] for name, found in groups.items()} == {
        "raster.asm": ["CopyName", "Install", "Entry", "Table"],
        "screens.c": ["FillBytes"],
    }


def test_assembly_groups_keep_one_entry_per_procedure(tmp_path):
    path = write(tmp_path)

    groups = parse_source_function_groups(str(path))

    assert [(group.name, group.addresses) for group in groups][:2] == [
        ("CopyName", ("00439C40",)),
        ("Install", ("00439C69",)),
    ]


def test_assembly_comment_markers_include_unmatched_annotations(tmp_path):
    path = write(tmp_path)

    assert [marker.address for marker in parse_assembly_function_comments(str(path))] == [
        "00439C40", "00439C69", "00439C88", "00439CA0", "00439CB0",
    ]
