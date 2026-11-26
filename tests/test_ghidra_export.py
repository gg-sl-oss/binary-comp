from __future__ import annotations

from binary_comp.core.ghidra import (
    ExportHeader,
    export_address,
    export_path,
    find_export,
    iter_exports,
    read_export_body,
    read_export_header,
    render_export_header,
    resolve_export,
)


def _write(path, name, address, body):
    path.write_text("\n".join(render_export_header(name, address) + body) + "\n", encoding="utf-8")


def test_header_round_trips_through_render_and_read(tmp_path):
    path = tmp_path / "FUN_00401000.disassembled.txt"
    _write(path, "Door::canOpen", 0x401000, ["PUSH EBP", "RET"])

    assert read_export_header(str(path)) == ExportHeader("Door::canOpen", 0x401000)
    assert read_export_body(str(path)) == ["PUSH EBP", "RET"]
    assert render_export_header(None, 0x401000)[0] == "Function: FUN_00401000"


def test_find_export_accepts_the_spellings_seen_in_practice(tmp_path):
    for name in ("FUN_00401000", "FUN_401010", "FUN_00401abc"):
        (tmp_path / f"{name}.disassembled.txt").write_text("", encoding="utf-8")

    assert find_export(str(tmp_path), 0x401000) == str(tmp_path / "FUN_00401000.disassembled.txt")
    assert find_export(str(tmp_path), 0x401010) == str(tmp_path / "FUN_401010.disassembled.txt")
    assert find_export(str(tmp_path), 0x401ABC) == str(tmp_path / "FUN_00401abc.disassembled.txt")
    assert find_export(str(tmp_path), 0x402000) is None
    assert find_export(None, 0x401000) is None


def test_resolve_export_falls_back_to_the_default_path(tmp_path):
    assert resolve_export(str(tmp_path), 0x402000) == export_path(str(tmp_path), 0x402000)
    assert resolve_export(None, 0x402000) is None


def test_iter_exports_lists_function_exports_in_filename_order(tmp_path):
    for name in ("FUN_00401010", "FUN_00401000"):
        (tmp_path / f"{name}.disassembled.txt").write_text("", encoding="utf-8")
    (tmp_path / "FUN_00401000.decompiled.txt").write_text("", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")

    assert [address for address, _ in iter_exports(str(tmp_path))] == [0x401000, 0x401010]
    assert iter_exports(str(tmp_path / "missing")) == []


def test_export_address_prefers_the_filename_then_the_header(tmp_path):
    named = tmp_path / "FUN_00401000.disassembled.txt"
    _write(named, "f", 0x409999, [])
    other = tmp_path / "chunk.disassembled.txt"
    _write(other, "f", 0x401234, [])

    assert export_address(str(named)) == 0x401000
    assert export_address(str(other)) == 0x401234
    assert export_address(str(tmp_path / "missing.txt")) is None
