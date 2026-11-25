"""32-bit OMF CLI regression cases; synthetic fixtures, no game binaries."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from binary_comp.analyzers.omf import (
    EmbeddedTable, OmfCompareError, OmfCompareSpec, OmfLiteralSpec,
    compare_omf_spec, compare_omf_spec_bytes, embedded_tables, format_omf_comparison,
)
from binary_comp.cli import main


CODE = bytes.fromhex("b8 07 00 00 00 e8 00 00 00 00 c3")
LITERAL = b"Invalid slot.\0"


def record(kind, content):
    header = bytes([kind]) + (len(content) + 1).to_bytes(2, "little")
    return header + content + bytes([(-sum(header + content)) & 0xff])


def ledata(segment, offset, data):
    return record(0xA1, bytes([segment]) + offset.to_bytes(4, "little") + data)


def public(name, offset):
    return bytes([len(name)]) + name.encode() + offset.to_bytes(4, "little") + b"\0"


def write_object(path, code=CODE, literal=LITERAL, extra_fixup=False):
    # The function begins at segment offset 0x10 and spans two LEDATA32
    # records. A second public function bounds it before the segment ends.
    path.write_bytes(
        ledata(1, 0x10, code[:5])
        + (record(0x9D, bytes.fromhex("a4 01 16 02 01")) if extra_fixup else b"")
        + ledata(1, 0x15, code[5:])
        + record(0x9D, bytes.fromhex("a4 01 16 02 01"))
        + ledata(1, 0x10 + len(code), b"\x90\xc3")
        + record(0x91, b"\0\x01" + public("CheckSlot_", 0x10)
                 + public("Next_", 0x10 + len(code)))
        + ledata(2, 0, literal)
        # A fixup in another segment must not mask bytes in the function.
        + ledata(3, 0, b"\0" * 8)
        + record(0x9D, bytes.fromhex("a4 00 16 02 01"))
    )


@pytest.fixture
def sample(tmp_path):
    original = tmp_path / "original.bin"
    linked = bytearray(CODE)
    linked[6:10] = bytes.fromhex("11 22 33 44")
    original.write_bytes(b"\0" * 0x30 + linked + LITERAL)
    obj = tmp_path / "sample.obj"
    write_object(obj)
    return OmfCompareSpec(
        name="CheckSlot", function_name="CheckSlot", original_path=str(original),
        original_offset=0x30, original_address=0x10200, object_path=str(obj),
        size=len(CODE), bits=32, symbol="CheckSlot_", expected_fixups=((6, 4),),
        literals=(OmfLiteralSpec(0x30 + len(CODE), 2, 0, len(LITERAL)),),
    )


def test_fragmented_symbol_compares_full_body_and_decodes_32_bits(sample):
    pytest.importorskip("capstone")
    comparison = compare_omf_spec_bytes(sample)
    assert comparison.matches
    assert comparison.object_offset == 0x10
    assert comparison.rebuilt == CODE
    assert comparison.masked_count == 4
    assert comparison.literal_matches == (True,)
    assembly = compare_omf_spec(sample)
    assert assembly.original_addr == 0x10200
    assert assembly.rebuilt_addr == 0x10
    assert assembly.rebuilt.instructions[0].op_str == "eax, 7"
    assert assembly.similarity == 100


@pytest.mark.parametrize("code", [CODE[:-1], CODE + b"\x90"])
def test_size_differences_cannot_be_hidden_by_truncation(sample, code):
    write_object(Path(sample.object_path), code)
    comparison = compare_omf_spec_bytes(sample)
    assert not comparison.matches
    assert len(comparison.rebuilt) == len(code)
    assert "length:   MISMATCH" in format_omf_comparison(comparison)


def test_changed_constant_fails_even_when_mnemonics_match(sample):
    pytest.importorskip("capstone")
    code = bytearray(CODE)
    code[1] = 8
    write_object(Path(sample.object_path), code)
    assert compare_omf_spec(sample).similarity == 100
    assert not compare_omf_spec_bytes(sample).matches


def test_unexpected_fixup_cannot_hide_changed_constant(sample):
    code = bytearray(CODE)
    code[1] = 8
    write_object(Path(sample.object_path), code, extra_fixup=True)
    comparison = compare_omf_spec_bytes(sample)
    assert not comparison.mismatches  # The bogus fixup masks the change.
    assert comparison.fixup_layout_matches is False
    assert not comparison.matches


def test_changed_literal_fails_with_identical_code(sample):
    write_object(Path(sample.object_path), literal=b"X" + LITERAL[1:])
    comparison = compare_omf_spec_bytes(sample)
    assert not comparison.mismatches
    assert comparison.literal_matches == (False,)
    assert not comparison.matches


def test_missing_symbol_is_an_error(sample):
    with pytest.raises(OmfCompareError, match="public symbol not found"):
        compare_omf_spec_bytes(replace(sample, symbol="Missing_"))


def config_for(sample, tmp_path):
    entry = {
        "target": "sample", "name": "CheckSlot", "symbol": "CheckSlot_",
        "original": sample.original_path, "original_offset": "0x30",
        "original_address": "0x10200", "object": sample.object_path,
        "size": len(CODE), "expected_fixups": [{"offset": 6, "size": 4}],
        "literals": [{"original_offset": 0x30 + len(CODE), "segment_index": 2,
                      "object_offset": 0, "size": len(LITERAL)}],
    }
    config = {
        "targets": {"sample": {"kind": "dos32-omf", "original_exe": sample.original_path,
                                "source_dirs": [str(tmp_path)]}},
        "omf_compare": {"functions": [entry]},
    }
    path = tmp_path / "binary-comp.json"
    path.write_text(json.dumps(config))
    return path


def test_config_cli_compare_report_and_strict_gate(sample, tmp_path, capsys):
    pytest.importorskip("capstone")
    config = config_for(sample, tmp_path)
    args = ["--config", str(config), "--target", "sample", "--no-build"]
    assert main(["compare", *args, "CheckSlot"]) == 0
    assert "eax, 7" in capsys.readouterr().out
    assert main(["report", *args]) == 0
    assert "Total compared: 1" in capsys.readouterr().out
    assert main(["omf-compare", *args]) == 0
    assert "result:   MATCH" in capsys.readouterr().out
    write_object(Path(sample.object_path), literal=b"X" + LITERAL[1:])
    assert main(["omf-compare", *args, "--function", "CheckSlot"]) == 1
    assert "literal 1: MISMATCH" in capsys.readouterr().out
    assert main(["omf-compare", *args, "--function", "Missing"]) == 2
    assert "no matching OMF" in capsys.readouterr().err
    data = json.loads(config.read_text())
    data["omf_compare"]["functions"] = []
    config.write_text(json.dumps(data))
    assert main(["omf-compare", *args]) == 2
    assert "no matching OMF" in capsys.readouterr().err


def test_raw_cli_32_bit_symbol_mode(sample, capsys):
    assert main(["omf-compare", "--bits", "32", "--original", sample.original_path,
                 "--original-offset", "0x30", "--object", sample.object_path,
                 "--symbol", "CheckSlot_", "--size", str(len(CODE))]) == 0
    assert "result:   MATCH" in capsys.readouterr().out


def test_raw_cli_preserves_16_bit_default(tmp_path, capsys):
    original = tmp_path / "original.bin"
    obj = tmp_path / "sample.obj"
    original.write_bytes(b"\xb8\x07\x00\xcb")
    obj.write_bytes(record(0xA0, b"\x01\0\0" + original.read_bytes()))
    assert main(["omf-compare", "--original", str(original), "--original-offset", "0",
                 "--object", str(obj), "--size", "4"]) == 0
    assert "result:   MATCH" in capsys.readouterr().out


# A switch: the indexing jump's displacement is followed directly by a
# three-entry table, then the three cases.
SWITCH_TABLE = 0x0C
SWITCH_CASES = (0x18, 0x1E, 0x24)
SWITCH_FIXUPS = (0x08, 0x0C, 0x10, 0x14)


def switch_code(base):
    code = bytearray.fromhex("83 f8 02 77 1f ff 24 85") + (base + SWITCH_TABLE).to_bytes(4, "little")
    for case in SWITCH_CASES:
        code += (base + case).to_bytes(4, "little")
    for value in (1, 2, 3):
        code += bytes([0xB8, value, 0, 0, 0, 0xC3])
    return bytes(code)


def segment_fixup(offset):
    # Segment-relative 32-bit offset at ``offset`` in the preceding LEDATA32.
    return bytes([0xE4 | (offset >> 8), offset & 0xFF]) + bytes.fromhex("16 02 01")


@pytest.fixture
def switch_sample(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"\0" * 0x30 + switch_code(0x10200))
    obj = tmp_path / "switch.obj"
    code = switch_code(0x10)
    obj.write_bytes(
        ledata(1, 0x10, code)
        + record(0x9D, b"".join(segment_fixup(offset) for offset in SWITCH_FIXUPS))
        + ledata(1, 0x10 + len(code), b"\x90\xc3")
        + record(0x91, b"\0\x01" + public("Select_", 0x10) + public("Next_", 0x10 + len(code)))
    )
    return OmfCompareSpec(
        name="Select", function_name="Select", original_path=str(original),
        original_offset=0x30, original_address=0x10200, object_path=str(obj),
        size=len(code), bits=32, symbol="Select_",
        expected_fixups=tuple((offset, 4) for offset in SWITCH_FIXUPS),
    )


def test_embedded_jump_table_is_not_decoded_as_code(switch_sample):
    pytest.importorskip("capstone")
    assert compare_omf_spec_bytes(switch_sample).matches
    comparison = compare_omf_spec(switch_sample)
    for side, base in ((comparison.original, 0x10200), (comparison.rebuilt, 0x10)):
        by_address = {instruction.address - base: instruction for instruction in side.instructions}
        assert [by_address[offset].mnemonic for offset in (0x0C, 0x10, 0x14)] == ["dd"] * 3
        assert by_address[0x05].mnemonic == "jmp"
        assert all(by_address[case].mnemonic == "mov" for case in SWITCH_CASES)
    assert comparison.original.instructions[3].op_str == "0x10218"
    assert comparison.similarity == 100


def test_adjacent_operands_outside_the_function_are_not_a_table():
    # mov dword ptr [0x5000], 0x6000 relocates two adjacent words.
    code = bytes.fromhex("c7 05 00 50 00 00 00 60 00 00 c3")
    assert embedded_tables(code, ((2, 4), (6, 4)), 0x10200, 0x10200 + len(code)) == ()


def test_relocated_values_override_stored_table_words():
    # Executable formats such as LE store object-relative words that the
    # loader rebases; the caller supplies the final values.
    code = switch_code(0x200)
    linked = {offset: 0x10000 + int.from_bytes(code[offset:offset + 4], "little")
              for offset in SWITCH_FIXUPS}
    assert embedded_tables(code, ((offset, 4) for offset in SWITCH_FIXUPS),
                           0x10200, 0x10200 + len(code)) == ()
    assert embedded_tables(code, ((offset, 4) for offset in SWITCH_FIXUPS),
                           0x10200, 0x10200 + len(code), linked) == (EmbeddedTable(0x0C, 4, 3),)
