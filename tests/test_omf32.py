"""32-bit OMF CLI regression cases; synthetic fixtures, no game binaries."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from binary_comp.analyzers.omf import (
    OmfCompareError, OmfCompareSpec, OmfLiteralSpec,
    compare_omf_spec, compare_omf_spec_bytes, format_omf_comparison,
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
