from __future__ import annotations

import pytest

from binary_comp.analyzers.function_compare import format_comparison
from binary_comp.analyzers.omf import (
    OmfCompareSpec,
    compare_omf_spec,
    compare_omf_to_original,
    generate_omf_similarity_report,
    load_omf_object,
)
from binary_comp.analyzers.report import SimilarityReportOptions, format_similarity_report
from binary_comp.config import BuildConfig, ProjectTarget


def omf_record(record_type: int, content: bytes) -> bytes:
    length = len(content) + 1
    return bytes([record_type]) + length.to_bytes(2, "little") + content + b"\x00"


def test_omf_parser_reads_ledata_and_fixupp(tmp_path):
    # LEDATA: segment 1, offset 0, code with a zeroed 16-bit data fixup.
    obj = tmp_path / "sample.obj"
    obj.write_bytes(
        omf_record(0xA0, b"\x01\x00\x00\x55\x8b\xec\xa2\x00\x00\xcb")
        + omf_record(0x9C, b"\xc4\x04\x14\x01\x03")
    )

    ledata, fixups = load_omf_object(obj)

    assert len(ledata) == 1
    assert ledata[0].segment_index == 1
    assert ledata[0].data == bytes.fromhex("55 8b ec a2 00 00 cb")
    assert [(fixup.offset, fixup.length) for fixup in fixups] == [(4, 2)]


def test_omf_compare_masks_fixup_operands(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("55 8b ec a2 ab 5e cb"))
    obj = tmp_path / "sample.obj"
    obj.write_bytes(
        omf_record(0xA0, b"\x01\x00\x00" + bytes.fromhex("55 8b ec a2 00 00 cb"))
        + omf_record(0x9C, b"\xc4\x04\x14\x01\x03")
    )

    comparison = compare_omf_to_original(
        original_path=original,
        original_offset=0,
        object_path=obj,
        size=7,
        name="setter",
    )

    assert comparison.matches
    assert comparison.mask == bytes.fromhex("ff ff ff ff 00 00 ff")


def test_omf_compare_reports_unmasked_differences(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("55 8b ec a2 ab 5e cb"))
    obj = tmp_path / "sample.obj"
    obj.write_bytes(
        omf_record(0xA0, b"\x01\x00\x00" + bytes.fromhex("55 8b ed a2 00 00 cb"))
        + omf_record(0x9C, b"\xc4\x04\x14\x01\x03")
    )

    comparison = compare_omf_to_original(
        original_path=original,
        original_offset=0,
        object_path=obj,
        size=7,
        name="setter",
    )

    assert not comparison.matches
    assert comparison.mismatches == (2,)


def test_omf_compare_spec_uses_function_compare_format(tmp_path):
    pytest.importorskip("capstone")

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("55 8b ec a2 ab 5e cb"))
    obj = tmp_path / "sample.obj"
    obj.write_bytes(
        omf_record(0xA0, b"\x01\x00\x00" + bytes.fromhex("55 8b ec a2 00 00 cb"))
        + omf_record(0x9C, b"\xc4\x04\x14\x01\x03")
    )

    comparison = compare_omf_spec(OmfCompareSpec(
        name="setter_case",
        function_name="setter",
        original_path=str(original),
        original_offset=0,
        object_path=str(obj),
        size=7,
    ))
    text = format_comparison(comparison)

    assert comparison.similarity == pytest.approx(100.0)
    assert "Comparison for function 'setter':" in text
    assert "Similarity: 100.00%" in text
    assert "retf" in text


def test_omf_report_reads_config_entries(tmp_path):
    pytest.importorskip("capstone")

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    source = src_dir / "SETTER.C"
    source.write_text("void setter(void) {}\n", encoding="utf-8")

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("55 8b ec a2 ab 5e cb"))
    obj = tmp_path / "sample.obj"
    obj.write_bytes(
        omf_record(0xA0, b"\x01\x00\x00" + bytes.fromhex("55 8b ec a2 00 00 cb"))
        + omf_record(0x9C, b"\xc4\x04\x14\x01\x03")
    )

    config_path = config_dir / "binary-comp.json"
    config = {
        "omf_compare": {
            "functions": [
                {
                    "target": "sample",
                    "name": "setter_case",
                    "function": "setter",
                    "source": "../src/SETTER.C",
                    "original": "../original.bin",
                    "original_offset": "0x0",
                    "object": "../sample.obj",
                    "size": "0x7",
                }
            ]
        }
    }
    target = ProjectTarget(
        name="sample",
        original_exe=str(original),
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(src_dir),),
        build=BuildConfig(),
        kind="dos16-omf",
    )

    report = generate_omf_similarity_report(
        config,
        config_path,
        target,
        SimilarityReportOptions(build=False),
    )
    text = format_similarity_report(report)

    assert report.compared == 1
    assert report.at_100 == 1
    assert "=== SETTER.C ===" in text
    assert "setter" in text
    assert "Average similarity: 100.00%" in text
