"""Golden-output tests for the DOS commands on the synthetic test fixtures.

These pin the full text of ``omf-compare``, ``tpu-compare`` and
``byte-compare``, which the unit tests only check line by line. Regenerate
with BINARY_COMP_UPDATE_GOLDEN=1, as described in ``test_golden_demo.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import assert_golden, run_cli
from test_omf32 import CODE, LITERAL, config_for, write_object
from test_omf32 import sample  # noqa: F401  (pytest fixture)
from test_tpu import FAR_CALL, LOC_BLOCK, LOC_FIXUP, POINTER_FIXUP, make_tpu


def test_omf_compare_match_and_literal_mismatch(sample, tmp_path, capsys):  # noqa: F811
    config = config_for(sample, tmp_path)
    args = ["--config", str(config), "--target", "sample", "--no-build"]
    paths = {str(tmp_path): "<TMP>"}

    matched = run_cli(["omf-compare", *args], capsys, paths)
    write_object(Path(sample.object_path), literal=b"X" + LITERAL[1:])
    mismatched = run_cli(["omf-compare", *args, "--function", "CheckSlot"], capsys, paths)

    assert_golden("synthetic/omf-compare", matched + "\n" + mismatched)


def test_omf_compare_raw_32_bit(sample, tmp_path, capsys):  # noqa: F811
    argv = ["omf-compare", "--bits", "32", "--original", sample.original_path,
            "--original-offset", "0x30", "--object", sample.object_path,
            "--symbol", "CheckSlot_", "--size", str(len(CODE))]
    assert_golden("synthetic/omf-compare-raw", run_cli(argv, capsys, {str(tmp_path): "<TMP>"}))


def test_tpu_compare_match_mismatch_and_locate(tmp_path, capsys):
    paths = {str(tmp_path): "<TMP>"}
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [POINTER_FIXUP])]))
    matching = tmp_path / "matching.bin"
    matching.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    different = tmp_path / "different.bin"
    different.write_bytes(bytes.fromhex("9a 78 56 34 12 c3"))

    located_tpu = tmp_path / "located.tpu"
    located_tpu.write_bytes(make_tpu([(LOC_BLOCK, [LOC_FIXUP])]))
    linked = bytearray(LOC_BLOCK)
    linked[4:6] = bytes.fromhex("34 12")
    image = tmp_path / "image.bin"
    image.write_bytes(bytes(0x30) + bytes(linked) + bytes(0x20))

    runs = [
        ["tpu-compare", "--original", str(matching), "--original-offset", "0",
         "--tpu", str(tpu), "--name", "caller"],
        ["tpu-compare", "--original", str(different), "--original-offset", "0",
         "--tpu", str(tpu), "--name", "caller"],
        ["tpu-compare", "--original", str(image), "--tpu", str(located_tpu),
         "--block", "0", "--locate", "--name", "f"],
    ]
    assert_golden("synthetic/tpu-compare", "\n".join(run_cli(argv, capsys, paths) for argv in runs))


@pytest.mark.parametrize("rebuilt_tail", [b"\x90\xc3", b"\x90\xc2"], ids=["same", "different"])
def test_byte_compare(rebuilt_tail, tmp_path, capsys):
    original = tmp_path / "original.bin"
    original.write_bytes(b"\x55\x8b\xec" * 8 + b"\x90\xc3")
    rebuilt = tmp_path / "rebuilt.bin"
    rebuilt.write_bytes(b"\x55\x8b\xec" * 8 + rebuilt_tail)
    argv = ["byte-compare", str(original), str(rebuilt), "--fail-on-difference"]
    name = "same" if rebuilt_tail == b"\x90\xc3" else "different"
    assert_golden(f"synthetic/byte-compare-{name}", run_cli(argv, capsys, {str(tmp_path): "<TMP>"}))
