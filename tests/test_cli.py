from __future__ import annotations

import pytest

from binary_comp.cli import build_parser, main
from test_omf32 import CODE, write_object


def test_number_options_accept_any_base():
    args = build_parser().parse_args(["data", "--address", "0x401000", "--min-address", "4096"])
    assert args.address == 0x401000
    assert args.min_address == 4096


def test_invalid_number_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["data", "--address", "zz"])
    assert exit_info.value.code == 2
    assert "invalid hex_int value: 'zz'" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["values", "calls", "global-access", "compare", "seh",
                                     "report", "order", "triage"])
def test_build_commands_share_target_and_build_options(command):
    argv = [command, "--config", "project.json", "--target", "demo", "--no-build"]
    if command == "compare":
        argv.append("SomeFunction")
    args = build_parser().parse_args(argv)
    assert (args.config, args.target, args.no_build) == ("project.json", "demo", True)


def test_missing_config_is_reported_not_raised(tmp_path, capsys):
    assert main(["values", "--config", str(tmp_path / "missing.json"), "--no-build"]) == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_word_delta_on_different_sizes_is_reported_not_raised(tmp_path, capsys):
    # With --symbol the whole rebuilt body is compared, so it can be longer
    # than --size; word-delta analysis then has nothing to pair up.
    original = tmp_path / "original.bin"
    original.write_bytes(b"\0" * 0x30 + CODE[:8] + b"\xcc" * 8)
    obj = tmp_path / "sample.obj"
    write_object(obj)
    code = main(["omf-compare", "--bits", "32", "--original", str(original), "--original-offset", "0x30",
                 "--object", str(obj), "--symbol", "CheckSlot_", "--size", "8", "--word-delta", "1"])
    assert code == 2
    assert capsys.readouterr().err == "error: word-delta analysis requires equal-sized inputs\n"
