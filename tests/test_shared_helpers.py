from __future__ import annotations

import pytest

from binary_comp.config import ConfigError, config_int, optional_string, resolve_config_path
from binary_comp.core.binary import masked_count, masked_mismatches, relocation_mask
from binary_comp.core.disasm import signed32
from binary_comp.policy import load_policy


def test_relocation_mask_clips_spans_to_the_window():
    # Window covers addresses 0x10..0x17. One span straddles its start, one
    # sits inside, one straddles its end and one lies wholly outside.
    mask = relocation_mask(8, [(0x0E, 4), (0x13, 1), (0x16, 4), (0x30, 2)], window_start=0x10)
    assert mask == bytes([0x00, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00])
    assert masked_count(mask) == 5


def test_masked_mismatches_ignores_masked_bytes():
    original = bytes([1, 2, 3, 4])
    rebuilt = bytes([1, 9, 3, 8])
    assert masked_mismatches(original, rebuilt, bytes([0xFF, 0x00, 0xFF, 0xFF])) == (3,)


@pytest.mark.parametrize(("value", "expected"), [(0, 0), (0x7FFFFFFF, 0x7FFFFFFF), (0x80000000, -0x80000000),
                                                 (0xFFFFFFFF, -1), (0x1FFFFFFFF, -1), (-1, -1)])
def test_signed32(value, expected):
    assert signed32(value) == expected


def test_config_int_required_and_optional():
    assert config_int("0x10", "size") == 16
    assert config_int(None, "size", required=False) is None
    with pytest.raises(ConfigError, match="missing required configuration value: size"):
        config_int("", "size")
    with pytest.raises(ConfigError, match="size must be an integer"):
        config_int("ten", "size")


def test_optional_string_returns_the_first_key_with_a_value():
    assert optional_string({"tpu": "", "object": "unit.tpu"}, "tpu", "object") == "unit.tpu"
    assert optional_string({}, "tpu", "object") is None
    with pytest.raises(ConfigError, match="tpu must be a string"):
        optional_string({"tpu": 3}, "tpu")


def test_resolve_config_path_is_relative_to_the_config_file(tmp_path):
    config = tmp_path / "project" / "binary-comp.json"
    assert resolve_config_path(config, "build/unit.obj") == str(tmp_path / "project" / "build" / "unit.obj")
    assert resolve_config_path(config, str(tmp_path / "abs.obj")) == str(tmp_path / "abs.obj")
    assert resolve_config_path(config, None) is None


def test_malformed_policy_is_a_config_error(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_policy(str(policy))
