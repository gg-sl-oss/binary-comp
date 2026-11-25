"""The value-check policy: tunable limits and name lists for the analyzers.

The bundled default lives in ``binary_comp/data/default_values_policy.json``;
a target can point ``values_policy`` at its own copy.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from importlib import resources

from binary_comp.config import ConfigError, parse_int


@dataclass(frozen=True)
class VerifierPolicy:
    max_disassembly_bytes: int
    max_member_displacement: int
    nearby_window: int
    small_immediate_min: int
    small_immediate_max: int
    value_mnemonics: frozenset[str]
    padding_mnemonics: frozenset[str]
    stack_registers: frozenset[str]
    diagnostic_functions: frozenset[str]
    allowed_one_char_strings: frozenset[str]
    rejected_string_substrings: tuple[str, ...]


def default_policy_path() -> str:
    return str(resources.files("binary_comp.data").joinpath("default_values_policy.json"))


def required_config(config: dict, key: str, label: str):
    if not isinstance(config, dict):
        raise ConfigError(f"{label} must be a JSON object")
    if key not in config:
        raise ConfigError(f"missing required value-check config field: {label}.{key}")
    return config[key]


def string_list_config(config: dict, key: str, label: str) -> list[str]:
    value = required_config(config, key, label)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{label}.{key} must be a list of strings")
    return value


def load_policy(path: str | None = None) -> VerifierPolicy:
    if not path:
        path = default_policy_path()
    if not os.path.exists(path):
        raise ConfigError(f"value-check policy file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"value-check policy is not valid JSON: {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ConfigError(f"value-check policy root must be an object: {path}")

    literal_config = required_config(config, "literal_strings", "policy")
    return VerifierPolicy(
        max_disassembly_bytes=parse_int(
            required_config(config, "max_disassembly_bytes", "policy"),
            "policy.max_disassembly_bytes",
        ),
        max_member_displacement=parse_int(
            required_config(config, "max_member_displacement", "policy"),
            "policy.max_member_displacement",
        ),
        nearby_window=parse_int(required_config(config, "nearby_window", "policy"), "policy.nearby_window"),
        small_immediate_min=parse_int(
            required_config(config, "small_immediate_min", "policy"),
            "policy.small_immediate_min",
        ),
        small_immediate_max=parse_int(
            required_config(config, "small_immediate_max", "policy"),
            "policy.small_immediate_max",
        ),
        value_mnemonics=frozenset(m.lower() for m in string_list_config(config, "value_mnemonics", "policy")),
        padding_mnemonics=frozenset(m.lower() for m in string_list_config(config, "padding_mnemonics", "policy")),
        stack_registers=frozenset(r.lower() for r in string_list_config(config, "stack_registers", "policy")),
        diagnostic_functions=frozenset(string_list_config(config, "diagnostic_functions", "policy")),
        allowed_one_char_strings=frozenset(
            string_list_config(literal_config, "allowed_one_char", "policy.literal_strings")
        ),
        rejected_string_substrings=tuple(
            string_list_config(literal_config, "reject_substrings", "policy.literal_strings")
        ),
    )
