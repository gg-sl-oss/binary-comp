from __future__ import annotations

import pytest

from binary_comp.analyzers.calls import normalize_compiled
from binary_comp.analyzers.values import ValuesOptions, check_values, format_summary, load_policy
from binary_comp.config import BuildConfig, ProjectTarget, load_project_target
from binary_comp.source.cpp import parse_source_function_groups
from binary_comp.source.functions import load_source_groups, map_source_groups


pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_cpp")


def test_source_function_groups_from_cpp_fixture(fixture_root):
    groups = parse_source_function_groups(str(fixture_root / "src" / "sample.cpp"))

    assert len(groups) == 1
    assert groups[0].name == "sample_function"
    assert groups[0].addresses == ("00401000",)


def test_source_function_groups_can_add_configured_signatures(tmp_path):
    source = tmp_path / "overload.cpp"
    source.write_text(
        """
struct Item {};
struct Box {
  Item* Take(Item* item);
};
/* Function start: 0x00401000 */
Item* Box::Take(Item* item) { return item; }
""",
        encoding="utf-8",
    )

    groups = parse_source_function_groups(str(source), signature_names=frozenset({"Box::Take"}))

    assert groups[0].name == "Box::Take(Item*)"


def test_msvc_member_name_can_use_configured_signature():
    symbol = "?Take@Box@@QAEPAVItem@@PAV2@@Z"

    assert normalize_compiled(symbol, frozenset({"Box::Take"})) == "Box::Take(Item*)"


def test_source_groups_map_to_rebuilt_symbols(fixture_root):
    groups_by_source = load_source_groups((str(fixture_root / "src"),))
    mapped, missing, entries_by_obj = map_source_groups(groups_by_source, str(fixture_root / "rebuilt.map"))

    assert not missing
    assert len(mapped) == 1
    assert mapped[0].name == "sample_function"
    assert mapped[0].original_addrs == (0x401000,)
    assert mapped[0].rebuilt_addr == 0x401000
    assert "sample.obj" in entries_by_obj


def test_load_minimal_project_config(fixture_root):
    _, target = load_project_target(str(fixture_root / "binary-comp.json"), "full")

    assert target.name == "full"
    assert target.original_exe == str(fixture_root / "original.exe")
    assert target.rebuilt_exe == str(fixture_root / "rebuilt.exe")
    assert target.map_path == str(fixture_root / "rebuilt.map")
    assert target.source_dirs == (str(fixture_root / "src"),)
    assert target.globals_source == str(fixture_root / "src" / "globals.cpp")
    assert target.globals_header == str(fixture_root / "src" / "globals.h")
    assert target.code_globals_header == str(fixture_root / "code" / "globals.h")
    assert target.define_headers == (str(fixture_root / "src" / "constants.h"),)
    assert target.auto_complete == str(fixture_root / "src" / "auto_complete.txt")
    assert target.asm_dir == str(fixture_root / "out")


def test_standalone_values_policy_is_relative_to_config(tmp_path):
    config_path = tmp_path / "config" / "binary-comp.json"
    config_path.parent.mkdir()
    config_path.write_text(
        """
{
  "targets": {
    "full": {
      "original_exe": "../original.exe",
      "rebuilt_exe": "../rebuilt.exe",
      "map": "../rebuilt.map",
      "source_dirs": ["../src"],
      "values": {"policy": "values-policy.json"}
    }
  }
}
""",
        encoding="utf-8",
    )

    _, target = load_project_target(str(config_path), "full")

    assert target.values_policy == str(config_path.parent / "values-policy.json")


def test_value_checker_on_generated_fixture_project(fixture_root, sample_binaries):
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(fixture_root / "code"),
        build=BuildConfig(),
    )

    summary = check_values(
        target,
        load_policy(),
        ValuesOptions(build=False, min_similarity=90.0),
    )

    assert summary.functions_checked == 1
    assert summary.with_value_mismatches == 0
    assert summary.total_mismatches == 0
    expected = (fixture_root / "expected" / "values-summary.txt").read_text(encoding="utf-8").rstrip("\n")
    assert format_summary(summary, min_similarity=90.0) == expected
