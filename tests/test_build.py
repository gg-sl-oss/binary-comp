from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from binary_comp.build import BuildError, maybe_build
from binary_comp.config import BuildConfig, ProjectTarget


def target_with(build: BuildConfig) -> ProjectTarget:
    return ProjectTarget(
        name="full",
        original_exe="original.exe",
        rebuilt_exe="rebuilt.exe",
        map_path="rebuilt.map",
        source_dirs=(),
        build=build,
    )


def recorder(path: Path, exit_code: int = 0) -> str:
    """A command that writes its arguments to ``path`` as JSON and exits."""
    script = f"import json, sys; open({str(path)!r}, 'w').write(json.dumps(sys.argv[1:])); sys.exit({exit_code})"
    return shlex.join([sys.executable, "-c", script])


def test_no_build_runs_nothing(tmp_path):
    log = tmp_path / "log.json"
    maybe_build(target_with(BuildConfig(clean=recorder(log), build=recorder(log))), False)
    assert not log.exists()


def test_quoted_arguments_extra_args_and_jobs_reach_the_build(tmp_path):
    log = tmp_path / "log.json"
    command = recorder(log) + " 'two words' plain"
    maybe_build(target_with(BuildConfig(build=command, jobs=4)), True, extra_args=("EXTRA=1",))
    assert json.loads(log.read_text()) == ["two words", "plain", "EXTRA=1", "-j4"]


def test_failed_clean_stops_before_the_build(tmp_path):
    clean_log = tmp_path / "clean.json"
    build_log = tmp_path / "build.json"
    target = target_with(BuildConfig(clean=recorder(clean_log, exit_code=3), build=recorder(build_log)))
    with pytest.raises(BuildError, match="clean failed with exit code 3"):
        maybe_build(target, True)
    assert clean_log.exists()
    assert not build_log.exists()


def test_failed_build_names_the_command_and_exit_code(tmp_path):
    target = target_with(BuildConfig(build=recorder(tmp_path / "log.json", exit_code=5)))
    with pytest.raises(BuildError, match="build failed with exit code 5: .*python"):
        maybe_build(target, True)


def test_unbalanced_quotes_are_a_build_error():
    with pytest.raises(BuildError, match="cannot parse build command"):
        maybe_build(target_with(BuildConfig(build="make 'oops")), True)


@pytest.mark.parametrize("exit_code", [0, 5])
def test_build_forgets_cached_map_parses(tmp_path, exit_code):
    from binary_comp.core.mapfile import _read_msvc_map_cached, parse_msvc_map_symbols

    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(" 0001:00000000       _main   00401000 f   main.obj\n", encoding="latin1")
    parse_msvc_map_symbols(str(map_path))
    assert _read_msvc_map_cached.cache_info().currsize > 0

    target = target_with(BuildConfig(build=recorder(tmp_path / "log.json", exit_code=exit_code)))
    if exit_code:
        with pytest.raises(BuildError):
            maybe_build(target, True)
    else:
        maybe_build(target, True)

    # Even a failed build may have rewritten maps that were already read.
    assert _read_msvc_map_cached.cache_info().currsize == 0
