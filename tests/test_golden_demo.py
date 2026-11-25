"""Golden-output tests for the PE commands, run on the reconstruction demo.

The demo ships both executables, their maps and the compiler listings, so
every command runs with ``--no-build`` and needs no compiler. The output and
exit code of each command are compared with a snapshot in ``tests/golden/``.

When a change alters a report on purpose, regenerate the snapshots with

    BINARY_COMP_UPDATE_GOLDEN=1 python -m pytest tests/test_golden_demo.py

and review the diff of ``tests/golden/`` before committing it.
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
from pathlib import Path

import pytest

from conftest import PROJECT_ROOT, assert_golden, run_cli

pytest.importorskip("capstone")
pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_cpp")


DEMO_SOURCE = PROJECT_ROOT / "examples" / "reconstruction-mismatch-demo"
TARGET = ["--config", "binary-comp.json", "--target", "demo"]

# (snapshot name, command arguments after the target options)
CASES = [
    ("report", ["report", "--no-build", "--bytes"]),
    ("compare", ["compare", "--no-build", "LessonLog::severity", "code/FUN_004010E8.disassembled.txt"]),
    ("values", ["values", "--no-build", "--include-stack-locals"]),
    ("seh", ["seh", "--report", "--no-build"]),
    ("globals", ["globals", "--fail-on-issues"]),
    ("data", ["data"]),
    ("vtables", ["vtables"]),
    ("exe", ["exe", "--functions"]),
    ("order", ["order"]),
    ("triage", ["triage"]),
    ("calls", ["calls", "--no-build"]),
    ("global-access", ["global-access", "--no-build"]),
]


@pytest.fixture(scope="module")
def demo_dir(tmp_path_factory) -> Path:
    """A private copy of the demo with its Ghidra-style exports generated."""
    from binary_comp.cli import main

    demo = tmp_path_factory.mktemp("demo")
    for name in ("src", "artifacts", "binary-comp.json"):
        source = DEMO_SOURCE / name
        if source.is_dir():
            shutil.copytree(source, demo / name)
        else:
            shutil.copy2(source, demo / name)

    previous = Path.cwd()
    os.chdir(demo)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assert main(["export-asm", *TARGET, "--clean", "--no-source"]) == 0
    finally:
        os.chdir(previous)
    return demo


@pytest.mark.parametrize(("name", "command"), CASES, ids=[name for name, _ in CASES])
def test_demo_command_output(name, command, demo_dir, monkeypatch, capsys):
    monkeypatch.chdir(demo_dir)
    argv = [command[0], *TARGET, *command[1:]]
    actual = run_cli(argv, capsys, {str(demo_dir): "<DEMO>"})
    assert_golden(f"demo/{name}", actual)
