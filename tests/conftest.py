from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "project"
IMAGE_BASE = 0x00400000
TEXT_VA = IMAGE_BASE + 0x1000
DATA_VA = IMAGE_BASE + 0x2000


def write_tiny_pe(
    path: Path,
    function_bytes: bytes | None = None,
    data_overrides: dict[int, bytes] | None = None,
) -> None:
    function_bytes = function_bytes or b"\xB8\x07\x00\x00\x00\x83\xF8\x07\xC3"
    text = bytearray(b"\x90" * 0x200)
    text[:len(function_bytes)] = function_bytes
    if len(function_bytes) <= 0x10:
        text[0x10] = 0xC3

    data = bytearray(0x600)
    pe_offset = 0x80
    optional_size = 0xE0
    section_table = pe_offset + 24 + optional_size

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4, 0x14C)
    struct.pack_into("<H", data, pe_offset + 6, 2)
    struct.pack_into("<H", data, pe_offset + 20, optional_size)

    optional_header = pe_offset + 24
    struct.pack_into("<H", data, optional_header, 0x10B)
    struct.pack_into("<I", data, optional_header + 16, 0x1000)
    struct.pack_into("<I", data, optional_header + 28, IMAGE_BASE)

    text_header = section_table
    data[text_header:text_header + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, text_header + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, text_header + 36, 0x60000020)

    data_header = section_table + 40
    data[data_header:data_header + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, data_header + 8, 0x20, 0x2000, 0x20, 0x400)
    struct.pack_into("<I", data, data_header + 36, 0xC0000040)
    data[0x400:0x406] = b"hello\0"
    struct.pack_into("<I", data, 0x410, 7)
    for offset, value in (data_overrides or {}).items():
        data[0x400 + offset:0x400 + offset + len(value)] = value

    data[0x200:0x400] = text
    path.write_bytes(data)


@pytest.fixture
def fixture_root() -> Path:
    return FIXTURE_ROOT


@pytest.fixture
def sample_binaries(tmp_path: Path) -> tuple[Path, Path]:
    original = tmp_path / "original.exe"
    rebuilt = tmp_path / "rebuilt.exe"
    write_tiny_pe(original)
    write_tiny_pe(rebuilt)
    return original, rebuilt


GOLDEN_DIR = Path(__file__).parent / "golden"
UPDATE_GOLDEN = os.environ.get("BINARY_COMP_UPDATE_GOLDEN") == "1"


def run_cli(argv: list[str], capsys, replacements: dict[str, str]) -> str:
    """Run the CLI in-process and return its exit code and output as one text.

    Each key in ``replacements`` (usually a temporary directory) is replaced
    by its placeholder so the text does not depend on where the test ran.
    """
    from binary_comp.cli import main

    capsys.readouterr()
    code = main(argv)
    captured = capsys.readouterr()
    text = (
        f"$ binary-comp {' '.join(argv)}\n"
        f"exit: {code}\n"
        f"--- stdout ---\n{captured.out}"
        f"--- stderr ---\n{captured.err}"
    )
    for old, new in sorted(replacements.items(), key=lambda item: -len(item[0])):
        text = text.replace(old, new)
    return text


def assert_golden(name: str, actual: str) -> None:
    """Compare ``actual`` with ``tests/golden/<name>.txt``.

    Set BINARY_COMP_UPDATE_GOLDEN=1 to rewrite the snapshot instead; review
    the resulting diff before committing it.
    """
    path = GOLDEN_DIR / f"{name}.txt"
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    if not path.exists():
        pytest.fail(f"missing golden file {path}; run with BINARY_COMP_UPDATE_GOLDEN=1 to create it")
    assert actual == path.read_text(encoding="utf-8")
