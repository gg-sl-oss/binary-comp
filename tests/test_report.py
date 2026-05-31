from __future__ import annotations

import pytest

from binary_comp.analyzers.report import (
    SimilarityReportOptions,
    format_similarity_report,
    generate_similarity_report,
)
from binary_comp.config import BuildConfig, ProjectTarget


def test_generate_similarity_report_on_fixture_project(fixture_root, sample_binaries):
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

    report = generate_similarity_report(target, SimilarityReportOptions(build=False))
    text = format_similarity_report(report)

    assert report.compared == 1
    assert report.at_100 == 1
    assert report.errors == 0
    assert report.missing_asm == 0
    assert "sample_function" in text
    assert "Average similarity: 100.00%" in text


def test_similarity_report_filter_limits_rows(fixture_root, sample_binaries):
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

    report = generate_similarity_report(
        target,
        SimilarityReportOptions(build=False, file_filter="does-not-match"),
    )

    assert report.rows == ()
    assert report.compared == 0


def test_similarity_report_counts_missing_asm(fixture_root, sample_binaries, tmp_path):
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(tmp_path / "missing-code"),
        build=BuildConfig(),
    )

    report = generate_similarity_report(target, SimilarityReportOptions(build=False))

    assert report.compared == 0
    assert report.missing_asm == 1
    assert report.rows[0].status == "MISSING ASM"


def test_similarity_report_merges_seh_split_chunks(sample_binaries, tmp_path):
    """An SEH function annotated with several "Function start" addresses (prologue
    chunk + body chunk) must be measured as ONE combined function, not as a
    spurious low-similarity prologue row plus a separate body row."""
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries
    # sample_binaries default bytes are MOV EAX,7 / CMP EAX,7 (at 0x401000) then
    # RET (at 0x401008): a natural prologue chunk + body chunk split.

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "seh.cpp").write_text(
        "/* Function start: 0x00401000 */\n"
        "/* Function start: 0x00401008 */\n"
        "int seh_function() {\n"
        "    return 7;\n"
        "}\n"
    )

    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0001:00000000       _seh_function 00401000 f seh.obj\n"
        " 0001:00000010       _seh_boundary 00401010 f seh.obj\n"
    )

    code_dir = tmp_path / "code"
    code_dir.mkdir()
    (code_dir / "FUN_00401000.disassembled.txt").write_text(
        "Function: FUN_00401000\nAddress: 0x00401000\n\nMOV EAX,0x7\nCMP EAX,0x7\n"
    )
    (code_dir / "FUN_00401008.disassembled.txt").write_text(
        "Function: FUN_00401008\nAddress: 0x00401008\n\nRET\n"
    )

    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(map_path),
        source_dirs=(str(src_dir),),
        code_dir=str(code_dir),
        build=BuildConfig(),
    )

    report = generate_similarity_report(target, SimilarityReportOptions(build=False))

    seh_rows = [row for row in report.rows if row.function_name == "seh_function"]
    assert len(seh_rows) == 1
    assert seh_rows[0].address == 0x00401000
    assert report.compared == 1
    assert report.errors == 0
    # Combined prologue+body matches the (identical) rebuilt function fully.
    assert seh_rows[0].similarity == pytest.approx(100.0)
