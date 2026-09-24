from __future__ import annotations

import csv
import json

import pytest

from binary_comp.analyzers.report import (
    SimilarityReport,
    SimilarityReportOptions,
    SimilarityReportRow,
    format_similarity_report,
    generate_similarity_report,
    load_similarity_reasons,
)
from binary_comp.cli import main
from binary_comp.config import BuildConfig, ProjectTarget

from conftest import write_tiny_pe


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


@pytest.mark.parametrize("reason_field", ["reason", "evidence_and_likely_cause"])
def test_report_reasons_use_current_rows_and_unrounded_scores(tmp_path, reason_field):
    path = tmp_path / "reasons.csv"
    with path.open("w", newline="", encoding="utf-8-sig") as source:
        writer = csv.writer(source)
        writer.writerow(["original_address", reason_field, "function", "similarity_percent"])
        writer.writerow(["0x00401000", "Register order,\nwith the same terms.", "old_name", "15.0"])
        writer.writerow(["0x00401020", "Close to threshold.", "rounded", "95.0"])
        writer.writerow(["0x00401030", "No longer below 90%.", "recovered", "25.0"])

    report = SimilarityReport(
        rows=(
            SimilarityReportRow("sample.cpp", "Renamed::function", 0x401000, 82.5, "82.50%"),
            SimilarityReportRow("sample.cpp", "new_low", 0x401010, 65.0, "65.00%"),
            SimilarityReportRow("sample.cpp", "rounded", 0x401020, 89.999, "90.00%"),
            SimilarityReportRow("sample.cpp", "recovered", 0x401030, 95.0, "95.00%"),
            SimilarityReportRow("sample.cpp", "boundary", 0x401040, 90.0, "90.00%"),
            SimilarityReportRow("sample.cpp", "unavailable", 0x401050, None, "NOT FOUND"),
        ),
        compared=5, similarity_sum=422.499, at_100=0, above_90=2, below_90=3,
        errors=1, missing_asm=0, asm_fallbacks=0,
    )
    plain = format_similarity_report(report)
    text = format_similarity_report(report, reasons=load_similarity_reasons(str(path)))
    assert text.startswith(plain + "\n\n--- Recorded reasons for similarity below 90% ---\n")
    footer = text[len(plain):]
    assert "82.50% Renamed::function: Register order, with the same terms." in footer
    assert "65.00% new_low: Review needed: no reason recorded." in footer
    assert "90.00% rounded: Close to threshold." in footer
    assert footer.index("new_low") < footer.index("Renamed::function") < footer.index("rounded")
    assert all(name not in footer for name in ("old_name", "recovered", "boundary", "unavailable"))


@pytest.mark.parametrize("contents, error", [
    ("function,reason\nexample,note\n", "expected CSV columns"),
    ("original_address,reason\ninvalid,note\n", "invalid original_address"),
    ("original_address,reason\n", None),
    ("original_address,reason\n0x401000,first\n0x00401000,second\n", "duplicate address"),
])
def test_report_reasons_validate_addresses(tmp_path, contents, error):
    path = tmp_path / "reasons.csv"
    path.write_text(contents)
    if error is None:
        assert load_similarity_reasons(str(path)) == {}
    else:
        with pytest.raises(ValueError, match=error):
            load_similarity_reasons(str(path))


@pytest.mark.parametrize("file_filter", ["sample_function", "does-not-match"])
def test_report_cli_appends_reasons_after_filtering(
    fixture_root, sample_binaries, tmp_path, capsys, file_filter,
):
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries
    write_tiny_pe(rebuilt, function_bytes=b"\x31\xc0\xc3")
    config = tmp_path / "binary-comp.json"
    config.write_text(json.dumps({"targets": {"full": {
        "original_exe": str(original),
        "rebuilt_exe": str(rebuilt),
        "map": str(fixture_root / "rebuilt.map"),
        "source_dirs": [str(fixture_root / "src")],
        "code_export_dir": str(fixture_root / "code"),
    }}}))
    reasons = tmp_path / "reasons.csv"
    reasons.write_text("original_address,reason\n0x00401000,Changed return instructions.\n")

    result = main([
        "report", "--config", str(config), "--no-build", "--filter", file_filter,
        "--reasons", str(reasons),
    ])
    output = capsys.readouterr()
    assert result == 0, output.err
    footer = output.out.split("--- Recorded reasons for similarity below 90% ---", 1)[1]
    if file_filter == "sample_function":
        assert "sample_function: Changed return instructions." in footer
    else:
        assert "None in the current report." in footer
        assert "sample_function" not in footer


def test_report_cli_invalid_reasons_returns_error(tmp_path, capsys):
    reasons = tmp_path / "reasons.csv"
    reasons.write_text("wrong,columns\n")
    assert main(["report", "--reasons", str(reasons), "--no-build"]) == 2
    output = capsys.readouterr()
    assert "expected CSV columns" in output.err
    assert "Recorded reasons" not in output.out
