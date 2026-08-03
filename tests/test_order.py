from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.order import OrderOptions, format_order_report, generate_order_report
from binary_comp.cli import build_parser, run_order
from binary_comp.config import BuildConfig, ProjectTarget

from conftest import write_tiny_pe


def require_cpp_parser() -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")


def fixture_target(fixture_root, original, rebuilt) -> ProjectTarget:
    return ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(fixture_root / "code"),
        build=BuildConfig(),
    )


def test_order_command_parser_exposes_analysis_controls():
    args = build_parser().parse_args([
        "order",
        "--no-build",
        "--no-similarity",
        "--alignment",
        "0x20",
        "--limit",
        "0",
        "--show-runs",
        "--show-all",
    ])

    assert args.handler is run_order
    assert args.no_build is True
    assert args.no_similarity is True
    assert args.alignment == 32
    assert args.limit == 0
    assert args.show_runs is True
    assert args.show_all is True


def test_order_report_inventories_fixture_and_formats_hints(fixture_root, sample_binaries):
    require_cpp_parser()
    original, rebuilt = sample_binaries
    report = generate_order_report(
        fixture_target(fixture_root, original, rebuilt),
        OrderOptions(
            build=False,
            include_similarity=False,
            show_all=True,
            show_runs=True,
        ),
    )
    text = format_order_report(report)

    assert [entry.address for entry in report.entries] == [0x00401000, 0x00401010]
    assert report.mapped_count == 1
    assert report.unmapped_count == 1
    assert report.aligned_count == 2
    assert len(report.boundary_hints) == 1
    assert report.source_summaries[0].source_file == "sample.cpp"
    assert report.source_summaries[0].run_count == 1
    assert "Compilation-unit order and boundary hints" in text
    assert "Source-file order hints" in text
    assert "sample.cpp" in text
    assert "0x00401010" in text
    assert "not probabilities or proof" in text
    assert "Original-address source-file runs" in text


def test_order_report_attaches_rebuilt_similarity(fixture_root, sample_binaries):
    require_cpp_parser()
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries

    report = generate_order_report(
        fixture_target(fixture_root, original, rebuilt),
        OrderOptions(build=False, include_similarity=True),
    )

    entry = next(item for item in report.entries if item.address == 0x00401000)
    assert entry.similarity == pytest.approx(100.0)


def test_order_report_detects_source_fragmentation_and_inversions(sample_binaries, tmp_path):
    require_cpp_parser()
    original, rebuilt = sample_binaries
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a.cpp").write_text(
        "/* Function start: 0x00401030 */\n"
        "int a_late() { return 3; }\n"
        "/* Function start: 0x00401000 */\n"
        "int a_early() { return 0; }\n"
    )
    (src_dir / "b.cpp").write_text(
        "/* Function start: 0x00401020 */\n"
        "int b_middle() { return 2; }\n"
    )
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0001:00000000       _a_early 00401000 f a.obj\n"
        " 0001:00000020       _b_middle 00401020 f b.obj\n"
    )
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(map_path),
        source_dirs=(str(src_dir),),
        build=BuildConfig(),
    )

    report = generate_order_report(
        target,
        OrderOptions(build=False, include_similarity=False, file_filter="a.cpp", show_all=True),
    )
    summary = next(item for item in report.source_summaries if item.source_file == "a.cpp")
    text = format_order_report(report)

    assert summary.run_count == 2
    assert summary.inversion_count == 1
    assert summary.rebuilt_object_start == 0x00401000
    assert [run.source_file for run in report.source_runs] == ["a.cpp", "b.cpp", "a.cpp"]
    assert any(hint.classification == "boundary candidate" for hint in report.boundary_hints)
    assert "2 original-address run(s)" in text
    assert "1 source-order inversion(s)" in text
    assert "source:  0x00401030 -> 0x00401000" in text
    assert "address: 0x00401000 -> 0x00401030" in text


def test_order_report_finds_initializer_like_pointer_anchor(fixture_root, tmp_path):
    require_cpp_parser()
    original = tmp_path / "original.exe"
    rebuilt = tmp_path / "rebuilt.exe"
    pointer_table = struct.pack("<IIII", 0, 0x00401000, 0x00401010, 0)
    write_tiny_pe(original, data_overrides={0: pointer_table})
    write_tiny_pe(rebuilt)

    report = generate_order_report(
        fixture_target(fixture_root, original, rebuilt),
        OrderOptions(build=False, include_similarity=False),
    )

    assert len(report.initializer_runs) == 1
    assert report.initializer_runs[0].targets == (0x00401000, 0x00401010)
    assert any(
        "initializer-like pointer table" in reason
        for hint in report.boundary_hints
        for reason in hint.reasons
    )


def test_order_report_rejects_invalid_alignment_before_reading_inputs():
    target = ProjectTarget("full", "missing.exe", "", "", ())

    with pytest.raises(ValueError, match="positive power of two"):
        generate_order_report(target, OrderOptions(alignment=3))
