from __future__ import annotations

from binary_comp.analyzers.triage import (
    TriageOptions,
    format_triage_report,
    normalise,
    triage_comparison,
)
from binary_comp.cli import build_parser, run_triage
from binary_comp.core.disasm import Instruction

IMAGE = (0x00400000, 0x00800000)
OPTIONS = TriageOptions(image_range=IMAGE, show_diffs=4)


def instr(text: str) -> Instruction:
    mnemonic, _, op_str = text.partition(" ")
    return Instruction(address=0, mnemonic=mnemonic, op_str=op_str, operands=(), raw=text)


def row_for(ours: list[str], orig: list[str], options: TriageOptions = OPTIONS):
    return triage_comparison(
        "fn", "a.c", 0x401000, 50.0,
        [instr(t) for t in ours], [instr(t) for t in orig], options,
    )


def test_normalise_erases_registers_slots_and_relocations_but_keeps_constants():
    assert normalise("mov eax, dword ptr [ebp - 0x18]", IMAGE) == "mov R, dword ptr [R+D]"
    # Capstone prints small displacements in decimal.
    assert normalise("mov eax, dword ptr [ebp - 8]", IMAGE) == "mov R, dword ptr [R+D]"
    assert normalise("push 0x4b5eb4", IMAGE) == "push A"
    assert normalise("and eax, 0xffff007f", IMAGE) == "and R, 0xffff007f"


def test_register_and_slot_differences_are_churn_not_structural():
    row = row_for(
        ["mov eax, dword ptr [ebp - 8]", "add eax, 1"],
        ["mov esi, dword ptr [ebp - 0x18]", "add esi, 1"],
    )
    assert row.verdict == "churn"
    assert row.structural == 0
    assert row.register == 1      # eax vs esi in the add
    assert row.slot == 1          # the mov differs in register *and* slot


def test_relocation_only_difference_is_churn():
    row = row_for(["push 0x4a9610"], ["push 0x4b5eb4"])
    assert row.verdict == "churn"
    assert row.relocation == 1


def test_differing_constant_is_structural_not_churn():
    row = row_for(["and eax, 0xfffffe00"], ["and eax, 0xffff007f"])
    assert row.verdict == "structural"
    assert row.immediate == 1
    assert row.diffs[0].kind == "immediate"


def test_differing_mnemonic_is_structural():
    row = row_for(["jle 0x401100"], ["jge 0x402100"])
    assert row.verdict == "structural"
    assert row.mnemonic == 1


def test_insertion_is_reported_as_missing_and_does_not_shift_the_rest():
    # The original has one extra instruction in the middle; everything after it
    # still matches, so a positional comparison would be wrong here.
    row = row_for(
        ["push 1", "call 0x401000", "ret"],
        ["push 1", "xor eax, eax", "call 0x402000", "ret"],
    )
    assert row.missing == 1
    assert row.extra == 0
    assert row.mnemonic == 0
    assert row.matched == 2       # push and ret; the call is a relocation
    assert row.relocation == 1


def test_deletion_is_reported_as_extra():
    row = row_for(["push 1", "nop", "ret"], ["push 1", "ret"])
    assert row.extra == 1
    assert row.missing == 0


def test_report_lists_quick_wins_before_large_gaps():
    small = row_for(["jle 0x401100"], ["jge 0x402100"])
    from binary_comp.analyzers.triage import TriageReport
    big = triage_comparison(
        "big", "b.c", 0x402000, 50.0,
        [instr("nop")] * 2, [instr("push 1")] * 8, OPTIONS,
    )
    report = TriageReport(options=OPTIONS, rows=(small, big))
    text = format_triage_report(report)
    assert "fewest first" in text
    assert "structural:             2" in text
    assert "churn only:             0" in text


def test_triage_command_parser_exposes_controls():
    args = build_parser().parse_args([
        "triage", "--no-build", "--filter", "x.c",
        "--max-similarity", "99.5", "--min-similarity", "80",
        "--limit", "5", "--show-diffs", "3", "--largest-first",
        "--image-base", "0x400000", "--image-end", "0x800000",
    ])
    assert args.handler is run_triage
    assert args.no_build is True
    assert args.file_filter == "x.c"
    assert args.max_similarity == 99.5
    assert args.min_similarity == 80.0
    assert args.limit == 5
    assert args.show_diffs == 3
    assert args.largest_first is True
    assert args.image_base == 0x400000
    assert args.image_end == 0x800000
