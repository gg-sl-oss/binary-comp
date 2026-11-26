from __future__ import annotations

from binary_comp.core.asm_listing import function_lines, function_lines_from

LISTING = """\
_TEXT\tSEGMENT
?score@ScoreTable@@QAEHH@Z PROC NEAR\t\t\t; ScoreTable::score, COMDAT
\tpush\tebp
\tmov\teax, DWORD PTR _g_Bonus_00407038
_TEXT\tENDS
text$x\tSEGMENT
__unwindfunclet$?score@ScoreTable@@QAEHH@Z$0:
\tmov\teax, DWORD PTR _g_Cleanup_00407040
text$x\tENDS
?score@ScoreTable@@QAEHH@Z ENDP\t\t\t; ScoreTable::score
_TEXT\tSEGMENT
?score@ScoreTable@@QAEHH@Z PROC NEAR\t\t\t; ScoreTable::score, COMDAT
\tret\t0
?score@ScoreTable@@QAEHH@Z ENDP
_TEXT\tENDS
""".splitlines()


def test_body_stops_at_the_segment_end_by_default():
    assert function_lines_from(LISTING, "ScoreTable::score") == [
        "push\tebp",
        "mov\teax, DWORD PTR _g_Bonus_00407038",
    ]


def test_body_can_include_eh_funclets_up_to_endp():
    lines = function_lines_from(LISTING, "ScoreTable::score", stop_at_segment_end=False)
    assert "mov\teax, DWORD PTR _g_Cleanup_00407040" in lines
    assert lines[-1] == "text$x\tENDS"


def test_occurrence_index_selects_a_later_copy():
    assert function_lines_from(LISTING, "ScoreTable::score", 1) == ["ret\t0"]
    assert function_lines_from(LISTING, "ScoreTable::score", 2) == []


def test_symbol_matching_can_be_turned_off():
    no_comment = ["_main PROC NEAR", "\tret\t0", "_main ENDP"]
    assert function_lines_from(no_comment, "main") == ["ret\t0"]
    assert function_lines_from(no_comment, "main", match_symbol=False) == []


def test_unreadable_listing_gives_no_lines(tmp_path):
    assert function_lines(str(tmp_path / "missing.asm"), "main") == []
