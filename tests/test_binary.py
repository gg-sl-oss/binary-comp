from __future__ import annotations

import pytest

from binary_comp.core.binary import analyze_word_delta, format_word_delta_analysis


def test_word_delta_explains_non_overlapping_little_endian_words():
    rebuilt = bytes.fromhex("aa 91 15 ef 15 bb")
    original = bytes.fromhex("aa 4e 16 ac 16 bb")

    analysis = analyze_word_delta(original, rebuilt, delta=0xBD)

    assert analysis.complete
    assert analysis.mismatch_count == 4
    assert analysis.explained_count == 4
    assert [word.offset for word in analysis.words] == [1, 3]
    assert [(word.rebuilt, word.original) for word in analysis.words] == [
        (0x1591, 0x164E),
        (0x15EF, 0x16AC),
    ]
    assert "explained differences: 4 / 4 byte(s)" in format_word_delta_analysis(analysis)
    assert "unexplained offsets: none" in format_word_delta_analysis(analysis)


def test_word_delta_reports_unexplained_and_ignores_masked_bytes():
    rebuilt = bytes.fromhex("91 15 10 20 30 40")
    original = bytes.fromhex("4e 16 11 22 31 40")
    mask = bytes.fromhex("ff ff ff ff 00 ff")

    analysis = analyze_word_delta(original, rebuilt, delta=0xBD, mask=mask)

    assert not analysis.complete
    assert analysis.explained_count == 2
    assert analysis.mismatch_count == 4
    assert analysis.unexplained_offsets == (2, 3)


def test_word_delta_rejects_different_input_or_mask_sizes():
    with pytest.raises(ValueError, match="equal-sized"):
        analyze_word_delta(b"\x00", b"", delta=1)
    with pytest.raises(ValueError, match="mask"):
        analyze_word_delta(b"\x00", b"\x01", delta=1, mask=b"")
