"""Position-aware comparison helpers for arbitrary binary images.

These metrics deliberately describe positional identity, not edit-distance or
semantic similarity.  A shifted region therefore remains visible instead of
being presented as reconstruction progress that has not actually been linked
at the target address yet.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryComparison:
    original_size: int
    rebuilt_size: int
    matching_positions: int
    differing_positions: int
    differing_runs: int
    common_prefix: int
    common_suffix: int

    @property
    def compared_size(self) -> int:
        return max(self.original_size, self.rebuilt_size)

    @property
    def positional_identity(self) -> float:
        if self.compared_size == 0:
            return 100.0
        return self.matching_positions * 100.0 / self.compared_size

    @property
    def exact(self) -> bool:
        return self.differing_positions == 0


@dataclass(frozen=True)
class WordDeltaMatch:
    offset: int
    original: int
    rebuilt: int


@dataclass(frozen=True)
class WordDeltaAnalysis:
    delta: int
    words: tuple[WordDeltaMatch, ...]
    mismatch_count: int
    explained_count: int
    unexplained_offsets: tuple[int, ...]

    @property
    def complete(self) -> bool:
        return self.mismatch_count > 0 and not self.unexplained_offsets


def compare_binary(original: bytes, rebuilt: bytes) -> BinaryComparison:
    """Compare bytes at the same file/image offsets."""

    shared_size = min(len(original), len(rebuilt))
    compared_size = max(len(original), len(rebuilt))
    matching_positions = sum(
        original[index] == rebuilt[index]
        for index in range(shared_size)
    )

    common_prefix = 0
    while (
        common_prefix < shared_size
        and original[common_prefix] == rebuilt[common_prefix]
    ):
        common_prefix += 1

    common_suffix = 0
    suffix_limit = shared_size - common_prefix
    while (
        common_suffix < suffix_limit
        and original[len(original) - common_suffix - 1]
        == rebuilt[len(rebuilt) - common_suffix - 1]
    ):
        common_suffix += 1

    differing_runs = 0
    in_difference = False
    for index in range(compared_size):
        differs = (
            index >= len(original)
            or index >= len(rebuilt)
            or original[index] != rebuilt[index]
        )
        if differs and not in_difference:
            differing_runs += 1
        in_difference = differs

    return BinaryComparison(
        original_size=len(original),
        rebuilt_size=len(rebuilt),
        matching_positions=matching_positions,
        differing_positions=compared_size - matching_positions,
        differing_runs=differing_runs,
        common_prefix=common_prefix,
        common_suffix=common_suffix,
    )


def analyze_word_delta(
    original: bytes,
    rebuilt: bytes,
    *,
    delta: int,
    mask: bytes | None = None,
) -> WordDeltaAnalysis:
    """Explain byte differences as non-overlapping little-endian word deltas.

    ``delta`` is interpreted modulo 65536 as ``original - rebuilt``.  A word
    is eligible only when both of its bytes are unmasked and at least one byte
    differs.  Dynamic programming chooses a non-overlapping set that explains
    the most differing bytes, then uses the fewest words.
    """

    if len(original) != len(rebuilt):
        raise ValueError("word-delta analysis requires equal-sized inputs")
    if mask is None:
        mask = bytes([0xFF]) * len(original)
    if len(mask) != len(original):
        raise ValueError("word-delta mask must match the compared input size")

    size = len(original)
    normalized_delta = delta & 0xFFFF
    mismatches = {
        index
        for index, (left, right, enabled) in enumerate(zip(original, rebuilt, mask))
        if enabled and left != right
    }

    candidates: list[WordDeltaMatch | None] = [None] * size
    candidate_coverage = [0] * size
    for offset in range(size - 1):
        if not mask[offset] or not mask[offset + 1]:
            continue
        covered = int(offset in mismatches) + int(offset + 1 in mismatches)
        if not covered:
            continue
        original_word = int.from_bytes(original[offset:offset + 2], "little")
        rebuilt_word = int.from_bytes(rebuilt[offset:offset + 2], "little")
        if (original_word - rebuilt_word) & 0xFFFF != normalized_delta:
            continue
        candidates[offset] = WordDeltaMatch(offset, original_word, rebuilt_word)
        candidate_coverage[offset] = covered

    # best_covered/best_words describe the best selection at or after each
    # byte.  On an otherwise exact tie, prefer the earlier candidate so the
    # report remains stable.
    best_covered = [0] * (size + 2)
    best_words = [0] * (size + 2)
    take = [False] * size
    for offset in range(size - 1, -1, -1):
        skip_score = (best_covered[offset + 1], -best_words[offset + 1])
        candidate = candidates[offset]
        if candidate is None:
            best_covered[offset] = best_covered[offset + 1]
            best_words[offset] = best_words[offset + 1]
            continue
        take_score = (
            candidate_coverage[offset] + best_covered[offset + 2],
            -(1 + best_words[offset + 2]),
        )
        if take_score >= skip_score:
            take[offset] = True
            best_covered[offset] = take_score[0]
            best_words[offset] = -take_score[1]
        else:
            best_covered[offset] = skip_score[0]
            best_words[offset] = -skip_score[1]

    words: list[WordDeltaMatch] = []
    covered_offsets: set[int] = set()
    offset = 0
    while offset < size:
        if take[offset]:
            candidate = candidates[offset]
            assert candidate is not None
            words.append(candidate)
            covered_offsets.update({offset, offset + 1} & mismatches)
            offset += 2
        else:
            offset += 1

    unexplained = tuple(sorted(mismatches - covered_offsets))
    return WordDeltaAnalysis(
        delta=normalized_delta,
        words=tuple(words),
        mismatch_count=len(mismatches),
        explained_count=len(covered_offsets),
        unexplained_offsets=unexplained,
    )


def format_word_delta_analysis(
    analysis: WordDeltaAnalysis,
    *,
    max_words: int = 8,
) -> str:
    lines = [
        f"16-bit little-endian word delta 0x{analysis.delta:04x}",
        f"  explained differences: {analysis.explained_count} / {analysis.mismatch_count} byte(s)",
        f"  non-overlapping words: {len(analysis.words)}",
    ]
    for word in analysis.words[:max_words]:
        lines.append(
            f"    +0x{word.offset:04x}: original=0x{word.original:04x} rebuilt=0x{word.rebuilt:04x}"
        )
    if len(analysis.words) > max_words:
        lines.append(f"    ... {len(analysis.words) - max_words} more")
    if analysis.unexplained_offsets:
        shown = analysis.unexplained_offsets[:max_words]
        offsets = ", ".join(f"+0x{offset:04x}" for offset in shown)
        if len(analysis.unexplained_offsets) > max_words:
            offsets += f", ... {len(analysis.unexplained_offsets) - max_words} more"
        lines.append(f"  unexplained offsets: {offsets}")
    else:
        lines.append("  unexplained offsets: none")
    return "\n".join(lines)


def format_binary_comparison(
    comparison: BinaryComparison,
    *,
    title: str = "Binary positional comparison",
) -> str:
    delta = comparison.rebuilt_size - comparison.original_size
    delta_text = f"{delta:+d}"
    return "\n".join(
        [
            title,
            f"  original size:       {comparison.original_size}",
            f"  rebuilt size:        {comparison.rebuilt_size} ({delta_text})",
            f"  matching positions:  {comparison.matching_positions} / "
            f"{comparison.compared_size} "
            f"({comparison.positional_identity:.4f}%)",
            f"  differing positions: {comparison.differing_positions} "
            f"in {comparison.differing_runs} run(s)",
            f"  common prefix:       {comparison.common_prefix}",
            f"  common suffix:       {comparison.common_suffix}",
            f"  exact:               {'yes' if comparison.exact else 'no'}",
        ]
    )
