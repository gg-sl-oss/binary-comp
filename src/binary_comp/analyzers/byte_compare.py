"""Byte-level comparison of one original function with its rebuilt counterpart.

Mnemonic similarity cannot see registers, operands or encodings, so two
functions can score 100% and still differ in every byte.  This compares the
encoded bytes instead, over the function's whole span when its end is known:
the code, the switch tables a compiler places after it, and the padding up to
the next function, all of which decide where everything after it lands.

A field a base relocation patches compares by position only, since the two
images place data differently.  A direct branch compares by its target's
offset into the function when the target is inside it, and not at all when
it is outside (another function, which may sit elsewhere in the rebuilt
image).
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from binary_comp.core.disasm import Instruction, is_branch_or_call
from binary_comp.core.pe import PEImage


@dataclass(frozen=True)
class ByteComparison:
    original_size: int
    rebuilt_size: int
    instructions: int
    differing: int
    first_difference: int | None

    @property
    def exact(self) -> bool:
        return self.differing == 0 and self.original_size == self.rebuilt_size

    @property
    def same_size(self) -> bool:
        return self.original_size == self.rebuilt_size

    @property
    def label(self) -> str:
        if self.exact:
            return "EXACT"
        if self.same_size:
            return f"BYTES {self.differing}/{self.instructions}"
        return f"SIZE {self.rebuilt_size - self.original_size:+d}"


def instruction_bytes(image: PEImage, instr: Instruction) -> bytes:
    from binary_comp.analyzers.function_compare import instruction_size

    return image.read(instr.address, instruction_size(image, instr)) or b""


def branch_target(instr: Instruction) -> int | None:
    if not is_branch_or_call(instr.mnemonic) or not instr.operands:
        return None
    operand = instr.operands[0]
    if operand.kind != "imm":
        return None
    return operand.imm & 0xFFFFFFFF


def span_tokens(
    image: PEImage,
    start: int,
    end: int,
    instructions: list[Instruction],
) -> list[object]:
    """One token per byte of [start, end): the byte, or a marker for a field
    that is compared by meaning rather than value."""
    data = image.read(start, end - start) or b""
    tokens: list[object] = list(data)
    relocations = image.relocations()
    for offset in range(len(tokens)):
        if start + offset in relocations:
            for field in range(offset, min(offset + 4, len(tokens))):
                tokens[field] = ("reloc", field - offset)
    for instr in instructions:
        if not start <= instr.address < end:
            continue
        target = branch_target(instr)
        if target is None:
            continue
        size = len(instruction_bytes(image, instr))
        width = 1 if size <= 3 else 4
        offset = instr.address - start + size - width
        if offset < 0 or offset + width > len(tokens):
            continue
        if any(isinstance(token, tuple) for token in tokens[offset:offset + width]):
            continue
        marker = ("internal", target - start) if start <= target < end else ("external",)
        for field in range(offset, offset + width):
            tokens[field] = (marker, field - offset)
    return tokens


def instruction_spans(start: int, end: int, instructions: list[Instruction], image: PEImage) -> list[tuple[int, int]]:
    spans = []
    for instr in sorted(instructions, key=lambda item: item.address):
        if start <= instr.address < end:
            offset = instr.address - start
            spans.append((offset, offset + len(instruction_bytes(image, instr))))
    return spans


def extent(image: PEImage, instructions: list[Instruction]) -> tuple[int, int]:
    first = min(instructions, key=lambda item: item.address)
    last = max(instructions, key=lambda item: item.address)
    return first.address, last.address + len(instruction_bytes(image, last))


def compare_function_bytes(
    original_image: PEImage,
    original: list[Instruction],
    rebuilt_image: PEImage,
    rebuilt: list[Instruction],
    original_end: int | None = None,
    rebuilt_end: int | None = None,
) -> ByteComparison:
    """Compare two functions byte for byte.

    ``original_end`` and ``rebuilt_end`` are the next function starts; with
    them the comparison covers each function's whole span, including switch
    tables and padding, and without them only its instructions.
    """
    if not original or not rebuilt:
        count = max(len(original), len(rebuilt))
        return ByteComparison(0, 0, count, count, 0)

    original_start, code_end = extent(original_image, original)
    rebuilt_start, rebuilt_code_end = extent(rebuilt_image, rebuilt)
    original_end = max(original_end or code_end, code_end)
    rebuilt_end = max(rebuilt_end or rebuilt_code_end, rebuilt_code_end)
    left = span_tokens(original_image, original_start, original_end, original)
    right = span_tokens(rebuilt_image, rebuilt_start, rebuilt_end, rebuilt)
    pieces = instruction_spans(original_start, original_end, original, original_image)

    if len(left) == len(right):
        differing_offsets = [offset for offset, (a, b) in enumerate(zip(left, right)) if a != b]
        first_difference = differing_offsets[0] if differing_offsets else None
        hit = set()
        outside = False
        for offset in differing_offsets:
            for index, (lo, hi) in enumerate(pieces):
                if lo <= offset < hi:
                    hit.add(index)
                    break
            else:
                outside = True
        differing = len(hit) + (1 if outside else 0)
        return ByteComparison(len(left), len(right), len(pieces), differing, first_difference)

    # Different sizes: count the instructions that have no counterpart.
    def keys(tokens, spans):
        return [tuple(tokens[lo:hi]) for lo, hi in spans]

    rebuilt_pieces = instruction_spans(rebuilt_start, rebuilt_end, rebuilt, rebuilt_image)
    original_keys = keys(left, pieces)
    rebuilt_keys = keys(right, rebuilt_pieces)
    matcher = SequenceMatcher(None, original_keys, rebuilt_keys, autojunk=False)
    matched = sum(block.size for block in matcher.get_matching_blocks())
    differing = max(len(original_keys), len(rebuilt_keys)) - matched
    first_difference = None
    for tag, index, _index_end, _other, _other_end in matcher.get_opcodes():
        if tag != "equal":
            first_difference = pieces[min(index, len(pieces) - 1)][0] if pieces else 0
            break
    return ByteComparison(
        original_size=len(left),
        rebuilt_size=len(right),
        instructions=max(len(original_keys), len(rebuilt_keys)),
        differing=differing,
        first_difference=first_difference,
    )
