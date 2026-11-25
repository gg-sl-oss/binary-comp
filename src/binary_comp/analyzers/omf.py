"""16/32-bit OMF object parsing and relocation-masked comparison helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from binary_comp.analyzers.function_compare import (
    DisassemblyResult,
    FunctionComparison,
    instruction_mnemonics,
    mnemonic_similarity,
)
from binary_comp.analyzers.report import SimilarityReport, SimilarityReportOptions, SimilarityReportRow
from binary_comp.config import (
    ProjectTarget,
    config_int,
    optional_string,
    require_string,
    resolve_config_path,
)
from binary_comp.core.binary import masked_count, masked_mismatches, relocation_mask
from binary_comp.core.disasm import Instruction, disassemble_raw
from binary_comp.core.le import LEImage


OMF_LEDATA = 0xA0
OMF_LEDATA32 = 0xA1
OMF_FIXUPP = 0x9C
OMF_FIXUPP32 = 0x9D
OMF_PUBDEF = 0x90
OMF_PUBDEF32 = 0x91
OMF_LPUBDEF = 0xB6
OMF_LPUBDEF32 = 0xB7


class OmfCompareError(RuntimeError):
    pass


@dataclass(frozen=True)
class OmfRecord:
    record_type: int
    offset: int
    content: bytes


@dataclass(frozen=True)
class LedataRecord:
    segment_index: int
    offset: int
    data: bytes


@dataclass(frozen=True)
class OmfFixup:
    offset: int
    length: int
    location_type: int


@dataclass(frozen=True)
class OmfImageFixup:
    segment_index: int
    offset: int
    length: int
    location_type: int


@dataclass(frozen=True)
class OmfObjectImage:
    segments: dict[int, bytes]
    publics: dict[str, tuple[int, int]]
    fixups: tuple[OmfImageFixup, ...]


@dataclass(frozen=True)
class OmfComparison:
    name: str
    original_path: str
    original_offset: int
    object_path: str
    object_offset: int
    segment_index: int | None
    original: bytes
    rebuilt: bytes
    mask: bytes
    fixups: tuple[OmfFixup, ...]
    fixup_layout_matches: bool | None = None
    literal_matches: tuple[bool, ...] = ()

    @property
    def compared_size(self) -> int:
        return len(self.rebuilt)

    @property
    def masked_count(self) -> int:
        return masked_count(self.mask)

    @property
    def mismatches(self) -> tuple[int, ...]:
        return masked_mismatches(self.original, self.rebuilt, self.mask)

    @property
    def matches(self) -> bool:
        return (
            bool(self.rebuilt)
            and len(self.original) == len(self.rebuilt)
            and not self.mismatches
            and self.fixup_layout_matches is not False
            and all(self.literal_matches)
        )


@dataclass(frozen=True)
class OmfLiteralSpec:
    original_offset: int
    segment_index: int
    object_offset: int
    size: int


@dataclass(frozen=True)
class OmfCompareSpec:
    name: str
    function_name: str
    original_path: str
    original_offset: int
    object_path: str
    size: int | None = None
    object_offset: int = 0
    segment_index: int | None = None
    ledata_index: int = 0
    source_path: str | None = None
    target: str | None = None
    compiler_flags: str | None = None
    bits: int = 16
    symbol: str | None = None
    original_address: int | None = None
    expected_fixups: tuple[tuple[int, int], ...] | None = None
    literals: tuple[OmfLiteralSpec, ...] = ()


def read_index(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise OmfCompareError("truncated OMF index")
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= len(data):
            raise OmfCompareError("truncated two-byte OMF index")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def iter_records(data: bytes) -> list[OmfRecord]:
    records: list[OmfRecord] = []
    offset = 0
    while offset < len(data):
        if offset + 3 > len(data):
            raise OmfCompareError(f"truncated OMF record header at 0x{offset:x}")
        record_type = data[offset]
        record_len = int.from_bytes(data[offset + 1:offset + 3], "little")
        record_end = offset + 3 + record_len
        if record_len <= 0 or record_end > len(data):
            raise OmfCompareError(f"truncated OMF record at 0x{offset:x}")
        content = data[offset + 3:record_end - 1]
        records.append(OmfRecord(record_type, offset, content))
        offset = record_end
    return records


def parse_ledata_with_width(content: bytes, offset_width: int) -> LedataRecord:
    segment_index, cursor = read_index(content, 0)
    if segment_index == 0:
        raise OmfCompareError("LEDATA segment index must be nonzero")
    if cursor + offset_width > len(content):
        raise OmfCompareError("truncated LEDATA offset")
    offset = int.from_bytes(content[cursor:cursor + offset_width], "little")
    return LedataRecord(
        segment_index=segment_index,
        offset=offset,
        data=content[cursor + offset_width:],
    )


def parse_ledata(content: bytes) -> LedataRecord:
    return parse_ledata_with_width(content, 2)


def parse_pubdef_with_width(
    content: bytes,
    offset_width: int,
) -> tuple[tuple[str, int, int], ...]:
    _, cursor = read_index(content, 0)  # base group
    segment_index, cursor = read_index(content, cursor)
    if segment_index == 0:
        if cursor + 2 > len(content):
            raise OmfCompareError("truncated absolute PUBDEF frame")
        cursor += 2

    publics: list[tuple[str, int, int]] = []
    while cursor < len(content):
        name_length = content[cursor]
        cursor += 1
        if cursor + name_length + offset_width > len(content):
            raise OmfCompareError("truncated PUBDEF symbol")
        name = content[cursor:cursor + name_length].decode("latin-1")
        cursor += name_length
        offset = int.from_bytes(content[cursor:cursor + offset_width], "little")
        cursor += offset_width
        _, cursor = read_index(content, cursor)  # type index
        publics.append((name, segment_index, offset))
    return tuple(publics)


def fixup_length(location_type: int) -> int:
    # Standard Intel/IBM/Microsoft OMF location kinds. PharLap assigns
    # conflicting meanings to 5 and 6; this parser follows the TIS values.
    return {
        0: 1,
        1: 2,
        2: 2,
        3: 4,
        4: 1,
        5: 2,
        9: 4,
        11: 6,
        13: 4,
    }.get(location_type, 0)


def skip_frame_datum(content: bytes, cursor: int, method: int) -> int:
    if method in (0, 1, 2):
        _, cursor = read_index(content, cursor)
    elif method not in (4, 5):
        raise OmfCompareError(f"unsupported FIXUPP FRAME method F{method}")
    return cursor


def skip_target_datum(content: bytes, cursor: int, method: int) -> int:
    if method in (0, 1, 2):
        _, cursor = read_index(content, cursor)
    else:
        raise OmfCompareError(f"unsupported FIXUPP TARGET method T{method}")
    return cursor


def parse_fixupp_locations(
    content: bytes,
    *,
    displacement_width: int,
    segment_index: int,
    ledata_offset: int,
) -> tuple[OmfImageFixup, ...]:
    """Parse all patch locations in one FIXUPP/FIXUPP32 record.

    FIXUPP locations are relative to the nearest preceding data record. Frame
    and target metadata is consumed even though masking only needs each patch's
    location and width; doing so avoids mistaking two-byte indexes for the next
    subrecord.
    """
    if displacement_width not in (2, 4):
        raise ValueError("FIXUPP displacement width must be 2 or 4")

    fixups: list[OmfImageFixup] = []
    cursor = 0
    while cursor < len(content):
        first = content[cursor]
        cursor += 1
        if not (first & 0x80):
            frame_thread = bool(first & 0x40)
            method = (first >> 2) & (0x07 if frame_thread else 0x03)
            if frame_thread:
                cursor = skip_frame_datum(content, cursor, method)
            else:
                cursor = skip_target_datum(content, cursor, method)
            continue

        if cursor >= len(content):
            raise OmfCompareError("truncated FIXUPP location")
        locat = ((first & 0x3F) << 8) | content[cursor]
        cursor += 1
        data_offset = locat & 0x03FF
        location_type = (locat >> 10) & 0x0F
        length = fixup_length(location_type)
        if not length:
            raise OmfCompareError(
                f"unsupported FIXUPP location type {location_type}"
            )
        fixups.append(
            OmfImageFixup(
                segment_index=segment_index,
                offset=ledata_offset + data_offset,
                length=length,
                location_type=location_type,
            )
        )

        if cursor >= len(content):
            raise OmfCompareError("truncated FIXUPP fix data")
        fix_data = content[cursor]
        cursor += 1
        frame_uses_thread = bool(fix_data & 0x80)
        frame_method = (fix_data >> 4) & 0x07
        target_uses_thread = bool(fix_data & 0x08)
        no_displacement = bool(fix_data & 0x04)
        target_method = fix_data & 0x03

        if not frame_uses_thread:
            cursor = skip_frame_datum(content, cursor, frame_method)
        if not target_uses_thread:
            cursor = skip_target_datum(content, cursor, target_method)
        if not no_displacement:
            if cursor + displacement_width > len(content):
                raise OmfCompareError("truncated FIXUPP target displacement")
            cursor += displacement_width
    return tuple(fixups)


def parse_fixupp(content: bytes) -> tuple[OmfFixup, ...]:
    parsed = parse_fixupp_locations(
        content,
        displacement_width=2,
        segment_index=0,
        ledata_offset=0,
    )
    return tuple(
        OmfFixup(fixup.offset, fixup.length, fixup.location_type)
        for fixup in parsed
    )


def load_omf_image(path: str | Path) -> OmfObjectImage:
    chunks: dict[int, list[tuple[int, bytes]]] = {}
    publics: dict[str, tuple[int, int]] = {}
    fixups: list[OmfImageFixup] = []
    last_ledata: LedataRecord | None = None

    for record in iter_records(Path(path).read_bytes()):
        if record.record_type in (OMF_LEDATA, OMF_LEDATA32):
            width = 4 if record.record_type == OMF_LEDATA32 else 2
            ledata = parse_ledata_with_width(record.content, width)
            chunks.setdefault(ledata.segment_index, []).append(
                (ledata.offset, ledata.data)
            )
            last_ledata = ledata
        elif record.record_type in (OMF_FIXUPP, OMF_FIXUPP32):
            width = 4 if record.record_type == OMF_FIXUPP32 else 2
            parsed = parse_fixupp_locations(
                record.content,
                displacement_width=width,
                segment_index=last_ledata.segment_index if last_ledata else 0,
                ledata_offset=last_ledata.offset if last_ledata else 0,
            )
            if parsed and last_ledata is None:
                raise OmfCompareError(
                    "FIXUPP patch appears before a supported LEDATA record"
                )
            fixups.extend(parsed)
        elif record.record_type in (
            OMF_PUBDEF,
            OMF_PUBDEF32,
            OMF_LPUBDEF,
            OMF_LPUBDEF32,
        ):
            width = 4 if record.record_type in (OMF_PUBDEF32, OMF_LPUBDEF32) else 2
            for name, segment_index, offset in parse_pubdef_with_width(
                record.content,
                width,
            ):
                publics[name] = (segment_index, offset)
        elif record.record_type in (0xA2, 0xA3, 0xC2, 0xC3):
            # LIDATA and COMDAT require expansion/allocation before their
            # fixup locations can be projected into a segment image.
            last_ledata = None

    if not chunks:
        raise OmfCompareError(f"no LEDATA records found in {path}")

    segments: dict[int, bytes] = {}
    for segment_index, records in chunks.items():
        size = max(offset + len(data) for offset, data in records)
        image = bytearray(size)
        for offset, data in records:
            image[offset:offset + len(data)] = data
        segments[segment_index] = bytes(image)
    return OmfObjectImage(segments, publics, tuple(fixups))


def load_omf_object(path: str | Path) -> tuple[list[LedataRecord], tuple[OmfFixup, ...]]:
    data = Path(path).read_bytes()
    ledata: list[LedataRecord] = []
    fixups: list[OmfFixup] = []
    for record in iter_records(data):
        if record.record_type == OMF_LEDATA:
            ledata.append(parse_ledata(record.content))
        elif record.record_type == OMF_FIXUPP:
            fixups.extend(parse_fixupp(record.content))
    if not ledata:
        raise OmfCompareError(f"no LEDATA records found in {path}")
    return ledata, tuple(fixups)


def select_ledata(
    records: list[LedataRecord],
    segment_index: int | None = None,
    ledata_index: int = 0,
) -> LedataRecord:
    candidates = [record for record in records if segment_index is None or record.segment_index == segment_index]
    if ledata_index < 0 or ledata_index >= len(candidates):
        raise OmfCompareError(
            f"LEDATA index {ledata_index} out of range for "
            f"{'any segment' if segment_index is None else f'segment {segment_index}'}"
        )
    return candidates[ledata_index]


def build_mask(size: int, fixups: tuple[OmfFixup, ...], object_offset: int = 0) -> bytes:
    return relocation_mask(size, ((fixup.offset, fixup.length) for fixup in fixups), object_offset)


def build_segment_mask(
    size: int,
    fixups: tuple[OmfImageFixup, ...],
    *,
    segment_index: int,
    object_offset: int = 0,
) -> bytes:
    """Build a mask for a window in one assembled OMF segment image."""
    spans = ((fixup.offset, fixup.length) for fixup in fixups if fixup.segment_index == segment_index)
    return relocation_mask(size, spans, object_offset)


def compare_omf_to_original(
    *,
    original_path: str | Path,
    original_offset: int,
    object_path: str | Path,
    size: int | None = None,
    object_offset: int = 0,
    segment_index: int | None = None,
    ledata_index: int = 0,
    name: str = "omf-function",
    bits: int = 16,
    symbol: str | None = None,
    expected_fixups: tuple[tuple[int, int], ...] | None = None,
    literals: tuple[OmfLiteralSpec, ...] = (),
) -> OmfComparison:
    if bits not in (16, 32):
        raise OmfCompareError("bits must be 16 or 32")
    if size is not None and size <= 0:
        raise OmfCompareError("size must be positive")
    image = None
    if bits == 32 or symbol is not None:
        if ledata_index:
            raise OmfCompareError("LEDATA index is not used with segment images")
        image = load_omf_image(object_path)
        if symbol is not None:
            if symbol not in image.publics:
                raise OmfCompareError(f"OMF public symbol not found: {symbol}")
            selected_segment, start = image.publics[symbol]
            if object_offset or segment_index not in (None, selected_segment):
                raise OmfCompareError("symbol cannot be combined with a different object window")
            segment_index, object_offset = selected_segment, start
        elif segment_index is None:
            segment_index = next(iter(image.segments))
        if segment_index not in image.segments:
            raise OmfCompareError(f"OMF segment not found: {segment_index}")
        data = image.segments[segment_index]
        end = min(
            [offset for segment, offset in image.publics.values()
             if symbol is not None and segment == segment_index and offset > object_offset]
            + [len(data)]
        )
        fixups = tuple(OmfFixup(f.offset, f.length, f.location_type)
                       for f in image.fixups if f.segment_index == segment_index)
    else:
        ledata_records, fixups = load_omf_object(object_path)
        ledata = select_ledata(ledata_records, segment_index=segment_index, ledata_index=ledata_index)
        data, end = ledata.data, len(ledata.data)
    if object_offset < 0 or object_offset >= end:
        raise OmfCompareError("object_offset outside emitted object bytes")
    rebuilt = data[object_offset:end]
    # A public symbol selects its whole body. The expected original size must
    # never truncate a larger rebuilt function or silently accept a shorter one.
    if size is not None and symbol is None:
        rebuilt = rebuilt[:size]
    original_data = Path(original_path).read_bytes()
    original_size = size if size is not None else len(rebuilt)
    if original_offset < 0 or original_offset + original_size > len(original_data):
        raise OmfCompareError("original byte window outside file")
    original = original_data[original_offset:original_offset + original_size]
    mask = build_mask(len(rebuilt), fixups, object_offset=object_offset)
    actual_fixups = sorted((f.offset - object_offset, f.length) for f in fixups
                           if f.offset < object_offset + len(rebuilt)
                           and f.offset + f.length > object_offset)
    layout_matches = None if expected_fixups is None else actual_fixups == sorted(expected_fixups)
    literal_matches = []
    if literals and image is None:
        image = load_omf_image(object_path)
    for literal in literals:
        if min(literal.original_offset, literal.object_offset) < 0 or literal.size <= 0:
            raise OmfCompareError("literal offsets must be non-negative and size positive")
        if literal.original_offset + literal.size > len(original_data):
            raise OmfCompareError("original literal window outside file")
        expected = original_data[literal.original_offset:literal.original_offset + literal.size]
        actual = image.segments.get(literal.segment_index, b"")[
            literal.object_offset:literal.object_offset + literal.size]
        literal_matches.append(actual == expected)
    return OmfComparison(
        name=name,
        original_path=str(original_path),
        original_offset=original_offset,
        object_path=str(object_path),
        object_offset=object_offset,
        segment_index=segment_index,
        original=original,
        rebuilt=rebuilt,
        mask=mask,
        fixups=fixups,
        fixup_layout_matches=layout_matches,
        literal_matches=tuple(literal_matches),
    )


def compare_omf_spec_bytes(spec: OmfCompareSpec) -> OmfComparison:
    return compare_omf_to_original(
        original_path=spec.original_path,
        original_offset=spec.original_offset,
        object_path=spec.object_path,
        size=spec.size,
        object_offset=spec.object_offset,
        segment_index=spec.segment_index,
        ledata_index=spec.ledata_index,
        name=spec.name,
        bits=spec.bits,
        symbol=spec.symbol,
        expected_fixups=spec.expected_fixups,
        literals=spec.literals,
    )


@dataclass(frozen=True)
class EmbeddedTable:
    """Relocated words a compiler stores inside a function's code."""

    offset: int
    width: int
    count: int

    @property
    def end(self) -> int:
        return self.offset + self.width * self.count


def embedded_tables(
    data: bytes,
    sites: Iterable[tuple[int, int]],
    low: int,
    high: int,
    values: dict[int, int] | None = None,
) -> tuple[EmbeddedTable, ...]:
    """Find jump tables embedded in a function's bytes.

    ``sites`` are relocated ``(offset, width)`` fields relative to ``data`` and
    ``low``/``high`` bound the function's addresses as the words hold them;
    ``values`` overrides the stored word at an offset, for images whose loader
    writes the final address. A table is a run of at least two adjacent,
    equally wide relocated words that all point back into the function.
    Instruction operands rarely form such runs; a leading word that points
    into its own run, such as the displacement of the jump that indexes a
    table placed right after it, is left to the instruction it belongs to.
    """
    def value_at(offset: int, width: int) -> int:
        if values is not None and offset in values:
            return values[offset]
        return int.from_bytes(data[offset:offset + width], "little")

    words = sorted({(offset, width) for offset, width in sites
                    if width in (2, 4) and offset >= 0 and offset + width <= len(data)})
    tables: list[EmbeddedTable] = []
    index = 0
    while index < len(words):
        width = words[index][1]
        end = index + 1
        while end < len(words) and words[end] == (words[end - 1][0] + width, width):
            end += 1
        run = [entry for entry, _width in words[index:end]]
        index = end
        targets = [value_at(entry, width) for entry in run]
        while len(run) >= 2 and low + run[0] <= targets[0] < low + run[-1] + width:
            run, targets = run[1:], targets[1:]
        if len(run) >= 2 and all(low <= target < high for target in targets):
            tables.append(EmbeddedTable(run[0], width, len(run)))
    return tuple(tables)


def disassemble_with_tables(
    data: bytes,
    address: int,
    tables: Iterable[EmbeddedTable],
    *,
    bits: int,
    values: dict[int, int] | None = None,
) -> list[Instruction]:
    """Disassemble code around embedded tables, emitting one item per entry."""
    instructions: list[Instruction] = []
    cursor = 0
    for table in sorted(tables, key=lambda item: item.offset):
        if table.offset < cursor:
            continue
        if table.offset > cursor:
            instructions += disassemble_raw(data[cursor:table.offset], address + cursor, bits=bits)
        directive = "dd" if table.width == 4 else "dw"
        for entry in range(table.offset, table.end, table.width):
            value = (values or {}).get(entry, int.from_bytes(data[entry:entry + table.width], "little"))
            instructions.append(Instruction(
                address=address + entry,
                mnemonic=directive,
                op_str=f"0x{value:x}",
                operands=(),
                raw=f"{directive} 0x{value:x}",
                size=table.width,
            ))
        cursor = table.end
    if cursor < len(data):
        instructions += disassemble_raw(data[cursor:], address + cursor, bits=bits)
    return instructions


@lru_cache(maxsize=4)
def linear_executable_relocations(path: str) -> dict[int, tuple[int, int]] | None:
    """Loader writes of an LE/LX executable, or None for other files."""
    try:
        return LEImage(path).relocations()
    except (OSError, ValueError, IndexError, struct.error):
        return None


def original_relocated_words(spec: OmfCompareSpec, size: int) -> dict[int, int] | None:
    """Final values of the original window's relocated words, by offset.

    LE/LX pages hold object-relative offsets that the loader rebases, so jump
    table entries only compare with the function's address after applying the
    executable's fixup records.
    """
    if spec.original_address is None:
        return None
    relocations = linear_executable_relocations(str(spec.original_path))
    if relocations is None:
        return None
    start = spec.original_address
    return {site - start: value for site, (width, value) in relocations.items()
            if width == 4 and start <= site and site + width <= start + size}


def omf_comparison_tables(
    spec: OmfCompareSpec,
    comparison: OmfComparison,
) -> tuple[tuple[EmbeddedTable, ...], tuple[EmbeddedTable, ...], dict[int, int] | None]:
    """Embedded tables of the original and rebuilt sides of a comparison.

    The rebuilt side uses the object's fixups, whose stored values are offsets
    in the function's segment. The original side needs the original address:
    an LE/LX original supplies its relocated words, which are also returned
    for display; any other original must store linked addresses, located by
    the reviewed fixup layout when the configuration provides one.
    """
    rebuilt_sites = [(fixup.offset - comparison.object_offset, fixup.length)
                     for fixup in comparison.fixups]
    rebuilt_tables = embedded_tables(
        comparison.rebuilt,
        rebuilt_sites,
        comparison.object_offset,
        comparison.object_offset + len(comparison.rebuilt),
    )
    original_tables: tuple[EmbeddedTable, ...] = ()
    original_values = None
    if spec.original_address is not None:
        original_values = original_relocated_words(spec, len(comparison.original))
        if original_values is not None:
            original_sites = [(offset, 4) for offset in original_values]
        elif spec.expected_fixups is not None:
            original_sites = list(spec.expected_fixups)
        else:
            original_sites = rebuilt_sites
        original_tables = embedded_tables(
            comparison.original,
            original_sites,
            spec.original_address,
            spec.original_address + len(comparison.original),
            original_values,
        )
    return original_tables, rebuilt_tables, original_values


def compare_omf_spec(spec: OmfCompareSpec) -> FunctionComparison:
    byte_comparison = compare_omf_spec_bytes(spec)
    address = spec.original_address if spec.original_address is not None else spec.original_offset
    original_tables, rebuilt_tables, original_values = omf_comparison_tables(spec, byte_comparison)
    original = DisassemblyResult(
        disassemble_with_tables(byte_comparison.original, address, original_tables,
                                bits=spec.bits, values=original_values),
        [],
    )
    rebuilt = DisassemblyResult(
        disassemble_with_tables(byte_comparison.rebuilt, byte_comparison.object_offset,
                                rebuilt_tables, bits=spec.bits),
        [],
    )
    if not original.instructions:
        raise OmfCompareError("could not disassemble original bytes")
    if not rebuilt.instructions:
        raise OmfCompareError("could not disassemble rebuilt OMF bytes")
    similarity = mnemonic_similarity(
        instruction_mnemonics(rebuilt.instructions),
        instruction_mnemonics(original.instructions),
    )
    return FunctionComparison(
        function_name=spec.function_name,
        original_addr=address,
        rebuilt_addr=byte_comparison.object_offset,
        similarity=similarity,
        rebuilt=rebuilt,
        original=original,
    )


def load_omf_specs(config: dict[str, Any], config_path: str | Path, target_name: str | None = None) -> tuple[OmfCompareSpec, ...]:
    section = config.get("omf_compare", {})
    if not isinstance(section, dict):
        raise OmfCompareError("omf_compare must be an object")
    functions = section.get("functions", [])
    if not isinstance(functions, list):
        raise OmfCompareError("omf_compare.functions must be a list")

    specs: list[OmfCompareSpec] = []
    for index, item in enumerate(functions):
        label = f"omf_compare.functions[{index}]"
        if not isinstance(item, dict):
            raise OmfCompareError(f"{label} must be an object")
        item_target = optional_string(item, "target")
        if target_name is not None and item_target not in (None, target_name):
            continue
        name = require_string(item, "name", f"{label}.name")
        original = require_string(item, "original", f"{label}.original")
        object_path = require_string(item, "object", f"{label}.object")
        function_name = optional_string(item, "function") or name
        target_kind = config.get("targets", {}).get(item_target or target_name, {}).get("kind")
        bits = config_int(item.get("bits", 32 if target_kind == "dos32-omf" else 16), f"{label}.bits")
        if bits not in (16, 32):
            raise OmfCompareError(f"{label}.bits must be 16 or 32")
        expected_fixups = None
        if "expected_fixups" in item:
            raw_fixups = item["expected_fixups"]
            if not isinstance(raw_fixups, list) or not all(isinstance(f, dict) for f in raw_fixups):
                raise OmfCompareError(f"{label}.expected_fixups must be a list of objects")
            expected_fixups = tuple(
                (config_int(f.get("offset"), f"{label}.expected_fixups.offset"),
                 config_int(f.get("size"), f"{label}.expected_fixups.size"))
                for f in raw_fixups
            )
            if any(offset < 0 or size <= 0 for offset, size in expected_fixups):
                raise OmfCompareError(f"{label}.expected_fixups has an invalid range")
        raw_literals = item.get("literals", [])
        if not isinstance(raw_literals, list) or not all(isinstance(f, dict) for f in raw_literals):
            raise OmfCompareError(f"{label}.literals must be a list of objects")
        literals = tuple(OmfLiteralSpec(**{
            key: config_int(literal.get(key), f"{label}.literals.{key}")
            for key in ("original_offset", "segment_index", "object_offset", "size")
        }) for literal in raw_literals)
        specs.append(OmfCompareSpec(
            name=name,
            function_name=function_name,
            original_path=resolve_config_path(config_path, original) or "",
            original_offset=config_int(item.get("original_offset"), f"{label}.original_offset") or 0,
            object_path=resolve_config_path(config_path, object_path) or "",
            size=config_int(item.get("size"), f"{label}.size", required=False),
            object_offset=config_int(item.get("object_offset", 0), f"{label}.object_offset") or 0,
            segment_index=config_int(item.get("segment_index"), f"{label}.segment_index", required=False),
            ledata_index=config_int(item.get("ledata_index", 0), f"{label}.ledata_index") or 0,
            source_path=resolve_config_path(config_path, optional_string(item, "source")),
            target=item_target,
            compiler_flags=optional_string(item, "compiler_flags"),
            bits=bits,
            symbol=optional_string(item, "symbol"),
            original_address=config_int(item.get("original_address"), f"{label}.original_address", required=False),
            expected_fixups=expected_fixups,
            literals=literals,
        ))
    return tuple(specs)


def find_omf_spec(
    config: dict[str, Any],
    config_path: str | Path,
    target_name: str,
    function_name: str,
) -> OmfCompareSpec:
    specs = load_omf_specs(config, config_path, target_name)
    for spec in specs:
        if function_name in (spec.function_name, spec.name):
            return spec
    raise OmfCompareError(f"OMF comparison entry not found for function: {function_name}")


def compare_omf_config_function(
    config: dict[str, Any],
    config_path: str | Path,
    target_name: str,
    function_name: str,
) -> FunctionComparison:
    return compare_omf_spec(find_omf_spec(config, config_path, target_name, function_name))


def omf_source_file(spec: OmfCompareSpec) -> str:
    if spec.source_path:
        return Path(spec.source_path).name
    return Path(spec.object_path).name


def generate_omf_similarity_report(
    config: dict[str, Any],
    config_path: str | Path,
    target: ProjectTarget,
    options: SimilarityReportOptions = SimilarityReportOptions(),
) -> SimilarityReport:
    from binary_comp.analyzers.function_compare import maybe_build

    maybe_build(target, options.build)
    rows: list[SimilarityReportRow] = []
    compared = 0
    similarity_sum = 0.0
    at_100 = 0
    above_90 = 0
    below_90 = 0
    errors = 0

    for spec in load_omf_specs(config, config_path, target.name):
        source_file = omf_source_file(spec)
        if (
            options.file_filter
            and options.file_filter not in source_file
            and options.file_filter not in spec.function_name
            and options.file_filter not in spec.name
        ):
            continue
        try:
            comparison = compare_omf_spec(spec)
        except (FileNotFoundError, OSError, RuntimeError, ValueError, OmfCompareError):
            errors += 1
            rows.append(SimilarityReportRow(source_file, spec.function_name, spec.original_offset, None, "NOT FOUND"))
            continue

        similarity = comparison.similarity
        compared += 1
        similarity_sum += similarity
        if similarity >= 99.99:
            at_100 += 1
        if similarity >= 90.0:
            above_90 += 1
        else:
            below_90 += 1
        rows.append(SimilarityReportRow(
            source_file,
            spec.function_name,
            comparison.original_addr,
            similarity,
            f"{similarity:.2f}%",
        ))

    return SimilarityReport(
        rows=tuple(rows),
        compared=compared,
        similarity_sum=similarity_sum,
        at_100=at_100,
        above_90=above_90,
        below_90=below_90,
        errors=errors,
        missing_asm=0,
        asm_fallbacks=0,
    )


def format_omf_comparison(comparison: OmfComparison, context: int = 8) -> str:
    lines = [
        f"OMF comparison for {comparison.name}",
        f"  original: {comparison.original_path}+0x{comparison.original_offset:x}",
        f"  object:   {comparison.object_path} LEDATA+0x{comparison.object_offset:x}",
        f"  size:     {comparison.compared_size} byte(s), masked fixup byte(s): {comparison.masked_count}",
    ]
    if len(comparison.original) != len(comparison.rebuilt):
        lines.append(f"  length:   MISMATCH ({len(comparison.original)} original / {len(comparison.rebuilt)} rebuilt)")
    if comparison.fixup_layout_matches is not None:
        lines.append(f"  fixups:   {'MATCH' if comparison.fixup_layout_matches else 'MISMATCH'} (reviewed layout)")
    for index, matches in enumerate(comparison.literal_matches):
        lines.append(f"  literal {index + 1}: {'MATCH' if matches else 'MISMATCH'}")
    if comparison.matches:
        lines.append("  result:   MATCH")
        return "\n".join(lines)

    mismatches = comparison.mismatches
    lines.append(f"  result:   MISMATCH ({len(mismatches)} unmasked byte difference(s))")
    for index in mismatches[:context]:
        lines.append(
            f"    +0x{index:04x}: original={comparison.original[index]:02x} rebuilt={comparison.rebuilt[index]:02x}"
        )
    if len(mismatches) > context:
        lines.append(f"    ... {len(mismatches) - context} more")
    return "\n".join(lines)
