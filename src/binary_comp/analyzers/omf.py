"""Small OMF/16-bit DOS object comparison helpers.

This is intentionally narrow: it reads Borland-style OMF LEDATA records and
uses FIXUPP locations to mask relocated operands before comparing against a raw
original byte window. It is meant for DOS reconstruction projects where the
compiler output is an OMF object and the reference is an overlay/code image.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from binary_comp.analyzers.function_compare import (
    DisassemblyResult,
    FunctionComparison,
    instruction_mnemonics,
    mnemonic_similarity,
)
from binary_comp.analyzers.report import SimilarityReport, SimilarityReportOptions, SimilarityReportRow
from binary_comp.config import ProjectTarget
from binary_comp.core.disasm import disassemble_raw_16


OMF_LEDATA = 0xA0
OMF_FIXUPP = 0x9C


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

    @property
    def compared_size(self) -> int:
        return len(self.rebuilt)

    @property
    def masked_count(self) -> int:
        return sum(1 for value in self.mask if value == 0)

    @property
    def mismatches(self) -> tuple[int, ...]:
        return tuple(
            index
            for index, (left, right, mask) in enumerate(zip(self.original, self.rebuilt, self.mask))
            if mask and left != right
        )

    @property
    def matches(self) -> bool:
        return not self.mismatches


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


def parse_ledata(content: bytes) -> LedataRecord:
    segment_index, cursor = read_index(content, 0)
    if cursor + 2 > len(content):
        raise OmfCompareError("truncated LEDATA offset")
    offset = int.from_bytes(content[cursor:cursor + 2], "little")
    return LedataRecord(segment_index=segment_index, offset=offset, data=content[cursor + 2:])


def fixup_length(location_type: int) -> int:
    # Intel OMF location kinds used by BCC/TASM here:
    #   1 = 16-bit offset
    #   2 = 16-bit base
    #   3 = 32-bit far pointer
    # The 8-bit kinds are included for completeness.
    return {
        0: 1,
        1: 2,
        2: 2,
        3: 4,
        4: 1,
    }.get(location_type, 0)


def parse_fixupp(content: bytes) -> tuple[OmfFixup, ...]:
    fixups: list[OmfFixup] = []
    cursor = 0
    while cursor < len(content):
        first = content[cursor]
        if not (first & 0x80):
            # Thread subrecord. For comparison masking, only explicit fixup
            # location subrecords matter. Skip two-byte thread forms if present.
            cursor += 2 if (first & 0x40) else 1
            continue
        if cursor + 1 >= len(content):
            raise OmfCompareError("truncated FIXUPP location")
        locat = ((first & 0x3F) << 8) | content[cursor + 1]
        data_offset = locat & 0x03FF
        location_type = (locat >> 10) & 0x0F
        length = fixup_length(location_type)
        if length:
            fixups.append(OmfFixup(data_offset, length, location_type))
        cursor += 2
        while cursor < len(content) and not (content[cursor] & 0x80):
            cursor += 1
    return tuple(fixups)


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
    mask = bytearray([0xFF] * size)
    for fixup in fixups:
        start = fixup.offset - object_offset
        end = start + fixup.length
        if end <= 0 or start >= size:
            continue
        for index in range(max(0, start), min(size, end)):
            mask[index] = 0
    return bytes(mask)


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
) -> OmfComparison:
    ledata_records, fixups = load_omf_object(object_path)
    ledata = select_ledata(ledata_records, segment_index=segment_index, ledata_index=ledata_index)
    if object_offset < 0 or object_offset > len(ledata.data):
        raise OmfCompareError("object_offset outside LEDATA")
    rebuilt = ledata.data[object_offset:]
    if size is not None:
        if size < 0:
            raise OmfCompareError("size must be non-negative")
        rebuilt = rebuilt[:size]
    original_data = Path(original_path).read_bytes()
    if original_offset < 0 or original_offset + len(rebuilt) > len(original_data):
        raise OmfCompareError("original byte window outside file")
    original = original_data[original_offset:original_offset + len(rebuilt)]
    mask = build_mask(len(rebuilt), fixups, object_offset=object_offset)
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
    )


def compare_omf_spec(spec: OmfCompareSpec) -> FunctionComparison:
    byte_comparison = compare_omf_to_original(
        original_path=spec.original_path,
        original_offset=spec.original_offset,
        object_path=spec.object_path,
        size=spec.size,
        object_offset=spec.object_offset,
        segment_index=spec.segment_index,
        ledata_index=spec.ledata_index,
        name=spec.name,
    )
    original = DisassemblyResult(
        disassemble_raw_16(byte_comparison.original, byte_comparison.original_offset),
        [],
    )
    rebuilt = DisassemblyResult(
        disassemble_raw_16(byte_comparison.rebuilt, byte_comparison.object_offset),
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
        original_addr=spec.original_offset,
        rebuilt_addr=spec.object_offset,
        similarity=similarity,
        rebuilt=rebuilt,
        original=original,
    )


def parse_config_int(value: Any, label: str, *, required: bool = True) -> int | None:
    if value in (None, ""):
        if required:
            raise OmfCompareError(f"missing required configuration value: {label}")
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise OmfCompareError(f"{label} must be an integer or integer string")


def require_config_string(config: dict[str, Any], key: str, label: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise OmfCompareError(f"missing required configuration value: {label}")
    return value


def optional_config_string(config: dict[str, Any], key: str) -> str | None:
    value = config.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise OmfCompareError(f"{key} must be a string")
    return value


def resolve_config_path(config_path: str | Path, path: str | None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        return str(candidate)
    return str(Path(config_path).resolve().parent / candidate)


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
        item_target = optional_config_string(item, "target")
        if target_name is not None and item_target not in (None, target_name):
            continue
        name = require_config_string(item, "name", f"{label}.name")
        original = require_config_string(item, "original", f"{label}.original")
        object_path = require_config_string(item, "object", f"{label}.object")
        function_name = optional_config_string(item, "function") or name
        specs.append(OmfCompareSpec(
            name=name,
            function_name=function_name,
            original_path=resolve_config_path(config_path, original) or "",
            original_offset=parse_config_int(item.get("original_offset"), f"{label}.original_offset") or 0,
            object_path=resolve_config_path(config_path, object_path) or "",
            size=parse_config_int(item.get("size"), f"{label}.size", required=False),
            object_offset=parse_config_int(item.get("object_offset", 0), f"{label}.object_offset") or 0,
            segment_index=parse_config_int(item.get("segment_index"), f"{label}.segment_index", required=False),
            ledata_index=parse_config_int(item.get("ledata_index", 0), f"{label}.ledata_index") or 0,
            source_path=resolve_config_path(config_path, optional_config_string(item, "source")),
            target=item_target,
            compiler_flags=optional_config_string(item, "compiler_flags"),
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
            spec.original_offset,
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
