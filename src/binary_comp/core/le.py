"""LE/LX images at preferred bases, including bound DOS/16M headers.

Page and fixup layouts follow Open Watcom's exeflat.h. Unsupported forms fail
explicitly instead of supplying incomplete audit data.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from pathlib import Path

from binary_comp.core.pe import EXECUTABLE_FLAG, READABLE_FLAG, Section


@dataclass(frozen=True)
class LEObject:
    index: int
    base: int
    size: int
    data: bytes
    flags: int = 0
    first_page: int = 0
    page_count: int = 0


def linear_header(raw: bytes) -> tuple[int, int]:
    """Return (container base, LE/LX header) by following executable headers."""
    position = 0
    visited: set[int] = set()
    while position not in visited and 0 <= position < len(raw):
        visited.add(position)
        signature = raw[position:position + 2]
        if signature in (b"LE", b"LX"):
            return position, position
        if signature == b"BW" and position + 32 <= len(raw):
            position = struct.unpack_from("<I", raw, position + 28)[0]
            continue
        if signature != b"MZ" or position + 64 > len(raw):
            break
        offset = struct.unpack_from("<I", raw, position + 60)[0]
        header = position + offset
        if offset >= 64 and raw[header:header + 2] in (b"LE", b"LX"):
            return position, header
        tail, pages = struct.unpack_from("<HH", raw, position + 2)
        position += pages * 512 - (512 - tail if tail else 0)
    raise ValueError("no LE/LX header in executable header chain")


class LEImage:
    def __init__(self, path: str, *, relocate: bool = False):
        raw = Path(path).read_bytes()
        base, header = linear_header(raw)
        if header + 0xA0 > len(raw):
            raise ValueError("truncated LE/LX header")
        if raw[header + 2:header + 4] != b"\0\0":
            raise ValueError("unsupported LE/LX byte order")
        self.path, self._raw, self._header = path, raw, header
        self.page_size = struct.unpack_from("<I", raw, header + 0x28)[0]
        if not self.page_size:
            raise ValueError("invalid LE/LX page size")
        page_count = struct.unpack_from("<I", raw, header + 0x14)[0]
        page_extra = struct.unpack_from("<I", raw, header + 0x2C)[0]
        page_data = base + struct.unpack_from("<I", raw, header + 0x80)[0]
        page_map = header + struct.unpack_from("<I", raw, header + 0x48)[0]
        table = header + struct.unpack_from("<I", raw, header + 0x40)[0]
        count = struct.unpack_from("<I", raw, header + 0x44)[0]
        if table + count * 24 > len(raw):
            raise ValueError("truncated LE/LX object table")
        self.objects: list[LEObject] = []
        self.sections: list[Section] = []
        for index in range(count):
            size, address, flags, first, pages = struct.unpack_from(
                "<IIIII", raw, table + index * 24)
            if pages and (first < 1 or first + pages - 1 > page_count):
                raise ValueError("LE/LX object pages outside page map")
            body = bytearray(size)
            initialized_end = 0
            for page in range(pages):
                logical = first - 1 + page
                if raw[header:header + 2] == b"LE":
                    entry = page_map + logical * 4
                    if entry + 4 > len(raw):
                        raise ValueError("truncated LE page map")
                    disk_page = int.from_bytes(raw[entry:entry + 3], "big")
                    kind = raw[entry + 3]
                    length = (page_extra or self.page_size) if disk_page == page_count else self.page_size
                    start = page_data + (disk_page - 1) * self.page_size
                    if kind == 0 and not 1 <= disk_page <= page_count:
                        raise ValueError("invalid LE disk page")
                else:
                    entry = page_map + logical * 8
                    if entry + 8 > len(raw) or page_extra > 31:
                        raise ValueError("invalid LX page map")
                    offset, length, kind = struct.unpack_from("<IHH", raw, entry)
                    start = page_data + (offset << page_extra)
                if kind == 3:
                    continue
                if kind != 0:
                    raise ValueError(f"unsupported LE/LX page kind {kind}")
                if length > self.page_size or start < 0 or start + length > len(raw):
                    raise ValueError("LE/LX data page outside file")
                destination = page * self.page_size
                length = min(length, max(0, size - destination))
                body[destination:destination + length] = raw[start:start + length]
                initialized_end = max(initialized_end, destination + length)
            self.objects.append(LEObject(index + 1, address, size, bytes(body), flags, first, pages))
            section_flags = (READABLE_FLAG if flags & 1 else 0) | (EXECUTABLE_FLAG if flags & 4 else 0)
            name = ".text" if flags & 4 else ".data" if flags & 2 else ".rdata"
            self.sections.append(Section(name, address, address + size, 0,
                                         initialized_end, size, section_flags))
        self.image_base = min((obj.base for obj in self.objects), default=0)
        entry_object, entry_offset = struct.unpack_from("<II", raw, header + 0x18)
        self.entry_point = (self.objects[entry_object - 1].base + entry_offset
                            if 1 <= entry_object <= count else 0)
        self._relocations: dict[int, tuple[int, int]] | None = None
        if relocate:
            bodies = {obj.index: bytearray(obj.data) for obj in self.objects}
            for site, (width, value) in self.relocations().items():
                obj = self.object_for_va(site)
                if obj is None or site + width > obj.base + obj.size:
                    raise ValueError("LE/LX fixup outside object")
                offset = site - obj.base
                bodies[obj.index][offset:offset + width] = value.to_bytes(width, "little")
            self.objects = [replace(obj, data=bytes(bodies[obj.index])) for obj in self.objects]

    def object_for_va(self, address: int) -> LEObject | None:
        return next((obj for obj in self.objects if obj.base <= address < obj.base + obj.size), None)

    def section_for_va(self, address: int) -> Section | None:
        return next((s for s in self.sections if s.start <= address < s.end), None)

    def section_named(self, name: str) -> Section | None:
        return next((s for s in self.sections if s.name.lower() == name.lower()), None)

    def read(self, address: int, size: int) -> bytes | None:
        if size < 0:
            return None
        result = bytearray()
        while size:
            obj = self.object_for_va(address)
            if obj is None:
                return None
            offset = address - obj.base
            length = min(size, obj.size - offset)
            result.extend(obj.data[offset:offset + length])
            address, size = address + length, size - length
        return bytes(result)

    def section_end_for_va(self, address: int) -> int | None:
        obj = self.object_for_va(address)
        return None if obj is None else obj.base + obj.size

    def maps(self, address: int) -> bool:
        return self.object_for_va(address) is not None

    def c_string_at(self, address: int, predicate=None, limit: int = 512) -> str | None:
        obj = self.object_for_va(address)
        if obj is None:
            return None
        offset = address - obj.base
        end = obj.data.find(b"\0", offset, offset + limit)
        if end < 0:
            return None
        value = obj.data[offset:end].decode("latin-1")
        return value if value and (predicate is None or predicate(value)) else None

    def segment_bases(self) -> dict[int, int]:
        return {obj.index: obj.base for obj in self.objects}

    def relocated_sites(self) -> frozenset[int]:
        return frozenset(self.relocations())

    def relocations(self) -> dict[int, tuple[int, int]]:
        """Internal 32-bit offset/self-relative loader writes at preferred bases."""
        if self._relocations is not None:
            return self._relocations
        raw, header = self._raw, self._header
        page_offset, record_offset = struct.unpack_from("<II", raw, header + 0x68)
        result: dict[int, tuple[int, int]] = {}
        if not page_offset and not record_offset:
            self._relocations = result
            return result
        pages = struct.unpack_from("<I", raw, header + 0x14)[0]
        page_table, record_table = header + page_offset, header + record_offset
        if not page_offset or not record_offset or page_table + (pages + 1) * 4 > len(raw):
            raise ValueError("invalid LE/LX fixup page table")
        for obj in self.objects:
            for page in range(obj.page_count):
                logical = obj.first_page - 1 + page
                start, end = struct.unpack_from("<II", raw, page_table + logical * 4)
                cursor, end = record_table + start, record_table + end
                if cursor > end or end > len(raw):
                    raise ValueError("invalid LE/LX fixup record range")
                def take(width: int, signed: bool = False) -> int:
                    nonlocal cursor
                    if cursor + width > end:
                        raise ValueError("truncated LE/LX fixup record")
                    value = int.from_bytes(raw[cursor:cursor + width], "little", signed=signed)
                    cursor += width
                    return value
                while cursor < end:
                    source, flags = take(1), take(1)
                    if source not in (7, 8, 0x27, 0x28) or flags & ~0x54:
                        raise ValueError(f"unsupported LE/LX fixup {source:#x}/{flags:#x}")
                    repeats = take(1) if source & 0x20 else 0
                    offsets = [] if source & 0x20 else [take(2, signed=True)]
                    target_object = take(2 if flags & 0x40 else 1)
                    target_offset = take(4 if flags & 0x10 else 2)
                    additive = take(2) if flags & 4 else 0
                    if not 1 <= target_object <= len(self.objects):
                        raise ValueError("LE/LX fixup target object out of range")
                    if source & 0x20:
                        offsets = [take(2, signed=True) for _ in range(repeats)]
                    target = self.objects[target_object - 1]
                    if target_offset > target.size:
                        raise ValueError("LE/LX fixup target offset out of range")
                    for offset in offsets:
                        site = obj.base + page * self.page_size + offset
                        value = target.base + target_offset + additive
                        if source & 0x0F == 8:
                            value -= site + 4
                        write = (4, value & 0xFFFFFFFF)
                        if site in result and result[site] != write:
                            raise ValueError("conflicting LE/LX fixups")
                        result[site] = write
        self._relocations = result
        return result
