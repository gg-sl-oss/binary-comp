"""Linear Executable (LE/LX) images, as produced by DOS extenders.

The analyzers only ask an image for bytes at a virtual address, where the
containing object ends, and whether an address holds a C string, so an LE
object table is enough to stand in for a PE section table.  The fixup tables
are exposed as well: an immediate the loader relocates is an unresolved
address, not a constant, and a value checker has to be able to tell them apart.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class LEObject:
    index: int
    base: int
    size: int
    data: bytes


class LEImage:
    def __init__(self, path: str):
        raw = open(path, "rb").read()
        header = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[header:header + 2] not in (b"LE", b"LX"):
            raise ValueError(f"not a linear executable: {path}")

        page_size = struct.unpack_from("<I", raw, header + 0x28)[0]
        page_data = struct.unpack_from("<I", raw, header + 0x80)[0]
        table = header + struct.unpack_from("<I", raw, header + 0x40)[0]
        count = struct.unpack_from("<I", raw, header + 0x44)[0]

        self.path = path
        self.page_size = page_size
        self.objects: list[LEObject] = []
        for index in range(count):
            size, base, _flags, first, pages = struct.unpack_from(
                "<IIIII", raw, table + index * 24)
            body = bytearray()
            for page in range(pages):
                start = page_data + (first + page - 1) * page_size
                body += raw[start:start + page_size]
            self.objects.append(LEObject(index + 1, base, size, bytes(body[:size])))
        self._raw = raw
        self._header = header

    def object_for_va(self, address: int) -> LEObject | None:
        for obj in self.objects:
            if obj.base <= address < obj.base + obj.size:
                return obj
        return None

    def read(self, address: int, size: int) -> bytes:
        obj = self.object_for_va(address)
        if obj is None:
            return b""
        offset = address - obj.base
        return obj.data[offset:offset + size]

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
        end = obj.data.find(b"\x00", offset, offset + limit)
        if end < 0:
            return None
        try:
            value = obj.data[offset:end].decode("latin-1")
        except UnicodeDecodeError:
            return None
        if not value:
            return None
        if predicate is not None and not predicate(value):
            return None
        return value

    def segment_bases(self) -> dict[int, int]:
        """Map file segment numbers, as a linker map writes them, to bases."""
        return {obj.index: obj.base for obj in self.objects}

    def relocated_sites(self) -> frozenset[int]:
        """Addresses the loader patches.  A value checker must skip immediates
        that land on one of these: the bytes are a link-time placeholder."""
        raw, header = self._raw, self._header
        pages = struct.unpack_from("<I", raw, header + 0x14)[0]
        page_table = header + struct.unpack_from("<I", raw, header + 0x68)[0]
        record_table = header + struct.unpack_from("<I", raw, header + 0x6C)[0]
        out: set[int] = set()
        for page in range(pages):
            cursor = record_table + struct.unpack_from("<I", raw, page_table + page * 4)[0]
            end = record_table + struct.unpack_from("<I", raw, page_table + (page + 1) * 4)[0]
            while cursor < end:
                source, flags = raw[cursor], raw[cursor + 1]
                cursor += 2
                offsets = []
                if source & 0x20:
                    repeats = raw[cursor]
                    cursor += 1
                    for _ in range(repeats):
                        offsets.append(struct.unpack_from("<h", raw, cursor)[0])
                        cursor += 2
                else:
                    offsets.append(struct.unpack_from("<h", raw, cursor)[0])
                    cursor += 2
                kind = flags & 3
                cursor += 2 if flags & 0x40 else 1
                if kind == 0:
                    if (source & 0x0F) != 2:
                        cursor += 4 if flags & 0x10 else 2
                elif kind in (1, 2):
                    cursor += 4 if (kind == 2 or flags & 0x10) else 2
                else:
                    cursor += 2
                for obj in self.objects:
                    first = self._first_page(obj)
                    if first is None:
                        continue
                    span = -(-obj.size // self.page_size)
                    if first - 1 <= page < first - 1 + span:
                        origin = obj.base + (page - (first - 1)) * self.page_size
                        out.update(origin + offset for offset in offsets)
                        break
        return frozenset(out)

    def _first_page(self, obj: LEObject) -> int | None:
        table = self._header + struct.unpack_from("<I", self._raw, self._header + 0x40)[0]
        _size, _base, _flags, first, pages = struct.unpack_from(
            "<IIIII", self._raw, table + (obj.index - 1) * 24)
        return first if pages else None
