"""Executable image selection for data and global audits."""
import struct
from pathlib import Path

from binary_comp.core.le import LEImage
from binary_comp.core.pe import PEImage


def load_image(path: str, *, relocate: bool = False) -> PEImage | LEImage:
    raw = Path(path).read_bytes()
    if len(raw) >= 64 and raw[:2] == b"MZ":
        header = struct.unpack_from("<I", raw, 60)[0]
        if raw[header:header + 4] == b"PE\0\0":
            return PEImage(path)
    return LEImage(path, relocate=relocate)
