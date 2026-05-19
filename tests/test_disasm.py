from __future__ import annotations

import struct

import pytest

from binary_comp.core.disasm import disassemble_x86
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


pytest.importorskip("capstone")


def test_disassemble_removes_msvc_byte_switch_map(tmp_path):
    code = bytearray()
    code.extend(b"\x83\xf8\x03")  # cmp eax, 3
    code.extend(b"\x77\x08")      # ja default
    code.extend(b"\x33\xd2")      # xor edx, edx
    code.extend(b"\x8a\x90" + struct.pack("<I", TEXT_VA + 0x20))
    code.extend(b"\xff\x24\x95" + struct.pack("<I", TEXT_VA + 0x28))
    code.extend(b"\xc3")
    code = code.ljust(0x20, b"\x90")
    code.extend(b"\x00\x01\x02\x03")
    code = code.ljust(0x28, b"\x90")
    code.extend(struct.pack("<IIII", TEXT_VA, TEXT_VA + 2, TEXT_VA + 4, TEXT_VA + 6))

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))

    instrs = disassemble_x86(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x40],
        max_bytes=0x40,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )

    assert {instr.address for instr in instrs}.isdisjoint(range(TEXT_VA + 0x20, TEXT_VA + 0x38))
