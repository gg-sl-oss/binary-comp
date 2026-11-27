from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.values.disassembly import (
    disassemble as disassemble_values,
    leading_successor_switch_table_start,
)
from binary_comp.policy import load_policy
from binary_comp.core.disasm import (
    Instruction,
    Operand,
    disassemble_reachable_x86,
    disassemble_x86,
    has_msvc_seh_frame,
    switch_jump_table_ranges,
    trim_leading_stack_probe,
)
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


pytest.importorskip("capstone")


def _instruction(address, mnemonic, operands=()):
    return Instruction(address, mnemonic, "", tuple(operands), mnemonic, 1)


def _register(name):
    return Operand("reg", name, reg=name)


def _immediate(value):
    return Operand("imm", str(value), imm=value)


def test_trim_leading_stack_probe_excludes_watcom_compiler_prefix():
    instructions = [
        _instruction(0x1000, "push", (_immediate(0x28),)),
        _instruction(0x1005, "call", (_immediate(0x9000),)),
        _instruction(0x100A, "push", (_register("ebx"),)),
        _instruction(0x100B, "push", (_register("ecx"),)),
        _instruction(0x100C, "push", (_register("edx"),)),
        _instruction(0x100D, "push", (_register("ebp"),)),
        _instruction(0x100E, "mov", (_register("ebp"), _register("esp"))),
    ]

    assert trim_leading_stack_probe(instructions) == instructions[2:]


def test_trim_leading_stack_probe_preserves_source_level_call():
    instructions = [
        _instruction(0x1000, "push", (_immediate(0x28),)),
        _instruction(0x1005, "call", (_immediate(0x9000),)),
        _instruction(0x100A, "test", (_register("eax"), _register("eax"))),
        _instruction(0x100C, "ret"),
        _instruction(0x100D, "nop"),
        _instruction(0x100E, "nop"),
    ]

    assert trim_leading_stack_probe(instructions) == instructions


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


def test_disassemble_resyncs_after_an_inline_jump_table(tmp_path):
    """A switch table sitting between the dispatch and the case bodies must not
    drag the decoder off the instruction boundaries of the code that follows it.

    The four table entries here decode into instructions that straddle the end of
    the table, so a sweep that runs straight through the table lands mid-opcode
    and never recovers the case bodies.
    """
    table = TEXT_VA + 0x0c
    body = TEXT_VA + 0x1c

    code = bytearray()
    code.extend(b"\x83\xf8\x03")                                # cmp eax, 3
    code.extend(b"\x77\x14")                                    # ja default
    code.extend(b"\xff\x24\x85" + struct.pack("<I", table))     # jmp [eax*4 + table]
    assert len(code) == 0x0c
    code.extend(struct.pack("<IIII", body, body, body, body))   # the table
    assert len(code) == 0x1c
    code.extend(b"\x40\x40\xc3")                                # case body
    code.extend(b"\x33\xc0\xc3")                                # default

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))

    instrs = disassemble_x86(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x40],
        max_bytes=0x40,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )
    addresses = {instr.address for instr in instrs}

    # The table is data, so none of it may show up as instructions ...
    assert addresses.isdisjoint(range(table, body))
    # ... and every instruction after it must land on a real boundary.
    assert {body, body + 1, body + 2, body + 3, body + 5} <= addresses


def test_values_boundary_excludes_successor_owned_leading_switch_table(tmp_path):
    table = TEXT_VA + 0x08
    successor = TEXT_VA + 0x10
    # One case is a shared tail outside the successor's symbol range.  The
    # compare still proves the table has two executable targets.
    case_zero = TEXT_VA + 0x50
    case_one = TEXT_VA + 0x21

    code = bytearray(b"\x53\xc3")                              # push ebx; ret
    code = code.ljust(0x08, b"\x90")
    code.extend(struct.pack("<II", case_zero, case_one))         # successor's table
    code.extend(b"\x83\xf8\x01")                              # cmp eax, 1
    code.extend(b"\x77\x09")                                  # ja case_one
    code.extend(b"\xff\x24\x85" + struct.pack("<I", table))  # jmp [eax*4 + table]
    code = code.ljust(0x20, b"\x90")
    code.extend(b"\xc3\xc3")                                  # case bodies

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))
    image = PEImage(str(exe))
    boundaries = {TEXT_VA, successor, TEXT_VA + 0x30}
    policy = load_policy()

    assert leading_successor_switch_table_start(
        image,
        TEXT_VA,
        boundaries,
        policy,
    ) == table

    instrs = disassemble_values(image, TEXT_VA, sorted(boundaries), policy)
    assert [instr.address for instr in instrs] == [TEXT_VA, TEXT_VA + 1]


def test_switch_table_accepts_segment_relative_cs_offsets():
    segment_base = 0x10000
    func_start = 0x12000
    func_end = 0x12200
    table_start = 0x12100

    class Segment:
        base = segment_base

    class SegmentedImage:
        table = struct.pack("<II", 0x2050, 0x2060)

        def object_for_va(self, address):
            return Segment() if segment_base <= address < 0x20000 else None

        def read(self, address, size):
            offset = address - table_start
            if offset < 0 or offset >= len(self.table):
                return b"\0" * size
            return self.table[offset:offset + size]

    dispatch = Instruction(
        address=func_start,
        mnemonic="jmp",
        op_str="dword ptr cs:[eax*4 + 0x2100]",
        operands=(Operand("mem", "", index="eax", scale=4, disp=0x2100),),
        raw="jmp dword ptr cs:[eax*4 + 0x2100]",
    )

    assert switch_jump_table_ranges(
        SegmentedImage(),
        [dispatch],
        func_start,
        func_end,
    ) == ((table_start, table_start + 8),)


def test_switch_table_accepts_segment_relative_shifted_base():
    segment_base = 0x10000
    func_start = 0x12000
    func_end = 0x12200
    table_start = 0x12100

    class Segment:
        base = segment_base

    class SegmentedImage:
        table = struct.pack("<II", 0x2050, 0x2060)

        def object_for_va(self, address):
            return Segment() if segment_base <= address < 0x20000 else None

        def read(self, address, size):
            offset = address - table_start
            if offset < 0 or offset >= len(self.table):
                return b"\0" * size
            return self.table[offset:offset + size]

    shift = Instruction(
        address=func_start,
        mnemonic="shl",
        op_str="eax, 2",
        operands=(Operand("reg", "eax", reg="eax"), Operand("imm", "2", imm=2)),
        raw="shl eax, 2",
    )
    dispatch = Instruction(
        address=func_start + 3,
        mnemonic="jmp",
        op_str="dword ptr cs:[eax + 0x2100]",
        operands=(Operand("mem", "", base="eax", scale=1, disp=0x2100),),
        raw="jmp dword ptr cs:[eax + 0x2100]",
    )

    assert switch_jump_table_ranges(
        SegmentedImage(),
        [shift, dispatch],
        func_start,
        func_end,
    ) == ((table_start, table_start + 8),)


def test_reachable_disassembly_follows_shifted_base_jump_table(tmp_path):
    """Recognize the `shl reg, 2; jmp [reg + table]` switch form."""
    table = TEXT_VA + 0x10
    case_zero = TEXT_VA + 0x18
    case_one = TEXT_VA + 0x1a
    default = TEXT_VA + 0x1c

    code = bytearray()
    code.extend(b"\x83\xf8\x01")                         # cmp eax, 1
    code.extend(b"\x77\x17")                             # ja default
    code.extend(b"\xc1\xe0\x02")                         # shl eax, 2
    code.extend(b"\xff\xa0" + struct.pack("<I", table))  # jmp [eax + table]
    code = code.ljust(0x10, b"\x90")
    code.extend(struct.pack("<II", case_zero, case_one))
    code.extend(b"\x40\xc3")                             # case 0
    code.extend(b"\x48\xc3")                             # case 1
    code.extend(b"\x33\xc0\xc3")                         # default

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))

    instrs = disassemble_reachable_x86(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x40],
        max_bytes=0x40,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )
    addresses = {instr.address for instr in instrs}

    assert addresses.isdisjoint(range(table, case_zero))
    assert {case_zero, case_zero + 1, case_one, case_one + 1, default, default + 2} <= addresses


def test_read_jump_table_stops_at_range_table_end_and_entry_limit():
    from binary_comp.core.disasm import read_jump_table

    class Image:
        def __init__(self, base, data):
            self.base, self.data = base, data

        def read(self, address, size):
            offset = address - self.base
            chunk = self.data[offset:offset + size]
            return chunk if offset >= 0 and len(chunk) == size else None

    entries = [0x401000, 0x401010, 0x401020, 0x999999]
    image = Image(0x401100, b"".join(struct.pack("<I", entry) for entry in entries))

    assert read_jump_table(image, 0x401100, 0x401000, 0x401100) == entries[:3]
    assert read_jump_table(image, 0x401100, 0x401000, 0x401100, table_end=0x401108) == entries[:2]
    assert read_jump_table(image, 0x401100, 0x401000, 0x401100, max_entries=1) == entries[:1]
    assert read_jump_table(image, 0x401200, 0x401000, 0x401100) == []


def _seh_prologue(*, write: bool) -> list[Instruction]:
    def ins(address, mnemonic, op_str, operands=()):
        return Instruction(address, mnemonic, op_str, tuple(operands), f"{mnemonic} {op_str}", 1)

    prologue = [
        ins(0, "push", "ebp"),
        ins(1, "mov", "ebp, esp"),
        ins(2, "push", "-1", [Operand("imm", "-1", imm=-1)]),
        ins(3, "push", "0x401000"),
        ins(4, "mov", "eax, dword ptr fs:[0]"),
        ins(5, "push", "eax"),
    ]
    if write:
        prologue.append(ins(6, "mov", "dword ptr fs:[0], esp"))
    prologue.append(ins(7, "ret", ""))
    return prologue


def test_msvc_seh_frame_needs_both_the_fs_read_and_the_fs_write():
    assert has_msvc_seh_frame(_seh_prologue(write=True))
    # Reading fs:[0] alone used to count as the write as well.
    assert not has_msvc_seh_frame(_seh_prologue(write=False))


def test_msvc_seh_frame_read_can_push_fs_directly():
    def ins(address, mnemonic, op_str, operands=()):
        return Instruction(address, mnemonic, op_str, tuple(operands), f"{mnemonic} {op_str}", 1)

    prologue = [
        ins(0, "push", "ebp"),
        ins(1, "mov", "ebp, esp"),
        ins(2, "push", "-1", [Operand("imm", "-1", imm=-1)]),
        ins(3, "push", "0x401000"),
        ins(4, "push", "dword ptr fs:[0]"),
    ]
    ret = ins(6, "ret", "")

    assert has_msvc_seh_frame(prologue + [ins(5, "mov", "dword ptr fs:[0], esp"), ret])
    # Still no frame without the write that installs it.
    assert not has_msvc_seh_frame(prologue + [ret])
