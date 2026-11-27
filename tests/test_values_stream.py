from __future__ import annotations

from binary_comp.analyzers.values.dataflow import affine_registers_at
from binary_comp.analyzers.values.stream import (
    InstructionStream,
    direct_branch_targets,
    instruction_positions,
)
from binary_comp.core.disasm import Instruction, Operand


def instruction(address, mnemonic, operands=()):
    raw_operands = ", ".join(operand.text for operand in operands)
    return Instruction(address, mnemonic, raw_operands, tuple(operands), f"{mnemonic} {raw_operands}".rstrip())


def reg(name):
    return Operand("reg", name, reg=name)


def imm(value):
    return Operand("imm", hex(value), imm=value, size=4)


def mem(base, disp=0, index=None, scale=1):
    return Operand("mem", f"[{base}+{disp}]", base=base, index=index, scale=scale, disp=disp, size=4)


def sample_function():
    ops = [
        ("push", [reg("ebp")]),
        ("mov", [reg("ebp"), reg("esp")]),
        ("mov", [reg("eax"), imm(8)]),
        ("lea", [reg("ecx"), mem("eax", 4, index="edx", scale=2)]),
        ("mov", [mem("esp", 4), reg("ecx")]),
        ("add", [reg("esp"), imm(0x10)]),
        ("mov", [reg("esi"), mem("esp", -12)]),
        ("shl", [reg("esi"), imm(2)]),
        ("je", [imm(0x401030)]),
        ("sub", [reg("esi"), reg("eax")]),
        ("inc", [reg("edi")]),
        ("call", [imm(0x402000)]),
        ("xor", [reg("ebx"), reg("ebx")]),
        ("jmp", [imm(0x401004)]),
        ("leave", []),
        ("ret", []),
    ]
    return [instruction(0x401000 + 4 * pos, mnemonic, operands) for pos, (mnemonic, operands) in enumerate(ops)]


def test_cached_affine_states_match_a_fresh_replay_in_any_query_order():
    instrs = sample_function()
    stream = InstructionStream(instrs)
    order = list(range(len(instrs) + 1))
    order = order[::3] + order[::-1]

    for idx in order:
        assert affine_registers_at(stream, idx) == affine_registers_at(instrs, idx)


def test_cached_affine_state_is_not_shared_with_the_caller():
    stream = InstructionStream(sample_function())
    first = affine_registers_at(stream, 4)
    first["eax"] = ({}, 999)

    assert affine_registers_at(stream, 4)["eax"] == ({}, 8)


def test_stream_indexes_match_plain_list():
    instrs = sample_function()
    stream = InstructionStream(instrs)

    assert instruction_positions(stream) == instruction_positions(instrs)
    assert direct_branch_targets(stream) == direct_branch_targets(instrs) == {0x401030, 0x401004}
    assert stream == instrs
