from __future__ import annotations

import copy
import pickle

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


def test_cached_affine_coefficients_are_not_shared_with_the_caller():
    instrs = sample_function()
    stream = InstructionStream(instrs)
    # The lea leaves ecx = edx*2 + 12; edit its coefficient dict in place.
    before = affine_registers_at(stream, 5)
    before["ecx"][0]["poison"] = 1

    for idx in (5, 6, len(instrs)):
        assert affine_registers_at(stream, idx) == affine_registers_at(instrs, idx)


def test_modifying_the_stream_rebuilds_its_indexes():
    instrs = sample_function()
    stream = InstructionStream(instrs)
    assert instruction_positions(stream)[0x401000] == 0
    affine_registers_at(stream, len(stream))

    extra = instruction(0x400FFC, "mov", [reg("eax"), imm(1)])
    stream.insert(0, extra)
    expected = [extra, *instrs]

    assert instruction_positions(stream) == instruction_positions(expected)
    assert affine_registers_at(stream, 1) == affine_registers_at(expected, 1)

    stream += [instruction(0x401040, "jne", [imm(0x401040)])]
    assert 0x401040 in direct_branch_targets(stream)
    assert isinstance(stream, InstructionStream)

    del stream[0]
    stream[0:1] = []
    assert instruction_positions(stream) == instruction_positions(list(stream))


def test_copies_do_not_share_cached_indexes():
    stream = InstructionStream(sample_function())
    positions = instruction_positions(stream)

    for clone in (copy.copy(stream), stream.copy(), copy.deepcopy(stream),
                  pickle.loads(pickle.dumps(stream))):
        assert isinstance(clone, InstructionStream)
        assert clone == stream
        clone.append(instruction(0x402000, "nop"))
        assert instruction_positions(clone)[0x402000] == len(clone) - 1
        assert instruction_positions(clone) is not positions

    assert 0x402000 not in instruction_positions(stream)


def test_stream_indexes_match_plain_list():
    instrs = sample_function()
    stream = InstructionStream(instrs)

    assert instruction_positions(stream) == instruction_positions(instrs)
    assert direct_branch_targets(stream) == direct_branch_targets(instrs) == {0x401030, 0x401004}
    assert stream == instrs
