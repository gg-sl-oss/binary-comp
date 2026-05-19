from __future__ import annotations

from binary_comp.analyzers.values import following_call_signature
from binary_comp.core.disasm import Instruction, Operand


def test_following_call_signature_follows_tail_merge_jump():
    instrs = [
        Instruction(0x1000, "push", "0", (Operand("imm", "0", imm=0),), "push 0"),
        Instruction(0x1002, "push", "1", (Operand("imm", "1", imm=1),), "push 1"),
        Instruction(0x1004, "jmp", "0x1010", (Operand("imm", "0x1010", imm=0x1010),), "jmp 0x1010"),
        Instruction(0x1010, "push", "edx", (Operand("reg", "edx", reg="edx"),), "push edx"),
        Instruction(
            0x1011,
            "call",
            "dword ptr [eax + 0xac]",
            (Operand("mem", "", base="eax", disp=0xAC, size=4),),
            "call dword ptr [eax + 0xac]",
        ),
    ]

    assert following_call_signature(instrs, 0) == ("mem", "", 0, 0xAC)
