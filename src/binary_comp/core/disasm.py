"""Capstone-backed instruction decoding helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from .pe import PEImage

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:  # pragma: no cover - exercised by users without optional extra
    Cs = None
    CS_ARCH_X86 = CS_MODE_32 = X86_OP_IMM = X86_OP_MEM = X86_OP_REG = None


@dataclass(frozen=True)
class Operand:
    kind: str
    text: str
    reg: str = ""
    imm: int = 0
    base: str = ""
    index: str = ""
    scale: int = 0
    disp: int = 0
    size: int = 0


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    operands: tuple[Operand, ...]
    raw: str
    size: int = 0
    # Where the encoded displacement and immediate start within the
    # instruction, so a caller can tell which field a relocation patches.
    disp_offset: int = 0
    imm_offset: int = 0


def require_capstone() -> None:
    if Cs is None:
        raise RuntimeError("capstone is required. Install with: python3 -m pip install binary-comp[capstone]")


def require_capstone_16():
    """Return a 16-bit real-mode Capstone constructor tuple.

    Kept separate from the 32-bit path so DOS reconstruction helpers can decode
    raw code images without a PE image wrapper.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_16, Cs as Cs16
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError(
            "capstone is required. Install with: python3 -m pip install binary-comp[capstone]"
        ) from exc
    return Cs16, CS_ARCH_X86, CS_MODE_16


def disassemble_raw_16(data: bytes, start: int = 0) -> list[Instruction]:
    """Disassemble a raw 16-bit code window starting at ``start``."""
    return disassemble_raw(data, start, bits=16)


def disassemble_raw(data: bytes, start: int = 0, *, bits: int = 32) -> list[Instruction]:
    """Disassemble a raw 16/32-bit code window without an executable wrapper.

    The address only labels instructions for display and similarity output; it
    does not have to be a real load address.
    """
    Cs16, CS_ARCH_X86, CS_MODE_16 = require_capstone_16()
    if bits not in (16, 32):
        raise ValueError("bits must be 16 or 32")
    md = Cs16(CS_ARCH_X86, CS_MODE_16 if bits == 16 else CS_MODE_32)
    instructions: list[Instruction] = []
    for insn in md.disasm(data, start):
        mnemonic = normalize_mnemonic(insn.mnemonic)
        instructions.append(Instruction(
            address=insn.address,
            mnemonic=mnemonic,
            op_str=insn.op_str,
            operands=(),
            raw=f"{insn.mnemonic} {insn.op_str}".strip(),
            size=insn.size,
        ))
    return instructions


def signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def unsigned32(value: int) -> int:
    return value & 0xFFFFFFFF


def normalize_mnemonic(mnemonic: str) -> str:
    aliases = {
        "je": "jz",
        "jne": "jnz",
        "jb": "jc",
        "jnae": "jc",
        "jae": "jnc",
        "jnb": "jnc",
        "jg": "jnle",
        "jnle": "jnle",
        "jge": "jnl",
        "jnl": "jnl",
        "jl": "jnge",
        "jnge": "jnge",
        "jle": "jng",
        "jng": "jng",
    }
    return aliases.get(mnemonic.lower(), mnemonic.lower())


def is_branch_or_call(mnemonic: str) -> bool:
    return mnemonic.startswith("j") or mnemonic in {"call", "loop", "loope", "loopne", "jecxz"}


def trim_leading_stack_probe(instructions: list[Instruction]) -> list[Instruction]:
    """Exclude a compiler-emitted Watcom stack-check prefix.

    Watcom places ``push <frame size>; call __STK`` before the saved-register
    prologue and publishes the symbol at the prefix.  Recovered function
    boundaries commonly start at the developer body instead.  The run of
    saved-register pushes followed by ``mov ebp, esp`` makes this conservative
    enough not to discard an ordinary source-level call with one argument.
    """
    if len(instructions) < 6:
        return instructions
    frame_size, probe = instructions[:2]
    if (
        frame_size.mnemonic != "push"
        or len(frame_size.operands) != 1
        or frame_size.operands[0].kind != "imm"
        or not (0 < frame_size.operands[0].imm <= 0x1000000)
        or probe.mnemonic != "call"
        or len(probe.operands) != 1
        or probe.operands[0].kind != "imm"
    ):
        return instructions

    saved_pushes = 0
    for instruction in instructions[2:10]:
        if (
            instruction.mnemonic == "push"
            and len(instruction.operands) == 1
            and instruction.operands[0].kind == "reg"
        ):
            saved_pushes += 1
            continue
        if (
            saved_pushes >= 3
            and instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].kind == "reg"
            and instruction.operands[1].kind == "reg"
            and full_register_name(instruction.operands[0].reg) == "ebp"
            and full_register_name(instruction.operands[1].reg) == "esp"
        ):
            return instructions[2:]
        break
    return instructions


def next_boundary(starts: Iterable[int], start: int) -> int | None:
    for candidate in starts:
        if candidate > start:
            return candidate
    return None


def function_bytes(image: PEImage, start: int, starts: Iterable[int], max_bytes: int) -> tuple[bytes | None, int | None]:
    section_end = image.section_end_for_va(start)
    if section_end is None:
        return None, None
    end = next_boundary(starts, start)
    if end is None or end > section_end:
        end = section_end
    if end <= start:
        return None, None
    size = min(end - start, max_bytes)
    return image.read(start, size), start + size


def make_operand(insn, op) -> Operand:
    if op.type == X86_OP_REG:
        reg = insn.reg_name(op.reg)
        return Operand("reg", reg, reg=reg, size=op.size)
    if op.type == X86_OP_IMM:
        imm = signed32(op.imm)
        return Operand("imm", str(imm), imm=imm, size=op.size)
    if op.type == X86_OP_MEM:
        base = insn.reg_name(op.mem.base) if op.mem.base else ""
        index = insn.reg_name(op.mem.index) if op.mem.index else ""
        return Operand(
            "mem",
            "",
            base=base,
            index=index,
            scale=op.mem.scale,
            disp=signed32(op.mem.disp),
            size=op.size,
        )
    return Operand("other", "")


def sweep_x86(
    md: "Cs",
    image: PEImage,
    start: int,
    end: int,
    data_ranges: tuple[tuple[int, int], ...],
    padding_mnemonics: frozenset[str],
) -> list[Instruction]:
    """Linear sweep of [start, end), stepping over known data ranges.

    Restarting the decode after each range is the whole point: a switch table
    sitting in the middle of a function is not code, and letting the sweep run
    through it leaves the decoder straddling instruction boundaries for the rest
    of the body.
    """
    ranges = sorted(data_ranges)
    instructions: list[Instruction] = []
    cursor = start

    while cursor < end:
        inside = next((hi for lo, hi in ranges if lo <= cursor < hi), None)
        if inside is not None:
            cursor = inside
            continue

        stop = min([end] + [lo for lo, _ in ranges if lo > cursor])
        chunk = image.read(cursor, stop - cursor)
        if not chunk:
            break

        chunk_start = cursor
        for insn in md.disasm(chunk, chunk_start):
            cursor = insn.address + insn.size
            mnemonic = normalize_mnemonic(insn.mnemonic)
            if mnemonic in padding_mnemonics:
                continue
            operands = tuple(make_operand(insn, op) for op in insn.operands)
            encoding = getattr(insn, "encoding", None)
            instructions.append(Instruction(
                address=insn.address,
                mnemonic=mnemonic,
                op_str=insn.op_str,
                operands=operands,
                raw=f"{insn.mnemonic} {insn.op_str}".strip(),
                size=insn.size,
                disp_offset=getattr(encoding, "disp_offset", 0) or 0,
                imm_offset=getattr(encoding, "imm_offset", 0) or 0,
            ))

        if cursor < stop:
            # Capstone gave up on a byte it could not decode; step over it and
            # resume, otherwise we would spin here forever.
            cursor = max(cursor, chunk_start) + 1

    return instructions


def disassemble_x86(
    image: PEImage,
    start: int,
    starts: Iterable[int],
    max_bytes: int,
    padding_mnemonics: frozenset[str],
    trim_msvc_seh: bool = True,
    remove_jump_tables: bool = True,
) -> list[Instruction]:
    require_capstone()
    data, end = function_bytes(image, start, starts, max_bytes)
    if not data or end is None:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    data_ranges: tuple[tuple[int, int], ...] = ()
    instructions = sweep_x86(md, image, start, end, data_ranges, padding_mnemonics)

    if remove_jump_tables:
        # Each pass can only spot a table whose `jmp [reg*4 + table]` decoded
        # cleanly, and a table found late re-syncs the bytes after it, which can
        # expose another one. Re-sweep until the set of tables stops growing.
        for _ in range(8):
            found = switch_jump_table_ranges(image, instructions, start, end)
            if set(found) <= set(data_ranges):
                break
            data_ranges = merge_ranges(list(data_ranges) + list(found))
            instructions = sweep_x86(md, image, start, end, data_ranges, padding_mnemonics)

    if trim_msvc_seh:
        instructions = trim_seh_cleanup_funclets(instructions)
    while instructions and instructions[-1].mnemonic in padding_mnemonics:
        instructions.pop()
    return trim_trailing_data(instructions)


TERMINATOR_MNEMONICS = frozenset({"ret", "retf", "iret", "iretd", "jmp"})


def trim_trailing_data(instructions: list[Instruction]) -> list[Instruction]:
    """Drop what a linear sweep decoded past the end of the function body.

    A sweep bounded by the next known entry point runs on into whatever the
    linker put in the gap -- alignment, a switch table, a constant pool -- and
    turns it into plausible-looking instructions.  Real code after the last
    return or unconditional jump has to be branched to from inside the
    function, so the last instruction that is either a control transfer or a
    branch target marks the end of the body.  A function with neither is left
    alone.
    """
    targets = {
        operand.imm
        for insn in instructions
        for operand in insn.operands
        if operand.kind == "imm"
    }
    for index in range(len(instructions) - 1, -1, -1):
        insn = instructions[index]
        if insn.mnemonic in TERMINATOR_MNEMONICS or insn.address in targets:
            return instructions[: index + 1]
    return instructions


def is_indexed_jump_table_operand(operand: Operand) -> bool:
    """``[table + reg*4]``: the operand of a ``jmp`` through a switch table."""
    return operand.kind == "mem" and not operand.base and bool(operand.index) and operand.scale == 4


def read_jump_table(
    image: PEImage,
    table: int,
    target_start: int,
    target_end: int,
    *,
    table_end: int | None = None,
    max_entries: int | None = 4096,
) -> list[int]:
    """Read 4-byte switch-table entries until one leaves [target_start, target_end).

    Reading also stops at ``table_end`` and after ``max_entries`` entries,
    when given, or at the first unreadable entry.
    """
    targets: list[int] = []
    cursor = table
    while max_entries is None or len(targets) < max_entries:
        if table_end is not None and cursor + 4 > table_end:
            break
        raw = image.read(cursor, 4)
        if raw is None or len(raw) != 4:
            break
        target = int.from_bytes(raw, "little")
        if not (target_start <= target < target_end):
            break
        targets.append(target)
        cursor += 4
    return targets


def disassemble_reachable_x86(
    image: PEImage,
    start: int,
    starts: Iterable[int],
    max_bytes: int,
    padding_mnemonics: frozenset[str],
) -> list[Instruction]:
    """Decode only instructions reachable from a 32-bit x86 entry point.

    This is useful for call auditing when a linear sweep would decode switch
    tables, EH metadata, or alignment bytes after an early return as code.  A
    direct in-range branch is followed, and indexed indirect jumps enqueue the
    in-range targets stored in their jump table.
    """
    require_capstone()
    section_end = image.section_end_for_va(start)
    if section_end is None:
        return []
    end = next_boundary(starts, start)
    if end is None or end > section_end:
        end = section_end
    end = min(end, start + max_bytes)
    if end <= start:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    pending = [start]
    decoded: dict[int, Instruction] = {}

    def enqueue(address: int) -> None:
        if start <= address < end and address not in decoded and address not in pending:
            pending.append(address)

    def enqueue_jump_table(
        operand: Operand,
        scaled_by_four: frozenset[str],
    ) -> bool:
        if operand.kind != "mem":
            return False
        indexed_scale = is_indexed_jump_table_operand(operand)
        shifted_base = (
            bool(operand.base)
            and not operand.index
            and operand.scale == 1
            and operand.base.lower() in scaled_by_four
        )
        if not indexed_scale and not shifted_base:
            return False
        targets = read_jump_table(image, unsigned32(operand.disp), start, end)
        for target in targets:
            enqueue(target)
        return bool(targets)

    while pending:
        cursor = pending.pop()
        scaled_by_four: set[str] = set()
        while start <= cursor < end and cursor not in decoded:
            raw = image.read(cursor, min(15, end - cursor))
            if not raw:
                break
            insn = next(md.disasm(raw, cursor, count=1), None)
            if insn is None or insn.address != cursor:
                break

            mnemonic = normalize_mnemonic(insn.mnemonic)
            operands = tuple(make_operand(insn, op) for op in insn.operands)
            instruction = Instruction(
                address=insn.address,
                mnemonic=mnemonic,
                op_str=insn.op_str,
                operands=operands,
                raw=f"{insn.mnemonic} {insn.op_str}".strip(),
                size=insn.size,
            )
            decoded[cursor] = instruction
            next_addr = cursor + insn.size

            if (
                mnemonic == "shl"
                and len(operands) == 2
                and operands[0].kind == "reg"
                and operands[1].kind == "imm"
                and operands[1].imm == 2
            ):
                scaled_by_four.add(operands[0].reg.lower())
            elif operands and operands[0].kind == "reg":
                scaled_by_four.discard(operands[0].reg.lower())

            if mnemonic in {"ret", "retf", "iret", "int3", "hlt", "ud2"}:
                break
            if mnemonic == "jmp":
                if operands and operands[0].kind == "imm":
                    enqueue(unsigned32(operands[0].imm))
                elif operands:
                    enqueue_jump_table(operands[0], frozenset(scaled_by_four))
                break
            if mnemonic.startswith("j") or mnemonic in {"loop", "loope", "loopne"}:
                if operands and operands[0].kind == "imm":
                    enqueue(unsigned32(operands[0].imm))
                cursor = next_addr
                continue
            if mnemonic in padding_mnemonics:
                break
            cursor = next_addr

    return [decoded[address] for address in sorted(decoded)]


def address_in_ranges(address: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def switch_jump_table_ranges(
    image: PEImage,
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
    table_bounds: tuple[int, int] | None = None,
) -> tuple[tuple[int, int], ...]:
    """Find switch tables embedded in a function body.

    Flat-memory compilers encode the table and its entries as virtual
    addresses.  Segmented 32-bit compilers can instead use a CS override and
    encode both as offsets from the current executable object's base.
    """
    table_start_bound, table_end_bound = table_bounds or (func_start, func_end)
    ranges: list[tuple[int, int]] = []
    for index, instr in enumerate(instrs):
        if instr.mnemonic != "jmp" or len(instr.operands) != 1:
            continue

        operand = instr.operands[0]
        if operand.kind != "mem":
            continue
        indexed_by_four = is_indexed_jump_table_operand(operand)
        shifted_base = False
        if operand.base and not operand.index and operand.scale == 1:
            base = full_register_name(operand.base)
            for previous in instrs[max(0, index - 3):index]:
                if (
                    previous.mnemonic == "shl"
                    and len(previous.operands) == 2
                    and previous.operands[0].kind == "reg"
                    and full_register_name(previous.operands[0].reg) == base
                    and previous.operands[1].kind == "imm"
                    and previous.operands[1].imm == 2
                ):
                    shifted_base = True
        if not indexed_by_four and not shifted_base:
            continue

        dispatch_register = full_register_name(operand.index or operand.base)

        segment_base = 0
        table_start = unsigned32(operand.disp)
        if "cs:" in instr.op_str.lower():
            owner = getattr(image, "object_for_va", lambda _address: None)(instr.address)
            if owner is not None:
                relative_start = owner.base + table_start
                if table_start_bound <= relative_start < table_end_bound:
                    segment_base = owner.base
                    table_start = relative_start
        if not (table_start_bound <= table_start < table_end_bound):
            continue

        upper_bound = previous_cmp_upper_bound(instrs, index, dispatch_register)
        table_end = None
        if upper_bound is not None:
            table_end = bounded_switch_jump_table_end(
                image,
                table_start,
                table_end_bound,
                upper_bound + 1,
                instr.address,
                segment_base,
            )
        if table_end is None:
            table_end = switch_jump_table_end(
                image,
                table_start,
                table_end_bound,
                func_start,
                func_end,
                segment_base,
            )
        if table_end is not None:
            ranges.append((table_start, table_end))

    ranges.extend(switch_byte_map_ranges(instrs, table_start_bound, table_end_bound))
    return merge_ranges(ranges)


def same_code_region(image: PEImage, source: int, target: int) -> bool:
    """Whether two addresses belong to the same executable image region."""
    object_for_va = getattr(image, "object_for_va", None)
    if object_for_va is not None:
        source_object = object_for_va(source)
        target_object = object_for_va(target)
        return source_object is not None and target_object is not None and \
            source_object.index == target_object.index

    section_for_va = getattr(image, "section_for_va", None)
    if section_for_va is None:
        return False
    source_section = section_for_va(source)
    target_section = section_for_va(target)
    return source_section is not None and target_section is not None and \
        source_section.start == target_section.start and \
        bool(source_section.flags & 0x20000000)


def bounded_switch_jump_table_end(
    image: PEImage,
    table_start: int,
    table_end_bound: int,
    entry_count: int,
    dispatch_address: int,
    segment_base: int = 0,
) -> int | None:
    """Validate a compare-bounded table, including shared-tail targets."""
    if entry_count <= 0 or table_start + entry_count * 4 > table_end_bound:
        return None
    for entry in range(entry_count):
        raw = image.read(table_start + entry * 4, 4)
        if raw is None or len(raw) != 4:
            return None
        target = struct.unpack("<I", raw)[0] + segment_base
        if not same_code_region(image, dispatch_address, target):
            return None
    return table_start + entry_count * 4


def switch_jump_table_end(
    image: PEImage,
    table_start: int,
    table_end_bound: int,
    target_start: int,
    target_end: int,
    segment_base: int = 0,
) -> int | None:
    cursor = table_start
    entries = 0
    while cursor + 4 <= table_end_bound:
        raw = image.read(cursor, 4)
        if raw is None or len(raw) != 4:
            break
        target = struct.unpack("<I", raw)[0] + segment_base
        if not (target_start <= target < target_end):
            break
        entries += 1
        cursor += 4

    if entries == 0:
        return None
    return cursor


def full_register_name(reg: str) -> str:
    aliases = {
        "al": "eax", "ah": "eax", "ax": "eax",
        "bl": "ebx", "bh": "ebx", "bx": "ebx",
        "cl": "ecx", "ch": "ecx", "cx": "ecx",
        "dl": "edx", "dh": "edx", "dx": "edx",
    }
    return aliases.get(reg, reg)


def switch_map_source_register(operand: Operand) -> str | None:
    if operand.kind != "mem":
        return None
    if operand.index and operand.scale not in (0, 1):
        return None
    if operand.base and operand.index:
        return None
    return full_register_name(operand.base or operand.index)


def memory_operand_key(operand: Operand) -> tuple[str | None, str | None, int, int] | None:
    if operand.kind != "mem":
        return None
    base = full_register_name(operand.base) if operand.base else None
    index = full_register_name(operand.index) if operand.index else None
    return (base, index, operand.scale, unsigned32(operand.disp))


def previous_cmp_upper_bound(instrs: list[Instruction], idx: int, reg: str) -> int | None:
    """Highest index the byte map can be read at, from the `cmp` that bounds it.

    The compare is against the register that indexes the map only when the switch
    value already lives in one. When it lives in a stack slot -- which is what an
    unoptimised build produces -- MSVC compares the slot and loads it into the
    register afterwards, so the bound is on the memory operand, not the register.
    Track where the register was loaded from and accept either form; missing the
    second one leaves the byte map to be decoded as instructions, and the garbage
    decode runs past its end and swallows the first real instruction after it.
    """
    loaded_from: set[tuple[str | None, str | None, int, int]] = set()
    for j in range(idx - 1, max(-1, idx - 8), -1):
        instr = instrs[j]

        if instr.mnemonic in {"mov", "movzx", "movsx"} and len(instr.operands) >= 2:
            dst, src = instr.operands[0], instr.operands[1]
            if dst.kind == "reg" and full_register_name(dst.reg) == reg:
                key = memory_operand_key(src)
                if key is not None:
                    loaded_from.add(key)
            continue

        if instr.mnemonic != "cmp" or len(instr.operands) < 2:
            continue
        left, right = instr.operands[0], instr.operands[1]
        if right.kind != "imm" or right.imm < 0:
            continue
        if left.kind == "reg" and full_register_name(left.reg) == reg:
            return right.imm
        if left.kind == "mem" and memory_operand_key(left) in loaded_from:
            return right.imm
    return None


def following_indirect_jump_uses(instrs: list[Instruction], idx: int, reg: str) -> bool:
    for j in range(idx + 1, min(len(instrs), idx + 5)):
        instr = instrs[j]
        if instr.mnemonic != "jmp" or len(instr.operands) != 1:
            continue
        operand = instr.operands[0]
        if operand.kind == "mem" and operand.index == reg and operand.scale == 4:
            return True
    return False


def switch_byte_map_ranges(
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
) -> tuple[tuple[int, int], ...]:
    """Find MSVC byte dispatch maps used before indirect switch jump tables."""
    ranges: list[tuple[int, int]] = []
    for idx, instr in enumerate(instrs):
        if instr.mnemonic not in {"mov", "movzx"} or len(instr.operands) < 2:
            continue

        dst, src = instr.operands[0], instr.operands[1]
        if dst.kind != "reg" or src.kind != "mem" or src.size != 1:
            continue

        table_start = unsigned32(src.disp)
        if not (func_start <= table_start < func_end):
            continue

        source_reg = switch_map_source_register(src)
        if source_reg is None:
            continue

        jump_reg = full_register_name(dst.reg)
        if not following_indirect_jump_uses(instrs, idx, jump_reg):
            continue

        upper_bound = previous_cmp_upper_bound(instrs, idx, source_reg)
        if upper_bound is None:
            continue

        table_end = table_start + upper_bound + 1
        if table_start < table_end <= func_end:
            ranges.append((table_start, table_end))

    return tuple(ranges)


def merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
            continue
        merged[-1][1] = max(merged[-1][1], end)
    return tuple((start, end) for start, end in merged)


def has_msvc_seh_frame(instrs: list[Instruction]) -> bool:
    """MSVC places EH cleanup funclets after the main body RET."""
    scan = instrs[:12]
    saw_fs_read = any(instr.mnemonic == "mov" and "fs:" in instr.op_str.lower() for instr in scan)
    saw_sentinel = any(
        instr.mnemonic == "push"
        and instr.operands
        and instr.operands[0].kind == "imm"
        and instr.operands[0].imm == -1
        for instr in scan
    )
    saw_fs_write = any(instr.mnemonic == "mov" and "fs:" in instr.op_str.lower() for instr in instrs[:24])
    return saw_fs_read and saw_sentinel and saw_fs_write


def trim_seh_cleanup_funclets(instrs: list[Instruction]) -> list[Instruction]:
    if not has_msvc_seh_frame(instrs):
        return instrs
    for idx, instr in enumerate(instrs):
        if instr.mnemonic == "ret":
            return instrs[:idx + 1]
    return instrs
