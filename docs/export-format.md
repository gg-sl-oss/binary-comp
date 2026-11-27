# Export format

`binary-comp` reads a directory of per-function text exports of the original
executable, the target's `code_export_dir`. Two tools write it:

- [`ghidra_scripts/ExportToCompile.java`](../ghidra_scripts/ExportToCompile.java),
  which uses Ghidra's function boundaries and labels;
- `binary-comp export-asm`, a faster Capstone-based replacement.

Exports from both can be mixed in one directory. This page is the contract
between the writers and the Python readers. The readers live mostly in
[`src/binary_comp/core/ghidra.py`](../src/binary_comp/core/ghidra.py), so change
that module, the Java script and this page together.

## What an export is trusted for

Exports supply **function boundaries, names and labels**. Wherever an
analyzer compares instructions, it decodes the bytes again from the original
executable. It never compares the export's instruction text.

`calls`, `global-access`, `order` and some `globals` checks are the exception:
they read operand text from the export, as described [below](#instruction-lines).
That makes them sensitive to the writer's syntax.

## Files

| File | Written by | Read by |
| --- | --- | --- |
| `FUN_XXXXXXXX.disassembled.txt` | Ghidra script, `export-asm` | Most commands: see [who reads what](#who-reads-what) |
| `FUN_XXXXXXXX.decompiled.txt` | Ghidra script | `calls`, to name library functions |
| `globals.h` | Ghidra script | `globals`, as the target's `code_globals_header` |
| `strings.txt` | Ghidra script | Nothing; an inventory for people |

## `FUN_XXXXXXXX.disassembled.txt`

### File name

`FUN_` + the function's entry address as eight upper-case hex digits +
`.disassembled.txt`, for example `FUN_00401000.disassembled.txt`. Readers
also accept six digits, no zero padding and lower-case hex, for older or
hand-made exports. The file name is the main source of the function's
address. The `Address:` header is used only when the name has no address.

Every export in the directory counts as a function start. `values`, `vtables`
and `report --bytes` use this set to decide where one function ends and the
next begins, so an export at a wrong address shortens its neighbour.

### Header

Exactly three lines:

```text
Function: <name>
Address: 0x<entry address, 8 upper-case hex digits>
<empty line>
```

`<name>` is Ghidra's function name, or `FUN_XXXXXXXX` when the function has
none. `export-asm` uses the source or map name when it has one. A name that
does not start with `FUN_` tells `calls` what the target is called.

Readers skip the first three lines unconditionally, so do not add or remove
header lines.

### Body

One instruction or label per line, in address order:

```text
Function: Widget::Update
Address: 0x00401000

PUSH EBP
MOV EBP,ESP
CMP dword ptr [EBP + 0x8],0x0
JZ       LAB_00401010
CALL 0x00402000

LAB_00401010:
POP EBP
RET
```

#### Labels

A label line is `LAB_XXXXXXXX:` on its own line, preceded by an empty line.
Readers also accept `loc_`/`FUN_` prefixes and 6–8 hex digits. A label starts
a new block at that address.

- The Ghidra script writes a label at every internal jump target and wherever
  the function body continues after a gap (a non-contiguous body range).
- `export-asm` writes a label only where the body continues after a gap.

`compare`, `report` and `triage` split the body at labels, count the
instruction lines in each block, and decode that many instructions from the
original executable at each block's address. A missing gap label therefore
makes those commands decode the wrong bytes.

#### Instruction lines

The mnemonic is upper-case and the operands are the disassembler's own text
(Intel syntax). Blank lines, `;` comments and `db`/`dd`/`dw`/`npad` lines are
not counted as instructions.

| Instruction | Ghidra script | `export-asm` |
| --- | --- | --- |
| Direct call | `CALL 0x00402000` (absolute target) | `CALL 0x402000` |
| Indirect call | Operand text kept, e.g. `CALL dword ptr [0x0040e1a4]` | Same |
| Jump inside the function | `JZ       LAB_00401010` | Capstone text, e.g. `JE 0x401010` |
| Anything else | Ghidra's instruction text | Capstone's instruction text |

An indirect call must keep its operand text. Printing a resolved import target
instead would lose the import-table slot that `calls` uses to name the import.

The commands that read operand text rely on:

- **`calls`**: `CALL <hex>` for direct calls (a target below `0x1000` counts
  as an import), `CALL LAB_<hex>`, `CALL`/`JMP dword ptr [<hex>]` through the
  import table or a known function pointer, and `CALL <reg>` after
  `MOV <reg>, dword ptr [<hex>]`. With `calls.use_capstone_original` set, the
  original side is decoded from the executable instead and only the
  boundaries are used.
- **`global-access`**: memory operands with an absolute address
  (`[0x00412345]`, 6–8 hex digits), and registers loaded with an address by
  `MOV <reg>, <hex>`.
- **`globals`** (checks of the original code's global accesses): bracketed
  operands that contain exactly one absolute address and no register, with
  the access size from `byte`/`word`/`dword`/`qword ptr`.
- **`order`**: the instruction count, the first hex address on `CALL`/`J*`
  lines, hex addresses that fall in non-executable sections, and whether the
  function opens with `PUSH EBP` / `MOV EBP,ESP`.

## `FUN_XXXXXXXX.decompiled.txt`

The same file name and three-line header as the disassembly, followed by
Ghidra's decompiler output. Decompiler warnings are rewritten as `//`
comments. A failed decompile writes `// Failed to decompile`.

`calls` reads only the first 2,000 characters, looking for Ghidra's
`Library Function` marker. For such a file it names the address after a
`Function:` header that does not start with `FUN_`, or else after the first
non-comment line following the marker.

## `globals.h`

A conservative inventory of the original's initialised data, read when the
target sets `code_globals_header`. Two line shapes are recognised:

```text
// DAT_0040e000 at 0x0040E000 (string, 12 bytes)
dword g_Count_0040E010 = 0x0;
```

The kind is one of `undefined1`/`2`/`4`/`8`, `byte`, `word`, `dword` or
`pointer`, and gives the size. The address comes from the `_XXXXXXXX` suffix
of the name, which the script appends when the symbol has none. Any other
line is ignored. The reconstructed source remains the authority for
declarations and values.

## `strings.txt`

`0xXXXXXXXX: "<escaped text>"` for every defined string. No command reads it.
