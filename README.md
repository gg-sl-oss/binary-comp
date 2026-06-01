# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects. The package is extracted from project-specific scripts into reusable
library modules plus a CLI.

`binary-comp` is built around the workflow used by many MSVC-era reverse
engineering projects:

1. Keep the original executable as the reference.
2. Rebuild C/C++ source with the matching compiler and linker.
3. Use source annotations, linker maps, and optional Ghidra text exports to map
   original functions and globals to rebuilt symbols.
4. Compare layout, function bytes, decoded operands, global data, calls,
   global accesses, vtables, and C++ exception-handling metadata.

## Install

For local development from a checkout:

```bash
PYTHONPATH=src python3 -m binary_comp.cli values --help
```

Or install it editable with all optional analyzer dependencies:

```bash
python3 -m pip install -e ".[all]"
binary-comp values --help
```

The optional dependencies are split by feature:

- `binary-comp[capstone]` for PE disassembly-backed analyzers.
- `binary-comp[cpp]` for C/C++ source annotation parsing.
- `binary-comp[all]` for both plus pytest.

## Configuration

The standalone config is target-oriented. A target describes the original PE,
the rebuilt PE, the rebuilt linker map, and the source tree that carries the
original-address annotations.

```json
{
  "targets": {
    "full": {
      "original_exe": "path/to/original.exe",
      "rebuilt_exe": "path/to/rebuilt.exe",
      "map": "path/to/rebuilt.map",
      "source_dirs": ["path/to/src"],
      "globals_source": "path/to/src/globals.cpp",
      "globals_header": "path/to/src/globals.h",
      "code_globals_header": "path/to/code/globals.h",
      "define_headers": ["path/to/src/constants.h"],
      "auto_complete": "path/to/src/auto_complete.txt",
      "code_export_dir": "path/to/ghidra-export",
      "asm_dir": "path/to/asm-output",
      "source_excludes": ["path/to/src/generated.cpp"],
      "library_ranges": [["0x00424540", "0x004304e0"]]
    }
  }
}
```

Relative paths are resolved from the config file directory. A copy of the
minimum shape is kept at
[`examples/minimal-binary-comp.json`](examples/minimal-binary-comp.json).

### Source Function Annotations

Place a `Function start` comment immediately before the rebuilt source function
that represents an original function:

```cpp
/* Function start: 0x00401000 */
int ScoreTable::score(int value) const
{
    return value + 7;
}
```

Multiple comments before the same function are allowed. This is useful when
Ghidra splits one MSVC SEH function into several original chunks but the rebuilt
compiler emits one function.

### Global Annotations

Global data analyzers need original addresses either encoded in symbol names or
placed in comments:

```cpp
int g_Bias_00405038 = 7;
char g_Label[6] = "alien"; // 0x00405030
```

The rebuilt MAP file provides the rebuilt VA for each encoded-address symbol,
allowing `binary-comp data` to compare original bytes against relocated rebuilt
bytes.

### Optional Inputs By Analyzer

| Analyzer | Required target fields | Extra notes |
| --- | --- | --- |
| `exe` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | `--functions` uses function annotations and the rebuilt MAP. `library_ranges` can exclude known CRT/library ranges. |
| `compare` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | Also takes one Ghidra-style `FUN_*.disassembled.txt` path. |
| `report` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs`, `code_export_dir` | Uses one export per annotated original address. |
| `values` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | `code_export_dir` improves original function boundaries. Capstone is required. |
| `data` | `original_exe`, `rebuilt_exe`, `map`, `globals_source` | Compares globals with encoded or commented original addresses. |
| `globals` | `original_exe`, `globals_source` | Optional headers and `auto_complete` broaden coverage. |
| `calls` | `source_dirs`, `code_export_dir`, `asm_dir` | Compares call target multisets from original exports and rebuilt assembly listings. |
| `global-access` | `source_dirs`, `code_export_dir`, `asm_dir` | Compares read/write multisets for global data references. |
| `vtables` | `original_exe`, `source_dirs`, `code_export_dir` | Reads vtable bytes and constructor vptr writes from the original PE. |
| `seh` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | Compares MSVC C++ EH FuncInfo metadata for a function or report. |

## CLI Examples

```bash
binary-comp exe --config path/to/binary-comp.json --target full --functions
binary-comp compare --config path/to/binary-comp.json --target full ScoreTable::score code/FUN_00401000.disassembled.txt
binary-comp values --config path/to/binary-comp.json --target full --filter ScoreTable::score
binary-comp data --config path/to/binary-comp.json --target full --verbose
binary-comp globals --config path/to/binary-comp.json --target full --fail-on-issues
binary-comp calls --config path/to/binary-comp.json --target full --fail-on-mismatches
binary-comp global-access --config path/to/binary-comp.json --target full --include-address-immediates
binary-comp report --config path/to/binary-comp.json --target full
binary-comp vtables --config path/to/binary-comp.json --target full --dump
binary-comp seh --config path/to/binary-comp.json --target full --report
```

Most analyzers that read rebuilt code will run the configured build command
first unless `--no-build` is supplied.

## Reconstruction Mismatch Demo

[`examples/reconstruction-mismatch-demo`](examples/reconstruction-mismatch-demo)
contains a small, partially reconstructed C++ console program built with MSVC
4.x. It is designed to show the analyzers on a non-perfect rebuild, not just a
100% match. It includes:

- Original and rebuilt C++ source files.
- Real 32-bit PE executables compiled by MSVC 4.2.
- MSVC linker maps and assembly listings.
- Generated Ghidra-style `FUN_*.disassembled.txt` exports.
- A `binary-comp.json` target that runs the package against those artifacts.
- A Makefile that downloads `wibo` and MSVC420 into a local `.tools/`
  directory; no submodules are required.
- A Makefile step that replaces `MSVC420/bin/msvcrt40.dll` with the known-good
  DLL required by `wibo` before compiling.

From the example directory:

```bash
make setup
make build
PYTHONPATH=../../src python3 -m binary_comp.cli exe --config binary-comp.json --target demo --functions
PYTHONPATH=../../src python3 -m binary_comp.cli report --config binary-comp.json --target demo --no-build
PYTHONPATH=../../src python3 -m binary_comp.cli compare --config binary-comp.json --target demo --no-build Door::canOpen code/FUN_00401075.disassembled.txt
PYTHONPATH=../../src python3 -m binary_comp.cli values --config binary-comp.json --target demo --no-build --include-stack-locals
PYTHONPATH=../../src python3 -m binary_comp.cli data --config binary-comp.json --target demo
```

The example intentionally includes discrepancies across four small classes:
function similarity differences, an immediate-value mismatch, a global data
mismatch, and shifted function addresses. `binary-comp data` exits nonzero in
this example because it finds the expected global mismatch.

## Development

Run the test suite with:

```bash
python3 -m pytest
```

The project still understands the legacy verification config shape used during
the first extraction, but new projects should prefer the standalone `targets`
schema shown above.
