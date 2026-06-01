# Reconstruction Mismatch Demo

This directory is a small end-to-end fixture using real 32-bit PE files built
with MSVC 4.x. It is intentionally not a perfect reconstruction: the rebuilt
source has several small differences so the analyzers have something useful to
report.

The example has four tiny classes:

- `ScoreTable`
- `Reactor`
- `Door`
- `LessonLog`

The rebuilt source carries the annotations that `binary-comp` uses to map
source functions back to original addresses:

```cpp
/* Function start: 0x00401000 */
int ScoreTable::score(int value) const
```

The globals encode their original addresses in their names:

```cpp
char g_Title_00405030[8] = "ALIEN!";
int g_Bonus_00405038 = 9;
```

## Tool Setup

This example does not use submodules. The Makefile downloads local tools under
`.tools/`:

- `decompals/wibo` release binary
- `itsmattkc/MSVC420` source archive
- a known-good `msvcrt40.dll`, copied into `MSVC420/bin/`

From this directory:

```bash
make setup
make build
```

Override paths when you already have local copies:

```bash
make build WIBO=/path/to/wibo MSVC42_DIR=/path/to/MSVC420
```

`make build` compiles both executables, writes MSVC maps and assembly listings
under `artifacts/`, and generates small `code/FUN_*.disassembled.txt` files
from the original executable for function-boundary hints.

The `msvcrt40.dll` copy is required for `wibo`: the DLL bundled in the MSVC420
archive is replaced before `CL.EXE` is invoked.

## Run The Example

From this directory, with `binary-comp` installed or with `PYTHONPATH` pointed
at the checkout:

```bash
PYTHONPATH=../../src python3 -m binary_comp.cli exe --config binary-comp.json --target demo --functions
PYTHONPATH=../../src python3 -m binary_comp.cli report --config binary-comp.json --target demo --no-build
PYTHONPATH=../../src python3 -m binary_comp.cli compare --config binary-comp.json --target demo --no-build Door::canOpen code/FUN_00401075.disassembled.txt
PYTHONPATH=../../src python3 -m binary_comp.cli values --config binary-comp.json --target demo --no-build --include-stack-locals
PYTHONPATH=../../src python3 -m binary_comp.cli data --config binary-comp.json --target demo
```

Or run the demonstration target:

```bash
make demo
```

Expected discrepancies include:

- `report`: `Door::canOpen` is below 90% similarity because the rebuilt method
  is missing one passcode branch.
- `values --include-stack-locals`: `ScoreTable::score` compares `12` against
  the original `10` threshold.
- `data`: `g_Bonus_00405038` is `9` in the rebuilt executable but `7` in the
  original. This command exits `1` by design.
- `exe --functions`: several reconstructed functions are shifted because the
  shorter `Door::canOpen` changes later function addresses.
