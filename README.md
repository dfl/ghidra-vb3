# ghidra-vb3

Ghidra script for disassembling Visual Basic 3 p-code.

## What it does

Parses a VB3 EXE's NE segment table, identifies all p-code segments, and
annotates the Ghidra listing with:
- A label and plate comment at each procedure start. Procedures come from the
  EXE's Sub table descriptors (code segment, start and size). Event procedures
  are named from the form, control and menu event tables (`Form10.Command1_Click`,
  with VB3's parameter list); other procedures get vb3dec's names
  (`sub0D5C`, `fn13EB`), qualified by their form in form modules. The plate
  shows the `Sub`/`Function` header, the form, the procedures that call it, and
  the parameters, locals and `Static` variables with their types and frame
  offsets (`Dim l0A6A As Integer  ' bp-0x1a`).
  Bytes no descriptor covers (or a raw p-code dump) are scanned for
  START..FINISH runs, labeled `seg08_proc_0000` etc.
- An EOL comment on every token: opcode keyword, parameter count, raw param
  bytes, a VBDIS3-style variable annotation (`gv1780%`), the form, control,
  `Screen` or `Clipboard` a module slot names (`[mv10eT List2]`), the
  variable and its type (`l0A6A:Integer`), block indentation, and a
  best-effort infix expression on operators.
- Resolved call targets, both `Call` statements and function calls in
  expressions: `->fn13EB@0x2fe02` for local procedures (also added as a call
  reference, so Ghidra's cross-references work) and `->vbprint.dll:moveypos`
  for external `Declare` functions. `Declare` parameter lists, which compiled
  programs do not keep, are inferred from the arguments each call pushes.

### Variable types

Variables are identified by storage: frame locals and parameters by their
module data slot (whose word is the frame offset), module and `Static`
variables by slot, and globals by their offset in the global data area, which
is the same in every module. Types come from two kinds of evidence, which are
never mixed silently:

- **recorded**: the data type each reference's control token says the opcode
  accesses, the element type of array element tokens, array descriptors in
  module data, and `ReDim ... As` clauses;
- **inferred** (shown with `~`): usage rules, each named in the JSON evidence:
  the source type of a conversion applied to the variable's value, scalar
  assignments through an explicit conversion or of a String, `Len`/`Asc`/
  `Mid$`/`Left$`/`Right$`/`InStr` arguments, `ChDrive`/`ChDir`/`MkDir`/
  `RmDir`/`Kill` operands, strings passed `ByVal` to DLLs, comparisons with
  Long literals, the typed `For`/`Next` and comparison tokens, objects whose
  properties are accessed (VB3 Variants hold no objects), event
  signatures, call-site argument types (mostly from vb3dec), and ByRef
  arguments (including array elements), which VB3 requires to have their
  parameter's type (propagated in both directions through pass-through
  parameters).

Disagreeing evidence is reported as a conflict; no evidence leaves the type
unknown (`?`) rather than defaulting to Variant. `Static` locals and module
variables share module data, so a module variable used by one procedure is
listed in its plate as a `Static` candidate.

`tests/vb3/types/` is a ground-truth program compiled with VB3: 57 variables
covering every type as a local, ByRef/ByVal parameter, `Static`, module-level
and global variable, `ReDim` and `Static` arrays, a `Form` object, event
parameters and usage-only cases. All 57 storage classes and types are
recovered (53 recorded, 4 inferred); `tests/score_types.py` reports it.
`tests/vb3/usage/` covers `For` counters, array elements and comparisons (40
variables, all recovered). `tests/vb3/byref/` covers argument passing: the temporaries VB3 creates for
constants passed ByRef (one token per type), and 38 parameters that only
argument passing types, all recovered.

Frame locals also get an upper bound on their size (`max_bytes`, the bytes up
to the next variable), which identifies user-defined types: a local `As
OFStruct` reads "at most 136 bytes", its exact size.

On a real program with published source, the VB3 setup kit's `SETUP1` as
shipped with Polaris, forms, controls, events and `Declare`s match exactly, and
all parameter and `Dim` types match. When comparing with source, note that
`DefInt` and the other `Def` statements apply only to the module that
contains them, so undeclared variables elsewhere are Variant.

Scope is intentionally limited to **opcode + params per token**, with call
resolution and light structuring on top. It does not reconstruct VB source.

### Runtime calls

`tools/vbrun_map.py` maps the p-code tokens a program uses to the Win16 and
DOS functions their handlers in `VBRUN300.DLL` can reach, so statements show
what they do at the system level (`Kill` reaches `DOS.delete`, `Shell`
`KERNEL.WINEXEC`, `MsgBox` `USER.MESSAGEBOX`, `InputBox$` the
`USER.DIALOGBOXPARAM` family):

```bash
python3 tools/vbrun_map.py VBRUN300.DLL APP.EXE -o vbrun-map.json --ghidra "$GHIDRA_INSTALL_DIR"
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --runtime-map vbrun-map.json
```

In Ghidra, put `vbrun-map.json` next to the imported EXE. Token comments then
end with `=> USER.MESSAGEBOX, ...` and each plate lists `Reaches:` with the
procedure's nearest calls. Calls reached by more than a third of a program's
procedures (lazy DLL loading behind `Declare` calls, shared painting paths)
are left out of plates as background and listed in the JSON.

How it works: a p-code token is the near offset of its handler in the
runtime's interpreter segment, and every handler ends by dispatching the next
token with `es: lodsw ; jmp ax`. The tool walks each handler's code with
[capstone](https://www.capstone-engine.org/), following NE relocations, the
runtime's inline runtime-function dispatch tables (parsed from its own code),
bounded jump tables and far pointers passed as callbacks, and names DOS
services by the AH function given to `DOS3Call`. Ordinals are named from
Ghidra's `data/symbols/win16/*.exports`.

The results are static reachability: a handler may reach a function on some
path, which does not mean every execution calls it, and paths through
unresolved indirect jumps are missed (each token counts them). Checked against
`tests/vb3/stmts` (114 statements compiled with VB3, using VBRUN300 3.0.5.38),
30 of 32 statements with a known Win16/DOS behaviour reach it. Not reached
yet: `Open` (its open/create routine is reached through a jump via a variable)
and `Load` (window creation only beyond the default depth). Following the
variable, and walking deeper, reaches both only through the runtime's shared
error paths, which most statements also reach, so neither is reported. The tool
needs `pip install capstone`; it is not needed for anything else.

### Library signatures

Many VB3 programs ship the same library code, such as the setup kit's `SETUP1`.
`tools/vb3_signatures.py` builds signatures from a compiled library and its
source, and `--signatures FILE` (or `vb3-signatures.json` next to the EXE, for
the Ghidra script) names the procedures that match:

```bash
python3 tools/vb3_signatures.py SETUP1.EXE SETUP1.BAS SETUP1.FRM PATH.FRM -o setup1.json
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --signatures setup1.json
```

A signature keeps only derived features: hashes of the procedure's token
sequence without operands, of its token 4-grams and of its strings, and the DLL
functions it calls. A match is exact (identical signature, so unmodified library
code) or similar (4-gram similarity of at least 0.5, ahead of the next library
procedure by 0.1, so modified library code). Short procedures without strings
or DLL calls only match in a module where a distinctive procedure matched too.
Exact matches name the procedure in Ghidra; both kinds appear in plates and the
JSON.

`signatures/vb3-setup-kit.json` is the VB 3.0 Professional setup kit's `SETUP1`
(28 procedures). On the `SETUP1` that Polaris ships, it names 27 of 29
procedures, 21 exact and 6 similar (modified copies); the 2 unnamed are
Polaris's own. On Polaris's main program and the ground-truth programs it
names nothing.

## Requirements

- Ghidra 11.x with PyGhidra enabled

## Usage

1. Load your VB3 EXE into Ghidra as a **Raw Binary** at base address 0.
2. Open the Script Manager and add this repo's `ghidra_scripts/` directory.
3. Run `DisassembleVB3PCode.py`.
4. The token tables (`vbdis3i.dat` / `vbdis3x.dat`) are included in `ghidra_scripts/` — no separate download needed.

Event names come from the control models in `VBRUN300.DLL` (built-in
controls) and the project's `.VBX` files (custom controls). They are not
included here: the script looks for them next to the EXE Ghidra imported, and
the command line also searches `--vbx-dir` directories. Without them, event
procedures keep their generic names and the output lists what was missing.

The script auto-detects p-code segments from the NE header. If the file is not
a standard NE executable (e.g. a raw p-code dump), it falls back to prompting
for a hex offset and byte length.

### Command line

The same file runs without Ghidra (Python 3.8+):

```bash
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE                 # every procedure
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --proc 0x13966  # one procedure
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --calls         # call graph
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --vbx-dir C:/WINDOWS/SYSTEM  # VBRUN300.DLL, .VBX files
```

### JSON output

`--json` emits `ghidra-vb3/disassembly-v1` for tools and agents:

```bash
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --json --summary        # no per-token records
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --json --proc 0x13966   # one procedure
```

- `target`, `tables`: path, size and SHA-256 of the EXE and the token tables used.
- `segments`: NE segments with file offset, size, flags, decoded procedure count and bytes.
- `control_models`: paths of the `VBRUN300.DLL` and `.VBX` files used (`null` when not
  found) and warnings.
- `forms`: each form's `name`, `file_name`, code `module` and `controls` (`id`, `name`,
  `type`, `array_index`), with decoding `warnings`.
- `variables`: `id`, `name`, `storage` (`local`, `param`, `module`, `global`), `module`,
  `slot`, `frame`, `slot_word`, `global_offset`, `array`, `bounds`, `max_bytes` (frame
  bytes up to the next variable, an upper bound on a non-array local's size, e.g. a
  user-defined type), `type`, `type_source` (`recorded`, `inferred`, `conflict` or
  `null`), `evidence` (recorded types with reference counts, inferred types with rule
  names) and `procedures`.
- `subs`: the Sub table (`index`, `kind`, `local`, `module`, `segment`, `code_start`,
  `code_end`, `lib`, `alias`, `name`, `returns`, `params` (`null` when unknown), `event`
  (`owner`, `event`, `slot`; `event` is `null` when the control's model is missing),
  `declaration`). With `--proc`, only Subs the procedure owns or calls.
- `procedures`: `start`/`end` file offsets, owning `sub`, `calls` (token offset and
  callee Sub index, `null` when unresolved), `callers`, `variables` (ids), and unless
  `--summary`, `tokens`
  (`offset`, `size`, `token`, `keyword`, `params` hex, `level`, and when known `int`,
  `string`, `var`, `ref`, `variable`, `callee`, `expr`, `runtime_calls`).
- `runtime_map` (with `--runtime-map`): the map's path and runtime SHA-256, its depth,
  whether it was made from the `VBRUN300.DLL` found (`matches_vbrun300`, `null` when
  none was found) and the program's `background` calls. Procedures then carry
  `runtime_calls` (nearest first, without background; `null` without a map) and tokens
  `runtime_calls` (all non-shared calls, nearest first).
- `signatures` (with `--signatures`): the file's path, library name and the number of
  procedures `matched`. Procedures then carry `signature` (`name`, `source` file,
  `match` `exact` or `similar`, `score`, `library`; `null` when none matched).
- `coverage`: totals versus returned counts, the number of unresolved calls, and variables
  by type source.

All offsets are 0-based file offsets. JSON strings are decoded as latin1, so every
byte is preserved; Ghidra comments and the text output show them as Windows-1252,
the encoding VB3 used. Input that is not an NE executable produces
`{"schema": ..., "error": {"code": "not-ne", "message": ...}}` with exit status 2.

### Tests

```bash
python3 -m unittest discover -s tests                         # unit and ground-truth tests
VB3_SAMPLE=/path/to/APP.EXE python3 -m unittest discover -s tests   # plus sample checks
VB3_VBX_DIR=/dir/with/VBRUN300.DLL GHIDRA_INSTALL_DIR=/path/to/ghidra \
  python3 -m unittest discover -s tests                       # plus event names and runtime-call checks
```

## Background

Token tables are from [VBDIS3](https://www.btinternet.com/~dodi/VBDIS3.zip) by
DoDi (Hans-Peter Diettrich), the reference VB3 p-code disassembler. The core
decode logic is a Python port of `MODULE11.BAS` (`ConvertToken` / `ScanTokens`);
Sub table and call resolution port `MODULE10.BAS` (`DoDecompilation`) and
`MODULE6.BAS` (`Declare` emission), with the descriptor and relocation fixes
documented in [vb3dec](https://github.com/jrmcpeek/vb3dec)'s VBDIS3 audit.

Form records, event tables, control model scanning (`VBRUN300.DLL` / `.VBX`),
module slot names and `Declare` parameter inference are ported from vb3dec by
Jamie McPeek.

## License

The scripts in this repository are released under the [MIT License](LICENSE).

Code ported from vb3dec is used under its MIT License, Copyright (c) 2026
Jamie McPeek.

The VBDIS3 token tables (`vbdis3i.dat`, `vbdis3x.dat`) are copyright DoDi
(Hans-Peter Diettrich) and are included here with attribution. No explicit
license was stated by the author.

## Status

Script (Phase 1), with call resolution, form and event names. A Java loader with full NE integration (Phase 2) and a
processor module (Phase 3) are planned.
