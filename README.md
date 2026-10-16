# ghidra-vb3

Ghidra script for disassembling Visual Basic 3 p-code.

## What it does

Parses a VB3 EXE's NE segment table, identifies all p-code segments, and
annotates the Ghidra listing with:
- A label and plate comment at each procedure start. Procedures matched to the
  EXE's Sub table are labeled `vb3_sub<N>`, and the plate shows the
  `Sub`/`Function` header and the procedures that call it. Others are labeled
  `seg08_proc_0000` etc.
- An EOL comment on every token: opcode keyword, parameter count, raw param
  bytes, a VBDIS3-style variable annotation (`gv1780%`), block indentation, and
  a best-effort infix expression on operators.
- Resolved call targets, both `Call` statements and function calls in
  expressions: `->sub#262@0x2fe02` for local procedures (also added as a call
  reference, so Ghidra's cross-references work) and `->vbprint.dll:moveypos`
  for external `Declare` functions.

Scope is intentionally limited to **opcode + params per token**, with call
resolution and light structuring on top. It does not reconstruct VB source.

## Requirements

- Ghidra 11.x with PyGhidra enabled

## Usage

1. Load your VB3 EXE into Ghidra as a **Raw Binary** at base address 0.
2. Open the Script Manager and add this repo's `ghidra_scripts/` directory.
3. Run `DisassembleVB3PCode.py`.
4. The token tables (`vbdis3i.dat` / `vbdis3x.dat`) are included in `ghidra_scripts/` — no separate download needed.

The script auto-detects p-code segments from the NE header. If the file is not
a standard NE executable (e.g. a raw p-code dump), it falls back to prompting
for a hex offset and byte length.

### Command line

The same file runs without Ghidra (Python 3.8+):

```bash
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE                 # every procedure
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --proc 0x13966  # one procedure
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --calls         # call graph
```

### JSON output

`--json` emits `ghidra-vb3/disassembly-v1` for tools and agents:

```bash
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --json --summary        # no per-token records
python3 ghidra_scripts/DisassembleVB3PCode.py APP.EXE --json --proc 0x13966   # one procedure
```

- `target`, `tables`: path, size and SHA-256 of the EXE and the token tables used.
- `segments`: NE segments with file offset, size, flags, decoded procedure count and bytes.
- `subs`: the Sub table (`index`, `kind`, `local`, `module`, `segment`, `code_start`,
  `lib`, `alias`, `declaration`). With `--proc`, only Subs the procedure owns or calls.
- `procedures`: `start`/`end` file offsets, owning `sub`, `calls` (token offset and
  callee Sub index, `null` when unresolved), `callers`, and unless `--summary`, `tokens`
  (`offset`, `size`, `token`, `keyword`, `params` hex, `level`, and when known `int`,
  `string`, `var`, `callee`, `expr`).
- `coverage`: totals versus returned counts and the number of unresolved calls.

All offsets are 0-based file offsets. Strings are decoded as latin1, so every byte
is preserved. Input that is not an NE executable produces
`{"schema": ..., "error": {"code": "not-ne", "message": ...}}` with exit status 2.

### Tests

```bash
python3 -m unittest discover -s tests                         # unit tests
VB3_SAMPLE=/path/to/APP.EXE python3 -m unittest discover -s tests   # plus sample checks
```

## Background

Token tables are from [VBDIS3](https://www.btinternet.com/~dodi/VBDIS3.zip) by
DoDi (Hans Dietrich Doebener), the reference VB3 p-code disassembler. The core
decode logic is a Python port of `MODULE11.BAS` (`ConvertToken` / `ScanTokens`);
Sub table and call resolution port `MODULE10.BAS` (`DoDecompilation`) and
`MODULE6.BAS` (`Declare` emission).

## License

The scripts in this repository are released under the [MIT License](LICENSE).

The VBDIS3 token tables (`vbdis3i.dat`, `vbdis3x.dat`) are copyright DoDi
(Hans Dietrich Doebener) and are included here with attribution. No explicit
license was stated by the author.

## Status

Script (Phase 1), with call resolution. A Java loader with full NE integration (Phase 2) and a
processor module (Phase 3) are planned.
