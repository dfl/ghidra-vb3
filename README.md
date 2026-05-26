# ghidra-vb3

Ghidra script for disassembling Visual Basic 3 p-code.

## What it does

Scans a region of a loaded binary for VB3 p-code procedure runs and annotates
the Ghidra listing with:
- A label (`vb3_proc_NNNN`) and plate comment at each procedure start
- An EOL comment on every token: opcode keyword, parameter count, raw param bytes

Scope is intentionally limited to **opcode + raw params per token**. No type
inference, no VB source reconstruction.

## Requirements

- Ghidra 11.x with PyGhidra enabled
- [VBDIS3](https://www.btinternet.com/~dodi/VBDIS3.zip) — only the two token
  table files are needed: `vbdis3i.dat` and `vbdis3x.dat`

## Usage

1. Load your VB3 EXE (or raw p-code dump) into Ghidra as a **Raw Binary**.
2. Open the Script Manager and add this repo's `ghidra_scripts/` directory.
3. Run `DisassembleVB3PCode.py`.
4. When prompted:
   - Select the directory containing `vbdis3i.dat` / `vbdis3x.dat`
   - Enter the hex file offset and byte length of the p-code region,
     e.g. `34a00 f800`

## Finding p-code regions

VB3 EXEs are 16-bit NE (New Executable) format. The p-code lives in dedicated
segments. Automatic segment detection is planned (Phase 2); for now, use a hex
editor to locate the segment containing `CASE_START` tokens or refer to the NE
segment table.

## Status

Phase 1 (script). Phase 2 (Java loader with automatic NE segment parsing) and
Phase 3 (full processor module) are planned.

## Background

Token tables are from [VBDIS3](https://www.btinternet.com/~dodi/VBDIS3.zip) by
DoDi (Hans Dietrich Doebener), the reference VB3 p-code disassembler. The core
decode logic is a Python port of `MODULE11.BAS` (`ConvertToken` / `ScanTokens`).
