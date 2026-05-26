# ghidra-vb3

Ghidra script for disassembling Visual Basic 3 p-code.

## What it does

Parses a VB3 EXE's NE segment table, identifies all p-code segments, and
annotates the Ghidra listing with:
- A label (`seg08_proc_0000` etc.) and plate comment at each procedure start
- An EOL comment on every token: opcode keyword, parameter count, raw param bytes

Scope is intentionally limited to **opcode + raw params per token**. No type
inference, no VB source reconstruction.

## Requirements

- Ghidra 11.x with PyGhidra enabled

## Usage

1. Load your VB3 EXE into Ghidra as a **Raw Binary**.
2. Open the Script Manager and add this repo's `ghidra_scripts/` directory.
3. Run `DisassembleVB3PCode.py`.
4. The token tables (`vbdis3i.dat` / `vbdis3x.dat`) are included in `ghidra_scripts/` — no separate download needed.

The script auto-detects p-code segments from the NE header. If the file is not
a standard NE executable (e.g. a raw p-code dump), it falls back to prompting
for a hex offset and byte length.

## Background

Token tables are from [VBDIS3](https://www.btinternet.com/~dodi/VBDIS3.zip) by
DoDi (Hans Dietrich Doebener), the reference VB3 p-code disassembler. The core
decode logic is a Python port of `MODULE11.BAS` (`ConvertToken` / `ScanTokens`).

## License

The scripts in this repository are released under the [MIT License](LICENSE).

The VBDIS3 token tables (`vbdis3i.dat`, `vbdis3x.dat`) are copyright DoDi
(Hans Dietrich Doebener) and are included here with attribution. No explicit
license was stated by the author.

## Status

Script (Phase 1). A Java loader with full NE integration (Phase 2) and a
processor module (Phase 3) are planned.
