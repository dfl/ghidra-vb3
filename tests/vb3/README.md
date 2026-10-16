# VB3 ground-truth programs

Original programs with known declarations, for measuring what ghidra-vb3
recovers. They contain no third-party code, so they and their compiled EXEs can
be shared.

## types

`types/TYPES.MAK` declares one variable per case procedure: every VB3 scalar
type as a local, ByRef and ByVal parameter, `Static`, module-level variable,
`ReDim` array and `Static` array, plus a global, a `ReDim ... As` array, a `Form` object, event
parameters, and variables whose types only usage reveals. Each case procedure
assigns `"CASE <name>"` to the global `Mark`; `types/expected.json` lists the
storage and type each case declares.

`types/TYPES.EXE` is the program as compiled by Visual Basic 3.0 Professional
(File > Make EXE File) under Windows 98. To rebuild it, open `TYPES.MAK` in
VB3 (not included) and make the EXE; VB3 rejects `Dim` of fixed-size arrays
inside procedures, so cases use `ReDim` or `Static`. Score it with:

```bash
python3 tests/score_types.py tests/vb3/types/TYPES.EXE --vbx-dir DIR_WITH_VBRUN300
python3 -m unittest discover -s tests          # VB3_VBX_DIR=... to check event names
```

Event parameter names need `VBRUN300.DLL` (searched next to the EXE and in
`--vbx-dir`); without it they are not checked.

The report groups results by the evidence behind each type: `recorded` (the
references' control tokens), `inferred` (usage rules), `conflict`, `unknown`.
The unit test fails on any mismatch whose type was recorded.
