# VB3 ground-truth programs

Original programs with known declarations, for measuring what ghidra-vb3
recovers. They contain no third-party code, so they and their compiled EXEs can
be shared.

## types

`types/TYPES.MAK` declares one variable per case procedure: every VB3 scalar
type as a local, ByRef and ByVal parameter, `Static`, module-level variable and
fixed array, plus a global, a `ReDim ... As` array, a `Form` object, event
parameters, and variables whose types only usage reveals. Each case procedure
assigns `"CASE <name>"` to the global `Mark`; `types/expected.json` lists the
storage and type each case declares.

Build it with Visual Basic 3.0 (not included): open `TYPES.MAK` and choose
File > Make EXE File, or run `VB.EXE /MAKE TYPES.MAK`. Keep `VBRUN300.DLL` next
to `TYPES.EXE` so event parameters are named. Then score it:

```bash
python3 tests/score_types.py tests/vb3/types/TYPES.EXE
VB3_TYPES_EXE=tests/vb3/types/TYPES.EXE python3 -m unittest discover -s tests
```

The report groups results by the evidence behind each type: `recorded` (the
references' control tokens), `inferred` (usage rules), `conflict`, `unknown`.
The unit test fails on any mismatch whose type was recorded.
