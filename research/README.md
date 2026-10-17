# Research: VB3 runtime calls

`vbrun_reach.py` maps the p-code handlers a program uses to the Win16 and DOS
functions they can reach in `VBRUN300.DLL`. Status: prototype.

Findings (VBRUN300.DLL 3.0.5.38):

- P-code is threaded code. A token is the near offset of its handler in the
  interpreter segment (segment 25), and every handler ends by dispatching the
  next token with `es: lodsw ; jmp ax` (339 times in that segment). All 434
  distinct tokens in Polaris and `tests/vb3/types` land on handlers there.
- Many handlers are thunks: `call helper` followed by an inline
  runtime-function number. The helper reads the number through its return
  address, doubles it into BX and far-jumps to one of three dispatchers, each a
  `jmp word ptr cs:[bx + disp]` table (segments 58, 51 and 49 by BX range).
  One helper variant resumes after the operand; the others end the handler.
  The walker parses this protocol from the runtime's own code.
- DOS services go through KERNEL.102 (DOS3Call) with the function in AH.
- `tests/vb3/stmts` (114 cases compiled with VB3) confirms the VBDIS3 keyword
  of every token it covers: 95 of 106 labelled cases decode as expected and
  the other 11 are explained (conversions compile to C<typ>, statement forms
  of Date$/Time$, Print # and LoadPicture compile to generic tokens).

Against expected Win16/DOS calls for 32 statements, 22 reach the exact
function (e.g. Kill -> DOS delete, Name -> rename, Dir$ -> findfirst/findnext,
Shell -> WinExec, DoEvents -> PeekMessage, Beep -> MessageBeep). Not yet
reached: ChDir/MkDir/RmDir (AH set dynamically), Open/Close, and the window
calls behind MsgBox, InputBox$, Load and Unload.

Results are reachability from static analysis: a handler may reach a function
on some path, which is not proof that every execution calls it.

    python3 research/vbrun_reach.py VBRUN300.DLL program.json [GHIDRA_INSTALL]

`program.json` is `DisassembleVB3PCode.py --json` output; ordinal names come
from Ghidra's `data/symbols/win16/*.exports` when a Ghidra install is given.
Requires capstone.
