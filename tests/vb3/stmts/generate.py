"""Generate STMTS.MAK: one procedure per VB3 statement or function.

Each case procedure assigns "CASE <name>" to the global Mark, then uses one
statement or function once. Compiled (never run), it shows which p-code token
the VB3 compiler emits for each, which settles the keyword of each token and
its handler entry in VBRUN300.DLL. expected.json maps each case to the keyword
the statement should decode as.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# (case name, body lines, expected keyword)
CASES = [
    ("baseline", [], None),
    # statements
    ("beep", ["Beep"], "Beep"),
    ("chdir", ['ChDir "C:\\"'], "ChDir"),
    ("chdrive", ['ChDrive "C"'], "ChDrive"),
    ("mkdir", ['MkDir "C:\\STMTS"'], "MkDir"),
    ("rmdir", ['RmDir "C:\\STMTS"'], "RmDir"),
    ("kill", ['Kill "C:\\STMTS.TMP"'], "Kill"),
    ("name", ['Name "C:\\A.TMP" As "C:\\B.TMP"'], "Name"),
    ("open_output", ['Open "C:\\S.TMP" For Output As #1'], "Open"),
    ("open_input", ['Open "C:\\S.TMP" For Input As #1'], "Open"),
    ("open_binary", ['Open "C:\\S.TMP" For Binary As #1'], "Open"),
    ("open_random", ['Open "C:\\S.TMP" For Random As #1 Len = 16'], "Open"),
    ("close", ["Close #1"], "Close"),
    ("close_all", ["Close"], "Close"),
    ("reset", ["Reset"], "Reset"),
    ("print_file", ['Print #1, "x"'], "Print"),
    ("write_file", ['Write #1, "x"'], "Write"),
    ("input_file", ["Input #1, S"], "Input"),
    ("line_input", ["Line Input #1, S"], "Line Input"),
    ("get", ["Get #1, 1, I"], "Get"),
    ("put", ["Put #1, 1, I"], "Put"),
    ("seek_stmt", ["Seek #1, 1"], "Seek"),
    ("randomize", ["Randomize"], "Randomize"),
    ("sendkeys", ['SendKeys "x"'], "SendKeys"),
    ("appactivate", ['AppActivate "Program Manager"'], "AppActivate"),
    ("date_stmt", ['Date$ = "01-01-1994"'], "Date$"),
    ("time_stmt", ['Time$ = "12:00:00"'], "Time$"),
    ("erase", ["Erase A"], "Erase"),
    ("error_stmt", ["Error 5"], "Error"),
    ("on_error", ["On Error Resume Next", "Tmp = 1"], "On Error"),
    ("end_stmt", ["End"], "End"),
    ("doevents", ["I = DoEvents()"], "DoEvents"),
    ("load", ["Load Form1"], "Load"),
    ("unload", ["Unload Form1"], "Unload"),
    ("show", ["Form1.Show"], None),
    ("cls", ["Form1.Cls"], None),
    ("pset", ["Form1.PSet (1, 1)"], None),
    ("line_method", ["Form1.Line (0, 0)-(10, 10)"], None),
    ("circle", ["Form1.Circle (5, 5), 2"], None),
    ("print_method", ['Form1.Print "x"'], None),
    ("clipboard", ['Clipboard.SetText "x"'], None),
    # functions
    ("msgbox_fn", ['I = MsgBox("x", 1, "t")'], "MsgBox"),
    ("msgbox_stmt", ['MsgBox "x"'], "MsgBox"),
    ("inputbox", ['S = InputBox$("x")'], "InputBox$"),
    ("shell", ['I = Shell("NOTEPAD.EXE", 1)'], "Shell"),
    ("timer", ["D = Timer"], "Timer"),
    ("now", ["D = Now"], "Now"),
    ("date_fn", ["S = Date$"], "Date$"),
    ("time_fn", ["S = Time$"], "Time$"),
    ("dateserial", ["D = DateSerial(1994, 1, 1)"], "DateSerial"),
    ("timeserial", ["D = TimeSerial(12, 0, 0)"], "TimeSerial"),
    ("datevalue", ['D = DateValue("1-1-94")'], "DateValue"),
    ("year", ["I = Year(D)"], "Year"),
    ("weekday", ["I = Weekday(D)"], "Weekday"),
    ("format", ['S = Format$(D, "0.00")'], "Format$"),
    ("dir", ['S = Dir$("C:\\*.*")'], "Dir$"),
    ("curdir", ["S = CurDir$"], "CurDir$"),
    ("environ", ['S = Environ$("PATH")'], "Environ$"),
    ("command", ["S = Command$"], "Command$"),
    ("freefile", ["I = FreeFile"], "FreeFile"),
    ("eof", ["I = EOF(1)"], "EOF"),
    ("lof", ["L = LOF(1)"], "LOF"),
    ("loc", ["L = Loc(1)"], "Loc"),
    ("seek_fn", ["L = Seek(1)"], "Seek"),
    ("filelen", ['L = FileLen("C:\\AUTOEXEC.BAT")'], "FileLen"),
    ("input_fn", ["S = Input$(1, #1)"], "Input$"),
    ("rnd", ["D = Rnd"], "Rnd"),
    ("loadpicture", ['Form1.Picture = LoadPicture("")'], "LoadPicture"),
    ("qbcolor", ["L = QBColor(1)"], "QBColor"),
    ("rgb", ["L = RGB(1, 2, 3)"], "RGB"),
    ("chr", ["S = Chr$(65)"], "Chr$"),
    ("asc", ['I = Asc("A")'], "Asc"),
    ("len", ["I = Len(S)"], "Len"),
    ("mid", ["S = Mid$(S, 1, 1)"], "Mid$"),
    ("left", ["S = Left$(S, 1)"], "Left$"),
    ("right", ["S = Right$(S, 1)"], "Right$"),
    ("instr", ['I = InStr(S, "x")'], "InStr"),
    ("lcase", ["S = LCase$(S)"], "LCase$"),
    ("ucase", ["S = UCase$(S)"], "UCase$"),
    ("ltrim", ["S = LTrim$(S)"], "LTrim$"),
    ("trim", ["S = Trim$(S)"], "Trim$"),
    ("space", ["S = Space$(3)"], "Space$"),
    ("string", ['S = String$(3, "x")'], "String$"),
    ("str", ["S = Str$(I)"], "Str$"),
    ("val", ["D = Val(S)"], "Val"),
    ("hex", ["S = Hex$(I)"], "Hex$"),
    ("oct", ["S = Oct$(I)"], "Oct$"),
    ("abs", ["D = Abs(D)"], "Abs"),
    ("int", ["D = Int(D)"], "Int"),
    ("fix", ["D = Fix(D)"], "Fix"),
    ("sgn", ["I = Sgn(D)"], "Sgn"),
    ("sqr", ["D = Sqr(D)"], "Sqr"),
    ("sin", ["D = Sin(D)"], "Sin"),
    ("cos", ["D = Cos(D)"], "Cos"),
    ("tan", ["D = Tan(D)"], "Tan"),
    ("atn", ["D = Atn(D)"], "Atn"),
    ("exp", ["D = Exp(D)"], "Exp"),
    ("log", ["D = Log(D)"], "Log"),
    ("cint", ["I = CInt(D)"], "CInt"),
    ("clng", ["L = CLng(D)"], "CLng"),
    ("csng", ["D = CSng(D)"], "CSng"),
    ("cdbl", ["D = CDbl(I)"], "CDbl"),
    ("ccur", ["V = CCur(D)"], "CCur"),
    ("cstr", ["S = CStr(D)"], "CStr"),
    ("cvar", ["V = CVar(D)"], "CVar"),
    ("isnull", ["I = IsNull(V)"], "IsNull"),
    ("isempty", ["I = IsEmpty(V)"], "IsEmpty"),
    ("isnumeric", ["I = IsNumeric(V)"], "IsNumeric"),
    ("isdate", ["I = IsDate(V)"], "IsDate"),
    ("vartype", ["I = VarType(V)"], "VarType"),
    ("lbound", ["I = LBound(A)"], "LBound"),
    ("ubound", ["I = UBound(A)"], "UBound"),
    ("err_fn", ["I = Err"], "Err"),
    ("error_fn", ["S = Error$"], "Error$"),
]

HEADER = [
    "Option Explicit",
    "",
    "Global Mark As String",
    "Global Tmp As Variant",
    "Global S As String",
    "Global I As Integer",
    "Global L As Long",
    "Global D As Double",
    "Global V As Variant",
    "Global A() As Integer",
    "",
]


def main():
    lines = HEADER + ["Sub Main ()", "    ReDim A(1 To 3)"]
    lines += [f"    Case_{name}" for name, _, _ in CASES if name != "end_stmt"] + ["End Sub", ""]
    for name, body, _ in CASES:
        lines += [f"Sub Case_{name} ()", f'    Mark = "CASE {name}"']
        lines += ["    " + b for b in body]
        lines += ["End Sub", ""]
    with open(os.path.join(HERE, "STMTS.BAS"), "w", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")
    form = open(os.path.join(HERE, "..", "types", "FORM1.FRM"), newline="").read()
    form = form[:form.index("Sub Command1_Click")] + "Sub Form_Load ()\r\n    Main\r\nEnd Sub\r\n"
    with open(os.path.join(HERE, "FORM1.FRM"), "w", newline="") as f:
        f.write(form)
    with open(os.path.join(HERE, "STMTS.MAK"), "w", newline="\r\n") as f:
        f.write("\n".join(["FORM1.FRM", "STMTS.BAS", "ProjWinSize=152,402,248,215", "ProjWinShow=2",
                           'Title="Stmts"', 'ExeName="STMTS.EXE"']) + "\n")
    with open(os.path.join(HERE, "expected.json"), "w") as f:
        json.dump({"program": "STMTS.MAK", "cases": {n: k for n, _, k in CASES}}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(len(CASES), "cases")


if __name__ == "__main__":
    main()
