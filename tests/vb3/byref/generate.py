"""Generate BYREF.MAK: argument passing cases for VB3 type propagation.

temp_* cases pass a constant to a ByRef parameter of each type; the compiler
stores it in a temporary of the parameter's type, so the token it emits names
that type (expected.json "temporaries"; extract.py reports the tokens).

The other cases each have one parameter under test, scored by
tests/score_types.py like tests/vb3/types: pass_* only pass it on to a typed
parameter, chain_* through a pass-through procedure, recv_* get it from a
typed caller variable, skip_* from constants next to a parameter the
procedure never references (so arguments bind by frame offset), and the
string cases use it as a ChDrive/Kill operand or a ByVal String DLL argument.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# (short name, VB type, typed literal)
TYPES = [
    ("int", "Integer", "1"),
    ("long", "Long", "100000"),
    ("single", "Single", "1.5!"),
    ("double", "Double", "2.25#"),
    ("currency", "Currency", "3.75@"),
    ("string", "String", '"x"'),
    ("variant", "Variant", "1"),
]

HEADER = [
    "Option Explicit",
    "",
    "Global Mark As String",
    "Global Tmp As Variant",
    "",
    'Declare Function GetWindowsDirectory Lib "Kernel" (ByVal lpBuffer As String, ByVal nSize As Integer) As Integer',
    "",
]


def proc(name, params, body):
    return [f"Sub {name} ({params})"] + ["    " + b for b in body] + ["End Sub", ""]


def case(name, params, body):
    return proc(f"Case_{name}", params, [f'Mark = "CASE {name}"'] + body)


def main():
    lines = list(HEADER)
    cases, temporaries, main_body = {}, {}, []
    for t, typ, lit in TYPES:
        lines += proc(f"Take_{t}", f"x As {typ}", ["Tmp = x"])
        lines += proc(f"Hole_{t}", f"x As {typ}", [])
        lines += proc(f"Pass_{t}", f"x As {typ}", [f"Take_{t} x"])
    for t, typ, lit in TYPES:
        lines += case(f"temp_{t}", "", [f"Take_{t} {lit}"])
        temporaries[f"temp_{t}"] = typ
        if lit != "1" and typ != "String":
            lines += case(f"temp_{t}_from_int", "", [f"Take_{t} 1"])
            temporaries[f"temp_{t}_from_int"] = typ
        lines += case(f"pass_{t}", f"x As {typ}", [f"Take_{t} x"])
        lines += case(f"chain_{t}", f"x As {typ}", [f"Pass_{t} x"])
        lines += case(f"recv_{t}", f"x As {typ}", [f"Hole_{t} x"])
        lines += case(f"skip_{t}", f"b As Long, x As {typ}", [f"Hole_{t} x"])
        lines += case(f"skip_byval_{t}", f"ByVal b As Integer, x As {typ}", [f"Hole_{t} x"])
        for c in ("pass", "chain", "recv", "skip", "skip_byval"):
            cases[f"{c}_{t}"] = {"storage": "param", "type": typ}
        main_body += [f"Dim a_{t} As {typ}", f"a_{t} = {lit}", f"Case_recv_{t} a_{t}",
                      f"Case_skip_{t} 1, {lit}", f"Case_skip_byval_{t} 1, {lit}"]
    lines += case("chdrive_string", "s As String", ["ChDrive s"])
    lines += case("kill_string", "s As String", ["Kill s"])
    lines += case("byval_string", "s As String", ["Tmp = GetWindowsDirectory(s, 10)"])
    for c in ("chdrive_string", "kill_string", "byval_string"):
        cases[c] = {"storage": "param", "type": "String"}
    lines += proc("Main", "", main_body)
    with open(os.path.join(HERE, "BYREF.BAS"), "w", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")
    form = open(os.path.join(HERE, "..", "stmts", "FORM1.FRM"), newline="").read()
    with open(os.path.join(HERE, "FORM1.FRM"), "w", newline="") as f:
        f.write(form.replace('"Types"', '"ByRef"'))
    with open(os.path.join(HERE, "BYREF.MAK"), "w", newline="\r\n") as f:
        f.write("\n".join(["FORM1.FRM", "BYREF.BAS", "ProjWinSize=152,402,248,215", "ProjWinShow=2",
                           'Title="ByRef"', 'ExeName="BYREF.EXE"']) + "\n")
    with open(os.path.join(HERE, "expected.json"), "w") as f:
        json.dump({"program": "BYREF.MAK", "cases": cases, "temporaries": temporaries},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    print(len(cases), "cases,", len(temporaries), "temporaries")


if __name__ == "__main__":
    main()
