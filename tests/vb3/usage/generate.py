"""Generate USAGE.MAK: variables whose type only their use shows.

Each case procedure has one variable under test, scored by tests/score_types.py
like tests/vb3/types: for_* use it only as a For counter, elem_* (local,
module and global dynamic arrays) only through element stores and loads,
elemref_* pass an element ByRef to a typed parameter, and cmp_* compare a
parameter with the Integer literal 1.
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
NUMERIC = ("int", "long", "single", "double", "currency")


def proc(name, params, body):
    return [f"Sub {name} ({params})"] + ["    " + b for b in body] + ["End Sub", ""]


def case(name, params, body):
    return proc(f"Case_{name}", params, [f'Mark = "CASE {name}"'] + body)


def main():
    lines = ["Option Explicit", "", "Global Mark As String", "Global Tmp As Variant"]
    lines += [f"Global G_{t}() As {typ}" for t, typ, _ in TYPES]
    lines += [f"Dim M_{t}() As {typ}" for t, typ, _ in TYPES]
    lines += [f"Dim R_{t}() As {typ}" for t, typ, _ in TYPES]
    lines.append("")
    cases = {}
    for t, typ, lit in TYPES:
        lines += proc(f"Take_{t}", f"x As {typ}", ["Tmp = x"])
    for t, typ, lit in TYPES:
        if t in NUMERIC:
            lines += case(f"for_{t}", "", [f"Dim i As {typ}", "For i = 1 To 3", "Next i"])
            cases[f"for_{t}"] = {"storage": "local", "type": typ}
        lines += case(f"elem_local_{t}", "", [f"Dim a() As {typ}", "ReDim a(1 To 3)", f"a(1) = {lit}", "Tmp = a(2)"])
        lines += case(f"elem_module_{t}", "", ["ReDim M_%s(1 To 3)" % t, f"M_{t}(1) = {lit}", f"Tmp = M_{t}(2)"])
        lines += case(f"elem_global_{t}", "", ["ReDim G_%s(1 To 3)" % t, f"G_{t}(1) = {lit}", f"Tmp = G_{t}(2)"])
        lines += case(f"elemref_{t}", "", ["ReDim R_%s(1 To 3)" % t, f"Take_{t} R_{t}(1)"])
        one = '"1"' if t == "string" else "1"
        lines += case(f"cmp_{t}", f"x As {typ}", [f"If x = {one} Then Tmp = 0"])
        cases[f"elem_local_{t}"] = {"storage": "local", "type": typ, "array": True}
        for c in ("elem_module", "elemref"):
            cases[f"{c}_{t}"] = {"storage": "module", "type": typ, "array": True}
        cases[f"elem_global_{t}"] = {"storage": "global", "type": typ, "array": True}
        cases[f"cmp_{t}"] = {"storage": "param", "type": typ}
    lines += proc("Main", "", [f"Case_for_{t}" for t in NUMERIC])
    with open(os.path.join(HERE, "USAGE.BAS"), "w", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")
    form = open(os.path.join(HERE, "..", "stmts", "FORM1.FRM"), newline="").read()
    with open(os.path.join(HERE, "FORM1.FRM"), "w", newline="") as f:
        f.write(form.replace('"Types"', '"Usage"'))
    with open(os.path.join(HERE, "USAGE.MAK"), "w", newline="\r\n") as f:
        f.write("\n".join(["FORM1.FRM", "USAGE.BAS", "ProjWinSize=152,402,248,215", "ProjWinShow=2",
                           'Title="Usage"', 'ExeName="USAGE.EXE"']) + "\n")
    with open(os.path.join(HERE, "expected.json"), "w") as f:
        json.dump({"program": "USAGE.MAK", "cases": cases}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(len(cases), "cases")


if __name__ == "__main__":
    main()
