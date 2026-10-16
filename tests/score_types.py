"""Score variable storage and type recovery against a compiled ground-truth program.

Usage: python3 tests/score_types.py TYPES.EXE [tests/vb3/types/expected.json] [--strict]

Each case procedure assigns the marker string "CASE <name>" to a global and has
exactly one other variable, the one under test. The report counts matches by
the evidence that produced each type (recorded, inferred, conflict, unknown).
With --strict, any mismatch on a case whose type was recorded exits 1.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")
DEFAULT_EXPECTED = os.path.join(ROOT, "tests", "vb3", "types", "expected.json")


def load_tool():
    spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
    vb3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb3)
    return vb3


def score(exe, expected_path):
    vb3 = load_tool()
    with open(exe, "rb") as f:
        data = f.read()
    tables = os.path.dirname(SCRIPT)
    analysis, err = vb3.analyze(data, tables, [os.path.dirname(os.path.abspath(exe))])
    if analysis is None:
        raise SystemExit(f"{exe}: {err}")
    with open(expected_path) as f:
        cases = json.load(f)["cases"]

    markers = {}
    for _, _, recs in analysis["procs"]:
        for rec in recs:
            if rec["str"] is not None and rec["str"].startswith(b"CASE "):
                markers[rec["str"][5:].decode("latin1")] = recs[0]["off"]

    variables = analysis["variables"]
    # Mark and Tmp, the globals every case procedure uses, are not under test.
    globals_ = sorted((v for v in variables.vars.values() if v.storage == "global"),
                      key=lambda v: -len(v.procs))
    shared = set(globals_[:2])
    results = []
    for name, want in sorted(cases.items()):
        start = markers.get(name)
        if start is None:
            results.append((name, "missing", None, want, "case procedure not found"))
            continue
        under_test = [v for v in variables.by_proc.get(start, ()) if v not in shared]
        if len(under_test) != 1:
            got = ", ".join(f"{v.name}:{v.storage}:{v.type}" for v in under_test)
            results.append((name, "ambiguous", None, want, f"{len(under_test)} variables: {got}"))
            continue
        v = under_test[0]
        got = {"storage": v.storage, "type": v.type}
        if "array" in want:
            got["array"] = v.array
        if "name" in want:
            got["name"] = v.name
        ok = all(got.get(k) == want[k] for k in want)
        detail = f"{v.name} {v.storage} {v.type or '?'}"
        if v.recorded or v.inferred:
            detail += f" recorded={dict(v.recorded)} inferred={ {t: sorted(r) for t, r in v.inferred.items()} }"
        results.append((name, "ok" if ok else "wrong", v.type_source, want, detail))
    return results


def main(argv):
    strict = "--strict" in argv
    args = [a for a in argv if a != "--strict"]
    if not args:
        raise SystemExit(__doc__)
    exe = args[0]
    expected = args[1] if len(args) > 1 else DEFAULT_EXPECTED
    results = score(exe, expected)
    totals = {}
    for name, status, source, want, detail in results:
        key = source or "unknown"
        t = totals.setdefault(key, [0, 0])
        t[0] += status == "ok"
        t[1] += 1
        mark = {"ok": "  ", "wrong": "XX", "missing": "??", "ambiguous": "!!"}[status]
        print(f"{mark} {name:<26} want {want}  got {detail}")
    print()
    for source, (ok, n) in sorted(totals.items()):
        print(f"{source:<10} {ok}/{n}")
    ok = sum(t[0] for t in totals.values())
    print(f"{'total':<10} {ok}/{len(results)}")
    if strict and any(status != "ok" and source == "recorded" for _, status, source, _, _ in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
