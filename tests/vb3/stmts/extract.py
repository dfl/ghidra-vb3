"""Report the p-code tokens the VB3 compiler emitted for each STMTS.EXE case.

Usage: python3 tests/vb3/stmts/extract.py STMTS.EXE [--json OUT]

For each case procedure, the statement's tokens are those not in the baseline
case (which only assigns the marker) and not operand plumbing
(DisassembleVB3PCode.PLUMBING_KEYWORDS). Each token is shown with the keyword the
VBDIS3 token table gives it, and checked against the keyword the case expects.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")
EXPECTED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected.json")


def norm(keyword):
    return keyword.strip().rstrip("(").strip().lower()


def main(argv):
    exe = argv[0]
    out_json = argv[argv.index("--json") + 1] if "--json" in argv else None
    spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
    vb3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb3)
    analysis, err = vb3.analyze(vb3.read_bytes(exe), os.path.dirname(SCRIPT), [])
    if analysis is None:
        raise SystemExit(err)
    expected = json.load(open(EXPECTED))["cases"]
    cases = {}
    for _, _, recs in analysis["procs"]:
        marker = next((r["str"][5:].decode("latin1") for r in recs if r["str"] and r["str"].startswith(b"CASE ")), None)
        if marker is not None:
            cases[marker] = [(r["tok"], r["kw"]) for r in recs]
    base = {t for t, _ in cases.get("baseline", [])}
    report, ok = {}, 0
    for name in sorted(expected):
        if name == "baseline":
            continue
        tokens = cases.get(name)
        if tokens is None:
            report[name] = {"status": "missing"}
            continue
        own = [(t, k) for t, k in tokens if t not in base and k.strip() not in vb3.PLUMBING_KEYWORDS]
        want = expected[name]
        match = want is not None and any(norm(k) == norm(want) for _, k in own)
        status = "match" if match else ("unlabelled" if want is None else "differs")
        ok += match
        report[name] = {"status": status, "expected": want,
                        "tokens": [{"token": f"{t:#06x}", "keyword": k.strip()} for t, k in own]}
        print(f"{'  ' if match else 'XX' if status == 'differs' else '--'} {name:<16} want {str(want):<12} "
              + ", ".join(f"{t:#06x}:{k.strip()}" for t, k in own))
    labelled = sum(1 for n, v in expected.items() if v is not None)
    print(f"\n{ok}/{labelled} cases decode to their expected keyword")
    if out_json:
        json.dump(report, open(out_json, "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1:])
