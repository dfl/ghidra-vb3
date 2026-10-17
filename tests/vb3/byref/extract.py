"""Report the temporary-reference token each BYREF.EXE temp_* case emits.

Usage: python3 tests/vb3/byref/extract.py BYREF.EXE

A temp_* case passes a constant to a ByRef parameter of a known type; the
compiler stores it in a temporary (numeric and Variant temporaries take a
negative frame offset operand) and passes the temporary's address. Each token
is checked against DisassembleVB3PCode.TEMP_REFERENCE_TYPES. Exits 1 on a
mismatch.
"""
import importlib.util
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")
EXPECTED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected.json")


def temporaries(exe):
    spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
    vb3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb3)
    analysis, err = vb3.analyze(vb3.read_bytes(exe), os.path.dirname(SCRIPT), [])
    if analysis is None:
        raise SystemExit(err)
    found = {}
    for _, _, recs in analysis["procs"]:
        marker = next((r["str"][5:].decode("latin1") for r in recs if r["str"] and r["str"].startswith(b"CASE ")), None)
        if marker and marker.startswith("temp_"):
            found[marker] = [r["tok"] for r in recs
                             if r["tok"] in vb3.TEMP_REFERENCE_TYPES or (
                                 (r.get("kw") or "").strip() == "exe" and r["str"] is None
                                 and len(r["params"]) in (2, 4) and struct.unpack_from("<h", r["params"])[0] < 0)]
    return vb3, found


def main(argv):
    vb3, found = temporaries(argv[0])
    expected = json.load(open(EXPECTED))["temporaries"]
    bad = 0
    for name, want in sorted(expected.items()):
        toks = found.get(name)
        got = [vb3.TEMP_REFERENCE_TYPES.get(t) for t in toks or ()]
        ok = toks is not None and len(toks) == 1 and got[0] == want
        bad += not ok
        print(f"{'  ' if ok else 'XX'} {name:<24} want {want:<9} tokens "
              + (", ".join(f"{t:#06x}={vb3.TEMP_REFERENCE_TYPES.get(t, 'unmapped')!r}" for t in toks)
                 if toks is not None else "case not found"))
    print(f"\n{len(expected) - bad}/{len(expected)} temporaries match")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
