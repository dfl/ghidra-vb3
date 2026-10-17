"""Build library signatures from a compiled VB3 program and its source.

Usage:
    python3 tools/vb3_signatures.py EXE SOURCE.BAS|.FRM [...] -o signatures.json
        [--library NAME]

Each source file's procedures, in file order, are the procedures of one code
module of EXE in code order (VB3 compiles a module's procedures in the order
of its source file). A module is paired with a source file when their
procedure counts agree and, at every position, Sub/Function agree and the
procedure references no more parameters than the source declares; each pairing
must be unique.

The output keeps only derived features (DisassembleVB3PCode.procedure_signature):
hashes of the operand-free token sequence, its token n-grams and its strings,
and the names of the DLL functions called. Pass it to DisassembleVB3PCode.py
--signatures, or put it next to an EXE as vb3-signatures.json for the Ghidra
script.
"""
import argparse
import collections
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")

PROC = re.compile(r"^(?:Static\s+)?(Sub|Function)\s+(\w+)\s*\(([^)]*)\)", re.M | re.I)


def load_tool():
    spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
    vb3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb3)
    return vb3


def source_procedures(path):
    """[(name, is_sub, declared parameter count)] in file order."""
    with open(path, encoding="latin1") as f:
        text = f.read()
    return [(m.group(2), m.group(1).lower() == "sub", len([p for p in m.group(3).split(",") if p.strip()]))
            for m in PROC.finditer(text)]


def binary_modules(analysis):
    """{module: [(recs, sub, referenced parameter count)]} in code order."""
    subs, variables = analysis["subs"], analysis["variables"]
    modules = collections.defaultdict(list)
    for _, _, recs in analysis["procs"]:
        sub = subs.proc_sub(recs)
        if sub is not None:
            modules[sub.module].append((recs, sub, len(variables.params(recs[0]["off"]))))
    return modules


def fits(procs, source):
    return len(procs) == len(source) and all(
        sub.is_sub == is_sub and nparams <= declared
        for (_, sub, nparams), (_, is_sub, declared) in zip(procs, source))


def build(vb3, exe, sources, library):
    with open(exe, "rb") as f:
        analysis, err = vb3.analyze(f.read(), os.path.dirname(SCRIPT), [os.path.dirname(os.path.abspath(exe))])
    if analysis is None:
        raise SystemExit(f"{exe}: {err}")
    modules = binary_modules(analysis)
    entries = []
    for path in sources:
        source = source_procedures(path)
        if not source:
            continue
        paired = [m for m, procs in modules.items() if fits(procs, source)]
        if len(paired) != 1:
            raise SystemExit(f"{path}: {len(source)} procedures pair with {len(paired)} code modules of {exe}")
        for (recs, _, _), (name, is_sub, declared) in zip(modules[paired[0]], source):
            sig = vb3.procedure_signature(recs)
            entries.append({"name": name, "source": os.path.basename(path), "kind": "sub" if is_sub else "function",
                            "params": declared, **sig})
    return {"schema": vb3.SIGNATURES_SCHEMA, "library": library, "built_from": os.path.basename(exe),
            "procedures": entries}


def main(argv):
    ap = argparse.ArgumentParser(description="Build VB3 library signatures.")
    ap.add_argument("exe")
    ap.add_argument("sources", nargs="+")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--library", help="library name shown with matches")
    args = ap.parse_args(argv)
    vb3 = load_tool()
    sigs = build(vb3, args.exe, args.sources, args.library or os.path.basename(args.exe))
    with open(args.output, "w") as f:
        json.dump(sigs, f, indent=1)
        f.write("\n")
    print(f"{args.output}: {len(sigs['procedures'])} procedures")


if __name__ == "__main__":
    main(sys.argv[1:])
