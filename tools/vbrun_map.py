"""Map VB3 p-code tokens to the Win16 and DOS functions their handlers reach.

Usage:
    python3 tools/vbrun_map.py VBRUN300.DLL PROGRAM [PROGRAM ...] [-o vbrun-map.json]
        [--ghidra GHIDRA_INSTALL] [--max-depth 8]

PROGRAM is a VB3 EXE or DisassembleVB3PCode.py --json output; the tokens it
uses are mapped. Pass the map to DisassembleVB3PCode.py --runtime-map (or put
vbrun-map.json next to the EXE for the Ghidra script).

P-code tokens are near offsets of their handlers in VBRUN300.DLL's
interpreter segment, whose handlers end by dispatching the next token with
`es: lodsw ; jmp ax`. Each handler's code is walked with capstone:

- jumps are followed, conditional jumps on both edges, and near jump tables
  `jmp cs:[bx + disp]` when a `cmp bx, N` bound precedes them;
- near and far calls are followed one call level deeper, through NE
  relocations for far calls and imports;
- the walk continues after a call only when the callee returns. Interpreter
  helpers often do not: some end in the next-token dispatch. A callee returns
  when some path ends in ret/retf, or in `jmp reg` through a register it popped;
- handlers that call a helper with an inline runtime-function number are
  followed through the helper's dispatch tables, parsed from the runtime's
  own code;
- `push <selector> ; push <offset>` far pointers passed to callees are
  treated as possible callbacks;
- DOS3Call (KERNEL.102) and INT 21h are named by the AH function, carried
  into callees when a caller loads it.

Results are reachability, not calls every execution makes. Indirect jumps and
calls the walk cannot resolve are counted per token. Import ordinals are named
from Ghidra's win16 .exports files.

Requires capstone.
"""
import collections
import glob
import json
import os
import re
import struct
import sys

import capstone

DISPATCH = b"\x26\xad\xff\xe0"   # es: lodsw ; jmp ax
RETURNS = ("ret", "retf", "iret")


class NeImage:
    def __init__(self, path):
        d = self.d = open(path, "rb").read()
        ne = struct.unpack_from("<H", d, 0x3C)[0]
        st = ne + struct.unpack_from("<H", d, ne + 0x22)[0]
        sh = struct.unpack_from("<H", d, ne + 0x32)[0]
        n = struct.unpack_from("<H", d, ne + 0x1C)[0]
        mods_at = ne + struct.unpack_from("<H", d, ne + 0x28)[0]
        names_at = ne + struct.unpack_from("<H", d, ne + 0x2A)[0]
        self.modules = {}
        for i in range(struct.unpack_from("<H", d, ne + 0x1E)[0]):
            o = names_at + struct.unpack_from("<H", d, mods_at + 2 * i)[0]
            self.modules[i + 1] = d[o + 1:o + 1 + d[o]].decode("latin1")
        self.segs = {}
        for k in range(n):
            so, sz, fl, _ = struct.unpack_from("<HHHH", d, st + 8 * k)
            self.segs[k + 1] = (so << sh, sz or 0x10000, fl)
        self._rel = {}

    def code(self, seg):
        so, sz, _ = self.segs.get(seg, (0, 0, 0))
        return self.d[so:so + sz] if so else b""

    def relocs(self, seg):
        """{fixup offset: target} with non-additive chains expanded."""
        if seg in self._rel:
            return self._rel[seg]
        out = {}
        so, sz, fl = self.segs[seg]
        if so and fl & 0x100:
            data = self.d[so:so + sz]
            at = so + sz
            for i in range(struct.unpack_from("<H", self.d, at)[0]):
                _src, flags, off, a, b = struct.unpack_from("<BBHHH", self.d, at + 2 + 8 * i)
                kind = flags & 3
                tgt = ("internal", a, b) if kind == 0 else ("import", a, b) if kind == 1 else ("other", a, b)
                hops = 0
                while off != 0xFFFF and off + 2 <= len(data) and hops < 4096:
                    out[off] = tgt
                    if flags & 4:
                        break
                    off = struct.unpack_from("<H", data, off)[0]
                    hops += 1
        self._rel[seg] = out
        return out

    def interpreter_segment(self):
        return max(self.segs, key=lambda s: self.code(s).count(DISPATCH))


def _imm(text):
    try:
        return int(text, 16) & 0xFFFF
    except ValueError:
        return None


def win16_names(ghidra_root):
    """{(MODULE, ordinal): NAME} from Ghidra's bundled win16 .exports files."""
    names = {}
    for path in glob.glob(os.path.join(ghidra_root, "Ghidra/Features/Base/data/symbols/win16/*.exports")):
        text = open(path, encoding="latin1").read()
        lib = re.search(r'<LIBRARY NAME="([^"]+)"', text)
        mod = os.path.splitext(lib.group(1))[0].upper() if lib else os.path.basename(path).split(".")[0].upper()
        for ordinal, name in re.findall(r'ORDINAL="(\d+)" NAME="([^"]+)"', text):
            names[(mod, int(ordinal))] = name
    for ordinal, name in KEYBOARD_NAMES.items():
        names.setdefault(("KEYBOARD", ordinal), name)
    return names


DOS3CALL = 102   # KERNEL.102: DOS3Call, Win16's INT 21h entry; the function is in AH
# KEYBOARD ordinals absent from Ghidra's win16 tables (Windows 3.x SDK)
KEYBOARD_NAMES = {5: "ANSITOOEM", 6: "OEMTOANSI", 134: "ANSITOOEMBUFF", 135: "OEMTOANSIBUFF"}

# Interpreter helper that reads a runtime-function number inline after the
# call: pop bx ; xor ax, ax ; mov al, cs:[bx]
INLINE_INDEX = bytes([0x5B, 0x33, 0xC0, 0x2E, 0x8A, 0x07])


class Walker:
    def __init__(self, img, max_depth=4, budget=60000):
        self.img = img
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        self.max_depth, self.budget = max_depth, budget
        self._returns = {}
        self._helpers = {}
        self._dispatch = None

    def _follow_jumps(self, seg, pc, hops=4):
        """Address reached from pc through plain `mov`/`jmp` instructions."""
        for _ in range(hops):
            code = self.img.code(seg)
            if code[pc:pc + len(INLINE_INDEX)] == INLINE_INDEX:
                return pc
            ins = self._decode(seg, pc)
            if ins is None:
                return None
            if ins.mnemonic == "jmp":
                t = _imm(ins.op_str)
                if t is None:
                    return None
                pc = t
            elif ins.mnemonic == "mov":
                pc += ins.size
            else:
                return None
        return pc if self.img.code(seg)[pc:pc + len(INLINE_INDEX)] == INLINE_INDEX else None

    def inline_helper(self, seg, target):
        """('ends' | 'returns', reader address) when target reads an inline
        runtime-function number, else None. The 'returns' variant advances past
        the operand (inc bx) and resumes the caller after it."""
        key = (seg, target)
        if key not in self._helpers:
            reader = self._follow_jumps(seg, target)
            kind = None
            if reader is not None:
                kind = "returns" if self.img.code(seg)[reader + 6] == 0x43 else "ends"   # inc bx
            self._helpers[key] = (kind, reader) if kind else None
        return self._helpers[key]

    def _dispatchers(self, seg, reader):
        """[(lowest BX, segment, table displacement)] parsed from the code that
        follows the inline read: cmp bx, X ; jae L ... ljmp seg:dispatcher,
        each dispatcher being `jmp word ptr cs:[bx + disp]`."""
        if self._dispatch is not None:
            return self._dispatch
        pc = reader
        for _ in range(12):                       # find the jump to the shared dispatch code
            ins = self._decode(seg, pc)
            if ins is None:
                break
            if ins.mnemonic == "jne":
                pc = _imm(ins.op_str)
                break
            pc += ins.size
        bounds, out, lower = [], [], 0
        for _ in range(40):
            ins = self._decode(seg, pc)
            if ins is None:
                break
            if ins.mnemonic == "cmp" and ins.op_str.startswith("bx, "):
                lower = _imm(ins.op_str[4:])
            elif ins.mnemonic == "jae":
                bounds.append((lower, _imm(ins.op_str)))
            elif ins.mnemonic == "ljmp":
                out.append(pc)
                if len(out) > len(bounds):
                    break
            pc += ins.size
        targets = []
        for at in [out[0]] + [t for _, t in bounds]:
            pc = at
            while True:
                ins = self._decode(seg, pc)
                if ins is None or ins.mnemonic == "ljmp":
                    break
                pc += ins.size
            if ins is None:
                continue
            tgt = self.far_target(seg, pc)
            if not tgt or tgt[0] != "internal":
                continue
            literal = struct.unpack_from("<H", self.img.code(seg), pc + 1)[0]
            jmp = self._decode(tgt[1], literal)
            m = re.search(r"cs:\[bx ([+-]) (0x[0-9a-f]+)\]", jmp.op_str if jmp else "")
            if m:
                disp = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                targets.append((tgt[1], disp))
        lows = [0] + [b for b, _ in bounds]
        self._dispatch = sorted(zip(lows, [t[0] for t in targets], [t[1] for t in targets]), reverse=True)
        return self._dispatch

    def _jump_table(self, seg, op, bound):
        """Targets of `jmp word ptr cs:[bx + disp]` when a `cmp bx, N` bound
        check precedes it (BX is a doubled index, so N // 2 + 1 entries)."""
        m = re.fullmatch(r"word ptr cs:\[bx \+ (0x[0-9a-f]+)\]", op)
        if not m or bound is None or bound > 0x200:
            return None
        code, disp = self.img.code(seg), int(m.group(1), 16)
        targets = []
        for i in range(bound // 2 + 1):
            at = disp + 2 * i
            if at + 2 > len(code):
                break
            target = struct.unpack_from("<H", code, at)[0]
            if target >= len(code):
                return None    # not a table of offsets in this segment
            targets.append(target)
        return targets

    def runtime_function(self, seg, ret, reader):
        """(segment, offset, operand bytes) of the routine named inline at ret."""
        code = self.img.code(seg)
        n, size = code[ret] + 1, 1
        if n == 0x100:
            n, size = code[ret + 1], 2
        bx = (n & 0xFF) * 2
        for low, dseg, disp in self._dispatchers(seg, reader):
            if bx >= low:
                table = self.img.code(dseg)
                at = (bx + disp) & 0xFFFF
                return dseg, struct.unpack_from("<H", table, at)[0], size
        return None

    def _decode(self, seg, pc):
        code = self.img.code(seg)
        if pc >= len(code):
            return None
        return next(self.md.disasm(code[pc:pc + 16], pc, 1), None)

    def far_target(self, seg, pc):
        """Target of a 5-byte far call/jump at pc: ('import', mod, ord) or ('internal', seg, off)."""
        code, rel = self.img.code(seg), self.img.relocs(seg)
        tgt = rel.get(pc + 1)
        if tgt is None and pc + 3 in rel:
            kind, a, b = rel[pc + 3]
            tgt = (kind, a, struct.unpack_from("<H", code, pc + 1)[0]) if kind == "internal" else rel[pc + 3]
        return tgt

    def returns(self, seg, off, _stack=None):
        """True when some path of the routine at seg:off returns to its caller
        (ret/retf, `jmp reg` through a popped return address, or a path the
        walk cannot follow). Paths ending in the next-token dispatch do not."""
        key = (seg, off)
        if key in self._returns:
            return self._returns[key]
        stack = _stack if _stack is not None else set()
        if key in stack:
            return True
        stack.add(key)
        result = False
        for edge in self._routine(seg, off, stack=stack):
            if edge[0] == "end" and edge[1] in ("return", "indirect jump", "indirect call", "undecodable"):
                result = True
                break
            if edge[0] == "tail" and edge[1] and edge[1][0] == "internal" and edge[1][1] != 0xFF \
                    and self.returns(edge[1][1], edge[1][2], stack):
                result = True
                break
        stack.discard(key)
        self._returns[key] = result
        return result

    def reach(self, seg, off):
        """({(module, ordinal): call depth}, Counter of path ends) reachable from seg:off.

        The AH value a caller loaded is carried into its callees: DOS routines
        are often shared, with each entry loading the function number into AH
        and the shared body passing it down (VBRUN300's ChDir/MkDir/RmDir).
        """
        imports, ends = {}, collections.Counter()
        seen, frontier, steps = set(), [(seg, off, None)], 0
        for depth in range(self.max_depth + 1):
            nxt = []
            for s, o, hint in frontier:
                if (s, o, hint) in seen or steps > self.budget:
                    continue
                seen.add((s, o, hint))
                for edge in self._routine(s, o, hint):
                    steps += 1
                    if edge[0] == "int":
                        imports.setdefault((f"INT{edge[1]:02X}h", edge[2]), depth)
                        continue
                    if edge[0] == "end":
                        ends[edge[1]] += 1
                    elif edge[1] is None:
                        ends["unrelocated far"] += 1
                    elif edge[1][0] == "import":
                        mod = self.img.modules.get(edge[1][1], str(edge[1][1]))
                        key = (mod, edge[1][2])
                        if key == ("KERNEL", DOS3CALL):
                            ah = edge[3] if len(edge) > 3 and edge[3] is not None else hint
                            key = ("DOS3CALL", ah)    # INT 21h function in AH
                        imports.setdefault(key, depth + (1 if edge[0] == "call" else 0))
                    elif edge[1][0] == "internal" and edge[1][1] != 0xFF:
                        ah = edge[3] if len(edge) > 3 and edge[3] is not None else hint
                        (nxt if edge[0] in ("call", "callback") else frontier).append((edge[1][1], edge[1][2], ah))
                        if edge[0] == "callback":
                            ends["callback"] += 1
            frontier = nxt
        return imports, ends

    def _routine(self, seg, start, ah=None, stack=None):
        """Edges of a routine, continuing after a call only when the callee
        returns. stack guards the returns() recursion against cycles."""
        seen, work = set(), [(start, ah)]
        while work:
            pc, ah = work.pop()
            for edge in self._linear(seg, pc, seen, ah):
                if edge[0] == "call" and edge[1] and edge[1][0] == "internal" and edge[1][1] == seg:
                    helper = self.inline_helper(seg, edge[1][2])
                    if helper is not None:
                        kind, reader = helper
                        fn = self.runtime_function(seg, edge[2], reader)
                        if fn is not None:
                            yield ("call", ("internal", fn[0], fn[1]), None, edge[3])
                            if kind == "returns":
                                work.append((edge[2] + fn[2], edge[3]))
                        break
                if edge[0] == "call":
                    yield edge
                    tgt = edge[1]
                    if tgt and tgt[0] == "internal" and tgt[1] != 0xFF and not self.returns(tgt[1], tgt[2], stack):
                        break
                    work.append((edge[2], edge[3]))
                    break
                if edge[0] == "branch":
                    work.append((edge[1], edge[2]))
                    continue
                if edge[0] == "callback":
                    yield edge
                    continue
                yield edge
                if edge[0] in ("end", "tail"):
                    break

    def _linear(self, seg, pc, seen, ah=None):
        popped = set()
        pushed_segment = None   # segment whose selector the previous instruction pushed
        bound = None            # last `cmp bx, N` (a jump-table bound check)
        # ah: DOS function number most recently loaded into AH (or inherited)
        # Paths are distinguished by the AH they carry: shared DOS call sites
        # are reached with different function numbers.
        while (seg, pc, ah) not in seen:
            seen.add((seg, pc, ah))
            ins = self._decode(seg, pc)
            if ins is None:
                yield ("end", "undecodable")
                return
            m, op = ins.mnemonic, ins.op_str
            nxt = pc + ins.size
            if m == "pop":
                popped.add(op)
            # push <selector fixup> ; push <offset> builds a far pointer to a
            # routine passed as an argument (called back by the callee).
            if m == "push" and ins.size == 3:
                fix = self.img.relocs(seg).get(pc + 1)
                if fix and fix[0] == "internal" and fix[1] != 0xFF:
                    pushed_segment = fix[1]
                    pc = nxt
                    continue
                if pushed_segment is not None:
                    yield ("callback", ("internal", pushed_segment, _imm(op)), None, ah)
            pushed_segment = None
            if m == "cmp" and op.startswith("bx, "):
                bound = _imm(op[4:])
            if m == "mov" and op.startswith("ah, "):
                ah = _imm(op[4:])
            elif m == "mov" and op.startswith("ax, "):
                imm = _imm(op[4:])
                ah = imm >> 8 if imm is not None else None
            elif m in ("inc", "dec") and op == "ah" and ah is not None:
                ah = (ah + (1 if m == "inc" else -1)) & 0xFF
            elif m in ("add", "sub") and op.startswith("ah, ") and ah is not None and _imm(op[4:]) is not None:
                ah = (ah + (_imm(op[4:]) if m == "add" else -_imm(op[4:]))) & 0xFF
            elif m == "int":
                yield ("int", _imm(op), ah)
            if m in RETURNS:
                yield ("end", "return")
                return
            if m in ("lcall", "ljmp") and ins.size == 5:
                tgt = self.far_target(seg, pc)
                yield ("call", tgt, nxt, ah) if m == "lcall" else ("tail", tgt)
                return
            if m in ("call", "jmp") or m.startswith("j") or m.startswith("loop"):
                try:
                    target = int(op, 16) & 0xFFFF
                except ValueError:
                    if m == "jmp":
                        table = self._jump_table(seg, op, bound)
                        if table:
                            for target in table:
                                yield ("branch", target, ah)
                            return
                        kind = "dispatch" if op == "ax" else "return" if op in popped else "indirect jump"
                        yield ("end", kind, seg, pc, op)
                        return
                    yield ("end", "indirect call")
                    pc = nxt
                    continue
                if m == "call":
                    yield ("call", ("internal", seg, target), nxt, ah)
                    return
                if m == "jmp":
                    pc = target
                    continue
                yield ("branch", target, ah)
            pc = nxt


DOS_FUNCTIONS = {
    0x0E: "select-disk", 0x19: "get-disk", 0x1A: "set-dta", 0x25: "set-vector", 0x2A: "get-date",
    0x2B: "set-date", 0x2C: "get-time", 0x2D: "set-time", 0x2F: "get-dta", 0x30: "get-version",
    0x35: "get-vector", 0x36: "disk-free", 0x39: "mkdir", 0x3A: "rmdir", 0x3B: "chdir", 0x3C: "create",
    0x3D: "open", 0x3E: "close", 0x3F: "read", 0x40: "write", 0x41: "delete", 0x42: "seek",
    0x43: "attributes", 0x44: "ioctl", 0x45: "dup", 0x47: "getcwd", 0x4C: "exit", 0x4E: "findfirst",
    0x4F: "findnext", 0x56: "rename", 0x57: "file-time", 0x59: "extended-error", 0x5C: "lock",
    0x0D: "disk-reset",
}
MAP_SCHEMA = "ghidra-vb3/runtime-map-v1"
SHARED_FRACTION = 0.25
UNRESOLVED = ("indirect jump", "indirect call", "undecodable", "unrelocated far")


def call_entry(key, depth, names):
    """Map entry for a reached import, DOS function or interrupt."""
    kind, value = key
    if kind in ("DOS3CALL", "INT21h"):
        fn = DOS_FUNCTIONS.get(value, f"{value:#04x}") if value is not None else "unknown"
        return {"name": f"DOS.{fn}", "via": "KERNEL.DOS3CALL" if kind == "DOS3CALL" else "INT 21h",
                "dos_function": value, "depth": depth}
    if kind.startswith("INT"):
        return {"name": f"{kind}.{value if value is not None else 'unknown'}", "depth": depth}
    name = names.get(key)
    return {"name": f"{kind}.{name or '#' + str(value)}", "module": kind, "ordinal": value, "depth": depth}


def program_tokens(path):
    """{token: keyword} used by a VB3 EXE or a DisassembleVB3PCode --json file."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:1] == b"{":
        prog = json.loads(data)
        return {t["token"]: t["keyword"].strip() for p in prog["procedures"] for t in p.get("tokens", ())}, prog["target"]["sha256"]
    import hashlib
    import importlib.util
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ghidra_scripts", "DisassembleVB3PCode.py")
    spec = importlib.util.spec_from_file_location("vb3pcode", script)
    vb3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb3)
    analysis, err = vb3.analyze(data, os.path.dirname(script), [])
    if analysis is None:
        raise SystemExit(f"{path}: {err}")
    return {r["tok"]: r["kw"].strip() for _, _, recs in analysis["procs"] for r in recs}, hashlib.sha256(data).hexdigest()


def build_map(vbrun, programs, ghidra=None, max_depth=8):
    import hashlib
    img = NeImage(vbrun)
    names = win16_names(ghidra) if ghidra else {}
    seg = img.interpreter_segment()
    tokens, sources = {}, []
    for path in programs:
        toks, sha = program_tokens(path)
        tokens.update(toks)
        sources.append({"path": os.path.abspath(path), "sha256": sha})
    walker = Walker(img, max_depth=max_depth, budget=400000)
    reached = {tok: walker.reach(seg, tok) for tok in sorted(tokens)}
    entries = {tok: [call_entry(k, d, names) for k, d in imps.items()] for tok, (imps, _) in reached.items()}
    reaching = [tok for tok, calls in entries.items() if calls]
    counts = collections.Counter(c["name"] for tok in reaching for c in entries[tok])
    shared = {n for n, k in counts.items() if k > SHARED_FRACTION * max(len(reaching), 1)}
    return {
        "schema": MAP_SCHEMA,
        "tool": {"name": "ghidra-vb3 vbrun_map"},
        "runtime": {"path": os.path.abspath(vbrun), "size": len(img.d), "sha256": hashlib.sha256(img.d).hexdigest()},
        "interpreter_segment": seg,
        "max_depth": max_depth,
        "shared_fraction": SHARED_FRACTION,
        "programs": sources,
        "shared": sorted(shared),
        "tokens": {
            f"{tok:#06x}": {
                "keyword": tokens[tok],
                "calls": sorted(({**c, "shared": c["name"] in shared} for c in entries[tok]),
                                key=lambda c: (c["depth"], c["name"])),
                "unresolved": {k: n for k, n in reached[tok][1].items() if k in UNRESOLVED},
            }
            for tok in sorted(tokens)
        },
    }


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Map VB3 p-code tokens to the Win16/DOS calls they reach.")
    ap.add_argument("vbrun", help="VBRUN300.DLL")
    ap.add_argument("programs", nargs="+", help="VB3 EXEs or DisassembleVB3PCode.py --json files")
    ap.add_argument("-o", "--output", default="vbrun-map.json")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"),
                    help="Ghidra installation, for Win16 ordinal names (default $GHIDRA_INSTALL_DIR)")
    ap.add_argument("--max-depth", type=int, default=8)
    args = ap.parse_args(argv)
    result = build_map(args.vbrun, args.programs, args.ghidra, args.max_depth)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=1)
    mapped = sum(1 for t in result["tokens"].values() if t["calls"])
    print(f"{args.output}: {len(result['tokens'])} tokens, {mapped} reach a call, {len(result['shared'])} shared")


if __name__ == "__main__":
    main(sys.argv[1:])
