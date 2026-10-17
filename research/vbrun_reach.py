"""Prototype: which Win16 functions can each VB3 p-code handler reach?

P-code tokens are near offsets of their handlers in VBRUN300.DLL's
interpreter segment, whose handlers end by dispatching the next token with
`es: lodsw ; jmp ax`. Given the tokens a program uses, this walks each
handler's code with capstone:

- jumps are followed; conditional jumps follow both edges;
- near and far calls are followed one call level deeper, through NE
  relocations for far calls and imports;
- the walk continues after a call only when the callee returns. Interpreter
  helpers often do not: some end in the next-token dispatch, and the bytes
  after the call are then not code. A callee returns when some path ends in
  ret/retf, or in `jmp reg` through a register it popped (helpers that pop
  their own return address to read stack arguments).

Indirect jumps and calls are not followed and are counted. Import ordinals are
named from Ghidra's win16 .exports files when a Ghidra installation is given.
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

    def edges(self, seg, start):
        """Walk one routine's flow from start without entering calls. Yields
        ('call', target, returns_after) for calls and ('end', kind) for path ends."""
        seen, work = set(), [start]
        while work:
            pc = work.pop()
            popped = set()
            while (seg, pc) not in seen:
                seen.add((seg, pc))
                ins = self._decode(seg, pc)
                if ins is None:
                    yield ("end", "undecodable")
                    break
                m, op = ins.mnemonic, ins.op_str
                nxt = pc + ins.size
                if m == "pop" and op in ("bx", "cx", "dx", "si", "di", "bp"):
                    popped.add(op)
                if m in RETURNS:
                    yield ("end", "return")
                    break
                if m in ("lcall", "ljmp") and ins.size == 5:
                    tgt = self.far_target(seg, pc)
                    if m == "ljmp":
                        yield ("tail", tgt)
                        break
                    yield ("call", tgt, nxt)
                    pc = nxt
                    continue
                if m in ("call", "jmp") or m.startswith("j") or m.startswith("loop"):
                    try:
                        target = int(op, 16) & 0xFFFF
                    except ValueError:
                        if m == "jmp" and op == "ax":
                            yield ("end", "dispatch")
                        elif m == "jmp" and op in popped:
                            yield ("end", "return")
                        elif m == "jmp":
                            yield ("end", "indirect jump")
                        else:
                            yield ("end", "indirect call")
                            pc = nxt
                            continue
                        break
                    if m == "call":
                        yield ("call", ("internal", seg, target), nxt)
                        pc = nxt
                        continue
                    if m == "jmp":
                        pc = target
                        continue
                    work.append(target)
                pc = nxt

    def returns(self, seg, off, _stack=None):
        """True when some path of the routine at seg:off returns to its caller."""
        key = (seg, off)
        if key in self._returns:
            return self._returns[key]
        stack = _stack or set()
        if key in stack:
            return True
        stack.add(key)
        result = False
        for edge in self.edges(seg, off):
            if edge[0] == "end" and edge[1] in ("return", "indirect jump", "indirect call", "undecodable"):
                result = True
                break
            if edge[0] == "tail" and edge[1] and edge[1][0] == "internal" and self.returns(edge[1][1], edge[1][2], stack):
                result = True
                break
        self._returns[key] = result
        return result

    def reach(self, seg, off):
        """({(module, ordinal): call depth}, Counter of path ends) reachable from seg:off."""
        imports, ends = {}, collections.Counter()
        seen, frontier, steps = set(), [(seg, off)], 0
        for depth in range(self.max_depth + 1):
            nxt = []
            for s, o in frontier:
                if (s, o) in seen or steps > self.budget:
                    continue
                seen.add((s, o))
                for edge in self._routine(s, o):
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
                        if key == ("KERNEL", DOS3CALL) and len(edge) > 3:
                            key = ("DOS3CALL", edge[3])    # INT 21h function in AH
                        imports.setdefault(key, depth + (1 if edge[0] == "call" else 0))
                    elif edge[1][0] == "internal" and edge[1][1] != 0xFF:
                        (nxt if edge[0] == "call" else frontier).append((edge[1][1], edge[1][2]))
            frontier = nxt
        return imports, ends

    def _routine(self, seg, start):
        """Edges of a routine, continuing after a call only when the callee returns."""
        seen, work = set(), [start]
        while work:
            pc = work.pop()
            for edge in self._linear(seg, pc, seen):
                if edge[0] == "call" and edge[1] and edge[1][0] == "internal" and edge[1][1] == seg:
                    helper = self.inline_helper(seg, edge[1][2])
                    if helper is not None:
                        kind, reader = helper
                        fn = self.runtime_function(seg, edge[2], reader)
                        if fn is not None:
                            yield ("call", ("internal", fn[0], fn[1]), None)
                            if kind == "returns":
                                work.append(edge[2] + fn[2])
                        break
                if edge[0] == "call":
                    yield edge
                    tgt = edge[1]
                    if tgt and tgt[0] == "internal" and tgt[1] != 0xFF and not self.returns(tgt[1], tgt[2]):
                        break
                    work.append(edge[2])
                    break
                if edge[0] == "branch":
                    work.append(edge[1])
                    continue
                yield edge
                if edge[0] in ("end", "tail"):
                    break

    def _linear(self, seg, pc, seen):
        popped = set()
        ah = None   # DOS function number most recently loaded into AH
        while (seg, pc) not in seen:
            seen.add((seg, pc))
            ins = self._decode(seg, pc)
            if ins is None:
                yield ("end", "undecodable")
                return
            m, op = ins.mnemonic, ins.op_str
            nxt = pc + ins.size
            if m == "pop":
                popped.add(op)
            if m == "mov" and op.startswith("ah, "):
                ah = _imm(op[4:])
            elif m == "mov" and op.startswith("ax, "):
                imm = _imm(op[4:])
                ah = imm >> 8 if imm is not None else None
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
                        yield ("end", "dispatch" if op == "ax" else "return" if op in popped else "indirect jump")
                        return
                    yield ("end", "indirect call")
                    pc = nxt
                    continue
                if m == "call":
                    yield ("call", ("internal", seg, target), nxt)
                    return
                if m == "jmp":
                    pc = target
                    continue
                yield ("branch", target)
            pc = nxt


def main(argv):
    vbrun, program_json = argv[0], argv[1]
    ghidra = argv[2] if len(argv) > 2 else ""
    img = NeImage(vbrun)
    names = win16_names(ghidra) if ghidra else {}
    seg = img.interpreter_segment()
    prog = json.load(open(program_json))
    tokens = {}
    for proc in prog["procedures"]:
        for t in proc.get("tokens", ()):
            tokens.setdefault(t["token"], t["keyword"].strip())
    walker = Walker(img)
    out = {}
    for tok, kw in sorted(tokens.items()):
        imports, ends = walker.reach(seg, tok)
        out[tok] = (kw, imports, ends)
    counts = collections.Counter(imp for _, imps, _ in out.values() for imp in imps)
    shared = {imp for imp, n in counts.items() if n > 0.25 * len(out)}
    return out, shared, names


if __name__ == "__main__":
    out, shared, names = main(sys.argv[1:])
    print(f"{len(out)} tokens, {len(shared)} shared imports")
    for tok, (kw, imps, ends) in sorted(out.items(), key=lambda kv: kv[1][0]):
        own = sorted(((d, f"{m}.{names.get((m, o), o)}") for (m, o), d in imps.items() if (m, o) not in shared))
        if own:
            print(f"{tok:#06x} {kw:<14} " + ", ".join(f"{n}@{d}" for d, n in own[:8]))
