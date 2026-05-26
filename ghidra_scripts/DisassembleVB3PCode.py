## ###
# IP: NONE — public domain
#
# VB3 P-Code Disassembler for Ghidra
#
# Disassembles Visual Basic 3 p-code from a loaded binary.
# Requires VBDIS3 token table files (vbdis3i.dat + vbdis3x.dat)
# from a VBDIS3 installation (https://www.btinternet.com/~dodi/VBDIS3.zip).
#
# Scope: opcode + raw params per token only. No type inference,
# no VB source reconstruction (deliberately mirrors pcode.py's design).
#
# Usage:
#   1. Load your VB3 EXE into Ghidra as a raw binary, OR load a raw p-code dump.
#   2. Run this script via Script Manager.
#   3. Point it at your VBDIS3 directory when prompted.
#   4. For a VB3 EXE the script auto-detects p-code segments via the NE header.
#      For a raw dump, enter the hex offset and length when prompted.
#
# The script creates a plate comment + label for each detected procedure
# and an EOL comment on every token line.
#
# @category VB3
# @runtime PyGhidra
##

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import struct
import os

# ---------------------------------------------------------------------------
# Token table loader (port of loader.py)
# ---------------------------------------------------------------------------

FLAG_SIZE = 10837  # VBDIS_FlagTokenSize


class Token9Bit:
    __slots__ = ("m2d1c", "m2d22", "keyword_str_idx")

    def __init__(self, m2d1c, m2d22, keyword_str_idx):
        self.m2d1c = m2d1c
        self.m2d22 = m2d22
        self.keyword_str_idx = keyword_str_idx


def _load_i_dat(path):
    raw = open(path, "rb").read()
    str_len = struct.unpack_from("<h", raw, 0)[0]
    off = 2
    tokens = []
    for _ in range(512):
        a, b, c = struct.unpack_from("<hhh", raw, off)
        off += 6
        tokens.append(Token9Bit(a, b, c))
    m2d3c = list(struct.unpack_from("<97h", raw, off))
    off += 97 * 2
    vbdis_string = raw[off:off + str_len]
    return tokens, m2d3c, vbdis_string


def _load_x_dat(path, vb_ver=3):
    raw = open(path, "rb").read()
    ver_raw = struct.unpack_from("<h", raw, 0)[0]
    ver_check = ver_raw ^ (vb_ver * 0x100)
    assert ver_check == 2, f"VBDIS3 version mismatch (got {ver_check}); wrong dat file?"
    off = 2
    flag_token = list(struct.unpack_from(f"<{FLAG_SIZE + 1}h", raw, off))
    off += (FLAG_SIZE + 1) * 2
    control_token = raw[off:off + FLAG_SIZE * 3]
    off += FLAG_SIZE * 3
    t2_size = struct.unpack_from("<h", raw, off)[0]
    off += 2
    flag_token2 = raw[off:off + t2_size]
    return flag_token, control_token, flag_token2


def _get_keyword(tokens, vbdis_string, idx):
    if idx <= 0:
        return ""
    start = idx - 1
    end = vbdis_string.find(b"\xa7", start)
    if end < 0:
        end = len(vbdis_string)
    return vbdis_string[start:end].decode("latin1", errors="replace")


# ---------------------------------------------------------------------------
# NE (New Executable) header parser
# ---------------------------------------------------------------------------

def parse_ne_segments(data):
    """Parse a VB3 NE executable and return CODE segment list.

    Returns list of dicts: {seg_num, file_off, file_size, flags}
    Only segments with file data (lsec != 0) are included.
    """
    if data[:2] != b"MZ":
        return None, "Not an MZ executable"

    e_lfanew = struct.unpack_from("<H", data, 0x3C)[0]
    if e_lfanew + 4 > len(data):
        return None, "e_lfanew out of range"

    ne_off = e_lfanew
    if data[ne_off:ne_off + 2] != b"NE":
        return None, f"Expected NE signature at {ne_off:#x}, got {data[ne_off:ne_off+2]!r}"

    n_segs      = struct.unpack_from("<H", data, ne_off + 0x1C)[0]
    seg_tbl_off = struct.unpack_from("<H", data, ne_off + 0x22)[0]
    shift       = struct.unpack_from("<H", data, ne_off + 0x32)[0]
    sector_size = 1 << shift

    seg_tbl = ne_off + seg_tbl_off
    segments = []
    for i in range(n_segs):
        base = seg_tbl + i * 8
        lsec, fsize, flags, _ = struct.unpack_from("<HHHH", data, base)
        if lsec == 0:
            continue  # no file data (BSS / pure-virtual segment)
        file_off  = lsec * sector_size
        file_size = fsize if fsize != 0 else 0x10000
        is_data   = bool(flags & 0x0001)
        if not is_data:
            segments.append({
                "seg_num": i + 1,
                "file_off": file_off,
                "file_size": file_size,
                "flags": flags,
            })

    return segments, None


# ---------------------------------------------------------------------------
# Disassembler (port of pcode.py)
# ---------------------------------------------------------------------------

CASE_START   = 5
CASE_FINISH  = 4
CASE_SPECIAL = 8


def _signed16(v):
    return v - 0x10000 if v >= 0x8000 else v


class VB3Disasm:
    def __init__(self, vbdis_dir, data):
        tokens, _, vbstr = _load_i_dat(os.path.join(vbdis_dir, "vbdis3i.dat"))
        flag_token, _, _ = _load_x_dat(os.path.join(vbdis_dir, "vbdis3x.dat"))
        self.tokens = tokens
        self.vbstr = vbstr
        self.flag_token = flag_token
        self.data = data

    def convert_token(self, int_tokens):
        if int_tokens <= 0:
            return None
        idx = int_tokens // 3
        if idx >= len(self.flag_token):
            return None
        alt = self.flag_token[idx]
        alt9 = alt & 0x1FF
        t = self.tokens[alt9]
        tk_case = t.m2d1c
        flags = t.m2d22
        num_param = _signed16(tk_case & 0xF000) // 0x1000
        kw = _get_keyword(self.tokens, self.vbstr, t.keyword_str_idx)
        return {
            "alt9": alt9, "tk_case": tk_case, "flags": flags,
            "num_param": num_param, "low_nibble": tk_case & 0xF, "keyword": kw,
        }

    def probe_pcode(self, file_off, file_size, probe_bytes=0x200):
        """Quick check: does this segment start with a CASE_START token?"""
        end = file_off + min(file_size, probe_bytes)
        off = file_off
        while off + 2 <= min(end, len(self.data)):
            tok = struct.unpack_from("<H", self.data, off)[0]
            d = self.convert_token(tok)
            if d and d["low_nibble"] == CASE_START:
                return True
            off += 2
        return False

    def walk(self, start, end, max_tokens=4000):
        off = start
        n = 0
        while off + 2 <= min(end, len(self.data)) and n < max_tokens:
            int_tokens = struct.unpack_from("<H", self.data, off)[0]
            d = self.convert_token(int_tokens)
            if d is None:
                yield {"off": off, "tok": int_tokens, "bad": "undecodable"}
                return
            num_param = d["num_param"]
            tk_param_bytes = num_param * 2
            inline_str = None
            if tk_param_bytes < 0:
                vlen = struct.unpack_from("<H", self.data, off + 2)[0]
                params = self.data[off + 4:off + 4 + vlen]
                next_off = off + 2 + 2 + vlen
                if next_off & 1:
                    next_off += 1
                if d["low_nibble"] == CASE_SPECIAL:
                    inline_str = params
            else:
                params = self.data[off + 2:off + 2 + tk_param_bytes]
                next_off = off + 2 + tk_param_bytes

            cval = None
            if d["keyword"] == "c%":
                if num_param == 1 and len(params) >= 2:
                    cval = struct.unpack_from("<h", params, 0)[0]
                elif num_param == 0:
                    cval = (self.flag_token[int_tokens // 3] >> 9) // 2

            yield {
                "off": off, "tok": int_tokens, "kw": d["keyword"],
                "np": num_param, "nib": d["low_nibble"], "params": params,
                "str": inline_str, "cval": cval,
            }
            n += 1
            if d["low_nibble"] == CASE_FINISH:
                return
            if next_off <= off:
                yield {"off": off, "tok": int_tokens, "bad": "no-progress"}
                return
            off = next_off

    def find_procedures(self, region_start, region_end):
        """Scan a region for coherent START..FINISH procedure runs."""
        procs = []
        off = region_start
        while off < region_end:
            if off + 2 > len(self.data):
                break
            int_tokens = struct.unpack_from("<H", self.data, off)[0]
            d = self.convert_token(int_tokens)
            if d and d["low_nibble"] == CASE_START:
                recs = list(self.walk(off, region_end))
                if recs and not any("bad" in r for r in recs) and recs[-1]["nib"] == CASE_FINISH:
                    procs.append(recs)
                    off = recs[-1]["off"] + 2
                    continue
            off += 2
        return procs


# ---------------------------------------------------------------------------
# Ghidra annotation
# ---------------------------------------------------------------------------

def _fmt_token(rec):
    if "bad" in rec:
        return f"<{rec['bad']}> tok={rec['tok']:#06x}"
    p = rec["params"].hex(" ") if rec["params"] else ""
    extra = ""
    if rec["cval"] is not None:
        extra = f" ={rec['cval']}"
    if rec["str"] is not None:
        try:
            extra = f" {rec['str'].decode('latin1')!r}"
        except Exception:
            extra = f" {rec['str'].hex()}"
    return f"{rec['kw']:<10} np={rec['np']:>2} {p}{extra}".rstrip()


def annotate(program, base_addr, all_procs):
    from ghidra.program.model.symbol import SourceType
    listing = program.getListing()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()
    total = 0

    for seg_label, procs in all_procs:
        for i, recs in enumerate(procs):
            start_off = recs[0]["off"]
            addr = addr_space.getAddress(base_addr + start_off)
            label = f"{seg_label}_proc_{i:04d}"
            plate = f"VB3 {seg_label} procedure #{i}  ({len(recs)} tokens)"
            cu = listing.getCodeUnitAt(addr)
            if cu:
                cu.setComment(cu.PLATE_COMMENT, plate)
            symbol_table.createLabel(addr, label, SourceType.ANALYSIS)
            for rec in recs:
                tok_addr = addr_space.getAddress(base_addr + rec["off"])
                cu = listing.getCodeUnitAt(tok_addr)
                if cu:
                    cu.setComment(cu.EOL_COMMENT, _fmt_token(rec))
            total += 1

    return total


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    vbdis_dir = askDirectory("Select VBDIS3 directory (contains vbdis3i.dat)", "OK").getAbsolutePath()
    if not os.path.exists(os.path.join(vbdis_dir, "vbdis3i.dat")):
        popup("vbdis3i.dat not found in selected directory. Aborting.")
        return

    # Read current program bytes
    program = currentProgram
    mem = program.getMemory()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    min_addr = mem.getMinAddress()
    max_addr = mem.getMaxAddress()
    total_len = int(str(max_addr.subtract(min_addr))) + 1

    import jpype
    byte_buf = jpype.JByte[total_len]
    mem.getBytes(min_addr, byte_buf)
    data = bytes([(b + 256) % 256 for b in byte_buf])
    base_addr = min_addr.getOffset()

    println(f"Loading token tables from {vbdis_dir} ...")
    disasm = VB3Disasm(vbdis_dir, data)
    println(f"Loaded {len(disasm.tokens)} opcodes.")

    # Try NE auto-detect
    segments, err = parse_ne_segments(data)
    regions = []  # list of (label, file_off, file_size)

    if segments is not None:
        println(f"NE header found: {len(segments)} CODE segments.")
        pcode_segs = [s for s in segments if disasm.probe_pcode(s["file_off"], s["file_size"])]
        println(f"Probed {len(segments)} CODE segments, {len(pcode_segs)} look like p-code.")
        for s in pcode_segs:
            label = f"seg{s['seg_num']:02d}"
            regions.append((label, s["file_off"], s["file_off"] + s["file_size"]))
            println(f"  {label}: {s['file_off']:#x} .. {s['file_off'] + s['file_size']:#x}")
    else:
        println(f"NE auto-detect: {err}. Falling back to manual region entry.")

    if not regions:
        region_hex = askString(
            "P-code region",
            f"Enter hex file offset and byte length, e.g.  34a00 f800\n"
            f"(Program spans {hex(base_addr)}..{hex(base_addr + total_len - 1)})",
        )
        parts = region_hex.strip().split()
        if len(parts) != 2:
            popup("Expected two hex values: <offset> <length>. Aborting.")
            return
        rstart = int(parts[0], 16)
        rlen   = int(parts[1], 16)
        if rstart + rlen > len(data):
            popup(f"Region exceeds program size {hex(len(data))}. Aborting.")
            return
        regions.append(("manual", rstart, rstart + rlen))

    println("Scanning for procedures ...")
    all_procs = []
    for label, rstart, rend in regions:
        procs = disasm.find_procedures(rstart, rend)
        println(f"  {label}: {len(procs)} procedures")
        if procs:
            all_procs.append((label, procs))

    total_procs = sum(len(p) for _, p in all_procs)
    if total_procs == 0:
        popup("No coherent procedures found. Check region offsets and token tables.")
        return

    println(f"Annotating {total_procs} procedures ...")
    n = annotate(program, base_addr, all_procs)
    println(f"Done — annotated {n} procedures across {len(all_procs)} segment(s).")


main()
