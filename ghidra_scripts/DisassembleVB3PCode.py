## ###
# IP: NONE — public domain
#
# VB3 P-Code Disassembler for Ghidra
#
# Disassembles Visual Basic 3 p-code from a loaded binary.
# Requires VBDIS3 token table files (vbdis3i.dat + vbdis3x.dat)
# from a VBDIS3 installation (https://www.btinternet.com/~dodi/VBDIS3.zip).
#
# Produces two levels of annotation on each token:
#
#   Level 1 (always): opcode keyword + raw param bytes
#   Level 2 (when EXE resources are parseable): variable-reference annotation
#     in VBDIS3 style, e.g. "gv1780%" = global variable at slot 0x1780, type Integer
#
# Usage:
#   1. Load your VB3 EXE into Ghidra as a raw binary, OR load a raw p-code dump.
#   2. Run this script via Script Manager.
#   3. Point it at your VBDIS3 directory when prompted.
#   4. For a VB3 EXE the script auto-detects p-code segments via the NE header
#      and also attempts to load per-module type tables from the RC_DATA resources.
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
# NE (New Executable) header + RC_DATA resource parser
# ---------------------------------------------------------------------------

def parse_ne_segments(data):
    """Parse NE CODE segments. Returns (segments, error_string)."""
    if data[:2] != b"MZ":
        return None, "Not an MZ executable"
    e_lfanew = struct.unpack_from("<H", data, 0x3C)[0]
    if e_lfanew + 4 > len(data):
        return None, "e_lfanew out of range"
    ne_off = e_lfanew
    if data[ne_off:ne_off + 2] != b"NE":
        return None, f"Expected NE at {ne_off:#x}"
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
            continue
        file_off  = lsec * sector_size
        file_size = fsize if fsize != 0 else 0x10000
        if not (flags & 0x0001):
            segments.append({"seg_num": i + 1, "file_off": file_off, "file_size": file_size, "flags": flags})
    return segments, None


def _parse_ne_rcdata_list(data):
    """Return list of (file_off, byte_size) for all RT_RCDATA resources, in order."""
    if data[:2] != b"MZ":
        return []
    ne_off = struct.unpack_from("<H", data, 0x3C)[0]
    if data[ne_off:ne_off + 2] != b"NE":
        return []
    res_tbl_off  = struct.unpack_from("<H", data, ne_off + 0x24)[0]
    res_name_off = struct.unpack_from("<H", data, ne_off + 0x26)[0]
    if res_tbl_off == res_name_off:
        return []
    rt_base = ne_off + res_tbl_off
    align = 1 << struct.unpack_from("<H", data, rt_base)[0]
    off = rt_base + 2
    RT_RCDATA = 0x800A
    while True:
        type_id = struct.unpack_from("<H", data, off)[0]
        if type_id == 0:
            break
        n_res = struct.unpack_from("<H", data, off + 2)[0]
        off += 8
        resources = []
        for _ in range(n_res):
            r_off  = struct.unpack_from("<H", data, off)[0]
            r_size = struct.unpack_from("<H", data, off + 2)[0]
            resources.append((r_off * align, r_size * align))
            off += 12
        if type_id == RT_RCDATA:
            return resources
    return []


# ---------------------------------------------------------------------------
# VB3 resource data parser — loads SomeDataBuff + per-module local var tables
# ---------------------------------------------------------------------------
# VB3 stores module/form data as RC_DATA resources.
# RC_DATA[0] = main project data (form/module list, ScanRCFrmData)
# RC_DATA[1] = global data (ScanGlobalData): SomeDataBuff + module descriptor list
# RC_DATA[2..N] = per-module code + fixup data
#
# Within RC_DATA[1] (Base1, 1-based VB file positions):
#   Base1 + 0x24          → gv0B68
#   Base1 + 0x60          → fBuff2 (size of first block)
#   Base1 + 0x62          → first block (gv0B8A), skip fBuff2 bytes
#   then two more u16s     → fBuff1, fBuff2=gv09B6
#   then                   → SomeDataBuff (gv09B6 bytes = gv09BA+1 int16s)
#   skip two more u16 blocks → gv0B92
#   then one more u16 block → gfrmOffset
#
# Module descriptor list at gfrmOffset (all offsets relative to Base1):
#   [u16 module_id, then at mfrmOffset:]
#   u16 size = gRawVBCodeSize
#   (gRawVBCodeSize//2) int16s = gLocalVarsTypeArrExE[0..gLocalVarsCount]

def parse_vb3_resources(data):
    """
    Parse VB3 RC_DATA resources. Returns a VB3Resources object or None on failure.
    """
    rc = _parse_ne_rcdata_list(data)
    if len(rc) < 2:
        return None

    base1_foff = rc[1][0]   # file offset of RC_DATA[1] = Base1 - 1 (0-based)
    Base1 = base1_foff + 1  # VB 1-based file position

    def u16(vb_pos):
        return struct.unpack_from("<H", data, vb_pos - 1)[0]

    def s16(vb_pos):
        return struct.unpack_from("<h", data, vb_pos - 1)[0]

    try:
        i = 0x60
        fBuff2 = u16(Base1 + i);   i += 2
        i += fBuff2                 # skip first block (gv0B8A)
        _fBuff1 = s16(Base1 + i);  i += 2
        fBuff2  = s16(Base1 + i);  i += 2
        gv09B6  = fBuff2 & 0xFFFF
        gv09BA  = (gv09B6 // 2) - 1

        some_data_off = Base1 + i  # VB 1-based start of SomeDataBuff
        some_data = [s16(some_data_off + k * 2) for k in range(gv09BA + 1)]

        i += gv09B6
        fBuff2 = u16(Base1 + i); i += 2
        i += fBuff2
        fBuff2 = u16(Base1 + i); i += 2
        i += fBuff2
        gfrmOffset = i

        # Parse module descriptor list
        modules = []
        mi = gfrmOffset
        for _ in range(256):
            raw_id = s16(Base1 + mi); mi += 2
            if raw_id == 0 or raw_id == -1:
                break
            mfrmOffset = mi
            skip = u16(Base1 + mi); mi += 2
            modules.append({"mfrmOffset": mfrmOffset, "raw_id": raw_id})
            mi += skip
            # If form type (M24D0='F'=0x46), skip two more blocks
            # We can't easily distinguish without the form struct, so skip conservatively

        return VB3Resources(data, Base1, some_data, gv09BA, modules)

    except Exception:
        return None


class VB3Resources:
    def __init__(self, data, Base1, some_data, gv09BA, modules):
        self.data   = data
        self.Base1  = Base1
        self.some_data = some_data
        self.gv09BA    = gv09BA
        self.modules   = modules

    def load_module_locals(self, mfrmOffset):
        """Load gLocalVarsTypeArrExE for a module. Returns (arr, count) or ([], 0)."""
        def s16(vb_pos):
            return struct.unpack_from("<h", self.data, vb_pos - 1)[0]
        def u16(vb_pos):
            return struct.unpack_from("<H", self.data, vb_pos - 1)[0]
        try:
            raw_size = u16(self.Base1 + mfrmOffset)
            count = (raw_size // 2) - 1
            if count < 0 or raw_size < 6:
                return [], 0
            arr = [s16(self.Base1 + mfrmOffset + 2 + k * 2) for k in range(count + 1)]
            return arr, count
        except Exception:
            return [], 0


# ---------------------------------------------------------------------------
# Type inference — simplified ProcessType / SetType1 / SetType2
#
# We bypass gvConv_bw (always zero in the available source) and derive the
# type suffix directly from pToken1/pToken2 (control_token bytes).
#
# pToken1 (from control_token[tok]) encodes the storage class / variable kind:
#   8  = plain Integer-typed reference
#   9  = Object / module-level
#   10 = Array element
#   11 = Dynamic variable
#   12 = Static variable
#   14 = Long/String/user-type (pToken2 gives specifics)
#
# pToken2 (from control_token[tok+1]) encodes the VB type suffix (gc117C index):
#   directly 2..7: '%', '&', '!', '#', '@', 'v'
#   8 (mc0162): no suffix
#   9 (mc0164): user type 'T'
#   10 (mc015A): complex (array of user-type)
#   12 (mc015C): special string/Long marker
#   13 (mc0166): fixed-length string '*' (gTypeFixString=8 → gc117C[8]='O' — but in practice '*')
# ---------------------------------------------------------------------------

# gc114A = "?pmlgcfOTas"   (1-indexed: 1='p' 2='m' 3='l' 4='g' 5='c' 6='f' 7='O' 8='T' 9='a' 10='s')
GC114A = "?pmlgcfOTas"
# gc117C = "t%&!#@vOT*A$4|"  (1-indexed)
GC117C = "t%&!#@vOT*A$4|"

# pToken2 → gc117C index (type suffix)
_PT2_SUFFIX = {2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 9: 9, 10: 10, 12: 12, 13: 8}


def _ptoken_type_suffix(pToken2):
    """Return the gc117C-index type char for pToken2, or '' if none."""
    idx = _PT2_SUFFIX.get(pToken2, 0)
    if 1 <= idx <= len(GC117C):
        return GC117C[idx - 1]
    return ""


class TypeState:
    """Per-procedure type inference state."""
    __slots__ = ("buf", "arr", "count")

    def __init__(self, count, arr):
        self.buf   = bytearray(count + 2)  # 1-indexed, like gLocalVarsTypeBuff
        self.arr   = arr                   # gLocalVarsTypeArrExE
        self.count = count

    def process_type(self, var_offset, pToken1, pToken2):
        """Simplified ProcessType — scalar cases only."""
        if pToken1 < 8:
            return
        VarIndex = (var_offset & 0xFFFF) // 2
        if VarIndex == 0 or VarIndex > self.count or VarIndex >= len(self.buf):
            return
        if self.buf[VarIndex]:
            return  # already typed
        # map pToken1 → high-bits type category, pToken2 → low-bits type
        type_hi = {8: 0x80, 9: 0x60, 10: 0xA0, 11: 0x40, 12: 0x20}.get(pToken1, 0)
        type_lo = pToken2 if pToken2 < 8 else 0
        self.buf[VarIndex] = (type_hi | type_lo) & 0xFF

    def get_type_char(self, VarIndex):
        """Return (kind_char, type_suffix_char) from buf[VarIndex]."""
        if VarIndex <= 0 or VarIndex >= len(self.buf):
            return "?", ""
        v = self.buf[VarIndex]
        if v == 0:
            return "?", ""
        type_lo = v & 0x07
        suffix = _ptoken_type_suffix(type_lo) if type_lo else ""
        return "v", suffix


# ---------------------------------------------------------------------------
# Disassembler (port of pcode.py)
# ---------------------------------------------------------------------------

CASE_START   = 5
CASE_FINISH  = 4
CASE_SPECIAL = 8
MASK_LOCALVAR = 0x40   # Cur_VBDat.mTokenFlags And MASK_0100_0000


def _signed16(v):
    return v - 0x10000 if v >= 0x8000 else v


class VB3Disasm:
    def __init__(self, vbdis_dir, data):
        tokens, _, vbstr = _load_i_dat(os.path.join(vbdis_dir, "vbdis3i.dat"))
        flag_token, control_token, flag_token2 = _load_x_dat(os.path.join(vbdis_dir, "vbdis3x.dat"))
        self.tokens        = tokens
        self.vbstr         = vbstr
        self.flag_token    = flag_token
        self.control_token = control_token
        self.flag_token2   = flag_token2
        self.data          = data

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
        flags   = t.m2d22
        num_param = _signed16(tk_case & 0xF000) // 0x1000
        kw = _get_keyword(self.tokens, self.vbstr, t.keyword_str_idx)
        return {
            "alt9": alt9, "tk_case": tk_case, "flags": flags,
            "num_param": num_param, "low_nibble": tk_case & 0xF, "keyword": kw,
        }

    def probe_pcode(self, file_off, file_size, probe_bytes=0x200):
        end = file_off + min(file_size, probe_bytes)
        off = file_off
        while off + 2 <= min(end, len(self.data)):
            tok = struct.unpack_from("<H", self.data, off)[0]
            d = self.convert_token(tok)
            if d and d["low_nibble"] == CASE_START:
                return True
            off += 2
        return False

    def _ft2_lookup(self, int_tokens):
        """
        Perform flag_token2 ptr lookup for int_tokens.
        Returns (l01B4, l01BA, l01BC) where l01B4>1 means a variable reference exists.
        VB: l01B2 = ft2[tok+1], l01BC = ft2[tok+2]; if l01BC & 0x80: l01BC ^= 0x80
            if l01B2: ptr = tok - l01B2; l01B4 = ft2[ptr]; l01BA = ft2[ptr+1]
        """
        ft2 = self.flag_token2
        if int_tokens + 1 >= len(ft2):
            return 0, 0, 0
        b1 = ft2[int_tokens]          # VB: Mid(ft2, tok+1, 1) → 0-based = tok
        b2 = ft2[int_tokens + 1]      # VB: Mid(ft2, tok+2, 1) → 0-based = tok+1
        if b2 & 0x80:
            b2 ^= 0x80
        if not b1:
            return 0, 0, b2
        ptr = int_tokens - b1         # redirect into ft2
        if ptr <= 0 or ptr >= len(ft2):
            return 0, 0, b2
        l01B4 = ft2[ptr - 1]          # VB: Mid(ft2, ptr, 1) → 0-based = ptr-1
        l01BA = ft2[ptr] if ptr < len(ft2) else 0
        return l01B4, l01BA, b2

    def _ft2_annotation(self, rec, type_state=None):
        """
        Build a VBDIS3-style variable annotation for a token record.
        Returns a string like 'gv1780%' or '' if no variable reference.

        Uses flag_token2 for kind (gc114A char) and VarIndex from params.
        Uses TypeState.get_type_char() for the type suffix if available.
        Falls back to control_token pToken2 otherwise.
        """
        tok = rec["tok"]
        l01B4, _l01BA, l01BC = self._ft2_lookup(tok)
        # Also need VarIndex: last 2-byte param when flags & MASK_LOCALVAR
        d = self.convert_token(tok)
        if not d:
            return ""
        has_lv = bool(d["flags"] & MASK_LOCALVAR)
        var_index = None
        if has_lv and len(rec["params"]) >= 2:
            var_off = struct.unpack_from("<H", rec["params"], len(rec["params"]) - 2)[0]
            var_index = var_off // 2

        # Build annotation
        # Kind char from gc114A (l01B4 1-indexed)
        kind_char = ""
        if 1 <= l01B4 <= len(GC114A) - 1:
            kind_char = GC114A[l01B4]  # 1-indexed in VB; GC114A[0]='?', [1]='p', ...
        elif has_lv:
            kind_char = "?"

        if not kind_char and var_index is None:
            return ""

        # Type suffix
        type_suffix = ""
        if type_state is not None and var_index is not None:
            _, type_suffix = type_state.get_type_char(var_index)
        if not type_suffix:
            # Fall back to control_token pToken2
            ct2 = self.control_token[tok + 1] if tok + 1 < len(self.control_token) else 0
            type_suffix = _ptoken_type_suffix(ct2)

        slot_hex = f"{(var_index * 2):x}" if var_index is not None else "?"
        access = "a" if (l01BC == 4) else "v"  # gc116E=4 = array element
        return f"{kind_char}{access}{slot_hex}{type_suffix}"

    def walk(self, start, end, max_tokens=4000, type_state=None):
        """
        Yield decoded tokens. Each record includes:
          'ann': type annotation string (VBDIS3 M26A6 style), may be ''
        If type_state is provided, annotations use its gLocalVarsTypeBuff;
        the walk also calls process_type() to build the state incrementally.
        """
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

            rec = {
                "off": off, "tok": int_tokens, "kw": d["keyword"],
                "np": num_param, "nib": d["low_nibble"], "params": params,
                "str": inline_str, "cval": cval, "ann": "",
            }

            # Type inference pass (incremental)
            if type_state is not None and (d["flags"] & MASK_LOCALVAR) and len(params) >= 2:
                var_off = struct.unpack_from("<H", params, len(params) - 2)[0]
                ct1 = self.control_token[int_tokens] if int_tokens < len(self.control_token) else 0
                ct2 = self.control_token[int_tokens + 1] if int_tokens + 1 < len(self.control_token) else 0
                type_state.process_type(var_off, ct1, ct2)

            rec["ann"] = self._ft2_annotation(rec, type_state)

            yield rec
            n += 1
            if d["low_nibble"] == CASE_FINISH:
                return
            if next_off <= off:
                yield {"off": off, "tok": int_tokens, "bad": "no-progress"}
                return
            off = next_off

    def find_procedures(self, region_start, region_end, type_state=None):
        """Scan a region for coherent START..FINISH procedure runs."""
        procs = []
        off = region_start
        while off < region_end:
            if off + 2 > len(self.data):
                break
            int_tokens = struct.unpack_from("<H", self.data, off)[0]
            d = self.convert_token(int_tokens)
            if d and d["low_nibble"] == CASE_START:
                recs = list(self.walk(off, region_end, type_state=type_state))
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
    ann = f" [{rec['ann']}]" if rec.get("ann") else ""
    return f"{rec['kw']:<10} np={rec['np']:>2} {p}{extra}{ann}".rstrip()


def annotate(program, base_addr, all_procs):
    from ghidra.program.model.symbol import SourceType
    listing = program.getListing()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()
    total = 0
    for seg_label, procs in all_procs:
        for i, recs in enumerate(procs):
            addr = addr_space.getAddress(base_addr + recs[0]["off"])
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

    # Try to load per-module type data from RC_DATA resources
    vb3res = parse_vb3_resources(data)
    if vb3res:
        println(f"VB3 resources: {len(vb3res.modules)} module(s) found.")
    else:
        println("VB3 resource parse: not available (raw dump or unsupported format).")

    # Try NE auto-detect
    segments, err = parse_ne_segments(data)
    regions = []

    if segments is not None:
        println(f"NE header: {len(segments)} CODE segments.")
        pcode_segs = [s for s in segments if disasm.probe_pcode(s["file_off"], s["file_size"])]
        println(f"  {len(pcode_segs)} look like p-code.")
        for s in pcode_segs:
            label = f"seg{s['seg_num']:02d}"
            regions.append((label, s["file_off"], s["file_off"] + s["file_size"]))
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
        # Build a TypeState for this segment if we have resource data
        type_state = None
        if vb3res and vb3res.modules:
            # Use the largest module's locals (heuristic for single-module apps)
            best = max(vb3res.modules, key=lambda m: vb3res.load_module_locals(m["mfrmOffset"])[1])
            arr, count = vb3res.load_module_locals(best["mfrmOffset"])
            if count > 0:
                type_state = TypeState(count, arr)

        procs = disasm.find_procedures(rstart, rend, type_state=type_state)
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
