## ###
# IP: NONE — public domain
#
# VB3 P-Code Disassembler for Ghidra
#
# Disassembles Visual Basic 3 p-code from a loaded binary.
# Requires VBDIS3 token table files (vbdis3i.dat + vbdis3x.dat)
# from a VBDIS3 installation (https://www.btinternet.com/~dodi/VBDIS3.zip).
#
# Produces these annotations on each token:
#
#   - opcode keyword + raw param bytes (always)
#   - VBDIS3-style variable reference, e.g. "gv1780%" = global variable at slot
#     0x1780, type Integer (when EXE resources are parseable)
#   - resolved call targets (Call statements and function calls):
#     "->sub#262@0x2fe02" for local Subs/Functions, "->vbprint.dll:moveypos"
#     for external Declare functions
#   - block indentation (If/For/Do/Select) and a best-effort infix expression
#
# Usage:
#   1. Load your VB3 EXE into Ghidra as a raw binary, OR load a raw p-code dump.
#   2. Run this script via Script Manager.
#   3. The token tables are read from this script's directory; if they are not
#      there you are prompted for a VBDIS3 directory.
#   4. For a VB3 EXE the script auto-detects p-code segments via the NE header
#      and also attempts to load per-module type tables from the RC_DATA resources.
#      For a raw dump, enter the hex offset and length when prompted.
#
# The script creates a label and plate comment (Sub/Function/Declare header and
# callers) for each detected procedure, an EOL comment on every token line, and
# a call reference from each resolved local Call token to its callee.
#
# Outside Ghidra it runs as a command-line disassembler:
#   python3 DisassembleVB3PCode.py APP.EXE [--proc 0xOFFSET] [--calls]
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

SEG_DATA      = 0x0001
SEG_RELOCINFO = 0x0100


def parse_ne_segments(data):
    """Parse NE segments that have file data. Returns (segments, error_string).

    Each segment is a dict with 1-based seg_num, file_off, file_size (a stored
    size of 0 means 64K) and flags.
    """
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
        segments.append({"seg_num": i + 1, "file_off": file_off, "file_size": file_size, "flags": flags})
    return segments, None


def _parse_ne_rcdata_list(data):
    """Return list of (file_off, byte_size, name_id) for all RT_RCDATA resources, in order."""
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
            r_off, r_size, _flags, name_id = struct.unpack_from("<HHHH", data, off)
            resources.append((r_off * align, r_size * align, name_id))
            off += 12
        if type_id == RT_RCDATA:
            return resources
    return []


# ---------------------------------------------------------------------------
# VB3 global data (RC_DATA name id 0x8002, VBDIS3 MODULE4 ScanGlobalData)
#
# Layout from offset 0x60, each block prefixed by its u16 byte size:
#   gv0B8A block
#   fBuff1 (u16)
#   SomeDataBuff (gv09B6 bytes of int16)
#   global array table block
#   name pool block (gv0B92): T2237 records <M2241:2><M12C8:1><len:1><name>
#   module data blocks: <module id:u16><size:u16><module data>, each followed
#     by fixup blocks <size:u16><count:u16><0x001E:u16>...
#
# Module data (gLocalVarsTypeArrExE) is addressed by the byte offsets that
# appear in variable-reference tokens; a slot can hold a rotated Sub chain
# token for calls to Declare'd functions.
# ---------------------------------------------------------------------------

RT_RCDATA_VB_GLOBAL = 0x8002
FIXUP_BLOCK_TAG = 0x001E


class VB3GlobalData:
    def __init__(self, data):
        self.data = data
        self.base = None          # file offset of the RC_DATA resource
        self.some_data = []
        self.name_pool = None     # (file offset, size)
        self.modules = {}         # module id -> module data bytes
        rc = [r for r in _parse_ne_rcdata_list(data) if r[2] == RT_RCDATA_VB_GLOBAL]
        if rc:
            self.base, self.size = rc[0][0], rc[0][1]
            self._parse()

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, self.base + off)[0]

    def _in_bounds(self, off, n):
        return off + n <= self.size and self.base + off + n <= len(self.data)

    def _parse(self):
        i = 0x60
        if not self._in_bounds(i, 2):
            return
        i += 2 + self._u16(i)                      # gv0B8A
        i += 2                                      # fBuff1
        some_size = self._u16(i)
        i += 2
        if not self._in_bounds(i, some_size):
            return
        self.some_data = list(struct.unpack_from(f"<{some_size // 2}h", self.data, self.base + i))
        i += some_size
        i += 2 + self._u16(i)                      # global array table
        pool_size = self._u16(i)
        self.name_pool = (self.base + i + 2, pool_size)
        i += 2 + pool_size

        while self._in_bounds(i, 4):
            mod_id = self._u16(i)
            if mod_id in (0, 0xFFFF):
                break
            size = self._u16(i + 2)
            i += 4
            if not self._in_bounds(i, size):
                break
            self.modules[mod_id] = self.data[self.base + i:self.base + i + size]
            i += size
            while self._in_bounds(i, 6) and self._u16(i + 4) == FIXUP_BLOCK_TAG:
                fsize, count = self._u16(i), self._u16(i + 2)
                i += 6
                i += 3 * ((fsize - 4) // 3) if count == 0 else count * 2

    def pool_name(self, offs):
        if self.name_pool is None:
            return ""
        pos = self.name_pool[0] + offs
        if pos + 4 > len(self.data):
            return ""
        length = self.data[pos + 3]
        return self.data[pos + 4:pos + 4 + length].decode("latin1", errors="replace")

    def module_word(self, mod_id, offset):
        mod = self.modules.get(mod_id)
        if mod is None or offset + 2 > len(mod):
            return None
        return struct.unpack_from("<H", mod, offset)[0]

    def module_locals(self, mod_id):
        """gLocalVarsTypeArrExE for a module: (int16 array, count)."""
        mod = self.modules.get(mod_id)
        if not mod or len(mod) < 4:
            return [], 0
        arr = list(struct.unpack_from(f"<{len(mod) // 2}h", mod))
        return arr, len(arr) - 1


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


def _inline_string(params):
    """String constant payload: <link:u16><length:u16><chars>, NUL-padded."""
    if len(params) >= 4:
        length = struct.unpack_from("<H", params, 2)[0]
        if length <= len(params) - 4:
            return params[4:4 + length]
    return params


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

        # Kind char: Mid$(gc114A, l01B4, 1), only for l01B4 > gc114E (MODULE11)
        kind_char = ""
        if 2 <= l01B4 <= len(GC114A):
            kind_char = GC114A[l01B4 - 1]
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
                    inline_str = _inline_string(params)
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
# Sub table + call resolution (port of VBDIS3 MODULE10 DoDecompilation:
# sub0986 / sub0944 / Applyreloc1 / VBAbsOffs, and MODULE6 sub0785)
#
#   - The VBModuleDef descriptor segment (VBStartSeg) is the first RELOCINFO
#     segment other than the initial CS that is at least 256 bytes; some EXEs
#     put a small stub segment first.
#   - The sub chain starts at RC_DATA 0x8002 + 86 and links through
#     VBModuleDef.M1551. VBAbsOffs(t) = seg(VBStartSeg + (t>>13)&3) + (t&0x1FFF)*8.
#   - SELECTOR relocation chains of the descriptor segment give each local
#     sub's code segment; code_start = seg_base + VBModuleDef.Offs.
#   - A Call target T resolves via NamesLookUpTbl[ror3(T)+1] -> sub index.
# ---------------------------------------------------------------------------

MAX_SUBS = 2000

# VBModuleDef_struc field indexes (u16 words)
VBMD_SUB_OR_FUNC = 6    # bit 0: 1 = Sub, 0 = Function
VBMD_MODULE      = 10   # owning module id
VBMD_IS_LOCAL    = 11   # bit 0: 1 = local, 0 = external Declare
VBMD_OFFS        = 12   # code offset within the sub's segment
VBMD_NEXT        = 13   # M1551 chain link
VBMD_LIB         = 20   # M1587 Lib name (name-pool offset)
VBMD_ALIAS       = 23   # M159D Alias/proc name (name-pool offset)

CALL_KEYWORDS = ("Call ", "call")
# flag_token2 classes (MAIN.bas). Under access class gc1172 a token references
# a Sub: kind gc1156 carries the chain token inline, kind gc1152 names a module
# data slot that holds it (MODULE11 ScanTokens Case Else).
GC1152 = 3
GC1156 = 5
GC1172 = 6


def _ror3(v):
    """RotateRight3 (MODULE17)."""
    return ((v >> 3) & 0x1FFF) | ((v & 6) << 12)


class SubInfo:
    __slots__ = ("idx", "is_local", "is_sub", "offs", "seg", "module", "lib", "alias")

    def __init__(self, idx, vals, lib, alias):
        self.idx      = idx
        self.is_local = bool(vals[VBMD_IS_LOCAL] & 1)
        self.is_sub   = bool(vals[VBMD_SUB_OR_FUNC] & 1)
        self.offs     = vals[VBMD_OFFS] if self.is_local else -1
        self.seg      = None   # code segment number, from SELECTOR relocs
        self.module   = vals[VBMD_MODULE]
        self.lib      = lib
        self.alias    = alias


class SubTable:
    """VB3 Sub/Function/Declare table recovered from an NE EXE."""

    def __init__(self, data, segments, globals_):
        self.data = data
        self.globals = globals_
        self.seg_base = {s["seg_num"]: s["file_off"] for s in segments}
        self.subs = {}         # sub index (1-based) -> SubInfo
        self.names_tbl = {}    # ror3(chain token) + 1 -> sub index
        self._by_code_start = None
        self._load(segments)

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _load(self, segments):
        data = self.data
        ne_off = self._u16(0x3C)
        initial_cs = self._u16(ne_off + 0x16)
        start = next(
            (s for s in segments
             if (s["flags"] & SEG_RELOCINFO) and s["seg_num"] != initial_cs and s["file_size"] >= 256),
            None,
        )
        if start is None or self.globals.base is None:
            return
        rc_base = self.globals.base
        vb_start_seg = start["seg_num"]

        def vb_abs_offs(tok):
            return self.seg_base.get(vb_start_seg + ((tok >> 13) & 3), 0) + (tok & 0x1FFF) * 8

        link = self._u16(rc_base + 86)
        seen = set()
        while link != 0xFFFF and link not in seen and len(self.subs) < MAX_SUBS:
            seen.add(link)
            r = _ror3(link)
            pos = vb_abs_offs(r)
            if pos + 56 > len(data):
                break
            vals = struct.unpack_from("<28H", data, pos)
            idx = len(self.subs) + 1
            self.names_tbl[r + 1] = idx
            is_local = bool(vals[VBMD_IS_LOCAL] & 1)
            lib = alias = ""
            if not is_local:
                lib = self.globals.pool_name(vals[VBMD_LIB])
                alias = self.globals.pool_name(vals[VBMD_ALIAS])
            self.subs[idx] = SubInfo(idx, vals, lib, alias)
            link = vals[VBMD_NEXT]

        # SELECTOR (type 2), internal-reference relocation chains assign code segments.
        reloc_base = start["file_off"] + start["file_size"]
        if reloc_base + 2 > len(data):
            return
        nrelocs = self._u16(reloc_base)
        for i in range(nrelocs):
            rpos = reloc_base + 2 + i * 8
            if rpos + 8 > len(data):
                break
            src_type, flags_b, src_off, tgt_seg, _ = struct.unpack_from("<BBHHH", data, rpos)
            if src_type != 2 or (flags_b & 3) != 0:
                continue
            chain = src_off
            hops = 0
            while chain != 0xFFFF and hops < 0x2000:
                idx = self.names_tbl.get((chain // 8) - 4 + 1)
                if idx is not None:
                    self.subs[idx].seg = tgt_seg
                chain_pos = start["file_off"] + chain
                if chain_pos + 2 > len(data):
                    break
                chain = self._u16(chain_pos)
                hops += 1

    def code_start(self, sub):
        if not sub.is_local or sub.offs <= 0 or sub.seg not in self.seg_base:
            return None
        return self.seg_base[sub.seg] + sub.offs

    def sub_at(self, code_start):
        if self._by_code_start is None:
            self._by_code_start = {}
            for sub in self.subs.values():
                cs = self.code_start(sub)
                if cs is not None:
                    self._by_code_start[cs] = sub
        return self._by_code_start.get(code_start)

    def resolve(self, target):
        """Call target token -> SubInfo or None."""
        idx = self.names_tbl.get(_ror3(target) + 1)
        return self.subs.get(idx) if idx is not None else None

    def resolve_call(self, disasm, rec, module=None):
        """Resolve a token that references a Sub to its SubInfo, or None.

        `Call` tokens carry an internal target directly in params[2:4]. Other
        references follow MODULE11 under access class gc1172, with VarIndex =
        the token's last param word / 2:
          gc1156: chain token = VarIndex * 2 (bit 0 cleared)
          gc1152: chain token = gLocalVarsTypeArrExE[VarIndex] of `module`
        """
        params = rec.get("params") or b""
        if len(params) < 2 or rec.get("str") is not None:
            return None
        if rec.get("kw") in CALL_KEYWORDS and len(params) >= 4:
            sub = self.resolve(struct.unpack_from("<H", params, 2)[0])
            if sub is not None and (not sub.is_local or self.code_start(sub) is not None):
                return sub
        l01B4, _l01BA, l01BC = disasm._ft2_lookup(rec["tok"])
        if l01BC != GC1172:
            return None
        raw = struct.unpack_from("<H", params, len(params) - 2)[0]
        if l01B4 == GC1156:
            return self.resolve(raw & 0xFFFE)
        if l01B4 == GC1152 and module is not None:
            token = self.globals.module_word(module, raw & 0xFFFE)
            return self.resolve(token) if token else None
        return None

    def name(self, sub):
        if not sub.is_local:
            return sub.alias or f"ext#{sub.idx}"
        return f"sub#{sub.idx}"

    def target_text(self, sub):
        if not sub.is_local:
            return f"{sub.lib.rstrip('.')}:{sub.alias}"
        cs = self.code_start(sub)
        return f"{self.name(sub)}@{cs:#x}" if cs is not None else self.name(sub)

    def declaration(self, sub):
        """MODULE6 sub0785: VB header line for a sub."""
        kind = "Sub" if sub.is_sub else "Function"
        if not sub.is_local:
            return f'Declare {kind} {sub.alias} Lib "{sub.lib.rstrip(".")}"'
        cs = self.code_start(sub)
        where = f"@{cs:#x}" if cs is not None else ""
        return f"{kind} sub#{sub.idx}{where}()"

    def proc_sub(self, recs):
        """SubInfo whose code_start falls on this procedure's START token.

        VBModuleDef.Offs points just past the START opcode, so the code_start
        can lie anywhere from the START token up to the next token.
        """
        first = recs[0]["off"]
        last = recs[1]["off"] if len(recs) > 1 else first + 2
        for cs in range(first, last + 1, 2):
            sub = self.sub_at(cs)
            if sub is not None:
                return sub
        return None


def build_call_graph(subs, disasm, procs):
    """Return (calls, callers) for decoded procedures.

    calls:   {proc start offset: [(token offset, SubInfo)]}
    callers: {sub index: set(proc start offset)}
    """
    calls, callers = {}, {}
    for recs in procs:
        start = recs[0]["off"]
        owner = subs.proc_sub(recs)
        module = owner.module if owner is not None else None
        for rec in recs:
            sub = subs.resolve_call(disasm, rec, module)
            if sub is None:
                continue
            rec["callee"] = sub
            calls.setdefault(start, []).append((rec["off"], sub))
            callers.setdefault(sub.idx, set()).add(start)
    return calls, callers


# ---------------------------------------------------------------------------
# Statement structuring (MODULE13, keyword heuristic) and expression tree
# (MODULE12, best effort). Readable output, not byte parity with VBDIS3.
# ---------------------------------------------------------------------------

OPENERS = {"Sub", "Function", "If", "For", "Do", "While", "Select", "Select Case", "With"}
CLOSERS = {"End Sub", "End Function", "End If", "Next", "Loop", "Wend", "End Select", "End With"}
MIDDLES = {"Else", "ElseIf", "Case", "Case Else"}
BINOPS = {"+", "-", "*", "/", "\\", "^", "&", "=", "<>", "<", ">", "<=", ">=",
          "And", "Or", "Xor", "Eqv", "Imp", "Mod", "Like"}
UNARY = {"Neg", "Not"}


def structure(recs):
    """Set rec['level'] to the block nesting depth of each token."""
    level = 0
    for r in recs:
        kw = (r.get("kw") or "").strip()
        if kw in CLOSERS:
            level = max(0, level - 1)
            r["level"] = level
        elif kw in MIDDLES:
            r["level"] = max(0, level - 1)
        else:
            r["level"] = level
            if kw in OPENERS:
                level += 1
    return recs


def expr_infix(recs):
    """Set rec['expr'] to an inferred infix expression where derivable."""
    stack = []
    for r in recs:
        kw = (r.get("kw") or "").strip()
        expr = None
        if r.get("cval") is not None:
            expr = str(r["cval"])
        elif r.get("str") is not None:
            expr = '"' + r["str"].decode("latin1", errors="replace") + '"'
        elif r.get("ann"):
            expr = r["ann"]
        elif kw in BINOPS and len(stack) >= 2:
            rhs = stack.pop()
            lhs = stack.pop()
            expr = f"{lhs} {kw} {rhs}"
        elif kw in UNARY and stack:
            expr = f"{kw} {stack.pop()}"
        if expr is not None:
            stack.append(expr)
            r["expr"] = expr
    return recs


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _is_operator(rec):
    kw = (rec.get("kw") or "").strip()
    return kw in BINOPS or kw in UNARY


def _fmt_token(rec, subs=None):
    if "bad" in rec:
        return f"<{rec['bad']}> tok={rec['tok']:#06x}"
    p = rec["params"].hex(" ") if rec["params"] else ""
    extra = ""
    if rec["cval"] is not None:
        extra = f" ={rec['cval']}"
    elif rec["str"] is not None:
        extra = f" {rec['str'].decode('latin1', errors='replace')!r}"
    elif rec.get("callee") is not None and subs is not None:
        extra = f" ->{subs.target_text(rec['callee'])}"
    elif rec.get("kw") in CALL_KEYWORDS:
        extra = " ->?"
    ann = f" [{rec['ann']}]" if rec.get("ann") else ""
    expr = rec.get("expr")
    tail = f"  ; {expr}" if expr and _is_operator(rec) else ""
    indent = "  " * rec.get("level", 0)
    return f"{indent}{rec['kw']:<10} np={rec['np']:>2} {p}{extra}{ann}{tail}".rstrip()


def _plate(seg_label, i, recs, subs, callers):
    sub = subs.proc_sub(recs) if subs else None
    lines = []
    if sub is not None:
        lines.append(subs.declaration(sub))
    lines.append(f"VB3 {seg_label} procedure #{i}  ({len(recs)} tokens)")
    if sub is not None and callers.get(sub.idx):
        lines.append("Called from: " + ", ".join(f"{c:#x}" for c in sorted(callers[sub.idx])))
    return sub, "\n".join(lines)


def annotate(program, base_addr, all_procs, subs, callers):
    from ghidra.program.model.symbol import RefType, SourceType
    listing = program.getListing()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()
    ref_mgr = program.getReferenceManager()
    total = refs = 0
    for seg_label, procs in all_procs:
        for i, recs in enumerate(procs):
            addr = addr_space.getAddress(base_addr + recs[0]["off"])
            sub, plate = _plate(seg_label, i, recs, subs, callers)
            label = f"vb3_sub{sub.idx}" if sub is not None else f"{seg_label}_proc_{i:04d}"
            cu = listing.getCodeUnitAt(addr)
            if cu:
                cu.setComment(cu.PLATE_COMMENT, plate)
            symbol_table.createLabel(addr, label, SourceType.ANALYSIS).setPrimary()
            for rec in recs:
                tok_addr = addr_space.getAddress(base_addr + rec["off"])
                cu = listing.getCodeUnitAt(tok_addr)
                if cu:
                    cu.setComment(cu.EOL_COMMENT, _fmt_token(rec, subs))
                callee = rec.get("callee")
                target = subs.code_start(callee) if callee is not None else None
                if target is not None:
                    ref_mgr.addMemoryReference(
                        tok_addr, addr_space.getAddress(base_addr + target),
                        RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, -1,
                    )
                    refs += 1
            total += 1
    return total, refs


def decode_all(disasm, regions, subs=None):
    """Decode every region; returns [(label, procs)] with structure/expr applied.

    Each procedure owned by a known Sub is re-walked with its module's type
    state (gLocalVarsTypeArrExE), shared across that module's procedures.
    """
    type_states = {}

    def module_type_state(recs):
        owner = subs.proc_sub(recs) if subs is not None else None
        if owner is None:
            return None
        if owner.module not in type_states:
            arr, count = subs.globals.module_locals(owner.module)
            type_states[owner.module] = TypeState(count, arr) if count > 0 else None
        return type_states[owner.module]

    all_procs = []
    for label, rstart, rend in regions:
        procs = []
        for recs in disasm.find_procedures(rstart, rend):
            type_state = module_type_state(recs)
            if type_state is not None:
                recs = list(disasm.walk(recs[0]["off"], rend, type_state=type_state))
            structure(recs)
            expr_infix(recs)
            procs.append(recs)
        if procs:
            all_procs.append((label, procs))
    return all_procs


def pcode_regions(disasm, segments):
    return [
        (f"seg{s['seg_num']:02d}", s["file_off"], s["file_off"] + s["file_size"])
        for s in segments
        if not (s["flags"] & SEG_DATA) and disasm.probe_pcode(s["file_off"], s["file_size"])
    ]



# ---------------------------------------------------------------------------
# Main (Ghidra)
# ---------------------------------------------------------------------------

def _table_dir():
    script_dir = getSourceFile().getParentFile().getAbsolutePath()
    if os.path.exists(os.path.join(script_dir, "vbdis3i.dat")):
        return script_dir
    chosen = askDirectory("Select VBDIS3 directory (contains vbdis3i.dat)", "OK").getAbsolutePath()
    if os.path.exists(os.path.join(chosen, "vbdis3i.dat")):
        return chosen
    return None


def main():
    vbdis_dir = _table_dir()
    if vbdis_dir is None:
        popup("vbdis3i.dat not found in selected directory. Aborting.")
        return

    program = currentProgram
    mem = program.getMemory()
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

    globals_ = VB3GlobalData(data)
    if globals_.base is not None:
        println(f"VB3 global data: {len(globals_.modules)} module data block(s).")
    else:
        println("VB3 global data: not available (raw dump or unsupported format).")

    segments, err = parse_ne_segments(data)
    regions = []
    subs = None
    if segments is not None:
        regions = pcode_regions(disasm, segments)
        println(f"NE header: {len(segments)} segments, {len(regions)} look like p-code.")
        subs = SubTable(data, segments, globals_)
        externals = sum(1 for s in subs.subs.values() if not s.is_local)
        println(f"Sub table: {len(subs.subs)} subs ({externals} external Declares).")
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
    all_procs = decode_all(disasm, regions, subs)
    for label, procs in all_procs:
        println(f"  {label}: {len(procs)} procedures")

    total_procs = sum(len(p) for _, p in all_procs)
    if total_procs == 0:
        popup("No coherent procedures found. Check region offsets and token tables.")
        return

    callers = {}
    if subs is not None:
        _, callers = build_call_graph(subs, disasm, [r for _, procs in all_procs for r in procs])

    println(f"Annotating {total_procs} procedures ...")
    n, refs = annotate(program, base_addr, all_procs, subs, callers)
    println(f"Done — annotated {n} procedures across {len(all_procs)} segment(s), {refs} call references.")


# ---------------------------------------------------------------------------
# Command line (outside Ghidra)
# ---------------------------------------------------------------------------

def cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Disassemble VB3 p-code from an NE EXE.")
    ap.add_argument("exe")
    ap.add_argument("--tables", default=os.path.dirname(os.path.abspath(__file__)),
                    help="directory containing vbdis3i.dat and vbdis3x.dat")
    ap.add_argument("--proc", type=lambda v: int(v, 0),
                    help="only print the procedure containing this file offset")
    ap.add_argument("--calls", action="store_true", help="print the call graph instead of tokens")
    args = ap.parse_args(argv)

    data = open(args.exe, "rb").read()
    disasm = VB3Disasm(args.tables, data)
    segments, err = parse_ne_segments(data)
    if segments is None:
        raise SystemExit(f"{args.exe}: {err}")
    subs = SubTable(data, segments, VB3GlobalData(data))
    all_procs = decode_all(disasm, pcode_regions(disasm, segments), subs)
    procs = [(label, i, recs) for label, ps in all_procs for i, recs in enumerate(ps)]
    calls, callers = build_call_graph(subs, disasm, [recs for _, _, recs in procs])

    if args.calls:
        for label, i, recs in procs:
            sub = subs.proc_sub(recs)
            name = subs.declaration(sub) if sub else f"{label}_proc_{i:04d}"
            for off, callee in calls.get(recs[0]["off"], []):
                print(f"{recs[0]['off']:#08x} {name} @{off:#08x} -> {subs.target_text(callee)}")
        return

    for label, i, recs in procs:
        if args.proc is not None and not (recs[0]["off"] <= args.proc <= recs[-1]["off"]):
            continue
        _, plate = _plate(label, i, recs, subs, callers)
        print("\n".join(f"; {line}" for line in plate.splitlines()))
        for rec in recs:
            print(f"{rec['off']:#08x}: {_fmt_token(rec, subs)}")
        print()


if "currentProgram" in globals():
    main()
elif __name__ == "__main__":
    import sys
    cli(sys.argv[1:])
