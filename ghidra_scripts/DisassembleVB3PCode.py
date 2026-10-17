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
#     0x1780, type Integer (when EXE resources are parseable), plus the form or
#     control a module slot names
#   - resolved call targets (Call statements and function calls):
#     "->fn13EB@0x2fe02" for local Subs/Functions, "->vbprint.dll:moveypos"
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
# Event procedures are named from the forms' event tables using the control
# models in VBRUN300.DLL and the project's .VBX files, found next to the
# imported EXE. Form, event table, control model and Declare inference code is
# ported from vb3dec (https://github.com/jrmcpeek/vb3dec, MIT License,
# Copyright (c) 2026 Jamie McPeek).
#
# The script creates a label and plate comment (Sub/Function/Declare header and
# callers) for each detected procedure, an EOL comment on every token line, and
# a call reference from each resolved local Call token to its callee.
#
# Outside Ghidra it runs as a command-line disassembler:
#   python3 DisassembleVB3PCode.py APP.EXE [--proc 0xOFFSET] [--calls] [--json] [--vbx-dir DIR]
#
# @category VB3
# @runtime PyGhidra
##

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import struct
import json
import os
import sys

__version__ = "0.3.0"
JSON_SCHEMA = "ghidra-vb3/disassembly-v1"

# ---------------------------------------------------------------------------
# Token table loader (port of loader.py)
# ---------------------------------------------------------------------------

FLAG_SIZE = 10837  # VBDIS_FlagTokenSize


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class Token9Bit:
    __slots__ = ("m2d1c", "m2d22", "keyword_str_idx")

    def __init__(self, m2d1c, m2d22, keyword_str_idx):
        self.m2d1c = m2d1c
        self.m2d22 = m2d22
        self.keyword_str_idx = keyword_str_idx


def _load_i_dat(path):
    raw = read_bytes(path)
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
    raw = read_bytes(path)
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
        self.fixups = {}          # module id -> [(fixup type, module data offset)]
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
            fixups = self.fixups.setdefault(mod_id, [])
            i += size
            while self._in_bounds(i, 6) and self._u16(i + 4) == FIXUP_BLOCK_TAG:
                fsize, count = self._u16(i), self._u16(i + 2)
                i += 6
                if count:
                    i += count * 2
                    continue
                for _ in range((fsize - 4) // 3):
                    if not self._in_bounds(i, 3):
                        break
                    fixups.append((self.data[self.base + i], self._u16(i + 1)))
                    i += 3

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


# ---------------------------------------------------------------------------
# Control models: the Control Development Kit MODEL, PROPINFO and EVENTINFO
# structures that describe every VB3 control class. Built-in models are read
# from VBRUN300.DLL and custom models from the project's .VBX files; neither
# ships with this script. A form record's property IDs index its model's
# property list, and its event table slots index the model's event list.
#
# Ported from vb3dec pkg/vbx and cmd/vbrunprops
# (https://github.com/jrmcpeek/vb3dec, MIT License, Copyright (c) 2026 Jamie McPeek).
# ---------------------------------------------------------------------------

DT_HSZ, DT_SHORT, DT_LONG, DT_BOOL, DT_COLOR, DT_ENUM, DT_REAL = 1, 2, 3, 4, 5, 6, 7
DT_XPOS, DT_XSIZE, DT_YPOS, DT_YSIZE, DT_PICTURE = 8, 9, 10, 11, 12
DT_INDEX = 61
STD_LEFT, STD_FONTNAME, STD_TEXT = 5, 13, 27

MODEL_DEF_NAME, MODEL_CLASS_NAME, MODEL_PROP_LIST, MODEL_EVENT_LIST = 0x14, 0x16, 0x1A, 0x1C
MODEL_MIN_SIZE = 0x20
VBX_MODEL_VERSIONS = (0x0100, 0x0200, 0x0300)

STD_PROP_COUNT = 43
STD_PROP_ANCHOR = ("Name", "Index", "hWnd", "BackColor", "ForeColor", "Left", "Top", "Width",
                   "Height", "Enabled", "Visible", "MousePointer", "Caption", "FontName")
STD_EVENT_COUNT = 17
STD_EVENT_ANCHOR = ("Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown")
BUILTIN_DEF_NAMES = {
    "Check", "Combo", "Command", "Data", "Dir", "Drive", "File", "Form", "Frame", "HScroll",
    "Image", "Label", "Line", "List", "MDIForm", "Menu", "Option", "Picture", "Shape", "Text",
    "Timer", "VScroll",
}

# Form record control type ID -> (VB3 type name, VBRUN300 model default name)
BUILTIN_CONTROL_TYPES = {
    0x00: ("PictureBox", "Picture"), 0x01: ("Label", "Label"), 0x02: ("TextBox", "Text"),
    0x03: ("Frame", "Frame"), 0x04: ("CommandButton", "Command"), 0x05: ("CheckBox", "Check"),
    0x06: ("OptionButton", "Option"), 0x07: ("ComboBox", "Combo"), 0x08: ("ListBox", "List"),
    0x09: ("HScrollBar", "HScroll"), 0x0A: ("VScrollBar", "VScroll"), 0x0B: ("Timer", "Timer"),
    0x0C: ("Printer", None), 0x0D: ("Form", "Form"), 0x10: ("DriveListBox", "Drive"),
    0x11: ("DirListBox", "Dir"), 0x12: ("FileListBox", "File"), 0x13: ("Menu", "Menu"),
    0x14: ("MDIForm", "MDIForm"), 0x17: ("Line", "Line"), 0x18: ("Image", "Image"),
}


class Prop:
    __slots__ = ("name", "flags", "std")

    def __init__(self, name, flags, std=-1):
        self.name, self.flags, self.std = name, flags, std

    @property
    def dtype(self):
        return self.flags & 0x7F


class Event:
    __slots__ = ("name", "params", "profile", "std")

    def __init__(self, name, params, profile="", std=-1):
        self.name, self.params, self.profile, self.std = name, params, profile, std


class Model:
    __slots__ = ("version", "def_name", "class_name", "props", "events")

    def __init__(self, version, def_name, class_name, props, events):
        self.version, self.def_name, self.class_name = version, def_name, class_name
        self.props, self.events = props, events


def _seg_word(seg, off):
    return struct.unpack_from("<H", seg, off)[0] if 0 <= off and off + 2 <= len(seg) else 0


def _cstring_at(seg, off, max_len=64):
    """Printable NUL-terminated string at a near pointer, or None."""
    if off == 0 or off >= len(seg):
        return None
    end = seg.find(b"\0", off, off + max_len + 1)
    if end <= off or any(c < 0x20 or c > 0x7E for c in seg[off:end]):
        return None
    return seg[off:end].decode("ascii")


def _identifier_at(seg, off):
    s = _cstring_at(seg, off)
    if s is None or not (s[0].isalpha() or s[0] == "_"):
        return None
    if not all(c.isalnum() or c == "_" for c in s) or not s.isascii():
        return None
    return s


def _prop_info_at(seg, off):
    """PROPINFO: near pointer to the name, then the 32-bit flags."""
    if off + 6 > len(seg):
        return None
    name = _cstring_at(seg, _seg_word(seg, off))
    if name is None:
        return None
    return Prop(name, struct.unpack_from("<I", seg, off + 2)[0])


def _event_info_at(seg, off):
    """EVENTINFO: name pointer, parameter count, ..., parameter profile pointer."""
    if off + 10 > len(seg):
        return None
    name = _identifier_at(seg, _seg_word(seg, off))
    params = _seg_word(seg, off + 2)
    if name is None or params > 16:
        return None
    profile = ""
    if params:
        text = _cstring_at(seg, _seg_word(seg, off + 8))
        if text and " As " in text:
            profile = text
    return Event(name, params, profile)


def _ref_list(seg, off, std, decode, limit=255):
    """NULL-terminated array of references; ~n sentinels (0xFFFF - n) name std[n]."""
    items = []
    pos = off
    while pos + 2 <= len(seg):
        ref = _seg_word(seg, pos)
        if ref == 0:
            return items
        if 0xFFFF - ref < len(std):
            items.append(std[0xFFFF - ref])
        else:
            item = decode(seg, ref)
            if item is None or len(items) >= limit:
                return None
            items.append(item)
        pos += 2
    return None


def _scan_models(seg, std_props, std_events, require_class):
    models = []
    for m in range(0, len(seg) - MODEL_MIN_SIZE + 1):
        def_name = _identifier_at(seg, _seg_word(seg, m + MODEL_DEF_NAME))
        if def_name is None:
            continue
        class_name = _identifier_at(seg, _seg_word(seg, m + MODEL_CLASS_NAME))
        if class_name is None:
            if require_class:
                continue
            class_name = ""
        props = _ref_list(seg, _seg_word(seg, m + MODEL_PROP_LIST), std_props, _prop_info_at)
        if not props:
            continue
        event_off = _seg_word(seg, m + MODEL_EVENT_LIST)
        events = (_ref_list(seg, event_off, std_events, _event_info_at) if event_off else None) or []
        models.append(Model(_seg_word(seg, m), def_name, class_name, props, events))
    return models


def _find_std_table(seg, count, anchor, decode, blank):
    """Locate VBRUN300's table of standard property/event pointers by its leading names."""
    for off in range(0, len(seg) - count * 2 + 1):
        items = []
        for i in range(count):
            item = decode(seg, _seg_word(seg, off + i * 2))
            if item is None:
                if blank is None or i < len(anchor):
                    break
                item = blank()
            if i < len(anchor) and item.name != anchor[i]:
                break
            item.std = i
            items.append(item)
        else:
            return items
    return None


def _ne_data_segments(data):
    segments, _ = parse_ne_segments(data)
    for s in segments or []:
        if s["flags"] & SEG_DATA:
            yield data[s["file_off"]:s["file_off"] + s["file_size"]]


def load_vbrun(path):
    """(standard props, standard events, {default name: Model}) from VBRUN300.DLL, or None."""
    data = read_bytes(path)
    for seg in _ne_data_segments(data):
        std_props = _find_std_table(seg, STD_PROP_COUNT, STD_PROP_ANCHOR, _prop_info_at,
                                    lambda: Prop("", 0))
        if std_props is None:
            continue
        std_events = _find_std_table(seg, STD_EVENT_COUNT, STD_EVENT_ANCHOR, _event_info_at, None)
        if std_events is None:
            return None
        builtin = {}
        for m in _scan_models(seg, std_props, std_events, require_class=False):
            prev = builtin.get(m.def_name)
            if m.def_name in BUILTIN_DEF_NAMES and (prev is None or len(m.props) > len(prev.props)):
                builtin[m.def_name] = m
        return std_props, std_events, builtin
    return None


def load_vbx(path, std_props, std_events):
    """{lower-case class name: Model} registered by a .VBX, newest VB3-usable version."""
    best = {}
    for seg in _ne_data_segments(read_bytes(path)):
        for m in _scan_models(seg, std_props, std_events, require_class=True):
            if m.version not in VBX_MODEL_VERSIONS:
                continue
            key = m.class_name.lower()
            if key not in best or m.version > best[key].version:
                best[key] = m
    return best


# VB3-documented parameters of the built-in events (VBRUN300 records only counts).
EVENT_PARAMS = {
    "MouseDown": ["Button As Integer", "Shift As Integer", "X As Single", "Y As Single"],
    "MouseMove": ["Button As Integer", "Shift As Integer", "X As Single", "Y As Single"],
    "MouseUp": ["Button As Integer", "Shift As Integer", "X As Single", "Y As Single"],
    "KeyDown": ["KeyCode As Integer", "Shift As Integer"],
    "KeyUp": ["KeyCode As Integer", "Shift As Integer"],
    "KeyPress": ["KeyAscii As Integer"],
    "Unload": ["Cancel As Integer"],
    "QueryUnload": ["Cancel As Integer", "UnloadMode As Integer"],
    "DragDrop": ["Source As Control", "X As Single", "Y As Single"],
    "DragOver": ["Source As Control", "X As Single", "Y As Single", "State As Integer"],
    "LinkOpen": ["Cancel As Integer"],
    "LinkError": ["LinkErr As Integer"],
    "LinkExecute": ["CmdStr As String", "Cancel As Integer"],
    "Error": ["DataErr As Integer", "Response As Integer"],
    "Validate": ["Action As Integer", "Save As Integer"],
}


def event_params(event, is_array):
    """Parameter declarations of an event procedure; control array handlers get Index first."""
    params = ["Index As Integer"] if is_array else []
    known = EVENT_PARAMS.get(event.name)
    if event.profile:
        params += [" ".join(p.split()) for p in event.profile.split(",") if p.strip()]
    elif known is not None and len(known) == event.params:
        params += known
    else:
        params += [f"p{i} As Variant" for i in range(1, event.params + 1)]
    return params


class ControlModels:
    """Built-in and custom control models found for a project."""

    def __init__(self, search_dirs, custom_vbxs):
        self.vbrun_path = _find_file(search_dirs, "VBRUN300.DLL")
        self.vbx_paths = {}
        self.builtin, self.custom = {}, {}
        self.warnings = []
        std_props, std_events = [], []
        if self.vbrun_path:
            loaded = load_vbrun(self.vbrun_path)
            if loaded is None:
                self.warnings.append(f"no control models found in {self.vbrun_path}")
            else:
                std_props, std_events, self.builtin = loaded
        else:
            self.warnings.append("VBRUN300.DLL not found; built-in event names unavailable")
        for name in custom_vbxs:
            path = _find_file(search_dirs, name)
            self.vbx_paths[name] = path
            if path is None:
                self.warnings.append(f"{name} not found; its controls' event names unavailable")
                continue
            models = load_vbx(path, std_props, std_events)
            if not models:
                self.warnings.append(f"no control models found in {path}")
            self.custom.update(models)

    def builtin_model(self, def_name):
        return self.builtin.get(def_name) if def_name else None


def _find_file(dirs, name):
    """Case-insensitive lookup of a file name in the first directory that has it."""
    target = name.lower()
    for d in dirs:
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for entry in entries:
            if entry.lower() == target:
                return os.path.join(d, entry)
    return None


# ---------------------------------------------------------------------------
# Project directory and form records
#
# RC_DATA 1 is the project directory: a 19-byte header, the title, then
# records of <type:1><name length:1><resource id:2><instance tag:2>..<module
# id:2 at +9>; type 'F' = form, 'C' = custom control file, 'X' = control type.
# Each form's stream is RC_DATA <resource id> and, unless VBGuard stripped it,
# its name table (form name, then control names by control ID) is RC_DATA
# <resource id + 1>. A form stream (magic FF CC 2C) holds the form record and
# then tagged control records: <len:4 (bit 31 = control array)><id:1>
# [<array index:2>]<name>[<type id:1> | 0xFF <type name>]<properties>
# 0xFF <event slot count:1> <slot words>; a slot word with bit 0 set names
# the event procedure's descriptor.
#
# Ported from vb3dec pkg/frm (MIT License, Copyright (c) 2026 Jamie McPeek).
# ---------------------------------------------------------------------------

RC_PROJECT = 1
FORM_MAGIC = b"\xff\xcc\x2c"
SCALE_MODE = "ScaleMode"
COMBO_STYLE_DROPDOWN_LIST = 2
GLOBAL_OBJECT_TAGS = {0x33: "Screen", 0x34: "Clipboard"}


class FormRef:
    __slots__ = ("index", "res_id", "file_name", "name", "instance_tag", "module_id", "control_names")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class Control:
    __slots__ = ("id", "name", "type_name", "is_array", "array_index", "events")

    def __init__(self, id, name, type_name, is_array=False, array_index=0):
        self.id, self.name, self.type_name = id, name, type_name
        self.is_array, self.array_index = is_array, array_index
        self.events = []   # [(slot, Event or None, descriptor token)]


class Form:
    __slots__ = ("ref", "root", "controls", "warnings")

    def __init__(self, ref, root):
        self.ref, self.root, self.controls, self.warnings = ref, root, [], []


def _rcdata(data, res_id):
    for off, size, name_id in _parse_ne_rcdata_list(data):
        if name_id == 0x8000 | res_id and off:
            return data[off:off + size]
    return None


def parse_vb_project(data):
    """(forms, custom control files) from the project directory, or ([], [])."""
    rc = _rcdata(data, RC_PROJECT)
    if rc is None or len(rc) < 19:
        return [], []
    title_len, help_len = struct.unpack_from("<HH", rc, 15)
    pos = 19 + title_len + help_len
    forms, vbxs = [], []
    while pos + 11 <= len(rc):
        rec_type, name_len = rc[pos], rc[pos + 1]
        if rec_type == 0:
            break
        res_assoc, instance_tag = struct.unpack_from("<HH", rc, pos + 2)
        module_id = struct.unpack_from("<H", rc, pos + 9)[0]
        pos += 11
        if name_len == 0xFF and pos < len(rc):
            name_len = rc[pos]
            pos += 1
        name = rc[pos:pos + name_len].rstrip(b"\0").decode("latin1")
        pos += name_len
        if rec_type in (0x46, 0x58) and pos + 2 <= len(rc):
            sub_count = struct.unpack_from("<h", rc, pos)[0]
            pos += 2 + max(sub_count, 0) * 4
        if rec_type == 0x43 and name:
            vbxs.append(name)
        elif rec_type == 0x46:
            res_id = res_assoc & 0x7FFF
            index = len(forms) + 1
            form_name = os.path.splitext(name)[0] if name else f"frm{index}"
            names = _name_table(_rcdata(data, res_id + 1))
            control_names = {}
            if names and names[0]:
                form_name = names[0]
                control_names = {i: n for i, n in enumerate(names[1:], 1) if n}
            forms.append(FormRef(index=index, res_id=res_id, file_name=name or f"FRM{index}.FRM",
                                 name=form_name, instance_tag=instance_tag, module_id=module_id,
                                 control_names=control_names))
        elif rec_type not in (0x43, 0x46, 0x58):
            break
    return forms, vbxs


def _name_table(rc):
    names, pos = [], 0
    while rc and pos < len(rc) and rc[pos]:
        n = rc[pos]
        if pos + 1 + n > len(rc):
            break
        names.append(rc[pos + 1:pos + 1 + n].decode("latin1"))
        pos += 1 + n
    return names


def _payload_size(prop, rest, is_form):
    """Serialized size of a property value, or None if it cannot be determined."""
    if prop.std == STD_LEFT:
        n = 16 if is_form else 8      # Left, Top, Width, Height together
    elif prop.std == STD_FONTNAME:
        if not rest:
            return None
        n = 1 + rest[0] + 4 + 1       # name, Single size, attribute flags
    elif prop.name == SCALE_MODE and prop.dtype == DT_ENUM:
        n = 4
    elif prop.dtype == DT_HSZ:
        if not rest:
            return None
        n = 1 + rest[0]
    elif prop.dtype in (DT_SHORT, DT_INDEX):
        n = 2
    elif prop.dtype in (DT_LONG, DT_COLOR, DT_REAL, DT_XPOS, DT_XSIZE, DT_YPOS, DT_YSIZE):
        n = 4
    elif prop.dtype in (DT_BOOL, DT_ENUM):
        n = 1
    elif prop.dtype == DT_PICTURE:
        if len(rest) < 4:
            return None
        length = struct.unpack_from("<I", rest)[0]
        n = 4 + (length if length != 0xFFFFFFFF else 0)
    else:
        return None
    return n if n <= len(rest) else None


def _event_table_offset(model, blob, is_form, is_combo):
    """Offset of the event table after walking the properties, or None."""
    seen_separator = False
    combo_style = -1
    p = 0
    while p < len(blob):
        if blob[p] == 0xFF:
            if seen_separator:
                return p
            seen_separator = True
            p += 1
            continue
        prop_id = blob[p]
        p += 1
        if prop_id >= len(model.props):
            return None
        prop = model.props[prop_id]
        if is_combo and prop.std == STD_TEXT and combo_style == COMBO_STYLE_DROPDOWN_LIST:
            continue
        n = _payload_size(prop, blob[p:], is_form)
        if n is None:
            return None
        if is_combo and prop.name == "Style" and n == 1:
            combo_style = blob[p]
        p += n
    return None


def _event_table_from_end(blob):
    """An event table that ends the record, allowing a few trailing bytes."""
    for p in range(len(blob) - 2, -1, -1):
        if blob[p] != 0xFF:
            continue
        count = blob[p + 1]
        rem = len(blob) - (p + 2 + count * 2)
        if count > 0 and 0 <= rem <= 4:
            return p
    return None


def _decode_events(blob, model, is_form=False, is_combo=False):
    pos = _event_table_offset(model, blob, is_form, is_combo) if model else None
    if pos is None:
        pos = _event_table_from_end(blob)
    if pos is None or pos + 2 > len(blob) or blob[pos] != 0xFF:
        return []
    events = []
    for slot in range(blob[pos + 1]):
        w = _seg_word(blob, pos + 2 + slot * 2)
        if pos + 4 + slot * 2 > len(blob):
            break
        if w and w & 1:
            event = model.events[slot] if model and slot < len(model.events) else None
            events.append((slot, event, w & ~1))
    return events


def _is_record(stream, pos, known_type=True):
    """True when a control record (length, id, name, type) starts at pos;
    with known_type, its type must also be a built-in or custom control."""
    if pos + 7 > len(stream):
        return False
    raw_len = struct.unpack_from("<I", stream, pos)[0]
    length = raw_len & 0x7FFFFFFF
    if length < 7 or pos + length > len(stream):
        return False
    at = pos + 5 + (2 if raw_len & 0x80000000 else 0)
    type_at = at + 1 + stream[at]
    if type_at >= pos + length:
        return False
    return not known_type or stream[type_at] in BUILTIN_CONTROL_TYPES or stream[type_at] == 0xFF


def form_records(stream, pos, warnings=None):
    """Offsets of the control and menu records after the form record.

    Each record is preceded by a tag. Tags 1 (first child), 2, 3 (next
    sibling) and 5 (menu section) carry a record when one follows and are
    structural otherwise: among controls 2 closes a level, menu items are
    tagged 2, and 3 closes menu levels. 4 ends the form.
    """
    while pos < len(stream):
        tag = stream[pos]
        pos += 1
        if tag == 4:
            return
        if tag not in (1, 2, 3, 5):
            if warnings is not None:
                warnings.append(f"unknown form record tag {tag:#04x} at {pos - 1:#x}")
            return
        # The tag is structural when the next byte is a tag that introduces a
        # record (or ends the form). Otherwise it carries a record: tags 1 and
        # 3 among controls always do, possibly of a control type this table
        # lacks; other tags need a recognisable type.
        nxt = stream[pos] if pos < len(stream) else None
        if nxt == 4 or (nxt in (1, 2, 3, 5) and (_is_record(stream, pos + 1, known_type=False)
                                                 or (pos + 1 < len(stream) and stream[pos + 1] in (1, 2, 3, 4, 5)))):
            continue
        if _is_record(stream, pos, known_type=tag not in (1, 3)):
            yield pos
            pos += struct.unpack_from("<I", stream, pos)[0] & 0x7FFFFFFF
        else:
            if warnings is not None:
                warnings.append(f"form record tag {tag} at {pos - 1:#x} is followed by no record")
            return


def decode_form(data, ref, models):
    """Form with its controls and event bindings, or None when the stream is unreadable."""
    stream = _rcdata(data, ref.res_id)
    if stream is None or len(stream) < 13 or stream[:3] != FORM_MAGIC:
        return None
    rec_len = struct.unpack_from("<I", stream, 9)[0] & 0x7FFFFFFF
    form_end = 9 + rec_len
    if form_end > len(stream):
        return None
    p = 9 + 5
    if p < form_end:
        n = stream[p]
        inline = stream[p + 1:p + 1 + n].rstrip(b"\0").decode("latin1")
        if inline and not ref.control_names:
            ref.name = inline
        p += 1 + n
    p += 1   # form type id
    form = Form(ref, Control(0, ref.name, "Form"))
    form.root.events = _decode_events(stream[p:form_end], models.builtin_model("Form"), is_form=True)

    for pos in form_records(stream, form_end, form.warnings):
        raw_len = struct.unpack_from("<I", stream, pos)[0]
        end = pos + (raw_len & 0x7FFFFFFF)
        ctrl_id = stream[pos + 4]
        cp = pos + 5
        is_array = bool(raw_len & 0x80000000)
        array_index = 0
        if is_array:
            array_index = _seg_word(stream, cp)
            cp += 2
        inline = ""
        if cp < end:
            n = stream[cp]
            inline = stream[cp + 1:cp + 1 + n].rstrip(b"\0").decode("latin1")
            cp += 1 + n
        if cp >= end:
            form.warnings.append(f"control record at {pos:#x} is missing its type")
            pos = end
            continue
        type_id = stream[cp]
        cp += 1
        if type_id == 0xFF:
            n = stream[cp] if cp < end else 0
            type_name = stream[cp + 1:cp + 1 + n].decode("latin1")
            cp += 1 + n
            model = models.custom.get(type_name.lower())
        else:
            type_name, def_name = BUILTIN_CONTROL_TYPES.get(type_id, (f"UnknownControl_0x{type_id:02X}", None))
            model = models.builtin_model(def_name)
        name = ref.control_names.get(ctrl_id) or inline or f"control{ctrl_id}"
        control = Control(ctrl_id, name, type_name, is_array, array_index)
        control.events = _decode_events(stream[cp:end], model, is_combo=type_name == "ComboBox")
        if model is None and control.events:
            form.warnings.append(f"{name} ({type_name}): no control model; event names unavailable")
        form.controls.append(control)
    return form


# ---------------------------------------------------------------------------
# VBDIS3 annotation tables (MAIN.bas): variable kind letters and type suffixes
# ---------------------------------------------------------------------------

# gc114A = "?pmlgcfOTas"   (1-indexed: 1='p' 2='m' 3='l' 4='g' 5='c' 6='f' 7='O' 8='T' 9='a' 10='s')
GC114A = "?pmlgcfOTas"

# Control token kind -> annotation suffix. Kinds 1..7 are the VB3 data type
# codes Integer, Long, Single, Double, Currency, Variant, String; 'v' marks
# Variant as in VBDIS3, which has no Basic type character.
KIND_SUFFIX = {1: "%", 2: "&", 3: "!", 4: "#", 5: "@", 6: "v", 7: "$",
               9: "O", 10: "*"}   # object reference, array


def _ptoken_type_suffix(kind):
    """Type suffix for a variable reference's control token kind, or ''."""
    return KIND_SUFFIX.get(kind, "")


# ---------------------------------------------------------------------------
# Disassembler (port of pcode.py)
# ---------------------------------------------------------------------------

CASE_START   = 5
CASE_FINISH  = 4
CASE_SPECIAL = 8
MASK_LOCALVAR = 0x40   # Cur_VBDat.mTokenFlags And MASK_0100_0000


def _signed16(v):
    return v - 0x10000 if v >= 0x8000 else v


CP1252_UNDEFINED = {0x81, 0x8D, 0x8F, 0x90, 0x9D}


def _ansi_text(raw):
    """Display text for VB3 ANSI (Windows-1252) bytes; undefined bytes map to U+0080..U+009F."""
    return "".join(chr(b) if b in CP1252_UNDEFINED else bytes([b]).decode("cp1252") for b in raw)


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
        self._token_cache  = {}

    def convert_token(self, int_tokens):
        if int_tokens in self._token_cache:
            return self._token_cache[int_tokens]
        d = self._convert_token(int_tokens)
        self._token_cache[int_tokens] = d
        return d

    def _convert_token(self, int_tokens):
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
            "bit_fwd2": _signed16(flags & 0xF000) // 0x1000,   # argument count of some functions
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

    def _ft2_annotation(self, rec):
        """
        Build a VBDIS3-style variable annotation for a token record.
        Returns a string like 'gv1780%' or '' if no variable reference.

        Uses flag_token2 for kind (gc114A char), VarIndex from params and the
        control token's kind for the type suffix.
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

        # Type suffix from the control token's kind
        ct2 = self.control_token[tok + 1] if tok + 1 < len(self.control_token) else 0
        type_suffix = _ptoken_type_suffix(ct2)

        slot_hex = f"{(var_index * 2):x}" if var_index is not None else "?"
        access = "a" if (l01BC == 4) else "v"  # gc116E=4 = array element
        return f"{kind_char}{access}{slot_hex}{type_suffix}"

    def walk(self, start, end, max_tokens=4000, stop_at_finish=True):
        """
        Yield decoded tokens until end, a FINISH token (unless stop_at_finish
        is False), or a decode failure. Each record includes:
          'ann': type annotation string (VBDIS3 M26A6 style), may be ''
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
            params_off, params_len, next_off = self._token_extent(off, num_param)
            params = self.data[params_off:params_off + params_len]
            inline_str = None
            if num_param < 0 and d["low_nibble"] == CASE_SPECIAL:
                inline_str = _inline_string(params)

            cval = None
            if d["keyword"] == "c%":
                if num_param == 1 and len(params) >= 2:
                    cval = struct.unpack_from("<h", params, 0)[0]
                elif num_param == 0:
                    cval = (self.flag_token[int_tokens // 3] >> 9) // 2

            rec = {
                "off": off, "tok": int_tokens, "kw": d["keyword"],
                "np": num_param, "nib": d["low_nibble"], "params": params,
                "str": inline_str, "cval": cval, "ann": "", "end": next_off,
            }

            rec["ann"] = self._ft2_annotation(rec)

            yield rec
            n += 1
            if stop_at_finish and d["low_nibble"] == CASE_FINISH:
                return
            if next_off <= off:
                yield {"off": off, "tok": int_tokens, "bad": "no-progress"}
                return
            off = next_off

    def _token_extent(self, off, num_param):
        """(params offset, params length, next token offset) for a token at off.

        A negative param count means [opcode:2][length:2][bytes], word-aligned.
        """
        if num_param < 0:
            vlen = struct.unpack_from("<H", self.data, off + 2)[0] if off + 4 <= len(self.data) else 0
            next_off = off + 4 + vlen
            return off + 4, vlen, next_off + (next_off & 1)
        return off + 2, num_param * 2, off + 2 + num_param * 2

    def _scan(self, start, end, memo):
        """Follow token boundaries from start like walk(), without decoding.

        Records memo[offset] = (finished, tokens to the terminal token) for
        every offset on the path; finished is True when the path reaches a
        FINISH token, False when it hits an undecodable token, makes no
        progress, or leaves the region first. Paths that join an already
        scanned offset reuse its result, so a region is scanned in linear time.
        """
        path = []
        off = start
        limit = min(end, len(self.data))
        finished, tail = False, 0
        while off not in memo:
            if off + 2 > limit:
                break
            d = self.convert_token(struct.unpack_from("<H", self.data, off)[0])
            if d is None:
                break
            path.append(off)
            if d["low_nibble"] == CASE_FINISH:
                finished = True
                break
            next_off = self._token_extent(off, d["num_param"])[2]
            if next_off <= off:
                break
            off = next_off
        else:
            finished, tail = memo[off]
        # memo value: (finished, tokens from this offset through the FINISH token)
        n = len(path)
        for i, o in enumerate(path):
            memo[o] = (finished, n - i + tail)
        return memo.get(start, (False, 0))

    def find_procedures(self, region_start, region_end, max_tokens=4000):
        """Scan a region for coherent START..FINISH procedure runs of at most
        max_tokens tokens (walk()'s default cap)."""
        procs = []
        memo = {}
        off = region_start
        while off < region_end:
            if off + 2 > len(self.data):
                break
            d = self.convert_token(struct.unpack_from("<H", self.data, off)[0])
            if d and d["low_nibble"] == CASE_START:
                finished, count = memo[off] if off in memo else self._scan(off, region_end, memo)
                if finished and count <= max_tokens:
                    recs = list(self.walk(off, region_end))
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
#     VBModuleDef.M1551. A chain token's descriptor lies at token & 0xFFF8 in
#     VBStartSeg; the low three bits are flags. VBDIS3 instead indexed by
#     RotateRight3(token), which moves those flags into bits 13-15: its
#     VBAbsOffs then picked the wrong segment and Applyreloc1, which indexes
#     without rotating, missed the descriptor and dropped the procedure (see
#     vb3dec docs/audit_vbdis3.md 1.1 and 1.3).
#   - SELECTOR relocation chains of the descriptor segment link the descriptors
#     (at descriptor + 0x26) of each code segment's local subs.
#   - A local sub's code is [seg_base + Offs, seg_base + codeSize).
# ---------------------------------------------------------------------------

MAX_SUBS = 2000
DESC_SIZE = 56
DESC_RELOC_LINK = 0x26   # relocation chain link within a descriptor

# VBModuleDef_struc field indexes (u16 words)
VBMD_NAME_ID     = 2    # name id; vb3dec names procedures sub<id>/fn<id>
VBMD_SUB_OR_FUNC = 6    # bit 0: 1 = Sub, 0 = Function; bits 8-10: return type
VBMD_MODULE      = 10   # owning module id
VBMD_IS_LOCAL    = 11   # bit 0: 1 = local, 0 = external Declare
VBMD_OFFS        = 12   # code offset within the sub's segment
VBMD_NEXT        = 13   # M1551 chain link
VBMD_CODE_SIZE   = 18   # code end offset within the sub's segment
VBMD_LIB         = 20   # M1587 Lib name (name-pool offset)
VBMD_ALIAS       = 23   # M159D Alias/proc name (name-pool offset)

CALL_KEYWORDS = ("Call ", "call")
# flag_token2 classes (MAIN.bas). Under access class gc1172 a token references
# a Sub: kind gc1156 carries the chain token inline, kind gc1152 names a module
# data slot that holds it (MODULE11 ScanTokens Case Else).
GC1152 = 3
GC1156 = 5
GC1172 = 6


def _desc_offset(token):
    """Descriptor offset in VBStartSeg named by a Sub chain token."""
    return token & 0xFFF8


DATA_TYPES = {1: "Integer", 2: "Long", 3: "Single", 4: "Double", 5: "Currency",
              6: "Variant", 7: "String", 8: "String *"}
TYPE_SUFFIX = {"Integer": "%", "Long": "&", "Single": "!", "Double": "#", "Currency": "@", "String": "$"}


class SubInfo:
    __slots__ = ("idx", "desc", "is_local", "is_sub", "returns", "offs", "code_size", "seg",
                 "module", "lib", "alias", "name", "event", "params")

    def __init__(self, idx, desc, vals, lib, alias):
        self.idx      = idx
        self.desc     = desc   # descriptor offset in VBStartSeg
        self.is_local = bool(vals[VBMD_IS_LOCAL] & 1)
        self.is_sub   = bool(vals[VBMD_SUB_OR_FUNC] & 1)
        self.returns  = DATA_TYPES.get((vals[VBMD_SUB_OR_FUNC] >> 8) & 7)
        # vb3dec's names, so its output can be cross-referenced
        prefix = ("" if self.is_local else "ext") + ("sub" if self.is_sub else "fn")
        self.name     = f"{prefix}{vals[VBMD_NAME_ID]:04X}"
        self.event    = None   # (owner, event name, slot) for event procedures
        self.params   = None   # parameter declarations, when known
        self.offs     = vals[VBMD_OFFS] if self.is_local else -1
        self.code_size = vals[VBMD_CODE_SIZE] if self.is_local else -1
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
        self.by_desc = {}      # descriptor offset -> sub index
        self.module_names = {} # module id -> form name, for form modules
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
        desc_end = start["file_size"]

        link = self._u16(rc_base + 86)
        seen = set()
        while link != 0xFFFF and link not in seen and len(self.subs) < MAX_SUBS:
            seen.add(link)
            desc = _desc_offset(link)
            if desc + DESC_SIZE > desc_end:
                break
            vals = struct.unpack_from("<28H", data, start["file_off"] + desc)
            idx = len(self.subs) + 1
            self.by_desc[desc] = idx
            is_local = bool(vals[VBMD_IS_LOCAL] & 1)
            lib = alias = ""
            if not is_local:
                lib = self.globals.pool_name(vals[VBMD_LIB])
                alias = self.globals.pool_name(vals[VBMD_ALIAS])
            self.subs[idx] = SubInfo(idx, desc, vals, lib, alias)
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
                idx = self.by_desc.get(chain - DESC_RELOC_LINK)
                if idx is not None:
                    self.subs[idx].seg = tgt_seg
                chain_pos = start["file_off"] + chain
                if chain_pos + 2 > len(data):
                    break
                chain = self._u16(chain_pos)
                hops += 1

    def code_start(self, sub):
        if not sub.is_local or sub.offs < 0 or sub.seg not in self.seg_base:
            return None
        return self.seg_base[sub.seg] + sub.offs

    def code_end(self, sub):
        cs = self.code_start(sub)
        if cs is None or sub.code_size <= sub.offs:
            return None
        return self.seg_base[sub.seg] + sub.code_size

    def sub_at(self, code_start):
        if self._by_code_start is None:
            self._by_code_start = {}
            for sub in self.subs.values():
                cs = self.code_start(sub)
                if cs is not None:
                    self._by_code_start[cs] = sub
        return self._by_code_start.get(code_start)

    def resolve(self, target):
        """Sub chain token -> SubInfo or None."""
        idx = self.by_desc.get(_desc_offset(target))
        return self.subs.get(idx) if idx is not None else None

    def resolve_call(self, disasm, rec, module=None):
        """Resolve a token that references a Sub to its SubInfo, or None.

        `Call` tokens carry an internal target directly in params[2:4]. Other
        references follow MODULE11 under access class gc1172, with VarIndex =
        the token's last param word / 2:
          gc1156: chain token = the param word
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
            return self.resolve(raw)
        if l01B4 == GC1152 and module is not None:
            token = self.globals.module_word(module, raw & 0xFFFE)
            return self.resolve(token) if token else None
        return None

    def target_text(self, sub):
        if not sub.is_local:
            return f"{sub.lib.rstrip('.')}:{sub.alias}"
        cs = self.code_start(sub)
        return f"{sub.name}@{cs:#x}" if cs is not None else sub.name

    def declaration(self, sub):
        """VB header line for a sub (MODULE6 sub0785). The parameter list is
        omitted when unknown; compiled programs keep only event and call-site
        evidence of it."""
        kind = "Sub" if sub.is_sub else "Function"
        params = f" ({', '.join(sub.params)})" if sub.params is not None else ""
        returns = f" As {sub.returns}" if not sub.is_sub and sub.returns else ""
        if not sub.is_local:
            alias = f' Alias "{sub.alias}"' if sub.alias and sub.alias != sub.name else ""
            return f'Declare {kind} {sub.name} Lib "{sub.lib.rstrip(".")}"{alias}{params}{returns}'
        return f"{kind} {sub.name}{params}{returns}"

    def label(self, sub):
        """Symbol name: event procedures are qualified by their form."""
        form = self.module_names.get(sub.module)
        return f"{form}.{sub.name}" if form and sub.is_local else sub.name

    def apply_forms(self, forms):
        """Name the event procedures bound in each form's event tables."""
        self.module_names.update({f.ref.module_id: f.ref.name for f in forms})
        for form in forms:
            owners = [("Form", False, form.root)] + [(c.name, c.is_array, c) for c in form.controls]
            for owner, is_array, control in owners:
                for slot, event, token in control.events:
                    sub = self.resolve(token)
                    if sub is None or not sub.is_local or sub.module != form.ref.module_id:
                        continue
                    sub.event = (owner, event.name if event else None, slot)
                    if event is not None:
                        sub.name = f"{owner}_{event.name}"
                        sub.params = event_params(event, is_array)

    def proc_sub(self, recs):
        """SubInfo whose code starts at this procedure's first token."""
        return self.sub_at(recs[0]["off"])


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
# Module data slots that name forms and controls, and Declare parameter lists
# inferred from call sites. Ported from vb3dec pkg/pcode/project.go
# (MIT License, Copyright (c) 2026 Jamie McPeek).
# ---------------------------------------------------------------------------

FIXUP_CONTROL = 9   # fixup type: module data slot holding a form control reference


def slot_names(globals_, forms):
    """{module id: {module data offset: name}} for form instances, Screen,
    Clipboard and the controls of the module's own form."""
    form_by_tag = {f.ref.instance_tag & 0xFF: f.ref.name for f in forms}
    form_by_module = {f.ref.module_id: f for f in forms}
    names = {}
    for mod_id, mod in globals_.modules.items():
        slots = {}
        for b in range(0, len(mod) - 3, 2):
            w = _seg_word(mod, b)
            if w & 0xFF00 == 0x8000 and _seg_word(mod, b + 2):
                target = form_by_tag.get(w & 0xFF) or GLOBAL_OBJECT_TAGS.get(w & 0xFF)
                if target:
                    slots[b + 2] = target
        form = form_by_module.get(mod_id)
        by_id = {c.id: c.name for c in form.controls} if form else {}
        for fix_type, off in globals_.fixups.get(mod_id, ()):
            w = _seg_word(mod, off)
            if fix_type == FIXUP_CONTROL and w & 0xF000 == 0x8000:
                slots[off] = by_id.get(w & 0xFF, f"control{w & 0xFF}")
        if slots:
            names[mod_id] = slots
    return names


def _var_slot(disasm, rec):
    """Module data offset a variable-reference token names, or None."""
    d = disasm.convert_token(rec["tok"])
    if not d or not d["flags"] & MASK_LOCALVAR or len(rec["params"]) < 2 or rec["str"] is not None:
        return None
    return struct.unpack_from("<H", rec["params"], len(rec["params"]) - 2)[0]


def apply_slot_names(subs, disasm, procs, names):
    """Set rec['ref'] on tokens whose module data slot names a form or control."""
    for recs in procs:
        owner = subs.proc_sub(recs)
        slots = names.get(owner.module) if owner is not None else None
        if not slots:
            continue
        for rec in recs:
            slot = _var_slot(disasm, rec)
            if slot is not None and slot in slots:
                rec["ref"] = slots[slot]


class ExternArg:
    __slots__ = ("by_ref", "by_val_string", "typ")

    def __init__(self, by_ref=False, by_val_string=False, typ=""):
        self.by_ref, self.by_val_string, self.typ = by_ref, by_val_string, typ


def _arg_size(a):
    if a.by_ref or a.by_val_string:
        return 4   # far pointer
    return {"Integer": 2, "Long": 4, "Single": 4, "Double": 8, "Currency": 8}.get(a.typ, 0)


def _only_integers_unknown(args, arg_bytes):
    """True when the untyped arguments account for exactly 2 bytes each."""
    if arg_bytes < 0:
        return False
    known = sum(_arg_size(a) for a in args)
    unknown = sum(1 for a in args if not _arg_size(a))
    return unknown > 0 and arg_bytes - known == 2 * unknown


def infer_declare_params(calls, arg_bytes):
    """Declare parameters from every call's arguments. VB3 keeps no Declare
    parameter lists; each call converts and pushes arguments as the declaration
    requires. A parameter is ByVal unless some call passes an address, and its
    type is the one all calls agree on (As Any for addresses of unknown type)."""
    n = max((len(c) for c in calls), default=0)
    params = []
    for i in range(n):
        by_ref, types = False, set()
        for args, nbytes in zip(calls, arg_bytes):
            if i >= len(args):
                continue
            a = args[i]
            typ = a.typ
            if not typ and not a.by_ref and not a.by_val_string and _only_integers_unknown(args, nbytes):
                typ = "Integer"
            by_ref = by_ref or a.by_ref
            if a.by_val_string:
                types.add("ByVal String")
            elif typ and typ != "Variant":
                types.add(typ)
        typ = next(iter(types)) if len(types) == 1 else ""
        name = f"p{i + 1}"
        if by_ref:
            # A String's address could be declared As String or As Any, which pass different things.
            params.append(f"{name} As {typ if typ in TYPE_SUFFIX and typ != 'String' else 'Any'}")
        elif typ == "ByVal String":
            params.append(f"ByVal {name}$")
        elif typ in TYPE_SUFFIX and typ != "String":
            params.append(f"ByVal {name}{TYPE_SUFFIX[typ]}")
        else:
            params.append(f"ByVal {name} As Any")
    return params


# Tokens of the call-site protocol for external procedures
TOK_EXTERN_ARG_BYTES = 0x67EA   # operand: argument bytes the call pushes
TOK_BYVAL_STRING = 0x1972       # converts the string on the stack to a ByVal C string
TOK_BYVAL = (0x6A63, 0x6A02)
# Store the value on the stack in a frame temporary of the parameter's type and
# pass the temporary by reference (constants and expressions passed to ByRef
# parameters). Observed in tests/vb3/byref/BYREF.EXE.
TEMP_REFERENCE_TYPES = {0x6AD5: "Integer", 0x6AC5: "Long", 0x6AAB: "Single", 0x6AB5: "Double",
                        0x6A95: "Currency", 0x6A63: "String", 0x699D: "Variant"}
ARG_BYTES = {"Integer": 2, "Long": 4, "Single": 4, "Double": 8, "Currency": 8}
ALT_UNARY_MINUS = 0x00F9
CTL_KIND_ADDRESS = 8
CTL_MODE_VALUE4 = 14            # 4-byte value of a local, not its address
# C<typ> coercion tokens -> target type (vb3dec, from the assignments consuming them)
COERCION_TARGETS = {
    0x0E7B: "Long", 0x0EB0: "Variant", 0x0EC5: "Integer", 0x0F1C: "Variant",
    0x0F67: "Integer", 0x0F7B: "Long", 0x1050: "Integer", 0x1060: "Long",
    0x106D: "Single", 0x10A3: "String", 0x11C3: "Variant",
    0x10F1: "Variant", 0x1102: "Variant", 0x1156: "Variant",
}
# C<typ> conversions to Variant -> the type they convert from, observed in the
# ground-truth program tests/vb3/types (Tmp = v for each declared type)
COERCION_SOURCES = {
    0x0EB0: "Integer", 0x0F1C: "Long", 0x10F1: "Single", 0x1102: "Double",
    0x1156: "Currency", 0x11C3: "String",
}
CONST_TYPES = {"c%": "Integer", "c&": "Long", "c!": "Single", "c#": "Double", "c@": "Currency", "c$": "String",
               "True": "Integer", "False": "Integer", "&Hc&": "Long", "&Hc%": "Integer"}
LONG_LITERALS = {"c&", "&Hc&"}
LONG_FUNCS = {"RGB": 3, "QBColor": 1}   # argument counts of functions returning Long
STRING_FUNCS = {"LCase$", "UCase$", "Mid$", "Left$", "Right$", "Chr$", "String$", "Space$",
                "Format$", "Trim$", "Hex$", "Oct$", "Str$"}
ARITH_OPS = {"+", "-", "*", "/", "\\", "Mod", "=", "<>", "<", ">", "<=", ">=",
             "And", "Or", "Xor", "Eqv", "Imp"}


# ---------------------------------------------------------------------------
# Variables and their types
#
# Each variable reference names a module data slot. Its control token records
# the addressing mode (local frame, module data, global data, parameter, array
# header) and the data type the opcode accesses; for frame variables the slot
# holds the frame offset (negative = local, positive = parameter; String
# locals keep a descriptor word there instead, odd or zero), and for
# globals the offset into the global data area, which identifies the variable
# across modules. Those are recorded facts. Variables whose references record
# no type get types inferred from use, following vb3dec's rules (pkg/pcode
# disasm.go, MIT License, Copyright (c) 2026 Jamie McPeek); every inferred
# type names the rule that produced it.
# ---------------------------------------------------------------------------

# Counter type of For and Next tokens (tests/vb3/usage; 0x1AE8, 0x1B37, 0x1C87 and
# 0x1E08 from Polaris loops over counters of known type)
FOR_COUNTER_TYPES = {0x1A7E: "Integer", 0x1AA6: "Long", 0x1AC8: "Single", 0x1AE2: "Double",
                     0x1AE8: "Double", 0x1AFC: "Currency", 0x1B37: "Variant"}
NEXT_COUNTER_TYPES = {0x1C87: "Integer", 0x1C8A: "Integer", 0x1D08: "Long", 0x1D63: "Single",
                      0x1DA9: "Double", 0x1DCE: "Currency", 0x1E08: "Variant"}
# Operand type of comparison tokens, from operands of recorded type in Polaris and
# tests/vb3. Single and Double share their comparison tokens, so those are omitted.
COMPARE_TYPES = {
    0x396D: "Integer", 0x3980: "Integer", 0x3993: "Integer", 0x39A6: "Integer", 0x39B9: "Integer",
    0x39CC: "Integer", 0x3B1E: "Long", 0x3B42: "Long", 0x3B51: "Long",
    0x3DDB: "String", 0x3DE4: "String", 0x3DED: "String", 0x3DF6: "String", 0x3DFF: "String",
    0x4468: "Variant", 0x447A: "Variant", 0x448C: "Variant", 0x44B0: "Variant",
}
ARRAY_ELEMENT_ADDRESS = 17   # flag_token2 code of untyped element tokens, which push the element's address
# Element type of an array element access, from the second flag_token2 byte of
# its token: 17 + VB type code, 28 for String (11 and 17 are untyped tokens).
ARRAY_ELEMENT_TYPES = {18: "Integer", 19: "Long", 20: "Single", 21: "Double", 22: "Currency",
                       23: "Variant", 28: "String"}
CTL_MODE_LOCAL = 8
CTL_MODE_MODULE = 9
CTL_MODE_GLOBAL = 10
CTL_MODE_PARAM = 11
CTL_MODE_ARRAY_HEADER = 12
CTL_KIND_OBJECT = 9
CTL_KIND_ARRAY = 10
CTL_KIND_CALL = 12
STRING_TYPE_CODE = 7   # (flag token >> 10) & 7 of a String reference
GLOBAL_ARRAY_ELEMENT = 0xC000
STRING_ARG_FUNCS = {"Len": 1, "Asc": 1, "Mid$": 0, "Left$": 0, "Right$": 0, "InStr": 0}
# Statements whose one operand is a String (a Variant operand is converted first)
STRING_STATEMENTS = {"ChDrive", "ChDir", "MkDir", "RmDir", "Kill"}


def _signed(w):
    return w - 0x10000 if w >= 0x8000 else w


def array_descriptor(mod, slot):
    """(element type or None, [(lower, upper)]) of a module data array
    descriptor at slot, or None. Port of vb3dec parseModuleVarBounds."""
    words = [_seg_word(mod, i) for i in range(0, len(mod) - 1, 2)]
    p = slot // 2 + 3
    if p >= len(words) or p < 2:
        return None
    w1, w2 = words[p - 1], words[p - 2]
    if w1 & 0xFFC0 in (0xC000, 0xC500, 0xC600, 0x4600):
        dims = 0
    elif w1 & 0xFFC0 in (0xC100, 0xC200):
        dims = w2 & 0xFF if w2 & 0x4000 else 0
    else:
        dims = words[p + 2] & 0xFF if p + 2 < len(words) and words[p + 2] & 0x7FC0 == 0x5000 else 0
    if dims <= 0:
        return None
    bounds = []
    p += 6
    for _ in range(dims):
        if p + 1 >= len(words):
            break
        count, base = words[p], words[p + 1]
        bounds.insert(0, (base, count + base - 1))
        p += 2
    return DATA_TYPES.get(w1 & 7), bounds


class Variable:
    __slots__ = ("id", "key", "storage", "slot", "slot_word", "module", "frame", "global_offset",
                 "array", "bounds", "recorded", "inferred", "procs", "name", "max_bytes")

    def __init__(self, key, storage, slot, module=None, frame=None, global_offset=None, slot_word=None):
        self.id = None
        self.key, self.storage, self.slot, self.module = key, storage, slot, module
        self.frame, self.global_offset, self.slot_word = frame, global_offset, slot_word
        self.array = False
        self.bounds = None     # [(lower, upper)] per dimension, when recorded
        self.max_bytes = None  # frame bytes up to the next variable: an upper bound on the size
        self.recorded = {}     # type -> reference count
        self.inferred = {}     # type -> set of rule names
        self.procs = set()
        prefix = {"local": "l", "param": "p", "module": "m", "global": "gv"}[storage]
        self.name = f"{prefix}{(global_offset if storage == 'global' else slot):04X}"

    def record(self, typ):
        self.recorded[typ] = self.recorded.get(typ, 0) + 1

    def infer(self, typ, rule):
        if typ:
            self.inferred.setdefault(typ, set()).add(rule)

    @property
    def type_source(self):
        evidence = self.recorded or self.inferred
        if not evidence:
            return None
        if len(evidence) > 1:
            return "conflict"
        return "recorded" if self.recorded else "inferred"

    @property
    def type(self):
        source = self.type_source
        if source in ("recorded", "inferred"):
            return next(iter(self.recorded or self.inferred))
        return None


class VariableTable:
    """Variables referenced by the decoded procedures, keyed by storage identity."""

    def __init__(self, subs, disasm, procs):
        self.subs, self.disasm = subs, disasm
        self.vars = {}
        self.by_proc = {}
        # Global offsets referenced anywhere: an array header reference (ReDim,
        # LBound, element addresses) whose module word is one of them is that
        # global, and can precede the global's first direct reference.
        self.global_words = set()
        for recs in procs:
            owner = subs.proc_sub(recs)
            for rec in recs if owner is not None else ():
                tok = rec["tok"]
                if tok + 1 >= len(disasm.control_token) or rec.get("ref") or rec.get("callee") is not None:
                    continue
                slot = _var_slot(disasm, rec)
                if (slot is not None and disasm.control_token[tok] == CTL_MODE_GLOBAL
                        and disasm.control_token[tok + 1] != CTL_KIND_CALL):
                    word = subs.globals.module_word(owner.module, slot)
                    if word is not None:
                        self.global_words.add(word)
        for recs in procs:
            owner = subs.proc_sub(recs)
            start = recs[0]["off"]
            seen = self.by_proc.setdefault(start, [])
            as_type = None   # "As <type>" clause of a ReDim, recorded before its array reference
            for rec in recs:
                kw = (rec.get("kw") or "").strip()
                if kw == "As" and rec["str"] is None and len(rec["params"]) >= 2:
                    as_type = DATA_TYPES.get(struct.unpack_from("<H", rec["params"])[0])
                elif kw in ("nl", "eos") or kw.startswith("ReDim"):
                    as_type = None
                v = self._reference(rec, owner, start)
                if v is None:
                    continue
                if as_type and v.array:
                    v.record(as_type)
                    as_type = None
                rec["var"] = v
                v.procs.add(start)
                if v not in seen:
                    seen.append(v)
        for v in self.vars.values():
            if v.array and v.storage == "module":
                desc = array_descriptor(subs.globals.modules.get(v.module, b""), v.slot)
                if desc is not None:
                    elem, v.bounds = desc
                    if elem:
                        v.record(elem)
        for vs in self.by_proc.values():
            frames = sorted((v for v in vs if v.storage == "local" and v.frame is not None), key=lambda v: v.frame)
            for v, above in zip(frames, frames[1:]):
                if not v.array:   # an array's frame slot holds its descriptor
                    v.max_bytes = above.frame - v.frame
        for i, v in enumerate(sorted(self.vars.values(), key=lambda v: str(v.key)), 1):
            v.id = i

    def _reference(self, rec, owner, start):
        slot = _var_slot(self.disasm, rec)
        if slot is None or owner is None or rec.get("ref") or rec.get("callee") is not None:
            return None
        ct = self.disasm.control_token
        tok = rec["tok"]
        if tok + 1 >= len(ct):
            return None
        mode, kind = ct[tok], ct[tok + 1]
        if kind == CTL_KIND_CALL:
            return None
        word = self.subs.globals.module_word(owner.module, slot)
        if mode == CTL_MODE_GLOBAL:
            if word is None:
                return None
            v = self._get(("global", word), "global", slot, global_offset=word)
        elif mode == CTL_MODE_MODULE:
            v = self._get(("module", owner.module, slot), "module", slot, module=owner.module)
        elif mode in (CTL_MODE_LOCAL, CTL_MODE_PARAM, CTL_MODE_VALUE4):
            frame = _signed(word) if word is not None else None
            if frame is None or frame == 0 or frame & 1:
                frame = None   # not a frame offset (String locals keep a descriptor word)
            storage = "param" if frame is not None and frame > 0 else "local"
            v = self._get(("frame", start, slot), storage, slot, module=owner.module,
                          frame=frame, slot_word=word)
        elif mode == CTL_MODE_ARRAY_HEADER:
            if word in self.global_words:
                v = self._get(("global", word), "global", slot, global_offset=word)
            elif word is not None and _signed(word) < 0 and not word & 1:
                v = self._get(("frame", start, slot), "local", slot, module=owner.module,
                              frame=_signed(word), slot_word=word)
            else:
                v = self._get(("module", owner.module, slot), "module", slot, module=owner.module)
            v.array = True
            return v
        else:
            return None
        if kind == CTL_KIND_ARRAY:
            v.array = True
            elem = ARRAY_ELEMENT_TYPES.get(self.disasm._ft2_lookup(tok)[1])
            if elem:
                v.record(elem)
            elif v.storage == "global":
                elem = self.subs.globals.module_word(owner.module, slot + 4)
                if elem is not None and elem & GLOBAL_ARRAY_ELEMENT == GLOBAL_ARRAY_ELEMENT and DATA_TYPES.get(elem & 7):
                    v.record(DATA_TYPES[elem & 7])
        elif kind == CTL_KIND_OBJECT:
            v.record("Object")
        elif 1 <= kind <= 7:
            v.record(DATA_TYPES[kind])
        else:
            alt = self.disasm.flag_token[tok // 3] if tok // 3 < len(self.disasm.flag_token) else 0
            if (alt >> 10) & 7 == STRING_TYPE_CODE:
                v.record("String")
        return v

    def _get(self, key, storage, slot, **kw):
        v = self.vars.get(key)
        if v is None:
            v = self.vars[key] = Variable(key, storage, slot, **kw)
        return v

    def params(self, start):
        """Parameter variables of a procedure in declaration order (Pascal
        calling convention: the first parameter has the highest frame offset)."""
        ps = [v for v in self.by_proc.get(start, ()) if v.storage == "param"]
        return sorted(ps, key=lambda v: -v.frame)


class _StackItem:
    __slots__ = ("typ", "coerced", "by_ref", "c_string", "var", "long_literal", "reference", "element")

    def __init__(self, typ="", by_ref=False, var=None):
        self.typ, self.coerced, self.by_ref, self.c_string = typ, None, by_ref, False
        self.var, self.long_literal = var, False
        self.reference = by_ref   # refers to the variable itself (its address, or a ByRef parameter's pointer)
        self.element = False      # an array element's address

    @property
    def value_type(self):
        """Type of the value: its coercion target, "" when coerced to an unknown type."""
        return self.typ if self.coerced is None else self.coerced


def _words(rec):
    if rec["str"] is not None:
        return []
    p = rec["params"]
    return [struct.unpack_from("<H", p, i)[0] for i in range(0, len(p) - 1, 2)]


def simulate(subs, disasm, procs, variables):
    """One pass over every procedure with a typed expression stack. Infers
    Declare parameter lists from the arguments each call pushes, and variable
    types from use. Run after build_call_graph."""
    calls = {}
    local_args = {}   # callee sub index -> [[arg stack items]]
    for recs in procs:
        stack = []
        arg_bytes = -1

        def pop():
            return stack.pop() if stack else _StackItem()

        for rec in recs:
            kw = (rec.get("kw") or "").strip()
            tok = rec["tok"]
            words = _words(rec)
            var = rec.get("var")
            if rec["str"] is not None:
                stack.append(_StackItem("String"))
            elif rec["nib"] in (CASE_START, CASE_FINISH) or kw in ("nl", "eos"):
                stack.clear()
            elif tok == TOK_EXTERN_ARG_BYTES and len(words) == 1:
                arg_bytes = words[0]
            elif tok == TOK_BYVAL_STRING:
                if stack:
                    stack[-1].c_string = True
                    if stack[-1].var is not None and stack[-1].coerced is None:
                        stack[-1].var.infer("String", "byval-string-argument")
            elif kw in ("var()", "call"):
                nargs = words[0] if words else 0
                take = min(nargs, len(stack)) if nargs < 0x8000 else 0
                args = ([_StackItem() for _ in range(nargs - take)] if nargs < 0x8000 else [])
                args += stack[len(stack) - take:]
                del stack[len(stack) - take:]
                callee = rec.get("callee")
                if callee is not None and not callee.is_local:
                    calls.setdefault(callee.idx, ([], []))
                    calls[callee.idx][0].append([ExternArg(a.by_ref, a.c_string, a.value_type) for a in args])
                    calls[callee.idx][1].append(arg_bytes)
                    arg_bytes = -1
                elif callee is not None:
                    local_args.setdefault(callee.idx, []).append(args)
                if callee is not None:
                    stack.append(_StackItem(callee.returns if not callee.is_sub else ""))
                else:
                    item = _StackItem(var.type if var is not None else "", var=var)
                    if var is not None and var.array and disasm._ft2_lookup(tok)[1] == ARRAY_ELEMENT_ADDRESS:
                        item.by_ref = item.reference = item.element = True
                    stack.append(item)
            elif kw == "C<typ>":
                if stack:
                    if stack[-1].var is not None and tok in COERCION_SOURCES:
                        stack[-1].var.infer(COERCION_SOURCES[tok], "conversion-source")
                    stack[-1].coerced = COERCION_TARGETS.get(tok, "")
            elif kw in ("var", "pop.var"):
                mode = disasm.control_token[tok] if tok < len(disasm.control_token) else 0
                kind = disasm.control_token[tok + 1] if tok + 1 < len(disasm.control_token) else 0
                if kind == CTL_KIND_ADDRESS:
                    item = _StackItem(by_ref=mode != CTL_MODE_VALUE4, var=var)
                    item.reference = item.by_ref or (var is not None and var.storage == "param")
                    stack.append(item)
                elif 1 <= kind <= 7:
                    stack.append(_StackItem(DATA_TYPES[kind], var=var))
                else:
                    alt = disasm.flag_token[tok // 3] if tok // 3 < len(disasm.flag_token) else 0
                    stack.append(_StackItem("String" if (alt >> 10) & 7 == 7 else "", var=var))
            elif kw in CONST_TYPES:
                item = _StackItem(CONST_TYPES[kw])
                item.long_literal = kw in LONG_LITERALS
                stack.append(item)
            elif kw.startswith("var"):
                # assignments: var=, var()= (array element, indices first). Only
                # scalar assignments type the variable, and only through an
                # explicit conversion or a String value: store opcodes convert
                # numeric values themselves (a Single assigned a Double literal
                # has no conversion token).
                if kw.startswith("var()") and words:
                    for _ in range(min(words[0], len(stack)) if words[0] < 0x8000 else 0):
                        pop()
                value = pop()
                typed = value.coerced if value.coerced is not None else (
                    "String" if value.typ == "String" else "")
                if var is not None and typed and kw.startswith("var="):
                    var.infer(typed, "assign")
            elif tok in TEMP_REFERENCE_TYPES:
                if stack:
                    stack[-1] = _StackItem(TEMP_REFERENCE_TYPES[tok])
                    stack[-1].reference = True
            elif tok in TOK_BYVAL:
                pass
            elif kw == "&":
                pop()
                pop()
                stack.append(_StackItem("String"))
            elif kw in ARITH_OPS:
                alt = disasm.flag_token[tok // 3] if tok // 3 < len(disasm.flag_token) else 0
                if kw == "-" and alt & 0x1FF == ALT_UNARY_MINUS:
                    continue
                rhs, lhs = pop(), pop()
                if tok in COMPARE_TYPES:
                    for item in (lhs, rhs):
                        if item.var is not None and item.coerced is None:
                            item.var.infer(COMPARE_TYPES[tok], "comparison")
                if kw in ("=", "<>", "<", ">", "<=", ">="):
                    for a, b in ((lhs, rhs), (rhs, lhs)):
                        if b.long_literal and a.var is not None:
                            a.var.infer("Long", "compare-long-literal")
                stack.append(_StackItem("String" if kw == "+" and rhs.typ == "String" else ""))
            elif tok in FOR_COUNTER_TYPES:
                # counter, start, limit: the counter is pushed first
                counter = stack[0] if len(stack) >= 3 else None
                if counter is not None and counter.var is not None:
                    counter.var.infer(FOR_COUNTER_TYPES[tok], "for-counter")
                stack.clear()
            elif tok in NEXT_COUNTER_TYPES:
                if stack and stack[-1].var is not None:
                    stack[-1].var.infer(NEXT_COUNTER_TYPES[tok], "for-counter")
                stack.clear()
            elif kw in STRING_ARG_FUNCS:
                d = disasm.convert_token(tok)
                nargs = STRING_ARG_FUNCS[kw] or max(d["bit_fwd2"] if d else 0, 2)
                args = [pop() for _ in range(nargs)][::-1]
                text_index = 1 if kw == "InStr" and len(args) >= 3 else 0
                if text_index < len(args) and args[text_index].var is not None:
                    args[text_index].var.infer("String", f"{kw}-argument")
                stack.append(_StackItem("Integer" if kw in ("Len", "Asc", "InStr") else "String"))
            elif kw in LONG_FUNCS:
                for _ in range(LONG_FUNCS[kw]):
                    pop()
                stack.append(_StackItem("Long"))
            elif kw in STRING_FUNCS:
                if stack:
                    stack[-1] = _StackItem("String")
            elif kw in STRING_STATEMENTS:
                item = pop()
                if item.var is not None and item.coerced is None:
                    item.var.infer("String", f"{kw}-argument")
    for idx, (arg_lists, nbytes) in calls.items():
        subs.subs[idx].params = infer_declare_params(arg_lists, nbytes)
    _apply_parameter_evidence(subs, variables, local_args)


def _apply_parameter_evidence(subs, variables, local_args):
    """Name and type parameters from event signatures and from call sites."""
    for sub in subs.subs.values():
        start = subs.code_start(sub)
        if start is None:
            continue
        params = variables.params(start)
        if sub.event and sub.params:
            # Event parameters are passed by reference: 4 bytes each, the last at bp+6.
            n = len(sub.params)
            for v in params:
                rel = v.frame - 6
                if rel % 4 == 0 and 0 <= rel // 4 < n:
                    name, _, typ = sub.params[n - 1 - rel // 4].partition(" As ")
                    v.name = name
                    v.infer(typ, "event-signature")
            continue
        for c in local_args.get(sub.idx, []):
            for a, v in _bind_arguments(c, params) or ():
                v.infer(a.value_type, "call-site-argument")
    _propagate_byref_types(subs, variables, local_args)
    for sub in subs.subs.values():
        start = subs.code_start(sub)
        calls = local_args.get(sub.idx)
        if sub.params is None and start is not None and calls:
            params = variables.params(start)
            if params and all(len(c) == len(params) for c in calls):
                sub.params = [f"{v.name} As {v.type or 'Variant'}" for v in params]


def _bind_arguments(args, params):
    """Pair a call's arguments with the callee's referenced parameters, or None.
    By position when every parameter is referenced; otherwise by frame offset
    (Pascal convention: the last argument is at bp+6, and each argument takes 4
    bytes when passed by reference, else its value's size)."""
    if len(args) == len(params):
        return list(zip(args, params))
    sizes = [4 if a.reference else ARG_BYTES.get(a.value_type) for a in args]
    if None in sizes:
        return None
    frame, at = 6, {}
    for a, size in zip(reversed(args), reversed(sizes)):
        at[frame] = a
        frame += size
    if all(v.frame in at for v in params):
        return [(at[v.frame], v) for v in params]
    return None


def _propagate_byref_types(subs, variables, local_args):
    """A variable passed by reference has its parameter's type: VB3 rejects a
    ByRef argument of another type and passes other values in a temporary.
    Iterates because a type can travel through chains of pass-through
    parameters."""
    links = []
    for idx, calls in local_args.items():
        start = subs.code_start(subs.subs[idx])
        params = variables.params(start) if start is not None else []
        for c in calls:
            links += [(a.var, v) for a, v in _bind_arguments(c, params) or ()
                      if a.var is not None and a.reference and a.coerced is None and (a.element or not a.var.array)]
    changed = True
    while changed:
        changed = False
        for arg, param in links:
            for a, b in ((arg, param), (param, arg)):
                if a.type and not b.type:
                    b.infer(a.type, "byref-parameter")
                    changed = True


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
            expr = '"' + _ansi_text(r["str"]) + '"'
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

def _type_text(v):
    """Variable type for display: '~' marks an inferred type, '?' an unknown one."""
    if v.type_source == "inferred":
        return f"~{v.type}"
    if v.type_source == "conflict":
        return "?(" + "|".join(sorted(v.recorded or v.inferred)) + ")"
    return v.type or "?"


def _declarations(variables, start):
    """Plate comment lines for a procedure's parameters and frame variables."""
    lines = []
    for v in variables.params(start):
        lines.append(f"Param {v.name}{'()' if v.array else ''} As {_type_text(v)}  ' bp+{v.frame:#x}")
    for v in sorted(variables.by_proc.get(start, ()), key=lambda v: (v.frame is None, v.frame or 0, v.slot)):
        array = ""
        if v.array:
            dims = ", ".join(f"{lo} To {hi}" if lo else f"{hi}" for lo, hi in v.bounds or ())
            array = f"({dims})"
        if v.storage == "local":
            where = f"  ' bp-{-v.frame:#x}" if v.frame is not None else ""
            if v.type is None and v.max_bytes is not None:
                where += f", at most {v.max_bytes} bytes"
            lines.append(f"Dim {v.name}{array} As {_type_text(v)}{where}")
        elif v.storage == "module" and v.procs == {start}:
            # Static locals and module variables share module data; only this
            # procedure uses this one.
            lines.append(f"Static {v.name}{array} As {_type_text(v)}  ' module data, used only here")
    return lines


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
        extra = f" {_ansi_text(rec['str'])!r}"
    elif rec.get("callee") is not None and subs is not None:
        extra = f" ->{subs.target_text(rec['callee'])}"
    elif rec.get("kw") in CALL_KEYWORDS:
        extra = " ->?"
    v = rec.get("var")
    names = " ".join(x for x in (rec.get("ann"), rec.get("ref"),
                                 f"{v.name}:{_type_text(v)}" if v is not None else None) if x)
    ann = f" [{names}]" if names else ""
    expr = rec.get("expr")
    tail = f"  ; {expr}" if expr and _is_operator(rec) else ""
    runtime = rec.get("runtime_calls")
    if runtime:
        tail += "  => " + ", ".join(runtime[:TOKEN_RUNTIME_CALLS]) + (", ..." if len(runtime) > TOKEN_RUNTIME_CALLS else "")
    indent = "  " * rec.get("level", 0)
    return f"{indent}{rec['kw']:<10} np={rec['np']:>2} {p}{extra}{ann}{tail}".rstrip()


def _signature_text(match):
    kind = "exact" if match["match"] == "exact" else f"similar, {match['score']:.2f}"
    library = f", {match['library']}" if match.get("library") else ""
    return f"Signature: {match['name']} ({kind}{library})"


def _plate(seg_label, i, recs, subs, callers, variables=None, background=(), matches=None):
    sub = subs.proc_sub(recs) if subs else None
    lines = []
    if sub is not None:
        lines.append(subs.declaration(sub))
        form = subs.module_names.get(sub.module)
        if form:
            lines.append(f"Form {form}")
    lines.append(f"VB3 {seg_label} procedure #{i}  ({len(recs)} tokens)")
    match = (matches or {}).get(recs[0]["off"])
    if match:
        lines.append(_signature_text(match))
    if sub is not None and callers.get(sub.idx):
        lines.append("Called from: " + ", ".join(f"{c:#x}" for c in sorted(callers[sub.idx])))
    if variables is not None:
        lines += _declarations(variables, recs[0]["off"])
    reached = proc_runtime_calls(recs, background)
    if reached:
        lines.append("Reaches: " + ", ".join(reached[:PROC_RUNTIME_CALLS]) + (", ..." if len(reached) > PROC_RUNTIME_CALLS else ""))
    return sub, "\n".join(lines)


def annotate(program, base_addr, all_procs, subs, callers, variables=None, background=(), matches=None):
    from ghidra.program.model.symbol import RefType, SourceType
    listing = program.getListing()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()
    ref_mgr = program.getReferenceManager()
    total = refs = 0
    for seg_label, procs in all_procs:
        for i, recs in enumerate(procs):
            addr = addr_space.getAddress(base_addr + recs[0]["off"])
            sub, plate = _plate(seg_label, i, recs, subs, callers, variables, background, matches)
            label = subs.label(sub) if sub is not None else f"{seg_label}_proc_{i:04d}"
            match = (matches or {}).get(recs[0]["off"])
            if match and match["match"] == "exact" and not (sub is not None and sub.event and sub.event[1]):
                # an event procedure keeps its event name when the control model gave one
                form = subs.module_names.get(sub.module) if sub is not None else None
                label = f"{form}.{match['name']}" if form else match["name"]
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
                target = subs.code_start(callee) if callee is not None and subs else None
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

    Local Subs are decoded over their descriptor bounds. Bytes outside any
    descriptor are scanned for START..FINISH runs, which is the only discovery
    available for raw p-code dumps.
    """
    all_procs = []
    for label, rstart, rend in regions:
        spans = []
        if subs is not None:
            for sub in subs.subs.values():
                cs, ce = subs.code_start(sub), subs.code_end(sub)
                if cs is not None and ce is not None and rstart <= cs < ce <= rend:
                    spans.append((cs, ce, sub))
        spans.sort(key=lambda span: span[0])

        procs = []
        gap = rstart
        for cs, ce, sub in spans:
            if cs < gap:
                continue   # overlapping descriptor; keep the first
            procs.extend(disasm.find_procedures(gap, cs))
            recs = [r for r in disasm.walk(cs, ce, max_tokens=(ce - cs) // 2, stop_at_finish=False)
                    if "bad" not in r]
            if recs:
                procs.append(recs)
            gap = ce
        procs.extend(disasm.find_procedures(gap, rend))

        procs.sort(key=lambda recs: recs[0]["off"])
        for recs in procs:
            structure(recs)
            expr_infix(recs)
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

    search_dirs = [os.path.dirname(str(program.getExecutablePath() or "")), vbdis_dir]
    map_path = _find_file(search_dirs, RUNTIME_MAP_FILE)
    runtime_map = None
    if map_path:
        try:
            runtime_map = load_runtime_map(map_path)
            println(f"Runtime map: {map_path}")
        except (OSError, ValueError) as e:
            println(f"Ignoring runtime map: {e}")
    sig_path = _find_file(search_dirs, SIGNATURES_FILE)
    signatures = None
    if sig_path:
        try:
            signatures = load_signatures(sig_path)
            println(f"Signatures: {sig_path}")
        except (OSError, ValueError) as e:
            println(f"Ignoring signatures: {e}")
    analysis, err = analyze(data, vbdis_dir, search_dirs, runtime_map, map_path, signatures, sig_path)
    if analysis is not None:
        subs, callers = analysis["subs"], analysis["callers"]
        variables = analysis["variables"]
        models = analysis["models"]
        externals = sum(1 for s in subs.subs.values() if not s.is_local)
        println(f"NE header: {len(analysis['segments'])} segments, {len(analysis['regions'])} look like p-code.")
        println(f"Sub table: {len(subs.subs)} subs ({externals} external Declares).")
        println(f"Forms: {len(analysis['forms'])}; VBRUN300.DLL: {models.vbrun_path or 'not found'}.")
        for warning in models.warnings:
            println(f"  {warning}")
        all_procs = []
        for label, _, recs in analysis["procs"]:
            if not all_procs or all_procs[-1][0] != label:
                all_procs.append((label, []))
            all_procs[-1][1].append(recs)
    else:
        println(f"NE auto-detect: {err}. Falling back to manual region entry.")
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
        subs, callers, variables = None, {}, None
        all_procs = decode_all(VB3Disasm(vbdis_dir, data), [("manual", rstart, rstart + rlen)])

    for label, procs in all_procs:
        println(f"  {label}: {len(procs)} procedures")
    total_procs = sum(len(p) for _, p in all_procs)
    if total_procs == 0:
        popup("No coherent procedures found. Check region offsets and token tables.")
        return

    println(f"Annotating {total_procs} procedures ...")
    background = analysis["runtime_map"]["background"] if analysis and analysis["runtime_map"] else ()
    matches = analysis["signature_matches"] if analysis else None
    n, refs = annotate(program, base_addr, all_procs, subs, callers, variables, background, matches)
    println(f"Done: annotated {n} procedures across {len(all_procs)} segment(s), {refs} call references.")


# ---------------------------------------------------------------------------
# Command line (outside Ghidra)
# ---------------------------------------------------------------------------

RUNTIME_MAP_SCHEMA = "ghidra-vb3/runtime-map-v1"
RUNTIME_MAP_FILE = "vbrun-map.json"
TOKEN_RUNTIME_CALLS = 3      # nearest calls shown on a token's EOL comment
PROC_RUNTIME_CALLS = 8       # nearest calls shown on a procedure's plate
BACKGROUND_FRACTION = 1 / 3  # calls more procedures reach are left out of summaries
# Operand and statement-boundary tokens: statement starts, variable and
# constant pushes, conversions, separators and generic method/property
# dispatch. Their handlers run on every statement or for any object, so the
# calls they reach describe the runtime, not the statement.
PLUMBING_KEYWORDS = {
    "nl", "eos", ":", "lab", "eol", "eom", "#", ",", "pop.", "met", "v0", "exe", "C<typ>",
    "var", "var=", "var()", "var()=", "pop.var", "pop.var=", "pop.var()", "pop.var()=",
    "c%", "c&", "c!", "c#", "c@", "c$",
}


def load_runtime_map(path):
    """A tools/vbrun_map.py map, or ValueError."""
    with open(path) as f:
        runtime_map = json.load(f)
    if runtime_map.get("schema") != RUNTIME_MAP_SCHEMA:
        raise ValueError(f"runtime map {path}: expected schema {RUNTIME_MAP_SCHEMA}, got {runtime_map.get('schema')!r}")
    return runtime_map


# ---------------------------------------------------------------------------
# Library signatures (tools/vb3_signatures.py builds them from a compiled
# library with known source): name procedures that ship in many programs, such
# as the VB3 setup kit's SETUP1.
# ---------------------------------------------------------------------------

SIGNATURES_SCHEMA = "ghidra-vb3/signatures-v1"
SIGNATURES_FILE = "vb3-signatures.json"
SIGNATURE_NGRAM = 4        # tokens per n-gram for similarity
SIMILAR_MIN = 0.5          # least n-gram Jaccard similarity reported as similar
SIMILAR_MARGIN = 0.1       # lead over the next library procedure a similar match needs
DISTINCT_TOKENS = 20       # procedures this long, or with strings or DLL calls, identify themselves


def _hash32(data):
    import hashlib
    return int(hashlib.sha1(data).hexdigest()[:8], 16)


def procedure_signature(recs):
    """Build-independent features of a procedure: its token sequence without
    operands (slot and frame operands differ between builds), hashes of its
    string constants, and the DLL functions it calls. No code or text is kept."""
    import hashlib
    seq = struct.pack(f"<{len(recs)}H", *(r["tok"] for r in recs))
    strings = sorted(_hash32(r["str"]) for r in recs if r["str"] is not None)
    externs = sorted({(r["callee"].alias or r["callee"].name).lower() for r in recs
                      if r.get("callee") is not None and not r["callee"].is_local})
    n = SIGNATURE_NGRAM
    return {
        "tokens": len(recs),
        "exact": hashlib.sha1(seq + json.dumps([strings, externs]).encode()).hexdigest(),
        "ngrams": sorted({_hash32(seq[2 * i:2 * (i + n)]) for i in range(len(recs) - n + 1)}),
        "strings": strings,
        "externs": externs,
    }


def load_signatures(path):
    """A tools/vb3_signatures.py file, or ValueError."""
    with open(path) as f:
        sigs = json.load(f)
    if sigs.get("schema") != SIGNATURES_SCHEMA:
        raise ValueError(f"signatures {path}: expected schema {SIGNATURES_SCHEMA}, got {sigs.get('schema')!r}")
    return sigs


def _distinct(sig):
    return sig["tokens"] >= DISTINCT_TOKENS or bool(sig["strings"]) or bool(sig["externs"])


def match_signatures(procs, signatures, module_of=None):
    """{procedure start: match} for procedures matching a library procedure:
    exact when the signature is identical (and unique in the library), else
    similar when n-gram similarity is at least SIMILAR_MIN and leads the next
    candidate by SIMILAR_MARGIN. Each library procedure names at most one
    procedure, the best-scoring one. Short procedures without strings or DLL
    calls (a 6-token Sub that calls one procedure) match unrelated code, so
    they count only in a module where a distinctive procedure matched too.
    module_of maps a procedure start to its code module."""
    library = signatures["procedures"]
    by_exact = {}
    for entry in library:
        by_exact.setdefault(entry["exact"], []).append(entry)
    candidates, distinct = [], {}
    for recs in procs:
        sig = procedure_signature(recs)
        distinct[recs[0]["off"]] = _distinct(sig)
        exact = by_exact.get(sig["exact"], [])
        if len(exact) == 1:
            candidates.append((1.0, "exact", recs[0]["off"], exact[0]))
            continue
        grams = set(sig["ngrams"])
        if not grams:
            continue
        scores = sorted(((len(grams & set(e["ngrams"])) / len(grams | set(e["ngrams"])), i)
                         for i, e in enumerate(library) if e["ngrams"]), reverse=True)
        if scores and scores[0][0] >= SIMILAR_MIN and (len(scores) == 1 or scores[0][0] - scores[1][0] >= SIMILAR_MARGIN):
            candidates.append((scores[0][0], "similar", recs[0]["off"], library[scores[0][1]]))
    matches, named = {}, set()
    for score, kind, start, entry in sorted(candidates, key=lambda c: (-c[0], c[2])):
        if start in matches or id(entry) in named:
            continue
        named.add(id(entry))
        matches[start] = {"name": entry["name"], "source": entry.get("source"), "match": kind,
                          "score": round(score, 3), "library": signatures.get("library")}
    module_of = module_of or {}
    anchored = {module_of.get(start) for start in matches if distinct[start]}
    return {start: m for start, m in matches.items() if distinct[start] or module_of.get(start, start) in anchored}


def apply_runtime_map(procs, runtime_map):
    """Set rec['runtime_calls'] to the non-shared calls a token's handler
    reaches, nearest first, and return the program's background calls: those
    more than BACKGROUND_FRACTION of its procedures reach, which procedure
    summaries leave out."""
    calls = {}
    for tok, entry in runtime_map["tokens"].items():
        own = sorted((c for c in entry["calls"] if not c["shared"]), key=lambda c: (c["depth"], c["name"]))
        if own:
            calls[int(tok, 16)] = own
    per_proc = []
    for recs in procs:
        names = set()
        for rec in recs:
            if rec["tok"] in calls and (rec.get("kw") or "").strip() not in PLUMBING_KEYWORDS:
                rec["runtime_calls"] = [c["name"] for c in calls[rec["tok"]]]
                rec["runtime_depths"] = {c["name"]: c["depth"] for c in calls[rec["tok"]]}
                names.update(rec["runtime_calls"])
        per_proc.append(names)
    counts = {}
    for names in per_proc:
        for n in names:
            counts[n] = counts.get(n, 0) + 1
    return sorted(n for n, k in counts.items() if k > BACKGROUND_FRACTION * max(len(procs), 1))


def runtime_map_info(runtime_map, path, models, background=()):
    """Where the map came from, whether it was made from this VBRUN300.DLL,
    and the calls left out of procedure summaries as background."""
    if runtime_map is None:
        return None
    matches = None
    if models.vbrun_path:
        import hashlib
        with open(models.vbrun_path, "rb") as f:
            matches = hashlib.sha256(f.read()).hexdigest() == runtime_map["runtime"]["sha256"]
    return {"path": os.path.abspath(path) if path else None, "sha256": runtime_map["runtime"]["sha256"],
            "max_depth": runtime_map.get("max_depth"), "matches_vbrun300": matches,
            "background": list(background)}


def proc_runtime_calls(recs, background=()):
    """Distinct runtime calls of a procedure's tokens, nearest first, without
    the program's background calls."""
    depth = {}
    for rec in recs:
        for name, d in rec.get("runtime_depths", {}).items():
            if name not in background:
                depth[name] = min(d, depth.get(name, d))
    return sorted(depth, key=lambda n: (depth[n], n))


def analyze(data, tables_dir, search_dirs=(), runtime_map=None, runtime_map_path=None, signatures=None,
            signatures_path=None):
    """Decode an NE EXE. Returns (analysis dict, None) or (None, error string).

    search_dirs are searched for VBRUN300.DLL and the project's .VBX files.
    runtime_map, from tools/vbrun_map.py, annotates tokens with the Win16 and
    DOS calls their handlers reach. signatures, from tools/vb3_signatures.py,
    name library procedures.
    """
    segments, err = parse_ne_segments(data)
    if segments is None:
        return None, err
    disasm = VB3Disasm(tables_dir, data)
    globals_ = VB3GlobalData(data)
    subs = SubTable(data, segments, globals_)
    form_refs, vbxs = parse_vb_project(data)
    models = ControlModels(search_dirs, vbxs)
    forms = [f for f in (decode_form(data, ref, models) for ref in form_refs) if f is not None]
    subs.apply_forms(forms)
    regions = pcode_regions(disasm, segments)
    all_procs = decode_all(disasm, regions, subs)
    procs = [(label, i, recs) for label, ps in all_procs for i, recs in enumerate(ps)]
    flat = [recs for _, _, recs in procs]
    calls, callers = build_call_graph(subs, disasm, flat)
    apply_slot_names(subs, disasm, flat, slot_names(globals_, forms))
    variables = VariableTable(subs, disasm, flat)
    simulate(subs, disasm, flat, variables)
    background = apply_runtime_map(flat, runtime_map) if runtime_map is not None else []
    matches = {}
    if signatures is not None:
        module_of = {recs[0]["off"]: sub.module for recs in flat for sub in [subs.proc_sub(recs)] if sub is not None}
        matches = match_signatures(flat, signatures, module_of)
    return {
        "segments": segments, "regions": regions, "subs": subs, "disasm": disasm,
        "procs": procs, "calls": calls, "callers": callers, "forms": forms, "models": models,
        "variables": variables,
        "runtime_map": runtime_map_info(runtime_map, runtime_map_path, models, background),
        "signatures": ({"path": signatures_path, "library": signatures.get("library"), "matched": len(matches)}
                       if signatures is not None else None),
        "signature_matches": matches,
    }, None


# ---------------------------------------------------------------------------
# JSON output. Offsets are 0-based file offsets. Unknown values are null;
# string constants are latin1-decoded so every byte is preserved.
# ---------------------------------------------------------------------------

def _sha256(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _sub_json(subs, sub):
    return {
        "index": sub.idx,
        "kind": "sub" if sub.is_sub else "function",
        "local": sub.is_local,
        "module": sub.module,
        "segment": sub.seg if sub.is_local else None,
        "code_start": subs.code_start(sub),
        "code_end": subs.code_end(sub),
        "lib": sub.lib.rstrip(".") if not sub.is_local else None,
        "alias": sub.alias if not sub.is_local else None,
        "name": sub.name,
        "returns": sub.returns if not sub.is_sub else None,
        "params": sub.params,
        "event": ({"owner": sub.event[0], "event": sub.event[1], "slot": sub.event[2]}
                  if sub.event else None),
        "declaration": subs.declaration(sub),
    }


def _variable_json(v):
    return {
        "id": v.id,
        "name": v.name,
        "storage": v.storage,
        "module": v.module,
        "slot": v.slot,
        "frame": v.frame,
        "slot_word": v.slot_word,
        "global_offset": v.global_offset,
        "array": v.array,
        "bounds": [list(b) for b in v.bounds] if v.bounds else None,
        "max_bytes": v.max_bytes,
        "type": v.type,
        "type_source": v.type_source,
        "evidence": {
            "recorded": dict(sorted(v.recorded.items())),
            "inferred": {t: sorted(rules) for t, rules in sorted(v.inferred.items())},
        },
        "procedures": sorted(v.procs),
    }


def _form_json(form):
    return {
        "index": form.ref.index,
        "name": form.ref.name,
        "file_name": form.ref.file_name,
        "module": form.ref.module_id,
        "controls": [
            {"id": c.id, "name": c.name, "type": c.type_name,
             "array_index": c.array_index if c.is_array else None}
            for c in form.controls
        ],
        "warnings": form.warnings,
    }


def _token_json(rec):
    out = {
        "offset": rec["off"],
        "size": rec["end"] - rec["off"],
        "token": rec["tok"],
        "keyword": rec["kw"],
        "params": rec["params"].hex(),
        "level": rec.get("level", 0),
    }
    if rec["cval"] is not None:
        out["int"] = rec["cval"]
    if rec["str"] is not None:
        out["string"] = rec["str"].decode("latin1")
    if rec.get("ann"):
        out["var"] = rec["ann"]
    if rec.get("ref"):
        out["ref"] = rec["ref"]
    if rec.get("var") is not None:
        out["variable"] = rec["var"].id
    if rec.get("runtime_calls"):
        out["runtime_calls"] = rec["runtime_calls"]
    if rec.get("callee") is not None:
        out["callee"] = rec["callee"].idx
    elif rec.get("kw") in CALL_KEYWORDS:
        out["callee"] = None
    if rec.get("expr") and _is_operator(rec):
        out["expr"] = rec["expr"]
    return out


def to_json(analysis, exe_path, tables_dir, proc_offset=None, tokens=True):
    subs, callers = analysis["subs"], analysis["callers"]
    selected = [
        (label, i, recs) for label, i, recs in analysis["procs"]
        if proc_offset is None or recs[0]["off"] <= proc_offset < recs[-1]["end"]
    ]
    procedures, referenced, unresolved = [], set(), 0
    by_proc = analysis["variables"].by_proc
    used_vars = set()
    for label, i, recs in selected:
        owner = subs.proc_sub(recs)
        if owner is not None:
            referenced.add(owner.idx)
        calls = []
        for rec in recs:
            callee = rec.get("callee")
            if callee is not None:
                referenced.add(callee.idx)
                calls.append({"offset": rec["off"], "callee": callee.idx})
            elif rec.get("kw") in CALL_KEYWORDS:
                calls.append({"offset": rec["off"], "callee": None})
                unresolved += 1
        proc = {
            "segment": int(label[3:]),
            "index": i,
            "start": recs[0]["off"],
            "end": recs[-1]["end"],
            "sub": owner.idx if owner is not None else None,
            "token_count": len(recs),
            "calls": calls,
            "callers": sorted(callers.get(owner.idx, ())) if owner is not None else [],
            "variables": sorted(v.id for v in by_proc.get(recs[0]["off"], ())),
            "runtime_calls": (proc_runtime_calls(recs, analysis["runtime_map"]["background"])
                              if analysis["runtime_map"] else None),
            "signature": analysis["signature_matches"].get(recs[0]["off"]),
        }
        used_vars.update(proc["variables"])
        if tokens:
            proc["tokens"] = [_token_json(r) for r in recs]
        procedures.append(proc)

    decoded, proc_counts = {}, {}
    for label, _, recs in analysis["procs"]:
        seg = int(label[3:])
        decoded[seg] = decoded.get(seg, 0) + recs[-1]["end"] - recs[0]["off"]
        proc_counts[seg] = proc_counts.get(seg, 0) + 1
    sub_list = [
        _sub_json(subs, sub) for sub in subs.subs.values()
        if proc_offset is None or sub.idx in referenced
    ]
    return {
        "schema": JSON_SCHEMA,
        "tool": {"name": "ghidra-vb3", "version": __version__},
        "target": {"path": os.path.abspath(exe_path), "size": len(analysis["disasm"].data),
                   "sha256": _sha256(exe_path)},
        "tables": {name: _sha256(os.path.join(tables_dir, name))
                   for name in ("vbdis3i.dat", "vbdis3x.dat")},
        "segments": [
            {"segment": s["seg_num"], "file_offset": s["file_off"], "file_size": s["file_size"],
             "flags": s["flags"], "data": bool(s["flags"] & SEG_DATA),
             "procedures": proc_counts.get(s["seg_num"], 0), "decoded_bytes": decoded.get(s["seg_num"], 0)}
            for s in analysis["segments"]
        ],
        "control_models": {
            "vbrun300": analysis["models"].vbrun_path,
            "vbx": analysis["models"].vbx_paths,
            "warnings": analysis["models"].warnings,
        },
        "runtime_map": analysis["runtime_map"],
        "signatures": analysis["signatures"],
        "forms": [_form_json(f) for f in analysis["forms"]],
        "subs": sub_list,
        "variables": [_variable_json(v) for v in sorted(analysis["variables"].vars.values(), key=lambda v: v.id)
                      if proc_offset is None or v.id in used_vars],
        "procedures": procedures,
        "coverage": {
            "procedures": len(analysis["procs"]),
            "procedures_returned": len(procedures),
            "subs": len(subs.subs),
            "subs_returned": len(sub_list),
            "unresolved_calls": unresolved,
            "variables": len(analysis["variables"].vars),
            "variables_typed": {source: sum(1 for v in analysis["variables"].vars.values() if v.type_source == source)
                                for source in ("recorded", "inferred", "conflict")},
            "tokens_included": tokens,
        },
    }


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
                    help="only output the procedure containing this file offset")
    ap.add_argument("--calls", action="store_true", help="print the call graph instead of tokens")
    ap.add_argument("--json", action="store_true", help=f"emit {JSON_SCHEMA} JSON")
    ap.add_argument("--summary", action="store_true", help="with --json, omit per-token records")
    ap.add_argument("--vbx-dir", action="append", default=[],
                    help="directory to search for VBRUN300.DLL and .VBX files before the EXE's own")
    ap.add_argument("--runtime-map", help=f"{RUNTIME_MAP_SCHEMA} file from tools/vbrun_map.py")
    ap.add_argument("--signatures", help=f"{SIGNATURES_SCHEMA} file from tools/vb3_signatures.py")
    ap.add_argument("--version", action="version", version=f"ghidra-vb3 {__version__}")
    args = ap.parse_args(argv)

    with open(args.exe, "rb") as f:
        data = f.read()
    search_dirs = args.vbx_dir + [os.path.dirname(os.path.abspath(args.exe))]
    runtime_map = None
    if args.runtime_map:
        try:
            runtime_map = load_runtime_map(args.runtime_map)
        except (OSError, ValueError) as e:
            raise SystemExit(f"runtime map: {e}")
    signatures = None
    if args.signatures:
        try:
            signatures = load_signatures(args.signatures)
        except (OSError, ValueError) as e:
            raise SystemExit(f"signatures: {e}")
    analysis, err = analyze(data, args.tables, search_dirs, runtime_map, args.runtime_map, signatures, args.signatures)
    if analysis is None:
        if args.json:
            json.dump({"schema": JSON_SCHEMA, "error": {"code": "not-ne", "message": err}}, sys.stdout)
            print()
            raise SystemExit(2)
        raise SystemExit(f"{args.exe}: {err}")

    if args.json:
        json.dump(to_json(analysis, args.exe, args.tables, args.proc, tokens=not args.summary),
                  sys.stdout, separators=(",", ":"))
        print()
        return

    subs, calls, callers = analysis["subs"], analysis["calls"], analysis["callers"]
    if args.calls:
        for label, i, recs in analysis["procs"]:
            sub = subs.proc_sub(recs)
            name = subs.declaration(sub) if sub else f"{label}_proc_{i:04d}"
            for off, callee in calls.get(recs[0]["off"], []):
                print(f"{recs[0]['off']:#08x} {name} @{off:#08x} -> {subs.target_text(callee)}")
        return

    for label, i, recs in analysis["procs"]:
        if args.proc is not None and not (recs[0]["off"] <= args.proc < recs[-1]["end"]):
            continue
        background = analysis["runtime_map"]["background"] if analysis["runtime_map"] else ()
        _, plate = _plate(label, i, recs, subs, callers, analysis["variables"], background,
                          analysis["signature_matches"])
        print("\n".join(f"; {line}" for line in plate.splitlines()))
        for rec in recs:
            print(f"{rec['off']:#08x}: {_fmt_token(rec, subs)}")
        print()


def in_ghidra(namespace):
    """True when run as a Ghidra script. PyGhidra's script globals resolve the
    GhidraScript names on lookup but report False for `in`."""
    try:
        namespace["currentProgram"]
    except KeyError:
        return False
    return True


if in_ghidra(globals()):
    main()
elif __name__ == "__main__":
    cli(sys.argv[1:])
