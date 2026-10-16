"""CLI tests. Set VB3_SAMPLE to a VB3 NE EXE to run the sample-based tests."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")
SAMPLE = os.environ.get("VB3_SAMPLE")

spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
vb3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vb3)


def run(*args):
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)


class InlineStringTest(unittest.TestCase):
    def test_strips_link_and_length_header(self):
        self.assertEqual(vb3._inline_string(b"\x9aU\x0b\x00\\events.mdb\x00"), b"\\events.mdb")

    def test_keeps_params_when_length_exceeds_payload(self):
        self.assertEqual(vb3._inline_string(b"\x00\x00\xff\x00ab"), b"\x00\x00\xff\x00ab")


class AnsiTextTest(unittest.TestCase):
    def test_decodes_windows_1252(self):
        self.assertEqual(vb3._ansi_text(b"\x3e\x97\x97\xbb\x9b\xbb"), ">\u2014\u2014\u00bb\u203a\u00bb")

    def test_keeps_undefined_bytes(self):
        self.assertEqual(vb3._ansi_text(b"a\x81b"), "a\x81b")


class DescriptorOffsetTest(unittest.TestCase):
    def test_ignores_flag_bits(self):
        # Low three bits of a chain token are flags, not part of the descriptor offset.
        self.assertEqual(vb3._desc_offset(0x0996), 0x0990)
        self.assertEqual(vb3._desc_offset(0x0990), 0x0990)


class ParamProfileTest(unittest.TestCase):
    def test_event_params_add_index_for_control_arrays(self):
        click = vb3.Event("Click", 0, "", 0)
        self.assertEqual(vb3.event_params(click, True), ["Index As Integer"])
        key = vb3.Event("KeyPress", 1, "", 9)
        self.assertEqual(vb3.event_params(key, False), ["KeyAscii As Integer"])
        custom = vb3.Event("Change", 2, "Value As Integer, Shift As Integer", -1)
        self.assertEqual(vb3.event_params(custom, False), ["Value As Integer", "Shift As Integer"])


class DeclareParamsTest(unittest.TestCase):
    def test_byref_argument_becomes_as_any(self):
        calls = [[vb3.ExternArg(by_ref=True), vb3.ExternArg(typ="Integer")]]
        self.assertEqual(vb3.infer_declare_params(calls, [-1]), ["p1 As Any", "ByVal p2%"])

    def test_byval_string(self):
        self.assertEqual(vb3.infer_declare_params([[vb3.ExternArg(by_val_string=True)]], [-1]), ["ByVal p1$"])

    def test_unknown_types_resolved_by_argument_bytes(self):
        # Two unknown arguments filling 4 bytes can only be Integers.
        calls = [[vb3.ExternArg(), vb3.ExternArg()]]
        self.assertEqual(vb3.infer_declare_params(calls, [4]), ["ByVal p1%", "ByVal p2%"])


class NonNeTest(unittest.TestCase):
    def test_json_error_for_non_ne_input(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 62)
        try:
            result = run(f.name, "--json")
        finally:
            os.unlink(f.name)
        self.assertEqual(result.returncode, 2)
        out = json.loads(result.stdout)
        self.assertEqual(out["schema"], vb3.JSON_SCHEMA)
        self.assertEqual(out["error"]["code"], "not-ne")


@unittest.skipUnless(SAMPLE, "VB3_SAMPLE not set")
class SampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = run(SAMPLE, "--json")
        assert result.returncode == 0, result.stderr
        cls.out = json.loads(result.stdout)

    def test_offsets_are_consistent(self):
        for proc in self.out["procedures"]:
            tokens = proc["tokens"]
            self.assertEqual(tokens[0]["offset"], proc["start"])
            self.assertEqual(tokens[-1]["offset"] + tokens[-1]["size"], proc["end"])
            for a, b in zip(tokens, tokens[1:]):
                self.assertLessEqual(a["offset"] + a["size"], b["offset"])

    def test_calls_reference_known_subs(self):
        subs = {s["index"]: s for s in self.out["subs"]}
        unresolved = 0
        for proc in self.out["procedures"]:
            for call in proc["calls"]:
                if call["callee"] is None:
                    unresolved += 1
                else:
                    self.assertIn(call["callee"], subs)
        self.assertEqual(unresolved, self.out["coverage"]["unresolved_calls"])

    def test_callers_are_procedure_starts(self):
        starts = {p["start"] for p in self.out["procedures"]}
        for proc in self.out["procedures"]:
            self.assertTrue(set(proc["callers"]) <= starts)

    def test_every_local_sub_is_decoded_over_its_descriptor_bounds(self):
        by_start = {p["start"]: p for p in self.out["procedures"]}
        for sub in self.out["subs"]:
            if not sub["local"] or sub["code_start"] is None:
                continue
            proc = by_start.get(sub["code_start"])
            self.assertIsNotNone(proc, f"sub {sub['index']} at {sub['code_start']:#x}")
            self.assertEqual(proc["sub"], sub["index"])
            self.assertEqual(proc["end"], sub["code_end"])

    def test_event_procedures_are_named_after_owner_and_event(self):
        events = [s for s in self.out["subs"] if s["event"] is not None]
        if not self.out["control_models"]["vbrun300"]:
            self.skipTest("VBRUN300.DLL not found next to the sample")
        self.assertTrue(events)
        for sub in events:
            if sub["event"]["event"] is None:
                # Bound to a control whose model is unavailable: keep the generic name.
                self.assertRegex(sub["name"], r"^(sub|fn)[0-9A-F]{4}$")
                continue
            self.assertEqual(sub["name"], f"{sub['event']['owner']}_{sub['event']['event']}")
            self.assertIsNotNone(sub["params"])
        names = {}
        for sub in self.out["subs"]:
            key = (sub["module"], sub["name"])
            self.assertNotIn(key, names, f"duplicate {sub['name']} in module {sub['module']:#x}")
            names[key] = sub["index"]

    def test_called_declares_have_parameter_lists(self):
        called = {c["callee"] for p in self.out["procedures"] for c in p["calls"]}
        for sub in self.out["subs"]:
            if not sub["local"] and sub["index"] in called:
                self.assertIsNotNone(sub["params"], sub["declaration"])
                self.assertIn(" Lib ", sub["declaration"])

    def test_forms_list_controls_and_modules(self):
        modules = {s["module"] for s in self.out["subs"]}
        self.assertTrue(self.out["forms"])
        for form in self.out["forms"]:
            self.assertTrue(form["name"])
            for control in form["controls"]:
                self.assertGreater(control["id"], 0)
                self.assertTrue(control["name"])
        self.assertTrue(any(f["module"] in modules for f in self.out["forms"]))

    def test_proc_filter_returns_containing_procedure(self):
        proc = self.out["procedures"][len(self.out["procedures"]) // 2]
        result = run(SAMPLE, "--json", "--summary", "--proc", hex(proc["end"] - 2))
        out = json.loads(result.stdout)
        self.assertEqual([p["start"] for p in out["procedures"]], [proc["start"]])
        self.assertNotIn("tokens", out["procedures"][0])
        self.assertEqual({s["index"] for s in out["subs"]},
                         {proc["sub"]} | {c["callee"] for c in proc["calls"]} - {None})


if __name__ == "__main__":
    unittest.main()
