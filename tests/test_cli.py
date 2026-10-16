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
TYPES_EXE = os.environ.get("VB3_TYPES_EXE")

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


class TypeSuffixTest(unittest.TestCase):
    def test_suffix_follows_data_type_code(self):
        # Control token kinds 1..7 are Integer, Long, Single, Double, Currency, Variant, String.
        self.assertEqual([vb3._ptoken_type_suffix(k) for k in range(1, 8)],
                         ["%", "&", "!", "#", "@", "v", "$"])

    def test_array_and_address_kinds(self):
        self.assertEqual(vb3._ptoken_type_suffix(10), "*")
        self.assertEqual(vb3._ptoken_type_suffix(8), "")


class VariableTypeTest(unittest.TestCase):
    def var(self):
        return vb3.Variable(("frame", 0, 0x20), "local", 0x20)

    def test_recorded_type_wins_over_inferred(self):
        v = self.var()
        v.record("Integer")
        v.infer("String", "assign-string")
        self.assertEqual((v.type, v.type_source), ("Integer", "recorded"))

    def test_inferred_type_when_nothing_recorded(self):
        v = self.var()
        v.infer("Long", "compare-long-literal")
        self.assertEqual((v.type, v.type_source), ("Long", "inferred"))

    def test_disagreeing_evidence_is_a_conflict(self):
        v = self.var()
        v.record("Integer")
        v.record("String")
        self.assertEqual((v.type, v.type_source), (None, "conflict"))

    def test_no_evidence_is_unknown(self):
        self.assertEqual((self.var().type, self.var().type_source), (None, None))


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

    def test_variable_storage_matches_frame_words(self):
        variables = {v["id"]: v for v in self.out["variables"]}
        self.assertTrue(variables)
        for v in variables.values():
            self.assertIn(v["storage"], ("local", "param", "module", "global"))
            if v["storage"] == "local" and v["frame"] is not None:
                self.assertLess(v["frame"], 0)
            if v["storage"] == "param":
                self.assertGreaterEqual(v["frame"], 6)
            if v["storage"] == "global":
                self.assertIsNotNone(v["global_offset"])
            if v["type_source"] == "recorded":
                self.assertIn(v["type"], v["evidence"]["recorded"])
            if v["type_source"] == "inferred":
                self.assertIn(v["type"], v["evidence"]["inferred"])
        for proc in self.out["procedures"]:
            for vid in proc["variables"]:
                self.assertIn(proc["start"], variables[vid]["procedures"])

    def test_event_parameters_take_event_names(self):
        if not self.out["control_models"]["vbrun300"]:
            self.skipTest("VBRUN300.DLL not found next to the sample")
        variables = {v["id"]: v for v in self.out["variables"]}
        subs = {s["index"]: s for s in self.out["subs"]}
        named = 0
        for proc in self.out["procedures"]:
            sub = subs.get(proc["sub"])
            if not sub or not sub["event"] or not sub["params"]:
                continue
            declared = {p.split()[0] for p in sub["params"]}
            for vid in proc["variables"]:
                v = variables[vid]
                if v["storage"] == "param":
                    self.assertIn(v["name"], declared)
                    named += 1
        self.assertTrue(named)

    def test_proc_filter_returns_containing_procedure(self):
        proc = self.out["procedures"][len(self.out["procedures"]) // 2]
        result = run(SAMPLE, "--json", "--summary", "--proc", hex(proc["end"] - 2))
        out = json.loads(result.stdout)
        self.assertEqual([p["start"] for p in out["procedures"]], [proc["start"]])
        self.assertNotIn("tokens", out["procedures"][0])
        self.assertEqual({s["index"] for s in out["subs"]},
                         {proc["sub"]} | {c["callee"] for c in proc["calls"]} - {None})


@unittest.skipUnless(TYPES_EXE, "VB3_TYPES_EXE not set (see tests/vb3/README.md)")
class GroundTruthTypesTest(unittest.TestCase):
    def test_recorded_types_match_declarations(self):
        result = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "score_types.py"),
                                 TYPES_EXE, "--strict"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
