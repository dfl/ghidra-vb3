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
