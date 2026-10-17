"""Runtime map tests: annotation from a map, and the VBRUN300 walker on STMTS.EXE."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ghidra_scripts", "DisassembleVB3PCode.py")
TOOL = os.path.join(ROOT, "tools", "vbrun_map.py")
TYPES_EXE = os.path.join(ROOT, "tests", "vb3", "types", "TYPES.EXE")
STMTS_EXE = os.path.join(ROOT, "tests", "vb3", "stmts", "STMTS.EXE")
VBX_DIR = os.environ.get("VB3_VBX_DIR")
VBRUN = os.path.join(VBX_DIR, "VBRUN300.DLL") if VBX_DIR else None
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR")   # Win16 ordinal names

try:
    import capstone  # noqa: F401
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


def run(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


class RuntimeMapAnnotationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = json.loads(run(SCRIPT, TYPES_EXE, "--json").stdout)
        # the first token that is not operand plumbing
        plumbing = {"nl", "eos", "var", "var=", "var()", "var()=", "c%", "c$", "exe", "C<typ>", "End"}
        cls.token = next(t["token"] for p in out["procedures"] for t in p["tokens"]
                         if t["keyword"].strip() not in plumbing)
        cls.map = {
            "schema": "ghidra-vb3/runtime-map-v1",
            "runtime": {"path": "VBRUN300.DLL", "size": 1, "sha256": "0" * 64},
            "max_depth": 8,
            "tokens": {f"{cls.token:#06x}": {"keyword": "x", "calls": [
                {"name": "USER.MESSAGEBOX", "depth": 2, "shared": False},
                {"name": "KERNEL.GLOBALALLOC", "depth": 1, "shared": True},
            ]}},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cls.map, f)
            cls.map_path = f.name
        cls.out = json.loads(run(SCRIPT, TYPES_EXE, "--json", "--runtime-map", cls.map_path).stdout)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.map_path)

    def test_tokens_carry_their_non_shared_calls(self):
        tokens = [t for p in self.out["procedures"] for t in p["tokens"] if t["token"] == self.token]
        self.assertTrue(tokens)
        for t in tokens:
            self.assertEqual(t["runtime_calls"], ["USER.MESSAGEBOX"])

    def test_procedures_summarise_their_calls(self):
        procs = [p for p in self.out["procedures"] if any(t["token"] == self.token for t in p["tokens"])]
        for p in procs:
            self.assertEqual(p["runtime_calls"], ["USER.MESSAGEBOX"])
        others = [p for p in self.out["procedures"] if p not in procs]
        self.assertTrue(all(p["runtime_calls"] == [] for p in others))

    def test_plumbing_tokens_carry_no_runtime_calls(self):
        # Statement starts and operand tokens run runtime housekeeping on every
        # statement; their calls would drown every procedure's summary.
        nl = next(t["token"] for p in self.out["procedures"] for t in p["tokens"] if t["keyword"].strip() == "nl")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({**self.map, "tokens": {f"{nl:#06x}": {"keyword": "nl", "calls": [
                {"name": "GDI.DELETEMETAFILE", "depth": 2, "shared": False}]}}}, f)
        try:
            out = json.loads(run(SCRIPT, TYPES_EXE, "--json", "--runtime-map", f.name).stdout)
        finally:
            os.unlink(f.name)
        self.assertTrue(all(p["runtime_calls"] == [] for p in out["procedures"]))

    def test_calls_most_procedures_reach_are_background_in_summaries(self):
        # A call reached by more than a third of the procedures says nothing
        # about any one of them; tokens keep it, procedure summaries do not.
        # every procedure ends with an `End` token
        tokens = {t["token"] for p in self.out["procedures"] for t in p["tokens"] if t["keyword"].strip() == "End"}
        common = {f"{t:#06x}": {"keyword": "x", "calls": [{"name": "KERNEL.GLOBALLOCK", "depth": 1, "shared": False}]}
                  for t in tokens}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({**self.map, "tokens": common}, f)
        try:
            out = json.loads(run(SCRIPT, TYPES_EXE, "--json", "--runtime-map", f.name).stdout)
        finally:
            os.unlink(f.name)
        self.assertIn("KERNEL.GLOBALLOCK", out["runtime_map"]["background"])
        self.assertTrue(all("KERNEL.GLOBALLOCK" not in p["runtime_calls"] for p in out["procedures"]))
        self.assertTrue(any("KERNEL.GLOBALLOCK" in t.get("runtime_calls", ())
                            for p in out["procedures"] for t in p["tokens"]))

    def test_reports_the_map_and_whether_it_matches_the_runtime(self):
        info = self.out["runtime_map"]
        self.assertEqual(info["sha256"], "0" * 64)
        self.assertIsNone(info["matches_vbrun300"])   # no VBRUN300.DLL next to TYPES.EXE

    def test_rejects_a_map_with_another_schema(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({**self.map, "schema": "other"}, f)
        try:
            result = run(SCRIPT, TYPES_EXE, "--json", "--runtime-map", f.name)
        finally:
            os.unlink(f.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime map", result.stderr)


@unittest.skipUnless(HAVE_CAPSTONE and VBRUN and os.path.exists(VBRUN) and GHIDRA,
                     "needs capstone, VB3_VBX_DIR with VBRUN300.DLL and GHIDRA_INSTALL_DIR")
class VbrunMapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "map.json")
        result = run(TOOL, VBRUN, STMTS_EXE, "-o", cls.path, "--ghidra", GHIDRA)
        assert result.returncode == 0, result.stderr
        cls.map = json.load(open(cls.path))
        spec = importlib.util.spec_from_file_location("vb3", SCRIPT)
        vb3 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vb3)
        analysis, _ = vb3.analyze(vb3.read_bytes(STMTS_EXE), os.path.dirname(SCRIPT), [])
        cls.case_tokens = {}
        for _, _, recs in analysis["procs"]:
            marker = next((r["str"][5:].decode() for r in recs if r["str"] and r["str"].startswith(b"CASE ")), None)
            if marker:
                cls.case_tokens[marker] = {r["tok"] for r in recs}
        cls.expected = json.load(open(os.path.join(ROOT, "tests", "vb3", "stmts", "expected_calls.json")))

    def calls_of(self, case):
        names = set()
        for tok in self.case_tokens[case]:
            for call in self.map["tokens"].get(f"{tok:#06x}", {}).get("calls", []):
                names.add(call["name"])
        return names

    def test_statements_reach_their_expected_calls(self):
        for case, wanted in self.expected["cases"].items():
            if case in self.expected["known_gaps"]:
                continue
            with self.subTest(case=case):
                self.assertTrue(self.calls_of(case) & set(wanted), f"{case}: none of {wanted}")

    def test_map_identifies_its_runtime(self):
        import hashlib
        with open(VBRUN, "rb") as f:
            self.assertEqual(self.map["runtime"]["sha256"], hashlib.sha256(f.read()).hexdigest())


if __name__ == "__main__":
    unittest.main()
