"""Diagnostic/admission regressions, not content or capacity acceptance."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
LIMITS = HERE.parents[1] / "docs/g1-acceptance.json"


class RunnerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("OUTPOST_TEST_ROOT"))
        self.addCleanup(self.temp.cleanup)
        self.parent = pathlib.Path(self.temp.name)
        self.root = self.parent / "fixture"
        self.tool = self.parent / "tool"

    def invoke(self, size=128 << 20, extra=()):
        # Test scripts stay on the fixture filesystem, which may be noexec.
        # Only the synthetic tool is interpreted; runner subprocess I/O stays real.
        launcher = """import runpy, subprocess, sys
tool=sys.argv.pop(1)
sys.argv.pop(0)
original=subprocess.Popen
def invoke_tool(command, *args, **kwargs):
    if isinstance(command,list) and command and command[0]==tool:
        command=[sys.executable,*command]
    return original(command,*args,**kwargs)
subprocess.Popen=invoke_tool
runpy.run_path(sys.argv[0],run_name='__main__')
"""
        return subprocess.run([
            sys.executable, "-c", launcher, str(self.tool), str(HERE / "run.py"), "--root", str(self.root),
            "--kit-binary", str(self.tool), "--fixture-binary", str(self.tool),
            "--limits", str(LIMITS), "--bytes", str(size), *extra,
        ], capture_output=True, text=True)

    def stub(self, body):
        self.tool.write_text("#!" + sys.executable + "\n" + body)
        self.tool.chmod(0o700)

    def test_full_scale_requires_both_pins_before_creating_root(self):
        self.stub("raise SystemExit('must not execute')\n")
        for extra in ((), ("--container-image", "sha256:" + "1" * 64),
                      ("--filesystem-uuid", "unused-test-uuid")):
            with self.subTest(extra=extra):
                result = self.invoke(100 << 30, extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("full-scale acceptance requires", result.stderr)
                self.assertFalse(self.root.exists())

    def test_malformed_image_digest_rejected_before_root(self):
        self.stub("raise SystemExit('must not execute')\n")
        result = self.invoke(extra=("--container-image", "sha256:short"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pin the container image", result.stderr)
        self.assertFalse(self.root.exists())

    def test_successful_subprocess_cannot_hide_failed_postcondition(self):
        self.stub("""import json, pathlib, sys
if len(sys.argv)>1 and sys.argv[1]=='recovery-key':
    key=pathlib.Path(sys.argv[sys.argv.index('-dest')+1])
    key.write_bytes(b'non-secret diagnostic stub')
    key.chmod(0o600)
if '-op' in sys.argv and sys.argv[sys.argv.index('-op')+1]=='generate':
    pathlib.Path(sys.argv[sys.argv.index('-file')+1]).write_bytes(b'x')
print(json.dumps({'maxRSSKiB':0,'result':{'sourceBytes':0}}))
""")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        report = json.loads((self.root / "results/report.json").read_text())
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure"], {"afterLabel": "backup-base", "errorType": "AssertionError"})
        self.assertEqual(report["operations"][-1]["status"], "PASS")
        self.assertFalse(report["fullScale"])
        self.assertEqual(report["filesystemUUID"], "")
        self.assertGreater(report["filesystemBytes"], 0)
        self.assertFalse((self.root / "results/PASS").exists())
        self.assertEqual([p.name for p in (self.root / "recovery").iterdir()], ["owner.json"])
        self.assertEqual((self.root / "recovery/owner.json").stat().st_mode & 0o777, 0o600)

    def test_failed_subprocess_preserves_failure_receipt(self):
        self.stub("import sys\nsys.stderr.write('sensitive diagnostic text')\nraise SystemExit(3)\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        raw = (self.root / "results/report.json").read_text()
        report = json.loads(raw)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure"], {"afterLabel": "keygen", "errorType": "RuntimeError"})
        self.assertEqual(report["operations"], [{"label": "keygen", "exitCode": 3, "status": "FAIL"}])
        self.assertNotIn("sensitive diagnostic text", raw)
        self.assertFalse((self.root / "results/PASS").exists())


if __name__ == "__main__":
    unittest.main()
