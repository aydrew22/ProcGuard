"""Alert behaviour tests.  Run with:  python -m unittest discover -s tests -v"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from procguard import alerts  # noqa: E402
from procguard.alerts import AlertManager  # noqa: E402
from procguard.models import Assessed, Level, ProcessInfo, Reason, RiskResult  # noqa: E402


def item(pid, level, created=1.0, name="proc"):
    info = ProcessInfo(pid=pid, ppid=1, name=name, exe="/x/" + name, cmdline=[name], username="me",
                       create_time=created, status="running", num_threads=1, cpu_percent=0.0,
                       mem_percent=0.0, mem_rss=0)
    score = {Level.HIGH: 80, Level.MEDIUM: 30, Level.LOW: 0}[level]
    return Assessed(info, RiskResult(score, level, [Reason(score, "why")], "desc"))


class AlertManagerTests(unittest.TestCase):
    def setUp(self):
        self.m = AlertManager()

    def test_first_scan_is_a_baseline(self):
        new, first = self.m.update([item(1, Level.HIGH), item(2, Level.LOW)])
        self.assertTrue(first)
        self.assertEqual([a.info.pid for a in new], [1])

    def test_new_high_after_baseline_alerts(self):
        self.m.update([item(2, Level.LOW)])
        new, first = self.m.update([item(2, Level.LOW), item(3, Level.HIGH)])
        self.assertFalse(first)
        self.assertEqual([a.info.pid for a in new], [3])

    def test_same_process_does_not_alert_twice(self):
        self.m.update([item(2, Level.LOW)])
        self.m.update([item(3, Level.HIGH)])
        new, _ = self.m.update([item(3, Level.HIGH)])
        self.assertEqual(new, [])

    def test_medium_and_low_never_alert(self):
        self.m.update([])
        new, _ = self.m.update([item(4, Level.MEDIUM), item(5, Level.LOW)])
        self.assertEqual(new, [])

    def test_escalation_medium_to_high_alerts(self):
        self.m.update([item(6, Level.MEDIUM)])
        new, _ = self.m.update([item(6, Level.HIGH)])
        self.assertEqual([a.info.pid for a in new], [6])

    def test_flapping_high_medium_high_does_not_realert(self):
        self.m.update([])
        self.m.update([item(7, Level.HIGH)])
        self.m.update([item(7, Level.MEDIUM)])
        new, _ = self.m.update([item(7, Level.HIGH)])
        self.assertEqual(new, [])

    def test_reused_pid_is_a_different_process(self):
        self.m.update([])
        self.m.update([item(8, Level.HIGH, created=1.0)])
        self.m.update([])  # process exits
        new, _ = self.m.update([item(8, Level.HIGH, created=99.0)])  # new process, same PID
        self.assertEqual(len(new), 1)


class NotificationTests(unittest.TestCase):
    def test_macos_text_is_passed_as_argument_not_script(self):
        evil = 'x" & do shell script "touch /tmp/pwned" & "'
        with mock.patch.object(alerts.sys, "platform", "darwin"), \
                mock.patch.object(alerts.subprocess, "run") as run:
            alerts._notify_blocking("ProcGuard", evil)
        argv = run.call_args[0][0]
        self.assertEqual(argv[0], "osascript")
        self.assertIn(evil, argv[-2:])  # passed as a separate argv item
        self.assertFalse(any(evil in part for part in argv[:-2]))  # never inside the script text

    def test_notify_never_raises(self):
        with mock.patch.object(alerts.sys, "platform", "darwin"), \
                mock.patch.object(alerts.subprocess, "run", side_effect=OSError("boom")):
            alerts._notify_blocking("t", "m")  # must swallow the error


if __name__ == "__main__":
    unittest.main()
