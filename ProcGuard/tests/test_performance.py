"""Regression checks for performance evidence and process-control safeguards."""
import os
import sys
import unittest
from dataclasses import replace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from procguard.models import Assessed, Level, ProcessInfo, RiskResult
from procguard.performance import MIB, PerformanceEngine, protection_reason
from procguard.gui import App


def info(**changes):
    base = dict(pid=900, ppid=2, name="my_app", exe="/Applications/MyApp.app/my_app",
                cmdline=["my_app"], username="alice", create_time=100, status="running",
                num_threads=2, cpu_percent=0, mem_percent=1, mem_rss=100 * MIB)
    base.update(changes)
    return ProcessInfo(**base)


class PerformanceTests(unittest.TestCase):
    def setUp(self):
        self.engine = PerformanceEngine(99, "alice", {88})

    def test_short_cpu_spike_not_flagged(self):
        for now, cpu in ((0, 90), (2, 0), (4, 0), (6, 0)):
            finding = self.engine.assess([info(cpu_percent=cpu)], now=now)[0]
            self.assertFalse(finding.flagged)

    def test_sustained_cpu_requires_time_and_samples(self):
        for now in (0, 1, 2):
            finding = self.engine.assess([info(cpu_percent=25)], now=now)[0]
            self.assertFalse(finding.flagged)
        finding = self.engine.assess([info(cpu_percent=25)], now=4)[0]
        self.assertTrue(finding.flagged)
        self.assertEqual(finding.impact, "Sustained CPU use")

    def test_memory_heavy_can_be_identified_on_first_scan(self):
        finding = self.engine.assess([info(mem_rss=800 * MIB)], now=0)[0]
        self.assertEqual(finding.impact, "Memory heavy")
        self.assertTrue(finding.can_terminate)

    def test_pid_reuse_resets_cpu_history(self):
        for now in (0, 2, 4):
            self.engine.assess([info(cpu_percent=30)], now=now)
        finding = self.engine.assess([info(create_time=200)], now=6)[0]
        self.assertEqual(finding.samples, 1)
        self.assertFalse(finding.flagged)

    def test_long_pause_resets_history(self):
        self.engine.assess([info(cpu_percent=40)], now=0)
        finding = self.engine.assess([info(cpu_percent=40)], now=100)[0]
        self.assertEqual(finding.samples, 1)

    def test_exited_process_history_is_removed(self):
        self.engine.assess([info()], now=0)
        self.assertEqual(self.engine.assess([], now=2), [])
        self.assertEqual(self.engine._history, {})

    def test_system_other_owner_ancestor_and_unknown_identity_protected(self):
        for process in (info(name="WindowServer"), info(username="root"), info(username=None),
                        info(pid=99), info(pid=88), info(pid=1), info(create_time=None),
                        info(name="MsMpEng.exe"), info(name="crowdstrike-agent")):
            with self.subTest(process=process.name, pid=process.pid):
                finding = self.engine.assess([process])[0]
                self.assertFalse(finding.can_terminate)

    def test_simulated_entries_never_terminable(self):
        for process in (info(simulated=True), info(name="old demo (simulated)")):
            self.assertTrue(protection_reason(process, 99, "alice"))

    def test_browser_advice_prefers_tabs(self):
        finding = self.engine.assess([info(name="Google Chrome Helper", mem_rss=800 * MIB)])[0]
        self.assertIn("tabs", finding.advice)

    def test_windows_and_mac_system_paths_protected(self):
        self.assertTrue(protection_reason(info(exe="C:/Windows/System32/example.exe"), 99, "alice", platform="win32"))
        self.assertTrue(protection_reason(info(exe="/System/Library/example"), 99, "alice", platform="darwin"))


class TerminationTests(unittest.TestCase):
    def setUp(self):
        self.app = mock.Mock()
        self.app._own_pid.return_value = 99
        self.app._owner = "alice"
        self.app.performance_engine.ancestors = {88}
        self.process_patch = mock.patch("procguard.gui.psutil.Process")
        self.process = self.process_patch.start()
        self.addCleanup(self.process_patch.stop)

    def assessed(self, process):
        return Assessed(process, RiskResult(0, Level.LOW, [], ""))

    @mock.patch("procguard.gui.messagebox.showinfo")
    def test_demo_never_calls_process_api(self, _show):
        App._terminate_target(self.app, self.assessed(info(simulated=True)))
        self.process.assert_not_called()

    @mock.patch("procguard.gui.messagebox.showinfo")
    def test_system_candidate_cannot_be_terminated(self, _show):
        App._terminate_target(self.app, self.assessed(info(username="root")), from_junk=True)
        self.process.assert_not_called()

    @mock.patch("procguard.gui.messagebox.askyesno", return_value=False)
    def test_cancel_never_calls_process_api(self, _ask):
        App._terminate_target(self.app, self.assessed(info()), from_junk=True)
        self.process.assert_not_called()

    @mock.patch("procguard.gui.messagebox.showinfo")
    @mock.patch("procguard.gui.messagebox.askyesno", return_value=True)
    def test_recycled_pid_is_not_terminated(self, _ask, _show):
        self.process.return_value.create_time.return_value = 101
        App._terminate_target(self.app, self.assessed(info()), from_junk=True)
        self.process.return_value.terminate.assert_not_called()

    @mock.patch("procguard.gui.messagebox.showinfo")
    @mock.patch("procguard.gui.messagebox.askyesno", return_value=True)
    def test_owner_rechecked_after_confirmation(self, _ask, _show):
        process = self.process.return_value
        process.create_time.return_value = 100
        process.username.return_value = "root"
        process.name.return_value = "my_app"
        process.exe.return_value = "/opt/my_app"
        App._terminate_target(self.app, self.assessed(info()), from_junk=True)
        process.terminate.assert_not_called()

    @mock.patch("procguard.gui.threading.Thread")
    @mock.patch("procguard.gui.messagebox.askyesno", return_value=True)
    def test_confirmed_user_app_receives_terminate_only(self, _ask, _thread):
        process = self.process.return_value
        process.create_time.return_value = 100
        process.username.return_value = "alice"
        process.name.return_value = "my_app"
        process.exe.return_value = "/opt/my_app"
        App._terminate_target(self.app, self.assessed(info()), from_junk=True)
        process.terminate.assert_called_once()
        process.kill.assert_not_called()
        self.app._wake.set.assert_called_once()


if __name__ == "__main__":
    unittest.main()
