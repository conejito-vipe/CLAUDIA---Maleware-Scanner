"""Startbildschirm-Ablauf: Schritte, Prozent, Fehlermeldungen, sauberes Beenden (ohne Fenster testbar)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from claudia import launcher  # noqa: E402
from claudia.__main__ import pid_alive, watch_parent  # noqa: E402


class RecUi:
    def __init__(self):
        self.updates, self.lines = [], []

    def update(self, pct, title, detail):
        self.updates.append((pct, title, detail))

    def log(self, line):
        self.lines.append(line)


def make_root(with_venv=True, with_ok=True):
    """Programmordner-Attrappe: echter Quellcode, .venv zeigt auf den aktuellen Python."""
    d = tempfile.mkdtemp(prefix="claudia_launch_")
    shutil.copytree(os.path.join(ROOT, "claudia"), os.path.join(d, "claudia"), ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(os.path.join(ROOT, "requirements.txt"), d)
    shutil.copy(os.path.join(ROOT, "requirements-window.txt"), d)
    shutil.copy(os.path.join(ROOT, "requirements-splash.txt"), d)
    if with_venv:
        vpy = launcher.venv_python(d)
        os.makedirs(os.path.dirname(vpy))
        os.symlink(sys.executable, vpy)
        if with_ok:
            for ok in ("paramiko.ok", "webview.ok", "qt.ok"):
                with open(os.path.join(d, ".venv", ok), "w") as fh:
                    fh.write("ok")
    return d


class Env(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)
        os.environ["PYTHONPATH"] = os.pathsep.join([os.path.join(HERE, "fake_paramiko")])
        os.environ["CLAUDIA_HOME"] = tempfile.mkdtemp(prefix="claudia_lh_")
        os.environ["CLAUDIA_TEST_NO_WINDOW"] = "1"            # kein echtes Fenster in Tests (gibt keinen Zugang frei)
        self.log = os.path.join(tempfile.mkdtemp(prefix="claudia_ll_"), "launcher.log")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)


class Plan(Env):
    def test_first_start_has_install_steps_and_weights_sum(self):
        root = make_root(with_venv=False)
        la = launcher.Launcher(root, RecUi(), log_file=self.log)
        keys = [k for k, _t, _w in la.make_plan()]
        self.assertEqual(keys[:6], ["py", "dir", "venv", "pyqt", "pip", "pipwin"])
        self.assertEqual(keys[-3:], ["self", "start", "window"])

    def test_later_start_skips_install(self):
        la = launcher.Launcher(make_root(), RecUi(), log_file=self.log)
        keys = [k for k, _t, _w in la.make_plan()]
        self.assertNotIn("venv", keys)
        self.assertNotIn("pip", keys)
        self.assertNotIn("pipwin", keys)


class FullRun(Env):
    def test_run_hands_over_reports_monotonic_percent_and_stops(self):
        ui = RecUi()
        la = launcher.Launcher(make_root(), ui, python=sys.executable, log_file=self.log)
        try:
            la.run()
            self.assertTrue(la.handed_over)
            self.assertTrue(la.alive())
            pcts = [p for p, _t, _d in ui.updates]
            self.assertEqual(pcts, sorted(pcts))
            self.assertEqual(pcts[-1], 100)
            titles = [t for _p, t, _d in ui.updates if t]
            for want in ("Python prüfen", "Programmordner prüfen", "Programm prüfen (Selbsttest)", "Programm starten", "Programmfenster öffnen"):
                self.assertIn(want, titles)
            la.close_log()
            with open(self.log, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("Selbsttest", text)
            self.assertIn("Übergabe", text)
        finally:
            la.stop()
        self.assertFalse(la.alive())

    def test_release_keeps_program_running(self):
        la = launcher.Launcher(make_root(), RecUi(), python=sys.executable, log_file=self.log)
        la.run()
        try:
            la.release()
            time.sleep(0.5)
            self.assertTrue(la.alive(), "Nach der Übergabe muss das Programm weiterlaufen")
        finally:
            la.child.terminate()
            la.child.wait(10)

    def test_no_url_or_key_in_launcher_output(self):
        ui = RecUi()
        la = launcher.Launcher(make_root(), ui, python=sys.executable, log_file=self.log)
        try:
            la.run()
            time.sleep(0.3)
            joined = "\n".join(ui.lines)
            self.assertNotIn("?k=", joined)
            self.assertNotRegex(joined, r"127\.0\.0\.1:\d+")
        finally:
            la.stop()


class FakeProc:
    def __init__(self, out, rc):
        import io
        self.stdout = io.StringIO(out)
        self._rc = rc

    def poll(self):
        return self._rc

    def wait(self, timeout=None):
        return self._rc

    def kill(self):
        pass

    terminate = kill


class Errors(Env):
    def test_pip_failure_gives_clear_error_with_output(self):
        root = make_root(with_venv=True, with_ok=False)

        def popen(args, **kw):
            if "pip" in args:
                return FakeProc("ERROR: Could not find a version that satisfies the requirement paramiko\n", 1)
            return subprocess.Popen(args, **kw)
        la = launcher.Launcher(root, RecUi(), popen=popen, log_file=self.log)
        with self.assertRaises(launcher.LaunchError) as cm:
            la.run()
        self.assertIn("paramiko", cm.exception.title)
        self.assertIn("Could not find", cm.exception.details)
        self.assertFalse(os.path.exists(os.path.join(root, ".venv", "paramiko.ok")))

    def test_missing_program_files(self):
        root = make_root()
        shutil.rmtree(os.path.join(root, "claudia"))
        with self.assertRaises(launcher.LaunchError) as cm:
            launcher.Launcher(root, RecUi(), log_file=self.log).run()
        self.assertIn("fehlen", cm.exception.title)

    def test_server_exits_immediately(self):
        root = make_root()

        def popen(args, **kw):
            if "--parent-pid" in args:
                return FakeProc("Traceback (most recent call last):\nboom\n", 1)
            return subprocess.Popen(args, **kw)
        with self.assertRaises(launcher.LaunchError) as cm:
            launcher.Launcher(root, RecUi(), popen=popen, log_file=self.log).run()
        self.assertIn("boom", cm.exception.details)

    def test_selftest_problem_is_reported(self):
        root = make_root()
        os.environ["PYTHONPATH"] = ""          # paramiko nicht auffindbar -> Selbsttest meldet FEHLT
        with self.assertRaises(launcher.LaunchError) as cm:
            launcher.Launcher(root, RecUi(), log_file=self.log).run()
        self.assertIn("Selbsttest", cm.exception.title)
        self.assertIn("paramiko", cm.exception.details)

    def test_too_old_python_message(self):
        old = launcher.MIN_PY
        launcher.MIN_PY = (99, 0)
        try:
            with self.assertRaises(launcher.LaunchError) as cm:
                launcher.Launcher(make_root(), RecUi(), log_file=self.log).run()
            self.assertIn("zu alt", cm.exception.title)
        finally:
            launcher.MIN_PY = old


class ParentWatch(unittest.TestCase):
    def test_pid_alive(self):
        self.assertTrue(pid_alive(os.getpid()))
        p = subprocess.Popen([sys.executable, "-c", "pass"])
        p.wait()
        self.assertFalse(pid_alive(p.pid))
        self.assertFalse(pid_alive(0))

    def test_stop_called_when_parent_ends(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"])
        hit = []
        t = watch_parent(p.pid, lambda: hit.append(1), interval=0.1)
        p.wait()
        t.join(5)
        self.assertEqual(hit, [1])


class ConsoleFallback(unittest.TestCase):
    def test_console_ui_collects_lines(self):
        ui = launcher.ConsoleUi()
        ui.log("x")
        ui.update(5, "a", "b")
        self.assertEqual(ui.lines, ["x"])


if __name__ == "__main__":
    unittest.main()


class ConsoleFlow(Env):
    def test_console_main_ends_after_handover(self):
        ui = launcher.ConsoleUi()
        la = launcher.Launcher(make_root(), ui, log_file=self.log)
        import threading

        def work():
            try:
                la.run()
                ui.finished()
            except launcher.LaunchError:
                ui.failed = True
                ui.done.set()
        threading.Thread(target=work, daemon=True).start()
        t = threading.Thread(target=lambda: ui.mainloop(la), daemon=True)
        t.start()
        t.join(60)
        try:
            self.assertFalse(t.is_alive(), "Das Startfenster muss nach der Übergabe enden")
            self.assertTrue(la.handed_over)
            self.assertTrue(la.alive())
        finally:
            la.stop()


class Fonts(unittest.TestCase):
    def test_monospace_preferred(self):
        self.assertEqual(launcher.pick_mono(["Arial", "Consolas", "Courier New"]), "Consolas")
        self.assertEqual(launcher.pick_mono(["Arial", "courier new"]), "courier new")
        self.assertEqual(launcher.pick_mono(["Arial"]), "TkFixedFont")


class TkSmoke(Env):
    """tkinter ist hier nicht installiert: Der Fensteraufbau wird mit Attrappen durchgespielt (Namen, Aufrufe, Ablauf)."""

    def test_window_code_runs_with_stub_toolkit(self):
        from unittest import mock
        tk = mock.MagicMock()
        root = tk.Tk.return_value
        root.winfo_screenwidth.return_value, root.winfo_screenheight.return_value, root.winfo_fpixels.return_value = 1920, 1080, 96.0
        tk.font.families.return_value = ["Arial", "Consolas"]
        with mock.patch.dict(sys.modules, {"tkinter": tk, "tkinter.ttk": tk.ttk, "tkinter.font": tk.font, "tkinter.messagebox": tk.messagebox}):
            ui = launcher._tk_ui()
            self.assertIsNotNone(ui)
            self.assertIsNotNone(ui.skin)
            ui.update(40, "Schritt", "Detail")
            ui.log("Zeile")
            ui.error("Titel", "Text", "Ausgabe", "pfad.log")
            ui._poll()
            ui.finished()
            ui._poll()
            root.destroy.assert_called()


if __name__ == "__main__":
    unittest.main()
