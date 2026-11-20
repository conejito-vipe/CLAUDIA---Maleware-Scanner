"""2.4.0: Startbildschirm mit PySide6 (Offscreen), Anbindung an den Launcher, Neustart in der eigenen Umgebung, Plan mit PySide6-Schritt."""
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from claudia import launcher  # noqa: E402
from test_launcher import RecUi, make_root  # noqa: E402

try:
    from PySide6.QtCore import QCoreApplication, QTimer  # noqa: E402
    from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402
    from claudia import splash_qt  # noqa: E402
    HAVE_QT = True
except Exception:            # pragma: no cover
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 nicht installiert")
class Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_size_height_is_20_percent_smaller_and_name_uppercase(self):
        self.assertEqual((splash_qt.WIN_W, splash_qt.WIN_H), (765, 480))
        self.assertEqual(splash_qt.APP_NAME, "CLAUDIA")
        s = splash_qt.Splash()
        self.assertEqual(s.width(), 765 + 2 * splash_qt.SHADOW)
        self.assertEqual(s.height(), 480 + 2 * splash_qt.SHADOW)

    def test_logo_is_complete_not_cropped_and_fits(self):
        s = splash_qt.Splash()
        self.assertFalse(s.logo.isHidden())
        shown = s.logo.pixmap()
        src = s._logo_src
        self.assertFalse(src.isNull())
        dpr = shown.devicePixelRatio()
        w, h = shown.width() / dpr, shown.height() / dpr
        self.assertLessEqual(w, splash_qt.LOGO_BOX[0] + 1)
        self.assertLessEqual(h, splash_qt.LOGO_BOX[1] + 1)
        self.assertAlmostEqual(w / h, src.width() / src.height(), delta=0.02)     # Seitenverhältnis unverändert: nichts abgeschnitten
        self.assertLessEqual(h + 40 + 50, splash_qt.WIN_H)                          # passt mit Kopfzeile und Balken ins Fenster

    def test_missing_logo_does_not_crash(self):
        with mock.patch.object(splash_qt, "LOGO_FILE", "assets/gibtsnicht.png"):
            s = splash_qt.Splash()
        self.assertTrue(s.logo.isHidden())

    def test_progress_modes_and_status(self):
        s = splash_qt.Splash()
        s.show()
        self.assertEqual(s.bar.maximum(), 0)                    # Start: unbestimmt
        s.set_progress(40, "Prüfe Umgebung")
        self.assertEqual((s.bar.minimum(), s.bar.maximum()), (0, 100))
        self.assertEqual(s.pct.text(), "40 %")
        self.assertIn("Prüfe", s.status.text())
        s.set_progress(-1, "Warte")
        self.assertEqual(s.bar.maximum(), 0)
        self.assertEqual(s.pct.text(), "")
        s.set_progress(500, "")
        self.assertEqual(s.pct.text(), "100 %")                  # begrenzt

    def test_qtui_thread_safe_updates_and_finish(self):
        ui = splash_qt.QtUi()
        got = []

        def work():
            ui.update(10, "Python prüfen", "Version 3")
            ui.log("ignoriert")
            ui.update(100, "Fertig", "")
            ui.finished()
            got.append(1)
        threading.Thread(target=work, daemon=True).start()
        QTimer.singleShot(5000, QCoreApplication.quit)           # Notbremse
        ui.mainloop(None)
        self.assertEqual(got, [1])
        self.assertEqual(ui.splash.pct.text(), "100 %")
        self.assertFalse(ui.failed)

    def test_qtui_error_shows_message_and_ends(self):
        ui = splash_qt.QtUi()
        shown = []
        with mock.patch.object(QMessageBox, "exec", lambda self: shown.append(self.text())):
            threading.Thread(target=lambda: ui.error("Titel", "Text", "Details", "log.txt"), daemon=True).start()
            QTimer.singleShot(5000, QCoreApplication.quit)
            ui.mainloop(None)
        self.assertTrue(ui.failed)
        self.assertTrue(shown and "Titel" in shown[0] and "log.txt" in shown[0])


class Launch(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)
        os.environ["CLAUDIA_HOME"] = tempfile.mkdtemp(prefix="claudia_q_")
        for k in ("CLAUDIA_NO_REEXEC", "CLAUDIA_NO_QT"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def test_plan_has_pyqt_step_only_until_installed(self):
        first = [k for k, _t, _w in launcher.Launcher(make_root(with_venv=False), RecUi(), log_file=os.devnull).make_plan()]
        self.assertEqual(first[:6], ["py", "dir", "venv", "pyqt", "pip", "pipwin"])
        later = [k for k, _t, _w in launcher.Launcher(make_root(), RecUi(), log_file=os.devnull).make_plan()]
        self.assertNotIn("pyqt", later)
        root = make_root()
        os.remove(os.path.join(root, ".venv", "qt.ok"))
        again = [k for k, _t, _w in launcher.Launcher(root, RecUi(), log_file=os.devnull).make_plan()]
        self.assertIn("pyqt", again)

    def test_reexec_in_venv_only_with_marker_once_and_outside_venv(self):
        root = make_root()
        with mock.patch.object(launcher.subprocess, "Popen") as po:
            self.assertTrue(launcher._reexec_in_venv(root))
            args, kw = po.call_args
            self.assertEqual(args[0][-2:], ["-m", "claudia.launcher"])
            self.assertEqual(kw["env"]["CLAUDIA_NO_REEXEC"], "1")
            self.assertEqual(kw["cwd"], root)
        with mock.patch.object(launcher.subprocess, "Popen") as po:
            os.environ["CLAUDIA_NO_REEXEC"] = "1"                 # kein zweites Mal (keine Schleife)
            self.assertFalse(launcher._reexec_in_venv(root))
            os.environ.pop("CLAUDIA_NO_REEXEC")
            os.remove(os.path.join(root, ".venv", "qt.ok"))       # ohne Marke: nichts tun
            self.assertFalse(launcher._reexec_in_venv(root))
            with open(os.path.join(root, ".venv", "qt.ok"), "w") as fh:
                fh.write("ok")
            with mock.patch.object(launcher.sys, "prefix", os.path.join(root, ".venv")):      # läuft schon in der Umgebung
                self.assertFalse(launcher._reexec_in_venv(root))
            os.environ["CLAUDIA_NO_QT"] = "1"
            self.assertFalse(launcher._reexec_in_venv(root))
            self.assertEqual(po.call_count, 0)

    def test_bootstrap_plan_only_sets_up_environment_and_pyside(self):
        l = launcher.Launcher(make_root(with_venv=False), RecUi(), log_file=os.devnull)
        l.bootstrap = True
        self.assertEqual([k for k, _t, _w in l.make_plan()], ["py", "dir", "venv", "pyqt"])

    def test_bootstrap_ui_prints_ascii_and_reports_failure(self):
        import io
        ui = launcher.BootstrapUi()
        buf = io.StringIO()
        with mock.patch.object(launcher.sys, "stdout", buf):
            ui.update(10, "Umgebung für Python", "")
            ui.update(10, "doppelt", "")
            ui.error("Fehlschlag", "x", "", "log.txt")
        out = buf.getvalue()
        self.assertEqual(out.count("[ 10 %]"), 1)
        self.assertNotIn("ü", out)
        self.assertTrue(ui.failed and ui.done.is_set())

    def test_start_bat_runs_bootstrap_before_window_when_marker_missing(self):
        txt = open(os.path.join(os.path.dirname(HERE), "start.bat"), encoding="utf-8").read()
        self.assertIn('if not exist ".venv\\qt.ok"', txt)
        self.assertLess(txt.index("claudia.launcher --bootstrap"), txt.index("pyw -3 -m claudia.launcher"))

    def test_qt_ui_falls_back_when_disabled(self):
        os.environ["CLAUDIA_NO_QT"] = "1"
        self.assertIsNone(launcher._qt_ui())


if __name__ == "__main__":
    unittest.main()
