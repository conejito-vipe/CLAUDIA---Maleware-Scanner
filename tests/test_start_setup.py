"""start.bat richtet Python selbst ein (Download von python.org mit Signaturpruefung), startet ohne Neustart weiter
und legt die Verknuepfung mit dem Eichhoernchen-Symbol an. Auf Linux nur Aufbau und Sicherheitsregeln pruefbar,
das Verhalten unter Windows ist hier NICHT getestet."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def raw(rel):
    with open(os.path.join(ROOT, rel), "rb") as fh:
        return fh.read()


class StartBat(unittest.TestCase):
    def setUp(self):
        self.b = raw("start.bat")
        self.t = self.b.decode("ascii")          # nur ASCII: keine Umlaute, die je nach Codepage kaputt gehen

    def test_crlf_line_endings(self):
        # Marken (goto/call) brauchen unter Windows Zeilenende CRLF
        self.assertNotIn(b"\n", self.b.replace(b"\r\n", b""))

    def test_labels_exist_for_every_call_and_goto(self):
        labels = set(re.findall(r"(?m)^:(\w+)", self.t))
        used = set(re.findall(r"(?:call|goto) :(\w+)", self.t))
        self.assertTrue(used)
        self.assertEqual(used - labels, set())

    def test_installs_python_instead_of_asking_user(self):
        self.assertIn("python_setup.ps1", self.t)
        self.assertLess(self.t.index("call :install_python"), self.t.index("goto :python_failed"))
        # nach der Installation wird sofort weitergesucht, kein manueller Neustart
        self.assertRegex(self.t, r"call :install_python\s+call :find_python")
        self.assertIn("LOCALAPPDATA%\\Programs\\Python", self.t)

    def test_no_dead_end_before_install_attempt(self):
        # zwischen "Python fehlt" und dem Installationsversuch darf es keine Pause und keinen Abbruch geben
        part = self.t.split("\r\n:install_python")[1].split("\r\n:python_failed")[0]
        self.assertNotIn("pause", part)
        self.assertNotIn("exit /b 1", part)

    def test_shortcut_with_icon(self):
        self.assertIn("make_shortcut.ps1", self.t)
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "claudia", "make_shortcut.ps1")))
        ps = raw("claudia/make_shortcut.ps1").decode("ascii")
        self.assertIn("claudia\\assets\\claudia.ico", ps)

    def test_bootstrap_still_runs_before_window(self):
        self.assertLess(self.t.index("claudia.launcher --bootstrap"), self.t.index("claudia.launcher\r\n    exit /b 0"))


class PythonSetupScript(unittest.TestCase):
    def setUp(self):
        self.ps = raw("claudia/python_setup.ps1").decode("ascii")

    def test_only_official_source_and_signature_check(self):
        urls = set(re.findall(r"https?://[^\s\"']+", self.ps))
        self.assertEqual({u.split("/")[2] for u in urls}, {"www.python.org"})
        self.assertIn("Get-AuthenticodeSignature", self.ps)
        self.assertIn("Python Software Foundation", self.ps)
        self.assertLess(self.ps.index("Get-AuthenticodeSignature"), self.ps.index("Start-Process"))

    def test_user_install_without_admin_and_no_code_from_net(self):
        self.assertIn("InstallAllUsers=0", self.ps)
        self.assertNotRegex(self.ps, r"(?i)invoke-expression|\biex\b|-Verb\s+RunAs|DownloadString")

    def test_exit_codes_and_cleanup(self):
        self.assertIn("exit 0", self.ps)
        self.assertIn("exit 1", self.ps)
        self.assertIn("Remove-Item", self.ps)


class Icon(unittest.TestCase):
    def test_ico_has_all_sizes(self):
        from PIL import Image
        im = Image.open(os.path.join(ROOT, "claudia", "assets", "claudia.ico"))
        self.assertEqual(im.format, "ICO")
        self.assertIn((256, 256), im.info.get("sizes", set()))
        self.assertIn((16, 16), im.info.get("sizes", set()))


if __name__ == "__main__":
    unittest.main()
