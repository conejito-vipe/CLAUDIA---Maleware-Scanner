"""2.4.1: Python von python.org wird nicht selbst entfernt; der Hinweis auf Windows-Einstellungen erscheint nur mit Marker unter Windows."""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia import uninstall  # noqa: E402


class Hint(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_uni_")
        self.root = os.path.join(self.d, "prog")
        os.makedirs(os.path.join(self.root, "claudia"))
        open(os.path.join(self.root, "start.bat"), "w").close()
        self.data = os.path.join(self.d, "data")
        os.makedirs(self.data)

    def venv_why(self):
        items = uninstall.plan(self.root, self.data, os.path.join(self.d, "Berichte"))
        return [i for i in items if i["id"] == "venv"][0]["why"], [i["id"] for i in items]

    def test_hint_with_marker_on_windows(self):
        open(os.path.join(self.data, uninstall.PY_MARKER_ORG), "w").close()
        with mock.patch.object(uninstall.os, "name", "nt"):
            why, ids = self.venv_why()
        self.assertIn("Einstellungen > Apps", why)
        self.assertNotIn("python", ids)                     # kein automatisches Entfernen

    def test_no_hint_without_marker(self):
        with mock.patch.object(uninstall.os, "name", "nt"):
            why, _ = self.venv_why()
        self.assertNotIn("Einstellungen", why)

    def test_no_hint_off_windows(self):
        open(os.path.join(self.data, uninstall.PY_MARKER_ORG), "w").close()
        why, _ = self.venv_why()
        self.assertNotIn("Einstellungen", why)


if __name__ == "__main__":
    unittest.main()
