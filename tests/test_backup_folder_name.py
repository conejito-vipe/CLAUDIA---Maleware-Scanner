"""2.4.1: Neue Ordner heißen claudia-sicherung-… / claudia-quarantaene-…; Ordner früherer Versionen bleiben les- und löschbar."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import actions  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


class Names(unittest.TestCase):
    def test_new_and_old_backup_names_accepted(self):
        for n in ("claudia-sicherung-20260101-000000", "claudia-sicherung-api-20260101-000000-ab12cd34",
                  (OLD + "-sicherung-20250101-000000"), (OLD + "-sicherung-tmp-20250101-000000")):
            self.assertTrue(actions.BACKUP_NAME_RE.match(n), n)
        for n in ("claudia-sicherung-../x", "andere-sicherung-20260101-000000", "claudia-sicherung-20260101-000000-XYZ"):
            self.assertFalse(actions.BACKUP_NAME_RE.match(n), n)

    def test_quarantine_names_and_keys(self):
        for n in ("claudia-quarantaene-20260101-000000", (OLD + "-quarantaene-20260101-000000-2")):
            self.assertTrue(actions.QUAR_NAME_RE.match(n), n)
            self.assertTrue(actions.QUAR_KEY_RE.match(n + "/0001"), n)
        self.assertFalse(actions.QUAR_NAME_RE.match("claudia-quarantaene-../x"))
        self.assertEqual(actions.QUAR_PREFIX, "claudia-quarantaene")

    def test_scan_and_delete_scripts_know_both_prefixes(self):
        """Die fertigen Skripte (nach dem Einsetzen der Kennung früherer Versionen) kennen beide Vorsilben und enthalten keinen Platzhalter mehr."""
        scan, back, dele = actions.SCAN_SCRIPT, actions.QUAR_BACK, actions.QUAR_DEL
        self.assertNotIn("@OLD@", scan + back + dele)
        self.assertIn('"$HOME"/claudia-sicherung-* "$HOME"/' + OLD + '-sicherung-*', scan)
        self.assertIn('"$HOME"/claudia-quarantaene-* "$HOME"/' + OLD + '-quarantaene-*', scan)
        for script in (back, dele):
            self.assertIn("claudia-quarantaene-*|" + OLD + "-quarantaene-*", script)
        src = open(os.path.join(HERE, "..", "claudia", "actions.py"), encoding="utf-8").read()
        self.assertIn("claudia-sicherung-*|' + OLD_ID + '-sicherung-*", src)

if __name__ == "__main__":
    unittest.main()
