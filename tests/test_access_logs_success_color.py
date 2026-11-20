"""Angriffsliste: abgewehrte Versuche grün, nur erfolgreiche (2xx) rot."""
import os, sys, tempfile, threading, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_falsepositives import BlockedAttacksAreWarnings, titles, has


class AccessLogColor(BlockedAttacksAreWarnings):
    def test_blocked_is_green_not_red_not_yellow(self):
        r = self._run([403, 404, 404])
        self.assertEqual(titles(r, "crit"), [])
        self.assertEqual(titles(r, "warn"), [])
        self.assertTrue(has(r, "keiner erfolgreich", "ok"))

    def test_success_stays_red_and_blocked_group_green(self):
        r = self._run([200, 403])
        self.assertTrue(has(r, "JCE", "crit"))
        self.assertFalse(has(r, "keiner erfolgreich", "ok"))


if __name__ == "__main__":
    unittest.main()
