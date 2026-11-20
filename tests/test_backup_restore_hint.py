"""2.4.1 Punkt 8 (Wiederherstellung): reiner Hinweis zu Wiederherstellungstest und Kopie außerhalb des Servers. Es wird nichts geprüft, übertragen oder verändert."""
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import test_backup_tool as bt  # noqa: E402
import wpfixture  # noqa: E402

TITLE = "Sicherung nützt nur, wenn sich zurückspielen lässt und eine Kopie woanders liegt"


def hint(r):
    return [f for f in r.findings if f.title == TITLE]


class RestoreHint(unittest.TestCase):
    def wp(self):
        return wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_rh_"), False)

    def test_hint_without_backup_tool_mentions_host_backups(self):
        r = bt.run(self.wp(), "wordpress")
        h = hint(r)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0].sev, "info")
        txt = " ".join(h[0].items)
        self.assertIn("Testkopie", txt)
        self.assertIn("anderen Ort", txt)
        self.assertIn("Hoster", txt)
        self.assertIn("überträgt selbst nichts", txt)

    def test_hint_with_active_tool_has_no_host_line_and_is_never_a_finding(self):
        w = self.wp()
        os.makedirs(os.path.join(w["site"], "wp-content/plugins/updraftplus"), exist_ok=True)
        c = sqlite3.connect(w["db"])
        c.execute("UPDATE wp_options SET option_value='a:1:{i:0;s:27:\"updraftplus/updraftplus.php\";}' WHERE option_name='active_plugins'")
        c.commit()
        c.close()
        r = bt.run(w, "wordpress")
        h = hint(r)
        self.assertEqual(len(h), 1)
        self.assertNotIn("Hoster", " ".join(h[0].items))
        self.assertEqual(h[0].sev, "info")
        self.assertEqual(r.findings[0].sev, "ok")

    def test_hint_for_joomla_without_tool(self):
        import fixture
        r = bt.run(fixture.make_world(tempfile.mkdtemp(prefix="jo_rh_"), False), "joomla")
        self.assertEqual(len(hint(r)), 1)


if __name__ == "__main__":
    unittest.main()
