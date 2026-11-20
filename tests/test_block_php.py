"""2.3.1: PHP-Sperre im Bilder-Ordner mit Wirkungsprüfung (Abruf ersetzt) und Rückgängig."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


class Resp:
    def __init__(self, status=200, body="", error=""):
        self.status, self.body, self.error = status, body, error


def fake_web(site, mode):
    """Spielt einen Server nach: liest die Testdatei aus dem Seitenordner und antwortet je nach Modus."""
    def fetch(url):
        rel = url.split("example.org/", 1)[1]
        path = os.path.join(site, rel)
        if mode == "offline":
            return Resp(0, "", "Verbindung abgelehnt")
        if not os.path.exists(path):
            return Resp(404, "nicht da")
        body = open(path, encoding="utf-8").read()
        if rel.endswith(".php"):
            if mode == "ignored":                                  # Server beachtet .htaccess nicht: PHP läuft
                return Resp(200, "claudia-42")
            return Resp(403, "Forbidden")
        if mode == "broken":                                       # fehlerhafte .htaccess: Server liefert 500
            return Resp(500, "Internal Server Error")
        return Resp(200, body)
    return fetch


class BlockPhp(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]
        os.makedirs(os.path.join(self.s, "images"), exist_ok=True)
        if os.path.lexists(self.ht()):
            os.remove(self.ht())
        self.ctx = {"url": "https://example.org"}
        self._orig = actions._fetch_url

    def tearDown(self):
        actions._fetch_url = self._orig

    def go(self, mode):
        actions._fetch_url = fake_web(self.s, mode)
        return actions.run_action(self.r, self.w["site_rel"], "block_php_uploads", {"upload_dir": "images"}, [], context=self.ctx)

    def ht(self):
        return os.path.join(self.s, "images", ".htaccess")

    def test_new_file_is_written_and_tests_removed(self):
        res = self.go("works")
        self.assertTrue(res["ok"], res)
        self.assertIn("PHP-Sperre", open(self.ht()).read())
        self.assertEqual([f for f in os.listdir(os.path.join(self.s, "images")) if f.startswith("claudia-test-")], [])
        self.assertIn("rm -f --", open(os.path.join(res["backup_dir"], "rueckgaengig.txt")).read())

    def test_existing_htaccess_is_kept_and_extended(self):
        open(self.ht(), "w").write("Options -Indexes\n")
        res = self.go("works")
        self.assertTrue(res["ok"], res)
        txt = open(self.ht()).read()
        self.assertTrue(txt.startswith("Options -Indexes"))
        self.assertIn("PHP-Sperre", txt)
        self.assertEqual(open(os.path.join(res["backup_dir"], "htaccess.vorher")).read(), "Options -Indexes\n")

    def test_server_ignores_htaccess_rolls_back(self):
        res = self.go("ignored")
        self.assertFalse(res["ok"])
        self.assertIn("weiter ausgeführt", res["error"])
        self.assertFalse(os.path.exists(self.ht()))
        open(self.ht(), "w").write("Options -Indexes\n")
        res = self.go("ignored")
        self.assertEqual(open(self.ht()).read(), "Options -Indexes\n")

    def test_broken_htaccess_and_offline_roll_back(self):
        for mode in ("broken", "offline"):
            res = self.go(mode)
            self.assertFalse(res["ok"], mode)
            self.assertFalse(os.path.exists(self.ht()), mode)
            self.assertEqual([f for f in os.listdir(os.path.join(self.s, "images")) if f.startswith("claudia-test-")], [], mode)

    def test_already_blocked_changes_nothing(self):
        self.assertTrue(self.go("works")["ok"])
        before = open(self.ht()).read()
        res = self.go("works")
        self.assertTrue(res["ok"])
        self.assertEqual(open(self.ht()).read(), before)

    def test_needs_https_address_and_no_symlink(self):
        for url in ("http://example.org", ""):
            self.ctx = {"url": url}
            res = self.go("works")
            self.assertFalse(res["ok"], url)
            self.assertIn("https", res["error"])
            self.assertFalse(os.path.lexists(self.ht()))
        self.ctx = {"url": "https://example.org"}
        outside = os.path.join(os.path.dirname(self.s), "fremd.txt")
        open(outside, "w").write("x")
        os.symlink(outside, self.ht())
        res = self.go("works")
        self.assertFalse(res["ok"])
        self.assertEqual(open(outside).read(), "x")

    def test_offered_from_findings_and_preview(self):
        res = [{"id": "php_in_uploads", "findings": [{"sev": "crit", "title": "2 PHP-Datei(en) in images/files/tmp", "items": ["images/x.php  (2026-06-22 05:22, 638 Byte)"]}]}]
        av = {a["id"]: a for a in actions.available(res, t2.Plan.INFO if hasattr(t2, "Plan") else {"php": ""}, "8.3")}
        self.assertIn("block_php_uploads", av)
        self.assertNotIn("block_php_uploads", {a["id"] for a in actions.available([], {"php": ""}, "8.3")})
        pv = actions.commands_preview("block_php_uploads", {"upload_dir": "images"}, [])
        self.assertTrue(any("Require all denied" in l for l in pv))
        self.assertTrue(any(l.startswith("rm -f --") for l in pv))


if __name__ == "__main__":
    unittest.main()
