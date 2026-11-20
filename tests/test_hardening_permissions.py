"""2.4.1 Härtung: Dateirechte auf Sollwerte (Gruppen-Schreibrecht weg, Konfigurationsdatei 440) mit Wirkungsprüfung und Rückweg."""
import os
import stat
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402


class Resp:
    def __init__(self, status=200, error=""):
        self.status, self.error, self.body, self.headers = status, error, "", {}


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class Perms(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]
        self.cfg = os.path.join(self.s, "configuration.php")
        self.fil = os.path.join(self.s, "grp.php")
        self.dir = os.path.join(self.s, "grpdir")
        os.makedirs(self.dir, exist_ok=True)
        for p in (self.cfg, self.fil):
            if os.path.exists(p):
                os.chmod(p, 0o644)  # Fixture legt die Konfiguration mit 444 an; als Nicht-root nicht beschreibbar
            open(p, "w").write("<?php\n")
        os.chmod(self.cfg, 0o644)
        os.chmod(self.fil, 0o664)
        os.chmod(self.dir, 0o775)
        self.ctx = {"url": "https://example.org"}
        self._orig = actions._fetch_url
        self.params = {"files": ["./configuration.php", "./grp.php", "./grpdir"], "config": "./configuration.php"}

    def tearDown(self):
        actions._fetch_url = self._orig

    def go(self, web, params=None, allowed=None):
        actions._fetch_url = web
        return actions.run_action(self.r, self.w["site_rel"], "harden_perms", params or self.params, [], allowed_files=allowed if allowed is not None else self.params["files"], context=self.ctx)

    def test_sets_target_values_and_keeps_old_ones_in_log(self):
        res = self.go(lambda url: Resp(200))
        self.assertTrue(res["ok"], res)
        self.assertEqual(mode(self.cfg), 0o440)
        self.assertEqual(mode(self.fil), 0o644)
        self.assertEqual(mode(self.dir), 0o755)
        old = open(os.path.join(res["backup_dir"], "rechte_vorher.txt")).read()
        self.assertIn("644 ./configuration.php", old)
        self.assertIn("664 ./grp.php", old)
        self.assertIn("775 ./grpdir", old)

    def test_start_page_down_restores_old_rights(self):
        calls = []

        def web(url):
            calls.append(url)
            return Resp(200) if len(calls) == 1 else Resp(500)
        res = self.go(web)
        self.assertFalse(res["ok"])
        self.assertIn("wiederhergestellt", res["error"])
        self.assertEqual(mode(self.cfg), 0o644)
        self.assertEqual(mode(self.fil), 0o664)
        self.assertEqual(mode(self.dir), 0o775)

    def test_only_what_the_check_reported_is_touched(self):
        other = os.path.join(self.s, "nicht-gemeldet.php")
        open(other, "w").write("x")
        os.chmod(other, 0o664)
        res = self.go(lambda url: Resp(200), dict(self.params, files=self.params["files"] + ["./nicht-gemeldet.php"]))
        self.assertTrue(res["ok"], res)
        self.assertEqual(mode(other), 0o664)

    def test_symlink_is_skipped_and_https_needed(self):
        outside = os.path.join(os.path.dirname(self.s), "fremd-perm.txt")
        open(outside, "w").write("x")
        os.chmod(outside, 0o664)
        link = os.path.join(self.s, "lnk.php")
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(outside, link)
        res = self.go(lambda url: Resp(200), dict(self.params, files=self.params["files"] + ["./lnk.php"]), allowed=self.params["files"] + ["./lnk.php"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(mode(outside), 0o664)
        self.ctx = {"url": "http://example.org"}
        res = self.go(lambda url: Resp(200))
        self.assertFalse(res["ok"])
        self.assertIn("https", res["error"])

    def test_offered_from_check_findings_and_preview(self):
        res = [{"id": "perms", "findings": [
            {"sev": "info", "title": "configuration.php ist für alle lesbar (644)", "items": ["644  ./configuration.php"]},
            {"sev": "info", "title": "2 Datei(en)/Ordner für die Gruppe beschreibbar", "items": ["664  ./grp.php", "775  ./grpdir"]}]}]
        av = {a["id"]: a for a in actions.available(res, {"cms": "joomla", "php": ""}, "8.3")}
        self.assertEqual(av["harden_perms"]["params"]["files"], ["./configuration.php", "./grp.php", "./grpdir"])
        self.assertEqual(av["harden_perms"]["params"]["config"], "./configuration.php")
        self.assertNotIn("harden_perms", {a["id"] for a in actions.available([], {"cms": "joomla", "php": ""}, "8.3")})
        pv = actions.commands_preview("harden_perms", av["harden_perms"]["params"], [])
        self.assertTrue(any("chmod 440" in l for l in pv))
        self.assertTrue(any("g-w" in l for l in pv))
        self.assertTrue(any(l.startswith("Test:") for l in pv))


if __name__ == "__main__":
    unittest.main()
