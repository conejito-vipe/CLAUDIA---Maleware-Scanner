"""2.4.0 / B5: .htaccess im Hauptordner auf den Standard zurücksetzen (Plan, Vergleich, Sicherung, Test der Startseite, Rückweg)."""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402

JSTD = "## Joomla standard\nRewriteEngine On\n# RewriteBase /\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule .* index.php [L]\n"
GOOD_OWN = "Header set X-Frame-Options SAMEORIGIN\n"
EVIL = "RewriteCond %{HTTP_USER_AGENT} (googlebot|bing) [NC]\nRewriteRule .* http://spam.example/ [R=302,L]\n"
PREPEND = "# BEGIN WordfenceWAF\nphp_value auto_prepend_file '/x/wordfence-waf.php'\n# END WordfenceWAF\n"
WPOLD = "# BEGIN WordPress\nRewriteEngine On\nRewriteBase /blog/\nRewriteRule . /blog/index.php [L]\n# END WordPress\n"


class Resp:
    def __init__(self, status=200, error=""):
        self.status, self.error, self.body = status, error, "<html>ok</html>"


class Plan(unittest.TestCase):
    def test_dangerous_not_carried_harmless_carried(self):
        cur = JSTD + "\n" + GOOD_OWN + "\n" + EVIL + "\n" + PREPEND
        p = actions.ht_plan(cur, JSTD, "joomla")
        self.assertIn("X-Frame-Options", p["text"])
        self.assertNotIn("spam.example", p["text"])
        self.assertNotIn("auto_prepend_file", p["text"])
        sev = sorted(d["sev"] for d in p["dropped"])
        self.assertEqual(sev, ["crit", "warn"])
        self.assertEqual(len(p["carried"]), 1)

    def test_keep_own_off_drops_even_harmless(self):
        p = actions.ht_plan(GOOD_OWN, JSTD, "joomla", keep_own=False)
        self.assertNotIn("X-Frame-Options", p["text"])
        self.assertEqual(len(p["dropped"]), 1)

    def test_standard_lines_are_not_listed(self):
        p = actions.ht_plan(JSTD, JSTD, "joomla")
        self.assertEqual((p["carried"], p["dropped"]), ([], []))
        self.assertEqual(p["text"], JSTD)

    def test_wordpress_block_replaced_with_own_base_and_own_rules_first(self):
        std, _ = actions.ht_standard("wordpress", "", WPOLD)
        self.assertIn("RewriteBase /blog/", std)
        self.assertIn("RewriteRule . /blog/index.php [L]", std)
        p = actions.ht_plan(GOOD_OWN + "\n" + WPOLD, std, "wordpress")
        self.assertTrue(p["text"].index("X-Frame-Options") < p["text"].index("# BEGIN WordPress"))
        self.assertEqual(p["text"].count("# BEGIN WordPress"), 1)

    def test_idempotent(self):
        p1 = actions.ht_plan(JSTD + "\n" + GOOD_OWN, JSTD, "joomla")
        p2 = actions.ht_plan(p1["text"], JSTD, "joomla")
        self.assertEqual(p1["text"], p2["text"])

    def test_diff_marks_removed_and_added(self):
        d = actions.ht_diff("a\nb\n", "a\nc\n")
        self.assertTrue(any(l == "-b" for l in d) and any(l == "+c" for l in d))


class Run(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.ht = os.path.join(self.w["site"], ".htaccess")
        open(self.ht, "w").write(JSTD + "\n" + EVIL + "\n" + GOOD_OWN)
        os.chmod(self.ht, 0o644)
        self.params = {"cms": "joomla", "version": "5.0.0", "keep_own": True, "own_host": "x.example"}

    def run_it(self, fetch, **kw):
        params = dict(self.params, **kw)
        with mock.patch.object(actions, "ht_standard", return_value=(JSTD, "Teststandard")), mock.patch.object(actions, "_fetch_url", side_effect=fetch):
            return actions.run_action(self.r, self.w["site_rel"], "reset_htaccess", params, [], context={"url": "https://x.example"})

    def test_success_backs_up_first_and_keeps_rights(self):
        res = self.run_it(lambda u: Resp(200))
        self.assertTrue(res["ok"], res)
        new = open(self.ht).read()
        self.assertNotIn("spam.example", new)
        self.assertIn("X-Frame-Options", new)
        self.assertEqual(oct(os.stat(self.ht).st_mode & 0o777), "0o644")
        bk = os.path.join(self.w["home"], os.path.basename(res["backup_dir"]))
        self.assertIn("spam.example", open(os.path.join(bk, "htaccess.vorher")).read())
        self.assertTrue(os.path.exists(os.path.join(bk, "rueckgaengig.txt")))
        self.assertFalse(os.path.exists(self.ht + ".claudia-neu"))

    def test_server_error_after_write_restores_old_file(self):
        calls = []

        def fetch(u):
            calls.append(u)
            return Resp(200) if len(calls) == 1 else Resp(500)
        old = open(self.ht).read()
        res = self.run_it(fetch)
        self.assertFalse(res["ok"])
        self.assertEqual(open(self.ht).read(), old)

    def test_start_page_broken_before_does_not_trigger_restore(self):
        res = self.run_it(lambda u: Resp(503))
        self.assertTrue(res["ok"], res)
        self.assertNotIn("spam.example", open(self.ht).read())

    def test_needs_https_and_changes_nothing_without(self):
        old = open(self.ht).read()
        with mock.patch.object(actions, "ht_standard", return_value=(JSTD, "x")):
            res = actions.run_action(self.r, self.w["site_rel"], "reset_htaccess", self.params, [], context={"url": "http://x.example"})
        self.assertFalse(res["ok"])
        self.assertEqual(open(self.ht).read(), old)

    def test_symlink_and_missing_file_are_refused(self):
        os.remove(self.ht)
        res = self.run_it(lambda u: Resp(200))
        self.assertFalse(res["ok"])
        open(os.path.join(self.w["site"], "real"), "w").write("x")
        os.symlink("real", self.ht)
        res = self.run_it(lambda u: Resp(200))
        self.assertFalse(res["ok"])
        self.assertIn("Symlink", res.get("error", "") + str(res))

    def test_already_standard_changes_nothing(self):
        open(self.ht, "w").write(JSTD)
        res = self.run_it(lambda u: Resp(200))
        self.assertTrue(res["ok"])
        self.assertIn("schon dem Standard", res["message"])
        self.assertFalse(res.get("backup_dir"))

    def test_preview_is_read_only_and_lists_dropped(self):
        old = open(self.ht).read()
        with mock.patch.object(actions, "ht_standard", return_value=(JSTD, "Teststandard")):
            p = actions.htaccess_preview(self.r, self.w["site_rel"], self.params)
        self.assertEqual(open(self.ht).read(), old)
        self.assertTrue(any("spam.example" in d["line"] for d in p["dropped"]))
        self.assertTrue(any(l.startswith("-") and "spam.example" in l for l in p["diff"]))

    def test_available_only_with_root_htaccess_finding(self):
        res = [{"id": "htaccess", "title": "t", "findings": [{"sev": "crit", "title": "1 gefährliche Zeile(n) in .htaccess-Dateien", "items": ["./.htaccess Zeile 3: x  -> y"]}]}]
        res2 = [{"id": "htaccess", "title": "t", "findings": [{"sev": "crit", "title": "1 gefährliche Zeile(n)", "items": ["./images/.htaccess Zeile 3: x  -> y"]}]}]
        ids = lambda rr: [a["id"] for a in actions.available(rr, {"joomla": "5.0.0"}, scan={})["actions"]] if isinstance(actions.available(rr, {"joomla": "5.0.0"}, scan={}), dict) else [a["id"] for a in actions.available(rr, {"joomla": "5.0.0"}, scan={})]
        self.assertIn("reset_htaccess", ids(res))
        self.assertNotIn("reset_htaccess", ids(res2))


if __name__ == "__main__":
    unittest.main()
