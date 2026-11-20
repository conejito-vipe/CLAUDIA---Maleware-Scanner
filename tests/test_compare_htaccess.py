"""2.5.0 / 2.14: .htaccess und .user.ini im Basis-Vergleich: werden erfasst, immer einzeln gemeldet (auch bei vielen Änderungen) und nicht doppelt gezählt."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_baseline_compare import world, put, run, titles  # noqa: E402
from claudia import baseline  # noqa: E402
from claudia.checks import compare  # noqa: E402

TITLE = "Server-Konfiguration geändert oder neu seit der Basis"


def cfg_finding(r):
    return [f for f in r.findings if f.title.startswith(TITLE)]


class Htaccess(unittest.TestCase):
    def test_script_and_pattern_cover_htaccess_and_user_ini(self):
        self.assertIn("-name '.htaccess'", compare.SCRIPT)
        self.assertIn("-name '.user.ini'", compare.SCRIPT)
        for p in (".htaccess", "a/b/.htaccess", ".user.ini", "x/.user.ini"):
            self.assertTrue(compare.CFG_RE.search(p), p)
        for p in ("a/htaccess.php", "x/.htaccess.bak", "my.user.ini.php"):
            self.assertFalse(compare.CFG_RE.search(p), p)

    def test_changed_and_new_htaccess_reported_separately_as_warn(self):
        w = world()
        put(w, ".htaccess", "RewriteEngine On\n")
        run(w, save=True)
        put(w, ".htaccess", "RewriteEngine On\nRewriteRule ^(.*)$ http://fremd.example/ [R=301]\n")
        put(w, "sub/.user.ini", "auto_prepend_file=/tmp/x.php\n")
        r, _ = run(w)
        f = cfg_finding(r)
        self.assertEqual(len(f), 1, titles(r))
        self.assertEqual(f[0].sev, "warn")
        self.assertTrue(any(i.endswith(".htaccess") for i in f[0].items) and any(i.endswith(".user.ini") for i in f[0].items), f[0].items)
        self.assertFalse([x for x in r.findings if x.title.startswith("Geänderte Code-Dateien")], "nicht zusätzlich als normale Code-Datei melden")
        self.assertFalse([x for x in r.findings if x.sev == "ok"], "mit Abweichung darf nicht 'Keine Abweichung' stehen")

    def test_unchanged_htaccess_is_no_finding_and_clean_run_is_ok(self):
        w = world()
        put(w, ".htaccess", "RewriteEngine On\n")
        run(w, save=True)
        r, _ = run(w)
        self.assertEqual(cfg_finding(r), [])
        self.assertIn("Keine Abweichung von der Basis", [t for _, t in titles(r)])

    def test_htaccess_not_hidden_in_mass_update(self):
        w = world()
        for i in range(compare.MANY + 20):
            put(w, "lib/f%03d.php" % i, "<?php //1")
        put(w, ".htaccess", "RewriteEngine On\n")
        run(w, save=True)
        for i in range(compare.MANY + 20):
            put(w, "lib/f%03d.php" % i, "<?php //2")
        put(w, ".htaccess", "php_value auto_prepend_file /tmp/x.php\n")
        r, _ = run(w)
        self.assertTrue(any(t.startswith("Viele Änderungen") for _, t in titles(r)), titles(r))
        self.assertEqual(len(cfg_finding(r)), 1, "bei vielen Änderungen muss die .htaccess trotzdem einzeln erscheinen")

    def test_new_htaccess_in_upload_dir_stays_critical_and_is_not_duplicated(self):
        w = world()
        put(w, "index.php")
        run(w, save=True)
        put(w, "images/neu/.htaccess", "AddType application/x-httpd-php .jpg\n")
        r, _ = run(w)
        self.assertEqual([f.sev for f in r.findings if f.title.startswith("Neue Programmdateien in Upload-Ordnern")], ["crit"], titles(r))
        self.assertEqual(cfg_finding(r), [], "die Upload-Meldung bleibt die einzige, nicht doppelt")


if __name__ == "__main__":
    unittest.main()
