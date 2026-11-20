"""Prüfung 'Lässt sich die Seite automatisch aktualisieren?' (Joomla und WordPress) samt Lösungen."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()
CHOICES = [{"name": "php8.3", "version": "8.3.6", "default": True}]


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


class Base(unittest.TestCase):
    CMS = "joomla"

    def world(self, infected=False):
        mk = wpfixture.make_wp_world if self.CMS == "wordpress" else fixture.make_world
        w = mk(tempfile.mkdtemp(prefix="claudia_ur_"), infected)
        w["extra"] = tempfile.mkdtemp(prefix="claudia_urbin_")       # eigene Attrappen haben Vorrang
        return w

    def runner(self, w):
        return LocalRunner(w["home"], extra_path=w["extra"] + os.pathsep + w["bin"])

    def run_check(self, w, online=False):
        s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=self.CMS, url="", allow_hosts=ADV["allow_hosts"])
        eng = Engine(self.runner(w), s, ADV)
        env = {}
        if online:
            os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            res = eng.run(["update_ready"], lambda e: None, threading.Event())
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        return res[0]

    @staticmethod
    def results(r):
        return [{"id": r.id, "title": r.title, "status": r.status,
                 "findings": [{"sev": f.sev, "title": f.title, "items": list(f.items)} for f in r.findings]}]

    def info(self):
        return {"cms": self.CMS, "wordpress": "6.8.3", "joomla": "6.2.0", "php": "",
                "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}

    def avail(self, r, w):
        return {a["id"]: a for a in actions.available(self.results(r), self.info(), "8.3", {}, actions.scan_server(self.runner(w), w["site_rel"]))}

    def titles(self, r):
        return [f.title for f in r.findings]


class Common(object):
    """Gilt für beide Systeme."""

    def core_file(self, w):
        raise NotImplementedError

    def test_clean_site_only_reports_success(self):
        r = self.run_check(self.world())
        self.assertEqual([f.sev for f in r.findings], ["ok"], self.titles(r))
        self.assertIn("lässt sich automatisch aktualisieren", r.findings[0].title)
        self.assertIn("geprüft: Schreibrechte der Kernordner", " ".join(r.findings[0].items))

    def test_title_names_the_system(self):
        r = self.run_check(self.world())
        self.assertIn("WordPress" if self.CMS == "wordpress" else "Joomla", r.findings[0].title)

    def test_locked_file_is_found_and_fixed(self):
        w = self.world()
        f = self.core_file(w)
        os.chmod(f, 0o444)
        r = self.run_check(w)
        self.assertEqual(r.findings[0].sev, "crit")
        self.assertIn("ohne Schreibrecht für den Besitzer", r.findings[0].title)
        self.assertTrue(any(os.path.relpath(f, w["site"]) in i for i in r.findings[0].items), r.findings[0].items)
        self.assertNotIn("ok", [x.sev for x in r.findings])          # keine Erfolgsmeldung, wenn etwas im Weg steht
        av = self.avail(r, w)
        self.assertIn("fix_update_perms", av)
        self.assertEqual(av["fix_update_perms"]["params"]["files"][0], "./" + os.path.relpath(f, w["site"]))
        res = actions.run_action(self.runner(w), w["site_rel"], "fix_update_perms", av["fix_update_perms"]["params"], CHOICES,
                                 allowed_files=av["fix_update_perms"]["params"]["files"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(os.stat(f).st_mode & stat.S_IWUSR)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o644)       # nur Besitzer-Schreibrecht ergänzt
        self.assertEqual([x.sev for x in self.run_check(w).findings], ["ok"])

    def test_action_only_touches_reported_files(self):
        w = self.world()
        f = self.core_file(w)
        os.chmod(f, 0o444)
        other = os.path.join(w["site"], "index.php")
        os.chmod(other, 0o444)
        res = actions.run_action(self.runner(w), w["site_rel"], "fix_update_perms",
                                 {"files": ["./" + os.path.relpath(f, w["site"]), "./index.php"]}, CHOICES,
                                 allowed_files=["./" + os.path.relpath(f, w["site"])])
        self.assertTrue(res["ok"], res)
        self.assertTrue(os.stat(f).st_mode & stat.S_IWUSR)
        self.assertFalse(os.stat(other).st_mode & stat.S_IWUSR)

    def test_world_writable_is_reported_and_removed(self):
        w = self.world()
        f = self.core_file(w)
        os.chmod(f, 0o666)
        r = self.run_check(w)
        t = [x for x in r.findings if "für alle beschreibbar" in x.title]
        self.assertTrue(t and t[0].sev == "warn", self.titles(r))
        av = self.avail(r, w)
        self.assertIn("fix_permissions", av)
        res = actions.run_action(self.runner(w), w["site_rel"], "fix_permissions", av["fix_permissions"]["params"], CHOICES,
                                 allowed_files=av["fix_permissions"]["params"]["files"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode) & 0o002, 0)
        self.assertEqual([x.sev for x in self.run_check(w).findings], ["ok"])

    def test_not_enough_disk_space(self):
        w = self.world()
        script(os.path.join(w["extra"], "df"), 'echo "Filesystem 1024-blocks Used Available Capacity Mounted"; echo "x 1000000 900000 50000 95% /"')
        r = self.run_check(w)
        self.assertEqual(r.findings[0].sev, "crit")
        self.assertIn("Speicherplatz", r.findings[0].title)
        script(os.path.join(w["extra"], "df"), 'echo "Filesystem 1024-blocks Used Available Capacity Mounted"; echo "x 1000000 900000 100000 90% /"')
        r = self.run_check(w)
        self.assertEqual(r.findings[0].sev, "warn")

    def test_missing_php_modules(self):
        w = self.world()
        script(os.path.join(w["extra"], "php"), r'''
case "$1" in
  -m) printf "Core\njson\nmbstring\nxml\nmysqli\nmysqlnd\n";;
  -r) printf "VER 8.3.6\nMEM 256M\nURLFOPEN 1\nEXEC 30\n";;
  -v) echo "PHP 8.3.6 (cli)";;
esac''')
        r = self.run_check(w)
        sev = {f.title: f.sev for f in r.findings}
        self.assertTrue(any("zip" in t and "zlib" in t for t in sev), sev)          # weder zip noch zlib
        self.assertTrue(any("openssl" in t for t in sev), sev)

    def test_low_memory_limit(self):
        w = self.world()
        script(os.path.join(w["extra"], "php"), r'''
case "$1" in
  -m) printf "zip\nzlib\nopenssl\ncurl\njson\nmbstring\nxml\nmysqli\nmysqlnd\n";;
  -r) printf "VER 8.3.6\nMEM 64M\nURLFOPEN 1\nEXEC 30\n";;
  -v) echo "PHP 8.3.6 (cli)";;
esac''')
        r = self.run_check(w)
        self.assertEqual([f.title for f in r.findings if f.sev == "warn"], ["PHP-Speicherlimit ist niedrig (64M)"])

    def test_update_server_reachability(self):
        w = self.world()
        script(os.path.join(w["extra"], "curl"), 'echo -n 200')
        r = self.run_check(w, online=True)
        self.assertEqual([f.sev for f in r.findings], ["ok"], self.titles(r))
        self.assertIn("Update-Server erreichbar", " ".join(r.findings[0].items))
        script(os.path.join(w["extra"], "curl"), 'echo -n 000; exit 7')
        r = self.run_check(w, online=True)
        self.assertEqual(r.findings[0].sev, "warn")
        self.assertIn("erreicht den Update-Server nicht", r.findings[0].title)
        script(os.path.join(w["extra"], "curl"), 'echo -n 503')
        r = self.run_check(w, online=True)
        self.assertIn("HTTP 503", r.findings[0].title)

    def test_offline_mode_says_not_checked(self):
        r = self.run_check(self.world())
        self.assertIn("nicht prüfbar: Erreichbarkeit des Update-Servers", " ".join(r.findings[0].items))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "braucht root zum Ändern des Besitzers")
    def test_foreign_owner_is_reported_but_not_changed_by_program(self):
        w = self.world()
        f = self.core_file(w)
        os.chown(f, 65534, 65534)
        r = self.run_check(w)
        self.assertTrue(any("gehören einem anderen Konto" in t for t in self.titles(r)), self.titles(r))
        av = self.avail(r, w)
        self.assertNotIn("fix_update_perms", av)        # fremde Dateien kann nur der Hoster ändern

    def test_plan_puts_permission_fix_before_updates(self):
        w = self.world()
        os.chmod(self.core_file(w), 0o444)
        r = self.run_check(w)
        order = [a["id"] for a in actions.available(self.results(r), self.info(), "8.3", {}, {})]
        self.assertIn("fix_update_perms", order)
        self.assertLess(actions.STEP_ORDER.index("fix_update_perms"), actions.STEP_ORDER.index("fix_permissions"))
        self.assertLess(actions.STEP_ORDER.index("fix_update_perms"), actions.STEP_ORDER.index("core_update"))

    def test_check_changes_nothing(self):
        w = self.world()
        os.chmod(self.core_file(w), 0o444)

        def snap():
            out = {}
            for dp, dn, fn in os.walk(w["home"]):
                for n in dn + fn:
                    p = os.path.join(dp, n)
                    st = os.lstat(p)
                    out[p] = (st.st_mode, st.st_size, st.st_mtime_ns)
            return out
        before = snap()
        self.run_check(w)
        self.assertEqual(before, snap())


class JoomlaUpdateReady(Common, Base):
    CMS = "joomla"

    def core_file(self, w):
        return os.path.join(w["site"], "libraries", "src", "Version.php")

    def test_leftovers_found_and_clean_tmp_offered(self):
        w = self.world()
        os.makedirs(os.path.join(w["site"], "tmp", "joomla_update_abc"), exist_ok=True)
        open(os.path.join(w["site"], "tmp", "Joomla_6.2.1-Stable-Update_Package.zip"), "w").write("x")
        open(os.path.join(w["site"], "tmp", "joomla_update.zip"), "w").write("x")
        r = self.run_check(w)
        t = [x for x in r.findings if "abgebrochener oder alter Updates" in x.title]
        self.assertTrue(t, self.titles(r))
        self.assertIn("clean_tmp", self.avail(r, w))

    def test_joomla_has_no_wordpress_actions(self):
        w = self.world()
        os.chmod(self.core_file(w), 0o444)
        self.assertNotIn("wp_remove_maintenance", self.avail(self.run_check(w), w))

    def test_texts_do_not_mention_wordpress(self):
        w = self.world()
        os.chmod(self.core_file(w), 0o444)
        blob = json.dumps([[f.title, f.detail, f.hint, f.items] for f in self.run_check(w).findings], ensure_ascii=False)
        self.assertNotIn("WordPress", blob)


class WordPressUpdateReady(Common, Base):
    CMS = "wordpress"

    def core_file(self, w):
        return os.path.join(w["site"], "wp-includes", "version.php")

    def test_maintenance_file_found_and_removed(self):
        w = self.world()
        m = os.path.join(w["site"], ".maintenance")
        open(m, "w").write("<?php $upgrading = 1730000000; ?>")
        r = self.run_check(w)
        self.assertEqual(r.findings[0].sev, "crit")
        self.assertTrue(r.findings[0].title.startswith(".maintenance liegt"))
        av = self.avail(r, w)
        self.assertIn("wp_remove_maintenance", av)
        res = actions.run_action(self.runner(w), w["site_rel"], "wp_remove_maintenance", {}, CHOICES)
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(m))
        self.assertTrue(os.path.isfile(os.path.join(res["backup_dir"], ".maintenance")))
        self.assertEqual([f.sev for f in self.run_check(w).findings], ["ok"])

    def test_odd_maintenance_file_is_not_deleted(self):
        w = self.world()
        m = os.path.join(w["site"], ".maintenance")
        open(m, "w").write("<?php system($_GET['x']); ?>")
        res = actions.run_action(self.runner(w), w["site_rel"], "wp_remove_maintenance", {}, CHOICES)
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.exists(m))

    def test_blocking_constants_in_wp_config(self):
        w = self.world()
        cfg = os.path.join(w["site"], "wp-config.php")
        t = open(cfg).read()
        open(cfg, "w").write(t.replace("require_once", "define( 'DISALLOW_FILE_MODS', true );\ndefine( 'FS_METHOD', 'ftpext' );\nrequire_once", 1))
        r = self.run_check(w)
        w_ = [f for f in r.findings if f.sev == "warn" and "wp-config.php" in f.title]
        self.assertTrue(w_, self.titles(r))
        self.assertTrue(any("DISALLOW_FILE_MODS" in i for i in w_[0].items))
        self.assertTrue(any("FS_METHOD" in i for i in w_[0].items))

    def test_leftovers_in_upgrade_folder(self):
        w = self.world()
        d = os.path.join(w["site"], "wp-content", "upgrade", "wordpress-6.8.4")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "x.php"), "w").write("<?php")
        r = self.run_check(w)
        self.assertTrue(any("abgebrochener oder alter Updates" in t for t in self.titles(r)), self.titles(r))

    def test_wordpress_has_no_joomla_text(self):
        w = self.world()
        os.chmod(self.core_file(w), 0o444)
        blob = json.dumps([[f.title, f.detail, f.hint, f.items] for f in self.run_check(w).findings], ensure_ascii=False)
        self.assertNotIn("Joomla", blob)


if __name__ == "__main__":
    unittest.main()


class SelectorProgram(unittest.TestCase):
    """'php' ist auf manchen Hostern nur ein Auswahlprogramm: Es darf nie als PHP gewertet werden."""

    def test_pick_skips_selector_and_uses_real_binary(self):
        from claudia import phppick
        d = tempfile.mkdtemp(prefix="claudia_pick_")
        script(os.path.join(d, "php"), 'echo "Multiple PHP versions found:"; echo "  1) php-5.3"')
        script(os.path.join(d, "php-8.4"), 'echo "PHP 8.4.1 (cli)"')
        code = phppick.snippet("", [{"name": "php-8.4", "version": "PHP 8.4.1"}]) + 'echo "BIN=$P"'
        out = subprocess.run(["bash", "-c", code], env=dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"]), capture_output=True, text=True).stdout
        self.assertEqual(out.strip(), "BIN=" + os.path.join(d, "php-8.4"))

    def test_pick_returns_empty_when_nothing_works(self):
        from claudia import phppick
        d = tempfile.mkdtemp(prefix="claudia_pick_")
        script(os.path.join(d, "php"), 'echo "Multiple PHP versions found:"')
        code = phppick.snippet("", []) + 'echo "BIN=[$P]"'
        out = subprocess.run(["bash", "-c", code], env=dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"]), capture_output=True, text=True).stdout
        self.assertEqual(out.strip(), "BIN=[]")
