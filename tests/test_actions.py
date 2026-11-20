"""Lösungen auf Knopfdruck: Sicherung zuerst, nur erlaubte Dateien, ausdrückliche Bestätigung."""
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError, App  # noqa: E402


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def world(php_body=None, dump=True):
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_a_"), False)
    b = tempfile.mkdtemp(prefix="claudia_abin_")
    script(os.path.join(b, "php8.3"), php_body or r'''
if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
echo "php $*" >> "$HOME/php_calls.txt"
case "$2" in
  core:check-updates) echo "Update available: 6.2.1";;
  update:extensions:check) echo "Found 2 updates";;
  core:update) echo "Joomla updated to 6.2.1";;
  cache:clean) echo "Cache cleaned";;
esac''')
    if dump:
        script(os.path.join(b, "mysqldump"), 'for a in "$@"; do case "$a" in --connect-timeout*|--max-allowed-packet*|--no-tablespaces-x) echo "mysqldump: [ERROR] unknown variable ${a#--}" >&2; exit 7;; --no-tablespaces) [ -n "$CLAUDIA_REJECT_NOTBS" ] && { echo "mysqldump: unknown option --no-tablespaces" >&2; exit 7; };; esac; done; cat >/dev/null </dev/null; for i in $(seq 1 400); do echo "INSERT INTO x VALUES ($i,\'abcdefghijklmnopqrstuvwxyz\');"; done')
    r = LocalRunner(w["home"], extra_path=b + os.pathsep + w["bin"])
    return r, w


CHOICES = [{"name": "php8.3", "version": "8.3.6", "default": True}]


class Actions(unittest.TestCase):
    def test_check_updates_runs_php_with_chosen_binary(self):
        r, w = world()
        res = actions.run_action(r, w["site_rel"], "check_updates", {"php": "php8.3"}, CHOICES)
        self.assertTrue(res["ok"])
        self.assertIn("6.2.1", res["steps"][0]["output"])

    def test_php_must_be_from_list(self):
        r, w = world()
        res = actions.run_action(r, w["site_rel"], "check_updates", {"php": "rm -rf /"}, CHOICES)
        self.assertFalse(res["ok"])
        self.assertIn("PHP-Programm", res["error"])

    def test_core_update_makes_verified_backup_first(self):
        r, w = world()
        # cli/joomla.php muss existieren, ist hier nur Attrappe
        os.makedirs(os.path.join(w["site"], "cli"), exist_ok=True)
        open(os.path.join(w["site"], "cli", "joomla.php"), "w").write("<?php\n")
        res = actions.run_action(r, w["site_rel"], "core_update", {"php": "php8.3"}, CHOICES)
        self.assertTrue(res["ok"], res)
        titles = [s["title"] for s in res["steps"]]
        self.assertLess(titles.index("Sicherung prüfen"), titles.index("Joomla aktualisieren"))
        bdir = res["backup_dir"]
        self.assertTrue(os.path.getsize(os.path.join(bdir, "db.sql.gz")) > 1000)
        self.assertTrue(os.path.getsize(os.path.join(bdir, "dateien.tgz")) > 1000)
        self.assertNotIn("password", " ".join(s["output"] for s in res["steps"]).lower().replace("passwort", ""))

    def test_no_backup_no_update(self):
        r, w = world(dump=False)                       # mysqldump fehlt
        res = actions.run_action(r, w["site_rel"], "core_update", {"php": "php8.3"}, CHOICES)
        self.assertFalse(res["ok"])
        calls = os.path.join(w["home"], "php_calls.txt")
        self.assertFalse(os.path.exists(calls) and "core:update" in open(calls).read(), "ohne Sicherung darf nichts aktualisiert werden")

    def test_fix_permissions_only_reported_files(self):
        r, w = world()
        f1 = os.path.join(w["site"], "tmpfile1.txt")
        f2 = os.path.join(w["site"], "unrelated.txt")
        for f in (f1, f2):
            open(f, "w").write("x")
            os.chmod(f, 0o666)
        res = actions.run_action(r, w["site_rel"], "fix_permissions", {"files": ["./tmpfile1.txt", "./unrelated.txt", "../../etc/passwd"]}, [],
                                 allowed_files=["./tmpfile1.txt"])
        self.assertTrue(res["ok"])
        self.assertEqual(oct(os.stat(f1).st_mode & 0o777), "0o664")          # o-w entfernt, Rest bleibt
        self.assertEqual(oct(os.stat(f2).st_mode & 0o777), "0o666")          # nicht gemeldet -> unverändert
        bdir = res["backup_dir"]
        self.assertIn("666", open(os.path.join(bdir, "rechte_vorher.txt")).read())

    def test_available_actions(self):
        res = [{"id": "perms", "findings": [{"sev": "warn", "title": "1 Datei(en) für alle beschreibbar", "items": ["666  ./a/b.jpa"]}]}]
        info = {"php": "", "php_candidates": [{"name": "php-8.3", "version": "PHP 8.3.36"}, {"name": "php-8.5", "version": "PHP 8.5.12"}]}
        upd = {"checked": True, "has_update": True, "latest": "6.2.1"}
        ids = [a["id"] for a in actions.available(res, info, "8.3", upd)]
        self.assertIn("fix_permissions", ids)
        a = [x for x in actions.available(res, info, "8.3", upd) if x["id"] == "core_update"][0]
        self.assertEqual([c["name"] for c in a["php_choices"] if c["default"]], ["php-8.3"])
        self.assertNotIn("fix_permissions", [x["id"] for x in actions.available([], info, "")])


class Gating(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_g_"), False)
        b = tempfile.mkdtemp(prefix="claudia_gbin_")
        script(os.path.join(b, "php8.3"), 'if [ "$1" = "-v" ]; then echo "PHP 8.3.6"; else echo ok; fi')
        script(os.path.join(b, "mysqldump"), 'for a in "$@"; do case "$a" in --connect-timeout*|--max-allowed-packet*|--no-tablespaces-x) echo "mysqldump: [ERROR] unknown variable ${a#--}" >&2; exit 7;; --no-tablespaces) [ -n "$CLAUDIA_REJECT_NOTBS" ] && { echo "mysqldump: unknown option --no-tablespaces" >&2; exit 7; };; esac; done; cat >/dev/null; for i in $(seq 1 400); do echo "INSERT $i abcdefghijklmnopqrstuvwxyz";done')
        self.app = App(tempfile.mkdtemp(prefix="claudia_gd_"))
        self.app.runner = LocalRunner(self.w["home"], extra_path=b + os.pathsep + self.w["bin"])
        self.app.conn = {"host": "x", "site_dir": self.w["site_rel"], "php_manual": "8.3"}
        self.app.info = {"php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}

    def test_needs_confirmation(self):
        with self.assertRaises(ApiError):
            self.app.action_run({"id": "clear_cache", "php": "php8.3"})

    def test_core_update_is_not_offered_without_known_update(self):
        with self.assertRaises(ApiError) as e:
            self.app.action_run({"id": "core_update", "php": "php8.3", "confirm": True})
        self.assertEqual(e.exception.status, 404)
        self.app.update_state = {"checked": True, "has_update": False, "latest": "6.2.0"}
        self.assertNotIn("core_update", [a["id"] for a in self.app.actions_list()["actions"]])

    def test_preview_lists_commands_and_backup(self):
        self.app.update_state = {"checked": True, "has_update": True, "latest": "6.2.1"}
        p = self.app.action_preview({"id": "core_update", "php": "php8.3"})
        txt = "\n".join(p["commands"])
        self.assertIn("mysqldump", txt)
        self.assertLess(txt.index("mysqldump"), txt.index("core:update"))

    def test_unknown_action(self):
        with self.assertRaises(ApiError):
            self.app.action_run({"id": "rm_everything", "confirm": True})

    def test_run_after_check(self):
        r = self.app.action_run({"id": "check_updates", "php": "php8.3", "confirm": True})
        self.assertTrue(r["ok"])
        self.assertTrue(self.app.update_state["checked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
