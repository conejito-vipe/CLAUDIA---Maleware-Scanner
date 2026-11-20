"""Sicherungs-Tool: Erkennung (vorhanden/fehlt/ausgeschaltet) und Installations-Aktion 'install_backup' mit Attrappen."""
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
import test_security_install as si  # noqa: E402
import wpfixture  # noqa: E402
from claudia import actions, store  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
import json  # noqa: E402

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()

CHOICES = si.CHOICES
INFO = si.INFO
MISSING = [{"id": "backup_tool", "title": "x", "status": "info", "findings": [
    {"sev": "info", "title": "Kein Sicherungs-Tool (Erweiterung) gefunden", "items": []}]}]
PRESENT = [{"id": "backup_tool", "title": "x", "status": "ok", "findings": [
    {"sev": "ok", "title": "Sicherungs-Erweiterung vorhanden: Akeeba Backup", "items": []}]}]


def run(w, cms):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url="", allow_hosts=ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    return eng.run(["backup_tool"], lambda e: None, threading.Event())[0]


class Detection(unittest.TestCase):
    def wp(self):
        return wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_bk_"), False)

    def test_wordpress_none_installed(self):
        r = run(self.wp(), "wordpress")
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Kein Sicherungs-Tool", r.findings[0].title)
        txt = "\n".join(r.findings[0].items)
        self.assertIn("UpdraftPlus", txt)

    def test_wordpress_installed_is_ok_and_honest(self):
        w = self.wp()
        os.makedirs(os.path.join(w["site"], "wp-content/plugins/updraftplus"), exist_ok=True)
        c = sqlite3.connect(w["db"])
        c.execute("UPDATE wp_options SET option_value='a:1:{i:0;s:27:\"updraftplus/updraftplus.php\";}' WHERE option_name='active_plugins'")
        c.commit()
        c.close()
        r = run(w, "wordpress")
        self.assertEqual(r.findings[0].sev, "ok", [f.title for f in r.findings])
        self.assertIn("UpdraftPlus", r.findings[0].title)
        self.assertIn("Ob sich eine Sicherung zurückspielen lässt, prüft es nicht", r.findings[0].detail)

    def test_wordpress_inactive_warns(self):
        w = self.wp()
        os.makedirs(os.path.join(w["site"], "wp-content/plugins/updraftplus"), exist_ok=True)
        c = sqlite3.connect(w["db"])
        c.execute("DELETE FROM wp_options WHERE option_name='active_plugins'")
        c.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('active_plugins', 'a:0:{}')")
        c.commit()
        c.close()
        r = run(w, "wordpress")
        self.assertEqual(r.findings[0].sev, "warn", [f.title for f in r.findings])
        self.assertIn("ausgeschaltet", r.findings[0].title)

    def test_joomla_akeeba_is_found(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_bk_"), False)
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "ok", [f.title for f in r.findings])
        self.assertIn("Akeeba", r.findings[0].title)

    def test_joomla_none_installed(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_bk_"), False)
        shutil.rmtree(os.path.join(w["site"], "administrator/components/com_akeebabackup"))
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Kein Sicherungs-Tool", r.findings[0].title)
        self.assertIn("extensions.joomla.org", "\n".join(r.findings[0].items))


class Offer(unittest.TestCase):
    def test_wordpress_offered_only_when_missing(self):
        av = {a["id"]: a for a in actions.available(MISSING, INFO, "8.3", {}, {"wpcli": "/h/wp-cli.phar"})}
        a = av["install_backup"]
        ids = [t["id"] for t in a["params"]["tools"]]
        self.assertEqual(ids[0], "akeeba")
        self.assertIn("updraftplus", ids)
        self.assertNotIn("aiowpmigration", ids)                              # Hintergrund-Helfer gehören nicht zur Auswahl
        self.assertTrue(all(t["installable"] for t in a["params"]["tools"]))
        self.assertTrue(all(t["store_url"].startswith("https://wordpress.org/plugins/") for t in a["params"]["tools"]))
        self.assertNotIn("install_security", av)
        self.assertNotIn("install_backup", [x["id"] for x in actions.available(PRESENT, INFO, "8.3", {}, {"wpcli": "/h/wp-cli.phar"})])

    def test_without_wpcli_only_links(self):
        a = {x["id"]: x for x in actions.available(MISSING, INFO, "8.3", {}, {})}["install_backup"]
        self.assertFalse(any(t["installable"] for t in a["params"]["tools"]))
        self.assertIn("WP-CLI", a["reason"])

    def test_joomla_akeeba_installable_via_verified_manifest(self):
        info = {"cms": "joomla", "joomla": "5.2.0", "php_candidates": INFO["php_candidates"]}
        a = {x["id"]: x for x in actions.available(MISSING, info, "8.3", {}, {})}["install_backup"]
        tools = a["params"]["tools"]
        self.assertEqual([t["id"] for t in tools], ["akeeba"])
        self.assertTrue(tools[0]["installable"])
        self.assertTrue(tools[0]["store_url"].startswith("https://extensions.joomla.org/"))

    def test_store_info_uses_backup_list(self):
        from claudia.checks.security_ext import load_tools
        t = [x for x in load_tools("backup")["wordpress"] if x["id"] == "akeeba"][0]
        i = store.lookup(t, "wordpress")
        self.assertTrue(i.get("url") or i.get("store_url") or i.get("name"), i)
        self.assertNotIn("akeeba", [x["id"] for x in load_tools("security")["wordpress"]])


class Target(unittest.TestCase):
    def test_unknown_or_hostile_tool_is_refused(self):
        for bad in ("", "nope", "akeeba; rm -rf ~", "aiowpmigration", "wordfence", "../x"):
            with self.assertRaises(actions.ActionError, msg=bad):
                actions._security_target({"cms": "wordpress", "tool": bad}, "backup")
        self.assertEqual(actions._security_target({"cms": "wordpress", "tool": "akeeba"}, "backup")["slug"], "akeebabackupwp")
        j = actions._security_target({"cms": "joomla", "tool": "akeeba"}, "backup")      # Joomla: nur die geprüfte Update-Adresse
        self.assertEqual(j["manifest"], "https://cdn.akeebabackup.com/updates/pkgakeebacore.xml")
        self.assertEqual(j["element"], "pkg_akeebabackup")
        with self.assertRaises(actions.ActionError):
            actions._security_target({"cms": "joomla", "tool": "nope"}, "backup")

    def test_preview(self):
        cmds = "\n".join(actions.commands_preview("install_backup", {"cms": "wordpress", "tool": "akeeba", "wpcli": "/h/wp-cli.phar", "php": "php8.3"}, CHOICES))
        self.assertIn("plugin install akeebabackupwp --activate", cmds)
        self.assertIn("Sicherung", cmds)
        with self.assertRaises(actions.ActionError):
            actions.commands_preview("install_backup", {"cms": "wordpress", "tool": "?", "wpcli": "x", "php": "php8.3"}, CHOICES)


class Run(unittest.TestCase):
    def test_install_and_activate(self):
        r, w = si.world()
        p = {"cms": "wordpress", "tool": "akeeba", "php": "php8.3", "wpcli": os.path.join(w["home"], "wp-cli.phar")}
        res = actions.run_action(r, w["site_rel"], "install_backup", p, CHOICES)
        self.assertTrue(res["ok"], res)
        self.assertTrue(os.path.isdir(res["backup_dir"]))
        calls = open(os.path.join(w["home"], "php_calls.txt")).read()
        self.assertIn("plugin install akeebabackupwp --activate", calls)
        self.assertIn("plugin verify-checksums akeebabackupwp", calls)

    def test_security_tool_name_is_refused_here(self):
        r, w = si.world()
        p = {"cms": "wordpress", "tool": "wordfence", "php": "php8.3", "wpcli": os.path.join(w["home"], "wp-cli.phar")}
        res = actions.run_action(r, w["site_rel"], "install_backup", p, CHOICES)
        self.assertFalse(res["ok"])
        self.assertEqual(res["backup_dir"], "")
        self.assertFalse(os.path.exists(os.path.join(w["home"], "php_calls.txt")))


if __name__ == "__main__":
    unittest.main()
