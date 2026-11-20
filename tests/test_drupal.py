"""Drupal (2.8.0): Profil, Erkennung, settings.php, Auswertungen und alle Drupal-Prüfungen auf einer nachgebauten Drupal-10-Testwelt. Nur lesend, keine Geheimnisse im Ergebnis."""
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ["CLAUDIA_OFFLINE"] = "1"      # kein Abruf bei drupal.org in der Testumgebung; Netz-Abrufe werden gezielt nachgestellt

import drupalfixture  # noqa: E402
import test_konto as k  # noqa: E402
from claudia import cms as cmsmod, drupal, drupalref, registry  # noqa: E402
from claudia.checks import auswertung_drupal as ad  # noqa: E402
from claudia.checks import drupal_checks as dc  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

DRUPAL_IDS = ["drupal_core", "drupal_settings", "drupal_exposed", "drupal_modules", "drupal_users", "drupal_config_db", "drupal_db_code"]
NOW = 1_800_000_000.0
DAY = 86400
HIST = """<project><title>Drupal</title><short_name>drupal</short_name><project_status>published</project_status>
<supported_branches>10.3.,11.0.</supported_branches><releases>
<release><name>drupal 10.3.5</name><version>10.3.5</version><status>published</status><mdhash>%s</mdhash><download_link>https://ftp.drupal.org/files/projects/drupal-10.3.5.tar.gz</download_link>
<terms><term><name>Release type</name><value>Security update</value></term></terms></release>
<release><name>drupal 10.3.1</name><version>10.3.1</version><status>published</status></release>
<release><name>drupal 11.0.0-rc1</name><version>11.0.0-rc1</version><status>published</status></release>
</releases></project>""" % ("a" * 32)


def run(w, ids, url=""):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="drupal", url=url, allow_hosts=k.ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, k.ADV)
    return eng.run(ids, lambda e: None, threading.Event())


def sevs(rows):
    return [r[0] for r in rows]


class Profile(unittest.TestCase):
    def test_known(self):
        self.assertEqual(cmsmod.known("drupal"), "drupal")
        self.assertEqual(cmsmod.name_of("drupal"), "Drupal")
        self.assertEqual(cmsmod.profile("drupal")["config_file"], "sites/default/settings.php")

    def test_common_checks_are_limited(self):
        ids = {c.id for c in registry.ordered("drupal")}
        for bad in ("update_ready", "security_ext", "sessions", "threat_intel", "mail_send", "compare_runs"):
            self.assertNotIn(bad, ids)
        for good in ("webshells", "php_in_uploads", "perms", "db_access", "access_logs"):
            self.assertIn(good, ids)
        for i in DRUPAL_IDS:
            self.assertIn(i, ids)

    def test_drupal_checks_not_in_other_systems(self):
        for cms in ("joomla", "wordpress"):
            ids = {c.id for c in registry.ordered(cms)}
            self.assertFalse(ids & set(DRUPAL_IDS))

    def test_joomla_and_wordpress_keep_all_common_checks(self):
        for cms in ("joomla", "wordpress"):
            self.assertTrue(cmsmod.runs_common(cms, "anything"))

    def test_cluster_and_group_fit(self):
        for c in registry.ordered("drupal"):
            if c.id in DRUPAL_IDS:
                self.assertIn(c.cluster_for("drupal"), registry.CLUSTERS)
        groups = {g[0] for g in registry.groups_for("drupal")}
        for c in registry.ordered("drupal"):
            self.assertIn(c.group, groups)

    def test_texts_say_drupal_not_joomla(self):
        for c in registry.ordered("drupal"):
            pub = c.public("drupal")
            blob = " ".join(str(pub.get(x, "")) for x in ("title", "what", "why", "reads"))
            if c.id != "other_installs":
                self.assertNotIn("Joomla", blob, c.id)
                self.assertNotIn("configuration.php", blob, c.id)
        for g in registry.groups_for("drupal"):
            self.assertNotIn("Joomla", g[1] + g[2])
        for c in registry.cluster_title_defs("drupal"):
            self.assertNotIn("Joomla", c["title"] + c["text"])


class Parsers(unittest.TestCase):
    def test_version(self):
        self.assertEqual(drupal.parse_drupal_version(drupalfixture.DRUPAL_PHP), "10.3.1")
        self.assertEqual(drupal.parse_drupal_version("", "define('VERSION', '7.103');"), "7.103")
        self.assertEqual(drupal.parse_drupal_version("", ""), "")

    def test_version_key_order(self):
        self.assertGreater(drupal.version_key("10.3.5"), drupal.version_key("10.3.1"))
        self.assertGreater(drupal.version_key("11.0.0"), drupal.version_key("11.0.0-rc1"))

    def test_settings(self):
        r = drupal.parse_settings(drupalfixture.SETTINGS_GOOD)
        self.assertEqual(r["vars"]["db"], "drupal_db")
        self.assertEqual(r["vars"]["user"], "drupal_user")
        self.assertEqual(r["vars"]["host"], "localhost:3306")
        self.assertTrue(r["trusted_hosts"])
        self.assertEqual(r["unexpected"], [])

    def test_settings_bad(self):
        r = drupal.parse_settings(drupalfixture.SETTINGS_BAD)
        self.assertFalse(r["trusted_hosts"])
        self.assertEqual(r["settings"]["update_free_access"], "TRUE")
        self.assertTrue(r["unexpected"])

    def test_settings_password_with_bracket(self):
        t = "<?php\n$databases['default']['default'] = [\n  'database' => 'd',\n  'username' => 'u',\n  'password' => 'a]b);c',\n  'host' => 'h',\n];\n"
        self.assertEqual(drupal.parse_settings(t)["vars"]["password"], "a]b);c")

    def test_settings_commented_out_is_ignored(self):
        t = "<?php\n// $databases['default']['default'] = ['database' => 'x', 'username' => 'y'];\n"
        self.assertEqual(drupal.parse_settings(t)["vars"]["db"], "")

    def test_info_yml(self):
        i = drupal.parse_info_yml("name: Pathauto\ntype: module  # kommentar\nversion: '1.12.0'\nproject: pathauto\n")
        self.assertEqual((i["name"], i["type"], i["version"], i["project"]), ("Pathauto", "module", "1.12.0", "pathauto"))

    def test_project_of(self):
        self.assertEqual(drupal.project_of("modules/contrib/pathauto/src"), "pathauto")
        self.assertEqual(drupal.project_of("./themes/custom/mein"), "mein")


class ReleaseHistory(unittest.TestCase):
    def test_parse(self):
        h = ad.parse_release_history(HIST)
        self.assertTrue(h["ok"])
        self.assertEqual(h["supported"], ["10.3.", "11.0."])
        self.assertEqual(len(h["releases"]), 3)
        self.assertIn("Security update", h["releases"][0]["types"])

    def test_rejects_garbage_and_entities(self):
        for t in ("", None, "<html>x</html>", "<project><releases>", '<!DOCTYPE x [<!ENTITY a "b">]><project/>'):
            self.assertFalse(ad.parse_release_history(t)["ok"])

    def test_state_security(self):
        st = ad.release_state("10.3.1", ad.parse_release_history(HIST))
        self.assertEqual(st["state"], "security")
        self.assertEqual(st["latest"], "10.3.5")

    def test_state_current_and_unknown(self):
        h = ad.parse_release_history(HIST)
        self.assertEqual(ad.release_state("10.3.5", h)["state"], "current")
        self.assertEqual(ad.release_state("10.3.1", None)["state"], "unknown")
        self.assertEqual(ad.release_state("10.3.x-dev", h)["state"], "unknown")

    def test_unsupported_branch(self):
        self.assertTrue(ad.release_state("10.2.7", ad.parse_release_history(HIST))["unsupported"])

    def test_insecure_marker(self):
        x = "<project><supported_branches>1.</supported_branches><releases><release><version>1.0.0</version><terms><term><name>Release type</name><value>Insecure</value></term></terms></release></releases></project>"
        self.assertEqual(ad.release_state("1.0.0", ad.parse_release_history(x))["state"], "insecure")


class Core(unittest.TestCase):
    def test_old_majors_are_critical(self):
        self.assertEqual(sevs(ad.judge_core("7.103", None)), ["crit"])
        self.assertEqual(sevs(ad.judge_core("9.5.11", None)), ["crit"])

    def test_security_update(self):
        r = ad.judge_core("10.3.1", ad.parse_release_history(HIST))
        self.assertEqual(r[0][0], "crit")
        self.assertIn("10.3.5", r[0][4])

    def test_unknown_is_info_not_ok(self):
        self.assertEqual(sevs(ad.judge_core("10.3.1", None)), ["info"])

    def test_no_version(self):
        self.assertIn("nicht prüfbar", ad.judge_core("", None)[0][1])

    def test_files_clean(self):
        self.assertEqual(sevs(ad.judge_core_files(300, [], [], [])), ["ok"])

    def test_files_php_extra_is_critical(self):
        r = ad.judge_core_files(300, [], [], ["core/lib/x.php", "core/notes.txt"])
        self.assertEqual(sevs(r), ["crit", "info"])

    def test_files_changed_is_warn_and_many_is_wrong_reference(self):
        self.assertEqual(sevs(ad.judge_core_files(300, ["core/a.php"], [], [])), ["warn"])
        self.assertEqual(sevs(ad.judge_core_files(300, ["core/%d.php" % i for i in range(150)], [], [])), ["warn"])
        self.assertIn("Sehr viele", ad.judge_core_files(300, ["core/%d.php" % i for i in range(150)], [], [])[0][1])


class Modules(unittest.TestCase):
    def inv(self):
        return [{"project": "pathauto", "name": "Pathauto", "version": "1.12.0", "custom": False},
                {"project": "token", "name": "Token", "version": "1.14.0", "custom": False},
                {"project": "meins", "name": "Meins", "version": "", "custom": True},
                {"project": "devel", "name": "Devel", "version": "5.2.0", "custom": False}]

    def test_security_and_unsupported(self):
        states = {"pathauto": {"state": "security", "latest": "1.13.0", "security": ["1.13.0"], "unsupported": False},
                  "token": {"state": "current", "latest": "1.14.0", "security": [], "unsupported": True}}
        r = ad.judge_modules(self.inv(), states)
        t = [x[1] for x in r]
        self.assertTrue(any("Sicherheitsupdates" in x for x in t))
        self.assertTrue(any("nicht mehr betreut" in x for x in t))
        self.assertTrue(any("Entwicklungs-Modul" in x for x in t))

    def test_without_online_data_never_claims_ok(self):
        r = ad.judge_modules(self.inv(), {})
        self.assertIn("nicht prüfbar", " ".join(x[1] for x in r))

    def test_empty(self):
        self.assertEqual(sevs(ad.judge_modules([], {})), ["info"])


class Users(unittest.TestCase):
    def test_fresh_admin_warns(self):
        rows = [{"uid": 1, "name": "chef", "status": 1, "created_ts": NOW - 900 * DAY, "access_ts": NOW - DAY, "admin": True},
                {"uid": 3, "name": "neu", "status": 1, "created_ts": NOW - 2 * DAY, "access_ts": None, "admin": True}]
        r = ad.judge_users(rows, NOW)
        self.assertEqual(sevs(r), ["info", "warn", "info"])
        self.assertEqual(r[1][3], ["neu"])

    def test_blocked_admin_not_counted(self):
        r = ad.judge_users([{"uid": 5, "name": "x", "status": 0, "created_ts": NOW, "access_ts": NOW, "admin": True}], NOW)
        self.assertEqual(sevs(r), ["info"])

    def test_garbage(self):
        self.assertIn("nicht prüfbar", ad.judge_users("x")[0][1])


class ConfigJudge(unittest.TestCase):
    def test_ok(self):
        r = ad.judge_config({"logging": 'a:1:{s:11:"error_level";s:4:"hide";}', "user_settings": 'a:1:{s:8:"register";s:10:"admin_only";}'})
        self.assertEqual(set(sevs(r)), {"ok"})

    def test_bad(self):
        r = ad.judge_config({"logging": 'a:1:{s:11:"error_level";s:7:"verbose";}', "user_settings": 'a:1:{s:8:"register";s:8:"visitors";}',
                             "core_extension": 'a:1:{s:6:"module";a:1:{s:5:"devel";i:0;}}',
                             "roles": {"anonymous": 'a:1:{s:11:"permissions";a:1:{i:0;s:15:"administer users";}}'}})
        self.assertEqual(sevs(r).count("warn"), 3)
        self.assertIn("crit", sevs(r))

    def test_empty(self):
        self.assertIn("nicht prüfbar", ad.judge_config({})[0][1])


class SettingsJudge(unittest.TestCase):
    def test_clean(self):
        r = ad.judge_settings(drupal.parse_settings(drupalfixture.SETTINGS_GOOD), {"sites/default/settings.php": "444 u", "sites/default": "755 u"})
        self.assertEqual(sevs(r), ["ok"])

    def test_bad(self):
        r = ad.judge_settings(drupal.parse_settings(drupalfixture.SETTINGS_BAD), {"sites/default/settings.php": "666 u"})
        self.assertEqual(sevs(r).count("crit"), 3)
        self.assertNotIn("GEHEIM", str(r))

    def test_owner_writable_is_info(self):
        r = ad.judge_settings(drupal.parse_settings(drupalfixture.SETTINGS_GOOD), {"sites/default/settings.php": "644 u"})
        self.assertEqual(sevs(r), ["info"])

    def test_missing(self):
        self.assertIn("nicht prüfbar", ad.judge_settings({"missing": True})[0][1])


class DbCode(unittest.TestCase):
    def test_levels(self):
        r = ad.judge_db_code([{"table": "node__body", "id": 2, "text": "<script>eval(atob('x'))</script>"},
                              {"table": "node__body", "id": 3, "text": '<iframe src="https://youtube.com/embed/x"></iframe>'},
                              {"table": "node__body", "id": 4, "text": "<p>hallo</p>"}])
        self.assertEqual(sevs(r), ["crit", "warn"])

    def test_none_found(self):
        self.assertEqual(sevs(ad.judge_db_code([])), ["ok"])


class Exposed(unittest.TestCase):
    def test_all(self):
        web = [{"kind": "file", "label": "s", "url": "u/sites/default/settings.php", "status": 200, "body": "<?php $databases"},
               {"kind": "api", "label": "j", "url": "u/jsonapi/user/user", "status": 200, "body": '{"data":[{"attributes":{"name":"x"}}]}'},
               {"kind": "install", "label": "i", "url": "u", "status": 200, "body": "Choose language"},
               {"kind": "version", "label": "v", "url": "u", "status": 200, "body": "Drupal 10.3.1, 2024"},
               {"kind": "dir", "label": "d", "url": "u", "status": 200, "body": "<title>Index of /files</title>"}]
        r = ad.judge_exposed(web)
        self.assertEqual(sevs(r), ["crit", "warn", "info"])
        self.assertEqual(len(r[0][3]), 3)

    def test_soft_404_and_protected(self):
        web = [{"kind": "file", "label": "s", "url": "u", "status": 200, "body": "<!DOCTYPE html><html>nicht gefunden</html>"},
               {"kind": "api", "label": "j", "url": "u", "status": 403, "body": "{}"}]
        self.assertEqual(sevs(ad.judge_exposed(web)), ["ok"])


class Reference(unittest.TestCase):
    def tar(self, version, n=210):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for i in range(n):
                data = b"<?php // %d" % i
                ti = tarfile.TarInfo("drupal-%s/core/lib/Part%d.php" % (version, i))
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            ti = tarfile.TarInfo("drupal-%s/core/../../evil.php" % version)
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
            ti = tarfile.TarInfo("drupal-%s/index.php" % version)
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        return buf.getvalue()

    def test_hash_tar_only_core_and_no_traversal(self):
        files = drupalref.hash_tar(self.tar("10.3.1"), "10.3.1")
        self.assertEqual(len(files), 210)
        self.assertTrue(all(p.startswith("core/") and ".." not in p for p in files))

    def test_package_url_only_official_host(self):
        self.assertEqual(drupalref.package_url("10.3.1", "https://evil.example/drupal-10.3.1.tar.gz"), "https://ftp.drupal.org/files/projects/drupal-10.3.1.tar.gz")
        self.assertEqual(drupalref.package_url("10.3.1", "http://ftp.drupal.org/files/projects/drupal-10.3.1.tar.gz"), "https://ftp.drupal.org/files/projects/drupal-10.3.1.tar.gz")

    def test_md5_mismatch_is_refused(self):
        with mock.patch.object(drupalref.coreref, "fetch_bytes", return_value=self.tar("10.3.1")):
            with self.assertRaises(drupalref.RefError):
                drupalref.reference("10.3.1", "0" * 32)

    def test_md5_ok(self):
        data = self.tar("10.3.1")
        with mock.patch.object(drupalref.coreref, "fetch_bytes", return_value=data):
            r = drupalref.reference("10.3.1", hashlib.md5(data).hexdigest())
        self.assertTrue(r["verified"])

    def test_prerelease_has_no_package(self):
        with self.assertRaises(drupalref.RefError):
            drupalref.reference("11.0.0-rc1")


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_drupal_")
        cls.bad = drupalfixture.make_drupal_world(cls.base, True)
        cls.good = drupalfixture.make_drupal_world(cls.base, False)
        for w in (cls.bad, cls.good):
            k.install(w["bin"], "crontab", k.FAKE_CRONTAB)
            k.install(w["bin"], "ssh-keygen", k.FAKE_KEYGEN)
            k.install(w["bin"], "ps", k.FAKE_PS)
        ids = [c.id for c in registry.ordered("drupal")]
        os.environ["CLAUDIA_TEST_DB"] = cls.bad["db"]
        cls.rb = {r.id: r for r in run(cls.bad, ids)}
        os.environ["CLAUDIA_TEST_DB"] = cls.good["db"]
        cls.rg = {r.id: r for r in run(cls.good, ids)}

    def test_no_check_crashes(self):
        for rr in (self.rb, self.rg):
            for i, r in rr.items():
                self.assertNotEqual(r.status, "error", (i, k.blob(r)[:300]))

    def test_infected_findings(self):
        b = self.rb
        self.assertEqual(b["drupal_settings"].findings[0].sev, "crit")
        self.assertIn(("crit", "1 Inhalt(e) enthalten verschleierten oder fremden Code"), k.tt(b["drupal_db_code"]))
        self.assertTrue(any(f.sev == "warn" and "Administrator-Konto" in f.title for f in b["drupal_users"].findings))
        self.assertEqual(max(f.sev == "crit" for f in b["drupal_config_db"].findings), True)
        self.assertTrue(any("Entwicklungs-Modul" in f.title for f in b["drupal_modules"].findings))
        self.assertEqual(b["webshells"].status, "crit")

    def test_clean_has_no_crit_in_drupal_checks(self):
        for i in ("drupal_settings", "drupal_users", "drupal_config_db", "drupal_db_code"):
            self.assertNotIn("crit", [f.sev for f in self.rg[i].findings], i)
        self.assertEqual(k.tt(self.rg["drupal_settings"]), [("ok", "Die settings.php ist unauffällig")])

    def test_database_access_uses_settings_php(self):
        self.assertEqual(self.rg["db_access"].findings[0].sev, "ok")

    def test_no_secrets_in_any_result(self):
        for rr in (self.rb, self.rg):
            for r in rr.values():
                b = k.blob(r)
                self.assertNotIn("GEHEIM-DB-PASSWORT", b)
                self.assertNotIn("zufallswert-geheim", b)

    def test_exposed_needs_url(self):
        self.assertEqual(self.rg["drupal_exposed"].status, "skipped")

    def test_drupal7_skips_database_checks(self):
        w = drupalfixture.make_drupal_world(tempfile.mkdtemp(), False)
        with open(os.path.join(w["site"], "core/lib/Drupal.php"), "w") as fh:
            fh.write("<?php\nclass Drupal {\n  const VERSION = '7.103';\n}\n")
        os.environ["CLAUDIA_TEST_DB"] = w["db"]
        r = {x.id: x for x in run(w, ["drupal_users", "drupal_config_db"])}
        self.assertEqual(r["drupal_users"].status, "skipped")

    def test_online_core_and_files(self):
        w = self.bad
        os.environ["CLAUDIA_TEST_DB"] = w["db"]
        site = w["site"]
        ref = {}
        for root, _, files in os.walk(os.path.join(site, "core")):
            for f in files:
                p = os.path.join(root, f)
                rel = os.path.relpath(p, site).replace(os.sep, "/")
                if rel.endswith("Backdoor.php"):
                    continue
                ref[rel] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        ref["core/lib/Drupal/Core/Part1.php"] = "0" * 64        # geänderte Datei
        ref["core/lib/Drupal/Core/Fehlt.php"] = "1" * 64        # fehlende Datei
        hist = ad.parse_release_history(HIST.replace("10.3.1</version>", "10.3.1</version><mdhash>" + "b" * 32 + "</mdhash>", 1))
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(dc, "history", return_value=hist), \
                    mock.patch.object(drupalref, "reference", return_value={"files": ref, "package": "drupal-10.3.1.tar.gz", "md5": "x", "verified": True}):
                r = run(w, ["drupal_core"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        t = k.tt(r)
        self.assertIn(("crit", "Für Drupal 10.3.1 gibt es Sicherheitsupdates"), t)
        self.assertIn(("crit", "1 unbekannte PHP-Datei(en) im Ordner core"), t)
        self.assertIn(("warn", "1 Kerndatei(en) weichen vom Original ab"), t)
        self.assertIn(("warn", "1 Kerndatei(en) fehlen"), t)

    def test_online_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith("settings.php") else 403
            f.body = "<?php $databases" if url.endswith("settings.php") else ""
            return f
        os.environ["CLAUDIA_TEST_DB"] = self.bad["db"]
        with mock.patch.object(webmod, "fetch", fake):
            r = run(self.bad, ["drupal_exposed"], "https://www.testseite.example")[0]
        self.assertEqual(r.findings[0].sev, "crit")

    def test_online_modules_with_fake_history(self):
        x = "<project><supported_branches>1.</supported_branches><releases><release><version>1.13.0</version><terms><term><name>Release type</name><value>Security update</value></term></terms></release><release><version>1.12.0</version></release></releases></project>"
        os.environ.pop("CLAUDIA_OFFLINE", None)
        os.environ["CLAUDIA_TEST_DB"] = self.good["db"]
        try:
            with mock.patch.object(dc, "history", side_effect=lambda p: ad.parse_release_history(x) if p == "pathauto" else None):
                r = run(self.good, ["drupal_modules"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        self.assertIn(("crit", "Für 1 Modul(e)/Theme(s) gibt es Sicherheitsupdates"), k.tt(r))


class Detection(unittest.TestCase):
    def test_probe_detects_drupal(self):
        from claudia import probe
        w = drupalfixture.make_drupal_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "drupal")
        self.assertEqual(info["drupal"], "10.3.1")
        self.assertTrue(info["drupal_config"])


if __name__ == "__main__":
    unittest.main()
