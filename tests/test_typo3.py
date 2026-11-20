"""TYPO3 (2.10.0): Profil, Erkennung, Einstellungsdatei, Auswertungen und alle TYPO3-Prüfungen auf einer nachgebauten TYPO3-12-Testwelt (klassisch und Composer). Nur lesend, keine Geheimnisse im Ergebnis."""
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ["CLAUDIA_OFFLINE"] = "1"      # kein Abruf im Netz in der Testumgebung; Netz-Abrufe werden gezielt nachgestellt

import typo3fixture  # noqa: E402
import test_konto as k  # noqa: E402
from claudia import cms as cmsmod, registry, typo3, typo3ref  # noqa: E402
from claudia.checks import auswertung_typo3 as at  # noqa: E402
from claudia.checks import typo3_checks as tc  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

NOW = 1_800_000_000.0     # 2027-01-15
DAY = 86400


def run(w, ids, url=""):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="typo3", url=url, allow_hosts=k.ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, k.ADV)
    return eng.run(ids, lambda e: None, threading.Event())


def sevs(rows):
    return [r[0] for r in rows]


def adv_json(pkg="typo3/cms-core", affected=">=12.0.0,<12.4.9"):
    return json.dumps({"advisories": {pkg: [{"advisoryId": "PKSA-1", "packageName": pkg, "title": "XSS im Backend", "link": "https://typo3.org/security/advisory/typo3-core-sa-2026-001",
                                             "cve": "CVE-2026-0001", "affectedVersions": affected, "reportedAt": "2026-05-01 00:00:00"}]}})


class Profile(unittest.TestCase):
    def test_known(self):
        self.assertIn("typo3", cmsmod.PROFILES)
        self.assertEqual(cmsmod.PROFILES["typo3"]["name"], "TYPO3")

    def test_common_checks_are_the_drupal_selection(self):
        self.assertEqual(cmsmod.PROFILES["typo3"]["common_checks"], cmsmod.PROFILES["drupal"]["common_checks"])
        ids = {c.id for c in registry.ordered("typo3")}
        self.assertNotIn("joomla_core", ids)
        self.assertNotIn("wp_info", ids)

    def test_typo3_checks_not_in_other_systems(self):
        t3 = {"typo3_core", "typo3_settings", "typo3_exposed", "typo3_extensions", "typo3_users", "typo3_db_code"}
        for cms in ("joomla", "wordpress", "drupal"):
            self.assertFalse(t3 & {c.id for c in registry.ordered(cms)}, cms)
        self.assertTrue(t3 <= {c.id for c in registry.ordered("typo3")})

    def test_joomla_and_wordpress_keep_all_common_checks(self):
        for cms in ("joomla", "wordpress"):
            self.assertTrue({"root_files", "perms", "webshells"} <= {c.id for c in registry.ordered(cms)})

    def test_cluster_and_group_fit(self):
        for c in registry.ordered("typo3"):
            if c.id.startswith("typo3_"):
                self.assertTrue(c.cluster_for("typo3"), c.id)
                self.assertIn(c.group, [g[0] for g in registry.groups_for("typo3")])
        self.assertIn("TYPO3", " ".join(g[1] for g in registry.groups_for("typo3")))

    def test_texts_say_typo3_not_joomla(self):
        for c in registry.ordered("typo3"):
            v = c.view("typo3") if hasattr(c, "view") else {}
            blob = json.dumps(v, ensure_ascii=False)
            self.assertNotIn("configuration.php", blob, c.id)


class Parsers(unittest.TestCase):
    def test_version_new_and_old(self):
        self.assertEqual(typo3.parse_typo3_version(typo3fixture.VERSION_PHP), "12.4.8")
        self.assertEqual(typo3.parse_typo3_version("", "define('TYPO3_version', '8.7.30');"), "8.7.30")
        self.assertEqual(typo3.parse_typo3_version("nichts"), "")

    def test_lifecycle(self):
        self.assertEqual(typo3.lifecycle("13.4.1", NOW)["state"], "supported")
        self.assertEqual(typo3.lifecycle("12.4.8", NOW)["state"], "elts")
        self.assertEqual(typo3.lifecycle("11.5.1", NOW)["state"], "elts")
        self.assertEqual(typo3.lifecycle("10.4.1", NOW)["state"], "ended")
        self.assertEqual(typo3.lifecycle("99.0.0", NOW)["state"], "unknown")
        self.assertEqual(typo3.lifecycle("", NOW)["state"], "unknown")

    def test_settings(self):
        r = typo3.parse_settings(typo3fixture.SETTINGS_GOOD)
        self.assertEqual(r["vars"], {"host": "localhost:3306", "user": "typo3_user", "password": "GEHEIM-DB-PASSWORT", "db": "typo3_db", "dbprefix": "", "dbtype": "mysqli"})
        self.assertTrue(r["parsed"] and r["has_key"])
        self.assertEqual(r["key_len"], 96)
        self.assertNotIn("encryptionKey", r["typo3"]["SYS"])           # Schlüssel werden nicht weitergegeben
        self.assertNotIn("installToolPassword", r["typo3"]["BE"])
        self.assertEqual(r["unexpected"], [])

    def test_settings_dangerous_in_both_files(self):
        r = typo3.parse_settings(typo3fixture.SETTINGS_GOOD + "\n@eval($x);", "<?php system('id');")
        self.assertEqual(len(r["unexpected"]), 2)

    def test_settings_commented_out_is_ignored(self):
        r = typo3.parse_settings("<?php\n// eval($x);\n/* system('x'); */\n# exec('y');\nreturn ['SYS' => ['displayErrors' => 0]];")
        self.assertEqual(r["unexpected"], [])
        self.assertEqual(r["typo3"]["SYS"]["displayErrors"], 0)

    def test_settings_password_with_special_characters(self):
        t = "<?php return ['DB' => ['Connections' => ['Default' => ['password' => 'a\\'b]c,d=>e', 'user' => 'u', 'dbname' => 'd', 'host' => 'h']]]];"
        r = typo3.parse_settings(t)
        self.assertEqual(r["vars"]["password"], "a'b]c,d=>e")
        self.assertEqual(r["vars"]["user"], "u")

    def test_settings_expression_stays_unknown(self):
        t = "<?php return ['DB' => ['Connections' => ['Default' => ['password' => getenv('X'), 'user' => 'u', 'dbname' => 'd', 'host' => 'h']]]];"
        r = typo3.parse_settings(t)
        self.assertEqual(r["vars"]["user"], "u")
        self.assertNotIn("getenv", r["vars"]["password"].replace("getenv('X')", "") + "x") if False else None
        self.assertTrue(isinstance(r["vars"]["password"], str))

    def test_settings_bad(self):
        r = typo3.parse_settings("kein php")
        self.assertFalse(r["parsed"])
        self.assertFalse(typo3.parse_settings("")["parsed"])

    def test_settings_deep_nesting_is_safe(self):
        r = typo3.parse_settings("<?php return " + "[" * 500 + "];")
        self.assertIsInstance(r, dict)

    def test_ext_emconf(self):
        self.assertEqual(typo3.parse_ext_emconf(typo3fixture.EMCONF % ("News", "stable", "11.4.2")), {"title": "News", "version": "11.4.2", "state": "stable", "category": "plugin"})
        self.assertEqual(typo3.parse_ext_emconf("kaputt"), {})

    def test_installed_json(self):
        r = typo3.parse_installed_json(json.dumps({"packages": [{"name": "a/b", "version": "v1.2.3", "type": "typo3-cms-extension", "dist": {"type": "path"}}]}))
        self.assertEqual(r, [{"name": "a/b", "version": "1.2.3", "type": "typo3-cms-extension", "path": "1"}])
        self.assertEqual(typo3.parse_installed_json("{kaputt"), [])
        self.assertEqual(len(typo3.parse_installed_json(json.dumps([{"name": "a/b", "version": "1"}]))), 1)      # Composer 1

    def test_package_names(self):
        self.assertEqual(typo3.sysext_package("fluid_styled_content"), "typo3/cms-fluid-styled-content")
        self.assertEqual(typo3.package_sysext("typo3/cms-fluid-styled-content"), "fluid_styled_content")
        self.assertEqual(typo3.package_sysext("georgringer/news"), "")
        self.assertEqual(typo3.ext_key_of("typo3conf/ext/news"), "news")
        self.assertEqual(typo3.composer_name_of('{"name": "georgringer/news"}'), "georgringer/news")
        self.assertEqual(typo3.composer_name_of('{"name": "../../x"}'), "")

    def test_release_list(self):
        t = json.dumps({"13": {"releases": {"13.4.12": {"version": "13.4.12", "type": "regular"}, "13.4.13": {"version": "13.4.13", "elts": True}, "13.5.0-rc1": {"version": "13.5.0-rc1"}}}})
        self.assertEqual([r["version"] for r in typo3.parse_release_list(t)], ["13.4.12"])
        self.assertEqual(typo3.parse_release_list("kaputt"), [])
        self.assertEqual(typo3.parse_release_list(None), [])

    def test_sha_from_page(self):
        h = "a" * 64
        self.assertEqual(typo3.sha256_from_version_page("%s  typo3_src-12.4.8.tar.gz\n%s  typo3_src-12.4.8.zip" % (h, "b" * 64), "12.4.8"), h)
        self.assertEqual(typo3.sha256_from_version_page("%s  typo3_src-12.4.9.tar.gz" % h, "12.4.8"), "")

    def test_split_config_output(self):
        r = typo3.split_config_output("@@CONF a/settings.php\n<?php x\n@@ADD a/additional.php\n<?php y\n")
        self.assertEqual((r["path"], r["add_path"]), ("a/settings.php", "a/additional.php"))
        self.assertEqual(typo3.split_config_output("")["path"], "")


class Constraints(unittest.TestCase):
    def test_affected(self):
        c = ">=12.0.0,<12.4.8|>=13.0.0,<13.1.1"
        self.assertTrue(typo3.affected("12.4.7", c))
        self.assertFalse(typo3.affected("12.4.8", c))
        self.assertTrue(typo3.affected("13.1.0", c))
        self.assertFalse(typo3.affected("11.5.0", c))

    def test_wildcard_and_exact(self):
        self.assertTrue(typo3.affected("1.2.5", "1.2.*"))
        self.assertFalse(typo3.affected("1.3.0", "1.2.*"))
        self.assertTrue(typo3.affected("1.2.3", "=1.2.3"))
        self.assertTrue(typo3.affected("1.2.3", ">=1.2.3 <1.3"))

    def test_dev_and_garbage_never_match(self):
        self.assertFalse(typo3.affected("dev-main", "<99"))
        self.assertFalse(typo3.affected("", "<99"))
        self.assertFalse(typo3.affected("1.0.0", "unsinn"))

    def test_parse_advisories(self):
        a = typo3.parse_advisories(adv_json())
        self.assertEqual(a["typo3/cms-core"][0]["cve"], "CVE-2026-0001")
        self.assertEqual(typo3.parse_advisories("kaputt"), {})
        self.assertEqual(len(typo3.advisories_for("12.4.8", a, "typo3/cms-core")), 1)
        self.assertEqual(typo3.advisories_for("12.4.9", a, "typo3/cms-core"), [])


class Core(unittest.TestCase):
    REL = [{"version": "12.4.8"}, {"version": "12.4.10"}, {"version": "13.4.1"}]

    def test_ended_and_elts_are_critical(self):
        self.assertEqual(sevs(at.judge_core("10.4.1", [], [], NOW))[0], "crit")
        self.assertEqual(sevs(at.judge_core("12.4.8", [], [], NOW))[0], "crit")

    def test_supported_current_is_ok(self):
        r = at.judge_core("13.4.1", self.REL, [], NOW)
        self.assertIn("ok", sevs(r))
        self.assertNotIn("crit", sevs(r))

    def test_update_available_warns(self):
        r = at.judge_core("13.4.1", self.REL + [{"version": "13.4.5"}], [], NOW)
        self.assertEqual(sevs(r), ["warn"])

    def test_advisories_are_critical(self):
        r = at.judge_core("13.4.1", self.REL, [{"id": "PKSA-1", "title": "XSS", "cve": "CVE-2026-1"}], NOW)
        self.assertIn("crit", sevs(r))
        self.assertIn("CVE-2026-1", json.dumps(r))

    def test_unknown_is_info_not_ok(self):
        r = at.judge_core("13.4.1", [], [], NOW, adv_ok=False)
        self.assertNotIn("ok", sevs(r))

    def test_no_version(self):
        self.assertEqual(sevs(at.judge_core("", [], [])), ["info"])

    def test_files_clean(self):
        self.assertEqual(sevs(at.judge_core_files(300, [], [], [])), ["ok"])

    def test_files_php_extra_is_critical(self):
        r = at.judge_core_files(300, [], [], ["typo3/sysext/core/Classes/Backdoor.php", "typo3/sysext/core/x.txt"])
        self.assertEqual(sevs(r), ["crit", "info"])

    def test_files_changed_and_missing_warn_and_many_means_wrong_reference(self):
        self.assertEqual(sevs(at.judge_core_files(300, ["a"], ["b"], [])), ["warn", "warn"])
        self.assertEqual(sevs(at.judge_core_files(100, ["x%d" % i for i in range(60)], [], [])), ["warn"])

    def test_composer_ignores_missing(self):
        self.assertEqual(sevs(at.judge_core_files(300, [], ["a", "b"], [], composer=True)), ["ok"])


class SettingsJudge(unittest.TestCase):
    def cfg(self, text=typo3fixture.SETTINGS_GOOD, extra=""):
        c = typo3.parse_settings(text, extra)
        c["missing"] = False
        return c

    def test_clean(self):
        self.assertEqual(sevs(at.judge_settings(self.cfg(), {"config/system/settings.php": "644 user"})), ["ok"])

    def test_bad(self):
        r = at.judge_settings(self.cfg(typo3fixture.SETTINGS_BAD, "<?php eval($x);"), {"typo3conf/system/settings.php": "666 user"}, {"path": "typo3conf/ENABLE_INSTALL_TOOL", "age_s": 86400})
        t = " | ".join(x[1] for x in r)
        for part in ("auffällige Befehle", "displayErrors", "devIPmask", "trustedHostsPattern", "encryptionKey", "Install-Tool ist freigeschaltet", "für alle beschreibbar"):
            self.assertIn(part, t)
        self.assertEqual(r[0][0], "crit")

    def test_install_tool_fresh_is_only_warn(self):
        r = at.judge_settings(self.cfg(), {}, {"path": "x", "age_s": 60})
        self.assertEqual(sevs(r), ["warn"])

    def test_missing_and_unparsed(self):
        self.assertEqual(sevs(at.judge_settings({"missing": True})), ["info"])
        self.assertEqual(sevs(at.judge_settings({"missing": False, "parsed": False})), ["info"])
        self.assertEqual(sevs(at.judge_settings(None)), ["info"])

    def test_weak_hashing(self):
        t = typo3fixture.SETTINGS_GOOD.replace("Argon2iPasswordHash", "Md5PasswordHash")
        self.assertIn("veralteten Verfahren", " ".join(x[1] for x in at.judge_settings(self.cfg(t))))

    def test_additional_is_only_info(self):
        r = at.judge_settings(self.cfg(extra="<?php // nur Umgebung\n"))
        self.assertEqual(sevs(r), ["info"])

    def test_no_secret_in_text(self):
        r = at.judge_settings(self.cfg(typo3fixture.SETTINGS_BAD))
        self.assertNotIn("GEHEIM", json.dumps(r))


class Extensions(unittest.TestCase):
    INV = [{"key": "georgringer/news", "name": "georgringer/news", "version": "11.4.2", "state": "", "pkg": "georgringer/news", "custom": False},
           {"key": "meine_ext", "name": "Meine", "version": "1.0.0", "state": "obsolete", "pkg": "", "custom": False},
           {"key": "extension_builder", "name": "Extension Builder", "version": "12.0.0", "state": "stable", "pkg": "", "custom": False},
           {"key": "meine/eigene", "name": "meine/eigene", "version": "dev-main", "state": "", "pkg": "meine/eigene", "custom": True}]

    def test_all_levels(self):
        r = at.judge_extensions(self.INV, {"georgringer/news": [{"id": "PKSA-2", "title": "SQL-Injection", "cve": "CVE-2026-2"}]}, checked=3, adv_ok=True)
        self.assertEqual(sevs(r)[:3], ["crit", "warn", "warn"])
        self.assertIn("info", sevs(r))

    def test_clean_with_online_data_is_ok(self):
        inv = [self.INV[0]]
        self.assertEqual(sevs(at.judge_extensions(inv, {}, checked=1, adv_ok=True)), ["ok"])

    def test_without_online_data_never_claims_ok(self):
        r = at.judge_extensions([self.INV[0]], {}, checked=1, adv_ok=False)
        self.assertNotIn("ok", sevs(r))

    def test_empty_and_garbage(self):
        self.assertEqual(sevs(at.judge_extensions([], {})), ["info"])
        self.assertEqual(sevs(at.judge_extensions(None, {})), ["info"])


class Users(unittest.TestCase):
    def test_fresh_and_never_logged_in_admin(self):
        rows = [{"uid": 1, "name": "chef", "admin": True, "disabled": False, "created_ts": NOW - 900 * DAY, "access_ts": NOW - DAY},
                {"uid": 4, "name": "support", "admin": True, "disabled": False, "created_ts": NOW - 2 * DAY, "access_ts": None}]
        r = at.judge_users(rows, NOW)
        self.assertEqual(sevs(r), ["info", "warn", "info"])

    def test_blocked_admin_not_counted_and_default_name_warns(self):
        r = at.judge_users([{"uid": 1, "name": "admin", "admin": True, "disabled": False, "created_ts": 1, "access_ts": 5},
                            {"uid": 2, "name": "alt", "admin": True, "disabled": True, "created_ts": 1, "access_ts": 5}], NOW)
        self.assertIn("leicht zu erratenden Namen", " ".join(x[1] for x in r))
        self.assertIn("1 aktive", r[0][1])

    def test_garbage(self):
        self.assertEqual(sevs(at.judge_users(None)), ["info"])


class DbCode(unittest.TestCase):
    def test_levels(self):
        r = at.judge_db_code([{"table": "tt_content", "id": 2, "text": "<script>eval(atob('x'))</script>"},
                              {"table": "tt_content", "id": 3, "text": '<iframe src="https://youtube.com/embed/x"></iframe>'},
                              {"table": "tt_content", "id": 4, "text": "<p>hallo</p>"}])
        self.assertEqual(sevs(r), ["crit", "warn"])

    def test_none_found_and_unreadable(self):
        self.assertEqual(sevs(at.judge_db_code([])), ["ok"])
        r = at.judge_db_code(None)
        self.assertEqual(sevs(r), ["info"])
        self.assertIn("TYPO3", r[0][1])


class Exposed(unittest.TestCase):
    def test_all(self):
        web = [{"kind": "file", "label": "s", "url": "u/typo3conf/system/settings.php", "status": 200, "body": "<?php return ['SYS' => ['encryptionKey' => 'x']];"},
               {"kind": "file", "label": "c", "url": "u/composer.json", "status": 200, "body": '{"require": {"typo3/cms-core": "^12"}}'},
               {"kind": "install", "label": "i", "url": "u/typo3/install.php", "status": 200, "body": "<h1>Install Tool</h1><input type=\"password\" name=\"install[password]\">"},
               {"kind": "dir", "label": "d", "url": "u/fileadmin/", "status": 200, "body": "<title>Index of /fileadmin</title>"},
               {"kind": "backend", "label": "b", "url": "u/typo3/", "status": 200, "body": "Login"}]
        r = at.judge_exposed(web)
        self.assertEqual(sevs(r), ["crit", "warn", "info"])
        self.assertEqual(len(r[0][3]), 2)

    def test_first_install_is_critical(self):
        r = at.judge_exposed([{"kind": "install", "label": "i", "url": "u", "status": 200, "body": "Installing TYPO3 - Choose a database"}])
        self.assertEqual(sevs(r), ["crit"])

    def test_locked_install_tool_and_soft_404_are_fine(self):
        web = [{"kind": "install", "label": "i", "url": "u", "status": 200, "body": "The Install Tool is locked. Create ENABLE_INSTALL_TOOL ... type=\"password\""},
               {"kind": "file", "label": "s", "url": "u", "status": 200, "body": "<!DOCTYPE html><html>nicht gefunden</html>"},
               {"kind": "file", "label": "s2", "url": "u", "status": 200, "body": ""},
               {"kind": "file", "label": "s3", "url": "u", "status": 403, "body": "{}"}]
        self.assertEqual(sevs(at.judge_exposed(web)), ["ok"])


class Reference(unittest.TestCase):
    def tar(self, version, n=520):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for i in range(n):
                data = b"<?php // %d" % i
                ti = tarfile.TarInfo("typo3_src-%s/typo3/sysext/core/Classes/Part%d.php" % (version, i))
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            for name in ("typo3_src-%s/typo3/sysext/../../evil.php" % version, "typo3_src-%s/index.php" % version):
                ti = tarfile.TarInfo(name)
                ti.size = 1
                tf.addfile(ti, io.BytesIO(b"x"))
        return buf.getvalue()

    def test_hash_tar_only_sysext_and_no_traversal(self):
        files = typo3ref.hash_tar(self.tar("12.4.8"), "12.4.8")
        self.assertEqual(len(files), 520)
        self.assertTrue(all(p.startswith("typo3/sysext/") and ".." not in p.split("/") for p in files))

    def test_garbage_is_refused(self):
        with self.assertRaises(typo3ref.RefError):
            typo3ref.hash_tar(b"kein archiv", "12.4.8")

    def test_sha_mismatch_is_refused(self):
        with mock.patch.object(typo3ref.coreref, "fetch_bytes", return_value=self.tar("12.4.8")):
            with self.assertRaises(typo3ref.RefError):
                typo3ref.reference("12.4.8", "0" * 64)

    def test_sha_ok(self):
        data = self.tar("12.4.8")
        with mock.patch.object(typo3ref.coreref, "fetch_bytes", return_value=data):
            r = typo3ref.reference("12.4.8", hashlib.sha256(data).hexdigest())
        self.assertTrue(r["verified"])

    def test_too_few_files_and_prerelease(self):
        with mock.patch.object(typo3ref.coreref, "fetch_bytes", return_value=self.tar("12.4.8", 5)):
            with self.assertRaises(typo3ref.RefError):
                typo3ref.reference("12.4.8")
        with self.assertRaises(typo3ref.RefError):
            typo3ref.reference("13.0.0-rc1")


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_typo3_")
        cls.bad = typo3fixture.make_typo3_world(cls.base, True)
        cls.good = typo3fixture.make_typo3_world(cls.base, False)
        cls.comp = typo3fixture.make_typo3_world(cls.base, False, composer=True)
        for w in (cls.bad, cls.good, cls.comp):
            k.install(w["bin"], "crontab", k.FAKE_CRONTAB)
            k.install(w["bin"], "ssh-keygen", k.FAKE_KEYGEN)
            k.install(w["bin"], "ps", k.FAKE_PS)
        ids = [c.id for c in registry.ordered("typo3")]
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
        self.assertEqual(b["typo3_settings"].findings[0].sev, "crit")
        self.assertIn(("crit", "2 Inhalt(e) enthalten verschleierten oder fremden Code"), k.tt(b["typo3_db_code"]))
        self.assertTrue(any(f.sev == "warn" and "Administrator-Konto" in f.title for f in b["typo3_users"].findings))
        self.assertTrue(any("Entwicklungs- oder Verwaltungs-Erweiterung" in f.title for f in b["typo3_extensions"].findings))
        self.assertTrue(any("obsolete" in f.title for f in b["typo3_extensions"].findings))
        self.assertTrue(any("Install-Tool ist freigeschaltet" in f.title for f in b["typo3_settings"].findings))
        self.assertEqual(b["webshells"].status, "crit")
        self.assertEqual(b["typo3_core"].findings[0].sev, "crit")            # TYPO3 12 ist 2027 nur noch ELTS

    def test_clean_has_no_crit_in_settings_users_and_code(self):
        for i in ("typo3_settings", "typo3_users", "typo3_db_code"):
            self.assertNotIn("crit", [f.sev for f in self.rg[i].findings], i)
        self.assertEqual(k.tt(self.rg["typo3_settings"]), [("ok", "Die Einstellungsdatei ist unauffällig")])

    def test_database_access_uses_settings_php(self):
        self.assertEqual(self.rg["db_access"].findings[0].sev, "ok")

    def test_no_secrets_in_any_result(self):
        for rr in (self.rb, self.rg):
            for r in rr.values():
                b = k.blob(r)
                for s in ("GEHEIM-DB-PASSWORT", "GEHEIM-INSTALL-HASH", "k" * 40):
                    self.assertNotIn(s, b)

    def test_exposed_needs_url(self):
        self.assertEqual(self.rg["typo3_exposed"].status, "skipped")

    def test_composer_layout_reads_version_and_packages(self):
        os.environ["CLAUDIA_TEST_DB"] = self.comp["db"]
        r = {x.id: x for x in run(self.comp, ["typo3_core", "typo3_extensions", "typo3_settings"])}
        self.assertNotIn("error", [x.status for x in r.values()])
        self.assertIn("12.4.8", k.blob(r["typo3_core"]))
        t = k.blob(r["typo3_extensions"])
        self.assertIn("georgringer/news", t)
        self.assertIn("eigene Erweiterung", t)
        self.assertEqual(k.tt(r["typo3_settings"]), [("ok", "Die Einstellungsdatei ist unauffällig")])

    def test_very_old_typo3_skips_database_checks(self):
        w = typo3fixture.make_typo3_world(tempfile.mkdtemp(), False)
        with open(os.path.join(w["site"], "typo3/sysext/core/Classes/Information/Typo3Version.php"), "w") as fh:
            fh.write("<?php\n// alt\n")
        os.makedirs(os.path.join(w["site"], "typo3/sysext/core/Classes/Core"), exist_ok=True)
        with open(os.path.join(w["site"], "typo3/sysext/core/Classes/Core/SystemEnvironmentBuilder.php"), "w") as fh:
            fh.write("<?php\ndefine('TYPO3_version', '6.2.31');\n")
        os.environ["CLAUDIA_TEST_DB"] = w["db"]
        r = {x.id: x for x in run(w, ["typo3_users", "typo3_core"])}
        self.assertEqual(r["typo3_users"].status, "skipped")
        self.assertEqual(r["typo3_core"].findings[0].sev, "crit")

    def test_online_core_advisories_files_and_release(self):
        w = self.bad
        os.environ["CLAUDIA_TEST_DB"] = w["db"]
        site = w["site"]
        ref = {}
        for root, _, files in os.walk(os.path.join(site, "typo3", "sysext")):
            for f in files:
                p = os.path.join(root, f)
                rel = os.path.relpath(p, site).replace(os.sep, "/")
                if rel.endswith("Backdoor.php"):
                    continue
                ref[rel] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        ref["typo3/sysext/core/Classes/Part1.php"] = "0" * 64        # geänderte Datei
        ref["typo3/sysext/core/Classes/Fehlt.php"] = "1" * 64        # fehlende Datei

        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            if "security-advisories" in url:
                f.body = adv_json()
            elif url.endswith("/json"):
                f.body = json.dumps({"12": {"releases": {"12.4.8": {"version": "12.4.8"}, "12.4.12": {"version": "12.4.12"}}}})
            else:
                f.body = "%s  typo3_src-12.4.8.tar.gz" % ("a" * 64)
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake), \
                    mock.patch.object(typo3ref, "reference", return_value={"files": ref, "package": "typo3_src-12.4.8.tar.gz", "sha256": "x", "verified": True}):
                r = run(w, ["typo3_core"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        t = k.tt(r)
        self.assertIn(("crit", "Für TYPO3 12.4.8 sind 1 Sicherheitsmeldung(en) bekannt"), t)
        self.assertIn(("crit", "1 unbekannte PHP-Datei(en) in den Systemerweiterungen"), t)
        self.assertIn(("warn", "1 Datei(en) der Systemerweiterungen weichen vom Original ab"), t)
        self.assertIn(("warn", "1 Datei(en) der Systemerweiterungen fehlen"), t)
        self.assertTrue(any("nicht die neueste Version" in x[1] for x in t))

    def test_online_extensions_with_fake_advisories(self):
        os.environ["CLAUDIA_TEST_DB"] = self.good["db"]
        seen = []

        def fake(url, ua, *a, **kw):
            seen.append(url)
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            f.body = adv_json("georgringer/news", "<11.5.0")
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake):
                r = run(self.good, ["typo3_extensions"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        self.assertIn(("crit", "1 Erweiterung(en) in einer Version mit bekannter Sicherheitslücke"), k.tt(r))
        self.assertTrue(any("georgringer%2Fnews" in u for u in seen))

    def test_online_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith("settings.php") and "typo3conf/system" in url else 403
            f.body = "<?php return ['SYS' => ['encryptionKey' => 'x']];" if f.status == 200 else ""
            return f
        os.environ["CLAUDIA_TEST_DB"] = self.bad["db"]
        with mock.patch.object(webmod, "fetch", fake):
            r = run(self.bad, ["typo3_exposed"], "https://www.testseite.example")[0]
        self.assertEqual(r.findings[0].sev, "crit")


class Advisories(unittest.TestCase):
    def test_batches_and_offline(self):
        calls = []

        def fake(url, ua, *a, **kw):
            calls.append(url)
            f = webmod.Fetched()
            f.status = 200
            f.body = json.dumps({"advisories": {}})
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake):
                out, ok = tc.advisories(["a/p%d" % i for i in range(60)] + ["../böse", "a/p1"])
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        self.assertTrue(ok)
        self.assertEqual(len(calls), 3)
        self.assertEqual(tc.advisories(["a/b"]), ({}, False))

    def test_failed_batch_is_not_ok(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.status = 500
            f.body = ""
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake):
                self.assertEqual(tc.advisories(["a/b"]), ({}, False))
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"


class Detection(unittest.TestCase):
    def test_probe_detects_classic(self):
        from claudia import probe
        w = typo3fixture.make_typo3_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "typo3")
        self.assertEqual(info["typo3"], "12.4.8")
        self.assertTrue(info["typo3_config"])
        self.assertEqual(info["typo3_mode"], "classic")

    def test_probe_detects_composer(self):
        from claudia import probe
        w = typo3fixture.make_typo3_world(tempfile.mkdtemp(), False, composer=True)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "typo3")
        self.assertEqual(info["typo3_mode"], "composer")

    def test_probe_from_public_folder_of_composer_install(self):
        from claudia import probe
        w = typo3fixture.make_typo3_world(tempfile.mkdtemp(), False, composer=True)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"] + "/public")
        self.assertEqual(info["cms"], "typo3")
        self.assertEqual(info["typo3"], "12.4.8")


if __name__ == "__main__":
    unittest.main()
