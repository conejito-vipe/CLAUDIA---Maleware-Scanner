"""Regressionstests: Fehlalarme aus dem echten Lauf (Oktober 2026) dürfen nicht wiederkehren,
echte Funde müssen weiterhin gemeldet werden."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_checks import ADV, has, run_all, titles  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402


def items(res, text):
    return [i for f in res.findings if text.lower() in f.title.lower() for i in f.items]


class CleanFalsePositives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.w = run_all(False)

    def test_binary_images_are_not_php(self):
        r = self.r["php_in_uploads"]
        self.assertFalse(has(r, "harmloser Endung"), titles(r))
        self.assertEqual(titles(r, "crit") + titles(r, "warn"), [])

    def test_empty_index_php_and_cache_data(self):
        r = self.r["php_in_uploads"]
        self.assertTrue(has(r, "Platzhalter", "info"))
        self.assertTrue(has(r, "Cache ohne die()", "info"))      # unbekannter Aufbau, aber keine Befehle: nur Hinweis
        self.assertEqual(titles(r, "warn") + titles(r, "crit"), [])

    def test_common_names(self):
        r = self.r["suspicious_names"]
        self.assertEqual(titles(r, "warn") + titles(r, "crit"), [])
        self.assertTrue(has(r, "üblich", "info"))

    def test_installer_sql_and_nested_protection(self):
        r = self.r["backups_in_webroot"]
        self.assertEqual(titles(r, "crit") + titles(r, "warn"), [])
        self.assertFalse(has(r, "SQL-Skript"), titles(r))        # bekannte Installationsskripte werden nicht angezeigt
        self.assertFalse(has(r, "SQL-Datei"), titles(r))
        self.assertTrue(any("core-6.1.3.zip" in i for i in items(r, "geschützten Ordnern")))

    def test_htaccess_protective_rules(self):
        r = self.r["htaccess"]
        self.assertEqual(titles(r, "crit") + titles(r, "warn"), [])
        self.assertTrue(has(r, "harmlose", "info"))

    def test_update_wave_and_data_files(self):
        r = self.r["webshells"]
        self.assertEqual(titles(r, "warn") + titles(r, "crit"), [])
        self.assertTrue(has(r, "vermutlich Update", "info"))
        self.assertTrue(has(r, "Datentabellen", "info"))
        self.assertTrue(has(r, "Beschreibungsdatei geändert", "info"))
        self.assertTrue(any("plugins/system/updated" in i for i in items(r, "Beschreibungsdatei")))

    def test_jquery_wrapper_and_plugin(self):
        r = self.r["js_scan"]
        self.assertEqual(titles(r, "crit") + titles(r, "warn"), [])

    def test_sub_extensions_not_compared(self):
        r = self.r["extensions_fs"]
        self.assertEqual(titles(r, "crit"), [])
        self.assertTrue(has(r, "nicht einzeln verglichen", "info"))

    def test_web_ld_json_and_noconflict(self):
        r = self.r["web_source"]
        self.assertFalse(has(r, "unbekannte Fremd-Server", "warn"), titles(r))
        self.assertFalse(has(r, "Schadcode-Merkmale", "crit"), titles(r))
        self.assertTrue(has(r, "erwähnt", "info"))        # linkedin steht nur im JSON-LD/Text, wird nicht geladen
        self.assertTrue(has(r, "nicht abrufbar", "ok"))     # automatischer Backup-Test: Backup-Safe liefert 403


class InfectedStillDetected(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.w = run_all(True)

    def test_real_findings_remain(self):
        self.assertTrue(has(self.r["php_in_uploads"], "harmloser Endung", "crit"))
        self.assertTrue(has(self.r["php_in_uploads"], "in images/files/tmp", "crit"))
        self.assertTrue(has(self.r["htaccess"], "gefährliche", "crit"))
        self.assertTrue(has(self.r["suspicious_names"], "Hintertür-Namen", "crit"))
        self.assertTrue(has(self.r["backups_in_webroot"], "ohne Zugriffssperre", "crit"))

    def test_only_component_is_reported(self):
        ext = items(self.r["extensions_fs"], "Sicherheitslücke")
        self.assertFalse(any("mod_convertforms" in i or "plugins/system/convertforms" in i for i in ext), ext)
        self.assertTrue(any("com_convertforms" in i for i in ext), ext)

    def test_cache_findings_show_snippet(self):
        r = self.r["php_in_uploads"]
        self.assertTrue(any("$_POST" in i and "cache/x1.php" in i for i in items(r, "Hintertür-Merkmalen")), items(r, "Hintertür"))
        self.assertEqual([t for t in titles(r, "warn") if "Sprach-Cache" in t].__len__(), 1)
        self.assertTrue(any("base64_decode" in i for i in items(r, "Sprach-Cache")))

    def test_public_backup_detected(self):
        self.assertTrue(has(self.r["web_source"], "öffentlich herunterladbar", "crit"))


class BlockedAttacksAreWarnings(unittest.TestCase):
    def _run(self, codes):
        load_all()
        d = tempfile.mkdtemp(prefix="claudia_log_")
        lines = ['203.0.113.7 - - [25/Oct/2026:08:17:%02d +0200] "POST /index.php?option=com_jce&task=profiles.import HTTP/1.1" %d 9 "-" "curl"' % (i, c)
                 for i, c in enumerate(codes)]
        open(os.path.join(d, "access.log"), "w").write("\n".join(lines) + "\n")
        eng = Engine(None, Settings(opts={"local_logs": {"path": d}}), ADV)
        return eng.run(["local_logs"], lambda e: None, threading.Event())[0]

    def test_all_blocked(self):
        r = self._run([403, 403, 404, 301])
        self.assertEqual(titles(r, "crit"), [])
        self.assertTrue(has(r, "keiner erfolgreich", "ok"))
        self.assertEqual(titles(r, "warn"), [])

    def test_one_success(self):
        r = self._run([403, 200, 404])
        self.assertTrue(has(r, "JCE", "crit"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class InstallerSql(unittest.TestCase):
    def test_reasons(self):
        from claudia.checks.files import sql_reason
        self.assertEqual(sql_reason("CREATE TABLE `#__x` (id INT);"), "")
        self.assertIn("Benutzer", sql_reason("INSERT INTO `#__users` (name) VALUES ('x');"))
        self.assertIn("PHP", sql_reason("INSERT INTO t VALUES ('<?php eval($_POST[1]); ?>');"))
        self.assertIn("Dateien", sql_reason("SELECT 1 INTO OUTFILE '/tmp/x'"))

    def test_suspicious_script_is_reported_with_reason(self):
        r, _ = run_all(True)
        r = r["backups_in_webroot"]
        self.assertTrue(has(r, "SQL-Skript", "warn"), titles(r))
        self.assertTrue(any("Benutzer" in i and "plugins/system/demo/sql" in i for i in items(r, "SQL-Skript")))


# ---- 2.4.0 / D4: Fehlalarme durch Sicherheits-/Backup-Tools: bekannt nur mit Pfad UND Inhalt
class KnownToolsPathAndContent(unittest.TestCase):
    SHELL = "<?php\n// %s\neval(base64_decode($_POST['x']));\n"

    @staticmethod
    def webshells(files):
        import fixture
        from claudia.runner import LocalRunner
        load_all()
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_d4_"), False)
        for rel, data in files.items():
            p = os.path.join(w["site"], rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(data)
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={}, allow_hosts=[]), ADV)
        return {r.id: r for r in eng.run(["webshells"], lambda e: None, threading.Event())}["webshells"]

    def test_tool_file_in_own_folder_with_own_marker_is_info(self):
        r = self.webshells({"wp-content/plugins/wordfence/lib/wfScanEngine.php": self.SHELL % "Wordfence malware signatures"})
        self.assertTrue(has(r, "Muster in Sicherheits-/Backup-Erweiterungen", "info"), titles(r))
        self.assertFalse(any("wfScanEngine.php" in i for f in r.findings if f.sev == "crit" for i in f.items), titles(r))
        self.assertTrue(any("[Wordfence]" in i for f in r.findings for i in f.items))

    def test_name_alone_does_not_hide_a_shell(self):
        # Dateiname/Ordner nennt ein Tool, liegt aber im Bilder-Ordner: keine Ausnahme
        r = self.webshells({"images/akeeba.php": self.SHELL % "Akeeba", "images/wordfence/x.php": self.SHELL % "Wordfence"})
        crit = " ".join(i for f in r.findings if f.sev == "crit" for i in f.items)
        self.assertIn("images/akeeba.php", crit)
        self.assertIn("images/wordfence/x.php", crit)

    def test_own_folder_without_marker_is_reported(self):
        # liegt im Ordner der Erweiterung, enthält aber keine Kennung des Tools: kein Freifahrtschein
        r = self.webshells({"wp-content/plugins/wordfence/lib/dropped.php": self.SHELL % "something else"})
        crit = " ".join(i for f in r.findings if f.sev == "crit" for i in f.items)
        self.assertIn("wordfence/lib/dropped.php", crit)

    def test_list_has_date_and_every_tool_needs_path_and_content(self):
        from claudia.checks.files import load_known_tools
        d = load_known_tools()
        self.assertRegex(d["stand"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertTrue(d["tools"])
        for t in d["tools"]:
            self.assertTrue(t["path"].startswith("^\\./"), t["id"])      # am Anfang verankert, kein Stichwort irgendwo im Pfad
            self.assertTrue(t["content"], t["id"])
