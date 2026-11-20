"""Kritische PHP-Einstellungen, Integrität der configuration.php, Google-Safe-Browsing-Abgleich (Schlüssel wird nie gespeichert)."""
import datetime
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia import report, server  # noqa: E402
from claudia.checks import blacklist, php_config  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()
TODAY = datetime.date(2026, 11, 3)


def fake_php(values, version="8.3.6", ini=""):
    d = tempfile.mkdtemp(prefix="claudia_php_")
    lines = "\n".join("%s\t%s" % kv for kv in values.items()) + "\nVER\t%s\n" % version
    p = os.path.join(d, "php")
    with open(p, "w") as fh:
        fh.write('#!/bin/bash\ncase "$1" in\n  -v) echo "PHP ' + version + ' (cli)";;\n  -l) if grep -q SYNTAXERR "$2"; then echo "PHP Parse error: syntax error, unexpected token in $2 on line 9"; else echo "No syntax errors detected in $2"; fi;;\n'
                 '  -r) case "$2" in *php_ini_loaded_file*) printf "%%s\\n" "' + ini + '";; *) cat <<\'EOF\'\n' + lines + '\nEOF\n;; esac;;\nesac\n')
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return d


def run(w, ids, php_dir=None, opts=None, url="", cms="joomla"):
    extra = os.pathsep.join(x for x in (php_dir, w["bin"]) if x)
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url=url, allow_hosts=ADV["allow_hosts"], opts=opts or {})
    eng = Engine(LocalRunner(w["home"], extra_path=extra), s, ADV)
    return {r.id: r for r in eng.run(ids, lambda e: None, threading.Event())}


def tl(r):
    return [(f.sev, f.title) for f in r.findings]


class Evaluate(unittest.TestCase):
    def ev(self, s, **kw):
        return php_config.evaluate(s, kw.get("display", []), kw.get("ver", ""), ADV["php_eol"], TODAY)

    def test_bad_settings(self):
        rows = self.ev({"allow_url_include": "1", "allow_url_fopen": "1", "expose_php": "1", "enable_dl": "1", "disable_functions": "exec,system",
                        "auto_prepend_file": "/home/x/html/.cache/a.php", "session.use_only_cookies": "0", "VER": "7.4.33"},
                       display=['/etc/php.ini:display_errors = On'])
        t = {title: sev for sev, title, *_ in rows}
        self.assertEqual(t["allow_url_include ist eingeschaltet"], "crit")
        self.assertEqual(t["auto_prepend_file lädt automatisch eine Datei"], "crit")
        self.assertEqual(t["enable_dl ist eingeschaltet"], "warn")
        self.assertEqual(t["display_errors ist in der PHP-Einstellung eingeschaltet"], "warn")
        self.assertEqual(t["5 von 7 gefährlichen Funktionen sind nicht gesperrt"], "info")
        self.assertEqual(t["PHP 7.4 wird nicht mehr mit Sicherheitsupdates versorgt"], "crit")      # mehr als 2 Jahre über Support-Ende

    def test_firewall_prepend_is_only_info_and_good_config_is_ok(self):
        rows = self.ev({"auto_prepend_file": "/var/www/wordfence-waf.php", "disable_functions": ",".join(php_config.DANGEROUS_FUNCS), "open_basedir": "/home", "VER": "8.3.6"})
        by = {t: s for s, t, *_ in rows}
        self.assertEqual(by["auto_prepend_file lädt automatisch eine Datei"], "info")
        self.assertEqual(by["Gefährliche Funktionen sind gesperrt"], "ok")
        self.assertEqual(by["PHP 8.3 wird noch mit Sicherheitsupdates versorgt"], "ok")
        self.assertFalse(any(s in ("warn", "crit") for s, *_ in rows))

    def test_eol_soon_and_recent(self):
        r = self.ev({"VER": "8.2.20"}, ver="8.2.20")
        self.assertEqual(r[-1][0], "info")                    # Support-Ende 2026-12-31, in weniger als 120 Tagen
        r = self.ev({"VER": "8.1.1"}, ver="8.1.1")
        self.assertEqual(r[-1][0], "warn")                    # seit Ende 2025 abgelaufen, unter 2 Jahren


class PhpCheck(unittest.TestCase):
    def test_check_reads_values_with_fake_php(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_pc_"), False)
        d = fake_php({"allow_url_include": "1", "disable_functions": "", "auto_prepend_file": ""}, "7.4.33")
        r = run(w, ["php_settings"], d)["php_settings"]
        self.assertEqual(r.status, "crit", tl(r) + [r.message])
        self.assertTrue(any("allow_url_include" in t for _, t in tl(r)))

    def test_works_with_the_real_php_if_installed(self):
        import shutil
        if not shutil.which("php"):
            self.skipTest("kein PHP in dieser Umgebung")
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_pc_"), False)
        r = run(w, ["php_settings"])["php_settings"]
        self.assertNotIn(r.status, ("error", "skipped"), tl(r) + [r.message])
        self.assertTrue(any(t == "Quelle der Einstellungen" for _, t in tl(r)))


class ConfigIntegrity(unittest.TestCase):
    def cfg_path(self, w):
        return os.path.join(w["site"], "configuration.php")

    def test_clean_config_is_ok(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_ci_"), False)
        r = run(w, ["config_integrity"], fake_php({}))["config_integrity"]
        self.assertNotIn(r.status, ("crit", "warn", "error"), tl(r) + [r.message])
        self.assertTrue(any("Syntaxprüfung" in t and s == "ok" for s, t in tl(r)))

    def test_appended_code_in_value_line_is_found(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_ci_"), False)
        with open(self.cfg_path(w)) as fh:
            txt = fh.read()
        txt = txt.replace("public $sitename = 'Testseite';", "public $sitename = 'Testseite'; @eval(base64_decode($_POST['x']));")
        os.chmod(self.cfg_path(w), 0o644)  # Fixture: 444, als Nicht-root nicht beschreibbar
        with open(self.cfg_path(w), "w") as fh:
            fh.write(txt)
        r = run(w, ["config_integrity"], fake_php({}))["config_integrity"]
        self.assertEqual(r.status, "crit", tl(r))
        self.assertTrue(any("enthalten Code" in t for _, t in tl(r)))
        raw = " ".join(r.raw.values())
        self.assertNotIn("GEHEIM-DB-PASSWORT", raw)

    def test_syntax_error_copies_and_perms(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_ci_"), False)
        os.chmod(self.cfg_path(w), 0o644)  # Fixture: 444, als Nicht-root nicht beschreibbar
        with open(self.cfg_path(w), "a") as fh:
            fh.write("\n// SYNTAXERR\n")
        os.chmod(self.cfg_path(w), 0o666)
        with open(os.path.join(w["site"], "configuration.php.bak"), "w") as fh:
            fh.write("<?php class JConfig { public $password = 'x'; }")
        with open(os.path.join(w["site"], "configuration.old-notes"), "w") as fh:
            fh.write("nichts")
        r = run(w, ["config_integrity"], fake_php({}))["config_integrity"]
        t = tl(r)
        self.assertIn(("crit", "Die configuration.php hat einen Syntaxfehler (Zeile 9)"), t)
        self.assertTrue(any(s == "crit" and "beschreibbar" in x for s, x in t), t)
        self.assertTrue(any(s == "crit" and "Kopie(n) der configuration.php" in x for s, x in t), t)

    def test_selector_program_is_not_a_syntax_error(self):
        wrapper = "Multiple PHP versions found:\n\t1)\tphp-5.3\n\t2)\tphp-5.4"
        sev, title, detail, items, _ = php_config.lint_row(wrapper, "<?php\n")
        self.assertEqual(sev, "info")
        self.assertIn("Auswahlprogramm", detail)
        rows = php_config.evaluate_config("", {}, "644 u 1 1000", "u", 10**9, wrapper, "x.de")
        self.assertFalse(any(s == "crit" for s, *_ in rows))

    def test_syntax_error_is_explained(self):
        text = "<?php\nclass JConfig {\n  public $sitename = 'Test;\n}\n"
        sev, title, detail, items, _ = php_config.lint_row("PHP Parse error:  syntax error, unexpected end of file in configuration.php on line 4", text)
        self.assertEqual(sev, "crit")
        self.assertIn("Zeile 4", title)
        self.assertIn("endet zu früh", detail)
        self.assertTrue(any(i.startswith("Zeile 4:") for i in items))
        self.assertTrue(any("gültige Zeile" in i for i in items))

    def test_live_site_foreign(self):
        rows = php_config.evaluate_config("", {"live_site": "https://evil.example"}, "644 u 1 1000", "u", 10**9, "No syntax errors detected", "meine-seite.de")
        self.assertTrue(any(s == "warn" and "live_site" in t for s, t, *_ in rows))
        rows = php_config.evaluate_config("", {"live_site": "https://www.meine-seite.de"}, "644 u 1 1000", "u", 10**9, "No syntax errors detected", "meine-seite.de")
        self.assertFalse(any(s == "warn" for s, *_ in rows))

    def test_literal_detection(self):
        ok = "public $a = 'x;y';\npublic $b = 12;\npublic $c = true;\npublic $d = array('a' => 1, 'b');\npublic $e = [];\npublic $f = \"x\";\npublic ?string $g = null;\n"
        self.assertEqual(php_config.literal_problems(ok), [])
        bad = php_config.literal_problems("public $a = 'x'; system($_GET['c']);\npublic $b = $_GET['x'];\npublic $c = \"a$b\";\n")
        self.assertEqual([b[1] for b in bad], ["a", "b", "c"])


class SafeBrowsing(unittest.TestCase):
    KEY = "AIzaSy-GEHEIMER-SCHLUESSEL-123"

    def go(self, post, key=KEY, url="https://meine-seite.de/"):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_sb_"), False)
        opts = {"safe_browsing": {"api_key": key}} if key else {}
        with mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": ""}), mock.patch.object(blacklist, "post_json", post):
            return run(w, ["safe_browsing"], opts=opts, url=url)["safe_browsing"]

    def test_no_key_means_no_request(self):
        called = []
        r = self.go(lambda *a, **k: called.append(1) or (200, "{}"), key="")
        self.assertEqual(called, [])
        self.assertEqual(r.status, "info")
        self.assertTrue(any("transparencyreport.google.com" in i for f in r.findings for i in f.items))

    def test_hit_is_critical_and_clean_is_ok(self):
        sent = {}

        def hit(url, payload, key, timeout=20.0):
            sent.update(url=url, payload=payload, key=key)
            return 200, json.dumps({"matches": [{"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threat": {"url": "https://meine-seite.de/"}}]})
        r = self.go(hit)
        self.assertEqual(r.status, "crit")
        self.assertNotIn(self.KEY, sent["url"])                                       # Schlüssel nie in der Adresse
        self.assertEqual({e["url"] for e in sent["payload"]["threatInfo"]["threatEntries"]} >= {"https://meine-seite.de/", "https://www.meine-seite.de/"}, True)
        r = self.go(lambda *a, **k: (200, "{}"))
        self.assertEqual(r.status, "ok")

    def test_rejected_key_and_network_error_do_not_leak_key(self):
        r = self.go(lambda *a, **k: (403, '{"error": {"message": "API key %s not valid"}}' % self.KEY))
        self.assertEqual(r.status, "info")
        self.assertNotIn(self.KEY, json.dumps([f.to_dict() for f in r.findings]))
        r = self.go(lambda *a, **k: (0, "Verbindung %s abgelehnt" % self.KEY))
        self.assertEqual(r.status, "skipped")
        self.assertNotIn(self.KEY, r.message)

    def test_key_never_in_public_settings_or_bundle(self):
        opts = {"safe_browsing": {"api_key": self.KEY}, "web_source": {"must_block": "/x"}}
        public, secrets_ = server.split_secret_opts(opts)
        self.assertEqual(public, {"safe_browsing": {}, "web_source": {"must_block": "/x"}})
        self.assertEqual(secrets_, [self.KEY])
        res = [{"id": "x", "title": "t", "group": "g", "status": "info", "findings": [{"sev": "info", "title": "Fehler mit " + self.KEY, "detail": "", "items": [], "hint": ""}], "raw": {}, "seconds": 0.1, "message": ""}]
        b = report.build_bundle(res, ["x"], {"site_dir": "x", "url": "", "mask_ips": True, "allow_hosts": [], "opts": public}, {}, 1.0, False, "2026-10-25", [self.KEY])
        self.assertNotIn(self.KEY, json.dumps(b))

    def test_candidates_and_post_only_https(self):
        self.assertIn("https://www.meine-seite.de/", blacklist.candidate_urls("meine-seite.de"))
        self.assertEqual(blacklist.post_json("http://example.org/x", {}, "k")[0], 0)


if __name__ == "__main__":
    unittest.main()
