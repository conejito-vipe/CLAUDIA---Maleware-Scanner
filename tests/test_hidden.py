"""Erweiterte Malware-Muster, versteckte Dateien/Strukturen, vertiefte .htaccess-Untersuchung."""
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia.checks import hidden  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

import json  # noqa: E402
ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))
load_all()


def run(w, cid, cms="joomla"):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url="", allow_hosts=ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    return eng.run([cid], lambda e: None, threading.Event())[0]


def put(w, rel, text, mode=0o644, age_days=100):
    return fixture.w(os.path.join(w["site"], rel), text, days_ago=age_days, mode=mode)


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class Signatures(unittest.TestCase):
    CASES = {
        "cb_request": "array_map($_POST['f'], array($_POST['x']));",
        "cb_danger": "array_filter(array('ls'), 'x'); call_user_func('assert', $a);",
        "dyn_call": "$_POST['f']($_POST['x']);",
        "eval_var": "eval($a($b));",
        "concat_name": "$f = 'ba' . 'se64_decode';",
        "input_wrap": "eval(file_get_contents('php://input'));",
        "wrapper_inc": "include('data://text/plain;base64,xx');",
        "mailer": "mail($_POST['to'], 'x', 'y');",
        "dropper": "file_put_contents('a.php', $_POST['c']);",
        "shell_head": "@set_time_limit(0); error_reporting(0);",
        "chr_chain": "chr(101).chr(118).chr(97).chr(108).chr(40).chr(36)",
        "globals_call": "$GLOBALS['x']($y);",
        "hex_escapes": '"\\x65\\x76\\x61\\x6c\\x28\\x24\\x5f\\x50"',
        "create_func": "create_function('$a', 'return 1;');",
    }

    def test_every_php_signature_matches_its_sample_and_regex_is_valid_for_grep(self):
        import shutil
        import subprocess
        d = tempfile.mkdtemp()
        for sid, sample in self.CASES.items():
            got = hidden.classify("./x.php:1:" + sample, hidden.PHP_SIGS)
            self.assertTrue(got and got[0][0] == sid or got and sid in [s[0] for s in hidden.PHP_SIGS], (sid, got))
            p = os.path.join(d, sid + ".php")
            with open(p, "w") as fh:
                fh.write("<?php\n" + sample + "\n")
        if shutil.which("grep"):
            rx = "|".join("(%s)" % s[3] for s in hidden.PHP_SIGS)
            out = subprocess.run(["grep", "-lIE", "-e", rx] + [os.path.join(d, n) for n in os.listdir(d)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            matched = {os.path.basename(x)[:-4] for x in out.stdout.split()}
            self.assertEqual(matched, set(self.CASES), matched ^ set(self.CASES))

    def test_harmless_code_does_not_match(self):
        for ok in ("array_map('strtoupper', $list);", "$x = $_POST['a'];", "usort($rows, function($a, $b) { return 0; });", "call_user_func(array($this, 'run'));",
                   "mail($to, $subject, $msg);", "file_put_contents($path, $data);", "$s = chr(65) . 'B';"):
            self.assertEqual(hidden.classify("./a.php:1:" + ok, hidden.PHP_SIGS), [], ok)


class MalwareCheck(unittest.TestCase):
    def test_finds_patterns_and_clean_site_is_ok(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_h_"), False)
        r = run(w, "malware_patterns")
        self.assertEqual(r.status, "ok", titles(r))
        put(w, "components/com_x/a.php", "<?php\narray_map($_POST['f'], array($_POST['x']));\n")
        put(w, "media/mining.js", "var m = new CoinHive.Anonymous('KEY');\n")
        put(w, "libraries/vendor/old/lib.php", "<?php\n$f = create_function('$a', 'return 1;');\n")
        r = run(w, "malware_patterns")
        t = titles(r)
        self.assertEqual(r.status, "crit", t)
        self.assertTrue(any(s == "crit" and "Rückruf" in x for s, x in t), t)
        self.assertTrue(any(s == "crit" and "Miner" in x for s, x in t), t)
        self.assertTrue(any(s == "info" and "create_function" in x for s, x in t), t)               # in Bibliothek nur Hinweis


class MalwareEvidence(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_h_"), False)

    def test_binary_hex_is_not_a_finding_but_decoded_command_is(self):
        put(self.w, "libraries/vendor/web-auth/cose-lib/src/Hash.php", "<?php\n$a = \"\\x30\\x21\\x30\\x09\\x06\\x05\\x2b\\x0e\\x03\\x02\\x1a\\x05\\x00\\x04\\x14\";\n")
        r = run(self.w, "malware_patterns")
        self.assertEqual(r.status, "ok", titles(r))                       # seit 2.4.1: Fundstellen ohne Befehl sind in Ordnung (grün)
        self.assertTrue(any(sv == "ok" and "keine enthält einen Befehl" in x for sv, x in titles(r)), titles(r))
        put(self.w, "components/com_x/b.php", "<?php\n$a = \"\\x65\\x76\\x61\\x6c\\x28\\x24\\x5f\\x50\\x4f\\x53\\x54\";\n")
        r = run(self.w, "malware_patterns")
        f = [f for f in r.findings if f.sev == "crit" and "Hex" in f.title]
        self.assertTrue(f, titles(r))
        ev = f[0].evidence[0]
        self.assertEqual((ev["file"], ev["line"]), ("./components/com_x/b.php", 2))
        hit = [c for c in ev["code"] if c["hit"]][0]
        self.assertIn("\\x65\\x76", hit["t"][hit["hit"][0]:hit["hit"][1]])
        self.assertEqual([c["n"] for c in ev["code"]], [1, 2, 3][:len(ev["code"])] if len(ev["code"]) < 3 else [1, 2])

    def test_name_list_in_security_extension_is_info_but_call_is_critical(self):
        put(self.w, "administrator/components/com_htprotect/core/defs.php", "<?php\n$sig = array(\n    'ev' . 'al',\n    'ass' . 'ert',\n);\n")
        r = run(self.w, "malware_patterns")
        t = titles(r)
        self.assertEqual(r.status, "info", t)
        f = [f for f in r.findings if "Liste zerlegter" in f.title][0]
        self.assertIn("HTProtect", f.detail)
        self.assertTrue(f.evidence and any(c["hit"] for c in f.evidence[0]["code"]))
        put(self.w, "components/com_evil/x.php", "<?php\n$f = 'ev' . 'al'; $f($_POST['c']);\n")
        put(self.w, "components/com_other/list.php", "<?php\n$a = array(\n 'ass' . 'ert',\n);\n")
        r = run(self.w, "malware_patterns")
        t = titles(r)
        self.assertEqual(r.status, "crit", t)
        self.assertTrue(any(s == "crit" and "Teilstücken" in x for s, x in t), t)
        self.assertTrue(any(s == "warn" and "Liste zerlegter" in x for s, x in t), t)             # Liste außerhalb bekannter Werkzeuge: prüfen

    def test_vendor_tests_are_skipped(self):
        put(self.w, "libraries/vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/PHP/DeprecatedFunctionsUnitTest.inc", "create_function(\n")
        r = run(self.w, "malware_patterns")
        self.assertEqual(r.status, "ok", titles(r))

    def test_hit_with_unreadable_context_still_has_code(self):
        from claudia import evidence
        ev = evidence.build("./a.php", 7, [], hit="eval(x)")
        self.assertEqual(ev["code"][0]["hit"], [0, 7])


class Structure(unittest.TestCase):
    def test_clean_world_and_findings(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_h_"), False)
        r = run(w, "hidden_structure")
        self.assertNotIn(r.status, ("crit", "error"), titles(r) + [r.message])
        put(w, ".cachex/payload.php", "<?php // x\n")
        put(w, "plugins/odd /x.php", "<?php // x\n")
        os.symlink("/etc/passwd", os.path.join(w["site"], "tmp", "pw.txt"))
        os.symlink("/etc", os.path.join(w["site"], "cache", "etc"))
        put(w, "cgi-bin/x.pl", "#!/usr/bin/perl\nprint 1;\n", mode=0o755)
        put(w, "media/prog", "\x7fELF\x02\x01binary", mode=0o755)
        put(w, "layouts/future.php", "<?php // x\n")
        t = time.time() + 30 * 86400
        os.utime(os.path.join(w["site"], "layouts/future.php"), (t, t))
        r = run(w, "hidden_structure")
        ts = titles(r)
        self.assertEqual(r.status, "crit", ts)
        for needle, sev in (("versteckte(r) Ordner", "warn"), ("symbolische Verknüpfung(en) auf Systemordner", "crit"), ("ausführbare Programme (ELF)", "crit"),
                            ("Skript(e)/Ordner für CGI", "warn"), ("Änderungsdatum in der Zukunft", "warn")):
            self.assertTrue(any(s == sev and needle in x for s, x in ts), (needle, ts))

    def test_evaluate_struct_symlinks(self):
        sec = {"ROOT": "/home/u/html\n", "LINKS": "./a\t/home/u/html/b\n./b\t/home/other/x\n./c\t/proc/self\n./d\t../../../../x\n./e\t/usr/share/z\n"}
        rows = hidden.evaluate_struct(sec)
        by = {t.split(" ")[1] if False else t: s for s, t, *_ in rows}
        self.assertEqual(sorted(s for s, *_ in rows), ["crit", "warn"])
        crit = next(r for r in rows if r[0] == "crit")
        self.assertEqual(crit[3], ["./c -> /proc/self"])
        warn = next(r for r in rows if r[0] == "warn")
        self.assertEqual(len(warn[3]), 2)                                         # fremder Pfad und ../../../..


class Htaccess(unittest.TestCase):
    def test_hidden_rules_and_locations(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_h_"), False)
        r = run(w, "htaccess_structure")
        self.assertNotIn(r.status, ("crit", "error"), titles(r) + [r.message])
        body = "RewriteEngine On\n" + "\n" * 60 + "RewriteRule ^(.*)$ spam-weiche.php [L]\n"
        put(w, "templates/gt_yoga/.htaccess", body)
        put(w, "components/com_x/.htaccess", "<FilesMatch \"shell\\.php\">\nAllow from all\n</FilesMatch>\n")
        put(w, "plugins/.htaccess", "Order deny,allow\nDeny from all\n")                                  # Sperrregel: in Ordnung
        put(w, "media/.htaccess", "# " + "x" * 900 + "\n")
        put(w, "modules/.htaccess", "RewriteEngine On\nRewriteCond %{HTTP_COOKIE} !angemeldet\nRewriteRule ^(.*)$ index.php [L]\n")
        r = run(w, "htaccess_structure")
        ts = titles(r)
        self.assertEqual(r.status, "crit", ts)
        for needle in ("versteckten Regeln hinter Leerzeilen", "erlauben PHP-Dateien gezielt", "extrem langer Zeile", "andere PHP-Datei als index.php", "nach Cookie, Browsersprache"):
            self.assertTrue(any(needle in x for _, x in ts), (needle, ts))
        loc = next(f for f in r.findings if "Programmordnern" in f.title)
        self.assertFalse(any("plugins/.htaccess" in i for i in loc.items))                        # gesperrt: nicht gemeldet
        self.assertTrue(any("components/com_x" in i for i in loc.items))


if __name__ == "__main__":
    unittest.main()
