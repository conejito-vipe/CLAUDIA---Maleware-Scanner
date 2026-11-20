"""2.4.0 / A10: Plugin-Dateien gegen die Prüfsummen von wordpress.org (nur mit nachgebildeten Antworten getestet, nicht gegen die echte Schnittstelle)."""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import wpfixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia import wpsums  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


class Reply:
    def __init__(self, body="", status=200, error=""):
        self.body, self.status, self.error = body, status, error


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def reference(site, slug, as_list=False, drop=()):
    root = os.path.join(site, "wp-content", "plugins", slug)
    files = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            fp = os.path.join(dp, f)
            rel = os.path.relpath(fp, root)
            if rel in drop:
                continue
            h = sha(fp)
            files[rel] = {"md5": hashlib.md5(open(fp, "rb").read()).hexdigest(), "sha256": [h] if as_list else h}
    return json.dumps({"plugin": slug, "files": files})


def run(w, fake, opts=None):
    load_all()
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="wordpress", url="", allow_hosts=ADV["allow_hosts"], opts=opts or {})
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    with mock.patch.dict(os.environ, {}), mock.patch.object(webmod, "fetch", fake):
        os.environ.pop("CLAUDIA_OFFLINE", None)
        return {x.id: x for x in eng.run(["wp_plugin_integrity"], lambda e: None, threading.Event())}["wp_plugin_integrity"]


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class A10(unittest.TestCase):
    def setUp(self):
        self.w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="claudia_a10_"), False)
        self.refs = {s: reference(self.w["site"], s, as_list=(s == "akismet")) for s in ("akismet", "contact-form-7")}
        self.urls = []
        prem = os.path.join(self.w["site"], "wp-content/plugins/premium-x")
        os.makedirs(prem)
        with open(os.path.join(prem, "premium-x.php"), "w") as fh:
            fh.write("<?php\n/*\nPlugin Name: Premium X\nVersion: 3.1\n*/\n")

    def fake(self, url, *a, **k):
        self.urls.append(url)
        self.assertTrue(url.startswith("https://downloads.wordpress.org/plugin-checksums/"), url)
        slug = url.split("/")[-2]
        if slug in self.refs:
            return Reply(self.refs[slug])
        return Reply("{}", 404)

    def test_clean_plugins_match_and_unknown_is_listed(self):
        r = run(self.w, self.fake)
        t = titles(r)
        self.assertTrue(any(s == "ok" and "stimmen mit dem Original" in x for s, x in t), t)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertTrue(any("ohne Prüfsummen" in x for _, x in t), t)          # Premium-Plugin: Antwort 404
        self.assertEqual(len(self.urls), len(set(self.urls)))                  # je Plugin genau eine Abfrage

    def test_changed_and_extra_file_detected(self):
        p = os.path.join(self.w["site"], "wp-content/plugins/akismet/akismet.php")
        with open(p, "a") as fh:
            fh.write("\n@eval(base64_decode($_POST['x']));\n")
        extra = os.path.join(self.w["site"], "wp-content/plugins/contact-form-7/cache.php")
        with open(extra, "w") as fh:
            fh.write("<?php echo 1;")
        r = run(self.w, self.fake)
        t = titles(r)
        self.assertTrue(any(s == "crit" and "weichen vom Original ab" in x for s, x in t), t)
        self.assertTrue(any("akismet: akismet.php" in " ".join(f.items) for f in r.findings))
        self.assertTrue(any(s == "warn" and "zusätzliche PHP" in x for s, x in t), t)
        self.assertTrue(any("contact-form-7: cache.php" in " ".join(f.items) for f in r.findings))
        self.assertFalse(any(s == "ok" and "stimmen mit dem Original" in x for s, x in t))

    def test_non_code_change_is_not_critical(self):
        p = os.path.join(self.w["site"], "wp-content/plugins/akismet/readme.txt")
        with open(p, "w") as fh:
            fh.write("lokal geändert")
        r = run(self.w, self.fake)
        self.assertFalse(any(s == "crit" for s, _ in titles(r)), titles(r))

    def test_network_error_and_limit(self):
        r = run(self.w, lambda url, *a, **k: Reply("", 0, "keine Verbindung"))
        t = titles(r)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertTrue(any("Nicht alles konnte geprüft werden" in x for _, x in t), t)
        self.urls.clear()
        run(self.w, self.fake, {"wp_plugin_integrity": {"max": 1}})
        self.assertEqual(len(self.urls), 1)

    def test_parser_tolerant(self):
        self.assertEqual(wpsums.parse_reference("kein json"), {})
        self.assertEqual(wpsums.parse_reference('{"files": 5}'), {})
        got = wpsums.parse_reference(json.dumps({"files": {"./a.php": {"sha256": ["AB" * 32], "md5": "c" * 32}, "b.php": "d" * 32}}))
        self.assertIn("a.php", got)
        self.assertEqual(got["a.php"]["sha256"], {"ab" * 32})
        self.assertEqual(got["b.php"]["md5"], {"d" * 32})
        self.assertEqual(wpsums.url("a b", "1.0"), "https://downloads.wordpress.org/plugin-checksums/a%20b/1.0.json")


if __name__ == "__main__":
    unittest.main()
