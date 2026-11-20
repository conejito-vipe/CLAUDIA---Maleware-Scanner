"""2.4.0 / D7: Sicherungen anderer Tools (Akeeba usw.): lesender Web-Test je Speicherordner (ein Abruf, nur erste Bytes) und Hinweis 'kann den Befall enthalten'."""
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
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
from claudia.checks import security_ext as SE  # noqa: E402
from claudia.checks import web as W  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))
BK = "administrator/components/com_akeebabackup/backup"


def reply(status=200, body="", headers=None, size=None, error=""):
    f = W.Fetched()
    f.status, f.body, f.headers, f.error = status, body, headers or {}, error
    f.size = len(body) if size is None else size
    return f


def run(files, answer, url="https://x.example", protect=False):
    load_all()
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_d7_"), False)
    d = os.path.join(w["site"], BK)
    os.makedirs(d, exist_ok=True)
    for n in files:
        open(os.path.join(d, n), "wb").write(b"JPA\x00" + b"x" * 100)
    if protect:
        open(os.path.join(d, ".htaccess"), "w").write("Require all denied\n")
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url=url, log_dir="logs", cms="joomla", opts={}, allow_hosts=ADV["allow_hosts"]), ADV)
    with mock.patch.object(W, "fetch", side_effect=answer if callable(answer) else None, return_value=None if callable(answer) else answer) as m:
        r = eng.run(["backup_tool"], lambda e: None, threading.Event())[0]
    return r, m


class D7(unittest.TestCase):
    def test_reachable_archive_is_critical(self):
        r, m = run(["site-a.jpa"], reply(200, "JPA\x00xxxx", {"content-type": "application/octet-stream"}))
        self.assertEqual(m.call_count, 1)
        url = m.call_args[0][0]
        self.assertTrue(url.startswith("https://x.example/" + BK + "/site-a.jpa"), url)
        crit = [f for f in r.findings if f.sev == "crit"]
        self.assertEqual(len(crit), 1)
        self.assertIn("von außen abrufbar", crit[0].title)
        self.assertEqual(m.call_args[1].get("max_bytes"), 512)       # nur die ersten Bytes

    def test_blocked_archive_is_ok(self):
        r, m = run(["site-a.jpa"], reply(403, "Forbidden"), protect=True)
        self.assertFalse([f for f in r.findings if f.sev == "crit"])
        self.assertTrue([f for f in r.findings if f.sev == "ok" and "nicht abrufbar" in f.title])

    def test_html_page_with_status_200_does_not_count(self):
        r, m = run(["site-a.jpa"], reply(200, "<!DOCTYPE html><html>Startseite</html>", {"content-type": "text/html; charset=utf-8"}))
        self.assertFalse([f for f in r.findings if f.sev == "crit"])

    def test_only_newest_file_per_folder_one_request(self):
        r, m = run(["a.jpa", "b.jpa", "c.jpa"], reply(404, "nf"))
        self.assertEqual(m.call_count, 1)

    def test_waf_is_info_not_verdict(self):
        r, m = run(["a.jpa"], reply(403, "<html>Attention Required! | Cloudflare</html>"))
        self.assertFalse([f for f in r.findings if f.sev in ("crit", "ok") and "abrufbar" in f.title])
        self.assertTrue([f for f in r.findings if "Firewall" in f.title])

    def test_hint_about_infection_always_present_and_no_url_means_no_request(self):
        r, m = run(["a.jpa"], reply(200, "x"), url="")
        self.assertEqual(m.call_count, 0)
        self.assertTrue([f for f in r.findings if f.title == "Sicherungen können den Befall enthalten"])
        self.assertTrue([f for f in r.findings if "nicht getestet" in f.title])

    def test_no_archive_no_request(self):
        r, m = run([], reply(200, "x"))
        self.assertEqual(m.call_count, 0)

    def test_archive_reachable_rules(self):
        self.assertTrue(SE.archive_reachable(reply(206, "PK\x03\x04", {})))
        self.assertFalse(SE.archive_reachable(reply(200, "", {}, size=0)))
        self.assertFalse(SE.archive_reachable(reply(404, "x")))
        self.assertFalse(SE.archive_reachable(reply(200, "x", error="boom")))


if __name__ == "__main__":
    unittest.main()
