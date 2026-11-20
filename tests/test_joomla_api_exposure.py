"""2.4.0 / A13: Joomla-API ohne Anmeldung (CVE-2023-23752): ein einzelner Abruf, nur bei betroffener oder unbekannter Version, Antwort nie im Bericht."""
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

import fixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia.checks import web as W  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

SECRET = "GEHEIM-DB-PASSWORT-4711"
LEAK = json.dumps({"links": {}, "data": [{"type": "application", "id": "224", "attributes": {"offline": False, "user": "dbuser", "password": SECRET, "db": "joomla"}}]})


def reply(body="", status=200, headers=None):
    f = W.Fetched()
    f.body, f.status, f.headers, f.url = body, status, headers or {}, "https://x.example/"
    return f


def run(version, fetched, url="https://x.example"):
    load_all()
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_a13_"), False)
    if version is not None:
        p = os.path.join(w["site"], "libraries/src/Version.php")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        a, b, c = (version.split(".") + ["0", "0"])[:3]
        open(p, "w").write("<?php\nclass Version {\n  public const MAJOR_VERSION = %s;\n  public const MINOR_VERSION = %s;\n  public const PATCH_VERSION = %s;\n  public const EXTRA_VERSION = '';\n}\n" % (a, b, c))
    else:
        for rel in ("libraries/src/Version.php", "administrator/manifests/files/joomla.xml"):
            q = os.path.join(w["site"], rel)
            if os.path.exists(q):
                os.remove(q)
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url=url, log_dir="logs", opts={}, allow_hosts=[]), ADV)
    with mock.patch.object(W, "fetch", return_value=fetched) as m:
        r = {x.id: x for x in eng.run(["joomla_api_exposure"], lambda e: None, threading.Event())}["joomla_api_exposure"]
    return r, m


class A13(unittest.TestCase):
    def test_vulnerable_version_with_leak_is_critical_and_hides_content(self):
        r, m = run("4.2.5", reply(LEAK))
        self.assertEqual(m.call_count, 1)
        self.assertTrue(m.call_args[0][0].endswith("/api/index.php/v1/config/application?public=true"))
        self.assertTrue(m.call_args[0][0].startswith("https://"))
        self.assertEqual([f.sev for f in r.findings], ["crit"])
        self.assertTrue(r.findings[0].title.startswith("Zugangsdaten sichtbar"))
        self.assertNotIn(SECRET, json.dumps([f.to_dict() for f in r.findings]))
        self.assertNotIn("dbuser", json.dumps([f.to_dict() for f in r.findings]))

    def test_unknown_version_is_checked(self):
        r, m = run(None, reply("", 401))
        self.assertEqual(m.call_count, 1)
        self.assertEqual(r.findings[0].sev, "ok")

    def test_fixed_version_is_not_requested(self):
        r, m = run("4.2.8", reply(LEAK))
        self.assertEqual(m.call_count, 0)
        self.assertEqual(r.findings[0].sev, "ok")

    def test_joomla3_has_no_api_and_is_not_requested(self):
        r, m = run("3.10.12", reply(LEAK))
        self.assertEqual(m.call_count, 0)
        self.assertEqual(r.findings[0].sev, "ok")

    def test_waf_block_is_info_not_a_verdict(self):
        r, m = run("4.1.0", reply("<html>Attention Required! | Cloudflare</html>", 403))
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Firewall", r.findings[0].title)

    def test_verdicts(self):
        self.assertEqual(W.api_config_verdict(reply(LEAK)), "sichtbar")
        self.assertEqual(W.api_config_verdict(reply("{}", 404)), "gesperrt")
        self.assertEqual(W.api_config_verdict(reply('{"errors":[{"title":"Forbidden"}]}', 403)), "gesperrt")
        self.assertEqual(W.api_config_verdict(reply("x", 500)), "unklar")

    def test_no_url_skips_and_no_request(self):
        r, m = run("4.1.0", reply(LEAK), url="")
        self.assertEqual(r.status, "skipped")
        self.assertEqual(m.call_count, 0)


if __name__ == "__main__":
    unittest.main()
