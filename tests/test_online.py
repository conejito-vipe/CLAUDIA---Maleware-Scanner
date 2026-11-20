"""Online-Abgleich (VEL-Liste, JED-Verzeichnis) gegen einen lokalen Ersatz-Server."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from test_checks import ADV, has, titles  # noqa: E402
from claudia.checks import online  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

FEED = {"success": True, "data": {"api_version": 1, "items": [
    {"id": 1, "title": "JCE Editor 2.9.99.3", "status": 1, "cve_id": "CVE-X", "start_version": "2.9.0", "vulnerable_version": "2.9.99.4",
     "patch_version": "2.9.99.5", "install_data": json.dumps({"name": "COM_JCE", "type": "component"})},
    {"id": 2, "title": "Osmap alt", "status": 2, "start_version": "5.0.0", "vulnerable_version": "5.1.12", "patch_version": "5.1.12",
     "install_data": {"name": "COM_OSMAP"}},
    {"id": 3, "title": "Nicht installiert", "status": 1, "vulnerable_version": "9.9.9", "install_data": {"name": "com_gibtsnicht"}},
    {"id": 4, "title": "Akeeba offen", "status": 1, "vulnerable_version": "10.4.0", "patch_version": "", "install_data": {"name": "COM_AKEEBABACKUP"}},
]}}
JED_PAGE = "<html><title>JCE | Joomla! Extensions Directory</title><body>Developer: Widget Factory Limited <a>547 reviews</a> Compatibility: J5</body></html>"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/vel-feed":
            body, code = json.dumps(FEED).encode(), 200
        elif self.path == "/extension/jce/":
            body, code = JED_PAGE.encode(), 200
        else:
            body, code = b"<html><title>Not found</title></html>", 404
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Online(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old = os.environ.pop("CLAUDIA_OFFLINE", None)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        if cls._old is not None:
            os.environ["CLAUDIA_OFFLINE"] = cls._old

    def run_checks(self, ids, infected=True, opts=None):
        load_all()
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_o_"), infected)
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], opts=opts or {}), ADV)
        return {r.id: r for r in eng.run(ids, lambda e: None, threading.Event())}

    def test_vel_matches(self):
        online.VEL_URLS[:] = [self.base + "/vel-feed"]
        r = self.run_checks(["vel_feed"])["vel_feed"]
        self.assertEqual(r.status, "crit", [(f.sev, f.title) for f in r.findings])
        items = [i for f in r.findings for i in f.items]
        self.assertTrue(any("JCE" in i.upper() and "CVE-X" in i for i in items))        # JCE 2.9.99.3 liegt im Bereich
        self.assertTrue(any("KEIN Update bekannt" in i for i in items))                  # Akeeba 10.4.0: kein Patch
        self.assertFalse(any("gibtsnicht" in i for i in items))

    def test_vel_only_affected_versions(self):
        online.VEL_URLS[:] = [self.base + "/vel-feed"]
        r = self.run_checks(["vel_feed"], infected=False)["vel_feed"]       # JCE 2.9.99.7 ist gepatcht
        self.assertFalse(any("JCE Editor 2.9.99.3" in i for f in r.findings for i in f.items))

    def test_vel_unreachable_is_skipped(self):
        online.VEL_URLS[:] = [self.base + "/gibt-es-nicht"]
        r = self.run_checks(["vel_feed"])["vel_feed"]
        self.assertEqual(r.status, "skipped")
        self.assertIn("eingebaute", r.message)

    def test_jed_lookup(self):
        online.JED_BASE = self.base + "/extension/"
        r = self.run_checks(["jed_listing"], opts={"jed_listing": {"max": 20}})["jed_listing"]
        found = [i for f in r.findings if "gefunden" in f.title and "nicht" not in f.title for i in f.items]
        self.assertTrue(any("Widget Factory" in i and "547" in i for i in found), found)
        self.assertFalse(any("dort nicht gefunden" in f.title for f in r.findings))      # alte, irreführende Formulierung ist weg

    def test_real_site_inventory_is_classified_sensibly(self):
        """Die 18 Erweiterungen aus dem echten Bericht: nichts Seriöses darf als 'nicht gefunden' enden, Zusatz-Plugins werden nicht einzeln gesucht."""
        def m(typ, element, name, author, group="", ver="1.0"):
            return {"type": typ, "element": element, "name": name, "author": author, "group": group, "version": ver, "path": "x"}
        ms = [m("component", "com_akeebabackup", "com_akeebabackup", "Akeeba Ltd", ver="10.3.6"),
              m("component", "COM_CONVERTFORMS", "COM_CONVERTFORMS", "Tassos Marinos", ver="5.2.2"),
              m("plugin", "calculations", "PLG_CONVERTFORMSTOOLS_CALCULATIONS", "Tassos Marinos (Tassos.gr)", group="convertformstools"),
              m("plugin", "pdf", "PLG_CONVERTFORMSTOOLS_PDF", "Tassos Marinos (Tassos.gr)", group="convertformstools"),
              m("plugin", "codemirror", "plg_editors_codemirror", "Marijn Haverbeke", group="editors"),
              m("plugin", "tinymce", "plg_editors_tinymce", "Tiny Technologies, Inc", group="editors"),
              m("plugin", "akeebabackup", "PLG_QUICKICON_AKEEBABACKUP", "Nicholas K. Dionysopoulos", group="quickicon"),
              m("plugin", "akwarn", "PLG_SYSTEM_AKWARN", "Nicholas K. Dionysopoulos", group="system"),
              m("plugin", "aimycanonical", "System - Aimy Canonical", "Aimy Extensions", group="system"),
              m("plugin", "cgwebp", "System - CG Webp", "ConseilGouz", group="system"),
              m("plugin", "helixultimate", "System - Helix Ultimate Framework", "JoomShaper.com", group="system"),
              m("template", "shaper_helixultimate", "shaper_helixultimate", "JoomShaper.com"),
              m("component", "COM_JCE", "COM_JCE", "Ryan Demmer")]
        jed = json.load(open(os.path.join(os.path.dirname(online.__file__), "..", "advisories.json"), encoding="utf-8"))["jed"]
        main, parts, core = online.classify_third(ms, jed)
        self.assertEqual(sorted(x["element"] for x in main), ["COM_CONVERTFORMS", "COM_JCE", "aimycanonical", "cgwebp", "com_akeebabackup", "helixultimate"])
        self.assertEqual(len(core), 2)
        self.assertEqual(len(parts), 5)             # 2 Convert-Forms-Plugins, Quickicon, AKWarn, Helix-Template
        slugs = {x["element"]: online.jed_candidates(x, jed["slugs"]) for x in main}
        self.assertEqual(slugs["com_akeebabackup"][0], "akeeba-backup")
        self.assertEqual(slugs["COM_CONVERTFORMS"][0], "convert-forms")
        self.assertEqual(slugs["cgwebp"][0], "cg-webp")
        self.assertEqual(slugs["aimycanonical"][0], "aimy-canonical")
        self.assertEqual(slugs["COM_JCE"][0], "jce")
        self.assertEqual(slugs["helixultimate"][:2], ["helix-ultimate-framework", "helix-ultimate"])

    def test_blocked_directory_is_reported_as_unreachable_not_missing(self):
        online.JED_BASE = self.base + "/blockiert/"
        r = self.run_checks(["jed_listing"], opts={"jed_listing": {"max": 3}})["jed_listing"]
        self.assertTrue(any("nicht abrufbar" in f.title or "nicht automatisch zugeordnet" in f.title for f in r.findings))

    def test_parse_vel_formats(self):
        self.assertEqual(online.parse_vel("kein json"), [])
        self.assertEqual(len(online.parse_vel(json.dumps(FEED))), 4)
        self.assertEqual(len(online.parse_vel(json.dumps(FEED["data"]))), 4)
        self.assertEqual(len(online.parse_vel(json.dumps(FEED["data"]["items"]))), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
