"""Tests für Berichte und Export."""
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixture  # noqa: E402
from claudia import report  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
PW = "Geheimes-SSH-Passwort-42"


def make_bundle(infected=True, with_db=True, lang="de"):
    load_all()
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_r_"), infected)
    s = Settings(site_dir=w["site_rel"], log_dir="logs", mask_ips=True)
    ids = [c.id for c in ordered() if c.needs != "web"]
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"] if with_db else None), s, ADV)
    res = eng.run(ids, lambda e: None, threading.Event())
    results = [r.to_dict() for r in res]
    # Das SSH-Passwort in einen Befund schmuggeln: das Sicherheitsnetz muss es entfernen
    results[0]["findings"].append({"sev": "info", "title": "Testzeile " + PW, "detail": "", "items": [PW], "hint": ""})
    results[0]["raw"]["x"] = "Passwort war " + PW
    info = {"host": "ssh.beispiel.de", "joomla": "6.2.0", "php": "PHP 8.3", "mysql": with_db}
    b = report.build_bundle(results, ids, {"site_dir": w["site_rel"], "url": "", "mask_ips": True, "allow_hosts": [], "opts": {}},
                            info, 12.3, False, ADV["stand"], [PW], lang=lang)
    return b, w


class Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b, cls.w = make_bundle(True)
        cls.files = report.all_files(cls.b)

    def test_files_present(self):
        for name in ("bericht.html", "bericht.txt", "ergebnisse.json"):
            self.assertIn(name, self.files)
        self.assertTrue(any(n.startswith("rohdaten/") for n in self.files))

    def test_no_secrets_anywhere(self):
        blob = "\n".join(self.files.values()) + report.claude_readme(self.b)
        z = zipfile.ZipFile(io.BytesIO(report.claude_zip(self.b)))
        blob += "\n".join(z.read(n).decode("utf-8") for n in z.namelist())
        for secret in (PW, "GEHEIM-DB-PASSWORT", "GEHEIMES-SECRET-123", "198.51.100.7"):
            self.assertNotIn(secret, blob, secret)

    def test_json_roundtrip_and_summary(self):
        data = json.loads(self.files["ergebnisse.json"])
        self.assertEqual(data["summary"]["level"], "crit")
        self.assertGreaterEqual(len(data["results"]), 20)
        self.assertTrue(all("raw" not in r for r in data["results"]))
        self.assertEqual(data["meta"]["server"], "ssh.beispiel.de")
        self.assertFalse([k for k in data["meta"] if "user" in k or "benutzer" in k or "passwor" in k])

    def test_text_report_sorted_worst_first(self):
        txt = self.files["bericht.txt"]
        first = txt.index("[KRITISCH]")
        self.assertLess(first, txt.index("[IN ORDNUNG]") if "[IN ORDNUNG]" in txt else len(txt))
        self.assertIn("Empfehlung:", txt)
        self.assertIn("nicht, dass", txt)         # Vorbehalt steht im Bericht

    def test_html_is_escaped_and_selfcontained(self):
        b = json.loads(json.dumps(self.b))
        b["results"][1]["findings"].append({"sev": "crit", "title": "<script>alert(1)</script>", "detail": "<img src=x onerror=1>",
                                            "items": ["<b>x</b>"], "hint": ""})
        out = report.render_html(b)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertNotRegex(out, r"(src|href)=['\"]https?://")      # keine externen Ressourcen

    def test_write_all_and_zip_content(self):
        base = tempfile.mkdtemp()
        outdir, listing = report.write_all(self.b, base)
        names = {f["name"] for f in listing}
        self.assertIn("fuer_claude.zip", names)
        for f in listing:
            self.assertTrue(os.path.getsize(os.path.join(outdir, *f["name"].split("/"))) > 0, f["name"])
        z = zipfile.ZipFile(os.path.join(outdir, "fuer_claude.zip"))
        zn = z.namelist()
        self.assertIn("LIES_MICH.txt", zn)
        self.assertIn("bericht.txt", zn)
        self.assertNotIn("bericht.html", zn)
        self.assertTrue(re.match(r"^ssh\.beispiel\.de_\d{8}-\d{6}$", os.path.basename(outdir)), os.path.basename(outdir))

    def test_sql_file_when_no_db(self):
        b, _ = make_bundle(True, with_db=False)
        files = report.all_files(b)
        self.assertIn("phpmyadmin_abfragen.sql", files)
        self.assertIn("SELECT", files["phpmyadmin_abfragen.sql"].upper())
        self.assertNotIn("GEHEIM-DB-PASSWORT", files["phpmyadmin_abfragen.sql"])

    def test_empty_bundle_does_not_crash(self):
        b = report.build_bundle([], [], {}, {}, 0, False, "x", [])
        self.assertIn("Noch keine Ergebnisse", report.render_txt(b))
        self.assertTrue(report.render_html(b))
        self.assertTrue(report.claude_zip(b))


if __name__ == "__main__":
    unittest.main()
