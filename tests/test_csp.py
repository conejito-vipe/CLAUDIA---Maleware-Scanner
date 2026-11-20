"""CSP-Prüfung: aktive Richtlinie einzeln erklärt, Schwächen, Testmodus, <meta>, und ohne CSP ein Vorschlag aus der Startseite."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_web_headers import run, serve  # noqa: E402
from claudia.checks import csp  # noqa: E402

PAGE = """<html><head><title>x</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
<link rel="stylesheet" href="/templates/a.css">
<script src="https://cdn.example.net/lib.js"></script><script src="/media/own.js"></script>
</head><body onload="init()"><script>var a=1;</script>
<img src="https://img.example.com/p.png"><img src="/images/x.png"><iframe src="https://www.youtube.com/embed/abc"></iframe>
<form action="https://pay.example.org/go"></form></body></html>"""


def findings(r):
    return {f.title: f for f in r.findings}


class Parse(unittest.TestCase):
    def test_parse_and_explain(self):
        pol = csp.parse_policies("default-src 'self'; script-src 'self' https://a.de 'nonce-abc'; object-src 'none'")[0]
        self.assertEqual([n for n, _ in pol], ["default-src", "script-src", "object-src"])
        txt = "\n".join(csp.explain_rule("script-src", pol[1][1]))
        self.assertIn("'self' - die eigene Domain", txt)
        self.assertIn("https://a.de - von https://a.de", txt)
        self.assertIn("Einmalkennung", txt)
        self.assertIn("nichts (gesperrt)", "\n".join(csp.explain_rule("object-src", ["'none'"])))
        self.assertIn("unbekannte", "\n".join(csp.explain_rule("neue-regel", ["x"])))

    def test_judge(self):
        weak = " ".join(csp.judge(csp.parse_policies("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' https:")[0]))
        for k in ("'unsafe-inline'", "'unsafe-eval'", "sehr weite Quellen", "object-src fehlt", "base-uri fehlt", "frame-ancestors fehlt"):
            self.assertIn(k, weak)
        good = csp.judge(csp.parse_policies("default-src 'none'; script-src 'self' 'nonce-x'; base-uri 'self'; frame-ancestors 'self'")[0])
        self.assertEqual(good, [])


class Web(unittest.TestCase):
    def go(self, headers, body=None):
        srv, url = serve(headers, body=body)
        try:
            return run("web_csp", url)
        finally:
            srv.shutdown()

    def test_active_policy_is_explained_rule_by_rule(self):
        r = self.go({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src * data:"})
        f = findings(r)
        act = [t for t in f if t.startswith("Eine Content-Security-Policy ist aktiv")][0]
        items = f[act].items
        self.assertEqual(len([i for i in items if not i.startswith("    ")]), 3)         # drei Regeln, darunter je Quelle eine Zeile
        self.assertTrue(any(i.startswith("script-src - Skripte:") for i in items))
        self.assertTrue(any(i.strip().startswith("'unsafe-inline' - Inline-Code") for i in items))
        weak = [t for t in f if "mögliche Schwächen" in t]
        self.assertTrue(weak)
        self.assertTrue(any("unsafe-inline" in i for i in f[weak[0]].items))
        self.assertNotIn("Keine Content-Security-Policy gesetzt", f)

    def test_without_csp_benefit_and_proposal_from_homepage(self):
        r = self.go({}, body=PAGE)
        f = findings(r)
        self.assertIn("Keine Content-Security-Policy gesetzt", f)
        self.assertIn("zweite Verteidigungslinie", f["Keine Content-Security-Policy gesetzt"].detail)
        prop = f["Vorschlag für eine Content-Security-Policy (zum Testen)"]
        code = "\n".join(c["t"] for c in prop.evidence[0]["code"])
        self.assertIn("Content-Security-Policy-Report-Only", code)
        self.assertIn("https://cdn.example.net", code)
        self.assertIn("https://fonts.gstatic.com", code)
        self.assertIn("frame-src https://www.youtube.com", code)
        self.assertIn("form-action 'self' https://pay.example.org", code)
        self.assertIn("'unsafe-inline'", code)                           # Inline-Skript auf der Seite
        self.assertTrue(any("Report-Only" in prop.detail for _ in [0]))
        self.assertEqual(r.status, "info")

    def test_report_only_and_meta(self):
        r = self.go({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        t = [x for x in findings(r)]
        self.assertTrue(any("Testmodus" in x for x in t))
        self.assertIn("Keine scharfgestellte Content-Security-Policy", t)
        meta = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; frame-ancestors \'none\'"></head><body>x</body></html>'
        r = self.go({}, body=meta)
        t = list(findings(r))
        self.assertTrue(any(x.startswith("Eine Content-Security-Policy ist aktiv") and "<meta>" in x for x in t))
        self.assertIn("Die CSP steht nur in einem <meta>-Tag", t)


if __name__ == "__main__":
    unittest.main()
