"""A14 (Sicherheits-Header, Zertifikat) und D3 (Firewall-Sperrseiten) gegen einen lokalen Test-Webserver."""
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
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
import webfixture  # noqa: E402
from claudia.checks import web  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))
load_all()

GOOD = {"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'self'", "Server": "nginx"}
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing the site. cf-chl</body></html>"


def serve(headers, status=200, body=None, only_bots_blocked=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            code, text = status, body
            if only_bots_blocked:
                code, text = (403, "<html>Access denied by Imunify360 bot-protection</html>") if "Googlebot" in ua else (200, webfixture.CLEAN_HOME)
            if text is None:
                text = webfixture.CLEAN_HOME
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


def run(check, url):
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_wh_"), False)
    s = Settings(site_dir=w["site_rel"], url=url, log_dir="logs", allow_hosts=[])
    return Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV).run([check], lambda e: None, threading.Event())[0]


class Judge(unittest.TestCase):
    def test_all_present(self):
        m, p, n = web.judge_headers({k.lower(): v for k, v in GOOD.items()}, True)
        self.assertEqual(m, [])
        self.assertEqual(len(p), 5)
        self.assertEqual(n, [])

    def test_missing_and_weak(self):
        m, p, n = web.judge_headers({"strict-transport-security": "max-age=300", "server": "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.2.1"}, True)
        self.assertEqual(len(m), 4)
        self.assertTrue(any("max-age ist kurz" in x for x in n))
        self.assertTrue(any("Server: Apache/2.4.58" in x for x in n))
        self.assertTrue(any("X-Powered-By" in x for x in n))

    def test_csp_frame_ancestors_counts(self):
        m, p, n = web.judge_headers({"content-security-policy": "frame-ancestors 'none'"}, False)
        self.assertFalse([x for x in m if "Einbettung" in x])
        self.assertFalse([x for x in m if "HSTS" in x])           # ohne https keine HSTS-Wertung

    def test_server_kind(self):
        self.assertEqual(web.server_kind({"server": "LiteSpeed"}), "litespeed")
        self.assertEqual(web.server_kind({"server": "nginx/1.25"}), "nginx")
        self.assertEqual(web.server_kind({"server": "cloudflare"}), "")


class Waf(unittest.TestCase):
    def fe(self, status, body, headers=None):
        f = web.Fetched()
        f.status, f.body, f.headers = status, body, headers or {}
        return f

    def test_blocks(self):
        self.assertEqual(web.waf_block(self.fe(403, "Access denied by Imunify360")), "Imunify360")
        self.assertEqual(web.waf_block(self.fe(406, "Not Acceptable! mod_security")), "ModSecurity")
        self.assertEqual(web.waf_block(self.fe(200, CHALLENGE)), "Cloudflare")
        self.assertEqual(web.waf_block(self.fe(429, "slow down")), "Firewall")
        self.assertEqual(web.waf_block(self.fe(403, "x", {"cf-ray": "1"})), "Firewall")

    def test_normal_pages_untouched(self):
        self.assertEqual(web.waf_block(self.fe(200, webfixture.CLEAN_HOME)), "")
        self.assertEqual(web.waf_block(self.fe(404, "Nicht gefunden")), "")
        self.assertEqual(web.waf_block(self.fe(403, "Forbidden: kein Zugriff auf diesen Ordner")), "")
        long_page = "<html>" + "Wir erklären hier, was ein Captcha ist. " * 600 + "</html>"
        self.assertEqual(web.waf_block(self.fe(200, long_page)), "")


class Live(unittest.TestCase):
    def test_headers_check_good_and_bad(self):
        srv, url = serve(GOOD)
        r = run("web_headers", url)
        srv.shutdown()
        self.assertFalse([f for f in r.findings if f.sev in ("warn", "crit")], [f.title for f in r.findings])
        self.assertTrue(any("Server-Typ laut Antwort: nginx" in f.title for f in r.findings))
        self.assertTrue(any("http auf https nicht getestet" in f.title for f in r.findings))
        srv, url = serve({"Server": "Apache/2.4.1"})
        r = run("web_headers", url)
        srv.shutdown()
        self.assertTrue(any("Sicherheits-Header fehlen" in f.title for f in r.findings))
        self.assertTrue(any("nennt seine genaue Version" in f.title or "Server nennt" in f.title for f in r.findings))

    def test_headers_check_waf_page(self):
        srv, url = serve({}, 200, CHALLENGE)
        r = run("web_headers", url)
        srv.shutdown()
        self.assertEqual([f.title for f in r.findings], ["Von einer Firewall blockiert, Header nicht aussagekräftig"])

    def test_web_source_stops_on_waf(self):
        srv, url = serve({}, 403, "<html>Access denied by Imunify360</html>")
        r = run("web_source", url)
        srv.shutdown()
        self.assertEqual(r.findings[0].sev, "warn")
        self.assertIn("Firewall blockiert", r.findings[0].title)
        self.assertEqual(len(r.findings), 1)

    def test_web_source_ignores_blocked_bot_variant(self):
        srv, url = serve({}, only_bots_blocked=True)
        r = run("web_source", url)
        srv.shutdown()
        self.assertTrue(any("Googlebot wird von einer Firewall blockiert" in f.title for f in r.findings), [f.title for f in r.findings])
        self.assertFalse(any("Cloaking" in f.title for f in r.findings))


class Cert(unittest.TestCase):
    def check(self, days, err=""):
        orig = web.cert_info
        web.cert_info = lambda host, port=443, timeout=15.0: (days, "Testaussteller", err)
        web.secure.is_loopback = web.secure.is_loopback
        try:
            from claudia import secure
            real = secure.is_loopback
            secure.is_loopback = lambda h: False
            # https-Adresse ohne echten Server: der Abruf scheitert, deshalb fetch ersetzen
            of = web.fetch
            def fake(url, ua, referer="", max_bytes=0, timeout=0, binary=False):
                f = web.Fetched()
                f.status, f.body, f.headers = 200, "<html>x</html>", {k.lower(): v for k, v in GOOD.items()}
                return f
            web.fetch = fake
            return run("web_headers", "https://example.org/")
        finally:
            web.cert_info = orig
            web.fetch = of
            secure.is_loopback = real

    def test_expiry_levels(self):
        sev = lambda r: [f.sev for f in r.findings if "Zertifikat" in f.title][0]
        self.assertEqual(sev(self.check(90)), "ok")
        self.assertEqual(sev(self.check(20)), "warn")
        self.assertEqual(sev(self.check(5)), "crit")
        self.assertEqual(sev(self.check(-3)), "crit")
        self.assertEqual(sev(self.check(None, "Zertifikat wird nicht als vertrauenswürdig akzeptiert: x")), "crit")


if __name__ == "__main__":
    unittest.main()
