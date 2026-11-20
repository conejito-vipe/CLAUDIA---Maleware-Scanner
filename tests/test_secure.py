"""Verschlüsselung: nur SSH zum Server, nur https zu Webseiten und Online-Quellen."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
from claudia import secure  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402


class Helpers(unittest.TestCase):
    def test_secure_url(self):
        self.assertTrue(secure.is_secure_url("https://example.org/x"))
        self.assertFalse(secure.is_secure_url("http://example.org/x"))
        self.assertFalse(secure.is_secure_url("ftp://example.org/x"))
        self.assertFalse(secure.is_secure_url("example.org"))
        for ok in ("http://127.0.0.1:8080/", "http://localhost/", "http://[::1]:9/"):
            self.assertTrue(secure.is_secure_url(ok), ok)
        self.assertFalse(secure.is_secure_url("http://127.0.0.1.evil.example/"))

    def test_to_https(self):
        self.assertEqual(secure.to_https("http://www.beispiel.de/a"), ("https://www.beispiel.de/a", True))
        self.assertEqual(secure.to_https("www.beispiel.de"), ("https://www.beispiel.de", False))
        self.assertEqual(secure.to_https("https://x.de"), ("https://x.de", False))
        self.assertEqual(secure.to_https("http://127.0.0.1:1234/")[1], False)


class Fetch(unittest.TestCase):
    def test_http_is_refused_without_any_request(self):
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Netzwerkzugriff!")):
            f = webmod.fetch("http://www.beispiel.example/", webmod.UA_BROWSER)
        self.assertIn("nur verschlüsselt", f.error)
        self.assertEqual(f.status, 0)

    def test_redirect_to_http_is_not_followed(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://www.beispiel.example/ziel")
                self.end_headers()
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            f = webmod.fetch("http://127.0.0.1:%d/" % srv.server_address[1], webmod.UA_BROWSER, timeout=5)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("unverschlüsselte Adresse", f.error)
        self.assertTrue(any("http://www.beispiel.example/ziel" in c for c in f.chain))

    def test_loopback_http_still_works_for_own_tests(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hallo")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            f = webmod.fetch("http://127.0.0.1:%d/" % srv.server_address[1], webmod.UA_BROWSER, timeout=5)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual((f.status, f.body, f.error), (200, "hallo", ""))


class VisitorCheck(unittest.TestCase):
    def test_http_address_is_upgraded_and_only_https_requested(self):
        from claudia.engine import Engine, Settings
        from claudia.registry import load_all
        from claudia.runner import LocalRunner
        load_all()
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_sc_"), False)
        adv = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
        seen = []

        def fake(url, *a, **k):
            seen.append(url)
            return mock.Mock(status=200, error="", body="<html><head><title>x</title></head><body>" + "Text " * 100 + "</body></html>", final=url, chain=[], size=600, url=url)
        s = Settings(site_dir=w["site_rel"], log_dir="logs", url="http://www.beispiel.example", allow_hosts=adv["allow_hosts"])
        with mock.patch.object(webmod, "fetch", fake):
            res = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, adv).run(["web_source"], lambda e: None, threading.Event())[0]
        self.assertTrue(seen)
        self.assertTrue(all(u.startswith("https://") for u in seen), seen)
        self.assertTrue(any("auf https umgestellt" in f.title for f in res.findings), [f.title for f in res.findings])

    def test_php_detection_http_probe_refuses_http(self):
        from claudia import phpdetect
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("Netzwerkzugriff!")):
            r = phpdetect.http_probe("http://www.beispiel.example/")
        # http wird auf https umgestellt; der Abruf selbst ist hier gesperrt, also Fehler statt Klartext-Abruf
        self.assertEqual(r["version"], "")


class Ssh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="claudia_ssh_")
        cls.world = fixture.make_world(cls.tmp, infected=False)
        sys.path.insert(0, os.path.join(HERE, "fake_paramiko"))
        sys.modules.pop("paramiko", None)
        import paramiko
        cls.pm = paramiko
        cls.pm.CONFIG.update(home=cls.world["home"], password="pw", fail=None, seen_disabled=[])

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(os.path.join(HERE, "fake_paramiko"))
        sys.modules.pop("paramiko", None)

    def runner(self, name):
        from claudia.runner import KnownHosts, SSHRunner
        kh = KnownHosts(os.path.join(self.tmp, "known_%s.json" % name))
        r = SSHRunner("fake.example.org", 22, "tester", password="pw", known_hosts=kh, trusted_fp=self._fp())
        return r

    def _fp(self):
        from claudia.runner import fingerprint
        return fingerprint(self.pm._Key(self.pm.CONFIG["host_key"]))

    def test_strict_algorithms_are_requested_first(self):
        self.pm.CONFIG.update(fail=None, seen_disabled=[])
        r = self.runner("strict")
        r.connect()
        first = self.pm.CONFIG["seen_disabled"][0]
        self.assertIn("3des-cbc", first["ciphers"])
        self.assertIn("diffie-hellman-group1-sha1", first["kex"])
        self.assertFalse(r.weak_fallback)
        info = r.security_info()
        self.assertTrue(info["encrypted"])
        self.assertEqual(info["cipher"], "aes256-ctr")
        self.assertTrue(info["fingerprint"].startswith("SHA256:"))
        self.assertEqual(info["weak"], [])
        r.close()

    def test_old_server_needs_confirmation(self):
        from claudia.runner import WeakCrypto
        self.pm.CONFIG.update(fail="legacy", seen_disabled=[])
        try:
            r = self.runner("legacy")
            with self.assertRaises(WeakCrypto):                       # ohne Bestätigung kein Rückfall
                r.connect()
            self.assertEqual(len(self.pm.CONFIG["seen_disabled"]), 1)
        finally:
            self.pm.CONFIG["fail"] = None

    def test_old_server_connects_with_warning_after_confirmation(self):
        self.pm.CONFIG.update(fail="legacy", seen_disabled=[])
        try:
            r = self.runner("legacy")
            r.allow_weak = True
            r.connect()
            self.assertTrue(r.weak_fallback)
            self.assertTrue(r.security_info()["weak_fallback"])
            self.assertEqual(len(self.pm.CONFIG["seen_disabled"]), 2)
            self.assertIsNone(self.pm.CONFIG["seen_disabled"][1])
            r.close()
        finally:
            self.pm.CONFIG["fail"] = None

    def test_wrong_password_does_not_downgrade(self):
        from claudia.runner import AuthFailed
        self.pm.CONFIG.update(fail=None, seen_disabled=[])
        r = self.runner("auth")
        r.password = "falsch"
        with self.assertRaises(AuthFailed):
            r.connect()
        self.assertEqual(len(self.pm.CONFIG["seen_disabled"]), 1)         # kein zweiter Versuch mit schwachen Verfahren

    def test_connection_info_contains_encryption(self):
        from claudia.server import App
        app = App(tempfile.mkdtemp(prefix="claudia_sx_"))
        self.pm.CONFIG.update(fail=None)
        r = self.runner("app")
        r.connect()
        info = {"site_found": True}
        info["security"] = r.security_info()
        self.assertTrue(info["security"]["encrypted"])
        r.close()


if __name__ == "__main__":
    unittest.main()
