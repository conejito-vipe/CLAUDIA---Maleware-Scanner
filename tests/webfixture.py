"""Lokaler Test-Webserver: 'sauber' oder 'infiziert' (Cloaking, Schadcode im JS, offene .env)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fixture import JQUERY_INFECTED, JQUERY_REAL_HEAD

CLEAN_HOME = """<!doctype html><html><head><title>Kinder Test</title>
<script src="/media/vendor/jquery/js/jquery.min.js"></script>
<script async src="https://www.googletagmanager.com/gtm.js?id=GTM-AAAA111"></script>
<script src="https://static.elfsight.com/platform/platform.js" async></script>
<script src="https://elfsightcdn.com/platform.js" async></script>
<script src="/media/vendor/jquery/js/jquery-noconflict.min.js"></script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Person","sameAs":["https://www.linkedin.com/in/test"]}</script>
<script>var share = {network: "https://social.example.org/share?mini=true"};</script>
</head><body><h1>Willkommen bei der Kinderperspektive</h1>
<p>""" + "Ein langer normaler Text für die Besucher. " * 30 + """</p></body></html>"""

INFECTED_HOME = CLEAN_HOME.replace("</head>", '<script src="https://cdn.whitellllshop.icu/landers/type.php"></script></head>')

SPAM_HOME = """<!doctype html><html><head><title>Cheap viagra casino</title></head><body>
<h1>Buy viagra and cialis online</h1><p>casino payday loans replica</p>
<div style="display:none"><a href="https://spam-pharma.example/a">x</a></div></body></html>"""


def make_handler(infected: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            ref = self.headers.get("Referer", "")
            path = self.path.split("?")[0]
            if path in ("/", "/index.php"):
                if infected and "Googlebot" in ua:
                    return self._send(200, SPAM_HOME)
                if infected and "google.com" in ref:
                    self.send_response(302)
                    self.send_header("Location", "https://spam-pharma.example/in")
                    self.send_header("Content-Length", "0")
                    return self.end_headers()
                return self._send(200, INFECTED_HOME if infected else CLEAN_HOME)
            if path == "/media/vendor/jquery/js/jquery.min.js":
                return self._send(200, JQUERY_INFECTED if infected else JQUERY_REAL_HEAD, "application/javascript")
            if path == "/media/vendor/jquery/js/jquery-noconflict.min.js":
                return self._send(200, "window.$=jQuery.noConflict();\n", "application/javascript")
            if path.startswith("/administrator/components/com_akeebabackup/Backup-Open/"):
                return self._send(200, "JPA")
            if path.startswith("/administrator/components/com_akeebabackup/Backup-Safe/"):
                return self._send(403, "forbidden")
            if path == "/.env" and infected:
                return self._send(200, "APP_KEY=base64:abc\nDB_PASSWORD=x\n", "text/plain")
            if path.startswith("/backup-open/"):
                return self._send(200, "listing")
            if path.startswith("/backup-safe/"):
                return self._send(403, "forbidden")
            return self._send(404, "<html><body>Nicht gefunden</body></html>")
    return H


def start(infected: bool):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(infected))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]
