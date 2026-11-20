"""PHP-Version der WEBSEITE erkennen (nicht die der Kommandozeile).

Auf Shared Hosting laufen Webseite und Kommandozeile oft mit verschiedenen PHP-Versionen. Das Programm fragt deshalb mehrere Quellen
ab und nennt immer die Quelle. Findet sich keine verlässliche Angabe, steht dort 'nicht erkannt' - es wird nichts geraten.

Quellen (in dieser Reihenfolge):
  1. HTTP-Kopfzeile 'X-Powered-By: PHP/8.3.6' der Webseite (liest nur die Kopfzeilen)
  2. Handler-Zeilen in der .htaccess (z. B. AddHandler application/x-httpd-php83)
  3. Laufende PHP-Prozesse des Server-Kontos (php-cgi/php-fpm mit Versionsnummer im Pfad)
  4. Das Standard-Programm 'php' der Kommandozeile (nur als schwacher Hinweis, ausdrücklich so benannt)
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

_HDR_RE = re.compile(r"\bPHP/(\d+\.\d+(?:\.\d+)?)", re.I)
_DOT_RE = re.compile(r"(?<!\d)(\d)\.(\d{1,2})(?!\d)")
_COMPACT_RE = re.compile(r"php[-_]?(?:cgi|fpm|fcgi)?[-_]?(\d)(\d{1,2})(?!\d)", re.I)


def version_in_token(token: str) -> str:
    """'x-httpd-php83' -> '8.3', '/opt/php-8.5/bin/php-cgi' -> '8.5'. Leer, wenn nichts Eindeutiges vorkommt."""
    t = token.strip()
    if "php" not in t.lower():
        return ""
    m = _COMPACT_RE.search(t)
    if m and not re.search(r"php[-_]?\d\.\d", t, re.I):
        return "%s.%s" % (m.group(1), m.group(2))
    m = re.search(r"php[-_]?(\d)\.(\d{1,2})(?!\d)", t, re.I)
    if m:
        return "%s.%s" % (m.group(1), m.group(2))
    m = re.search(r"/php[-_]?(\d)\.(\d{1,2})/", t, re.I) or re.search(r"(\d)\.(\d{1,2})(?:\.\d+)?/(?:bin|sbin|etc)/", t)
    if m:
        return "%s.%s" % (m.group(1), m.group(2))
    return ""


def versions_in_lines(text: str) -> List[str]:
    out: List[str] = []
    for ln in (text or "").splitlines():
        for tok in re.split(r"[\s;:=,\"']+", ln):
            v = version_in_token(tok)
            if v and v not in out:
                out.append(v)
    return out


def from_headers(headers: Dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() in ("x-powered-by", "x-php-version", "server"):
            m = _HDR_RE.search(v or "")
            if m:
                return m.group(1)
    return ""


def http_probe(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Ruft die Startseite ab (nur Kopfzeilen werden ausgewertet). {'version': '', 'error': ''}"""
    url = (url or "").strip()
    if not url:
        return {"version": "", "error": "keine Webadresse angegeben"}
    from . import secure
    url, _ = secure.to_https(url)
    if not secure.is_secure_url(url):
        return {"version": "", "error": "unverschlüsselte Adresse wird nicht abgerufen"}
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (CLAUDIA PHP-Erkennung)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return {"version": from_headers(dict(r.headers.items())), "error": ""}
    except urllib.error.HTTPError as e:
        return {"version": from_headers(dict(e.headers.items())) if e.headers else "", "error": "HTTP %s" % e.code}
    except Exception as e:  # Netzwerk, Zertifikat, Zeitüberschreitung
        return {"version": "", "error": str(e)[:120]}


def decide(info: Dict[str, Any], url: str = "", http: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Faßt alle Quellen zusammen: {'version': '8.3', 'source': '...', 'note': '...'}. version leer = nicht erkannt."""
    notes: List[str] = []
    http = http if http is not None else http_probe(url) if url else {"version": "", "error": "keine Webadresse angegeben"}
    if http.get("version"):
        return {"version": ".".join(http["version"].split(".")[:2]), "source": "HTTP-Kopfzeile X-Powered-By der Webseite", "note": ""}
    notes.append("Die Webseite nennt ihre PHP-Version nicht in den Kopfzeilen" + (" (%s)" % http["error"] if http.get("error") else ""))
    ht = versions_in_lines(info.get("php_hint", ""))
    if len(ht) == 1:
        return {"version": ht[0], "source": "Handler-Zeile in der .htaccess", "note": ""}
    if len(ht) > 1:
        notes.append("In der .htaccess stehen mehrere Versionen (%s)" % ", ".join(ht))
    ps = versions_in_lines(info.get("php_ps", ""))
    if len(ps) == 1:
        return {"version": ps[0], "source": "laufender PHP-Prozess des Server-Kontos", "note": ""}
    if len(ps) > 1:
        notes.append("Es laufen PHP-Prozesse mit mehreren Versionen (%s)" % ", ".join(ps))
    return {"version": "", "source": "", "note": "; ".join(notes)}
