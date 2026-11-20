"""Store-Angaben zu Sicherheits-Erweiterungen: Kurzbeschreibung, Bild und Link der Store-Seite (wordpress.org bzw. Joomla Extensions Directory).

Nur lesend und nur von diesem PC aus. Die Adressen kommen ausschließlich aus der festen Liste (security_tools.json) oder aus der Antwort des Stores
und werden vor dem Abruf geprüft (https, feste Hosts). Bilder werden an den Bytes erkannt (PNG, JPEG, GIF, WebP; kein SVG, weil das Skripte enthalten kann)
und als data:-Adresse an die Oberfläche gegeben, damit die Oberfläche keine fremden Adressen laden muss.
Ohne Verbindung oder bei jedem Fehler bleibt es bei den eigenen Texten der Liste und einer Platzhalter-Kachel.
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import threading
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin, urlparse

from . import cms as cmsmod
from .checks import web as webmod

IMAGE_HOSTS = ("ps.w.org", "s.w.org", "extensions.joomla.org", "docs.joomla.org")
MAX_IMAGE = 300_000                 # Bytes; größere Bilder werden nicht angezeigt (es gibt den Platzhalter)
MAX_PAGE = 600_000
_lock = threading.Lock()
_cache: Dict[str, Dict[str, Any]] = {}


def store_url(tool: Dict[str, Any], cms: str) -> str:
    if cmsmod.profile(cms)["store"] == "wporg":
        return "https://wordpress.org/plugins/%s/" % quote(str(tool.get("slug") or ""), safe="")
    return str(tool.get("jed") or "")


def image_ok(url: str) -> bool:
    """Nur https, kein Benutzername, kein eigener Port, nur feste Bild-Hosts."""
    try:
        u = urlparse(url)
        return u.scheme == "https" and (u.hostname or "").lower() in IMAGE_HOSTS and not u.username and not u.port and len(url) < 500 and not re.search(r"[\s\x00-\x1f]", url)
    except ValueError:
        return False


def sniff(data: bytes) -> str:
    """Bildart an den ersten Bytes. Leer, wenn es kein erlaubtes Bild ist."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return ""


def data_uri(raw: bytes) -> str:
    mime = sniff(raw)
    if not mime or len(raw) > MAX_IMAGE:
        return ""
    return "data:%s;base64,%s" % (mime, base64.b64encode(raw).decode("ascii"))


def parse_wp(text: str) -> Dict[str, str]:
    """Antwort von api.wordpress.org (plugin_information) -> Kurzbeschreibung und Bildadresse."""
    try:
        d = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(d, dict):
        return {}
    out: Dict[str, str] = {}
    short = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", str(d.get("short_description") or "")))).strip()
    if short:
        out["short"] = short[:400]
    try:
        rating, num = float(d.get("rating") or 0), int(d.get("num_ratings") or 0)
        if num > 0 and 0 < rating <= 100:
            out["stars"] = "%.1f" % (rating / 20.0)
            out["reviews"] = str(num)
    except (TypeError, ValueError):
        pass
    icons = d.get("icons")
    if isinstance(icons, dict):
        for k in ("2x", "1x", "default"):
            u = icons.get(k)
            if isinstance(u, str) and image_ok(u) and not u.lower().split("?")[0].endswith(".svg"):
                out["image_url"] = u
                break
    return out


def _meta(page: str, prop: str) -> str:
    for m in re.finditer(r"<meta\b[^>]*>", page[:MAX_PAGE], re.I):
        tag = m.group(0)
        if re.search(r"""(?:property|name)\s*=\s*["']%s["']""" % re.escape(prop), tag, re.I):
            c = re.search(r"""content\s*=\s*(?:"([^"]*)"|'([^']*)')""", tag, re.I)
            if c:
                return html.unescape(c.group(1) or c.group(2) or "").strip()
    return ""


def parse_jed(page: str, base: str) -> Dict[str, str]:
    """JED-Seite -> Kurzbeschreibung (og:description) und Bild (og:image)."""
    out: Dict[str, str] = {}
    desc = re.sub(r"\s+", " ", _meta(page, "og:description") or _meta(page, "description"))
    if desc:
        out["short"] = desc[:400]
    img = _meta(page, "og:image")
    if img:
        img = urljoin(base, img)
        if image_ok(img) and not img.lower().split("?")[0].endswith(".svg"):
            out["image_url"] = img
    return out


def lookup(tool: Dict[str, Any], cms: str, offline: Optional[bool] = None) -> Dict[str, Any]:
    """Store-Angaben zu einem Eintrag der Liste. Immer ein Ergebnis: 'live' sagt, ob etwas vom Store kam."""
    tid = str(tool.get("id") or "")
    key = "%s:%s" % (cms, tid)
    with _lock:
        if key in _cache:
            return dict(_cache[key])
    off = bool(os.environ.get("CLAUDIA_OFFLINE")) if offline is None else offline
    url = store_url(tool, cms)
    res: Dict[str, Any] = {"id": tid, "name": tool.get("name", ""), "store_url": url, "short": str(tool.get("text") or ""), "image": "", "live": False}
    if off or not url:
        return res
    got: Dict[str, str] = {}
    try:
        if cmsmod.profile(cms)["store"] == "wporg":
            api = ("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=" + quote(str(tool.get("slug") or ""), safe="")
                   + "&request%5Bfields%5D%5Bicons%5D=1&request%5Bfields%5D%5Bshort_description%5D=1")
            f = webmod.fetch(api, webmod.UA_BROWSER, max_bytes=1_500_000, timeout=20)
            if not f.error and f.status == 200:
                got = parse_wp(f.body)
        else:
            f = webmod.fetch(url, webmod.UA_BROWSER, max_bytes=MAX_PAGE, timeout=20)
            if not f.error and f.status == 200 and urlparse(f.final or url).hostname == "extensions.joomla.org":
                got = parse_jed(f.body, f.final or url)
        if got.get("image_url"):
            img = webmod.fetch(got["image_url"], webmod.UA_BROWSER, max_bytes=MAX_IMAGE + 1, timeout=20, binary=True)
            if not img.error and img.status == 200 and image_ok(img.final or got["image_url"]):
                res["image"] = data_uri(img.raw)
    except Exception:
        got = got or {}
    if got.get("short"):
        res["short"] = got["short"]
    if got.get("stars"):
        res["stars"], res["reviews"] = float(got["stars"]), int(got["reviews"])
    res["live"] = bool(got)
    if res["live"]:
        with _lock:
            _cache[key] = dict(res)
    return res


# Offizielle Logos: werden unverändert vom Server des Projekts geladen und nur angezeigt (nicht ins Programm eingebaut, nicht verändert).
# Marken: Joomla! (Open Source Matters, Inc.), WordPress (WordPress Foundation).
CMS_LOGOS = {"wordpress": "https://s.w.org/style/images/about/WordPress-logotype-wmark.png",
             "joomla": "https://docs.joomla.org/Special:FilePath/Joomla-flat-logo-en.png"}


def cms_logo(cms: str, offline: Optional[bool] = None) -> Dict[str, Any]:
    """Offizielles Logo des Systems als data:-Adresse; leer ohne Verbindung (dann zeigt die Oberfläche nur den Namen)."""
    key = "logo:%s" % cms
    url = CMS_LOGOS.get(cms, "")
    with _lock:
        if key in _cache:
            return dict(_cache[key])
    res: Dict[str, Any] = {"cms": cms, "image": "", "source": url.split("/")[2] if url else ""}
    off = bool(os.environ.get("CLAUDIA_OFFLINE")) if offline is None else offline
    if off or not url:
        return res
    try:
        img = webmod.fetch(url, webmod.UA_BROWSER, max_bytes=MAX_IMAGE + 1, timeout=20, binary=True)
        if not img.error and img.status == 200 and image_ok(img.final or url):
            res["image"] = data_uri(img.raw)
    except Exception:
        res["image"] = ""
    if res["image"]:
        with _lock:
            _cache[key] = dict(res)
    return res


def clear_cache() -> None:
    with _lock:
        _cache.clear()
