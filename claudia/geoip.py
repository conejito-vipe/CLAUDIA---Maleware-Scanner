"""Herkunft von Absender-Netzen: Land und Netzname laut RDAP der Regional-Registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC).

Datenschutz und Missbrauchsschutz: Es wird nur das gekürzte Netz abgefragt (IPv4 a.b.c.0, IPv6 /48), nie die volle Adresse; höchstens MAX_NETS
verschiedene Netze je Lauf, eine Anfrage nach der anderen, nur https. Das Land ist das der Registrierung des Netzes, nicht der genaue Standort
(ein Anbieter kann Netze in einem anderen Land nutzen)."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import coreref

BOOT = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
RDAP_HOSTS = ("rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net")
MAX_NETS = 12
FETCH_BUDGET = 60.0                                  # Sekunden für alle Abfragen eines Laufs
Fetcher = Callable[[str], bytes]

COUNTRY_DE = {
    "DE": "Deutschland", "AT": "Österreich", "CH": "Schweiz", "US": "USA", "GB": "Vereinigtes Königreich", "FR": "Frankreich", "NL": "Niederlande", "BE": "Belgien", "LU": "Luxemburg",
    "IT": "Italien", "ES": "Spanien", "PT": "Portugal", "IE": "Irland", "DK": "Dänemark", "SE": "Schweden", "NO": "Norwegen", "FI": "Finnland", "IS": "Island", "PL": "Polen",
    "CZ": "Tschechien", "SK": "Slowakei", "HU": "Ungarn", "RO": "Rumänien", "BG": "Bulgarien", "GR": "Griechenland", "TR": "Türkei", "UA": "Ukraine", "RU": "Russland", "BY": "Belarus",
    "LT": "Litauen", "LV": "Lettland", "EE": "Estland", "RS": "Serbien", "HR": "Kroatien", "SI": "Slowenien", "MD": "Moldau", "CY": "Zypern", "MT": "Malta", "CA": "Kanada", "MX": "Mexiko",
    "BR": "Brasilien", "AR": "Argentinien", "CL": "Chile", "CO": "Kolumbien", "PE": "Peru", "VE": "Venezuela", "CN": "China", "HK": "Hongkong", "TW": "Taiwan", "JP": "Japan", "KR": "Südkorea",
    "KP": "Nordkorea", "IN": "Indien", "PK": "Pakistan", "BD": "Bangladesch", "ID": "Indonesien", "VN": "Vietnam", "TH": "Thailand", "MY": "Malaysia", "SG": "Singapur", "PH": "Philippinen",
    "AU": "Australien", "NZ": "Neuseeland", "IR": "Iran", "IQ": "Irak", "IL": "Israel", "SA": "Saudi-Arabien", "AE": "Vereinigte Arabische Emirate", "EG": "Ägypten", "ZA": "Südafrika",
    "NG": "Nigeria", "KE": "Kenia", "MA": "Marokko", "DZ": "Algerien", "TN": "Tunesien", "KZ": "Kasachstan", "GE": "Georgien", "AM": "Armenien", "AZ": "Aserbaidschan", "SC": "Seychellen",
}
_CC = re.compile(r"^[A-Z]{2}$")


def flag(cc: str) -> str:
    """Flaggen-Emoji aus dem Ländercode (zwei Regionalindikator-Zeichen); ohne Code ein neutrales Symbol."""
    cc = (cc or "").upper()
    if not _CC.match(cc):
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)


def network_of(ip: str) -> Optional[str]:
    """Gekürztes Netz zur Adresse: IPv4 -> a.b.c.0, IPv6 -> /48-Netzadresse. None bei ungültiger oder nicht öffentlicher Adresse."""
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if not a.is_global:
        return None
    if a.version == 4:
        return str(ipaddress.ip_address(int(a) & 0xFFFFFF00))
    return str(ipaddress.ip_address(int(a) >> 80 << 80))


def _bootstrap(version: int, fetch: Fetcher, cache: Dict[int, Any]) -> List[Tuple[Any, str]]:
    if version not in cache:
        rows: List[Tuple[Any, str]] = []
        data = json.loads(fetch(BOOT[version]).decode("utf-8", "replace"))
        for prefixes, urls in data.get("services") or []:
            https = [u for u in urls if str(u).startswith("https://")]
            if not https or urlparse(https[0]).hostname not in RDAP_HOSTS:
                continue                                              # nur die fünf Regional-Registries
            for p in prefixes:
                try:
                    rows.append((ipaddress.ip_network(p), https[0]))
                except ValueError:
                    continue
        cache[version] = rows
    return cache[version]


def parse_rdap(doc: Dict[str, Any]) -> Dict[str, str]:
    """Land und Namen aus einer RDAP-Antwort (RFC 9083). Land: Feld 'country' des Netzes, sonst die Adresse der Kontakte (vCard)."""
    cc = str(doc.get("country") or "").upper()
    if not _CC.match(cc):
        cc = ""
    org = ""

    def walk(ents: List[Dict[str, Any]]) -> None:
        nonlocal cc, org
        for e in ents or []:
            vc = (e.get("vcardArray") or [None, []])[1] if isinstance(e.get("vcardArray"), list) and len(e["vcardArray"]) > 1 else []
            for item in vc:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                if item[0] == "fn" and not org and isinstance(item[3], str):
                    org = item[3]
                if item[0] == "adr" and not cc:
                    c = str((item[1] or {}).get("cc") or "").upper() if isinstance(item[1], dict) else ""
                    if not _CC.match(c) and isinstance(item[3], list) and item[3] and isinstance(item[3][-1], str):
                        c = item[3][-1].strip().upper()
                    if _CC.match(c):
                        cc = c
            walk(e.get("entities") or [])

    walk(doc.get("entities") or [])
    return {"cc": cc, "name": str(doc.get("name") or ""), "org": org[:80]}


class Geo:
    """Fragt je Lauf höchstens MAX_NETS Netze ab und merkt sich die Antworten."""

    def __init__(self, fetch: Optional[Fetcher] = None, enabled: Optional[bool] = None):
        self.fetch = fetch or (lambda u: coreref.fetch_bytes(u, 1_000_000, timeout=8))
        self.enabled = (not (os.environ.get("CLAUDIA_OFFLINE") or os.environ.get("CLAUDIA_NO_GEO"))) if enabled is None else enabled
        self.cache: Dict[str, Dict[str, str]] = {}
        self.boot: Dict[int, Any] = {}
        self.started = 0.0
        self.error = ""

    def lookup(self, ip: str) -> Dict[str, str]:
        net = network_of(ip)
        if not net or not self.enabled:
            return {}
        if net in self.cache:
            return self.cache[net]
        if len(self.cache) >= MAX_NETS:
            return {}
        if not self.started:
            self.started = time.monotonic()
        if time.monotonic() - self.started > FETCH_BUDGET:
            return {}
        info: Dict[str, str] = {}
        try:
            addr = ipaddress.ip_address(net)
            base = next((u for n, u in self._rows(addr.version) if addr in n), "")
            if base:
                doc = json.loads(self.fetch("%sip/%s" % (base if base.endswith("/") else base + "/", net)).decode("utf-8", "replace"))
                info = parse_rdap(doc)
                info["registry"] = urlparse(base).hostname or ""
        except (coreref.RefError, ValueError, OSError, TypeError, KeyError) as e:
            self.error = str(e)[:160]
            info = {}
        self.cache[net] = info
        return info

    def _rows(self, version: int) -> List[Tuple[Any, str]]:
        return _bootstrap(version, self.fetch, self.boot)


def label(cc: str) -> str:
    return "%s (%s)" % (COUNTRY_DE.get(cc, cc), cc) if cc else ""
