"""Verschlüsselung: Das Programm baut Verbindungen nur verschlüsselt auf.

- Zum Server: SSH (alle Befehle und Dateien laufen durch den verschlüsselten SSH-Kanal, Dateien wie bei SFTP).
- Zu Webseiten und Online-Quellen: nur https. Einzige Ausnahme ist der eigene Rechner (127.0.0.1/localhost), z. B. für Tests.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Tuple
from urllib.parse import urlparse

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

# Verfahren, die als veraltet gelten. Sie werden zuerst abgeschaltet; geht es nicht anders, wird mit Warnung verbunden.
WEAK_CIPHERS = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256"]
WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]
WEAK_MACS = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"]
WEAK_KEYS = ["ssh-dss"]


def is_loopback(host: str) -> bool:
    h = (host or "").strip("[]").lower()
    if h in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_secure_url(url: str) -> bool:
    """True für https:// und für Adressen auf dem eigenen Rechner."""
    p = urlparse((url or "").strip())
    if p.scheme == "https":
        return True
    return p.scheme == "http" and is_loopback(p.hostname or "")


def to_https(url: str) -> Tuple[str, bool]:
    """Macht aus 'http://...' und 'www.beispiel.de' eine https-Adresse. Rückgabe: (Adresse, wurde_geändert)."""
    u = (url or "").strip()
    if not u:
        return u, False
    if re.match(r"^http://", u, re.I):
        if is_loopback(urlparse(u).hostname or ""):
            return u, False
        return "https://" + u[7:], True
    if "//" not in u:
        return "https://" + u, False
    return u, False


STRICT_DISABLED = {"ciphers": WEAK_CIPHERS, "kex": WEAK_KEX, "macs": WEAK_MACS, "keys": WEAK_KEYS}


def describe_transport(tr) -> dict:
    """Angaben zur SSH-Verschlüsselung aus dem paramiko-Transport (ohne Geheimnisse)."""
    def g(name, default=""):
        try:
            v = getattr(tr, name, default)
            return str(v() if callable(v) else v) if v else default
        except Exception:
            return default
    cipher = g("remote_cipher") or g("local_cipher")
    mac = g("remote_mac") or g("local_mac")
    host_key = ""
    try:
        k = tr.get_remote_server_key()
        host_key = k.get_name() if k else ""
    except Exception:
        pass
    weak = [x for x in (cipher, mac) if x in WEAK_CIPHERS + WEAK_MACS]
    return {"protocol": "SSH-2", "cipher": cipher, "mac": mac, "host_key_type": host_key, "server": g("remote_version"), "weak": weak}
