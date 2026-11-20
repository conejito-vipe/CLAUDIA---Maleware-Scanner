"""WooCommerce-Prüfungen (2.7.0): API-Schlüssel, Webhooks, Zahlungsarten, Shop-Manager und öffentlich abrufbare Shop-Daten. Nur WordPress, nur lesend.

Die Bewertung steckt in auswertung_woo.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen. Ist WooCommerce nicht installiert, werden alle Prüfungen mit einem klaren Hinweis übersprungen.
Geheimnisse: Schlüssel, Geheimwörter und Zugangsdaten werden nie abgefragt. Tabellen- und Optionsnamen von WooCommerce (wc_webhooks, woocommerce_api_keys, woocommerce_*_settings) sind gegen einen echten Shop noch NICHT geprüft;
fehlt eine Tabelle, meldet die Prüfung 'nicht prüfbar' statt zu raten."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..model import CheckSkipped
from ..registry import check
from . import auswertung_woo as aw
from . import web as webmod
from .database import fetch, need_db, parse_dt

G = "erweiterungen"
Q_ACTIVE = "SELECT option_value AS v FROM #__options WHERE option_name = 'active_plugins'"
Q_DBVER = "SELECT option_value AS v FROM #__options WHERE option_name = 'woocommerce_db_version'"
Q_KEYS = ("SELECT k.description AS description, k.permissions AS permissions, k.last_access AS last_access, u.user_login AS owner "
          "FROM #__woocommerce_api_keys k LEFT JOIN #__users u ON u.ID = k.user_id ORDER BY k.key_id LIMIT 300")
Q_HOOKS = "SELECT name, status, topic, delivery_url, failure_count FROM #__wc_webhooks ORDER BY webhook_id LIMIT 300"
Q_GATES = "SELECT option_name AS name, option_value AS v FROM #__options WHERE option_name LIKE 'woocommerce_%_settings' ORDER BY option_name LIMIT 300"
Q_MANAGERS = ("SELECT u.user_login AS login, u.user_registered AS reg FROM #__users u JOIN #__usermeta m ON m.user_id = u.ID "
              "WHERE m.meta_key = '#__capabilities' AND m.meta_value LIKE '%\"shop_manager\"%' ORDER BY u.ID LIMIT 300")


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def woo_info(ctx) -> Dict[str, Any]:
    """Ist WooCommerce installiert, aktiv, welche Version? (einmal je Lauf)"""
    if "woo" in ctx.shared:
        return ctx.shared["woo"]
    out = ctx.sh("test -d wp-content/plugins/woocommerce && echo DA; grep -m1 -iE '^[[:space:]*]*Version:' wp-content/plugins/woocommerce/woocommerce.php 2>/dev/null | head -c 200", timeout=30).out
    info: Dict[str, Any] = {"installed": out.startswith("DA"), "active": False, "version": "", "db_version": ""}
    m = re.search(r"Version:\s*([0-9][0-9A-Za-z.\-]*)", out, re.I)
    if m:
        info["version"] = m.group(1)
    if info["installed"]:
        db = ctx.db()
        if db.ok:
            rows = fetch(db, Q_ACTIVE) or []
            info["active"] = "woocommerce/woocommerce.php" in ((rows[0].get("v") or "") if rows else "")
            rows = fetch(db, Q_DBVER) or []
            info["db_version"] = (rows[0].get("v") or "") if rows else ""
    ctx.shared["woo"] = info
    return info


def need_woo(ctx) -> Dict[str, Any]:
    info = woo_info(ctx)
    if not info["installed"]:
        raise CheckSkipped("WooCommerce ist auf dieser Seite nicht installiert (kein Ordner wp-content/plugins/woocommerce). Es gibt nichts zu prüfen.")
    return info


@check(
    "woo_overview", G, "WooCommerce: Überblick",
    "Ist WooCommerce installiert und aktiv, und ist sein Datenbank-Update durchgelaufen?",
    what="Sucht den Ordner wp-content/plugins/woocommerce, liest die Version aus der Plugin-Datei, prüft in der Datenbank, ob das Plugin aktiv ist, und vergleicht die Version des Plugins mit der Datenbank-Version von WooCommerce.",
    why="Ein Shop sammelt Kundendaten und Zahlungen und ist deshalb ein bevorzugtes Ziel. Ein abgebrochenes Datenbank-Update oder ein ausgeschaltetes, aber vorhandenes Plugin mit alter Version bleiben oft lange unbemerkt.",
    reads="Den Ordnernamen und die Kopfzeile der Plugin-Datei sowie zwei Einträge der Tabelle options (aktive Plugins, woocommerce_db_version). Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def woo_overview(ctx, res):
    need_db(ctx, res, "WooCommerce-Überblick", [("Aktive Plugins", Q_ACTIVE), ("Datenbank-Version", Q_DBVER)])
    info = need_woo(ctx)
    _emit(res, aw.judge_overview(info))


@check(
    "woo_api_keys", G, "WooCommerce: API-Schlüssel",
    "Welche Anwendungen dürfen sich über die WooCommerce-Schnittstelle anmelden, und sind alte oder verwaiste Schlüssel dabei?",
    what="Liest die Liste der REST-API-Schlüssel (Beschreibung, Recht Lesen/Schreiben, letzter Zugriff, Besitzer) und meldet verwaiste, nie benutzte und lange unbenutzte Schlüssel sowie Schlüssel mit Schreibrecht.",
    why="Ein API-Schlüssel mit Schreibrecht ersetzt ein Passwort: Wer ihn hat, kann Bestellungen, Preise und Produkte ändern. Angreifer legen nach einem Einbruch gern einen eigenen Schlüssel an, weil er ein Passwortänderung überlebt.",
    reads="Nur Beschreibung, Recht, Zeitpunkt des letzten Zugriffs und den Anmeldenamen des Besitzers. Die Schlüssel selbst und die Geheimwörter werden nie abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def woo_api_keys(ctx, res):
    db = need_db(ctx, res, "WooCommerce-API-Schlüssel", [("API-Schlüssel", Q_KEYS)])
    need_woo(ctx)
    rows = fetch(db, Q_KEYS)
    if rows is None:
        _emit(res, aw.judge_api_keys(None))
        return
    keys = [{"description": r.get("description"), "permissions": r.get("permissions"), "last_access_ts": parse_dt(r.get("last_access")), "owner": r.get("owner")} for r in rows]
    _emit(res, aw.judge_api_keys(keys))


@check(
    "woo_webhooks", G, "WooCommerce: Webhooks",
    "Schickt der Shop Bestell- oder Kundendaten automatisch an fremde Adressen?",
    what="Liest die eingerichteten Webhooks (Name, Status, Thema, Zieladresse) und prüft, wohin aktive Webhooks Bestell-, Kunden- und Gutscheindaten senden. Auffang-Adressen von Test- und Tunneldiensten, reine IP-Adressen und Empfänger außerhalb der bekannten und erlaubten Adressen werden gemeldet.",
    why="Ein Webhook ist eine Dauerleitung nach draußen: Jede neue Bestellung wird mit Namen, Adresse und E-Mail an den Empfänger geschickt. Angreifer legen so unbemerkt eine Kopie aller Kundendaten an.",
    reads="Name, Status, Thema, Zieladresse und Fehlerzähler der Webhooks. Das Geheimwort des Webhooks wird nie abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def woo_webhooks(ctx, res):
    db = need_db(ctx, res, "WooCommerce-Webhooks", [("Webhooks", Q_HOOKS)])
    need_woo(ctx)
    rows = fetch(db, Q_HOOKS)
    if rows is None:
        _emit(res, aw.judge_webhooks(None))
        return
    hooks = [{"name": r.get("name"), "status": r.get("status"), "topic": r.get("topic"), "url": r.get("delivery_url"), "failure_count": r.get("failure_count")} for r in rows]
    _emit(res, aw.judge_webhooks(hooks, ctx.own_host(), ctx.allow()))


@check(
    "woo_gateways", G, "WooCommerce: Zahlungsarten",
    "Welche Zahlungsarten sind eingeschaltet, laufen sie im Testmodus, und steckt Code in ihren Texten?",
    what="Liest die Einstellungen der Zahlungsarten aus der Tabelle options (woocommerce_*_settings), listet die eingeschalteten auf, meldet Testmodus und sucht in Titeln und Beschreibungen nach eingeschleustem Code (Skripte, javascript:-Adressen).",
    why="Kartendaten werden meist über Skripte im Bezahlvorgang abgegriffen. Ein beliebter Weg ist ein Skript im Beschreibungstext einer Zahlungsart: Es steht in der Datenbank, nicht in einer Datei, und fällt bei einer reinen Dateisuche nicht auf.",
    reads="Die Einstellungs-Einträge der Zahlungsarten aus der Datenbank. Geheimwörter und Schlüssel der Anbieter werden zwar mitgelesen, aber nur nach Schadcode durchsucht und nie ausgegeben oder gespeichert. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def woo_gateways(ctx, res):
    db = need_db(ctx, res, "WooCommerce-Zahlungsarten", [("Zahlungsarten", Q_GATES)])
    need_woo(ctx)
    rows = fetch(db, Q_GATES)
    if rows is None:
        _emit(res, aw.judge_gateways(None))
        return
    gws: List[Dict[str, Any]] = []
    for r in rows:
        name = str(r.get("name") or "")
        raw = r.get("v") or ""
        if not (name.startswith("woocommerce_") and name.endswith("_settings")):
            continue
        # E-Mail- und Versandeinstellungen heißen ähnlich, gehören aber nicht zu den Zahlungsarten
        if any(aw.php_value(raw, k) is not None for k in ("subject", "heading", "cost", "recipient")) or re.search(r"_\d+_settings$", name):
            continue
        if aw.php_value(raw, "enabled") is None:
            continue
        gws.append({"id": name[len("woocommerce_"):-len("_settings")], "enabled": aw.php_value(raw, "enabled"), "raw": raw})
    _emit(res, aw.judge_gateways(gws))


@check(
    "woo_managers", G, "WooCommerce: Konten mit Shop-Rechten",
    "Wer hat die Rolle Shop-Manager, und wurde kürzlich ein neues Konto angelegt?",
    what="Zählt die Konten mit der Rolle Shop-Manager und meldet solche, die in den letzten 14 Tagen angelegt wurden.",
    why="Shop-Manager dürfen Bestellungen, Kundendaten, Produkte und Zahlungseinstellungen ändern. Ein neues, unbekanntes Konto mit dieser Rolle ist ein typischer Dauerzugang nach einem Einbruch.",
    reads="Anmeldenamen und Anlegedatum der Konten mit dieser Rolle. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def woo_managers(ctx, res):
    db = need_db(ctx, res, "WooCommerce-Shop-Manager", [("Shop-Manager", Q_MANAGERS)])
    need_woo(ctx)
    rows = fetch(db, Q_MANAGERS)
    if rows is None:
        _emit(res, aw.judge_shop_managers(None))
        return
    _emit(res, aw.judge_shop_managers([{"login": r.get("login"), "registered_ts": parse_dt(r.get("reg")), "role": "shop_manager"} for r in rows]))


@check(
    "woo_exposed", G, "WooCommerce: frei abrufbare Shop-Daten",
    "Kann jeder Besucher Bestellungen, Kunden oder Protokolle des Shops abrufen?",
    what="Ruft von DIESEM PC aus die Shop-Schnittstelle für Bestellungen und Kunden ohne Anmeldung auf, prüft die Ordner woocommerce_uploads und wc-logs auf eine öffentliche Ordnerliste und versucht, bis zu drei Protokolldateien aus wc-logs abzurufen. Es werden nur normale Seitenaufrufe gesendet.",
    why="Protokolle eines Shops enthalten oft Namen, Adressen und Antworten der Zahlungsanbieter. Die Schnittstelle zu Bestellungen und Kunden muss eine Anmeldung verlangen, sonst liest sie jeder Besucher aus.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht, und die Dateinamen im Ordner wc-logs. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack"], cms="wordpress",
)
def woo_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    need_woo(ctx)
    from .. import secure
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    out = ctx.sh("ls -1 wp-content/uploads/wc-logs 2>/dev/null | head -n 3000", timeout=30).out
    names = [x.strip() for x in out.splitlines() if re.fullmatch(r"[A-Za-z0-9._-]{1,150}", x.strip())]
    logs = [n for n in names if n.lower().endswith(".log")]
    targets = [("api", "Bestell-Schnittstelle", "/wp-json/wc/v3/orders"), ("api", "Kunden-Schnittstelle", "/wp-json/wc/v3/customers"),
               ("dir", "Ordner woocommerce_uploads", "/wp-content/uploads/woocommerce_uploads/"), ("dir", "Ordner wc-logs", "/wp-content/uploads/wc-logs/")]
    targets += [("file", "Protokoll " + n, "/wp-content/uploads/wc-logs/" + n) for n in logs[:3]]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, aw.judge_exposed(web, len(logs) if names or logs else None))
