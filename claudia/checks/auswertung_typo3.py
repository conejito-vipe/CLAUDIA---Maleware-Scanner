"""Bewertung der TYPO3-Prüfungen (2.10.0): reine Funktionen ohne Server-, Datenbank- oder Netzzugriff, mit Beispieldaten prüfbar.

Jede Funktion bekommt einfache Wörterbücher/Listen und liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar'.
Geheimnisse (Passwörter, encryptionKey, Hashes) werden nie gelesen oder ausgegeben; es zählen Namen, Rechte, Zeiten, Versionen und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import typo3
from .auswertung_drupal import judge_db_code as _judge_db_code
from .auswertung_joomla import _clean, _f, _np

Finding = Tuple[str, str, str, List[str], str]

DEV_EXTENSIONS = {"extension_builder", "kickstarter", "devlog", "t3adminer", "adminer", "phpmyadmin", "ke_dev", "debugmail", "tt_address_dev", "coreapi", "typo3_console_dev"}
ADMIN_TOOLS_NOTE = "Werkzeuge zur Entwicklung oder Datenbank-Verwaltung gehören nicht auf eine Live-Seite."


# ------------------------------------------------------------------ Kern
def judge_core(version: str, releases: Any, adv: Any, now: Optional[float] = None, adv_ok: bool = True) -> List[Finding]:
    """version: installierte Version; releases: Liste von typo3.parse_release_list (leer = nicht erreichbar); adv: Sicherheitsmeldungen, die auf diese Version zutreffen (Liste)."""
    if not version:
        return _np("TYPO3-Version", "Die Version konnte nicht aus den Dateien des Kerns gelesen werden.")
    ver = _clean(version, 30)
    mj = typo3.major(version)
    life = typo3.lifecycle(version, now)
    out: List[Finding] = []
    if life["state"] == "ended":
        out.append(_f("crit", "TYPO3 %d wird nicht mehr mit Sicherheitsupdates versorgt" % mj,
                      "Diese Hauptversion hat das Ende der Unterstützung erreicht%s. Neue Sicherheitslücken werden nicht mehr behoben." % (" (am %s)" % life["elts_until"] if life["elts_until"] else ""),
                      [ver], "Auf eine unterstützte Hauptversion umziehen (vorher vollständige Sicherung und Test mit einer Kopie der Seite)."))
    elif life["state"] == "elts":
        out.append(_f("crit", "TYPO3 %d erhält nur noch kostenpflichtige Sicherheitsupdates (ELTS)" % mj,
                      "Die kostenlose Unterstützung endete am %s. Updates gibt es nur noch mit einem ELTS-Vertrag (bis %s)." % (life["free_until"], life["elts_until"]), [ver],
                      "Auf eine unterstützte Hauptversion (TYPO3 %s oder neuer) umziehen oder einen ELTS-Vertrag abschließen." % ("13" if mj < 13 else str(mj + 1))))
    elif life["state"] == "supported" and life["days_left"] is not None and life["days_left"] < 180:
        out.append(_f("warn", "TYPO3 %d: Die kostenlose Unterstützung endet in %d Tagen" % (mj, life["days_left"]), "Ende am %s." % life["free_until"], [ver], "Den Umzug auf die nächste Hauptversion jetzt planen."))
    elif life["state"] == "unknown":
        out.append(_f("info", "TYPO3 %s: Laufzeit der Hauptversion unbekannt" % ver, "Für diese Hauptversion enthält das Programm keine Angaben zum Support-Ende (Stand der Tabelle: %s)." % typo3.LIFECYCLE_ASOF))
    hits = [a for a in (adv or []) if isinstance(a, dict)]
    if hits:
        out.append(_f("crit", "Für TYPO3 %s sind %d Sicherheitsmeldung(en) bekannt" % (ver, len(hits)),
                      "Die Version liegt im betroffenen Bereich dieser Meldungen (Quelle: Packagist, Sicherheitsmeldungen des TYPO3-Teams). Sie ist dort als verwundbar geführt.",
                      ["%s %s%s" % (_clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 90), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else "") for a in hits[:15]]
                      + (["... und %d weitere" % (len(hits) - 15)] if len(hits) > 15 else []),
                      "Auf die neueste Version dieser Hauptversion aktualisieren (vorher Sicherung)."))
    rel = [r for r in (releases or []) if isinstance(r, dict) and typo3.major(r["version"]) == mj]
    if rel:
        latest = max((r["version"] for r in rel), key=typo3.version_key)
        if typo3.version_key(latest) > typo3.version_key(version) and not re.search(r"-", version):
            out.append(_f("crit" if hits else "warn", "TYPO3 %s ist nicht die neueste Version" % ver, "Neueste Version dieser Hauptversion: %s." % _clean(latest, 30), [],
                          "Beim nächsten Wartungsfenster aktualisieren (vorher Sicherung)." if not hits else "Sofort aktualisieren (vorher Sicherung)."))
        elif not hits and life["state"] == "supported":
            out.append(_f("ok", "TYPO3 %s ist auf dem neuesten Stand" % ver, "Neueste bekannte Version dieser Hauptversion: %s." % _clean(latest, 30)))
    elif not hits and life["state"] != "ended":
        out.append(_f("info", "TYPO3 %s: Aktualität nicht prüfbar" % ver, "Die Liste der Veröffentlichungen von get.typo3.org war nicht erreichbar oder nicht lesbar."))
    if not adv_ok:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares. Ob für diese Version Sicherheitsmeldungen vorliegen, ist offen.", [],
                      "Auf typo3.org/help/security-advisories nachsehen."))
    return out


def judge_core_files(ref_count: int, changed: List[str], missing: List[str], extra: List[str], source: str = "", composer: bool = False) -> List[Finding]:
    """Ergebnis des Dateivergleichs der Systemerweiterungen (typo3/sysext) mit dem Original-Paket. Bei Composer-Installationen fehlen im Paket mancher Erweiterungen Dateien
    (Tests, Dokumentation), deshalb zählen dort fehlende Dateien nicht."""
    out: List[Finding] = []
    total = max(1, ref_count)
    if composer:
        missing = []
    if (len(changed) + len(missing)) / total > 0.35:
        return [_f("warn", "Sehr viele Dateien der Systemerweiterungen weichen ab (%d von %d)" % (len(changed) + len(missing), total),
                   "Das spricht für eine angepasste Version, einen Fork oder ein unpassendes Paket als Vergleich, nicht für einen Einzelangriff. " + source, [],
                   "Prüfen, welche Version wirklich installiert ist.")]
    php_extra = [p for p in extra if re.search(r"\.(php\d?|phtml|pht|phar|inc)$", p, re.I)]
    other_extra = [p for p in extra if p not in php_extra]
    if php_extra:
        out.append(_f("crit", "%d unbekannte PHP-Datei(en) in den Systemerweiterungen" % len(php_extra),
                      "In typo3/sysext liegen PHP-Dateien, die nicht zum Original gehören. Das ist ein typischer Ablageort für Hintertüren. " + source,
                      php_extra[:40], "Datei ansehen; wenn sie nicht von Ihnen oder einem bekannten Patch stammt, sichern und entfernen und die Zugangsdaten erneuern."))
    if changed:
        out.append(_f("warn", "%d Datei(en) der Systemerweiterungen weichen vom Original ab" % len(changed), "Das kann ein bewusster Patch (cweagans/composer-patches) sein oder eine Manipulation. " + source,
                      changed[:40], "Ist kein Patch bekannt: Datei gegen das Original vergleichen und den Kern neu einspielen (composer install bzw. Paket von get.typo3.org)."))
    if missing:
        out.append(_f("warn", "%d Datei(en) der Systemerweiterungen fehlen" % len(missing), "Fehlende Dateien deuten auf ein unvollständiges Update oder auf entfernte Dateien hin.", missing[:40], "Kern neu einspielen."))
    if other_extra:
        out.append(_f("info", "%d zusätzliche Datei(en) in den Systemerweiterungen (ohne Programmcode)" % len(other_extra), "Sie können nichts ausführen und sind meist harmlos.", other_extra[:40]))
    if not out:
        out.append(_f("ok", "Alle Dateien der Systemerweiterungen stimmen mit dem Original überein", "%d Dateien verglichen. %s" % (ref_count, source)))
    return out


# ------------------------------------------------------------------ Einstellungen
def judge_settings(cfg: Any, modes: Optional[Dict[str, str]] = None, install_tool: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """cfg: Ergebnis von typo3.parse_settings (+ 'missing'); modes: {'Pfad': '444 user'} (stat-Ausgabe); install_tool: {'path': ..., 'age_s': Sekunden} wenn die Datei ENABLE_INSTALL_TOOL liegt."""
    if not isinstance(cfg, dict) or cfg.get("missing"):
        return _np("TYPO3-Einstellungsdatei", "Die Datei config/system/settings.php (bzw. typo3conf/system/settings.php oder typo3conf/LocalConfiguration.php) wurde nicht gefunden.")
    if not cfg.get("parsed"):
        return _np("TYPO3-Einstellungsdatei", "Die Datei ließ sich nicht als Liste von Einstellungen lesen (andere Schreibweise oder beschädigt). Die Werte wurden nicht bewertet.")
    t = cfg.get("typo3") or {}
    sysd, bed, fed = t.get("SYS") or {}, t.get("BE") or {}, t.get("FE") or {}
    out: List[Finding] = []
    if cfg.get("unexpected"):
        out.append(_f("crit", "In den Einstellungsdateien stehen auffällige Befehle", "Dort gehören nur Einstellungen hin. Befehle wie eval oder base64_decode sind ein typisches Zeichen für eine Manipulation.",
                      ["Zeile %s: %s" % (n, _clean(x, 160)) for n, x in cfg["unexpected"][:20]], "Datei mit einer Sicherung vergleichen, Zugangsdaten und encryptionKey erneuern."))
    de = sysd.get("displayErrors")
    if de in (1, "1", True):
        out.append(_f("warn", "Fehlermeldungen werden den Besuchern angezeigt (displayErrors = 1)", "Meldungen verraten Pfade, Datenbank-Namen und Programmteile.", [],
                      "In den Einstellungen SYS/displayErrors auf 0 setzen (im Install-Tool unter Einstellungen > Konfigurationsvorgaben)."))
    mask = str(sysd.get("devIPmask") or "").strip()
    if mask == "*":
        out.append(_f("crit", "Debug-Ausgaben sind für alle Besucher eingeschaltet (devIPmask = *)", "Mit diesem Wert bekommen alle Besucher Fehlerdetails und Entwickler-Hinweise zu sehen.", [],
                      "SYS/devIPmask leeren oder auf die eigene Adresse beschränken."))
    elif mask and mask not in ("127.0.0.1,::1", "127.0.0.1", "::1"):
        out.append(_f("info", "devIPmask ist gesetzt", "Die Debug-Ausgaben gelten für die dort eingetragenen Adressen. Prüfen Sie, ob das gewollt ist.", [_clean(mask, 80)]))
    th = sysd.get("trustedHostsPattern")
    if isinstance(th, str) and th.strip() in (".*", ".+", ""):
        out.append(_f("warn", "trustedHostsPattern erlaubt jeden Hostnamen", "Ohne Einschränkung akzeptiert TYPO3 Anfragen unter jedem Hostnamen (Host-Header-Angriffe, gefälschte Links in E-Mails).", [],
                      "In den Einstellungen SYS/trustedHostsPattern auf die eigene Domain setzen (z. B. 'beispiel\\.de|www\\.beispiel\\.de')."))
    elif th is None:
        out.append(_f("info", "trustedHostsPattern ist in der Datei nicht gesetzt", "Es gilt dann der Standard des Systems. Prüfen Sie im Install-Tool, welcher Wert gilt.", []))
    if not cfg.get("has_key"):
        out.append(_f("crit", "Der encryptionKey fehlt oder ist leer", "Der Schlüssel schützt Formulare, Sitzungen und Zugriffe. Ohne ihn ist die Installation nicht sicher.", [], "Im Install-Tool einen neuen Schlüssel erzeugen."))
    elif cfg.get("key_len", 0) < 64:
        out.append(_f("warn", "Der encryptionKey ist kurz (%d Zeichen)" % cfg.get("key_len", 0), "TYPO3 erzeugt Schlüssel mit 96 Zeichen. Kürzere Schlüssel sind leichter zu erraten.", [], "Im Install-Tool einen neuen Schlüssel erzeugen."))
    if bed.get("debug") in (True, 1, "1") or fed.get("debug") in (True, 1, "1"):
        out.append(_f("warn", "Der Debug-Modus ist eingeschaltet (%s)" % " und ".join(n for n, d in (("BE/debug", bed), ("FE/debug", fed)) if d.get("debug") in (True, 1, "1")),
                      "Im Debug-Modus zeigt TYPO3 Interna und Hinweise, die Angreifern helfen.", [], "Auf false setzen."))
    ph = str(_clean(str(((bed.get("passwordHashing") or {}) if isinstance(bed.get("passwordHashing"), dict) else {}).get("className") or ""), 160))
    if re.search(r"Md5|Phpass|Salted|Blowfish", ph, re.I):
        out.append(_f("warn", "Passwörter werden mit einem veralteten Verfahren gespeichert", "Das Verfahren %s gilt als schwach." % ph, [], "BE/passwordHashing auf Argon2id oder Bcrypt stellen (Standard der aktuellen Versionen)."))
    if install_tool:
        age = install_tool.get("age_s")
        old = isinstance(age, (int, float)) and age > 3600
        out.append(_f("crit" if old else "warn", "Das Install-Tool ist freigeschaltet", "Die Datei ENABLE_INSTALL_TOOL liegt auf dem Server%s. Solange sie liegt, kann sich jeder mit dem Install-Tool-Passwort anmelden und die Seite übernehmen." % (
            " (seit mehr als einer Stunde)" if old else ""), [_clean(str(install_tool.get("path") or "ENABLE_INSTALL_TOOL"), 120)], "Die Datei löschen, sobald die Arbeit im Install-Tool fertig ist."))
    if cfg.get("has_additional"):
        out.append(_f("info", "Eine zusätzliche Einstellungsdatei (additional.php) überschreibt Werte", "Ihre Werte wurden nicht ausgewertet (sie kann Umgebungsvariablen und Bedingungen enthalten); sie wurde nur auf auffällige Befehle gelesen.", []))
    for name, mode in (modes or {}).items():
        m = re.match(r"^(\d{3,4})\b", mode or "")
        if not m:
            continue
        octal = m.group(1)[-3:]
        if int(octal[2]) & 2:
            out.append(_f("crit", "%s ist für alle beschreibbar (%s)" % (name, octal), "Jeder Benutzer des Servers kann sie ändern.", [], "Rechte auf 640 bzw. 644 (Datei) und 755 (Ordner) setzen."))
        elif int(octal[1]) & 2 and name.endswith(".php"):
            out.append(_f("warn", "%s ist für die Gruppe beschreibbar (%s)" % (name, octal), "", [], "Rechte auf 644 setzen."))
    if not out:
        out.append(_f("ok", "Die Einstellungsdatei ist unauffällig", "Keine auffälligen Befehle, Fehlermeldungen aus, Hostnamen eingeschränkt, Schlüssel gesetzt, Install-Tool gesperrt."))
    return out


# ------------------------------------------------------------------ Erweiterungen
def judge_extensions(inventory: Any, adv_hits: Any, checked: int = 0, adv_ok: bool = True) -> List[Finding]:
    """inventory: [{'key','name','version','state','pkg'(Composer-Name oder ''),'custom'(bool)}]; adv_hits: {Schlüssel: [Meldungen]} (nur zutreffende); checked: so viele Pakete wurden abgefragt."""
    if not isinstance(inventory, list):
        return _np("TYPO3-Erweiterungen", "Die Liste der Erweiterungen fehlt oder ist unlesbar.")
    inv = [m for m in inventory if isinstance(m, dict) and m.get("key")]
    if not inv:
        return [_f("info", "Keine Erweiterungen gefunden", "Unter typo3conf/ext, packages und vendor/composer wurden keine Erweiterungen gelesen.")]
    hits = adv_hits if isinstance(adv_hits, dict) else {}
    out: List[Finding] = []

    def lab(m: Dict[str, Any]) -> str:
        return "%s %s" % (_clean(m.get("name") or m["key"], 60), _clean(m.get("version") or "?", 30))

    vuln = [m for m in inv if hits.get(m["key"])]
    if vuln:
        items: List[str] = []
        for m in vuln:
            for a in hits[m["key"]][:3]:
                items.append("%s: %s %s%s" % (lab(m), _clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 80), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else ""))
        out.append(_f("crit", "%d Erweiterung(en) in einer Version mit bekannter Sicherheitslücke" % len(vuln), "Die installierten Versionen liegen im betroffenen Bereich veröffentlichter Sicherheitsmeldungen (Packagist, TYPO3-Sicherheitsteam).",
                      items[:25], "Auf die in der Meldung genannte Version aktualisieren oder die Erweiterung entfernen (vorher Sicherung)."))
    obsolete = [m for m in inv if str(m.get("state") or "").lower() == "obsolete"]
    if obsolete:
        out.append(_f("warn", "%d Erweiterung(en) sind vom Autor als überholt (obsolete) gekennzeichnet" % len(obsolete), "Für sie ist keine Pflege mehr zu erwarten.", [lab(m) for m in obsolete], "Ersatz suchen oder entfernen."))
    dev = [m for m in inv if m["key"] in DEV_EXTENSIONS]
    if dev:
        out.append(_f("warn", "%d Entwicklungs- oder Verwaltungs-Erweiterung(en) liegen auf dem Server" % len(dev), ADMIN_TOOLS_NOTE, [lab(m) for m in dev], "Entfernen oder zumindest deinstallieren."))
    unchecked = [m for m in inv if not m.get("pkg") and not m.get("custom")]
    if unchecked:
        out.append(_f("info", "%d Erweiterung(en): Sicherheitsmeldungen nicht abgleichbar" % len(unchecked),
                      "Ohne Composer-Paketnamen lässt sich keine Meldung zuordnen (klassische Installation). Die Liste der Meldungen steht auf typo3.org/help/security-advisories.", [lab(m) for m in unchecked][:40],
                      "Die Versionen dort einmal mit den Meldungen vergleichen."))
    custom = [m for m in inv if m.get("custom")]
    if custom:
        out.append(_f("info", "%d eigene Erweiterung(en) (lokale Pakete)" % len(custom), "Eigene Programme werden nicht mit Sicherheitsmeldungen verglichen; sie wurden nur von den Dateisuchen geprüft.", [lab(m) for m in custom][:40]))
    if not adv_ok and checked:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares.", [], "Später erneut prüfen."))
    if not (vuln or obsolete or dev):
        out.append(_f("ok" if checked and adv_ok else "info", "Keine Erweiterung mit bekannter Sicherheitslücke gefunden" if checked and adv_ok else "Es wurde keine Erweiterung gegen Sicherheitsmeldungen geprüft",
                      "%d Paket(e) abgeglichen." % checked if checked else "Es lagen keine Paketnamen vor.", []))
    return out


# ------------------------------------------------------------------ Konten
def judge_users(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'uid','name','admin'(bool),'disabled'(bool),'created_ts','access_ts'}] aus der Tabelle be_users (Backend-Benutzer)."""
    if not isinstance(rows, list):
        return _np("TYPO3-Backend-Konten", "Die Benutzerliste fehlt oder ist unlesbar.")
    now = now or time.time()
    us = [r for r in rows if isinstance(r, dict)]
    admins = [r for r in us if r.get("admin") and not r.get("disabled")]
    out: List[Finding] = []
    if not admins:
        out.append(_f("info", "Keine aktiven Administrator-Konten gefunden", "Die Abfrage lieferte keine Benutzer mit dem Administrator-Merkmal."))
    else:
        out.append(_f("info", "%d aktive(s) Administrator-Konto/Konten im Backend" % len(admins), "Administratoren dürfen Erweiterungen, Rechte und Inhalte ändern.",
                      ["%s (uid %s)" % (_clean(str(r.get("name") or "?"), 60), r.get("uid")) for r in admins[:30]], "Nicht mehr gebrauchte Konten sperren."))
        if len(admins) > 5:
            out.append(_f("warn", "Auffällig viele Administrator-Konten (%d)" % len(admins), "Je mehr Administratoren, desto mehr Zugänge, über die ein Passwort verloren gehen kann.", [], "Die meisten auf normale Redakteurs-Rechte zurückstufen."))
    fresh = [r for r in admins if isinstance(r.get("created_ts"), (int, float)) and now - r["created_ts"] < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Administrator-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh), "Nach einem Einbruch legen Angreifer gern ein neues Konto mit Administratorrechten an.",
                      [_clean(str(r.get("name") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder Ihr Team das Konto angelegt haben. Wenn nicht: sperren und alle Passwörter ändern."))
    never = [r for r in admins if not r.get("access_ts")]
    if never:
        out.append(_f("info", "%d Administrator-Konto/Konten haben sich nie angemeldet" % len(never), "Ein nie benutztes Konto mit Administratorrechten ist unnötiges Risiko.", [_clean(str(r.get("name") or "?"), 60) for r in never], "Sperren oder Rechte entziehen."))
    default = [r for r in admins if str(r.get("name") or "").lower() in ("admin", "administrator", "typo3", "root", "test")]
    if default:
        out.append(_f("warn", "Administrator-Konto mit einem leicht zu erratenden Namen", "Namen wie admin werden bei Angriffen als Erstes durchprobiert.", [_clean(str(r.get("name") or "?"), 60) for r in default], "Konto umbenennen oder ein neues mit anderem Namen anlegen und das alte sperren."))
    return out


# ------------------------------------------------------------------ Eingeschleuster Code in Inhalten
def judge_db_code(rows: Any) -> List[Finding]:
    """rows: [{'table','id','text'}]: gleiche Bewertung wie bei Drupal (Skript-, Iframe- und Verschleierungsmuster), mit TYPO3-Bezeichnung."""
    return _judge_db_code(rows, "TYPO3")


# ------------------------------------------------------------------ Abrufbare Dateien und Schnittstellen
def judge_exposed(web: Any) -> List[Finding]:
    """web: [{'kind','label','url','status','body'}]; kind: file (darf nicht lesbar sein), dir (keine Ordnerliste), install (Install-Tool), backend (Anmeldeseite, nur Hinweis)."""
    if not isinstance(web, list):
        return _np("Abrufbare TYPO3-Dateien", "Die Abruf-Ergebnisse fehlen.")
    crit, warn, info = [], [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") != 200:
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 70), _clean(str(r.get("url") or ""), 160))
        k = r.get("kind")
        low = body.lstrip().lower()
        if k == "file":
            if body.strip() and not low.startswith(("<!", "<html")) and re.search(r"<\?php|encryptionKey|'Connections'|\"require\"|\"packages\"|APP_ENV|DB_PASSWORD|TYPO3_CONF_VARS|TYPO3_CONTEXT|\[core\]", body):
                crit.append(lab + " ist abrufbar")
        elif k == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif k == "install":
            if re.search(r"Installing TYPO3|Choose a (database|language)|first installation|FIRST_INSTALL", body, re.I):
                crit.append(lab + " zeigt den Installations-Assistenten")
            elif re.search(r"install\s*tool", body, re.I) and re.search(r'type="password"|name="install\[password\]"', body, re.I) and not re.search(r"locked|ENABLE_INSTALL_TOOL", body, re.I):
                warn.append(lab + " zeigt die Anmeldung des Install-Tools (nicht gesperrt)")
        elif k == "backend":
            info.append(lab + " ist erreichbar")
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Datei(en) oder Seite(n) sind frei abrufbar" % len(crit), "Einstellungen, Zugangsdaten oder der Installations-Assistent dürfen von außen nicht zu erreichen sein.", crit,
                      "Zugriff im Webserver sperren (Require all denied / Regel für die Datei bzw. den Ordner) und Zugriffe in den Protokollen prüfen."))
    if warn:
        out.append(_f("warn", "%d Adresse(n) sollten von außen nicht offen sein" % len(warn), "Ordnerlisten zeigen, welche Dateien dort liegen; ein offenes Install-Tool lädt zu Passwort-Versuchen ein.", warn,
                      "Ordnerlisten abschalten (Options -Indexes); die Datei ENABLE_INSTALL_TOOL löschen bzw. den Zugriff auf /typo3/install.php einschränken."))
    if info:
        out.append(_f("info", "Die Backend-Anmeldung ist öffentlich erreichbar", "Das ist normal. Zusätzlicher Schutz (Zugriff nur von bestimmten Adressen, Zwei-Faktor-Anmeldung) senkt das Risiko von Passwort-Versuchen.", info))
    if not (crit or warn):
        out.append(_f("ok", "Keine der geprüften Dateien und Seiten ist frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    return out
