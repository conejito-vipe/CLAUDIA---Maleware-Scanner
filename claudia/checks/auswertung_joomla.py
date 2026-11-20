"""CLAUDIA: reine Auswertefunktionen für Joomla-Einstellungen und Konten (Paket A).

Jede Funktion bekommt schon eingelesene Daten und gibt eine Liste von Befunden zurück:
    List[Tuple[sev, titel, text, items, hint]]
Es wird nichts gelesen, nichts verändert und keine Uhr benutzt. Die Funktionen stürzen nie ab:
Bei unbrauchbarer Eingabe kommt genau ein Befund der Stufe "info" ("... nicht prüfbar").
"""
from __future__ import annotations

import datetime
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

Finding = Tuple[str, str, str, List[str], str]

_EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F]")
_HEX_LONG = re.compile(r"[0-9a-fA-F]{32,}")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _clean(value: Any, limit: int = 100) -> str:
    """Eingegebenen Text für die Ausgabe säubern: keine Steuerzeichen, Emojis, Gedankenstriche, langen Hex-Ketten."""
    if not isinstance(value, str):
        return ""
    t = _CTRL.sub(" ", value)
    t = _EMOJI.sub("", t)
    t = t.replace("\u2014", "-").replace("\u2013", "-")
    t = _HEX_LONG.sub("(Kette entfernt)", t)
    t = re.sub(r"(?i)claudia", "CLAUDIA", t)
    t = " ".join(t.split())
    if len(t) > limit:
        t = t[: limit - 3].rstrip() + "..."
    return t


def _cap(items: List[str]) -> List[str]:
    """Höchstens 60 Einträge mit je höchstens 300 Zeichen."""
    out = [i if len(i) <= 300 else i[:297] + "..." for i in items]
    if len(out) > 60:
        rest = len(out) - 59
        out = out[:59] + ["... und %d weitere" % rest]
    return out


def _f(sev: str, title: str, text: str = "", items: Optional[List[str]] = None, hint: str = "") -> Finding:
    t = title if len(title) <= 120 else title[:117] + "..."
    return (sev, t, text, _cap(list(items or [])), hint)


def _np(was: str, grund: str) -> List[Finding]:
    """Genau ein Hinweis, wenn die Eingabe unbrauchbar ist."""
    return [_f("info", "%s nicht prüfbar" % was, grund)]


def _to_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and math.isfinite(v) and v == int(v):
        return int(v)
    if isinstance(v, str) and re.fullmatch(r"\s*-?\d{1,9}\s*", v):
        return int(v)
    return None


def _to_flag(v: Any) -> Optional[bool]:
    """'1'/'0', 1/0, True/False, 'true'/'false' -> bool, sonst None."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
    return None


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


def _group_label(title: str, gid: Optional[int]) -> str:
    if gid is None:
        return title
    return "%s (Gruppen-ID %d)" % (title, gid) if title else "Gruppen-ID %d" % gid


_DEFAULT_GROUPS = {1: "Public", 2: "Registered", 3: "Author", 4: "Editor", 5: "Publisher", 6: "Manager",
                   7: "Administrator", 8: "Super Users", 9: "Guest"}


# ---------------------------------------------------------------------------
# 1. Textfilter
# ---------------------------------------------------------------------------

_RISKY_TAGS = ("script", "iframe", "object", "embed")
_FILTER_TYPES = ("BL", "CBL", "WL", "NH", "NONE")


def judge_textfilter(rows):
    """Textfilter je Benutzergruppe (Joomla: Globale Konfiguration, Reiter Textfilter)."""
    if not isinstance(rows, list):
        return _np("Textfilter der Benutzergruppen", "Die Angaben zu den Textfiltern fehlen oder sind unlesbar.")
    valid = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        gid = _to_int(r.get("group_id"))
        ft = r.get("filter_type")
        if gid is None or not isinstance(ft, str) or not ft.strip():
            continue
        title = _clean(r.get("title"), 80) or _DEFAULT_GROUPS.get(gid, "Gruppe")
        tags = r.get("filter_tags") if isinstance(r.get("filter_tags"), str) else ""
        attrs = r.get("filter_attributes") if isinstance(r.get("filter_attributes"), str) else ""
        valid.append((gid, title, ft.strip().upper(), tags, attrs))
    if not valid:
        return _np("Textfilter der Benutzergruppen", "Es sind keine lesbaren Angaben zu Benutzergruppen vorhanden.")
    valid.sort(key=lambda v: (v[0], v[1]))

    out: List[Finding] = []
    no_filter = [v for v in valid if v[2] == "NONE" and v[0] != 8]
    if no_filter:
        out.append(_f(
            "warn", "Textfilter ist für %d Benutzergruppe(n) ausgeschaltet" % len(no_filter),
            "Ohne Filter darf eingegebener Text beliebigen Code enthalten, etwa Skripte. "
            "Wird ein Konto dieser Gruppen missbraucht, kann Schadcode in Ihre Seiten gelangen. "
            "Nur bei Super Users ist ein ausgeschalteter Filter normal.",
            [_group_label(v[1], v[0]) for v in no_filter],
            "In Joomla unter Globale Konfiguration, Reiter Textfilter, bei diesen Gruppen die Standard-Sperrliste einstellen."))
    risky = []
    for gid, title, ft, tags, attrs in valid:
        if ft == "WL":
            found = sorted(set(re.split(r"[,\s;]+", tags.lower())) & set(_RISKY_TAGS))
            if found:
                risky.append("%s: %s" % (_group_label(title, gid), ", ".join(found)))
    if risky:
        out.append(_f(
            "warn", "Positivliste erlaubt riskante Tags",
            "Die Positivliste erlaubt für diese Gruppen Tags, mit denen Fremdcode eingebunden werden kann (script, iframe, object, embed).",
            risky,
            "Diese Tags aus der Positivliste entfernen, wenn sie nicht zwingend gebraucht werden."))
    unclear = []
    for gid, title, ft, tags, attrs in valid:
        if ft == "CBL" and not tags.strip() and not attrs.strip():
            unclear.append("%s: eigene Sperrliste ohne Einträge" % _group_label(title, gid))
        elif ft not in _FILTER_TYPES:
            unclear.append("%s: unbekannter Filtertyp" % _group_label(title, gid))
    if unclear:
        out.append(_f(
            "info", "Textfilter nicht eindeutig bewertbar",
            "Bei diesen Gruppen lässt sich aus den Einstellungen nicht sicher sagen, wie streng gefiltert wird.",
            unclear,
            "Prüfen Sie die Einstellung in der Globalen Konfiguration. Im Zweifel die Standard-Sperrliste wählen."))
    if not out:
        return [_f("ok", "Textfilter der Benutzergruppen ist in Ordnung",
                   "Es wurden %d Gruppen geprüft. Es ist kein ausgeschalteter Filter und keine riskante Positivliste aufgefallen." % len(valid))]
    return out


# ---------------------------------------------------------------------------
# 2. Upload-Endungen
# ---------------------------------------------------------------------------

_EXT_CRIT = frozenset(["php", "php3", "php4", "php5", "php6", "php7", "php8", "phtml", "phar", "pht", "phps", "inc",
                       "cgi", "pl", "py", "sh", "exe", "bat", "asp", "aspx", "jsp"])
_EXT_WARN = frozenset(["html", "htm", "js", "svg", "swf", "xml"])


def _ext_list(v: Any) -> Optional[List[str]]:
    if isinstance(v, str):
        parts = v.split(",")
    elif isinstance(v, (list, tuple)):
        parts = [p for p in v if isinstance(p, str)]
    else:
        return None
    out = []
    for p in parts:
        e = p.strip().lstrip(".").strip().lower()
        if e:
            out.append(e)
    return out


def judge_upload_ext(params):
    """Erlaubte Upload-Endungen der Joomla-Medien (com_media-Parameter als Dict)."""
    if not isinstance(params, dict):
        return _np("Upload-Endungen", "Die Medien-Einstellungen fehlen oder sind unlesbar.")
    allowed = _ext_list(params.get("upload_extensions"))
    ignored = _ext_list(params.get("ignore_extensions"))
    restrict = _to_flag(params.get("restrict_uploads"))
    mime = _to_flag(params.get("check_mime"))
    if allowed is None and ignored is None and restrict is None and mime is None:
        return _np("Upload-Endungen", "In den Medien-Einstellungen wurden keine lesbaren Angaben gefunden.")

    out: List[Finding] = []
    bad_up = sorted(set(allowed or []) & _EXT_CRIT)
    if bad_up:
        out.append(_f(
            "crit", "Gefährliche Dateiendungen dürfen hochgeladen werden",
            "Dateien mit diesen Endungen können auf dem Server als Programm ausgeführt werden. "
            "Wer sie hochladen kann, kann damit die ganze Seite übernehmen.",
            bad_up,
            "Diese Endungen sofort aus der Liste der erlaubten Endungen (Medien-Optionen) streichen."))
    bad_ign = sorted(set(ignored or []) & _EXT_CRIT)
    if bad_ign:
        out.append(_f(
            "crit", "Gefährliche Endungen stehen in der Ausnahmeliste",
            "Die Ausnahmeliste nimmt Endungen von den Upload-Prüfungen aus. Gefährliche Endungen gehören dort nicht hinein.",
            bad_ign,
            "Diese Endungen aus der Ausnahmeliste der Medien-Optionen entfernen."))
    warn_up = sorted(set(allowed or []) & _EXT_WARN)
    if warn_up:
        out.append(_f(
            "warn", "Dateitypen mit möglichem Schadcode sind für Uploads erlaubt",
            "Diese Dateien können Skripte enthalten, die im Browser Ihrer Besucher laufen, etwa um Anmeldedaten zu stehlen.",
            warn_up,
            "Diese Endungen aus der Liste der erlaubten Endungen streichen, wenn sie nicht gebraucht werden."))
    if restrict is False:
        out.append(_f(
            "warn", "Die Prüfung der Upload-Endungen ist abgeschaltet",
            "Ist die Beschränkung der Uploads aus, wird die Liste der erlaubten Endungen unter Umständen nicht durchgesetzt.",
            [],
            "In den Medien-Optionen die Beschränkung der Uploads wieder einschalten."))
    if mime is False:
        out.append(_f(
            "info", "Die Prüfung des Dateityps (MIME) ist abgeschaltet",
            "MIME ist die Kennung, an der sich der wahre Dateityp erkennen lässt. Ohne Prüfung fallen umbenannte Dateien eher durch.",
            [],
            "In den Medien-Optionen die Prüfung des Dateityps einschalten."))
    if allowed is None:
        out.append(_f("info", "Liste der erlaubten Endungen nicht lesbar",
                      "Die Liste der erlaubten Upload-Endungen fehlt in den Angaben und konnte nicht bewertet werden."))
    if not out:
        return [_f("ok", "Upload-Endungen sind in Ordnung",
                   "In der Liste der erlaubten Endungen steht nichts, was als gefährlich bekannt ist.")]
    return out


# ---------------------------------------------------------------------------
# 3. Registrierung
# ---------------------------------------------------------------------------

def judge_registration(params, groups):
    """Benutzer-Registrierung (com_users-Parameter) und die Gruppe der neuen Konten."""
    if not isinstance(params, dict):
        return _np("Benutzer-Registrierung", "Die Einstellungen zur Registrierung fehlen oder sind unlesbar.")
    allow = _to_flag(params.get("allowUserRegistration"))
    if allow is None:
        return _np("Benutzer-Registrierung", "Ob Besucher sich selbst registrieren dürfen, ist aus den Angaben nicht erkennbar.")
    if not allow:
        return [_f("ok", "Selbst-Registrierung ist ausgeschaltet",
                   "Neue Konten können nur von Ihnen angelegt werden.")]

    gid = _to_int(params.get("new_usertype"))
    act_raw = params.get("useractivation")
    act = _to_int(act_raw)
    info_map: Dict[int, Tuple[str, Optional[bool]]] = {}
    if isinstance(groups, list):
        for g in groups:
            if not isinstance(g, dict):
                continue
            i = _to_int(g.get("id"))
            if i is None:
                continue
            bl = g.get("backend_login")
            info_map[i] = (_clean(g.get("title"), 80) or _DEFAULT_GROUPS.get(i, "Gruppe"), bl if isinstance(bl, bool) else None)

    out: List[Finding] = []
    unknown_group = False
    if gid is None:
        unknown_group = True
    else:
        title, backend = info_map.get(gid, (_DEFAULT_GROUPS.get(gid, ""), None))
        label = _group_label(title, gid)
        if gid not in info_map and gid not in _DEFAULT_GROUPS:
            unknown_group = True
        elif backend is True:
            out.append(_f(
                "crit", "Neue Konten erhalten Zugang zum Verwaltungsbereich",
                "Jeder Besucher kann sich selbst registrieren und landet dabei in einer Gruppe, die sich im Verwaltungsbereich (Backend) anmelden darf. "
                "Das ist ein klares Einfallstor.",
                [label],
                "Die Standardgruppe für neue Benutzer auf Registered stellen oder die Selbst-Registrierung ausschalten."))
        elif gid in (3, 4, 5):
            out.append(_f(
                "warn", "Neue Konten erhalten Redakteursrechte",
                "Jeder Besucher kann sich selbst registrieren und bekommt dabei Rechte zum Schreiben oder Veröffentlichen von Inhalten.",
                [label],
                "Die Standardgruppe für neue Benutzer auf Registered stellen."))
        elif gid in (6, 7, 8) and backend is None:
            out.append(_f(
                "warn", "Neue Konten erhalten Verwaltungsrechte",
                "Jeder Besucher kann sich selbst registrieren und landet dabei in einer Gruppe mit weitreichenden Rechten. "
                "Ob die Gruppe den Verwaltungsbereich nutzen darf, war nicht ermittelbar.",
                [label],
                "Die Standardgruppe für neue Benutzer auf Registered stellen."))
    if act == 0:
        out.append(_f(
            "warn", "Neue Konten werden ohne Aktivierung freigeschaltet",
            "Wer sich registriert, kann sofort loslegen, auch mit erfundener E-Mail-Adresse. Das lockt Spam-Konten an.",
            [],
            "Die Aktivierung per E-Mail oder durch den Administrator einstellen."))
    if unknown_group:
        out.append(_f(
            "info", "Gruppe der neuen Konten nicht bestimmbar",
            "Die Selbst-Registrierung ist eingeschaltet, aber die Gruppe für neue Konten ist unbekannt oder nicht in der Gruppenliste.",
            [],
            "Prüfen Sie in den Benutzer-Optionen, welche Gruppe für neue Benutzer eingestellt ist."))
    if not out:
        out.append(_f(
            "info", "Selbst-Registrierung ist eingeschaltet",
            "Besucher können sich selbst ein Konto anlegen. Neue Konten bekommen nur einfache Rechte und müssen aktiviert werden.",
            [],
            "Schalten Sie die Registrierung aus, wenn Ihre Seite sie nicht braucht."))
    return out


# ---------------------------------------------------------------------------
# 4. Zwei-Faktor bei Joomla
# ---------------------------------------------------------------------------

def judge_mfa_joomla(available, plugins_enabled, admins, mfa_rows):
    """Zwei-Faktor-Anmeldung (Joomla 4.2 und neuer, Tabelle #__user_mfa)."""
    if available is False:
        return [_f("info", "Zwei-Faktor-Anmeldung nicht verfügbar",
                   "Diese Joomla-Version ist zu alt für die eingebaute Zwei-Faktor-Anmeldung, oder die Tabelle dafür fehlt.",
                   [], "Mit einer aktuellen Joomla-Version steht die Zwei-Faktor-Anmeldung zur Verfügung.")]
    if available is not True:
        return _np("Zwei-Faktor-Anmeldung", "Ob die Zwei-Faktor-Anmeldung verfügbar ist, war nicht erkennbar.")

    out: List[Finding] = []
    plugins: Optional[List[str]] = None
    if isinstance(plugins_enabled, list):
        plugins = sorted(set(_clean(p, 40).lower() for p in plugins_enabled if isinstance(p, str) and _clean(p, 40)))
    if plugins is None:
        out.append(_f("info", "Aktive Zwei-Faktor-Plugins nicht prüfbar", "Die Liste der aktiven Zwei-Faktor-Plugins fehlt oder ist unlesbar."))
    else:
        if not plugins:
            out.append(_f(
                "warn", "Kein Zwei-Faktor-Plugin ist aktiv",
                "Ohne aktives Plugin können Ihre Konten nicht mit einem zweiten Faktor (z. B. App-Code) geschützt werden.",
                [],
                "In Joomla unter System, Plugins, Gruppe Multifactor Authentication, mindestens ein Verfahren wie TOTP aktivieren."))
        if "fixed" in plugins:
            out.append(_f(
                "warn", "Das Festcode-Plugin (fixed) ist aktiv",
                "Das Plugin mit festem Code ist nur zum Testen gedacht. Wer den Code kennt, kommt damit an der Zwei-Faktor-Anmeldung vorbei.",
                ["fixed"],
                "Das Plugin ausschalten und ein richtiges Verfahren wie TOTP verwenden."))

    admin_ok = isinstance(admins, list)
    rows_ok = isinstance(mfa_rows, list)
    if not admin_ok or not rows_ok:
        out.append(_f("info", "Zwei-Faktor je Konto nicht prüfbar",
                      "Die Liste der Administratoren oder der Zwei-Faktor-Einträge fehlt oder ist unlesbar."))
    else:
        active: List[Tuple[Optional[int], str]] = []
        for a in admins:
            if not isinstance(a, dict):
                continue
            name = _clean(a.get("username"), 80)
            if not name:
                continue
            blocked = _to_flag(a.get("block"))
            if blocked is True:
                continue
            active.append((_to_int(a.get("id")), name))
        have = set()
        for r in mfa_rows:
            if isinstance(r, dict):
                uid = _to_int(r.get("user_id"))
                if uid is not None:
                    have.add(uid)
        if not active:
            out.append(_f("info", "Keine aktiven Konten mit Zugang zum Verwaltungsbereich erkannt",
                          "Es konnte nicht geprüft werden, ob Administratoren die Zwei-Faktor-Anmeldung nutzen."))
        elif plugins:
            missing = sorted(set(n for i, n in active if i is None or i not in have))
            if missing:
                out.append(_f(
                    "warn", "%d Administrator(en) ohne Zwei-Faktor-Anmeldung" % len(missing),
                    "Für diese Konten mit Zugang zum Verwaltungsbereich ist keine Zwei-Faktor-Anmeldung eingerichtet. "
                    "Ein gestohlenes Passwort reicht dann zur Anmeldung.",
                    missing,
                    "Jeder dieser Benutzer richtet im eigenen Profil unter Multi-Faktor-Authentifizierung ein Verfahren ein."))
    if not out:
        return [_f("ok", "Zwei-Faktor-Anmeldung ist für alle Administratoren eingerichtet",
                   "Alle aktiven Konten mit Zugang zum Verwaltungsbereich haben einen Zwei-Faktor-Eintrag.")]
    return out


# ---------------------------------------------------------------------------
# 5. Zwei-Faktor bei WordPress
# ---------------------------------------------------------------------------

_WP_OWN_2FA = ("two-factor", "wp-2fa")
_WP_LOGIN_GUARD = ("wordfence", "ithemes-security")


def judge_2fa_wp(plugins, admin_count):
    """Zwei-Faktor bei WordPress, nur aus den Plugin-Angaben. Aussagen nie über einzelne Konten."""
    n = _to_int(admin_count)
    if not isinstance(plugins, list) or n is None or n < 1:
        return _np("Zwei-Faktor bei WordPress", "Die Plugin-Liste oder die Zahl der Administratoren fehlt, ist unlesbar oder ist null.")
    state: Dict[str, bool] = {}
    for p in plugins:
        if not isinstance(p, dict) or not isinstance(p.get("slug"), str):
            continue
        slug = p["slug"].strip().lower().split("/")[0]
        if not slug:
            continue
        act = _to_flag(p.get("active"))
        state[slug] = state.get(slug, False) or (act is True)
    if not state:
        return _np("Zwei-Faktor bei WordPress", "In der Plugin-Liste wurde kein lesbares Plugin gefunden.")

    adm = "%d Administrator(en)" % n
    own_active = [s for s in _WP_OWN_2FA if state.get(s)]
    own_inactive = [s for s in _WP_OWN_2FA if s in state and not state[s]]
    guards = [s for s in _WP_LOGIN_GUARD if state.get(s)]
    note = "Ob einzelne Konten Zwei-Faktor wirklich nutzen, ist so nicht erkennbar."
    if own_active:
        return [_f("ok", "Ein Zwei-Faktor-Plugin ist aktiv",
                   "Aktiv: %s. %s" % (", ".join(own_active), note), own_active)]
    if guards:
        return [_f("info", "Anmeldeschutz-Plugin aktiv, Zwei-Faktor unklar",
                   "Das Plugin bietet Schutz bei der Anmeldung. Ob es Zwei-Faktor einschaltet, ist hier nicht erkennbar. "
                   "Es gibt %s." % adm,
                   guards,
                   "Prüfen Sie in den Einstellungen des Plugins, ob Zwei-Faktor für Administratoren eingeschaltet ist.")]
    if own_inactive:
        return [_f("warn", "Zwei-Faktor-Plugin ist installiert, aber nicht aktiv",
                   "Das Plugin schützt die Anmeldung erst, wenn es aktiviert ist. Es gibt %s." % adm,
                   own_inactive,
                   "Das Plugin aktivieren und für alle Administratoren Zwei-Faktor einrichten.")]
    return [_f("warn", "Kein Zwei-Faktor-Plugin gefunden",
               "WordPress hat von sich aus keine Zwei-Faktor-Anmeldung. Unter den installierten Plugins ist keines dafür bekannt. "
               "Es gibt %s." % adm,
               [],
               "Ein Plugin wie Two Factor oder WP 2FA installieren und für alle Administratoren einrichten.")]


# ---------------------------------------------------------------------------
# 6. Admin-Anmeldungen
# ---------------------------------------------------------------------------

def _parse_dt(v: Any) -> Optional[datetime.datetime]:
    if not isinstance(v, str):
        return None
    try:
        return datetime.datetime.strptime(v.strip()[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def judge_admin_logins(rows, geo, tz_offset_hours):
    """Auffällige Admin-Anmeldungen im Joomla-Aktivitätsprotokoll (nur erfolgreiche Anmeldungen im Backend)."""
    if not isinstance(rows, list):
        return _np("Admin-Anmeldungen", "Das Aktivitätsprotokoll fehlt oder ist unlesbar.")
    logins = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        action = r.get("action")
        if not isinstance(action, str) or action.strip().upper() != "USER_LOGGED_IN":
            continue
        app = r.get("app")
        app = "" if app is None else app
        if not isinstance(app, str) or app.strip().lower() not in ("administrator", ""):
            continue
        dt = _parse_dt(r.get("log_date"))
        user = _clean(r.get("username"), 60)
        ip = _clean(r.get("ip"), 60)
        if dt is None or not user:
            continue
        logins.append((dt, user, ip))
    if not logins:
        return [_f("info", "Keine Anmeldungen im Verwaltungsbereich auswertbar",
                   "Im Protokoll wurden keine erfolgreichen Anmeldungen im Verwaltungsbereich gefunden. Das Protokoll kann ausgeschaltet oder leer sein.")]
    logins.sort()
    total = len(logins)

    def country(ip: str) -> Optional[str]:
        if not isinstance(geo, dict):
            return None
        c = geo.get(ip)
        if isinstance(c, str) and re.fullmatch(r"[A-Za-z]{2}", c.strip()):
            return c.strip().upper()
        return None

    out: List[Finding] = []
    countries = [country(ip) for _, _, ip in logins]
    counts = Counter(c for c in countries if c)
    major = None
    if not counts:
        out.append(_f("info", "Herkunftsländer der Anmeldungen nicht prüfbar",
                      "Für die Adressen der Anmeldungen liegen keine Länderangaben vor. Eine Auswertung nach Land ist nicht möglich."))
    else:
        top, top_n = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        if top_n * 10 >= total * 6:
            major = top
        else:
            out.append(_f("info", "Kein Land überwiegt bei den Anmeldungen",
                          "Von %d Anmeldungen im Verwaltungsbereich kommt keine Mehrheit aus einem Land. Eine Auffälligkeit nach Land lässt sich so nicht erkennen." % total))
    if major:
        foreign = [(l, c) for l, c in zip(logins, countries) if c and c != major]
        if foreign:
            items = ["%s UTC, %s, Land %s, IP %s" % (l[0].strftime("%Y-%m-%d %H:%M"), l[1], c, l[2] or "unbekannt") for l, c in foreign]
            out.append(_f(
                "warn", "%d Anmeldung(en) im Verwaltungsbereich aus einem anderen Land" % len(foreign),
                "Die meisten Anmeldungen (%d von %d) kommen aus %s. Die hier gelisteten kommen aus anderen Ländern. "
                "Das kann eine Reise oder ein VPN (verschlüsselte Umleitung) sein, aber auch ein fremder Zugriff." % (counts[major], total, major),
                items,
                "Prüfen Sie, ob Sie oder Ihre Mitarbeiter das waren. Wenn nicht: Passwörter ändern und Zwei-Faktor-Anmeldung einschalten."))
    tz = _num(tz_offset_hours)
    if tz is not None and -14 <= tz <= 14:
        night = []
        for dt, user, ip in logins:
            local = dt + datetime.timedelta(hours=tz)
            if 0 <= local.hour < 5:
                night.append("%s Ortszeit, %s, IP %s" % (local.strftime("%Y-%m-%d %H:%M"), user, ip or "unbekannt"))
        if night:
            out.append(_f(
                "info", "%d Anmeldung(en) im Verwaltungsbereich in der Nacht" % len(night),
                "Diese Anmeldungen liegen zwischen 0 und 5 Uhr Ortszeit. Das ist nur ein Hinweis: Manche arbeiten nachts.",
                night,
                "Prüfen Sie, ob Sie diese Anmeldungen kennen."))
    if not out:
        return [_f("ok", "Keine auffälligen Anmeldungen im Verwaltungsbereich",
                   "Alle %d erfolgreichen Anmeldungen kommen aus dem üblichen Land (%s) und zu üblichen Zeiten." % (total, major or "unbekannt"))]
    return out
