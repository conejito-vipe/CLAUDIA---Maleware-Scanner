"""Umgebung (2.4.1, Stufe 2 Punkt 7): Schutz der Absenderadresse gegen Fälschung - SPF, DMARC und DKIM der Domain.

Nur lesend: wenige DNS-Abfragen (höchstens 10) laufen über den Server (dig, host oder nslookup), nie von diesem PC aus und nie gegen fremde Server außer dem DNS-Auflöser des Servers.
Grenzen: DKIM-Einträge liegen unter frei wählbaren Namen (Selektor); es werden nur gängige Selektoren geprüft. 'Nicht gefunden' heißt deshalb bei DKIM nie 'fehlt'.
Die Hauptdomain wird ohne Liste öffentlicher Endungen bestimmt (nur gängige zweiteilige Endungen wie co.uk sind bekannt); bei seltenen Endungen kann sie falsch sein."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .. import baseline, secure
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import sq

G = "grundlagen"
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1"]
TWO_PART = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "co.za", "com.tr", "com.mx", "co.in", "com.cn", "com.pl"}
HOST_OK = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def org_domain(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    labels = h.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART else 2
    return ".".join(labels[-n:]) if len(labels) > n else h


def clean_host(url: str) -> str:
    """Rechnername aus der Adresse als reines ASCII (IDNA) oder '' bei IP-Adressen, lokalen Namen und ungültigen Zeichen."""
    h = (urlparse(url if "//" in url else "https://" + url).hostname or "").strip().lower().rstrip(".")
    if not h or secure.is_loopback(h) or re.fullmatch(r"[\d.]+|[0-9a-f:]+", h):
        return ""
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return h if HOST_OK.match(h) else ""


def dns_script(domain: str, selectors: List[str]) -> str:
    """Shell-Skript mit den TXT-Abfragen. Ausgabe: '@@TOOL <name>' bzw. '@@NOTOOL', dann je Abfrage '@@Q <Name>' und die Antwortzeilen, bei Fehlschlag '@@ERR'."""
    names = [domain, "_dmarc." + domain] + ["%s._domainkey.%s" % (s, domain) for s in selectors]
    qs = " ".join(sq(n) for n in names)
    return (
        "if command -v dig >/dev/null 2>&1; then T=dig; elif command -v host >/dev/null 2>&1; then T=host; "
        "elif command -v nslookup >/dev/null 2>&1; then T=nslookup; else echo '@@NOTOOL'; exit 0; fi; echo \"@@TOOL $T\"; "
        "for n in %s; do echo \"@@Q $n\"; "
        "case $T in dig) timeout 6 dig +short +time=3 +tries=1 TXT \"$n\" 2>&1; R=$?;; "
        "host) timeout 6 host -W 3 -t TXT \"$n\" 2>&1; R=$?;; "
        "*) timeout 6 nslookup -timeout=3 -type=TXT \"$n\" 2>&1; R=$?;; esac; "
        "[ $R -ge 124 ] && echo '@@ERR'; done" % qs
    )


def parse_dns(out: str) -> Tuple[str, Dict[str, Optional[List[str]]]]:
    """-> (Werkzeug, {Name: Liste der TXT-Einträge oder None bei Fehlschlag/Zeitüberschreitung}). Werkzeug '' = keines vorhanden."""
    tool = ""
    res: Dict[str, Optional[List[str]]] = {}
    cur = None
    for ln in (out or "").splitlines():
        if ln.startswith("@@TOOL"):
            tool = ln.split(None, 1)[1].strip() if " " in ln else ""
        elif ln.startswith("@@Q "):
            cur = ln[4:].strip().lower()
            res[cur] = []
        elif ln.startswith("@@ERR"):
            if cur:
                res[cur] = None
        elif cur and res.get(cur) is not None:
            if re.search(r"timed out|connection refused|SERVFAIL|no servers could be reached|communications error", ln, re.I):
                res[cur] = None
                continue
            parts = QUOTED.findall(ln)
            if parts:
                res[cur].append("".join(parts))
    return tool, res


def judge_spf(records: Optional[List[str]]) -> Tuple[str, str, str, List[str]]:
    """-> (Stufe, Titel, Text, Einzelheiten). Stufe 'info' bei nicht abfragbar."""
    if records is None:
        return "info", "SPF nicht prüfbar", "Die DNS-Abfrage lieferte keine Antwort (Zeitüberschreitung oder Fehler).", []
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return ("warn", "Kein SPF-Eintrag gefunden",
                "SPF legt fest, welche Server E-Mails im Namen der Domain senden dürfen. Ohne Eintrag lassen sich Absenderadressen der Domain leichter fälschen, und Mails deiner Seite (Kontaktformular, Passwort-Mails) landen eher im Spam.", [])
    if len(spf) > 1:
        return "warn", "Mehrere SPF-Einträge", "Pro Domain ist nur ein SPF-Eintrag erlaubt; bei mehreren wird SPF von vielen Empfängern ganz verworfen. Die Einträge zu einem zusammenfassen.", spf[:3]
    rec = spf[0]
    low = rec.lower()
    lookups = len(re.findall(r"(?:^|\s)[+\-~?]?(?:include:|a(?:[:/\s]|$)|mx(?:[:/\s]|$)|ptr|exists:)|redirect=", low))
    items = [rec[:200]]
    allm = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", low)
    if not allm:
        return "info", "SPF ohne Abschluss (all)", "Der Eintrag endet nicht mit -all oder ~all; dann bleibt offen, was mit fremden Absendern passieren soll.", items
    q = allm.group(1)
    if q in ("+", ""):
        return "crit", "SPF erlaubt jedem Server das Senden", "Der Eintrag endet mit +all (oder nur all). Damit darf jeder Server im Namen der Domain senden; der Schutz ist wirkungslos.", items
    if q == "?":
        return ("warn", "SPF ohne Wirkung (?all)",
                "SPF ist eine Liste im DNS (Namensdienst der Domain), die sagt, welche Server E-Mails im Namen deiner Domain senden dürfen. Das Ende des Eintrags legt fest, was mit allen anderen Servern geschehen soll: "
                "-all heißt abweisen, ~all heißt verdächtig, ?all heißt: keine Aussage. Dein Eintrag endet mit ?all. Das Problem: Wer E-Mails mit deiner Absenderadresse fälscht (Spam, Phishing), "
                "wird vom Empfänger nicht erkannt, weil deine Domain ausdrücklich nichts dazu sagt. Deine echten Mails sind davon nicht betroffen.", items)
    if lookups > 10:
        return "warn", "SPF braucht mehr als 10 DNS-Abfragen", "Die Zahl ist nur aus dem Eintrag selbst gezählt (verschachtelte include-Einträge nicht mitgerechnet) und liegt schon darüber. Mehr als 10 führt bei Empfängern zu einem Fehler.", items
    return "ok", "SPF-Eintrag vorhanden (%s)" % ("-all: fremde Absender abweisen" if q == "-" else "~all: fremde Absender verdächtig"), "", items


def judge_dmarc(records: Optional[List[str]]) -> Tuple[str, str, str, List[str]]:
    if records is None:
        return "info", "DMARC nicht prüfbar", "Die DNS-Abfrage lieferte keine Antwort (Zeitüberschreitung oder Fehler).", []
    dm = [r for r in records if r.lower().replace(" ", "").startswith("v=dmarc1")]
    if not dm:
        return ("info", "Kein DMARC-Eintrag gefunden",
                "DMARC sagt Empfängern, was mit gefälschten Mails der Domain geschehen soll, und liefert Berichte darüber. Das ist eine Empfehlung, keine Lücke der Seite. Ein Anfang ist p=none (nur beobachten).", [])
    rec = dm[0]
    m = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", rec, re.I)
    pol = m.group(1).lower() if m else ""
    items = [rec[:200]]
    pct = re.search(r"pct\s*=\s*(\d{1,3})", rec, re.I)
    if not pol:
        return "info", "DMARC-Eintrag ohne gültige Richtlinie (p=)", "Ohne p=none, p=quarantine oder p=reject wird der Eintrag von Empfängern ignoriert.", items
    if pol == "none":
        return "info", "DMARC nur im Beobachtungsmodus (p=none)", "Gefälschte Mails werden nicht abgewiesen, aber gemeldet. Nach einer Beobachtungszeit kann auf quarantine oder reject umgestellt werden.", items
    if pct and int(pct.group(1)) < 100:
        return "ok", "DMARC mit Richtlinie %s, gilt für %s %% der Mails" % (pol, pct.group(1)), "", items
    return "ok", "DMARC mit Richtlinie %s" % pol, "", items


@check(
    "mail_dns", G, "E-Mail-Absender der Domain (SPF, DMARC, DKIM)",
    "Lässt sich die Absenderadresse deiner Domain leicht fälschen?",
    what="Fragt über den Server die öffentlichen DNS-Einträge der Hauptdomain ab (TXT): SPF, DMARC und bei acht gängigen Namen (Selektoren) DKIM. Insgesamt höchstens zehn kurze Abfragen, über dig, host oder nslookup auf dem Server. "
         "Gemeldet wird, ob die Einträge vorhanden und sinnvoll sind. DKIM-Einträge können beliebig heißen; wird keiner gefunden, ist das nur ein Hinweis, kein Befund.",
    why="Gefälschte Mails im Namen deiner Domain werden für Betrug und Phishing genutzt, und Mails deiner Seite (Passwort zurücksetzen, Kontaktformular) landen ohne diese Einträge eher im Spam.",
    reads="Nur öffentliche DNS-Einträge, wie sie jeder abfragen kann. Es wird nichts verändert, es werden keine Mails gesendet.",
    load="leicht", needs="ssh",
)
def mail_dns(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    host = clean_host(url)
    if not host:
        raise CheckSkipped("Die Adresse ist keine öffentliche Domain (IP-Adresse oder lokaler Name); SPF, DMARC und DKIM gibt es nur für Domains.")
    dom = org_domain(host)
    ctx.progress("Frage DNS-Einträge von %s ab" % dom)
    out = ctx.sh(dns_script(dom, DKIM_SELECTORS), timeout=90).out
    tool, recs = parse_dns(out)
    if "@@NOTOOL" in (out or "") or not tool:
        res.add("info", "SPF, DMARC und DKIM nicht prüfbar", "Auf dem Server ist weder dig noch host noch nslookup vorhanden. Die Einträge lassen sich auch bei deinem Domain-Anbieter ansehen (DNS-Verwaltung, TXT-Einträge).")
        return
    if all(v is None for v in recs.values()) or not recs:
        res.add("info", "SPF, DMARC und DKIM nicht prüfbar", "Der Server konnte keine DNS-Abfrage beantworten (kein Netz zum Auflöser oder Zeitüberschreitung).")
        return
    info = ["Geprüfte Domain: %s%s" % (dom, "" if dom == host else " (Hauptdomain von %s)" % host), "Abfrage über: %s auf dem Server" % tool]
    res.add("info", "Geprüfte Domain: %s" % dom, "Mails deiner Seite werden meist im Namen dieser Domain gesendet. Läuft der Mailversand über einen anderen Anbieter, gelten dessen Angaben.", info)
    for fn, key, hint in ((judge_spf, dom, "Den SPF-Eintrag setzt du als TXT-Eintrag in der DNS-Verwaltung; die Angaben dazu liefert dein Mailanbieter oder Hoster."),
                          (judge_dmarc, "_dmarc." + dom, "Als TXT-Eintrag bei _dmarc in der DNS-Verwaltung anlegen, zum Beispiel v=DMARC1; p=none; rua=mailto:adresse@deine-domain.")):
        sev, title, text, items = fn(recs.get(key))
        if "?all" in title:
            hint = ("Im SPF-Eintrag am Ende ?all durch ~all ersetzen (sicherer Einstieg) oder durch -all, wenn alle deine Mail-Server im Eintrag stehen. "
                    "Das ändert nur der Anbieter, der die DNS-Einträge deiner Domain verwaltet (oft der Hoster); siehe Gruppe 'Nur beim Hoster änderbar'.")
        res.add(sev, title, text, items, hint if sev != "ok" and "nicht prüfbar" not in title else "")
    found = [s for s in DKIM_SELECTORS if any(r.lower().replace(" ", "").startswith("v=dkim1") or "k=rsa" in r.lower() or "p=" in r.lower()
                                                for r in (recs.get("%s._domainkey.%s" % (s, dom)) or []))]
    asked = [s for s in DKIM_SELECTORS if recs.get("%s._domainkey.%s" % (s, dom)) is not None]
    if found:
        res.add("ok", "DKIM-Eintrag gefunden (%s)" % ", ".join(found), "", ["%s._domainkey.%s" % (s, dom) for s in found])
    elif asked:
        res.add("info", "Kein DKIM-Eintrag unter gängigen Namen gefunden", "DKIM signiert Mails kryptografisch. Der Name (Selektor) ist frei wählbar; geprüft wurden nur %s. Deshalb ist das kein Beleg, dass DKIM fehlt. Ob es eingerichtet ist, sagt dein Mailanbieter." % ", ".join(asked))
    else:
        res.add("info", "DKIM nicht prüfbar", "Die DNS-Abfragen für die DKIM-Namen lieferten keine Antwort.")



# ---------------------------------------------------------------- 2.5.0 / 2.13: DNS-Änderungen gegen gespeicherte Basis
RTYPES = {"NS": "Nameserver", "MX": "Mail-Server", "A": "Adresse der Webseite (IPv4)", "AAAA": "Adresse der Webseite (IPv6)", "TXT": "SPF-Eintrag", "DMARC": "DMARC-Eintrag"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_FAIL = re.compile(r"timed out|connection refused|SERVFAIL|no servers could be reached|communications error", re.I)


def records_script(domain: str, host: str) -> str:
    """Shell-Skript für NS, MX, SPF, DMARC (Hauptdomain) und A, AAAA (Adresse der Webseite): 6 Abfragen. Ausgabe wie dns_script, Kopf je Abfrage '@@Q <Art> <Name>'."""
    qs = [("NS", domain), ("MX", domain), ("TXT", domain), ("TXT", "_dmarc." + domain), ("A", host), ("AAAA", host)]
    body = "".join(
        "echo \"@@Q %s %s\"; case $T in dig) timeout 6 dig +short +time=3 +tries=1 %s %s 2>&1; R=$?;; host) timeout 6 host -W 3 -t %s %s 2>&1; R=$?;; "
        "*) timeout 6 nslookup -timeout=3 -type=%s %s 2>&1; R=$?;; esac; [ $R -ge 124 ] && echo '@@ERR'; " % (t, n, t, sq(n), t, sq(n), t, sq(n)) for t, n in qs)
    return ("if command -v dig >/dev/null 2>&1; then T=dig; elif command -v host >/dev/null 2>&1; then T=host; "
            "elif command -v nslookup >/dev/null 2>&1; then T=nslookup; else echo '@@NOTOOL'; exit 0; fi; echo \"@@TOOL $T\"; " + body)


def _norm(v: str) -> str:
    return re.sub(r"\s+", " ", v.strip().lower().rstrip("."))


def _one(rtype: str, ln: str) -> Optional[str]:
    """Wert einer Antwortzeile (dig, host oder nslookup) oder None, wenn die Zeile keinen Eintrag dieser Art enthält."""
    ln = ln.strip()
    if not ln or "#" in ln:                                   # nslookup nennt zuerst den Auflöser ('Address: 1.2.3.4#53')
        return None
    if rtype == "NS":
        m = re.search(r"(?:name server|nameserver\s*=)\s*(\S+)\s*$", ln, re.I)
        return _norm(m.group(1)) if m else (_norm(ln) if re.fullmatch(r"[A-Za-z0-9._-]+\.?", ln) else None)
    if rtype == "MX":
        m = re.search(r"(?:handled by|mail exchanger\s*=)\s*(\d+\s+\S+)\s*$", ln, re.I)
        return _norm(m.group(1)) if m else (_norm(ln) if re.fullmatch(r"\d+\s+[A-Za-z0-9._-]+\.?", ln) else None)
    if rtype in ("A", "AAAA"):
        m = re.search(r"(?:has (?:AAAA |IPv6 )?address|^address:)\s*(\S+)\s*$", ln, re.I) or re.fullmatch(r"()(\S+)", ln)
        v = (m.group(m.lastindex) if m else "").lower()
        if rtype == "A":
            return v if _IPV4.match(v) and all(int(x) < 256 for x in v.split(".")) else None
        return v if ":" in v and re.fullmatch(r"[0-9a-f:.]+", v) else None
    parts = QUOTED.findall(ln)                                 # TXT
    return _norm("".join(parts)) if parts else None


def parse_records(out: str) -> Tuple[str, Dict[str, Optional[List[str]]]]:
    """-> (Werkzeug, {'NS'|'MX'|'A'|'AAAA'|'TXT'|'DMARC': Liste der Einträge, None bei Fehlschlag}). TXT enthält nur SPF, DMARC nur v=DMARC1 (andere TXT-Einträge wechseln zu oft)."""
    tool, res, cur = "", {}, None
    for ln in (out or "").splitlines():
        if ln.startswith("@@TOOL"):
            tool = ln.split(None, 1)[1].strip() if " " in ln else ""
        elif ln.startswith("@@Q "):
            p = ln.split()
            cur = ("DMARC" if p[1] == "TXT" and p[2].lower().startswith("_dmarc.") else p[1]) if len(p) >= 3 else None
            if cur:
                res[cur] = []
        elif ln.startswith("@@ERR"):
            if cur:
                res[cur] = None
        elif cur and res.get(cur) is not None:
            if _FAIL.search(ln):
                res[cur] = None
                continue
            v = _one("TXT" if cur == "DMARC" else cur, ln)
            if v is None:
                continue
            if cur == "TXT" and not v.startswith("v=spf1"):
                continue
            if cur == "DMARC" and not v.startswith("v=dmarc1"):
                continue
            res[cur].append(v)
    return tool, {k: (sorted(set(v)) if v is not None else None) for k, v in res.items()}


def diff_records(base: Dict[str, List[str]], now: Dict[str, Optional[List[str]]]) -> Tuple[List[Tuple[str, List[str], List[str]]], List[str]]:
    """-> ([(Art, entfernt, neu)], [Arten ohne Antwort]). Verglichen wird nur, was in der Basis steht UND jetzt eine Antwort hat."""
    changed, unknown = [], []
    for k in RTYPES:
        if k not in base:
            continue
        cur = now.get(k)
        if cur is None:
            unknown.append(k)
            continue
        gone, new = sorted(set(base[k]) - set(cur)), sorted(set(cur) - set(base[k]))
        if gone or new:
            changed.append((k, gone, new))
    return changed, unknown


@check(
    "dns_changes", G, "DNS-Änderungen seit der gespeicherten Basis",
    "Hat sich bei deiner Domain etwas an Nameservern, Mail-Servern, Webadresse, SPF oder DMARC geändert?",
    what="Fragt über den Server die öffentlichen DNS-Einträge ab (Nameserver, Mail-Server, Adresse der Webseite, SPF und DMARC; sechs kurze Abfragen über dig, host oder nslookup) und vergleicht sie mit einer Basis, "
         "die du früher selbst gespeichert hast. Gemeldet werden entfernte und neue Einträge. Die Basis wird nur gespeichert, wenn du das Häkchen setzt, und liegt ausschließlich auf deinem Computer.",
    why="Wer die Kontrolle über Konto oder Domain bekommt, ändert oft DNS-Einträge: Mail-Server für Phishing, SPF zum Mitsenden, die Adresse der Webseite für Weiterleitungen. "
        "Gegen einen Zustand, den du für richtig hältst, fällt jede Abweichung auf. Bei einem Umzug oder Anbieterwechsel sind Änderungen erwartbar, dann die Basis neu speichern.",
    reads="Nur öffentliche DNS-Einträge, wie sie jeder abfragen kann. Gespeichert werden nur diese Einträge und die Domain auf deinem Computer, keine Zugangsdaten. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=[],
    options=[Option("save", "Die aktuellen DNS-Einträge als Basis speichern (ersetzt eine vorhandene)", "bool", False,
                    "Speichere nur, wenn die Einträge nach deiner Einschätzung richtig sind. Rotierende Adressen (z. B. bei CDN-Anbietern) können Änderungen vortäuschen.")],
)
def dns_changes(ctx, res):
    if not ctx.s.baseline_dir or not ctx.s.baseline_key:
        raise CheckSkipped("Der Vergleich ist hier nicht verfügbar.")
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    host = clean_host(url)
    if not host:
        raise CheckSkipped("Die Adresse ist keine öffentliche Domain (IP-Adresse oder lokaler Name); DNS-Einträge gibt es nur für Domains.")
    dom = org_domain(host)
    ctx.progress("Frage DNS-Einträge von %s ab" % dom)
    out = ctx.sh(records_script(dom, host), timeout=90).out
    tool, now = parse_records(out)
    if "@@NOTOOL" in (out or "") or not tool:
        res.add("info", "DNS-Änderungen nicht prüfbar", "Auf dem Server ist weder dig noch host noch nslookup vorhanden. Die Einträge lassen sich auch bei deinem Domain-Anbieter ansehen (DNS-Verwaltung).")
        return
    if not now or all(v is None for v in now.values()):
        res.add("info", "DNS-Änderungen nicht prüfbar", "Der Server konnte keine DNS-Abfrage beantworten (kein Netz zum Auflöser oder Zeitüberschreitung).")
        return
    want_save = str(ctx.opt("save", "")).lower() in ("1", "true", "yes", "ja", "on")
    base = baseline.load_dns(ctx.s.baseline_dir, ctx.s.baseline_key)
    if base is None:
        res.add("info", "Noch keine DNS-Basis vorhanden", "Abgefragt wurden %d Einträge von %s über %s." % (sum(len(v) for v in now.values() if v), dom, tool),
                hint="Setze beim nächsten Lauf das Häkchen 'Die aktuellen DNS-Einträge als Basis speichern', wenn die Einträge nach deiner Einschätzung richtig sind.")
    else:
        changed, unknown = diff_records(base["records"], now)
        for k, gone, new in changed:
            items = ["entfernt: " + g for g in gone[:20]] + ["neu: " + n for n in new[:20]]
            res.add("warn", "%s hat sich geändert" % RTYPES[k], "Vergleich mit der Basis vom %s (Domain %s)." % (base.get("saved", "?"), base.get("domain", dom)), items,
                    "Stammt die Änderung von dir oder deinem Anbieter (Umzug, neuer Mailanbieter)? Wenn nicht, bei der DNS-Verwaltung die Zugänge prüfen und Passwörter ändern.")
        if unknown:
            res.add("info", "Nicht alle DNS-Einträge waren abfragbar", "Ohne Antwort geblieben: %s. Diese wurden nicht verglichen." % ", ".join(RTYPES[k] for k in unknown))
        if not changed:
            res.add("ok", "Keine DNS-Änderung seit der Basis", "Die abgefragten Einträge entsprechen dem Stand vom %s." % base.get("saved", "?"))
    if want_save:
        if any(v is None for v in now.values()):
            res.add("warn", "DNS-Basis wurde nicht gespeichert", "Nicht alle Abfragen waren beantwortet; die Basis wäre unvollständig.")
        else:
            baseline.save_dns(ctx.s.baseline_dir, ctx.s.baseline_key, dom, now)
            res.add("ok", "DNS-Basis gespeichert", "%d Einträge von %s (nur öffentliche DNS-Daten, auf deinem Computer)." % (sum(len(v) for v in now.values()), dom))
