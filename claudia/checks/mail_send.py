"""Umgebung (2.5.0, Punkt 2.8): E-Mail-Versand der Seite - Mailer-Einstellung (Joomla), PHP-Mail-Einstellungen, PHP-Mailprotokoll und Größe der Mail-Warteschlange.

Nur lesend und nur, was auf Shared Hosting überhaupt lesbar ist: Das PHP-Mailprotokoll (mail.log) und die Warteschlange (mailq/exim) sind oft nicht freigegeben; dann steht das ausdrücklich im Ergebnis
und es gibt keinen Befund. Empfängeradressen, Mail-Inhalte, SMTP-Benutzer und Passwörter werden weder gelesen noch ausgegeben (aus dem Protokoll werden nur die Pfade der aufrufenden PHP-Dateien gezählt).
Grenzen: Die PHP-Werte stammen von der Kommandozeile und können von denen der Webseite abweichen."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..model import CheckSkipped
from ..registry import check
from ..util import sq
from .mail_dns import clean_host, org_domain

G = "grundlagen"
Row = Tuple[str, str, str, List[str], str]
MAIL_KEYS = ("sendmail_path", "mail.log", "mail.add_x_header")
SUSPICIOUS_PATH = re.compile(r"/(tmp|dev/shm|var/tmp)/|[;|&`]|\$\(|\b(curl|wget|bash|perl|python\d?|ncat|base64)\b", re.I)
STANDARD_PATH = re.compile(r"^(/usr(/local)?|/opt|/bin|/sbin)/")
UPLOAD_DIRS = re.compile(r"/(images|media|tmp|cache|uploads|wp-content/uploads|logs?)/", re.I)
LOG_LINE = re.compile(r"mail\(\) on \[([^\]]+?):\d+\]")
SAFE_ABS = re.compile(r"^/[A-Za-z0-9._/\-]{1,200}$")
LOCAL_HOSTS = ("", "localhost", "127.0.0.1", "::1")
QUEUE_WARN, QUEUE_CRIT = 1000, 10000
LOG_MIN, LOG_SHARE = 200, 0.9


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "on", "true", "yes", "ja")


def judge_mailer(v: Any, site_domain: str) -> List[Row]:
    """Mailer-Einstellung aus der configuration.php (nur Mailer, Server, Verschlüsselung, Port, ob Anmeldung genutzt wird, Absender-Domain; nie Benutzer oder Passwort)."""
    if not isinstance(v, dict):
        return []
    mailer = str(v.get("mailer", "")).strip().lower()
    if not mailer:
        return []
    out: List[Row] = []
    if mailer == "smtp":
        host = str(v.get("smtphost", "")).strip().lower()[:100]
        sec = str(v.get("smtpsecure", "")).strip().lower()
        items = ["Mailer: smtp", "SMTP-Server: %s" % (host or "(leer)"), "Verschlüsselung: %s" % (sec if sec not in ("", "none", "0", "false") else "keine"),
                 "Port: %s" % str(v.get("smtpport", "")).strip()[:6], "Anmeldung am SMTP-Server: %s" % ("ja" if _truthy(v.get("smtpauth")) else "nein")]
        if sec in ("", "none", "0", "false") and host not in LOCAL_HOSTS:
            out.append(("warn", "SMTP-Verbindung ohne Verschlüsselung",
                        "Die Seite spricht mit dem Mailserver ohne SSL oder TLS. Mails und, falls eingestellt, die Anmeldung laufen dann unverschlüsselt durchs Netz.", items,
                        "In den Joomla-Mail-Einstellungen 'Verbindung sichern' auf SSL oder TLS stellen und den dazu passenden Port eintragen (meist 465 bzw. 587)."))
        else:
            out.append(("ok", "Versand über SMTP-Server", "", items, ""))
    else:
        out.append(("info", "Versand über PHP mail() oder sendmail", "Mails verlassen die Seite direkt über den Server. Dann hängen Zustellung und Spam-Einstufung stark vom Server und von SPF/DKIM der Domain ab.",
                    ["Mailer: %s" % mailer[:20]], ""))
    frm = str(v.get("mailfrom", "")).strip().lower()
    dom = frm.rsplit("@", 1)[1].strip(" >") if "@" in frm else ""
    if dom and site_domain and re.fullmatch(r"[a-z0-9.-]{3,253}", dom) and org_domain(dom) != site_domain:
        out.append(("info", "Absenderadresse gehört zu einer anderen Domain",
                    "Mails der Seite werden mit einer Absender-Domain gesendet, die nicht zur Domain der Webseite gehört. Dann gelten SPF und DMARC dieser anderen Domain.",
                    ["Absender-Domain: " + dom, "Domain der Webseite: " + site_domain], ""))
    return out


def judge_php_mail(s: Any) -> List[Row]:
    """PHP-Einstellungen zum Mailversand: ein sendmail_path mit Shell-Zeichen oder Download-Programmen oder in Temp-Ordnern ist ein klares Alarmzeichen."""
    if not isinstance(s, dict):
        return []
    path = str(s.get("sendmail_path", "")).strip()
    out: List[Row] = []
    if path and SUSPICIOUS_PATH.search(path):
        out.append(("crit", "sendmail_path in PHP ist verdächtig",
                    "PHP startet beim Mailversand dieses Programm. Hier stehen Shell-Zeichen, ein Download-Programm oder ein Temp-Ordner; so lässt sich Code bei jeder gesendeten Mail ausführen.",
                    ["sendmail_path: " + path[:200]], "Herkunft der Einstellung klären (php.ini, .user.ini, .htaccess, Hoster-Oberfläche) und bei Unklarheit zurücksetzen lassen."))
    elif path and not STANDARD_PATH.match(path):
        out.append(("info", "sendmail_path zeigt auf ein ungewöhnliches Programm", "Üblich sind Programme unter /usr, /bin, /sbin oder /opt. Das kann ein Hoster-Wrapper sein.",
                    ["sendmail_path: " + path[:200]], ""))
    items = ["%s: %s" % (k, str(s.get(k, "")).strip()[:150] or "(leer)") for k in MAIL_KEYS if k in s]
    if items and not out:
        x = str(s.get("mail.add_x_header", "")).strip().lower()
        out.append(("info" if x not in ("1", "on", "true", "yes") else "ok", "PHP-Einstellungen zum Mailversand",
                    "mail.add_x_header fügt jeder Mail den Absender-Skript-Namen hinzu und hilft bei der Suche nach einem Spam-Skript." if x not in ("1", "on", "true", "yes") else "", items, ""))
    return out


def parse_mail_log(text: str) -> List[str]:
    """Pfade der PHP-Dateien, die mail() aufgerufen haben (eine Angabe je Mail). Empfänger und Inhalte werden nicht übernommen."""
    return [m.group(1) for m in LOG_LINE.finditer(text or "")]


def judge_mail_log(paths: List[str]) -> List[Row]:
    total = len(paths)
    if not total:
        return [("info", "PHP-Mailprotokoll enthält keine Mails", "Das Protokoll ist leer oder enthält keine mail()-Einträge im erwarteten Format.", [], "")]
    cnt = Counter(paths)
    bad = sorted((p for p in cnt if UPLOAD_DIRS.search(p)), key=lambda p: -cnt[p])
    out: List[Row] = []
    if bad:
        out.append(("crit", "mail() wird aus einem Upload-, Cache- oder Temp-Ordner aufgerufen",
                    "In diesen Ordnern gehört normalerweise kein Programmcode hin; Spam-Skripte und Web-Shells versenden aber genau von dort Mails.",
                    ["%s (%d Mails)" % (p[:200], cnt[p]) for p in bad[:10]], "Datei ansehen, Herkunft klären und bei Unklarheit entfernen lassen (Vorfall-Maßnahmen)."))
    top, n = cnt.most_common(1)[0]
    if total >= LOG_MIN and n / total >= LOG_SHARE and top not in bad:
        out.append(("warn", "Fast alle Mails kommen aus einem einzigen Skript", "%d von %d Mails der Stichprobe stammen aus derselben Datei. Bei einem Kontaktformular ist das normal, bei Massenversand nicht." % (n, total),
                    [top[:200]], "Prüfen, ob die Datei zu einem Formular oder einer Erweiterung gehört."))
    if not out:
        out.append(("ok", "PHP-Mailprotokoll ohne Auffälligkeit", "%d Mails in der Stichprobe." % total, ["%s (%d)" % (p[:200], c) for p, c in cnt.most_common(3)], ""))
    return out


def parse_queue(out: str) -> Optional[int]:
    """Anzahl wartender Mails aus der Ausgabe von 'exim -bpc' oder 'mailq' (Postfix, Sendmail). None = nicht lesbar."""
    best = None
    for ln in (out or "").splitlines():
        ln = ln.strip()
        m = re.fullmatch(r"\d{1,9}", ln) or re.search(r"(\d+)\s+Requests?\b", ln, re.I) or re.search(r"Total requests:\s*(\d+)", ln, re.I)
        if m:
            best = int(m.group(m.lastindex or 0))
        elif re.search(r"queue is empty", ln, re.I):
            best = 0
    return best


def judge_queue(n: Optional[int]) -> List[Row]:
    if n is None:
        return []
    if n >= QUEUE_CRIT:
        return [("crit", "Mail-Warteschlange ist sehr voll (%d)" % n, "So viele wartende Mails deuten auf Massenversand (Spam-Skript) oder auf ein Zustellproblem hin.", [], "Mailprotokoll und Skripte der Seite prüfen; beim Hoster nachfragen.")]
    if n >= QUEUE_WARN:
        return [("warn", "Mail-Warteschlange ist ungewöhnlich voll (%d)" % n, "Für eine kleine Seite sind das viele wartende Mails.", [], "Prüfen, ob die Seite Mails in Massen versendet (Spam-Skript).")]
    return [("ok", "Mail-Warteschlange ist klein (%d)" % n, "", [], "")]


PHP_MAIL_SCRIPT = r"""
@PICK@if [ -n "$P" ]; then echo '@@SET'; timeout 15 "$P" -r '$k=explode(",","@KEYS@"); foreach($k as $x){ echo $x,"\t",str_replace(array("\r","\n","\t")," ",(string)ini_get($x)),"\n"; }' </dev/null 2>/dev/null; else echo '@@NOPHP'; fi
echo '@@QUEUE'
if command -v exim >/dev/null 2>&1; then timeout 10 exim -bpc </dev/null 2>/dev/null | head -n 1; fi
if command -v mailq >/dev/null 2>&1; then timeout 10 mailq </dev/null 2>/dev/null | tail -n 1; fi
"""


def parse_php_mail(out: str) -> Tuple[Dict[str, str], Optional[int], bool]:
    sec, cur, nophp = {}, None, "@@NOPHP" in (out or "")
    q: List[str] = []
    for ln in (out or "").splitlines():
        if ln.startswith("@@SET"):
            cur = "set"
        elif ln.startswith("@@QUEUE"):
            cur = "q"
        elif cur == "set" and "\t" in ln:
            k, v = ln.split("\t", 1)
            if k in MAIL_KEYS:
                sec[k] = v.strip()
        elif cur == "q":
            q.append(ln)
    return sec, parse_queue("\n".join(q)), nophp


@check(
    "mail_send", G, "E-Mail-Versand der Seite",
    "Wie versendet die Seite Mails, und gibt es Anzeichen für Massenversand oder ein Spam-Skript?",
    what="Liest die Mailer-Einstellung aus der Joomla-Konfiguration (Mailer, SMTP-Server, Verschlüsselung, Port, ob eine Anmeldung genutzt wird, Absender-Domain; nie Benutzer oder Passwort), "
         "die PHP-Einstellungen zum Mailversand (sendmail_path, mail.log, mail.add_x_header), das PHP-Mailprotokoll (nur die letzten 3000 Zeilen, nur die Pfade der aufrufenden PHP-Dateien) und, falls freigegeben, "
         "die Größe der Mail-Warteschlange (nur die Anzahl). Auf vielen Hostern sind Mailprotokoll und Warteschlange nicht lesbar; das wird dann ausdrücklich genannt und ist kein Befund.",
    why="Gehackte Seiten werden oft zum Versand von Spam und Phishing missbraucht. Spuren sind ein verbogener sendmail_path, ein Skript in einem Upload- oder Temp-Ordner, das Mails versendet, "
        "oder eine volle Warteschlange. Eine unverschlüsselte SMTP-Verbindung gefährdet Mails und Zugangsdaten.",
    reads="Nur Einstellungen, die Anzahl wartender Mails und die Pfade aus dem PHP-Mailprotokoll. Empfängeradressen, Mail-Inhalte, SMTP-Benutzer und Passwörter werden nicht gelesen und nicht ausgegeben. Es wird nichts verändert.",
    load="leicht", needs="ssh",
)
def mail_send(ctx, res):
    url = (ctx.s.url or "").strip()
    host = clean_host(url) if url else ""
    dom = org_domain(host) if host else ""
    rows: List[Row] = []
    if ctx.cms != "wordpress":
        cfg = ctx.config()
        if cfg.get("missing"):
            raise CheckSkipped("Die Konfigurationsdatei der Seite wurde nicht gefunden.")
        rows += judge_mailer(cfg.get("vars") or {}, dom)
    ctx.progress("PHP-Einstellungen und Warteschlange lesen")
    out = ctx.sh(PHP_MAIL_SCRIPT.replace("@PICK@", ctx.php_pick()).replace("@KEYS@", ",".join(MAIL_KEYS)), timeout=60).out
    s, queue, nophp = parse_php_mail(out)
    rows += judge_php_mail(s)
    notes: List[str] = []
    if nophp:
        notes.append("Es wurde kein PHP-Programm für die Kommandozeile gefunden; die PHP-Mail-Einstellungen sind nicht lesbar.")
    logp = s.get("mail.log", "")
    if logp and SAFE_ABS.match(logp):
        ctx.progress("PHP-Mailprotokoll lesen")
        txt = ctx.sh("test -r %s && tail -n 3000 %s 2>/dev/null | grep -a 'mail() on \\[' | head -n 3000" % (sq(logp), sq(logp)), timeout=60).out
        if txt.strip():
            rows += judge_mail_log(parse_mail_log(txt))
        else:
            notes.append("Das PHP-Mailprotokoll ist eingestellt, aber leer oder nicht lesbar.")
    elif logp:
        notes.append("mail.log ist eingestellt, aber kein gewöhnlicher absoluter Pfad; es wurde nicht gelesen.")
    else:
        notes.append("Es ist kein PHP-Mailprotokoll (mail.log) eingestellt; ein Spam-Skript lässt sich daran nicht erkennen.")
    if queue is None:
        notes.append("Die Mail-Warteschlange ist auf diesem Server nicht lesbar (mailq/exim nicht freigegeben).")
    rows += judge_queue(queue)
    if ctx.cms == "wordpress":
        notes.append("WordPress hat keine Mailer-Einstellung in der Konfigurationsdatei; ein SMTP-Plugin speichert sie in der Datenbank und wird hier nicht ausgewertet.")
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not rows:
        res.add("info", "Kein Hinweis auf Auffälligkeiten beim Mailversand lesbar", "Nichts davon ist ein Beleg dafür, dass kein Spam versendet wird.", notes)
    elif notes:
        res.add("info", "Was nicht lesbar war", "Das sind Grenzen dieser Prüfung, keine Befunde.", notes)
