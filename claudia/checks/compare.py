"""Vergleich zwischen Läufen (B9): Prüfsummen von PHP-, JS- und .htaccess-Dateien gegen eine lokal gespeicherte Vergleichsbasis. Rein lesend auf dem Server."""
from __future__ import annotations

import re

from .. import baseline
from ..model import CheckSkipped, Option
from ..registry import check

G = "dateien"
SHOW = 40          # so viele Pfade je Befund anzeigen
MANY = 150         # ab so vielen Änderungen wird ein Update vermutet (keine Warnung je Datei)
CFG_RE = re.compile(r"(^|/)\.(htaccess|user\.ini)$", re.I)   # Server-Konfiguration: Änderungen werden immer einzeln gemeldet
CODE_RE = re.compile(r"\.(php\d?|phtml|phar|inc)$|(^|/)\.htaccess$|(^|/)\.user\.ini$", re.I)

SCRIPT = r"""
find . -type f -size -2048k @SKIP@ \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.inc' -o -iname '*.js' -o -name '.htaccess' -o -name '.user.ini' \) -print0 2>/dev/null \
  | head -z -n @MAX@ | xargs -0 -r sha256sum 2>/dev/null | sed -n 's/^\([0-9a-f]\{64\}\)  \(.*\)$/H\t\1\t\2/p'
for d in @UP@; do test -d "$d" && find "./$d" -type f -printf 'U\t%s\t%p\n' 2>/dev/null | head -n @MAX@; done
echo '@@CUT'; find . -type f -size -2048k @SKIP@ \( -iname '*.php' -o -iname '*.js' -o -name '.htaccess' \) 2>/dev/null | sed -n "@MAXP@p" | head -n 1
"""


def _items(paths):
    p = list(paths)
    return p[:SHOW] + (["... und %d weitere" % (len(p) - SHOW)] if len(p) > SHOW else [])


@check(
    "compare_runs", G, "Vergleich mit gespeicherter Basis",
    "Was hat sich seit dem gespeicherten Lauf an Code-Dateien und Upload-Ordnern geändert?",
    what="Berechnet Prüfsummen (SHA-256) aller PHP-, JS- und .htaccess-Dateien sowie die Dateiliste der Upload-Ordner und vergleicht sie mit einer Basis, die du früher selbst gespeichert hast. "
         "Gemeldet werden neue, geänderte und gelöschte Dateien; Änderungen an .htaccess und .user.ini stehen immer in einem eigenen Befund, auch wenn sonst sehr viele Dateien geändert wurden. Die Basis wird nur gespeichert, wenn du das Häkchen setzt, und liegt ausschließlich auf deinem Computer; sie enthält Pfade und Prüfsummen, keine Dateiinhalte und keine Zugangsdaten.",
    why="Ein Angreifer ändert oder ergänzt Dateien. Gegen einen Zustand, den du für sauber hältst, fällt jede Abweichung auf, auch wenn der Code selbst unauffällig aussieht. "
        "Nach Updates ändern sich viele Dateien: Dann ist die Abweichung erwartbar und die Basis sollte neu gespeichert werden.",
    reads="Liest alle PHP-, JS- und .htaccess-Dateien bis 2 MB einmal ein (Prüfsumme, nur lesend; höchstens 30.000 Dateien) und listet die Upload-Ordner. Nur Pfade und Prüfsummen werden übertragen. Auf Shared Hosting kann das einige Minuten dauern.",
    load="hoch", presets=[],
    options=[Option("save", "Diesen Lauf als Vergleichsbasis speichern (ersetzt eine vorhandene Basis)", "bool", False,
                    "Speichert nur Pfade und Prüfsummen auf diesem Computer. Speichere nur, wenn die Seite nach deiner Einschätzung sauber ist.")],
)
def compare_runs(ctx, res):
    if not ctx.s.baseline_dir or not ctx.s.baseline_key:
        raise CheckSkipped("Der Vergleich ist hier nicht verfügbar.")
    ctx.progress("Prüfsummen berechnen")
    script = (SCRIPT.replace("@SKIP@", ctx.prof["recent_skip"]).replace("@UP@", ctx.prof["upload_dirs"])
              .replace("@MAX@", str(baseline.MAX_FILES)).replace("@MAXP@", str(baseline.MAX_FILES + 1)))
    out = ctx.sh(script, timeout=900).out
    files, uploads, cut = baseline.parse_scan(out)
    if not files:
        raise CheckSkipped("Es konnten keine Prüfsummen berechnet werden (sha256sum fehlt oder Ordner leer).")
    base = baseline.load(ctx.s.baseline_dir, ctx.s.baseline_key)
    want_save = str(ctx.opt("save", "")).lower() in ("1", "true", "yes", "ja", "on")
    if cut:
        res.add("info", "Sehr viele Dateien: Nur die ersten %d wurden verglichen" % baseline.MAX_FILES,
                "Der Vergleich ist unvollständig. Auf sehr großen Installationen deshalb nur als Anhaltspunkt verwenden.")
    if base is None:
        res.add("info", "Noch keine Vergleichsbasis vorhanden",
                "Gefunden: %d Code-Dateien und %d Dateien in Upload-Ordnern." % (len(files), len(uploads)),
                hint="Setze beim nächsten Lauf das Häkchen 'Diesen Lauf als Vergleichsbasis speichern', wenn du die Seite für sauber hältst.")
    else:
        d = baseline.compare(base, files, uploads)
        baseline.mark_compared(ctx.s.baseline_dir, ctx.s.baseline_key)
        total = len(d["new"]) + len(d["changed"]) + len(d["deleted"])
        up_php = [p for p in d["up_new"] if CODE_RE.search(p)]
        if up_php:
            res.add("crit", "Neue Programmdateien in Upload-Ordnern seit der Basis (%d)" % len(up_php),
                    "Seit %s liegen in Ordnern für Besucher-Uploads neue PHP-/.htaccess-Dateien. Dort gehört normalerweise kein ausführbarer Code hin." % base.get("saved", "?"),
                    items=_items(up_php), hint="Datei ansehen, Herkunft klären und bei Unklarheit löschen lassen (Vorfall-Maßnahmen).")
        cfg_changed = [p for p in d["changed"] if CFG_RE.search(p)]
        cfg_new = [p for p in d["new"] if CFG_RE.search(p) and p not in up_php]
        if cfg_changed or cfg_new:                # .htaccess/.user.ini: auch bei einem großen Update nie in der Masse verstecken
            res.add("warn", "Server-Konfiguration geändert oder neu seit der Basis (%d)" % (len(cfg_changed) + len(cfg_new)),
                    "In .htaccess- und .user.ini-Dateien lassen sich Weiterleitungen, Cloaking-Regeln und vor jede Seite geladener Fremdcode verstecken. "
                    "Geändert: %d, neu: %d (Basis vom %s)." % (len(cfg_changed), len(cfg_new), base.get("saved", "?")),
                    items=_items(cfg_changed + cfg_new),
                    hint="Stammt die Änderung von dir, einem Update oder einer Erweiterung (z. B. Sicherheits-Plugin)? Wenn nicht, die Datei ansehen und Herkunft klären.")
        d = dict(d, changed=[p for p in d["changed"] if p not in cfg_changed])
        total -= len(cfg_changed) + len(cfg_new)
        rest_new = [p for p in d["new"] if p not in up_php and p not in cfg_new]
        if total >= MANY:
            res.add("info", "Viele Änderungen seit der Basis (%d): vermutlich ein Update" % total,
                    "Neu: %d, geändert: %d, gelöscht: %d (Basis vom %s). Bei so vielen Dateien wird kein Einzelbefund je Datei gemeldet." % (len(d["new"]), len(d["changed"]), len(d["deleted"]), base.get("saved", "?")),
                    hint="Wenn du kürzlich aktualisiert hast, speichere nach einer Prüfung eine neue Basis.")
        else:
            for key, sev, title, hint in (
                ("changed", "warn", "Geänderte Code-Dateien seit der Basis", "Stammt die Änderung von dir oder einem Update? Wenn nicht, die Datei prüfen."),
                ("new", "warn", "Neue Code-Dateien seit der Basis", "Gehört die Datei zu einer Installation oder einem Update? Wenn nicht, prüfen."),
                ("deleted", "info", "Gelöschte Code-Dateien seit der Basis", "Meist Folge eines Updates oder einer Deinstallation.")):
                lst = rest_new if key == "new" else d[key]
                if lst:
                    res.add(sev, "%s (%d)" % (title, len(lst)), "Basis vom %s." % base.get("saved", "?"), items=_items(lst), hint=hint)
        if d["up_new"] or d["up_deleted"]:
            non_code = [p for p in d["up_new"] if p not in up_php]
            if non_code or d["up_deleted"]:
                res.add("info", "Upload-Ordner: %d neue, %d entfernte Dateien" % (len(non_code), len(d["up_deleted"])),
                        "Neue Uploads sind normal, wenn Besucher oder Redakteure Dateien hochladen.", items=_items(non_code))
        if not (total or cfg_changed or cfg_new or up_php or d["up_new"] or d["up_deleted"]):
            res.add("ok", "Keine Abweichung von der Basis", "Alle %d Code-Dateien und die Upload-Ordner entsprechen dem Stand vom %s." % (len(files), base.get("saved", "?")))
    if want_save:
        if cut:
            res.add("warn", "Basis wurde nicht gespeichert", "Wegen der Dateimenge wäre die Basis unvollständig.")
        else:
            baseline.save(ctx.s.baseline_dir, ctx.s.baseline_key, ctx.s.baseline_label, files, uploads)
            res.add("ok", "Vergleichsbasis gespeichert", "%d Code-Dateien und %d Upload-Dateien (nur Pfade und Prüfsummen, auf deinem Computer)." % (len(files), len(uploads)))
