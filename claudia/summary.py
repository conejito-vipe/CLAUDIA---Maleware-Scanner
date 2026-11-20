"""Gesamtbewertung aus den Testergebnissen (für Oberfläche und Bericht)."""
from __future__ import annotations

from typing import Any, Dict, Iterable

CAVEAT = ("Das Programm sucht nach bekannten Spuren. \"Keine Auffälligkeiten\" bedeutet nicht, dass eine Seite "
          "nachweislich sauber ist - nur, dass diese Prüfungen nichts gefunden haben.")


def summarize(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"ok": 0, "info": 0, "warn": 0, "crit": 0, "error": 0, "skipped": 0}
    findings = {"info": 0, "warn": 0, "crit": 0}
    total = 0
    for r in results:
        total += 1
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        for f in r.get("findings", []):
            if f["sev"] in findings:
                findings[f["sev"]] += 1
    not_run = counts["error"] + counts["skipped"]
    if total == 0:
        level, head, text = "none", "Noch keine Ergebnisse", "Starte eine Prüfung, um ein Ergebnis zu sehen."
    elif counts["crit"]:
        level = "crit"
        head = "Kritische Befunde gefunden"
        text = ("%d Test%s mit kritischem Befund. Diese Punkte zuerst bearbeiten, danach die Prüfung wiederholen."
                % (counts["crit"], "" if counts["crit"] == 1 else "s"))
    elif counts["warn"]:
        level = "warn"
        head = "Einige Punkte brauchen einen Blick"
        text = ("%d Test%s mit Hinweis auf etwas Prüfenswertes. Nichts davon ist für sich allein ein Beweis für einen Angriff."
                % (counts["warn"], "" if counts["warn"] == 1 else "s"))
    else:
        level = "ok"
        head = "Keine Auffälligkeiten gefunden"
        text = "In den durchgeführten Tests gab es keine Warnung und keinen kritischen Befund."
    if not_run and total:
        text += " %d Test%s konnte%s nicht vollständig laufen (siehe 'Übersprungen' bzw. 'Fehlgeschlagen')." % (
            not_run, "" if not_run == 1 else "s", "" if not_run == 1 else "n")
    return {"level": level, "headline": head, "text": text, "caveat": CAVEAT,
            "counts": counts, "findings": findings, "total": total}
