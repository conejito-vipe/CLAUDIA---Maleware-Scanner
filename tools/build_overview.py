#!/usr/bin/env python3
"""Erzeugt claudia_projekt.json: eine kompakte, maschinenlesbare Beschreibung des ganzen Programms.
Zweck: Als Grundlage für einen NEUEN Chat hochladen, damit der Chat nicht die ganze Vorgeschichte tragen muss.
Die Teile 'automatisch' werden aus dem Quelltext erzeugt (immer aktuell), die Teile 'handgepflegt' stehen in tools/overview_notes.json.

  python tools/build_overview.py [Ausgabedatei]"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from claudia import APP_NAME, __version__, actions, helpdocs, i18n  # noqa: E402
from claudia.registry import GROUPS, load_all, ordered  # noqa: E402


def first_doc_line(path: str) -> str:
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
        d = ast.get_docstring(tree) or ""
        return d.strip().split("\n")[0][:160]
    except (OSError, SyntaxError):
        return ""


def count_lines(path: str) -> int:
    try:
        return sum(1 for _ in open(path, encoding="utf-8"))
    except OSError:
        return 0


def modules() -> List[Dict[str, Any]]:
    out = []
    for base in ("claudia", "claudia/checks", "tools", "tests"):
        d = os.path.join(ROOT, base)
        for f in sorted(os.listdir(d)):
            if f.endswith(".py") and f != "__init__.py" and not f.startswith("_"):
                p = os.path.join(d, f)
                out.append({"datei": base + "/" + f, "zeilen": count_lines(p), "zweck": first_doc_line(p)})
    for f in ("app.js", "docs.js", "app.css", "index.html"):
        out.append({"datei": "claudia/web/" + f, "zeilen": count_lines(os.path.join(ROOT, "claudia", "web", f))})
    return out


def checks() -> List[Dict[str, Any]]:
    load_all()
    seen: Dict[str, Dict[str, Any]] = {}
    for cms in ("joomla", "wordpress"):
        for c in ordered(cms):
            e = seen.setdefault(c.id, {"id": c.id, "gruppe": c.group, "cluster": c.cluster or "", "last": c.load, "braucht": c.needs, "cms": [], "titel": c.view(cms)["title"]})
            e["cms"].append(cms)
    return list(seen.values())


def action_list() -> List[Dict[str, Any]]:
    return [{"id": k, "titel": v.get("title", ""), "risiko": v.get("risk", ""), "sicherung": bool(v.get("backup")), "nur": "joomla" if k in actions.JOOMLA_ONLY else ("wordpress" if k in actions.WP_ONLY else "beide")}
            for k, v in actions.ACTIONS.items()]


def routes() -> List[str]:
    s = open(os.path.join(ROOT, "claudia", "server.py"), encoding="utf-8").read()
    return sorted(set(re.findall(r'path == "(/api/[a-z/-]+)"', s)))


def env_vars() -> List[str]:
    found = set()
    for base in ("claudia", "tools", "tests"):
        for dp, _d, fs in os.walk(os.path.join(ROOT, base)):
            for f in fs:
                if f.endswith((".py", ".js")):
                    found |= set(re.findall(r"\bCLAUDIA_[A-Z_]+\b", open(os.path.join(dp, f), encoding="utf-8").read()))
    return sorted(found)


def tests() -> List[Dict[str, str]]:
    d = os.path.join(ROOT, "tests")
    return [{"datei": f, "zweck": first_doc_line(os.path.join(d, f))} for f in sorted(os.listdir(d)) if f.startswith("test_") and f.endswith(".py")]


def build() -> Dict[str, Any]:
    notes = json.load(open(os.path.join(ROOT, "tools", "overview_notes.json"), encoding="utf-8"))
    langs = {c: len((i18n.read_file(c).get("msg") or {})) for c in i18n.lang_files()}
    ch = checks()
    return {
        "_zweck": "Grundlage für einen neuen Chat: Beschreibung des Programms CLAUDIA (Stand %s). Zuerst 'arbeitsregeln' und 'anweisung_fuer_den_neuen_chat' lesen." % __version__,
        "programm": {"name": APP_NAME, "version": __version__, "stand": helpdocs.changelog("de")[0].get("date", "")},
        **notes,
        "automatisch": {
            "pruefgruppen": [{"id": g[0], "titel": g[1], "text": g[2]} for g in GROUPS],
            "pruefungen_anzahl": len(ch), "pruefungen": ch,
            "aktionen": action_list(), "api_routen": routes(), "umgebungsvariablen": env_vars(),
            "sprachen": {"dateien": langs, "quelle": "de"},
            "dokumentation": {"handbuch_kapitel": [s["id"] for s in helpdocs.handbook("de")], "versionen_im_verlauf": [r["version"] for r in helpdocs.changelog("de")]},
            "module": modules(), "tests": tests(),
        },
    }


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(ROOT), "claudia_projekt.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(build(), fh, ensure_ascii=False, indent=1)
    print(out, os.path.getsize(out), "Bytes")
