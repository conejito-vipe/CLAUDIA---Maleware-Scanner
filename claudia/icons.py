"""Technisches Icon-Set (einfache Linien-Symbole, 24x24, ohne Farben). Eine Quelle für Oberfläche und HTML-Bericht (icons.json)."""
from __future__ import annotations

import json
import os
from typing import Dict

_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons.json")
_CACHE: Dict[str, str] = {}


def all_icons() -> Dict[str, str]:
    if not _CACHE:
        with open(_FILE, encoding="utf-8") as fh:
            _CACHE.update(json.load(fh))
    return dict(_CACHE)


def svg(name: str, cls: str = "ic") -> str:
    """Fertiges <svg>-Element als Text (für den HTML-Bericht). Unbekannter Name -> leer."""
    inner = all_icons().get(name)
    if not inner:
        return ""
    return "<svg class='%s' viewBox='0 0 24 24' aria-hidden='true' focusable='false'>%s</svg>" % (cls, inner)
