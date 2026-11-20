#!/usr/bin/env python3
"""Zählt die Zeilen reinen Python-Codes (claudia/ und tools/, ohne tests/).

Nicht gezählt: Leerzeilen, Kommentare, Docstrings. Eine mehrzeilige Zeichenkette (z. B. ein eingebettetes Shell- oder SQL-Skript) zählt nur mit ihrer ersten Zeile,
denn ihr Inhalt ist kein Python. Das Ergebnis steht in claudia/loc.json und wird in der Fußzeile des Programms angezeigt.

  python tools/count_loc.py            nur anzeigen
  python tools/count_loc.py --write    zusätzlich claudia/loc.json schreiben"""
from __future__ import annotations

import ast
import io
import json
import os
import sys
import tokenize
from typing import Set

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"__pycache__", "tests", ".venv", ".git", "dist", "build"}
SKIP_TOK = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER}


def _doc_lines(tree: ast.AST) -> Set[int]:
    out: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return out


def count_source(text: str) -> int:
    tree = ast.parse(text)
    doc = _doc_lines(tree)
    lines: Set[int] = set()
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type in SKIP_TOK:
            continue
        if tok.type == tokenize.STRING:
            lines.add(tok.start[0])
        elif tok.type == getattr(tokenize, "FSTRING_START", -1) or tok.type in (getattr(tokenize, "FSTRING_MIDDLE", -1), getattr(tokenize, "FSTRING_END", -1)):
            lines.add(tok.start[0])
        else:
            lines.update(range(tok.start[0], tok.end[0] + 1))
    return len(lines - doc)


def count(root: str = ROOT) -> int:
    total = 0
    for sub in ("claudia", "tools"):
        for d, dirs, fs in os.walk(os.path.join(root, sub)):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in fs:
                if f.endswith(".py"):
                    with open(os.path.join(d, f), encoding="utf-8") as fh:
                        total += count_source(fh.read())
    return total


def main(argv) -> int:
    n = count()
    print(n)
    if "--write" in argv:
        with open(os.path.join(ROOT, "claudia", "loc.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"python_lines": n}, fh)
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
