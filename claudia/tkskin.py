"""Gemeinsames Aussehen der tkinter-Fenster (Start ohne PySide6 und Deinstallation) im Stil des Startbildschirms:
helle Fensterfarbe wie das Tool, orangener Chip mit dem Namen, Logo, schlanker orangener Ladebalken, grauer Statustext mit Prozentzahl.

Nur Standardbibliothek und KEIN Import aus dem Paket claudia: Das Deinstallationsfenster läuft aus dem Temp-Ordner (mit dieser Datei und dem Logo daneben).
Nicht möglich in tkinter: weicher Schatten und abgerundete Fensterecken (nur der PySide6-Startbildschirm hat sie)."""
from __future__ import annotations

import os
import tkinter as tk
import tkinter.font  # noqa: F401  (tk.font.families)
from tkinter import ttk
from typing import Any, Optional

NAME = "CLAUDIA"
BG, INK, GRAY, ACCENT, GROOVE = "#E7EDF0", "#1B2A33", "#6B7B86", "#E96413", "#E8E8E8"
LOG_BG, OK, BAD = "#F6F9FA", "#1E8E4E", "#C62828"
BTN_BG, BTN_ACTIVE = "#D5DEE3", "#C4D0D7"
SIZES = (200, 300, 400)                    # vorbereitete Logo-Breiten (Dateien claudia_logo_tk_<Breite>.png): tkinter skaliert nicht weich, deshalb passende Datei wählen
BASE_LOGO_W = 200


def find_logo(folder: str, scale: float) -> Optional[str]:
    """Logo-Datei in der passenden Größe (200/300/400 px) im Ordner suchen; None, wenn keine da ist."""
    want = BASE_LOGO_W * scale
    for w in sorted(SIZES, key=lambda x: abs(x - want)):
        for name in ("claudia_logo_tk_%d.png" % w, "logo_%d.png" % w):
            p = os.path.join(folder, name)
            if os.path.isfile(p):
                return p
    return None


class Skin:
    """Baut das Fenster. Danach benutzbar: title_var, detail_var, pct_var, bar, text, buttons (Rahmen für Schaltflächen), set_pct()."""

    def __init__(self, root: tk.Misc, scale: float, logo_dir: str, with_log: bool = True, title: str = ""):
        self.root = root
        self.scale = scale
        root.configure(bg=BG)
        fams = set(tk.font.families(root)) if hasattr(tk, "font") else set()
        self.ui_font = "Segoe UI" if "Segoe UI" in fams else "TkDefaultFont"
        mono = next((f for f in ("Consolas", "Cascadia Mono", "Lucida Console", "DejaVu Sans Mono", "Courier New") if f in fams), "TkFixedFont")
        self.f_status = (self.ui_font, 11, "bold")
        self.f_small = (self.ui_font, 10)
        self.f_log = (mono, 10)
        self.title_var = tk.StringVar(value=title or "Starte ...")
        self.detail_var = tk.StringVar(value="")
        self.pct_var = tk.StringVar(value="0 %")
        pad = {"padx": 16}

        self.buttons = tk.Frame(root, bg=BG)
        self.buttons.pack(side="bottom", fill="x", pady=12, **pad)

        top = tk.Frame(root, bg=BG)
        top.pack(fill="x", pady=(10, 0), **pad)
        tk.Label(top, text=NAME, bg=ACCENT, fg="#FFFFFF", font=(self.ui_font, 9, "bold"), padx=10, pady=2).pack(side="left")

        self.logo_img = None
        path = find_logo(logo_dir, scale)
        if path:
            try:
                self.logo_img = tk.PhotoImage(file=path)
            except tk.TclError:
                self.logo_img = None
        if self.logo_img is not None:
            tk.Label(root, image=self.logo_img, bg=BG, bd=0).pack(pady=(6, 6))
        else:
            tk.Label(root, text=NAME, bg=BG, fg=INK, font=(self.ui_font, 26, "bold")).pack(pady=(30, 20))

        row = tk.Frame(root, bg=BG)
        row.pack(fill="x", **pad)
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Claudia.Horizontal.TProgressbar", troughcolor=GROOVE, background=ACCENT, bordercolor=GROOVE, lightcolor=ACCENT, darkcolor=ACCENT, thickness=6)
        self.bar = ttk.Progressbar(row, orient="horizontal", mode="determinate", maximum=100, style="Claudia.Horizontal.TProgressbar")
        self.bar.pack(fill="x")

        info = tk.Frame(root, bg=BG)
        info.pack(fill="x", pady=(6, 0), **pad)
        tk.Label(info, textvariable=self.pct_var, width=6, anchor="e", font=self.f_small, bg=BG, fg=GRAY).pack(side="right")
        col = tk.Frame(info, bg=BG)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, textvariable=self.title_var, anchor="w", font=self.f_status, bg=BG, fg=INK).pack(fill="x")
        self.detail_lbl = tk.Label(col, textvariable=self.detail_var, anchor="w", justify="left", font=self.f_small, bg=BG, fg=GRAY, wraplength=int(680 * scale))
        self.detail_lbl.pack(fill="x")

        self.text: Optional[tk.Text] = None
        if with_log:
            box = tk.Frame(root, bg=BG)
            box.pack(fill="both", expand=True, pady=(8, 0), **pad)
            sb = tk.Scrollbar(box)
            sb.pack(side="right", fill="y")
            self.text = tk.Text(box, height=6, wrap="word", state="disabled", bg=LOG_BG, fg=INK, relief="flat", yscrollcommand=sb.set, font=self.f_log,
                                insertbackground=INK, padx=8, pady=6, highlightthickness=1, highlightbackground=GROOVE)
            self.text.pack(side="left", fill="both", expand=True)
            sb.config(command=self.text.yview)
            self.text.tag_configure("ok", foreground=OK)
            self.text.tag_configure("bad", foreground=BAD)

    def button(self, parent: tk.Misc, text: str, command: Any, state: str = "normal", width: int = 22) -> tk.Button:
        return tk.Button(parent, text=text, width=width, font=self.f_small, command=command, state=state, bg=BTN_BG, fg=INK, activebackground=BTN_ACTIVE,
                         activeforeground=INK, relief="flat", padx=8, pady=5)

    def set_pct(self, pct: int) -> None:
        self.bar["value"] = pct
        self.pct_var.set("%d %%" % pct)

    def add_log(self, line: str, tag: Any = ()) -> None:
        if self.text is None:
            return
        self.text.configure(state="normal")
        self.text.insert("end", line.rstrip() + "\n", tag)
        self.text.see("end")
        self.text.configure(state="disabled")
