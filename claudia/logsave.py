"""Protokolle vom Server auf den eigenen PC sichern (nur lesend auf dem Server).

Hintergrund: Hoster wie hosting.de löschen alte Zugriffsprotokolle automatisch. Wer sie später für eine
Untersuchung braucht, hat sie dann nicht mehr. Dieses Modul kopiert sie regelmäßig auf den eigenen Rechner.

Auf dem Server laufen ausschließlich 'find' (Liste) und 'head -c <Größe> -- <Datei>' (Kopie).
Beides verändert nichts. Die Datei wird nur kopiert, wenn sie vorher in der Liste stand.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import time
from typing import Any, Dict, List

from .runner import Runner, RunnerError
from .util import lines_of, sq, split_sections

MANIFEST = "SICHERUNG_manifest.json"
SUMS = "SICHERUNG_PRUEFSUMMEN.txt"
README = "SICHERUNG_LIESMICH.txt"
META_PREFIX = "SICHERUNG_"

HOSTER_CANDS = ["logs", "log", "access-logs", "access_log", "../logs", "../log"]
MAX_FILES = 2000
MIN_FREE_RESERVE = 500 * 1024 * 1024     # so viel bleibt auf der Platte immer frei


class LogSaveError(Exception):
    pass


# ----------------------------------------------------------------------------- Pfade
def host_slug(host: str, user: str = "") -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (host or "server").strip().lower()).strip("._") or "server"
    return s[:60]


WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)", re.I)


def safe_rel(rel: str) -> str:
    """Macht aus einem Server-Pfad einen sicheren, relativen Windows/Linux-Pfad (keine '..', keine Sonderzeichen)."""
    parts = []
    for p in re.split(r"[\\/]+", rel):
        p = p.strip()
        if not p or p in (".", ".."):
            continue
        p = re.sub(r'[<>:"|?*\x00-\x1f]', "_", p).rstrip(". ")
        if WIN_RESERVED.match(p):                 # CON, NUL, COM1 ... sind unter Windows Gerätenamen, auch mit Endung (nul.log)
            p = "_" + p
        if p:
            parts.append(p[:120])
    if not parts:
        raise LogSaveError("Ungültiger Dateiname.")
    return "/".join(parts)


def stamped(rel: str, when: float) -> str:
    """access.log.gz -> access.log.20261030-0912.gz (die Endung .gz bleibt erhalten, damit die Auswertung sie liest)."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when))
    d, _, name = rel.rpartition("/")
    gz = ""
    if name.lower().endswith(".gz"):
        name, gz = name[:-3], name[-3:]
    base, dot, ext = name.rpartition(".")
    new = ("%s.%s.%s" % (base, stamp, ext) if dot and base else "%s.%s" % (name, stamp)) + gz
    return (d + "/" if d else "") + new


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------- Liste auf dem Server
LIST_SCRIPT = r"""
echo '@@HOSTER'
for d in @CANDS@; do
  case "$d" in /*) p="$d";; "~"/*) p="$HOME/${d#\~/}";; *) p="$HOME/$d";; esac
  [ -d "$p" ] || continue
  r=$(cd -- "$p" 2>/dev/null && pwd -P) || continue
  printf 'ROOT\t%s\n' "$r"
  find "$r" -maxdepth 4 -type f \( -iname '*log*' -o -iname '*.gz' -o -iname '*.log.*' \) -printf 'LF\t%s\t%T@\t%p\n' 2>/dev/null
done | head -@MAX@
echo '@@JOOMLA'
if [ -d administrator/logs ]; then
  r=$(cd -- administrator/logs && pwd -P)
  printf 'ROOT\t%s\n' "$r"
  find "$r" -maxdepth 2 -type f -printf 'LF\t%s\t%T@\t%p\n' 2>/dev/null | head -@MAX@
fi
echo '@@WORDPRESS'
if [ -d wp-content ]; then
  r=$(cd -- wp-content && pwd -P)
  printf 'ROOT\t%s\n' "$r"
  find "$r" -maxdepth 1 -type f \( -name 'debug.log*' -o -name '*.log' -o -name 'error_log*' \) -printf 'LF\t%s\t%T@\t%p\n' 2>/dev/null | head -@MAX@
fi
"""


def list_remote(runner: Runner, site_dir: str, log_dir: str = "", include_joomla: bool = True) -> List[Dict[str, Any]]:
    cands = [log_dir.strip()] if log_dir.strip() else HOSTER_CANDS
    script = LIST_SCRIPT.replace("@CANDS@", " ".join(sq(c) for c in cands)).replace("@MAX@", str(MAX_FILES))
    r = runner.sh(site_dir, script, timeout=90)
    if r.timed_out:
        raise LogSaveError("Die Dateiliste vom Server kam nicht rechtzeitig an.")
    sec = split_sections(r.out)
    items: List[Dict[str, Any]] = []
    seen = set()
    for label, key, on in (("hoster", "HOSTER", True), ("joomla", "JOOMLA", include_joomla), ("wordpress", "WORDPRESS", include_joomla)):
        if not on:
            continue
        roots: List[str] = []
        for ln in lines_of(sec.get(key, "")):
            p = ln.split("\t")
            if p[0] == "ROOT" and len(p) >= 2:
                roots.append(p[1])
            elif p[0] == "LF" and len(p) >= 4:
                path = p[3]
                if path in seen:
                    continue
                seen.add(path)
                try:
                    size, mtime = int(p[1]), int(float(p[2]))
                except ValueError:
                    continue
                root = next((x for x in sorted(roots, key=len, reverse=True) if path.startswith(x.rstrip("/") + "/")), "")
                inside = path[len(root):].lstrip("/") if root else os.path.basename(path)
                lead = (os.path.basename(root.rstrip("/")) + "/") if (label == "hoster" and root) else ""
                try:
                    rel = label + "/" + safe_rel(lead + inside)
                except LogSaveError:
                    continue
                items.append({"source": label, "remote": path, "rel": rel, "size": size, "mtime": mtime})
    items.sort(key=lambda x: (x["source"], x["mtime"], x["rel"]))
    return items


# ----------------------------------------------------------------------------- lokales Archiv
class Archive:
    def __init__(self, base_dir: str, host: str):
        self.dir = os.path.join(base_dir, host_slug(host))
        self.mpath = os.path.join(self.dir, MANIFEST)
        self.manifest: Dict[str, Any] = {"files": {}}
        if os.path.isfile(self.mpath):
            try:
                with open(self.mpath, "r", encoding="utf-8") as fh:
                    m = json.load(fh)
                if isinstance(m, dict) and isinstance(m.get("files"), dict):
                    self.manifest = m
            except (OSError, ValueError):
                pass

    def _known(self) -> Dict[str, Dict[str, Any]]:
        return self.manifest["files"]

    def classify(self, it: Dict[str, Any]) -> str:
        """'neu' | 'vorhanden' (gleiche Datei schon gesichert) | 'geaendert' (gleicher Name, anderer Inhalt)"""
        rec = self._known().get(it["rel"])
        if not rec:
            return "neu"
        # Mit Zeitstempel versehene Versionen zählen mit: gleiche Größe und Zeit = schon gesichert.
        for v in [rec] + list(rec.get("versions", [])):
            if v.get("size") == it["size"] and abs(int(v.get("mtime", 0)) - it["mtime"]) <= 2 \
                    and os.path.isfile(os.path.join(self.dir, v["local"])) and os.path.getsize(os.path.join(self.dir, v["local"])) == it["size"]:
                return "vorhanden"
        return "geaendert"

    def target(self, it: Dict[str, Any], state: str, now: float) -> str:
        return it["rel"] if state == "neu" else stamped(it["rel"], now)

    def record(self, it: Dict[str, Any], local_rel: str, sha: str, when: float) -> None:
        entry = {"local": local_rel, "size": it["size"], "mtime": it["mtime"], "sha256": sha,
                 "saved": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(when)), "remote": it["remote"]}
        rec = self._known().get(it["rel"])
        if not rec:
            self._known()[it["rel"]] = entry
        else:
            rec.setdefault("versions", []).append(entry)
        self.write()

    def write(self) -> None:
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.mpath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh, indent=1, ensure_ascii=False)
        os.replace(tmp, self.mpath)
        lines = []
        for rel in sorted(self._known()):
            rec = self._known()[rel]
            for v in [rec] + list(rec.get("versions", [])):
                lines.append("%s  %s" % (v["sha256"], v["local"]))
        with open(os.path.join(self.dir, SUMS), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        with open(os.path.join(self.dir, README), "w", encoding="utf-8") as fh:
            fh.write(README_TEXT)


README_TEXT = """Gesicherte Server-Protokolle (CLAUDIA)
=====================================================

Diese Dateien wurden vom Server nur KOPIERT, nichts wurde dort verändert oder gelöscht.

 hoster/   Protokolle aus dem Log-Ordner des Hosters (Zugriffs- und Fehlerprotokolle)
 joomla/   Protokolle aus administrator/logs der Joomla-Installation
 wordpress/ Protokolle aus wp-content (debug.log u. ä.) der WordPress-Installation

 SICHERUNG_PRUEFSUMMEN.txt   SHA-256 jeder Datei zum Zeitpunkt der Sicherung. So lässt sich später belegen,
                             dass eine Datei nicht nachträglich verändert wurde (Prüfung z. B. mit: certutil -hashfile <Datei> SHA256).
 SICHERUNG_manifest.json     Merkzettel des Programms, damit schon gesicherte Dateien nicht doppelt kopiert werden.

Datenschutz: Zugriffsprotokolle enthalten IP-Adressen deiner Besucher. Das sind personenbezogene Daten.
Bewahre diesen Ordner nur auf deinem eigenen Rechner oder einem verschlüsselten Laufwerk auf, gib ihn nicht
unnötig weiter und lösche die Dateien, wenn du sie nicht mehr brauchst (Aufbewahrung nur so lange wie nötig).
Das Programm nimmt diesen Ordner NICHT in die Berichts-ZIP für Claude auf.

Auswerten: Im Programm den Test 'Zugriffsprotokoll von diesem PC auswerten' wählen und als Pfad diesen Ordner angeben.
"""


# ----------------------------------------------------------------------------- Plan und Job
def plan(archive: Archive, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    todo, have = [], []
    for it in items:
        st = archive.classify(it)
        (have if st == "vorhanden" else todo).append(dict(it, state=st))
    total = sum(x["size"] for x in todo)
    try:
        os.makedirs(archive.dir, exist_ok=True)
        free = shutil.disk_usage(archive.dir).free
    except OSError:
        free = 0
    return {
        "files": len(items), "new": len([x for x in todo if x["state"] == "neu"]),
        "changed": len([x for x in todo if x["state"] == "geaendert"]), "have": len(have),
        "bytes": total, "free": free, "fits": total + MIN_FREE_RESERVE <= free,
        "oldest": min((x["mtime"] for x in items), default=0), "newest": max((x["mtime"] for x in items), default=0),
        "todo": todo, "dir": archive.dir,
    }


class SaveJob:
    """Läuft in einem eigenen Thread; die Oberfläche fragt den Fortschritt ab."""

    def __init__(self, runner: Runner, site_dir: str, archive: Archive, todo: List[Dict[str, Any]]):
        self.runner, self.site_dir, self.archive, self.todo = runner, site_dir, archive, todo
        self.allowed = {x["remote"] for x in todo}
        self.cancel = threading.Event()
        self.total_bytes = sum(x["size"] for x in todo)
        self.done_bytes = 0
        self.done_files = 0
        self.current = ""
        self.failed: List[str] = []
        self.saved: List[str] = []
        self.finished = False
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self._work, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def state(self) -> Dict[str, Any]:
        return {"done": self.finished, "files": len(self.todo), "done_files": self.done_files, "bytes": self.total_bytes,
                "done_bytes": self.done_bytes, "current": self.current, "failed": list(self.failed), "saved": len(self.saved),
                "elapsed": round(time.monotonic() - self.started, 1), "dir": self.archive.dir, "cancelled": self.cancel.is_set()}

    def _work(self) -> None:
        try:
            base_done = 0
            for it in self.todo:
                if self.cancel.is_set():
                    break
                self.current = it["rel"]
                try:
                    self._one(it, base_done)
                except (RunnerError, OSError, LogSaveError) as e:
                    self.failed.append("%s: %s" % (it["rel"], e))
                base_done += it["size"]
                self.done_bytes = base_done
                self.done_files += 1
        finally:
            self.current = ""
            self.finished = True

    def _one(self, it: Dict[str, Any], base_done: int) -> None:
        if it["remote"] not in self.allowed:
            raise LogSaveError("Datei war nicht in der Liste.")
        now = time.time()
        state = it.get("state", "neu")
        local_rel = safe_rel(self.archive.target(it, state, now))
        dest = os.path.join(self.archive.dir, *local_rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        part = dest + ".teil"
        # head -c: genau die Größe aus der Liste. Wächst die Datei inzwischen, wird sie am gleichen Punkt abgeschnitten,
        # so lässt sich die Kopie eindeutig prüfen.
        cmd = "nice -n 15 head -c %d -- %s" % (it["size"], sq(it["remote"]))
        timeout = max(120.0, it["size"] / (200 * 1024.0))     # mindestens 200 KB/s erwartet
        try:
            with open(part, "wb") as fh:
                res = self.runner.fetch(cmd, fh, timeout=timeout, max_bytes=it["size"] + 1024, cancel=self.cancel,
                                        progress=lambda n: setattr(self, "done_bytes", base_done + n))
            if res.cancelled:
                raise LogSaveError("abgebrochen")
            if res.timed_out:
                raise LogSaveError("Zeitüberschreitung beim Kopieren")
            if not res.ok:
                raise LogSaveError("Server meldet Fehler (%s)" % (res.err.strip()[:120] or "Code %s" % res.rc))
            if os.path.getsize(part) != it["size"]:
                raise LogSaveError("Datei hat sich während des Kopierens verändert (%d statt %d Byte); beim nächsten Mal erneut versuchen"
                                   % (os.path.getsize(part), it["size"]))
            sha = sha256_file(part)
            os.replace(part, dest)
        finally:
            if os.path.exists(part):
                try:
                    os.remove(part)
                except OSError:
                    pass
        self.archive.record(it, local_rel, sha, now)
        self.saved.append(local_rel)
