"""Erweiterungen: Dateien gegen das Paket des Herstellers vergleichen (2.4.1). Eigenes Modul, weil es die Datenbank-Hilfen braucht."""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List

from .. import coreref, extsums, joomla, secure, updcheck, wpsums
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line
from .database import fetch, need_db

G = "erweiterungen"


INSTALL_ONLY = re.compile(r"(^|/)(packages/|script\.install[^/]*\.php$|[^/]*installer[^/]*\.php$|install\.[^/]*$|uninstall\.[^/]*$)", re.I)


def split_missing(missing):
    """Fehlende Dateien (Form 'Erweiterung: Ordner/Datei') in normale und reine Installationsdateien trennen. Installationsdateien (Zusatz-Pakete unter packages/, script.install*.php, *installer*.php) löscht das Installationsprogramm nach der Installation selbst."""
    normal, inst = [], []
    for m in missing:
        path = m.split(": ", 1)[-1]
        (inst if INSTALL_ONLY.search(path) else normal).append(m)
    return normal, inst


def count_by_ext(entries):
    """Eine Zeile je Erweiterung mit der Zahl der Dateien (statt tausender Einzelzeilen)."""
    cnt = {}
    for m in entries:
        k = m.split(": ", 1)[0]
        cnt[k] = cnt.get(k, 0) + 1
    return ["%s: %d Datei(en)" % (k, v) for k, v in sorted(cnt.items(), key=lambda kv: -kv[1])[:30]]



@check(
    "ext_integrity", G, "Erweiterungen gegen das Paket des Herstellers prüfen",
    "Stimmen die Dateien von Erweiterungen mit dem Paket überein, das der Hersteller ausliefert?",
    what="Liest aus der Datenbank, welche Erweiterungen eine öffentliche Update-Adresse haben, und ruft dort die Update-Datei ab. Bietet der Update-Server GENAU die installierte Version an, "
         "wird deren Paket einmal geladen (nur im Speicher gelesen, nie entpackt oder ausgeführt) und die Prüfsumme jeder Datei mit der auf dem Server verglichen. "
         "Gemeldet werden geänderte, zusätzliche und fehlende PHP-Dateien. Erweiterungen ohne Update-Adresse, mit Lizenzschlüssel, mit älterer Version als auf dem Update-Server oder als Paket-Sammlung werden als nicht prüfbar aufgelistet.",
    why="Hintertüren stecken oft in Dateien echter Erweiterungen, ohne dass ein Suchmuster anschlägt. Nur der Vergleich mit dem Original zeigt, dass eine Datei nicht mehr dem entspricht, was der Hersteller ausliefert. "
        "Der Vergleich beweist die Übereinstimmung mit dem Paket, das der Hersteller aktuell ausliefert; er kann nicht beweisen, dass dieses Paket selbst sauber ist.",
    reads="Prüfsummen der Erweiterungs-Dateien (Dateien werden nicht übertragen) und die Update-Adressen aus der Datenbank. Von diesem PC aus wird je Erweiterung eine Update-Datei und ein Paket (höchstens 25 MB) vom Update-Server des Herstellers geladen (https, nacheinander, mit Pause, höchstens die eingestellte Anzahl).",
    load="mittel", presets=["hack"], cms="joomla",
    options=[Option("max", "Höchstens so viele Erweiterungen prüfen", "int", 12, "Jedes Paket wird einzeln geladen, das dauert einige Sekunden.")],
)
def ext_integrity(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Pakete werden nicht abgerufen.")
    db = need_db(ctx, res, "Erweiterungen gegen das Paket des Herstellers prüfen", [("Update-Server der Erweiterungen", updcheck.SITES_SQL)])
    rows = fetch(db, updcheck.SITES_SQL)
    sites = extsums.sites_from_rows(rows or [])
    ver = ctx.shared.get("joomla_version") or ""
    if not ver:
        r = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null").out
        a, _, b = r.partition("@@M")
        ver = joomla.parse_joomla_version(a, b)
    if not ver:
        raise CheckSkipped("Joomla-Version nicht erkannt.")
    cands = [x for x in sites if x["type"] in ("component", "module", "plugin", "template") and x["version"]]
    skipped_other = [x for x in sites if x not in cands and x["type"] == "package"]
    no_ref: List[str] = []
    err: List[str] = []
    jobs = []      # (Erweiterung, [(Ordner im ZIP, Ordner auf dem Server)], Dateien im ZIP)
    limit = max(1, ctx.opt_int("max", 12))
    cache_xml: Dict[str, Any] = {}
    checked = 0
    seen_eid = set()
    for x in cands:
        if x["eid"] in seen_eid:
            continue
        label = "%s %s" % (clean_line(x["name"]), x["version"])
        if x["needs_key"]:
            no_ref.append("%s (braucht einen Lizenzschlüssel)" % label)
            continue
        if not x["location"].startswith("https://") or not secure.is_secure_url(x["location"]):
            no_ref.append("%s (Update-Adresse ohne https)" % label)
            continue
        if checked >= limit:
            err.append("Weitere Erweiterungen wegen der Höchstzahl nicht geprüft")
            break
        seen_eid.add(x["eid"])
        checked += 1
        ctx.progress("Update-Server: %s" % re.sub(r"^https://([^/]+).*$", r"\1", x["location"])[:60])
        if x["location"] not in cache_xml:
            time.sleep(updcheck.PAUSE)
            cache_xml[x["location"]] = updcheck._get(x["location"])
        body = cache_xml[x["location"]]
        if body is None:
            err.append("%s (Update-Server nicht erreichbar)" % label)
            continue
        entries = extsums.entries_with_downloads(body, ver)
        sets = updcheck.parse_set(body)
        for ref in sets[:updcheck.MAX_FOLLOW] if not entries else []:
            if ref["url"] and updcheck._matches({"element": ref["element"], "type": ref["type"], "folder": ref["folder"], "client": int(ref["client"])}, x):
                time.sleep(updcheck.PAUSE)
                sub = updcheck._get(ref["url"])
                if sub:
                    entries += extsums.entries_with_downloads(sub, ver)
        hit = [u for u in entries if updcheck._matches(u, x) and u["version"] == x["version"] and u["urls"]]
        if not hit:
            no_ref.append("%s (der Update-Server bietet diese Version nicht an)" % label)
            continue
        try:
            time.sleep(updcheck.PAUSE)
            raw = coreref.fetch_bytes(hit[0]["urls"][0], extsums.MAX_ZIP_BYTES, timeout=40)
            files, manifest = extsums.read_zip(raw)
        except (coreref.RefError, extsums.ZipProblem) as e:
            err.append("%s (%s)" % (label, str(e)[:120]))
            continue
        tdirs = extsums.target_dirs(manifest, x)
        if not tdirs:
            no_ref.append("%s (Paketaufbau nicht unterstützt)" % label)
            continue
        jobs.append((x, label, tdirs, files))
    changed, extra, missing, ok = [], [], [], []
    if jobs:
        dirs = sorted({s for _, _, td, _ in jobs for _, s in td})
        ctx.progress("Prüfsummen auf dem Server berechnen")
        local = extsums.parse_local(ctx.sh(extsums.find_script(dirs), timeout=600).out, dirs)
        for x, label, tdirs, files in jobs:
            bad = 0
            for zdir, sdir in tdirs:
                ref = extsums.as_reference(extsums.strip_prefix(files, zdir))
                if not ref or sdir not in local:
                    continue
                d = wpsums.compare(local[sdir], ref)
                tag = x["element"]
                changed += ["%s: %s/%s" % (tag, sdir, f) for f in d["changed"] if wpsums.CODE_RE.search(f)] if x["type"] != "template" else []
                tchg = ["%s: %s/%s" % (tag, sdir, f) for f in d["changed"] if wpsums.CODE_RE.search(f)] if x["type"] == "template" else []
                extra += ["%s: %s/%s" % (tag, sdir, f) for f in d["extra"]] + tchg
                missing += ["%s: %s/%s" % (tag, sdir, f) for f in d["missing"]]
                bad += len([f for f in d["changed"] if wpsums.CODE_RE.search(f)]) + len(d["extra"]) + len(d["missing"])
            if not bad:
                ok.append(label)
    if changed:
        res.add("crit", "%d Erweiterungs-Datei(en) weichen vom Paket des Herstellers ab" % len(changed),
                "Der Inhalt unterscheidet sich vom Paket, das der Update-Server für genau diese Version ausliefert. Entweder wurde die Datei manipuliert, oder jemand hat sie von Hand geändert.",
                changed[:60], "Erweiterung über Joomla neu installieren (Erweiterungen -> Verwalten -> Update bzw. gleiches Paket erneut installieren). Eigene Änderungen vorher sichern.")
    if extra:
        res.add("warn", "%d zusätzliche oder (bei Templates) geänderte PHP-Datei(en) in Erweiterungs-Ordnern" % len(extra),
                "Diese Dateien gehören nicht zum Paket des Herstellers oder wurden an einem Template geändert (Anpassungen sind dort üblich). Ein Versteck für Hintertüren ist möglich.",
                extra[:60], "Dateien ansehen (nicht ausführen). Ohne bekannte Herkunft löschen.")
    if missing:
        normal, inst = split_missing(missing)
        if inst:
            res.add("ok", "%d Installationsdatei(en) des Pakets fehlen (normal)" % len(inst),
                    "Diese Dateien dienen nur der Installation: Das Installationsprogramm der Erweiterung entpackt sie, installiert damit mitgelieferte Zusatz-Erweiterungen und löscht sie danach wieder. "
                    "Dass sie auf dem Server fehlen, ist der Normalfall. Es muss nichts nachgeladen werden.", count_by_ext(inst))
        if normal:
            res.add("info", "%d PHP-Datei(en) des Pakets fehlen auf dem Server" % len(normal),
                    "Das Paket des Herstellers enthält diese Dateien, auf deinem Server liegen sie nicht. Die Erweiterung kann dann Fehler zeigen oder einzelne Funktionen verlieren. "
                    "Ursachen: ein abgebrochenes Update, ein Virenscanner des Hosters, der Dateien entfernt hat, oder jemand hat sie gelöscht.",
                    count_by_ext(normal) + normal[:30],
                    "Erweiterung über Joomla neu installieren (Erweiterungen -> Verwalten -> Aktualisieren, oder das gleiche Paket noch einmal installieren). Das stellt die fehlenden Dateien wieder her; Einstellungen und Daten bleiben erhalten.")
    if no_ref or skipped_other:
        items = no_ref[:60] + ["%s (Paket-Sammlung, Inhalt wird einzeln geprüft)" % clean_line(x["name"]) for x in skipped_other[:10]]
        res.add("info", "%d Erweiterung(en) nicht prüfbar" % len(no_ref), "Ohne öffentliche Update-Adresse, mit Lizenzschlüssel oder wenn der Update-Server die installierte Version nicht mehr anbietet, gibt es nichts zum Vergleichen.", items)
    if err:
        res.add("info", "Nicht alles konnte geprüft werden", "", err[:20])
    if ok and not (changed or extra):
        res.add("ok", "%d Erweiterung(en) stimmen mit dem Paket des Herstellers überein" % len(ok), "Vergleich mit dem Paket des Update-Servers.", ok[:60])
