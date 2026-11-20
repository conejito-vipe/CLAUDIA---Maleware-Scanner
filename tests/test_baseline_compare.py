"""2.4.0 / B9: Vergleich mit lokal gespeicherter Basis (nur Pfade und Prüfsummen), Schutz vor Missbrauch der Kennung, Befunde."""
import json
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia import baseline  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


def world():
    load_all()
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_b9_"), False)
    w["bl"] = tempfile.mkdtemp(prefix="claudia_b9bl_")
    return w


def put(w, rel, data="<?php echo 1;"):
    p = os.path.join(w["site"], rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(data)


def run(w, save=False):
    key = baseline.make_key("h.example", "u", w["site_rel"])
    s = Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={"compare_runs": {"save": save}}, allow_hosts=[],
                 baseline_dir=w["bl"], baseline_key=key, baseline_label="h.example : site")
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    return {r.id: r for r in eng.run(["compare_runs"], lambda e: None, threading.Event())}["compare_runs"], key


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class B9(unittest.TestCase):
    def test_flow_no_base_save_clean_change_new_delete(self):
        w = world()
        r, key = run(w)
        self.assertEqual(r.status, "info", titles(r))
        self.assertIsNone(baseline.load(w["bl"], key))            # nie automatisch gespeichert
        r, _ = run(w, save=True)
        self.assertTrue(any("gespeichert" in t for _, t in titles(r)), titles(r))
        d = baseline.load(w["bl"], key)
        self.assertTrue(d and d["files"])
        raw = json.dumps(d)
        self.assertNotIn("echo", raw)                              # keine Inhalte
        r, _ = run(w)
        self.assertEqual(r.status, "ok", titles(r))
        put(w, "images/shell.php")                                  # neue PHP-Datei im Upload-Ordner
        put(w, "images/photo.jpg", "x")
        r, _ = run(w)
        self.assertTrue(any(s == "crit" and "Upload-Ordnern" in t for s, t in titles(r)), titles(r))
        self.assertTrue(any("images/shell.php" in " ".join(f.items) for f in r.findings))
        # geänderte und gelöschte Datei
        victim = sorted(p for p in d["files"] if p.endswith(".php") and "images/" not in p)[0]
        with open(os.path.join(w["site"], victim), "a") as fh:
            fh.write("\n// geändert\n")
        r, _ = run(w)
        self.assertTrue(any(s == "warn" and "Geänderte" in t for s, t in titles(r)), titles(r))
        self.assertTrue(any(victim in " ".join(f.items) for f in r.findings))
        os.remove(os.path.join(w["site"], victim))
        r, _ = run(w)
        self.assertTrue(any("Gelöschte" in t for _, t in titles(r)), titles(r))

    def test_save_replaces_and_does_not_touch_server(self):
        w = world()
        before = sorted(os.listdir(w["site"]))
        run(w, save=True)
        self.assertEqual(before, sorted(os.listdir(w["site"])))

    def test_many_changes_are_summarised(self):
        w = world()
        run(w, save=True)
        for i in range(160):
            put(w, "components/com_x/f%d.php" % i)
        r, _ = run(w)
        self.assertTrue(any(s == "info" and "Update" in t for s, t in titles(r)), titles(r))
        self.assertFalse(any("Neue Code-Dateien" in t for _, t in titles(r)))

    def test_key_validation_and_delete(self):
        w = world()
        with self.assertRaises(ValueError):
            baseline.save(w["bl"], "../../x", "l", {}, {})
        self.assertFalse(baseline.delete(w["bl"], "../x"))
        k = baseline.make_key("h", "u", "html/")
        self.assertEqual(k, baseline.make_key("H", "u", "html"))
        baseline.save(w["bl"], k, "h : html", {"./a.php": "0" * 64}, {})
        self.assertTrue(baseline.info(w["bl"], k)["exists"])
        self.assertTrue(baseline.delete(w["bl"], k))
        self.assertFalse(baseline.info(w["bl"], k)["exists"])

    def test_skipped_without_baseline_dir(self):
        load_all()
        w = world()
        s = Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={}, allow_hosts=[])
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
        r = {x.id: x for x in eng.run(["compare_runs"], lambda e: None, threading.Event())}["compare_runs"]
        self.assertEqual(r.status, "skipped")


if __name__ == "__main__":
    unittest.main()
