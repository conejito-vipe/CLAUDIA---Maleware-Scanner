"""2.4.0 / A9: recent_changes wertet zusätzlich die ctime aus (höchstens Hinweis/Warnung, nie kritisch)."""
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from test_checks import ADV, has, titles  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

OLD = time.time() - 400 * 86400


def run_recent(files, backdate):
    """files: {rel: Inhalt}; backdate: Pfade, deren mtime weit zurückgestellt wird (ctime bleibt jetzt)."""
    load_all()
    base = tempfile.mkdtemp(prefix="claudia_a9_")
    w = fixture.make_world(base, False)
    for rel, data in files.items():
        p = os.path.join(w["site"], rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data.encode())
    for rel in backdate:
        os.utime(os.path.join(w["site"], rel), (OLD, OLD))
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={}, allow_hosts=[]), ADV)
    return {r.id: r for r in eng.run(["recent_changes"], lambda e: None, threading.Event())}["recent_changes"]


class A9(unittest.TestCase):
    def test_backdated_php_outside_ext_dirs_is_warning_never_crit(self):
        r = run_recent({"images/stealth.php": "<?php echo 1;", "media/readme.txt": "x"}, ["images/stealth.php", "media/readme.txt"])
        w = [f for f in r.findings if "ctime" in f.title or "Eintrag kürzlich geändert" in f.title]
        self.assertTrue(w, titles(r))
        self.assertTrue(any(f.sev == "warn" and "stealth.php" in " ".join(f.items) for f in w), titles(r))
        # readme.txt (kein ausführbarer Typ) liegt mit den Dateien der Testwelt in derselben Stunde, also in der Massenänderung: nur gezählt, nicht genannt
        self.assertTrue(any(f.sev == "info" and "Massenänderung" in f.title for f in w), titles(r))
        self.assertFalse(any("readme.txt" in " ".join(f.items) for f in w))
        self.assertFalse(any(f.sev == "crit" for f in w))
        self.assertIn("touch", " ".join((f.detail or "") for f in w))

    def test_single_change_outside_a_mass_hour_is_listed_as_info(self):
        r = run_recent({"media/readme.txt": "x"}, ["media/readme.txt"])
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)))
        # ctime-Stunde der Datei künstlich unterscheiden geht nicht; daher Auswertung direkt prüfen
        from claudia.checks import files as F
        class Res:
            def __init__(s): s.f = []
            def add(s, sev, title, detail="", items=None, hint=""): s.f.append((sev, title, items or []))
        class Ctx:
            prof = {}
        res = Res()
        F._ctime_findings(Ctx(), res, "C\t2026-11-01 10:00\t5\t2025-01-01\t./media/readme.txt\nC\t2026-11-01 10:01\t5\t2025-01-01\t./components/a.php\n", 30)
        self.assertEqual([x[0] for x in res.f], ["info"])
        self.assertIn("readme.txt", " ".join(res.f[0][2]))
        self.assertIn("a.php", " ".join(res.f[0][2]))

    def test_mass_change_is_one_info_without_listing_files(self):
        files = {"media/bulk/f%d.txt" % i: "x" for i in range(40)}
        r = run_recent(files, list(files))
        f = [x for x in r.findings if "Massenänderung" in x.title]
        self.assertEqual(len(f), 1, titles(r))
        self.assertEqual(f[0].sev, "info")
        self.assertFalse(any("f1.txt" in " ".join(x.items) for x in r.findings if "ctime" in x.title))

    def test_no_ctime_finding_when_mtime_is_recent_too(self):
        r = run_recent({"media/new.txt": "x"}, [])
        # Die Dateien der Testwelt selbst haben eine alte mtime und eine frische ctime; entscheidend ist, dass new.txt (mtime frisch) nicht als ctime-Fund auftaucht
        self.assertFalse(any("new.txt" in " ".join(f.items) for f in r.findings if "ctime" in f.title or "Eintrag kürzlich" in f.title), titles(r))

    def test_fix_permissions_texts_mention_ctime(self):
        from claudia import actions
        self.assertIn("ctime", actions.ACTIONS["fix_permissions"]["warning"])


if __name__ == "__main__":
    unittest.main()
