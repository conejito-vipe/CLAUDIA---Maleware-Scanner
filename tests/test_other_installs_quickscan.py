"""2.4.0 / A12: optionaler Schnellscan weiterer Installationen im selben Konto (lesend, Auswahl, Zeitgrenze)."""
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
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


def put(root, rel, data):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(data)


def run(w, opts):
    load_all()
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={"other_installs": opts}, allow_hosts=[]), ADV)
    return {r.id: r for r in eng.run(["other_installs"], lambda e: None, threading.Event())}["other_installs"]


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class A12(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_a12_"), False)
        self.root = os.path.join(self.w["home"])
        self.before = {}

    def snapshot(self):
        out = {}
        for dp, _, fs in os.walk(self.w["home"]):
            for f in fs:
                p = os.path.join(dp, f)
                out[p] = (os.path.getsize(p), os.path.getmtime(p))
        return out

    def test_off_by_default(self):
        r = run(self.w, {})
        self.assertFalse(any("Schnellscan" in t for _, t in titles(r)), titles(r))

    def test_scan_finds_shell_and_php_in_uploads_in_other_install_only(self):
        put(self.root, "html/blog/wp-content/uploads/2026/x.php", "<?php echo 1;")
        put(self.root, "html/blog/wp-content/plugins/p/p.php", "<?php @eval(base64_decode($_POST['x']));")
        put(self.root, "html/site2/images/ok.jpg", "x")
        snap = self.snapshot()
        r = run(self.w, {"scan": True})
        t = titles(r)
        self.assertTrue(any(s == "crit" and "Upload-Ordnern" in x and "blog" in x for s, x in t), t)
        self.assertTrue(any(s == "warn" and "Hintertür-Muster" in x and "blog" in x for s, x in t), t)
        self.assertTrue(any(s == "ok" and "ohne Befund: html/site2" in x for s, x in t), t)
        self.assertEqual(snap, self.snapshot())                      # rein lesend

    def test_selection_limits_scan(self):
        put(self.root, "html/blog/wp-content/uploads/x.php", "<?php echo 1;")
        r = run(self.w, {"scan": True, "names": "site2"})
        t = titles(r)
        self.assertFalse(any("blog" in x and x.startswith(("WordPress:", "Schnellscan")) for _, x in t), t)
        self.assertTrue(any("html/site2" in x for _, x in t), t)
        r = run(self.w, {"scan": True, "names": "gibtsnicht"})
        self.assertTrue(any("keine passende" in x for _, x in titles(r)), titles(r))


if __name__ == "__main__":
    unittest.main()
