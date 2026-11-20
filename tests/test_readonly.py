"""Beweis für die Zusage 'nur lesen': nach einem Komplettlauf ist die Testseite (Dateien und Datenbank) unverändert."""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixture  # noqa: E402
import webfixture  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))


def snapshot(*roots):
    snap = {}
    for root in roots:
        for dp, dn, fn in os.walk(root):
            for n in dn + fn:
                p = os.path.join(dp, n)
                st = os.lstat(p)
                h = ""
                if os.path.isfile(p) and not os.path.islink(p):
                    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                snap[p] = (st.st_size, st.st_mtime_ns, st.st_mode, h)
    return snap


class ReadOnly(unittest.TestCase):
    def test_full_run_changes_nothing(self):
        load_all()
        for infected in (True, False):
            base = tempfile.mkdtemp(prefix="claudia_ro_")
            w = fixture.make_world(base, infected)
            srv, url = webfixture.start(infected)
            try:
                before = snapshot(w["home"], os.path.dirname(w["db"]))
                s = Settings(site_dir=w["site_rel"], url=url, log_dir="logs",
                             opts={"local_logs": {"path": os.path.join(w["home"], "logs")}})
                res = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV).run(
                    [c.id for c in ordered()], lambda e: None, threading.Event())
                self.assertGreaterEqual(len(res), 25)
                after = snapshot(w["home"], os.path.dirname(w["db"]))
            finally:
                srv.shutdown()
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            self.assertEqual(changed, [], "Folgende Dateien wurden verändert/angelegt/gelöscht: %s" % changed[:10])


if __name__ == "__main__":
    unittest.main()
