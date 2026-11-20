"""2.3.1: Kontrolle nach einer Aktion (Prüfungen noch einmal lesend ausführen und vorher/nachher vergleichen)."""
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.server import ActionJob  # noqa: E402

ADV = {"allow_hosts": [], "advisories": []}


class Stub:
    advisories = ADV

    def __init__(self, runner, settings, results):
        self.runner, self.last_settings, self.results = runner, settings, results

    def cms(self):
        return "joomla"


class Recheck(unittest.TestCase):
    def test_before_after_for_remove_shells(self):
        r, w = t2.world(infected=True)
        st = Settings(site_dir=w["site_rel"], log_dir="logs", cms="joomla")
        first = Engine(r, st, ADV).run(["webshells", "php_in_uploads"], lambda e: None, threading.Event())
        before = [x.to_dict() for x in first]
        crit_before = sum(1 for x in first if x.id == "webshells" for f in x.findings if f.sev == "crit")
        self.assertGreater(crit_before, 0)
        av = {a["id"]: a for a in actions.available(before, {"php": ""}, "8.3")}
        params = dict(av["remove_shells"]["params"])
        params["selected_pick"] = [x["key"] for x in params["pick"]]
        res = actions.run_action(r, w["site_rel"], "remove_shells", params, [], allowed_files=params["files"])
        self.assertTrue(res["ok"], res)
        tp = dict(av["clean_tmp"]["params"])
        self.assertTrue(actions.run_action(r, w["site_rel"], "clean_tmp", tp, [])["ok"])
        job = ActionJob(Stub(r, st, before), {"id": "remove_shells", "title": "x", "params": {}}, {})
        rc = job._recheck("remove_shells")
        ids = {c["id"]: c for c in rc}
        self.assertIn("webshells", ids)
        self.assertTrue(ids["webshells"]["better"])
        self.assertTrue(ids["webshells"]["before"].startswith("Vorher: "))
        self.assertTrue(ids["webshells"]["after"].startswith("Jetzt: 0 kritisch"), ids["webshells"])      # Hintertüren weg, tmp geleert
        self.assertIn("kritisch", ids["php_in_uploads"]["after"])
        self.assertTrue(any("Kontrolle nach der Aktion" in e["text"] for e in job.events))

    def test_no_previous_run_or_unmapped_action_gives_nothing(self):
        r, w = t2.world()
        st = Settings(site_dir=w["site_rel"], cms="joomla")
        job = ActionJob(Stub(r, st, []), {"id": "backup_now", "title": "x", "params": {}}, {})
        self.assertEqual(job._recheck("backup_now"), [])
        self.assertEqual(job._recheck("remove_shells"), [])           # kein Stand vorher -> kein Vergleich
        job = ActionJob(Stub(r, None, []), {"id": "x", "title": "x", "params": {}}, {})
        self.assertEqual(job._recheck("remove_shells"), [])

    def test_recheck_failure_never_breaks(self):
        r, w = t2.world()
        class Boom(Stub):
            def cms(self):
                raise RuntimeError("kaputt")
        job = ActionJob(Boom(r, None, []), {"id": "x", "title": "x", "params": {}}, {})
        self.assertEqual(job._recheck("remove_shells"), [])


if __name__ == "__main__":
    unittest.main()
