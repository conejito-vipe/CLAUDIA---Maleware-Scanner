"""2.4.1 Punkt 9: Maßnahmenplan eingebaut (Server, Bericht, Oberfläche). Der Kern (claudia/actionplan.py) hat eigene Tests in test_action_plan.py;
hier steht, was nur im Zusammenspiel mit dem restlichen Programm geprüft werden kann (Aktionsliste, Cluster, Bericht)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_report as tr  # noqa: E402
from claudia import actionplan, actions, report  # noqa: E402
from claudia.registry import cluster_map, load_all, ordered  # noqa: E402

ROOT = os.path.dirname(HERE)


class Consistency(unittest.TestCase):
    """Fällt auf, wenn später eine Aktion, ein Cluster oder die Reihenfolge geändert wird und der Plan nicht mitzieht."""

    def test_order_is_copy_of_step_order(self):
        self.assertEqual(list(actions.STEP_ORDER), actionplan.ACTION_ORDER)

    def test_every_action_has_a_phase(self):
        for aid in actions.ACTIONS:
            if aid not in actionplan.NEVER_IN_PLAN:
                self.assertIn(aid, actionplan.ACTION_TO_PHASE, aid)
        for aid in actionplan.ACTION_TO_PHASE:
            self.assertIn(aid, actions.ACTIONS, aid)

    def test_every_cluster_of_both_systems_has_a_phase(self):
        load_all()
        for cms in ("joomla", "wordpress"):
            m = cluster_map(cms)
            self.assertTrue(m)
            for cid, cl in m.items():
                self.assertTrue(cl, "%s ohne Cluster (%s)" % (cid, cms))
                self.assertIn(cl, actionplan.CLUSTER_TO_PHASE, "%s/%s" % (cid, cl))

    def test_wordpress_uses_own_cluster_else_shared(self):
        load_all()
        wp = cluster_map("wordpress")
        for c in ordered("wordpress"):
            self.assertEqual(wp[c.id], c.cluster_wp or c.cluster)
        for c in ordered("joomla"):
            self.assertEqual(cluster_map("joomla")[c.id], c.cluster)

    def test_shell_finding_lands_in_intrusion_phase_for_both_systems(self):
        for cms in ("joomla", "wordpress"):
            r = [{"id": "webshells", "title": "Webshells", "status": "crit", "findings": [{"sev": "crit", "title": "Shell gefunden"}]}]
            p = actionplan.build_plan(r, [], cms, cluster_map(cms))
            self.assertEqual([x["id"] for x in p["phases"]], ["einbruch"], cms)


class InBundle(unittest.TestCase):
    """Seit 2.5.0 zeigt der Bericht keinen Maßnahmenplan mehr, sondern die Liste "Nur beim Hoster änderbar" (claudia/hoster.py)."""

    def test_report_has_no_action_plan_section(self):
        b, _ = tr.make_bundle(infected=True)
        txt, html = report.render_txt(b), report.render_html(b)
        self.assertNotIn("MASSNAHMENPLAN", txt)
        self.assertNotIn("Maßnahmenplan", html)
        self.assertIn("hoster", b)

    def test_hoster_section_shown_when_items_exist(self):
        b, _ = tr.make_bundle(infected=True)
        b["hoster"] = {"items": [{"check": "php_settings", "title": "7 von 7 gefährlichen Funktionen sind nicht gesperrt", "sev": "warn",
                                  "ask": "In der PHP-Einstellung disable_functions bitte ergänzen: exec."}],
                       "mail": {"subject": "Betreff X", "body": "Guten Tag,\n\n1. Punkt"}}
        txt, html = report.render_txt(b), report.render_html(b)
        self.assertIn("NUR BEIM HOSTER ÄNDERBAR", txt)
        self.assertIn("Betreff X", txt)
        self.assertIn("disable_functions", html)

    def test_password_does_not_leak_into_plan(self):
        b, _ = tr.make_bundle(infected=True)
        self.assertNotIn(tr.PW, str(b["hoster"]))
        self.assertNotIn(tr.PW, str(b["massnahmenplan"]) if "massnahmenplan" in b else "")


class Wiring(unittest.TestCase):
    def test_server_and_screen(self):
        srv = open(os.path.join(ROOT, "claudia", "server.py"), encoding="utf-8").read()
        js = open(os.path.join(ROOT, "claudia", "web", "app.js"), encoding="utf-8").read()
        self.assertIn('"action_plan": actionplan.build_plan(', srv)
        self.assertIn('"hoster"', srv)
        self.assertIn("hosterCard()", js)
        self.assertNotIn("actionPlanCard()", js)
        self.assertNotIn("Maßnahmenplan (Empfehlung)", js)


if __name__ == "__main__":
    unittest.main()
