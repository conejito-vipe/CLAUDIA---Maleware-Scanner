"""Lebensende der CMS-Reihen (A15): feste Joomla-Termine, WordPress nach Abstand zur neuesten Reihe."""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia.checks.system import cms_branch_finding  # noqa: E402

ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))


def t(d):
    return time.mktime(time.strptime(d, "%Y-%m-%d"))


class Joomla(unittest.TestCase):
    def test_data_complete_and_dated(self):
        e = ADV["cms_eol"]
        self.assertRegex(e["stand"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertIn("quelle", e)
        self.assertEqual([b["branch"] for b in e["joomla"]], ["3", "4", "5", "6"])
        for b in e["joomla"]:
            self.assertLess(b["active_end"], b["eol"])

    def test_eol_branches_critical(self):
        for v in ("3.10.12", "4.4.14"):
            f = cms_branch_finding("joomla", v, ADV, t("2026-11-07"))
            self.assertEqual(f[0], "crit", v)
            self.assertIn("nicht mehr gepflegt", f[1])

    def test_five_security_only_now_and_warn_near_end(self):
        f = cms_branch_finding("joomla", "5.4.10", ADV, t("2026-11-07"))
        self.assertEqual(f[0], "info")
        self.assertIn("nur noch Sicherheitsfixes", f[1])
        f = cms_branch_finding("joomla", "5.4.10", ADV, t("2027-06-01"))
        self.assertEqual(f[0], "warn")
        f = cms_branch_finding("joomla", "5.4.10", ADV, t("2027-10-13"))
        self.assertEqual(f[0], "crit")

    def test_current_branch_silent(self):
        self.assertIsNone(cms_branch_finding("joomla", "6.2.0", ADV, t("2026-11-07")))
        self.assertIsNone(cms_branch_finding("joomla", "9.0.0", ADV, t("2026-11-07")))      # unbekannte Reihe: nichts behaupten


class WordPress(unittest.TestCase):
    def test_distance(self):
        latest = ADV["wordpress"]["latest_known"]
        self.assertIsNone(cms_branch_finding("wordpress", latest, ADV))
        major, minor = latest.split(".")[:2]
        self.assertEqual(cms_branch_finding("wordpress", "6.9.1", {"wordpress": {"latest_known": "7.0.1"}, "cms_eol": {}})[0], "info")
        self.assertEqual(cms_branch_finding("wordpress", "6.8.2", {"wordpress": {"latest_known": "7.0.1"}, "cms_eol": {}})[0], "warn")
        self.assertEqual(cms_branch_finding("wordpress", "5.0", {"wordpress": {"latest_known": "7.0.1"}, "cms_eol": {}})[0], "warn")

    def test_garbage_is_silent(self):
        self.assertIsNone(cms_branch_finding("wordpress", "", ADV))
        self.assertIsNone(cms_branch_finding("wordpress", "abc", ADV))


if __name__ == "__main__":
    unittest.main()
