"""2.4.0 / E: Joomla-Erweiterungen nur mit öffentlicher Hersteller-Adresse, kostenlos und mit Stand-Datum installierbar; sonst Store-Link plus Anleitung."""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import actions  # noqa: E402

TOOL = {"id": "x", "name": "X", "price": "kostenlos", "text": "t", "jed": "https://extensions.joomla.org/x/",
        "install": {"manifest": "https://example.org/x.xml", "element": "pkg_x"}}


def data(stand, **over):
    t = dict(TOOL, **over)
    return {"stand": stand, "joomla": [t, {"id": "y", "name": "Y", "price": "kostenlos", "text": "t", "jed": "https://extensions.joomla.org/y/"}], "wordpress": []}


class E(unittest.TestCase):
    def choices(self, d):
        with mock.patch("claudia.checks.security_ext.load_tools", return_value=d):
            return {c["id"]: c for c in actions.security_choices("joomla")}

    def test_installable_needs_manifest_free_and_stand(self):
        c = self.choices(data("2026-11-02"))
        self.assertTrue(c["x"]["installable"])
        self.assertEqual(c["x"]["stand"], "2026-11-02")
        self.assertEqual(c["x"]["howto"], "")
        self.assertFalse(c["y"]["installable"])                      # keine Hersteller-Adresse
        self.assertIn("Von URL installieren", c["y"]["howto"])
        self.assertEqual(c["y"]["stand"], "")

    def test_without_stand_date_nothing_is_installable(self):
        for bad in ("", "gestern", "2026-11"):
            c = self.choices(data(bad))
            self.assertFalse(c["x"]["installable"], bad)
            with mock.patch("claudia.checks.security_ext.load_tools", return_value=data(bad)):
                with self.assertRaises(actions.ActionError):
                    actions._security_target({"cms": "joomla", "tool": "x"})

    def test_paid_or_insecure_address_is_not_installable(self):
        self.assertFalse(self.choices(data("2026-11-02", price="kostenpflichtig"))["x"]["installable"])
        self.assertFalse(self.choices(data("2026-11-02", install={"manifest": "http://example.org/x.xml", "element": "pkg_x"}))["x"]["installable"])

    def test_wordpress_has_no_joomla_howto(self):
        with mock.patch("claudia.checks.security_ext.load_tools", return_value={"stand": "2026-11-02", "joomla": [], "wordpress": [{"id": "w", "name": "W", "slug": "w-p", "text": "t"}]}):
            c = actions.security_choices("wordpress", "")[0]
        self.assertEqual(c["howto"], "")

    def test_shipped_lists_only_installable_with_stand(self):
        for kind in ("security", "backup"):
            for c in actions.security_choices("joomla", "", kind):
                if c["installable"]:
                    self.assertTrue(c["stand"], c["id"])


if __name__ == "__main__":
    unittest.main()
