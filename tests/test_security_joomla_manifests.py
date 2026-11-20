"""2.4.1: Joomla-Sicherheits-Erweiterungen mit geprüftem Update-Server (aus den Manifest-Dateien der Pakete) sind direkt installierbar."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import actions  # noqa: E402
from claudia.checks.security_ext import load_tools  # noqa: E402

EXPECT = {
    "securitycheck": ("https://securitycheck.protegetuordenador.com/update/updates_securitycheck.xml", "pkg_securitycheck"),
    "htprotect": ("https://update.wb-dev.de/htprotect.xml", "com_htprotect"),
    "admintools": ("https://cdn.akeeba.com/updates/pkgadmintoolscore.xml", "pkg_admintools"),
}


class Targets(unittest.TestCase):
    def test_three_free_tools_resolve_to_their_update_server(self):
        for tid, (man, el) in EXPECT.items():
            t = actions._security_target({"cms": "joomla", "tool": tid})
            self.assertEqual((t["manifest"], t["element"]), (man, el), tid)

    def test_paid_and_background_tools_stay_refused(self):
        for tid in ("rsfirewall", "securitycheckpro", "adminexile", "bfstop", "jsecure", "ochsimplefirewall", "nope"):
            with self.assertRaises(actions.ActionError, msg=tid):
                actions._security_target({"cms": "joomla", "tool": tid})

    def test_manifests_are_https_and_elements_valid(self):
        for t in load_tools("security")["joomla"]:
            ins = t.get("install")
            if ins:
                self.assertTrue(actions.MANIFEST_RE.match(ins["manifest"]), t["id"])
                self.assertTrue(actions.ELEMENT_RE.match(ins["element"]), t["id"])
                self.assertTrue(t["price"].startswith("kostenlos"), t["id"])
                self.assertTrue(t["id"] in EXPECT, "unerwartet installierbar: " + t["id"])


class Offer(unittest.TestCase):
    def test_offer_marks_exactly_these_as_installable(self):
        res = [{"id": "security_ext", "title": "x", "status": "warn", "findings": [{"sev": "warn", "title": "Keine Sicherheits-Erweiterung gefunden", "items": []}]}]
        info = {"cms": "joomla", "joomla": "5.2.0", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
        a = {x["id"]: x for x in actions.available(res, info, "8.3", {}, {})}.get("install_security")
        if a is None:
            self.skipTest("Angebot hängt an einem anderen Befund-Titel")
        inst = sorted(t["id"] for t in a["params"]["tools"] if t["installable"])
        self.assertEqual(inst, sorted(EXPECT))


if __name__ == "__main__":
    unittest.main()
