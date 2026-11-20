"""Update-Suche: 'keine Updates' darf nur bei nachweislich funktionierender Suche erscheinen."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from claudia import updcheck  # noqa: E402

XML = """<updates>
 <update><element>com_demo</element><type>component</type><client>site</client><version>2.0.0</version>
  <tags><tag>stable</tag></tags><targetplatform name="joomla" version="[56]\\.[0-9]+"/></update>
 <update><element>com_demo</element><type>component</type><client>site</client><version>3.0.0</version>
  <tags><tag>beta</tag></tags><targetplatform name="joomla" version="[56]\\.[0-9]+"/></update>
 <update><element>com_demo</element><type>component</type><client>site</client><version>9.0.0</version>
  <tags><tag>stable</tag></tags><targetplatform name="joomla" version="3\\.[0-9]+"/></update>
</updates>"""

SITE = {"sid": 1, "eid": 7, "name": "Demo", "element": "com_demo", "type": "component", "folder": "", "client": 0, "version": "1.0.0",
        "location": "https://updates.example.org/demo.xml", "needs_key": False, "age": 10}
OK_CORE = {"has_update": False, "latest": "6.2.0"}


def live(found=(), ran=True, unreachable=()):
    return {"ran": ran, "found": list(found), "unreachable": list(unreachable), "sites": 1, "reason": ""}


class Parse(unittest.TestCase):
    def test_only_stable_and_matching_platform(self):
        got = updcheck.parse_updates(XML, "6.2.0")
        self.assertEqual([u["version"] for u in got], ["2.0.0"])

    def test_doctype_is_refused(self):
        self.assertEqual(updcheck.parse_updates('<!DOCTYPE x [<!ENTITY a "b">]><updates/>', "6.2.0"), [])

    def test_live_finds_newer_version(self):
        with mock.patch.object(updcheck, "_get", return_value=XML), mock.patch.object(updcheck, "PAUSE", 0), mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": ""}):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            r = updcheck.live_extensions([SITE], "6.2.0")
        self.assertTrue(r["ran"])
        self.assertEqual([(u["name"], u["old"], u["new"]) for u in r["found"]], [("Demo", "1.0.0", "2.0.0")])

    def test_live_marks_unreachable_servers(self):
        with mock.patch.object(updcheck, "_get", return_value=None), mock.patch.object(updcheck, "PAUSE", 0), mock.patch.dict(os.environ, {}):
            os.environ.pop("CLAUDIA_OFFLINE", None)   # wird am Ende des Blocks wiederhergestellt, damit spätere Tests offline bleiben
            r = updcheck.live_extensions([SITE], "6.2.0")
        self.assertEqual(r["unreachable"], ["updates.example.org"])

    def test_offline_mode_does_not_ask(self):
        with mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": "1"}), mock.patch.object(updcheck, "_get", side_effect=AssertionError("kein Abruf")):
            self.assertFalse(updcheck.live_extensions([SITE], "6.2.0")["ran"])
            self.assertIsNone(updcheck.live_core("6.2.0"))


class Assess(unittest.TestCase):
    def test_all_good_is_reliable_and_says_none(self):
        a = updcheck.assess(OK_CORE, True, [], (0, 3), live(), None, "6.2.0")
        self.assertTrue(a["reliable"])
        self.assertTrue(a["confirmed"])
        self.assertIn("keine Updates", updcheck.message(a, 0))

    def test_unreadable_update_table_is_never_none(self):
        a = updcheck.assess(OK_CORE, True, None, (0, 3), live(), None, "6.2.0")
        self.assertFalse(a["reliable"])
        self.assertNotIn("keine Updates", updcheck.message(a, 0))

    def test_cli_failure_or_unclear_core_answer_is_unreliable(self):
        self.assertFalse(updcheck.assess(OK_CORE, False, [], None, live(), None, "6.2.0")["reliable"])
        a = updcheck.assess(None, True, [], None, live(), None, "6.2.0")
        self.assertFalse(a["reliable"])
        self.assertIsNone(a["has_update"])
        self.assertNotIn("aktuell", updcheck.message(a, 0))

    def test_update_servers_find_what_joomla_missed(self):
        extra = {"eid": 7, "name": "Demo", "old": "1.0.0", "new": "2.0.0", "source": "updates.example.org", "needs_key": False}
        a = updcheck.assess(OK_CORE, True, [], (0, 3), live([extra]), None, "6.2.0")
        self.assertFalse(a["reliable"])
        self.assertEqual(len(a["live_extra"]), 1)
        self.assertIn("Demo", " ".join(a["reasons"]) + a["live_extra"][0]["name"])

    def test_stale_sources_make_result_unreliable(self):
        a = updcheck.assess(OK_CORE, True, [], (2, 5), live(), None, "6.2.0")
        self.assertFalse(a["reliable"])
        self.assertIn("2 von 5", " ".join(a["reasons"]))

    def test_core_update_found_by_update_server_wins(self):
        a = updcheck.assess(OK_CORE, True, [], (0, 1), live(), "6.2.1", "6.2.0")
        self.assertTrue(a["has_update"])
        self.assertEqual(a["latest"], "6.2.1")
        self.assertFalse(a["reliable"])

    def test_known_update_is_reported_and_reliable(self):
        a = updcheck.assess({"has_update": True, "latest": "6.2.1"}, True, [], (0, 1), live(), "6.2.1", "6.2.0")
        self.assertTrue(a["reliable"])
        self.assertIn("6.2.1", updcheck.message(a, 0))

    def test_without_cross_check_result_is_not_called_confirmed(self):
        a = updcheck.assess(OK_CORE, True, [], (0, 1), live(ran=False), None, "6.2.0")
        self.assertTrue(a["reliable"])
        self.assertFalse(a["confirmed"])
        self.assertIn("Gegenprobe", updcheck.message(a, 0))


if __name__ == "__main__":
    unittest.main()
