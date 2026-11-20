"""2.4.1 Punkt 6 (Erinnerung): 'letzter Vergleich vor X Tagen' in der Oberfläche. Kein Hintergrunddienst; es wird nur ein Zeitpunkt in der lokalen Basis-Datei vermerkt."""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import baseline  # noqa: E402

KEY = baseline.make_key("example.org", "u", "public_html")
DAY = 86400


class Reminder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_rem_")

    def stamp(self, days_ago):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days_ago * DAY - 60))

    def test_no_base_gives_first_hint(self):
        r = baseline.info(self.d, KEY)["reminder"]
        self.assertEqual(r["level"], "first")
        self.assertIn("noch keine Vergleichsbasis", r["text"])

    def test_levels_by_age_and_wording(self):
        base = {"exists": True}
        cases = [(0, "ok", "heute"), (1, "ok", "vor 1 Tag"), (13, "ok", "vor 13 Tagen"), (14, "due", "vor 14 Tagen"), (40, "due", "vor 40 Tagen")]
        for days, level, word in cases:
            r = baseline.reminder(dict(base, compared=self.stamp(days)))
            self.assertEqual((r["level"], word in r["text"]), (level, True), (days, r))
            self.assertIn("Letzter Vergleich", r["text"])
        r = baseline.reminder(dict(base, saved=self.stamp(20)))
        self.assertEqual(r["level"], "due")
        self.assertIn("seither nicht verglichen", r["text"])

    def test_broken_stamp_does_not_crash_or_nag(self):
        self.assertEqual(baseline.reminder({"exists": True, "compared": "kaputt"})["level"], "ok")

    def test_mark_compared_updates_only_time_and_resets_reminder(self):
        baseline.save(self.d, KEY, "example.org : .", {"a.php": "0" * 64}, {"u/x.jpg": 5})
        p = os.path.join(self.d, KEY + ".json")
        d = json.load(open(p))
        d["saved"] = self.stamp(30)
        json.dump(d, open(p, "w"))
        self.assertEqual(baseline.info(self.d, KEY)["reminder"]["level"], "due")
        self.assertTrue(baseline.mark_compared(self.d, KEY))
        i = baseline.info(self.d, KEY)
        self.assertEqual(i["reminder"]["level"], "ok")
        self.assertEqual(i["files"], 1)
        self.assertEqual(json.load(open(p))["files"], {"a.php": "0" * 64})
        self.assertFalse(baseline.mark_compared(self.d, baseline.make_key("x", "y", "z")))


class EndToEnd(unittest.TestCase):
    def test_real_comparison_run_sets_time_and_no_run_without_base_does_not(self):
        import test_baseline_compare as b9
        w = b9.world()
        r, key = b9.run(w)                                    # keine Basis: nichts wird angelegt
        self.assertIsNone(baseline.load(w["bl"], key))
        b9.run(w, save=True)
        self.assertNotIn("compared", baseline.load(w["bl"], key))
        r, _ = b9.run(w)                                      # Vergleich
        d = baseline.load(w["bl"], key)
        self.assertTrue(d.get("compared"))
        self.assertEqual(baseline.info(w["bl"], key)["reminder"]["level"], "ok")
        self.assertIn("Letzter Vergleich", baseline.info(w["bl"], key)["reminder"]["text"])


class Wiring(unittest.TestCase):
    def test_check_marks_comparison_and_screen_shows_reminder(self):
        root = os.path.dirname(HERE)
        cmp_ = open(os.path.join(root, "claudia", "checks", "compare.py"), encoding="utf-8").read()
        js = open(os.path.join(root, "claudia", "web", "app.js"), encoding="utf-8").read()
        self.assertIn("baseline.mark_compared", cmp_)
        self.assertIn("compareReminder()", js)
        self.assertIn("Zeit für einen Vergleich", js)


if __name__ == "__main__":
    unittest.main()
