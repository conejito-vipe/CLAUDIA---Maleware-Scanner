"""Tests für das Icon-Set (Oberfläche und HTML-Bericht)."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from claudia import icons  # noqa: E402
from claudia import report  # noqa: E402


class IconSet(unittest.TestCase):
    def test_pflichtsymbole(self):
        a = icons.all_icons()
        for n in ("ok", "info", "warn", "crit", "error", "skipped", "lock", "search", "download", "book"):
            self.assertIn(n, a, n)
        for n, inner in a.items():
            self.assertNotRegex(inner, r"<script|on\w+=|javascript:", n)
            self.assertNotRegex(inner, r"#[0-9a-fA-F]{3,6}\b", "%s: feste Farbe statt currentColor" % n)

    def test_svg_hilfsfunktion(self):
        self.assertTrue(icons.svg("crit").startswith("<svg class='ic'"))
        self.assertEqual(icons.svg("gibt-es-nicht"), "")

    def test_keine_bunten_emojis_in_oberflaeche_und_bericht(self):
        emoji = re.compile("[\U0001F300-\U0001FAFF✅❌⚠⭐❗]")
        allowed = "🆓💶💲⭐"                                   # vom Nutzer ausdrücklich gewünscht: Preis- und Sternmarkierung bei installierbaren Werkzeugen
        for f in (os.path.join(ROOT, "claudia", "web", "app.js"), os.path.join(ROOT, "claudia", "report.py")):
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
            if f.endswith("app.js"):
                text = re.sub("[%s]" % allowed, "", text)
            self.assertIsNone(emoji.search(text), f)

    def test_bericht_enthaelt_icons(self):
        import test_report
        b = test_report.make_bundle()[0]
        html = report.render_html(b)
        self.assertIn("<svg class='ic'", html)


if __name__ == "__main__":
    unittest.main()
