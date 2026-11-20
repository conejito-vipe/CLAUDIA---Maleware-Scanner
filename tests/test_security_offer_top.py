"""Sicherheits-Erweiterung wird nur oben (eigene Karte) angeboten, nicht noch einmal unter den Lösungen."""
import os, re, unittest

JS = open(os.path.join(os.path.dirname(__file__), "..", "claudia", "web", "app.js"), encoding="utf-8").read()


class SecurityOfferTop(unittest.TestCase):
    def test_card_is_rendered_after_updates(self):
        a, b = JS.index("root.append(updatesCard())"), JS.index("root.append(securityCard())")
        self.assertLess(a, b)

    def test_bottom_list_skips_install_security(self):
        self.assertIn('const SEC_IDS = ["install_security"]', JS)
        self.assertRegex(JS, r"visible = list\.filter\(a => !a\.hidden && !isTop\(a\.id\)\)")
        self.assertIn("&& !isTop(p.id)) card.append(actionBlock", JS)

    def test_updates_card_does_not_take_security(self):
        self.assertIn('const TOP_IDS = ["core_update", "update_extensions", "wp_update"];', JS)


if __name__ == "__main__":
    unittest.main()
