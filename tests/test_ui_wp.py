"""Oberfläche im echten Browser mit einer WordPress-Seite: erkannte Seite, WordPress-Prüfungen, WordPress-Lösungen."""
import importlib
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FAKE = os.path.join(HERE, "fake_paramiko")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import wpfixture  # noqa: E402
from claudia.server import make_server  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class UiWordPress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, FAKE)
        sys.modules.pop("paramiko", None)
        paramiko = importlib.import_module("paramiko")
        os.environ["CLAUDIA_OFFLINE"] = "1"
        cls.base = tempfile.mkdtemp(prefix="claudia_uiwp_")
        cls.w = wpfixture.make_wp_world(cls.base, True)
        paramiko.CONFIG.update(home=cls.w["home"], extra_path=cls.w["bin"], password="pw", fail=None)
        os.environ["CLAUDIA_REPORTS"] = os.path.join(cls.base, "b")
        os.environ["CLAUDIA_LOGS"] = os.path.join(cls.base, "l")
        cls.srv = make_server(directory=os.path.join(cls.base, "data"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        cls.page = cls.browser.new_page(viewport={"width": 1280, "height": 900})
        cls.errors = []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("console", lambda m: cls.errors.append(m.text) if m.type == "error" else None)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()
        sys.path.remove(FAKE)
        sys.modules.pop("paramiko", None)

    def test_flow(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.fill("#f-host", "fake.example.org")
        pg.fill("#f-user", "demo")
        pg.fill("#f-pw", "pw")
        pg.fill("#f-dir", self.w["site_rel"])
        pg.click("text=Verbindung testen")
        try:
            pg.wait_for_selector("#trust[open]", timeout=3000)
            pg.click("#trust-yes")
        except Exception:
            pass
        pg.wait_for_selector("text=Verbindung steht")
        card = pg.inner_text("main")
        self.assertIn("WordPress", card)
        self.assertIn("wp-config.php vorhanden", card)
        self.assertNotIn("Keine WordPress-Version erkannt", card)
        pg.click("text=Weiter zur Testauswahl")
        pg.wait_for_selector("text=Welche Prüfungen sollen laufen?")
        # WordPress-Prüfungen statt Joomla-Prüfungen
        self.assertEqual(pg.locator("#t-wp_core").count(), 1)
        self.assertEqual(pg.locator("#t-wp_config").count(), 1)
        self.assertEqual(pg.locator("#t-db_jce").count(), 0)
        self.assertEqual(pg.locator("#t-joomla_info").count(), 0)
        self.assertTrue(pg.locator("#t-wp_config").is_checked())
        self.assertIn("WordPress", pg.inner_text("#grp-datenbank"))
        pg.click("text=Prüfung starten")
        pg.wait_for_selector(".verdict", timeout=300000)
        pg.wait_for_selector("text=Lösungen auf Knopfdruck", timeout=60000)
        body = pg.inner_text("main")
        self.assertIn("Jeder darf sich als Administrator registrieren", body)
        # Lösungen: WordPress-Aktionen erscheinen, Joomla-Aktionen nicht
        acts = pg.inner_text("#actions")
        self.assertIn("Registrierung", acts)
        self.assertNotIn("JCE", acts)
        self.assertNotIn("configuration.php", acts)
        # Passwort-Hinweis nennt wp-config.php
        if pg.locator("#act-manual_passwords").count():
            self.assertIn("wp-config.php", pg.inner_text("#act-manual_passwords"))
        # Lösung direkt am Befund
        offer = pg.locator("text=Registrierung absichern ...")
        self.assertGreaterEqual(offer.count(), 1)
        offer.first.click()
        pg.wait_for_selector("#act-wp_fix_registration .code, #act-wp_fix_registration pre", timeout=20000)
        self.assertIn("users_can_register", pg.inner_text("#act-wp_fix_registration"))
        self.assertEqual([e for e in self.errors if "favicon" not in e], [])
        # Trennen: wieder Joomla-Prüfliste (Standard)
        pg.click("#conn-off")
        pg.wait_for_selector("text=Verbindung testen")
        self.assertEqual(self.srv_cms(), "joomla")

    def srv_cms(self):
        return self.page.evaluate("S.init.cms")


if __name__ == "__main__":
    unittest.main()
