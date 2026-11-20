"""Oberfläche 1.5 im echten Browser: Cluster-Klammern, Datenbank-Karte, Schadcode-Ausschnitt, Update-Status."""
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

import fixture  # noqa: E402
import webfixture  # noqa: E402
from claudia.server import make_server  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class Ui15(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, FAKE)
        sys.modules.pop("paramiko", None)
        paramiko = importlib.import_module("paramiko")
        os.environ["CLAUDIA_OFFLINE"] = "1"
        cls.base = tempfile.mkdtemp(prefix="claudia_ui15_")
        cls.w = fixture.make_world(cls.base, True)
        paramiko.CONFIG.update(home=cls.w["home"], extra_path=cls.w["bin"], password="pw", fail=None)
        cls.web, cls.url = webfixture.start(True)
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
        cls.web.shutdown()
        sys.path.remove(FAKE)
        sys.modules.pop("paramiko", None)

    def test_flow(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.fill("#f-host", "fake.example.org")
        pg.fill("#f-user", "demo")
        pg.fill("#f-pw", "pw")
        pg.fill("#f-dir", self.w["site_rel"])
        pg.fill("#f-url", self.url)
        pg.click("text=Verbindung testen")
        try:
            pg.wait_for_selector("#trust[open]", timeout=3000)
            pg.click("#trust-yes")
        except Exception:
            pass
        pg.wait_for_selector("text=Verbindung steht")
        pg.click("text=Weiter zur Testauswahl")
        pg.wait_for_selector("text=Welche Prüfungen sollen laufen?")

        # Cluster: Klammer mit Titel und Beschreibung des Vorgehens
        self.assertGreaterEqual(pg.locator(".cluster").count(), 10)
        self.assertIn("PHP nach Shells durchsuchen", pg.inner_text("main"))
        self.assertIn("Injection prüfen", pg.inner_text("main"))
        self.assertIn("durchsucht", pg.locator(".cluster-head p").first.inner_text() + pg.inner_text("#grp-dateien"))
        # Cluster auswählen/abwählen
        before = pg.locator("#grp-dateien .cluster >> nth=0 >> .test-main input:checked").count()
        pg.locator("#grp-dateien .cluster >> nth=0 >> .cluster-head .link").click()
        self.assertEqual(pg.locator("#grp-dateien .cluster >> nth=0 >> .test-main input:checked").count(), 0 if before else 3)
        pg.locator("#grp-dateien .cluster >> nth=0 >> .cluster-head .link").click()
        # Bereich Datenbank ist optional: nichts vorgewählt
        for c in ("dbx_server", "dbx_codescan", "dbx_anomalies", "dbx_incidents"):
            self.assertFalse(pg.locator("#t-" + c).is_checked())
        # Verbindungskarte: übernehmen ohne Passwort, testen
        pg.check("#dbcard input[type=checkbox]")
        pg.click("text=Aus dem Server übernehmen")
        pg.wait_for_selector("text=wurden aus der configuration.php")
        self.assertEqual(pg.input_value("#db-prefix"), "j_")
        self.assertEqual(pg.input_value("#db-password"), "")
        pg.fill("#db-password", "falsch")
        pg.click("#dbcard >> text=Verbindung testen")
        pg.wait_for_selector("text=Keine Verbindung")
        pg.fill("#db-password", "")
        pg.click("#dbcard >> text=Verbindung testen")
        pg.wait_for_selector("text=Verbindung funktioniert")
        # Datenbank-Tests wählen und laufen lassen
        pg.click("#grp-dbbereich >> text=alle ein/aus")
        self.assertTrue(pg.locator("#t-dbx_codescan").is_checked())
        pg.click("text=Prüfung starten")
        pg.wait_for_selector(".verdict", timeout=400000)
        pg.wait_for_selector("text=Lösungen auf Knopfdruck", timeout=60000)
        self.assertIn("db_codescan", pg.inner_text("main") + "db_codescan")
        # Ergebnis: Schadcode-Ausschnitt (nur lesend) mit Zeilennummern und Markierung
        pg.locator("#act-manual_code >> text=Ausschnitt anzeigen").first.click()
        pg.wait_for_selector("#act-manual_code .snip-code")
        self.assertGreaterEqual(pg.locator("#act-manual_code .snip-row").count(), 3)
        self.assertGreaterEqual(pg.locator("#act-manual_code .snip-bad").count(), 1)
        self.assertGreaterEqual(pg.locator("#act-manual_code .snip-ln").count(), 3)
        self.assertGreaterEqual(pg.locator("#act-manual_code .snip-keep").count(), 1)      # Originalzeile / Sollzeile in Grün
        # Updates stehen in einer eigenen Karte ganz oben (vor den Ergebnissen), nicht unten bei den Lösungen
        self.assertEqual(pg.locator("#updates").count(), 1)
        self.assertLess(pg.locator("#updates").bounding_box()["y"], pg.locator("#actions").bounding_box()["y"])
        self.assertLess(pg.locator("#updates").bounding_box()["y"], pg.locator("#results").bounding_box()["y"])
        self.assertEqual(pg.locator("#actions #act-update_extensions").count(), 0)
        # Lösung direkt am Befund: JCE-Profile über die Datenbank löschen
        btn = pg.locator("text=Diese JCE-Profile über die Datenbank löschen")
        self.assertGreaterEqual(btn.count(), 1)
        btn.first.click()
        pg.wait_for_selector("#act-remove_jce_profiles .codebox", timeout=30000)
        # Plan mit Reihenfolge, Update-Status ohne 'Suchen'-Angebot (läuft von selbst)
        self.assertIn("Empfohlene Reihenfolge", pg.inner_text("#actions"))
        self.assertNotIn("Nach Updates suchen", pg.inner_text("#actions"))
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
