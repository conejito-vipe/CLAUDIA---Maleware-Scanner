"""2.4.1 Härtung per .htaccess: Sicherheits-Header, HSTS (rot, nicht vollständig rückgängig), Ordnerlisten, XML-RPC.
Abruf ersetzt (kein Netz); geprüft werden Angebot, Vorschau, Sicherung, Schreiben, Wirkungsprüfung, Rückgängig."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402

ROOT = os.path.dirname(HERE)


class Resp:
    def __init__(self, status=200, body="", error="", headers=None):
        self.status, self.body, self.error, self.headers = status, body, error, headers or {}


def fake_web(site, mode):
    """Spielt einen Apache nach, der die .htaccess im Hauptordner liest. mode: works | ignored | broken | offline."""
    def fetch(url):
        if mode == "offline":
            return Resp(0, "", "Verbindung abgelehnt")
        ht = os.path.join(site, ".htaccess")
        text = open(ht, encoding="utf-8").read() if os.path.exists(ht) else ""
        if mode == "broken" and "CLAUDIA:" in text:
            return Resp(500, "Internal Server Error")
        hdrs = {}
        if mode != "ignored":
            for m in re.finditer(r'Header always set ([\w-]+) "([^"]+)"', text):
                hdrs[m.group(1).lower()] = m.group(2)
        if url.endswith("/xmlrpc.php"):
            if mode != "ignored" and "<Files xmlrpc.php>" in text:
                return Resp(403, "Forbidden", headers=hdrs)
            return Resp(405, "XML-RPC server accepts POST requests only.")
        return Resp(200, "<html></html>", headers=hdrs)
    return fetch


class Base(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]
        self.ht = os.path.join(self.s, ".htaccess")
        if os.path.lexists(self.ht):
            os.remove(self.ht)
        self.ctx = {"url": "https://example.org"}
        self._orig = actions._fetch_url

    def tearDown(self):
        actions._fetch_url = self._orig

    def go(self, aid, mode="works", params=None):
        actions._fetch_url = fake_web(self.s, mode)
        return actions.run_action(self.r, self.w["site_rel"], aid, params or {}, [], context=self.ctx)


class Headers(Base):
    P = {"headers": ["nosniff", "frame", "referrer"]}

    def test_block_is_written_with_backup_and_effect_checked(self):
        open(self.ht, "w").write("RewriteEngine On\n")
        res = self.go("harden_headers", params=self.P)
        self.assertTrue(res["ok"], res)
        txt = open(self.ht).read()
        self.assertTrue(txt.startswith("RewriteEngine On"))
        for want in ('X-Content-Type-Options "nosniff"', 'X-Frame-Options "SAMEORIGIN"', 'Referrer-Policy "strict-origin-when-cross-origin"', "# Ende CLAUDIA: Sicherheits-Header"):
            self.assertIn(want, txt)
        self.assertEqual(open(os.path.join(res["backup_dir"], "htaccess.vorher")).read(), "RewriteEngine On\n")
        self.assertIn("cp -p", open(os.path.join(res["backup_dir"], "rueckgaengig.txt")).read())

    def test_only_missing_headers_and_only_known_names(self):
        res = self.go("harden_headers", params={"headers": ["nosniff", "Evil-Header"]})
        self.assertTrue(res["ok"], res)
        txt = open(self.ht).read()
        self.assertIn("nosniff", txt)
        self.assertNotIn("Evil", txt)
        self.assertNotIn("X-Frame-Options", txt)
        with self.assertRaises(actions.ActionError):
            actions.ht_block_text("harden_headers", {"headers": ["Evil-Header"]})

    def test_new_file_is_removed_again_when_server_ignores_it(self):
        res = self.go("harden_headers", "ignored", self.P)
        self.assertFalse(res["ok"])
        self.assertIn("kommen nicht an", res["error"])
        self.assertFalse(os.path.exists(self.ht))

    def test_existing_file_restored_on_error_500_and_offline(self):
        for mode in ("broken", "offline"):
            open(self.ht, "w").write("Options +FollowSymLinks\n")
            res = self.go("harden_headers", mode, self.P)
            self.assertFalse(res["ok"], mode)
            self.assertEqual(open(self.ht).read(), "Options +FollowSymLinks\n", mode)

    def test_second_run_changes_nothing(self):
        self.assertTrue(self.go("harden_headers", params=self.P)["ok"])
        before = open(self.ht).read()
        res = self.go("harden_headers", params=self.P)
        self.assertTrue(res["ok"])
        self.assertEqual(open(self.ht).read(), before)

    def test_needs_https_address_and_refuses_symlink(self):
        for url in ("http://example.org", ""):
            self.ctx = {"url": url}
            res = self.go("harden_headers", params=self.P)
            self.assertFalse(res["ok"], url)
            self.assertFalse(os.path.lexists(self.ht))
        self.ctx = {"url": "https://example.org"}
        outside = os.path.join(os.path.dirname(self.s), "fremd-ht.txt")
        open(outside, "w").write("x")
        os.symlink(outside, self.ht)
        self.assertFalse(self.go("harden_headers", params=self.P)["ok"])
        self.assertEqual(open(outside).read(), "x")


class Hsts(Base):
    def test_short_max_age_without_subdomains_or_preload(self):
        txt = actions.ht_block_text("harden_hsts")
        self.assertIn("max-age=604800", txt)
        self.assertNotIn("includeSubDomains", txt)
        self.assertNotIn("preload", txt)

    def test_written_and_marked_as_not_fully_reversible(self):
        self.assertTrue(actions.ACTIONS["harden_hsts"]["irreversible"])
        self.assertEqual(actions.ACTIONS["harden_hsts"]["risk"], "hoch")
        res = self.go("harden_hsts")
        self.assertTrue(res["ok"], res)
        self.assertIn("ACHTUNG", res["message"])
        self.assertIn("604800", open(self.ht).read())

    def test_rolled_back_when_header_does_not_arrive(self):
        open(self.ht, "w").write("# alt\n")
        res = self.go("harden_hsts", "ignored")
        self.assertFalse(res["ok"])
        self.assertEqual(open(self.ht).read(), "# alt\n")

    def test_other_actions_are_not_marked_irreversible(self):
        for aid in ("harden_headers", "harden_listing", "wp_block_xmlrpc", "block_php_uploads", "reset_htaccess"):
            self.assertFalse(actions.ACTIONS[aid].get("irreversible"), aid)

    def test_server_and_screen_require_second_confirmation(self):
        srv = open(os.path.join(ROOT, "claudia", "server.py"), encoding="utf-8").read()
        js = open(os.path.join(ROOT, "claudia", "web", "app.js"), encoding="utf-8").read()
        self.assertIn('confirm_irreversible', srv)
        self.assertIn("confirm_irreversible", js)
        self.assertIn("NICHT VOLLSTÄNDIG RÜCKGÄNGIG", js)
        self.assertIn("#c62828", js)


class Listing(Base):
    def test_written_and_start_page_checked(self):
        res = self.go("harden_listing")
        self.assertTrue(res["ok"], res)
        self.assertIn("Options -Indexes", open(self.ht).read())
        self.assertIn("nicht einzeln geprüft", res["message"])

    def test_rolled_back_when_host_forbids_options(self):
        open(self.ht, "w").write("# alt\n")
        res = self.go("harden_listing", "broken")
        self.assertFalse(res["ok"])
        self.assertEqual(open(self.ht).read(), "# alt\n")


class Xmlrpc(Base):
    def test_blocked_and_verified(self):
        res = self.go("wp_block_xmlrpc")
        self.assertTrue(res["ok"], res)
        self.assertIn("<Files xmlrpc.php>", open(self.ht).read())
        self.assertIn("403", res["message"])

    def test_rolled_back_when_still_reachable(self):
        res = self.go("wp_block_xmlrpc", "ignored")
        self.assertFalse(res["ok"])
        self.assertIn("weiter", res["error"])
        self.assertFalse(os.path.exists(self.ht))


def res_of(rid, title, items, sev):
    return {"id": rid, "findings": [{"sev": sev, "title": title, "items": items}]}


HDR_ALL = ["HSTS (Strict-Transport-Security) - Der Browser darf die Seite danach nur noch verschlüsselt aufrufen.",
           "X-Content-Type-Options: nosniff - Der Browser darf Dateitypen nicht erraten.",
           "Schutz vor Einbettung (X-Frame-Options oder CSP frame-ancestors) - Andere Seiten dürfen ...",
           "Referrer-Policy - Steuert ..."]


class Offer(unittest.TestCase):
    def ids(self, results, cms="joomla"):
        info = {"cms": cms, "php": ""}
        return {a["id"]: a for a in actions.available(results, info, "8.3")}

    def test_nothing_offered_without_findings(self):
        got = self.ids([])
        for aid in actions.HARDEN_ACTIONS:
            self.assertNotIn(aid, got)

    def test_headers_and_hsts_offered_from_missing_headers(self):
        got = self.ids([res_of("web_headers", "4 Sicherheits-Header fehlen", HDR_ALL, "info")])
        self.assertEqual(got["harden_headers"]["params"]["headers"], ["nosniff", "frame", "referrer"])
        self.assertIn("harden_hsts", got)
        self.assertTrue(got["harden_hsts"]["irreversible"])
        self.assertFalse(got["harden_headers"].get("irreversible"))
        self.assertNotIn("harden_listing", got)
        self.assertNotIn("wp_block_xmlrpc", got)

    def test_only_what_is_missing_is_offered(self):
        got = self.ids([res_of("web_headers", "1 Sicherheits-Header fehlen", [HDR_ALL[3]], "info")])
        self.assertEqual(got["harden_headers"]["params"]["headers"], ["referrer"])
        self.assertNotIn("harden_hsts", got)

    def test_no_hsts_with_certificate_problem_and_nothing_on_nginx(self):
        bad = [res_of("web_headers", "4 Sicherheits-Header fehlen", HDR_ALL, "info"), res_of("web_headers", "Das Zertifikat läuft in 5 Tagen ab", [], "crit")]
        got = self.ids(bad)
        self.assertIn("harden_headers", got)
        self.assertNotIn("harden_hsts", got)
        ng = self.ids([res_of("web_headers", "4 Sicherheits-Header fehlen", HDR_ALL, "info"), res_of("web_headers", "Server-Typ laut Antwort: nginx", [], "info")])
        for aid in actions.HARDEN_ACTIONS:
            self.assertNotIn(aid, ng)

    def test_wordpress_listing_and_xmlrpc(self):
        res = [res_of("wp_exposure", "1 Datei(en)/Schnittstelle(n) geben Informationen preis", ["Ordnerliste ist öffentlich: https://x.de/wp-content/uploads/"], "warn"),
               res_of("wp_exposure", "1 Hinweis(e) zur Absicherung", ["xmlrpc.php ist aktiv. Wird für Massenversuche ..."], "info")]
        got = self.ids(res, "wordpress")
        self.assertIn("harden_listing", got)
        self.assertIn("wp_block_xmlrpc", got)
        self.assertNotIn("wp_block_xmlrpc", self.ids(res, "joomla"))

    def test_preview_shows_block_and_test(self):
        pv = actions.commands_preview("harden_headers", {"headers": ["nosniff"]}, [])
        self.assertTrue(any("X-Content-Type-Options" in l for l in pv))
        self.assertTrue(any(l.startswith("Test:") for l in pv))
        self.assertTrue(any("htaccess.vorher" in l for l in pv))

    def test_every_hardening_action_has_backup_order_and_text(self):
        for aid in actions.HARDEN_ACTIONS:
            self.assertIn(aid, actions.STEP_ORDER)
            self.assertIn(aid, actions.SICHERUNG)
            self.assertIn(aid, actions.STEP_WHY)
            self.assertIn(aid, actions.FILE_ACTIONS)
            self.assertTrue(actions.ACTIONS[aid]["undo"])


if __name__ == "__main__":
    unittest.main()
