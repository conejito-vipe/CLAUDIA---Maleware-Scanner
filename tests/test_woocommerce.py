"""Neue Prüfungen 2.7.0: WooCommerce (Überblick, API-Schlüssel, Webhooks, Zahlungsarten, Shop-Manager, abrufbare Daten). Nur lesend, keine Geheimnisse im Ergebnis."""
import os
import sqlite3
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_konto as k  # noqa: E402
from claudia.checks import auswertung_woo as aw  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.registry import CLUSTERS, ordered  # noqa: E402

WOO_IDS = ["woo_overview", "woo_api_keys", "woo_webhooks", "woo_gateways", "woo_managers", "woo_exposed"]
NOW = 1_800_000_000.0
DAY = 86400


def ts(days):
    return NOW - days * DAY


def sevs(rows):
    return [r[0] for r in rows]


class Registered(unittest.TestCase):
    def test_only_wordpress_gets_them(self):
        wp = {c.id for c in ordered("wordpress")}
        jo = {c.id for c in ordered("joomla")}
        for i in WOO_IDS:
            self.assertIn(i, wp)
            self.assertNotIn(i, jo)

    def test_cluster_and_group_fit(self):
        self.assertIn("shop_woo", CLUSTERS)
        for c in ordered("wordpress"):
            if c.id in WOO_IDS:
                self.assertEqual(c.cluster_for("wordpress"), "shop_woo")
                self.assertEqual(c.group, "erweiterungen")

    def test_texts_have_no_joomla(self):
        for c in ordered("wordpress"):
            if c.id in WOO_IDS:
                pub = c.public("wordpress")
                self.assertNotIn("Joomla", " ".join(str(pub.get(x, "")) for x in ("title", "what", "why", "reads")))


class Overview(unittest.TestCase):
    def test_not_installed_is_silent(self):
        self.assertEqual(aw.judge_overview({"installed": False}), [])

    def test_inactive(self):
        self.assertEqual(sevs(aw.judge_overview({"installed": True, "active": False, "version": "9.0.0"})), ["info"])

    def test_db_update_pending(self):
        r = aw.judge_overview({"installed": True, "active": True, "version": "9.4.1", "db_version": "9.2.0"})
        self.assertEqual(sevs(r), ["ok", "warn"])

    def test_db_current(self):
        r = aw.judge_overview({"installed": True, "active": True, "version": "9.4.1", "db_version": "9.4.1"})
        self.assertEqual(sevs(r), ["ok"])

    def test_garbage(self):
        self.assertEqual(aw.judge_overview("x")[0][1], "WooCommerce-Überblick nicht prüfbar")


class ApiKeys(unittest.TestCase):
    def test_none(self):
        self.assertEqual(sevs(aw.judge_api_keys([], NOW)), ["ok"])

    def test_missing_table(self):
        self.assertIn("nicht prüfbar", aw.judge_api_keys(None)[0][1])

    def test_mix(self):
        rows = [{"description": "Buchhaltung", "permissions": "read", "last_access_ts": ts(3), "owner": "chef"},
                {"description": "Fremd", "permissions": "read_write", "last_access_ts": ts(2), "owner": None},
                {"description": "Nie", "permissions": "read", "last_access_ts": None, "owner": "chef"},
                {"description": "Alt", "permissions": "read", "last_access_ts": ts(400), "owner": "chef"}]
        r = aw.judge_api_keys(rows, NOW)
        titles = " | ".join(x[1] for x in r)
        self.assertIn("gehören zu einem Konto, das es nicht mehr gibt", titles)
        self.assertIn("nie benutzt", titles)
        self.assertIn("180 Tagen", titles)
        self.assertIn("Schreibrecht", titles)

    def test_clean_keys_ok(self):
        r = aw.judge_api_keys([{"description": "A", "permissions": "read", "last_access_ts": ts(1), "owner": "chef"}], NOW)
        self.assertEqual(sevs(r), ["ok"])

    def test_no_secret_fields_used(self):
        r = aw.judge_api_keys([{"description": "A", "permissions": "read", "last_access_ts": ts(1), "owner": "chef", "consumer_secret": "cs_GEHEIM123"}], NOW)
        self.assertNotIn("GEHEIM", str(r))


class Webhooks(unittest.TestCase):
    def hook(self, url, topic="order.created", status="active", name="Test"):
        return {"name": name, "status": status, "topic": topic, "url": url, "failure_count": 0}

    def test_none(self):
        self.assertEqual(sevs(aw.judge_webhooks([])), ["ok"])

    def test_catcher_is_critical(self):
        r = aw.judge_webhooks([self.hook("https://webhook.site/abc-123")], "shop.example")
        self.assertEqual(r[0][0], "crit")

    def test_ip_is_critical(self):
        self.assertEqual(aw.judge_webhooks([self.hook("https://203.0.113.9/in")], "shop.example")[0][0], "crit")

    def test_unknown_host_with_orders_warns(self):
        r = aw.judge_webhooks([self.hook("https://sammler.example/hook")], "shop.example")
        self.assertEqual(r[0][0], "warn")

    def test_allowed_and_own_pass(self):
        rows = [self.hook("https://shop.example/wc-api/x"), self.hook("https://erp.firma.example/x"), self.hook("https://hooks.zapier.com/x")]
        r = aw.judge_webhooks(rows, "shop.example", ["firma.example", "hooks.zapier.com"])
        self.assertEqual(sevs(r), ["ok"])

    def test_automation_services_give_only_a_hint(self):
        for u, n in (("https://hooks.zapier.com/hooks/catch/1/a/", "Zapier"), ("https://hooks.slack.com/services/T/B/X", "Slack"),
                     ("https://hook.make.com/abc", "Make"), ("https://hook.eu1.make.com/abc", "Make")):
            r = aw.judge_webhooks([self.hook(u)], "shop.example")
            self.assertEqual(sevs(r), ["info"], u)
            self.assertIn(n, r[0][3][0])

    def test_lookalike_hosts_are_not_services(self):
        for u in ("https://hooks.zapier.com.evil.example/x", "https://evilmake.com/x", "https://hook.eu1.make.com.evil.example/x", "https://zapier.com/hooks/x"):
            self.assertEqual(aw.judge_webhooks([self.hook(u)], "shop.example")[0][0], "warn", u)

    def test_non_sensitive_topic_is_not_flagged(self):
        self.assertEqual(sevs(aw.judge_webhooks([self.hook("https://sammler.example/h", topic="product.updated")], "shop.example")), ["ok"])

    def test_plain_http_known_host(self):
        r = aw.judge_webhooks([self.hook("http://hooks.zapier.com/x")], "shop.example")
        self.assertEqual(r[0][0], "warn")
        self.assertIn("unverschlüsselt", r[0][1])

    def test_paused_is_info_only(self):
        self.assertEqual(sevs(aw.judge_webhooks([self.hook("https://webhook.site/x", status="paused")], "s.example")), ["info", "ok"])

    def test_broken_url(self):
        self.assertEqual(aw.judge_webhooks([self.hook("")], "s.example")[0][0], "warn")


class Gateways(unittest.TestCase):
    def raw(self, **kw):
        return "a:%d:{%s}" % (len(kw), "".join('s:%d:"%s";s:%d:"%s";' % (len(a), a, len(b), b) for a, b in kw.items()))

    def test_ok(self):
        r = aw.judge_gateways([{"id": "bacs", "enabled": "yes", "raw": self.raw(enabled="yes", title="Vorkasse")}])
        self.assertEqual(sevs(r), ["ok"])

    def test_script_in_description_is_critical(self):
        raw = self.raw(enabled="yes", title="Karte", description="<script src=https://x.example/s.js></script>")
        r = aw.judge_gateways([{"id": "stripe", "enabled": "yes", "raw": raw}])
        self.assertEqual(r[0][0], "crit")
        self.assertIn("stripe", r[0][3])

    def test_script_in_disabled_gateway_still_critical(self):
        raw = self.raw(enabled="no", description="javascript:alert(1)")
        self.assertEqual(aw.judge_gateways([{"id": "cheque", "enabled": "no", "raw": raw}])[0][0], "crit")

    def test_testmode(self):
        r = aw.judge_gateways([{"id": "stripe", "enabled": "yes", "raw": self.raw(enabled="yes", testmode="yes", secret_key="sk_live_GEHEIM")}])
        self.assertEqual(r[0][0], "warn")
        self.assertNotIn("GEHEIM", str(r))

    def test_unknown_gateway_is_info(self):
        r = aw.judge_gateways([{"id": "meinezahlung", "enabled": "yes", "raw": self.raw(enabled="yes")}])
        self.assertIn("info", sevs(r))

    def test_nothing_enabled(self):
        self.assertEqual(sevs(aw.judge_gateways([{"id": "cod", "enabled": "no", "raw": self.raw(enabled="no")}])), ["info"])

    def test_empty_list(self):
        self.assertEqual(sevs(aw.judge_gateways([])), ["info"])

    def test_php_value(self):
        self.assertEqual(aw.php_value('a:1:{s:7:"enabled";s:3:"yes";}', "enabled"), "yes")
        self.assertIsNone(aw.php_value('a:1:{s:7:"enabled";s:3:"yes";}', "title"))
        self.assertIsNone(aw.php_value(None, "x"))


class ShopManagers(unittest.TestCase):
    def test_none(self):
        self.assertEqual(sevs(aw.judge_shop_managers([{"login": "a", "role": "administrator"}], NOW)), ["ok"])

    def test_fresh_account_warns(self):
        r = aw.judge_shop_managers([{"login": "alt", "registered_ts": ts(500), "role": "shop_manager"}, {"login": "neu", "registered_ts": ts(2), "role": "shop_manager"}], NOW)
        self.assertEqual(sevs(r), ["info", "warn"])
        self.assertEqual(r[1][3], ["neu"])

    def test_garbage(self):
        self.assertIn("nicht prüfbar", aw.judge_shop_managers("x")[0][1])


class Exposed(unittest.TestCase):
    def test_api_data_is_critical(self):
        r = aw.judge_exposed([{"kind": "api", "label": "Bestellungen", "url": "https://s.example/wp-json/wc/v3/orders", "status": 200, "body": '[{"id": 1}]'}])
        self.assertEqual(r[0][0], "crit")

    def test_api_protected(self):
        r = aw.judge_exposed([{"kind": "api", "label": "B", "url": "u", "status": 401, "body": '{"code":"woocommerce_rest_cannot_view"}'}])
        self.assertEqual(sevs(r), ["ok"])

    def test_log_file_critical_but_html_soft404_not(self):
        r = aw.judge_exposed([{"kind": "file", "label": "Protokoll a.log", "url": "u", "status": 200, "body": "2026-11-01 Kunde Mustermann"}])
        self.assertEqual(r[0][0], "crit")
        r = aw.judge_exposed([{"kind": "file", "label": "Protokoll a.log", "url": "u", "status": 200, "body": "<html>Seite nicht gefunden</html>"}])
        self.assertEqual(sevs(r), ["ok"])

    def test_directory_listing_warns(self):
        r = aw.judge_exposed([{"kind": "dir", "label": "wc-logs", "url": "u", "status": 200, "body": "<title>Index of /wc-logs</title>"}])
        self.assertEqual(r[0][0], "warn")

    def test_many_logs_hint(self):
        r = aw.judge_exposed([], 500)
        self.assertIn("500", r[-1][1])


class Integration(unittest.TestCase):
    """Gegen die WordPress-Testwelt mit zusätzlichen WooCommerce-Tabellen."""

    @classmethod
    def setUpClass(cls):
        cls.w = k.world(False, wp=True)
        site = os.path.join(cls.w["home"], cls.w["site_rel"])
        os.makedirs(os.path.join(site, "wp-content/plugins/woocommerce"), exist_ok=True)
        with open(os.path.join(site, "wp-content/plugins/woocommerce/woocommerce.php"), "w") as fh:
            fh.write("<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 9.4.1\n */\n")
        logs = os.path.join(site, "wp-content/uploads/wc-logs")
        os.makedirs(logs, exist_ok=True)
        with open(os.path.join(logs, "fatal-errors-2026-11-01-abc.log"), "w") as fh:
            fh.write("Kunde Mustermann\n")
        con = sqlite3.connect(cls.w["db"])
        con.executescript("""
CREATE TABLE wp_woocommerce_api_keys (key_id INTEGER PRIMARY KEY, user_id INTEGER, description TEXT, permissions TEXT, consumer_key TEXT, consumer_secret TEXT, last_access TEXT);
CREATE TABLE wp_wc_webhooks (webhook_id INTEGER PRIMARY KEY, status TEXT, name TEXT, topic TEXT, delivery_url TEXT, failure_count INTEGER, secret TEXT);
""")
        con.execute("INSERT INTO wp_woocommerce_api_keys VALUES (1, 1, 'Buchhaltung', 'read', 'ck_GEHEIMKEY', 'cs_GEHEIMSECRET', '2026-11-10 10:00:00')")
        con.execute("INSERT INTO wp_woocommerce_api_keys VALUES (2, 99, 'Fremd', 'read_write', 'ck_X', 'cs_Y', NULL)")
        con.execute("INSERT INTO wp_wc_webhooks VALUES (1, 'active', 'Kopie', 'order.created', 'https://webhook.site/abc', 0, 'GEHEIMWORT')")
        con.execute("UPDATE wp_options SET option_value = REPLACE(option_value, 'a:2:{', 'a:3:{') WHERE option_name = 'active_plugins'")
        ap = con.execute("SELECT option_value FROM wp_options WHERE option_name = 'active_plugins'").fetchone()[0]
        con.execute("UPDATE wp_options SET option_value = ? WHERE option_name = 'active_plugins'", (ap[:-1] + 'i:9;s:27:"woocommerce/woocommerce.php";}',))
        con.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('woocommerce_db_version', '9.2.0')")
        con.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('woocommerce_stripe_settings', ?)",
                    ('a:3:{s:7:"enabled";s:3:"yes";s:11:"description";s:41:"<script src=https://x.example/s.js></script>";s:8:"testmode";s:3:"yes";}',))
        con.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('woocommerce_new_order_settings', ?)",
                    ('a:2:{s:7:"enabled";s:3:"yes";s:7:"subject";s:20:"<script>x</script>";}',))
        con.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (2, 'wp_capabilities', 'a:1:{s:12:\"shop_manager\";b:1;}')")
        con.commit()
        con.close()
        cls.r = {i: k.run(cls.w, i, cms="wordpress") for i in WOO_IDS if i != "woo_exposed"}

    def test_overview(self):
        self.assertEqual(k.tt(self.r["woo_overview"]), [("ok", "WooCommerce ist aktiv"), ("warn", "Das Datenbank-Update von WooCommerce steht aus")])

    def test_api_keys(self):
        t = k.tt(self.r["woo_api_keys"])
        self.assertIn(("warn", "1 API-Schlüssel gehören zu einem Konto, das es nicht mehr gibt"), t)
        self.assertIn(("warn", "1 API-Schlüssel wurden nie benutzt"), t)

    def test_webhooks(self):
        self.assertEqual(self.r["woo_webhooks"].findings[0].sev, "crit")

    def test_gateways_only_payment_settings(self):
        r = self.r["woo_gateways"]
        self.assertEqual(r.findings[0].sev, "crit")
        self.assertIn("stripe", k.blob(r))
        self.assertNotIn("new_order", k.blob(r))

    def test_managers(self):
        self.assertIn(("info", "1 Konto/Konten mit der Rolle Shop-Manager"), k.tt(self.r["woo_managers"]))

    def test_no_secrets_anywhere(self):
        for r in self.r.values():
            b = k.blob(r)
            for s in ("GEHEIMKEY", "GEHEIMSECRET", "GEHEIMWORT"):
                self.assertNotIn(s, b)

    def test_not_installed_is_skipped(self):
        w = k.world(False, wp=True)
        for i in WOO_IDS:
            self.assertEqual(k.run(w, i, cms="wordpress").status, "skipped", i)

    def test_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith(".log") else 401
            f.body = "Kunde Mustermann" if url.endswith(".log") else "{}"
            return f
        s = k.Settings(site_dir=self.w["site_rel"], log_dir="logs", cms="wordpress", url="https://www.testseite.example", allow_hosts=k.ADV["allow_hosts"])
        eng = k.Engine(k.LocalRunner(self.w["home"], extra_path=self.w["bin"]), s, k.ADV)
        with mock.patch.object(webmod, "fetch", fake):
            res = eng.run(["woo_exposed"], lambda e: None, k.threading.Event())[0]
        self.assertEqual(res.findings[0].sev, "crit")
        self.assertIn("fatal-errors", k.blob(res))

    def test_exposed_needs_url(self):
        self.assertEqual(k.run(self.w, "woo_exposed", cms="wordpress").status, "skipped")


if __name__ == "__main__":
    unittest.main()
