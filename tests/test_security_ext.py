"""Prüfung 'Schutz durch eine Sicherheits-Erweiterung': Erkennung, eingeschaltet?, Empfehlung mit Bewertungen."""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from claudia.checks import security_ext  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()


def run(w, cms, with_db=True):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url="", allow_hosts=ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"] if with_db else None), s, ADV)
    return eng.run(["security_ext"], lambda e: None, threading.Event())[0]


def mk_dirs(w, *rel):
    for r in rel:
        os.makedirs(os.path.join(w["site"], r), exist_ok=True)


class Data(unittest.TestCase):
    def test_data_file_has_the_requested_tools(self):
        d = security_ext.load_tools()
        names = " | ".join(t["name"] for t in d["joomla"])
        for want in ("RSFirewall!", "Securitycheck Pro", "Securitycheck", "HTProtect"):
            self.assertIn(want, names)
        for t in d["joomla"]:
            if not t.get("background"):
                self.assertTrue(t["jed"].startswith("https://extensions.joomla.org/"), t["name"])
                self.assertGreater(t["reviews"], 0, t["name"])
        self.assertRegex(d["stand"], r"^\d{4}-\d{2}-\d{2}$")

    def test_paths_unique_between_tools(self):
        seen = {}
        for cms in ("joomla", "wordpress"):
            for t in security_ext.load_tools()[cms]:
                for p in t["paths"]:
                    self.assertNotIn((cms, p), seen, p)
                    seen[(cms, p)] = t["id"]


class JoomlaCase(unittest.TestCase):
    def world(self):
        return fixture.make_world(tempfile.mkdtemp(prefix="claudia_se_"), False)

    def set_enabled(self, w, element, enabled, type_="plugin"):
        c = sqlite3.connect(w["db"])
        c.execute("INSERT INTO j_extensions (name, type, element, folder, client_id, enabled, manifest_cache, params) VALUES (?,?,?,?,?,?,?,?)",
                  (element, type_, element, "system" if type_ == "plugin" else "", 0, enabled, "{}", "{}"))
        c.commit()
        c.close()

    def test_none_installed_recommends_with_ratings(self):
        r = run(self.world(), "joomla")
        sev = [f.sev for f in r.findings]
        self.assertEqual(sev[0], "info")          # Hinweis, kein Alarm: fehlender Schutz ist kein Zeichen für einen Einbruch
        self.assertIn("Keine Sicherheits-Erweiterung", r.findings[0].title)
        why = " ".join(r.findings[0].items)
        self.assertIn("Firewall", why)
        rec = [f for f in r.findings if f.title.startswith("Empfehlungen")][0]
        txt = "\n".join(rec.items)
        for want in ("RSFirewall!", "Securitycheck Pro", "HTProtect", "110 Bewertungen", "84 Bewertungen", "15 Bewertungen", "extensions.joomla.org"):
            self.assertIn(want, txt)
        self.assertIn("Stand", rec.title)

    def test_installed_and_enabled_is_ok(self):
        w = self.world()
        mk_dirs(w, "administrator/components/com_rsfirewall", "plugins/system/rsfirewall")
        self.set_enabled(w, "rsfirewall", 1)
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "ok", [f.title for f in r.findings])
        self.assertIn("RSFirewall!", r.findings[0].title)
        self.assertIn("eingeschaltet", r.findings[0].title)

    def test_installed_but_disabled_warns(self):
        w = self.world()
        mk_dirs(w, "plugins/system/securitycheckpro")
        self.set_enabled(w, "securitycheckpro", 0)
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "warn")
        self.assertIn("ausgeschaltet", r.findings[0].title)

    def test_without_database_says_state_unknown(self):
        w = self.world()
        mk_dirs(w, "administrator/components/com_admintools")
        r = run(w, "joomla", with_db=False)
        self.assertEqual(r.findings[0].sev, "ok")
        self.assertIn("ließ sich nicht prüfen", r.findings[0].title)

    def test_partial_protection_is_not_enough(self):
        w = self.world()
        mk_dirs(w, "plugins/system/adminexile")
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Teilschutz", r.findings[0].title)
        self.assertTrue(any(f.title.startswith("Empfehlungen") for f in r.findings))

    def test_free_and_pro_of_same_maker_is_not_a_conflict(self):
        w = self.world()
        mk_dirs(w, "administrator/components/com_securitycheck", "administrator/components/com_securitycheckpro")
        self.set_enabled(w, "securitycheck", 1, "component")
        self.set_enabled(w, "securitycheckpro", 1, "component")
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "ok", [f.title for f in r.findings])

    def test_two_firewalls_info(self):
        w = self.world()
        mk_dirs(w, "administrator/components/com_rsfirewall", "administrator/components/com_securitycheckpro")
        self.set_enabled(w, "rsfirewall", 1, "component")
        self.set_enabled(w, "securitycheckpro", 1, "component")
        r = run(w, "joomla")
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Mehrere", r.findings[0].title)

    def test_read_only(self):
        w = self.world()
        mk_dirs(w, "plugins/system/rsfirewall")

        def snap():
            return {os.path.join(d, n): os.lstat(os.path.join(d, n)).st_mtime_ns for d, dn, fn in os.walk(w["home"]) for n in dn + fn}
        before = snap()
        run(w, "joomla")
        self.assertEqual(before, snap())


class WordPressCase(unittest.TestCase):
    def world(self):
        return wpfixture.make_wp_world(tempfile.mkdtemp(prefix="claudia_sew_"), False)

    def set_active(self, w, slugs):
        ap = "a:%d:{%s}" % (len(slugs), "".join('i:%d;s:%d:"%s";' % (i, len(p), p) for i, p in enumerate(slugs)))
        c = sqlite3.connect(w["db"])
        c.execute("UPDATE wp_options SET option_value=? WHERE option_name='active_plugins'", (ap,))
        c.commit()
        c.close()

    def test_none_installed(self):
        r = run(self.world(), "wordpress")
        self.assertEqual(r.findings[0].sev, "info")
        self.assertIn("Kein Sicherheits-Plugin", r.findings[0].title)
        self.assertEqual(r.title, "Schutz durch ein Sicherheits-Plugin") if hasattr(r, "title") else None
        rec = [f for f in r.findings if f.title.startswith("Empfehlungen")][0]
        self.assertTrue(any("Wordfence" in i for i in rec.items))
        self.assertNotIn("JED", " ".join(rec.items))

    def test_active_wordfence_ok(self):
        w = self.world()
        mk_dirs(w, "wp-content/plugins/wordfence")
        self.set_active(w, ["wordfence/wordfence.php", "hello/hello.php"])
        r = run(w, "wordpress")
        self.assertEqual(r.findings[0].sev, "ok", [f.title for f in r.findings])
        self.assertIn("Wordfence", r.findings[0].title)

    def test_inactive_wordfence_warns(self):
        w = self.world()
        mk_dirs(w, "wp-content/plugins/wordfence")
        self.set_active(w, ["hello/hello.php"])
        r = run(w, "wordpress")
        self.assertEqual(r.findings[0].sev, "warn")
        self.assertIn("ausgeschaltet", r.findings[0].title)

    def test_live_ratings_from_wordpress_org(self):
        w = self.world()
        from claudia.checks import web as webmod

        def fake(url, *a, **k):
            self.assertTrue(url.startswith("https://api.wordpress.org/plugins/info/1.0/"), url)
            return mock.Mock(status=200, error="", body=json.dumps({"rating": 90, "num_ratings": 4321, "active_installs": 4000000}))
        with mock.patch.dict(os.environ, {}), mock.patch.object(webmod, "fetch", fake):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            r = run(w, "wordpress")
        rec = [f for f in r.findings if f.title.startswith("Empfehlungen")][0]
        self.assertTrue(any("4.5 von 5 Sternen, 4321 Bewertungen (wordpress.org)" in i for i in rec.items), rec.items)

    def test_rating_failure_keeps_list(self):
        w = self.world()
        from claudia.checks import web as webmod
        with mock.patch.dict(os.environ, {}), mock.patch.object(webmod, "fetch", lambda *a, **k: mock.Mock(status=0, error="offline", body="")):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            r = run(w, "wordpress")
        rec = [f for f in r.findings if f.title.startswith("Empfehlungen")][0]
        self.assertTrue(any("Wordfence" in i for i in rec.items))


if __name__ == "__main__":
    unittest.main()
