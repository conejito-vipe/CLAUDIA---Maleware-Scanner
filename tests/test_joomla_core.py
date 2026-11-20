"""Joomla-Kern gegen das Original: Vergleich, Test (mit echtem Test-ZIP, ohne Netz) und Aktion 'Kerndateien neu einspielen'."""
import hashlib
import io
import json
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
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import fixture  # noqa: E402
from claudia import actions, coreref  # noqa: E402
from claudia.checks import joomla_core  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()
CORE_DIRS = ("administrator", "api", "components", "includes", "layouts", "libraries", "media", "modules", "plugins", "templates")
SKIP = ("administrator/cache", "administrator/logs", "administrator/_protected", "administrator/components/com_akeebabackup")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def package_from(site):
    """Ein 'Original-Paket' aus dem sauberen Test-Joomla (nur Kernordner und index.php)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for d in CORE_DIRS:
            for r, _, fs in os.walk(os.path.join(site, d)):
                for f in fs:
                    p = os.path.join(r, f)
                    rel = os.path.relpath(p, site).replace(os.sep, "/")
                    if rel.startswith(SKIP) or f == ".htaccess":
                        continue
                    z.write(p, rel)
        z.write(os.path.join(site, "index.php"), "index.php")
    return buf.getvalue()


class Env:
    def __init__(self, tc):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_core_"), False)
        self.cache = tempfile.mkdtemp(prefix="claudia_cache_")
        self.data = package_from(self.w["site"])
        self.zip = os.path.join(self.cache, "Joomla_6.2.0-Stable-Full_Package.zip")
        with open(self.zip, "wb") as fh:
            fh.write(self.data)
        self.ref = {"version": "6.2.0", "files": coreref.hash_zip(self.data), "verified": True, "cross": False, "source": "test", "package": os.path.basename(self.zip),
                    "sha256": sha(self.data), "url": "https://github.com/joomla/joomla-cms/releases/download/6.2.0/x.zip"}
        self.patches = [mock.patch.object(coreref, "reference", lambda v, force=False: self.ref), mock.patch.object(coreref, "package_path", lambda r: (self.zip, r["sha256"])),
                        mock.patch.object(joomla_core, "MIN_FILES", 10), mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": ""})]
        for p in self.patches:
            p.start()
            tc.addCleanup(p.stop)

    def run_check(self):
        s = Settings(site_dir=self.w["site_rel"], log_dir="logs", cms="joomla", url="", allow_hosts=ADV["allow_hosts"])
        eng = Engine(LocalRunner(self.w["home"], extra_path=self.w["bin"]), s, ADV)
        return eng.run(["joomla_core"], lambda e: None, threading.Event())[0]

    def path(self, rel):
        return os.path.join(self.w["site"], rel)


def titles(res):
    return [(f.sev, f.title) for f in res.findings]


class Compare(unittest.TestCase):
    def test_compare_categories(self):
        ref = {"a/x.php": "1", "a/y.php": "2", "a/index.html": "3", "b/z.php": "4", "language/en-GB/l.ini": "5", "index.php": "6", "installation/i.php": "7"}
        srv = {"a/x.php": "1", "a/y.php": "CHANGED", "b/z.php": "4", "language/en-GB/l.ini": "X", "index.php": "6", "a/evil.php": "9", "a/user.css": "9",
               "c/own.php": "9", "language/en-GB/own.ini": "9", "a/html/o.php": "9"}
        d = joomla_core.compare(ref, srv)
        self.assertEqual(d["changed"], ["a/y.php"])
        self.assertEqual(d["noindex"], ["a/index.html"])
        self.assertEqual(d["soft"], ["language/en-GB/l.ini"])
        self.assertEqual(d["extra"], ["a/evil.php"])          # Fremdordner, Overrides, user.css und Sprachordner zählen nicht
        self.assertEqual(d["missing"], [])

    def test_classify_extra_manifests_docs_and_code(self):
        extra = ["administrator/manifests/packages/pkg_jce.xml", "administrator/manifests/packages/jce/install.pkg.php",
                 "administrator/components/com_tags/jaupdater.com_tags.xml", "administrator/components/com_ajax/jaupdater.com_ajax.xml",
                 "libraries/vendor/google/recaptcha/README.md", "layouts/joomla/evil.php", "layouts/joomla/jaupdater.php"]
        c = joomla_core.classify_extra(extra, joomla_core.element_names("jaupdater\ncom_tags\nplg_x\n"))
        self.assertEqual(len(c["manifest"]), 2)
        self.assertEqual(c["exec"], ["layouts/joomla/evil.php", "layouts/joomla/jaupdater.php"])
        self.assertEqual(c["owned"], {"layouts/joomla/jaupdater.php": "jaupdater"})
        self.assertEqual(len(c["other"]), 3)
        self.assertTrue(any("jaupdater.*.xml" in r and "2 Datei" in r and "jaupdater" in r.split("gehört")[-1] for r in c["other_rows"]), c["other_rows"])

    def test_parse_sums_keeps_dotfiles(self):
        t = "%s  ./index.php\n%s  administrator/a b.php\n" % ("a" * 64, "b" * 64)
        d = joomla_core.parse_sums(t)
        self.assertIn("index.php", d)
        self.assertEqual(coreref.is_compared(".htaccess"), False)
        self.assertEqual(coreref.is_compared("configuration.php"), False)
        self.assertEqual(coreref.is_compared("libraries/src/Version.php"), True)


class Check(unittest.TestCase):
    def test_clean_site_is_ok(self):
        e = Env(self)
        r = e.run_check()
        self.assertEqual(r.status, "ok", titles(r) + [r.message])
        self.assertTrue(any(f.title.startswith(joomla_core.TITLE_OK) for f in r.findings))

    def test_changed_missing_extra_and_fix_offer(self):
        e = Env(self)
        with open(e.path("libraries/src/Version.php"), "a") as fh:
            fh.write("\n// eingeschleust\n")
        os.remove(e.path("includes/app.php"))
        with open(e.path("layouts/joomla/form/field/evil.php"), "w") as fh:
            fh.write("<?php // x\n")
        r = e.run_check()
        t = titles(r)
        self.assertIn(("crit", "1 " + joomla_core.TITLE_CHANGED), t, t)
        self.assertIn(("warn", "1 " + joomla_core.TITLE_MISSING), t)
        self.assertTrue(any(s == "crit" and "unbekannte" in x for s, x in t))
        fix = [f for f in r.findings if f.title.startswith(joomla_core.TITLE_FIX)]
        self.assertEqual(len(fix), 1)
        self.assertEqual(sorted(fix[0].items), ["includes/app.php", "libraries/src/Version.php"])      # unbekannte Datei nie dabei

    def test_extension_files_without_code_are_info_not_critical(self):
        e = Env(self)
        with open(e.path("layouts/joomla/form/field/jaupdater.field.xml"), "w") as fh:
            fh.write("<x/>\n")
        with open(e.path("layouts/joomla/form/field/README.md"), "w") as fh:
            fh.write("doc\n")
        r = e.run_check()
        t = titles(r)
        self.assertEqual(r.status, "info", t)
        self.assertTrue(any(s == "info" and "ohne Programmcode" in x for s, x in t), t)
        self.assertFalse(any("unbekannte" in x for s, x in t), t)

    def test_extra_php_has_code_preview_and_is_critical(self):
        e = Env(self)
        with open(e.path("layouts/joomla/form/field/evil.php"), "w") as fh:
            fh.write("<?php\necho 1;\n")
        r = e.run_check()
        f = [f for f in r.findings if "unbekannte" in f.title][0]
        self.assertEqual(f.sev, "crit")
        self.assertEqual(f.evidence[0]["file"], "./layouts/joomla/form/field/evil.php")
        self.assertEqual(f.evidence[0]["code"][0]["t"], "<?php")

    def _owned_env(self, content):
        e = Env(self)
        with open(e.path("administrator/components/com_convertforms/convertforms.php"), "w") as fh:
            fh.write(content)
        return e

    def test_php_of_installed_extension_without_danger_is_info(self):
        r = self._owned_env("<?php\n// Hilfsdatei\n$a = 1;\n").run_check()
        t = titles(r)
        self.assertTrue(any(s == "info" and "gehören zu installierten Erweiterungen" in x for s, x in t), t)
        self.assertFalse(any(s == "crit" and "unbekannte" in x for s, x in t), t)

    def test_php_of_installed_extension_with_danger_is_critical_and_marked_red(self):
        r = self._owned_env("<?php\n$a = 1;\n@eval(base64_decode($_POST['x']));\n").run_check()
        f = [f for f in r.findings if "unbekannte" in f.title]
        self.assertEqual(len(f), 1, titles(r))
        self.assertEqual(f[0].sev, "crit")
        self.assertIn("Zeile 3", f[0].items[0])
        self.assertTrue(f[0].evidence and "rot markiert" in f[0].evidence[0].get("note", ""), f[0].evidence)

    def test_single_unknown_php_with_danger_is_found(self):
        """Ein einzelner Pfad: grep nennt den Dateinamen nur mit -H (früher wurde der Treffer dann übersehen)."""
        e = Env(self)
        with open(e.path("layouts/joomla/form/field/evil.php"), "w") as fh:
            fh.write("<?php\nsystem($_GET['c']);\n")
        f = [f for f in e.run_check().findings if "unbekannte" in f.title][0]
        self.assertIn("enthält gefährlichen Ausdruck", f.items[0])

    def test_no_fix_when_reference_not_verified(self):
        e = Env(self)
        e.ref["verified"] = False
        with open(e.path("includes/app.php"), "a") as fh:
            fh.write("//x\n")
        r = e.run_check()
        self.assertFalse(any(f.title.startswith(joomla_core.TITLE_FIX) for f in r.findings))
        self.assertTrue(any(f.title == joomla_core.TITLE_NOFIX for f in r.findings))

    def test_offline_and_unavailable_reference_are_skipped_not_errors(self):
        e = Env(self)
        with mock.patch.object(coreref, "reference", side_effect=coreref.RefError("kein Netz")):
            r = e.run_check()
        self.assertEqual(r.status, "skipped")
        self.assertIn("kein Netz", r.message)
        with mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": "1"}):
            r = e.run_check()
        self.assertEqual(r.status, "skipped")

    def test_check_is_read_only(self):
        e = Env(self)
        before = {p: os.stat(p).st_mtime for p in (e.path("index.php"), e.path("libraries/src/Version.php"))}
        e.run_check()
        self.assertEqual(before, {p: os.stat(p).st_mtime for p in before})


class Action(unittest.TestCase):
    def setUp(self):
        self.e = Env(self)
        self.runner = LocalRunner(self.e.w["home"], extra_path=self.e.w["bin"])
        self.bk = os.path.join(self.e.w["home"], (OLD + "-sicherung-20261103-100000"))
        os.makedirs(self.bk)

    def params(self, files):
        return {"version": "6.2.0", "files": files}

    def run_core(self, files):
        steps = []
        result = {"ok": False, "steps": steps, "backup_dir": self.bk, "message": ""}
        actions._run_joomla_core(self.runner, self.e.w["site_rel"], self.params(files), lambda t, ok, o="": steps.append((t, ok, o)), result)
        return result, steps

    def test_replaces_only_listed_files_and_verifies(self):
        e = self.e
        good = open(e.path("includes/app.php"), "rb").read()
        with open(e.path("includes/app.php"), "a") as fh:
            fh.write("\n// hintertuer\n")
        os.remove(e.path("libraries/src/Version.php"))
        with open(e.path("layouts/joomla/form/field/evil.php"), "w") as fh:
            fh.write("<?php // unbekannt\n")
        other = open(e.path("templates/cassiopeia/index.php"), "rb").read()
        res, steps = self.run_core(["includes/app.php", "libraries/src/Version.php"])
        self.assertTrue(res["ok"], (res, steps))
        self.assertEqual(open(e.path("includes/app.php"), "rb").read(), good)
        self.assertTrue(os.path.exists(e.path("libraries/src/Version.php")))
        self.assertTrue(os.path.exists(e.path("layouts/joomla/form/field/evil.php")))            # Unbekanntes bleibt liegen
        self.assertEqual(open(e.path("templates/cassiopeia/index.php"), "rb").read(), other)
        self.assertFalse(os.path.exists(os.path.join(self.bk, "original.zip")))        # Aufräumen
        self.assertIn("2 Kerndatei", res["message"])

    def test_nothing_to_do_when_already_clean(self):
        res, _ = self.run_core(["includes/app.php"])
        self.assertTrue(res["ok"])
        self.assertIn("nichts zu tun", res["message"])

    def test_refuses_unverified_reference_and_bad_paths(self):
        self.e.ref["verified"] = False
        with self.assertRaises(actions.ActionError):
            self.run_core(["includes/app.php"])
        self.e.ref["verified"] = True
        with self.assertRaises(actions.ActionError):
            self.run_core(["../../etc/passwd", "configuration.php", "images/logo.jpg", "nicht/im/paket.php"])

    def test_available_offers_action_from_check_finding(self):
        res = [{"id": "joomla_core", "findings": [{"sev": "info", "title": joomla_core.TITLE_FIX + " (x)", "items": ["includes/app.php"]}]}]
        lst = actions.available(res, {"cms": "joomla", "joomla": "6.2.0"}, "", {}, {})
        a = [x for x in lst if x["id"] == "joomla_core_reinstall"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["params"]["files"], ["includes/app.php"])
        self.assertEqual(a[0]["params"]["version"], "6.2.0")
        self.assertTrue(a[0]["backup"])
        self.assertNotIn("joomla_core_reinstall", [x["id"] for x in actions.available([], {"cms": "joomla"}, "", {}, {})])
        self.assertNotIn("joomla_core_reinstall", [x["id"] for x in actions.available(res, {"cms": "wordpress"}, "", {}, {})])
        cmds = actions.commands_preview("joomla_core_reinstall", a[0]["params"], [])
        self.assertTrue(any("sha256sum" in c for c in cmds))


class Reference(unittest.TestCase):
    def test_reference_verifies_hash_and_caches(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            z.writestr("index.php", "<?php\n")
            z.writestr("libraries/a.php", "x")
        raw = data.getvalue()
        api = json.dumps({"assets": [{"name": "Joomla_5.2.1-Stable-Full_Package.zip", "browser_download_url": "https://github.com/joomla/joomla-cms/releases/download/5.2.1/Joomla_5.2.1-Stable-Full_Package.zip",
                                      "digest": "sha256:" + sha(raw)}]}).encode()

        def fake(url, max_bytes=5_000_000, timeout=30.0):
            if "api.github.com" in url:
                return api
            if url.endswith(".zip"):
                return raw
            raise coreref.RefError("nicht erreichbar")
        cache = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"CLAUDIA_CACHE": cache, "CLAUDIA_NO_UPDATE_SERVER": "1"}), mock.patch.object(coreref, "fetch_bytes", fake):
            ref = coreref.reference("5.2.1")
            self.assertTrue(ref["verified"])
            self.assertEqual(sorted(ref["files"]), ["index.php", "libraries/a.php"])
            with mock.patch.object(coreref, "fetch_bytes", side_effect=coreref.RefError("offline")):
                self.assertEqual(coreref.reference("5.2.1")["sha256"], sha(raw))          # aus dem Cache
            bad = json.dumps({"assets": [{"name": "Joomla_5.2.2-Stable-Full_Package.zip", "browser_download_url": "https://github.com/joomla/joomla-cms/releases/download/5.2.2/Joomla_5.2.2-Stable-Full_Package.zip",
                                          "digest": "sha256:" + "0" * 64}]}).encode()
            with mock.patch.object(coreref, "fetch_bytes", lambda u, m=5_000_000, timeout=30.0: bad if "api.github" in u else raw):
                with self.assertRaises(coreref.RefError):
                    coreref.reference("5.2.2")                                              # falsche Prüfsumme: Paket wird verworfen

    def test_only_https_and_standard_versions(self):
        with self.assertRaises(coreref.RefError):
            coreref.fetch_bytes("http://example.org/x.zip")
        with self.assertRaises(coreref.RefError):
            coreref.release_asset("5.2.1-rc1")


if __name__ == "__main__":
    unittest.main()
