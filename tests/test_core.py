"""Tests für Kern: Hilfsfunktionen, Konfig-Parser, Runner (lokal + SSH-Attrappe), Engine."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixture  # noqa: E402
from claudia import joomla, util  # noqa: E402
from claudia.engine import Ctx, Engine, Settings  # noqa: E402
from claudia.model import CheckSkipped  # noqa: E402
from claudia.registry import check, REGISTRY  # noqa: E402
from claudia.runner import LocalRunner, wrap_script  # noqa: E402


class UtilTests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(util.vcmp("2.9.99.3", "2.9.99.5"), -1)
        self.assertEqual(util.vcmp("6.0.62", "6.0.62"), 0)
        self.assertEqual(util.vcmp("6.0.62", "6.0.9"), 1)
        self.assertEqual(util.vcmp("5.2.5-beta1", "5.2.5"), 0)
        self.assertEqual(util.vcmp("2.9", "2.9.0.0"), 0)

    def test_mask(self):
        cfg = fixture.CONFIG_CLEAN
        m = util.mask_secrets(cfg)
        self.assertNotIn("GEHEIM", m)
        self.assertIn("public $dbprefix = 'j_';", m)
        self.assertIn("$password = '***'", m)
        self.assertEqual(util.mask_ip("IP 203.0.113.77 ok"), "IP 203.0.113.x ok")
        self.assertEqual(util.mask_ip("[15/Jun/2026:03:12:11 +0200] v1.2.3.4.5"), "[15/Jun/2026:03:12:11 +0200] v1.2.3.4.5")
        self.assertEqual(util.mask_ip("2.9.99.300"), "2.9.99.300")
        self.assertIn("2001:db8:1::x", util.mask_ip("addr 2001:db8:1:2:3:4:5:6 x"))

    def test_hosts(self):
        t = '<script src="https://cdn.evil.example/a.js"></script> <img src="//img.test.org/x.png"> http://localhost/x'
        self.assertEqual(util.extract_hosts(t), ["cdn.evil.example", "img.test.org"])
        self.assertTrue(util.host_allowed("static.elfsight.com", ["elfsight.com"]))
        self.assertFalse(util.host_allowed("notelfsight.com", ["elfsight.com"]))

    def test_mysql_unescape(self):
        self.assertEqual(util.mysql_unescape("a\\nb\\tc\\\\d"), "a\nb\tc\\d")
        self.assertIsNone(util.mysql_unescape("NULL"))

    def test_config_parser(self):
        p = joomla.parse_config(fixture.CONFIG_CLEAN)
        self.assertEqual(p["vars"]["dbprefix"], "j_")
        self.assertIs(p["vars"]["debug"], False)
        self.assertEqual(p["vars"]["lifetime"], 60)
        self.assertEqual(p["unexpected"], [])
        q = joomla.parse_config(fixture.CONFIG_INFECTED)
        self.assertEqual(len(q["unexpected"]), 1)
        self.assertIn("@include", q["unexpected"][0][1])

    def test_manifest(self):
        m = joomla.parse_manifest("plugins/system/t4/t4.xml", fixture.manifest("plg_system_t4", "2.6.2", "JoomlArt", "plugin", "system"))
        self.assertEqual((m["type"], m["group"], m["element"], m["version"], m["author"]), ("plugin", "system", "t4", "2.6.2", "JoomlArt"))
        self.assertIsNone(joomla.parse_manifest("x.xml", "<config><field/></config>"))
        v = joomla.parse_joomla_version(fixture.VERSION_PHP)
        self.assertEqual(v, "6.2.0")


class RunnerEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="claudia_t_")
        cls.world = fixture.make_world(cls.tmp, infected=True)

    def test_local_runner_in_site_dir(self):
        r = LocalRunner(self.world["home"])
        res = r.sh("html/site", "pwd; test -f configuration.php && echo CFG")
        self.assertTrue(res.ok, res.err)
        self.assertTrue(res.out.splitlines()[0].endswith("html/site"))
        self.assertIn("CFG", res.out)

    def test_missing_dir(self):
        r = LocalRunner(self.world["home"])
        res = r.sh("gibt/es/nicht", "echo x")
        self.assertEqual(res.rc, 97)
        self.assertIn("CLAUDIA_NO_SITE_DIR", res.err)

    def test_quoting_with_spaces_and_quotes(self):
        os.makedirs(os.path.join(self.world["home"], "mit leer 'zeichen'"), exist_ok=True)
        r = LocalRunner(self.world["home"])
        res = r.sh("mit leer 'zeichen'", "pwd")
        self.assertTrue(res.ok, res.err)
        self.assertTrue(res.out.strip().endswith("mit leer 'zeichen'"))

    def test_timeout(self):
        r = LocalRunner(self.world["home"])
        res = r.sh("html/site", "sleep 5", timeout=1)
        self.assertTrue(res.timed_out)

    def test_engine_runs_checks_and_isolates_errors(self):
        @check("t_ok", "grundlagen", "T ok", "s", "w", "w", "r")
        def t_ok(ctx, res):
            cfg = ctx.config()
            res.add("info", "Prefix", cfg["vars"]["dbprefix"])
            ctx.sh("ls", raw="ls")

        @check("t_boom", "grundlagen", "T boom", "s", "w", "w", "r")
        def t_boom(ctx, res):
            raise RuntimeError("kaputt")

        @check("t_skip", "grundlagen", "T skip", "s", "w", "w", "r")
        def t_skip(ctx, res):
            raise CheckSkipped("kein mysql")

        try:
            events = []
            eng = Engine(LocalRunner(self.world["home"]), Settings(site_dir="html/site"), {})
            out = eng.run(["t_ok", "t_boom", "t_skip"], events.append, threading.Event())
            st = {r.id: r.status for r in out}
            self.assertEqual(st, {"t_ok": "info", "t_boom": "error", "t_skip": "skipped"})
            self.assertIn("kaputt", out[1].message)
            self.assertIn("ls", out[0].raw)
            kinds = [e["type"] for e in events]
            self.assertEqual(kinds.count("start"), 3)
            self.assertEqual(kinds.count("done"), 3)
        finally:
            for k in ("t_ok", "t_boom", "t_skip"):
                REGISTRY.pop(k, None)

    def test_cancel(self):
        @check("t_slow", "grundlagen", "slow", "s", "w", "w", "r")
        def t_slow(ctx, res):
            ctx.progress("los")
            ctx.sh("sleep 0.2")
            ctx.progress("weiter")

        try:
            cancel = threading.Event()
            cancel.set()
            eng = Engine(LocalRunner(self.world["home"]), Settings(site_dir="html/site"), {})
            out = eng.run(["t_slow"], lambda e: None, cancel)
            self.assertEqual(out, [])
        finally:
            REGISTRY.pop("t_slow", None)

    def test_raw_masking(self):
        @check("t_raw", "grundlagen", "raw", "s", "w", "w", "r")
        def t_raw(ctx, res):
            ctx.sh("cat configuration.php", raw="cfg")
            ctx.add_raw("ips", "Besucher 203.0.113.99 war da", ips=True)
            ctx.add_raw("version", "JCE 2.9.99.7 bleibt")

        try:
            eng = Engine(LocalRunner(self.world["home"]), Settings(site_dir="html/site", mask_ips=True), {})
            out = eng.run(["t_raw"], lambda e: None, threading.Event())
            raw = out[0].raw
            self.assertNotIn("GEHEIM", raw["cfg"])
            self.assertEqual(raw["ips"], "Besucher 203.0.113.x war da")
            self.assertEqual(raw["version"], "JCE 2.9.99.7 bleibt")
        finally:
            REGISTRY.pop("t_raw", None)


class SSHAdapterTests(unittest.TestCase):
    """Testet claudia.runner.SSHRunner mit der paramiko-Attrappe."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="claudia_s_")
        cls.world = fixture.make_world(cls.tmp, infected=True)
        sys.path.insert(0, os.path.join(HERE, "fake_paramiko"))
        import paramiko  # die Attrappe
        cls.pm = paramiko
        cls.pm.CONFIG.update(home=cls.world["home"], password="pw", fail=None)

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(os.path.join(HERE, "fake_paramiko"))
        sys.modules.pop("paramiko", None)

    def _runner(self, **kw):
        from claudia.runner import KnownHosts, SSHRunner
        kh = KnownHosts(os.path.join(self.tmp, "known_%s.json" % kw.pop("kh", "a")))
        return SSHRunner("fake.example.org", 22, "tester", password=kw.pop("password", "pw"), known_hosts=kh, **kw)

    def test_unknown_host_key_then_trust(self):
        from claudia.runner import HostKeyUnknown
        r = self._runner(kh="trust")
        with self.assertRaises(HostKeyUnknown) as cm:
            r.connect()
        fp = cm.exception.fingerprint
        self.assertTrue(fp.startswith("SHA256:"))
        r2 = self._runner(kh="trust", trusted_fp=fp)
        r2.connect()
        res = r2.sh("html/site", "echo hallo; pwd")
        self.assertTrue(res.ok, res.err)
        self.assertIn("hallo", res.out)
        r2.close()
        # beim nächsten Mal ist der Schlüssel bekannt
        r3 = self._runner(kh="trust")
        r3.connect()
        r3.close()

    def test_wrong_trusted_fingerprint(self):
        from claudia.runner import HostKeyUnknown
        r = self._runner(kh="wrongfp", trusted_fp="SHA256:falsch")
        with self.assertRaises(HostKeyUnknown):
            r.connect()

    def test_changed_host_key(self):
        from claudia.runner import HostKeyChanged, HostKeyUnknown
        r = self._runner(kh="changed")
        with self.assertRaises(HostKeyUnknown) as cm:
            r.connect()
        r = self._runner(kh="changed", trusted_fp=cm.exception.fingerprint)
        r.connect()
        r.close()
        old = self.pm.CONFIG["host_key"]
        self.pm.CONFIG["host_key"] = b"anderer-schluessel"
        try:
            r = self._runner(kh="changed")
            with self.assertRaises(HostKeyChanged):
                r.connect()
        finally:
            self.pm.CONFIG["host_key"] = old

    def test_auth_and_network_errors(self):
        from claudia.runner import AuthFailed, ConnectFailed, HostKeyUnknown
        r = self._runner(kh="auth")
        with self.assertRaises(HostKeyUnknown) as cm:
            r.connect()
        with self.assertRaises(AuthFailed):
            self._runner(kh="auth", password="falsch", trusted_fp=cm.exception.fingerprint).connect()
        for mode in ("dns", "timeout", "refused"):
            self.pm.CONFIG["fail"] = mode
            try:
                with self.assertRaises(ConnectFailed):
                    self._runner(kh="auth").connect()
            finally:
                self.pm.CONFIG["fail"] = None

    def test_large_output_and_timeout_and_rc(self):
        from claudia.runner import HostKeyUnknown
        r = self._runner(kh="big")
        with self.assertRaises(HostKeyUnknown) as cm:
            r.connect()
        r = self._runner(kh="big", trusted_fp=cm.exception.fingerprint)
        r.connect()
        big = r.sh("html/site", "head -c 3000000 /dev/zero | tr '\\0' 'a'")
        self.assertEqual(len(big.out), 3000000)
        err = r.sh("html/site", "echo fehler >&2; exit 3")
        self.assertEqual(err.rc, 3)
        self.assertIn("fehler", err.err)
        slow = r.sh("html/site", "sleep 5", timeout=1)
        self.assertTrue(slow.timed_out)
        r.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
