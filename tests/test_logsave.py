"""Protokolle auf den PC sichern: vollständig, geprüft, nur lesend, nur Dateien aus der Liste."""
import hashlib
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia import logsave  # noqa: E402
from claudia.checks.logs import _iter_files  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError, App  # noqa: E402
from test_readonly import snapshot  # noqa: E402


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def wait(job, secs=20):
    t = time.time()
    while not job.finished and time.time() - t < secs:
        time.sleep(0.02)
    assert job.finished, "Sicherung wurde nicht fertig"


class Helpers(unittest.TestCase):
    def test_safe_rel_blocks_traversal_and_windows_chars(self):
        self.assertEqual(logsave.safe_rel("../../etc/passwd"), "etc/passwd")
        self.assertEqual(logsave.safe_rel("a/b:c*d?.log"), "a/b_c_d_.log")
        self.assertEqual(logsave.safe_rel("C:\\x\\y.log"), "C_/x/y.log")
        with self.assertRaises(logsave.LogSaveError):
            logsave.safe_rel("../..")

    def test_stamped_keeps_gz_extension(self):
        self.assertTrue(logsave.stamped("hoster/logs/access.log.1.gz", 0).endswith(".gz"))
        self.assertRegex(logsave.stamped("hoster/logs/access.log", 0), r"access\.\d{8}-\d{6}\.log$")
        self.assertRegex(logsave.stamped("joomla/x.php", 0), r"x\.\d{8}-\d{6}\.php$")


class Save(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_ls_"), False)
        self.r = LocalRunner(self.w["home"], extra_path=self.w["bin"])
        self.base = tempfile.mkdtemp(prefix="claudia_lsout_")

    def items(self, **kw):
        return logsave.list_remote(self.r, self.w["site_rel"], **kw)

    def run_job(self, arch, todo):
        job = logsave.SaveJob(self.r, self.w["site_rel"], arch, todo)
        job.start()
        wait(job)
        return job

    def test_list_contains_hoster_and_joomla_logs(self):
        it = self.items()
        rels = [x["rel"] for x in it]
        self.assertTrue(any(r.startswith("hoster/logs/access.log") for r in rels), rels)
        self.assertTrue(any(r.startswith("joomla/") and "joomla_error.php" in r for r in rels), rels)
        self.assertFalse(any(".." in r for r in rels))
        self.assertEqual([x["rel"] for x in self.items(include_joomla=False) if x["source"] == "joomla"], [])

    def test_copy_is_identical_and_checksummed(self):
        arch = logsave.Archive(self.base, "ssh.beispiel.de")
        pl = logsave.plan(arch, self.items())
        self.assertGreater(pl["new"], 2)
        self.assertTrue(pl["fits"])
        job = self.run_job(arch, pl["todo"])
        self.assertEqual(job.failed, [])
        for it in pl["todo"]:
            local = os.path.join(arch.dir, *it["rel"].split("/"))
            self.assertEqual(sha(local), sha(it["remote"].replace(self.w["home"], self.w["home"])), it["rel"])
        sums = open(os.path.join(arch.dir, logsave.SUMS), encoding="utf-8").read()
        self.assertIn(sha(os.path.join(arch.dir, "hoster", "logs", "access.log")), sums)
        self.assertTrue(os.path.isfile(os.path.join(arch.dir, logsave.README)))
        self.assertEqual([f for f in os.listdir(arch.dir) if f.endswith(".teil")], [])

    def test_second_run_copies_nothing_new(self):
        arch = logsave.Archive(self.base, "h")
        self.run_job(arch, logsave.plan(arch, self.items())["todo"])
        arch2 = logsave.Archive(self.base, "h")          # neu laden: Merkzettel kommt von der Platte
        pl = logsave.plan(arch2, self.items())
        self.assertEqual((pl["new"], pl["changed"]), (0, 0))
        self.assertGreater(pl["have"], 2)

    def test_changed_file_is_kept_as_new_version_not_overwritten(self):
        arch = logsave.Archive(self.base, "h")
        self.run_job(arch, logsave.plan(arch, self.items())["todo"])
        first = open(os.path.join(arch.dir, "hoster", "logs", "access.log"), "rb").read()
        with open(os.path.join(self.w["home"], "logs", "access.log"), "ab") as fh:
            fh.write(b"198.51.100.7 - - [30/Oct/2026:09:00:00 +0100] \"GET / HTTP/1.1\" 200 5\n")
        arch2 = logsave.Archive(self.base, "h")
        pl = logsave.plan(arch2, self.items())
        self.assertEqual(pl["changed"], 1)
        self.run_job(arch2, pl["todo"])
        self.assertEqual(open(os.path.join(arch.dir, "hoster", "logs", "access.log"), "rb").read(), first)   # alte Fassung bleibt
        newer = [f for f in os.listdir(os.path.join(arch.dir, "hoster", "logs")) if f.startswith("access.") and f.endswith(".log") and f != "access.log"]
        self.assertEqual(len(newer), 1, newer)

    def test_server_is_not_changed(self):
        before = snapshot(self.w["home"])
        arch = logsave.Archive(self.base, "h")
        self.run_job(arch, logsave.plan(arch, self.items())["todo"])
        self.assertEqual(snapshot(self.w["home"]), before)

    def test_only_listed_files_are_fetched(self):
        arch = logsave.Archive(self.base, "h")
        secret = os.path.join(self.w["home"], "geheim.txt")
        open(secret, "w").write("nicht kopieren")
        bad = [{"rel": "hoster/x.log", "remote": secret, "size": 14, "mtime": 0, "state": "neu"}]
        job = logsave.SaveJob(self.r, self.w["site_rel"], arch, [dict(bad[0])])
        job.allowed = set()            # Datei steht nicht in der Liste
        job.start()
        wait(job)
        self.assertEqual(len(job.failed), 1)
        self.assertFalse(os.path.exists(os.path.join(arch.dir, "hoster", "x.log")))

    def test_file_shrunk_during_copy_is_reported_not_saved(self):
        arch = logsave.Archive(self.base, "h")
        it = [x for x in self.items() if x["rel"].endswith("access.log")][0]
        it = dict(it, size=it["size"] + 50, state="neu")      # Liste behauptet mehr, als die Datei hat
        job = self.run_job(arch, [it])
        self.assertEqual(len(job.failed), 1)
        self.assertIn("verändert", job.failed[0])
        self.assertFalse(os.path.exists(os.path.join(arch.dir, "hoster", "logs", "access.log")))
        self.assertEqual([f for r, d, fs in os.walk(arch.dir) for f in fs if f.endswith(".teil")], [])

    def test_saved_folder_is_readable_by_local_check(self):
        arch = logsave.Archive(self.base, "h")
        self.run_job(arch, logsave.plan(arch, self.items())["todo"])
        files = _iter_files(arch.dir)
        self.assertTrue(any(f.endswith("access.log") for f in files))
        self.assertFalse(any(os.path.basename(f).startswith("SICHERUNG_") for f in files))

    def test_cancel_stops(self):
        arch = logsave.Archive(self.base, "h")
        pl = logsave.plan(arch, self.items())
        job = logsave.SaveJob(self.r, self.w["site_rel"], arch, pl["todo"])
        job.cancel.set()
        job.start()
        wait(job)
        self.assertEqual(job.saved, [])


class OverSSH(unittest.TestCase):
    """Derselbe Ablauf über SSHRunner (Paramiko-Attrappe): binäre Dateien müssen Byte für Byte ankommen."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="claudia_lss_")
        cls.world = fixture.make_world(cls.tmp, infected=False)
        sys.path.insert(0, os.path.join(HERE, "fake_paramiko"))
        import paramiko
        cls.pm = paramiko
        cls.pm.CONFIG.update(home=cls.world["home"], password="pw", fail=None, extra_path=cls.world["bin"])

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(os.path.join(HERE, "fake_paramiko"))
        sys.modules.pop("paramiko", None)

    def test_binary_gz_arrives_intact(self):
        from claudia.runner import KnownHosts, SSHRunner
        gz = os.path.join(self.world["home"], "logs", "access.log.1.gz")
        blob = bytes(range(256)) * 4000                        # ~1 MB, alle Byte-Werte inkl. 0x00 und 0xFF
        with open(gz, "wb") as fh:
            fh.write(blob)
        r = SSHRunner("fake.example.org", 22, "tester", password="pw", known_hosts=KnownHosts(None), trusted_fp="")
        try:
            r.connect()
        except Exception:
            kh = KnownHosts(None)
            from claudia.runner import HostKeyUnknown
            try:
                r.connect()
            except HostKeyUnknown as e:
                r = SSHRunner("fake.example.org", 22, "tester", password="pw", known_hosts=kh, trusted_fp=e.fingerprint)
                r.connect()
        base = tempfile.mkdtemp(prefix="claudia_lsso_")
        arch = logsave.Archive(base, "fake")
        items = logsave.list_remote(r, self.world["site_rel"])
        pl = logsave.plan(arch, items)
        job = logsave.SaveJob(r, self.world["site_rel"], arch, pl["todo"])
        job.start()
        wait(job)
        r.close()
        self.assertEqual(job.failed, [])
        got = open(os.path.join(arch.dir, "hoster", "logs", "access.log.1.gz"), "rb").read()
        self.assertEqual(got, blob)


class ViaApp(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_lsa_"), False)
        os.environ["CLAUDIA_LOGS"] = tempfile.mkdtemp(prefix="claudia_lsb_")
        self.app = App(tempfile.mkdtemp(prefix="claudia_lsd_"))
        self.app.runner = LocalRunner(self.w["home"], extra_path=self.w["bin"])
        self.app.conn = {"host": "ssh.beispiel.de", "site_dir": self.w["site_rel"]}

    def tearDown(self):
        os.environ.pop("CLAUDIA_LOGS", None)

    def test_plan_save_state(self):
        pl = self.app.logs_plan({})
        self.assertGreater(pl["new"], 2)
        self.assertNotIn("remote", pl["todo"][0])           # keine Serverpfade nach außen
        with self.assertRaises(ApiError):
            self.app.logs_save({})                            # ohne Bestätigung
        r = self.app.logs_save({"confirm": True})
        self.assertTrue(r["started"])
        wait(self.app.logjob)
        st = self.app.logs_state()
        self.assertTrue(st["done"])
        self.assertEqual(st["failed"], [])
        self.assertGreater(st["saved"], 2)
        again = self.app.logs_save({"confirm": True})
        self.assertFalse(again["started"])

    def test_not_connected(self):
        self.app.runner = None
        with self.assertRaises(ApiError):
            self.app.logs_plan({})


if __name__ == "__main__":
    unittest.main()
