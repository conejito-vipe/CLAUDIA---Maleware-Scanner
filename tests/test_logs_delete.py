"""delete_old_backups: lokale Aktionsprotokolle werden mit den alten Sicherungen löschbar, das jeweils neueste je Aktion bleibt."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


def mk(d, name, text="x"):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(text)


def logdir():
    d = tempfile.mkdtemp(prefix="claudia_logs_")
    for n in ("aktion_core_update_20261101-100000.txt", "aktion_core_update_20261102-090000.txt", "aktion_core_update_20261030-080000.txt",
              "aktion_clean_tmp_20261031-120000.txt", "aktion_delete_old_backups_20261101-110000.txt"):
        mk(d, n)
    mk(d, "bericht_20261101.html")                      # kein Aktionsprotokoll
    mk(d, "aktion_x_20261101-1.txt")                    # falsches Format
    os.symlink(os.path.join(d, "bericht_20261101.html"), os.path.join(d, "aktion_link_20261101-100000.txt"))
    return d


class LocalLogs(unittest.TestCase):
    def test_list_marks_newest_per_action(self):
        d = logdir()
        lst = actions.list_local_logs(d)
        names = {e["name"]: e for e in lst}
        self.assertEqual(len(lst), 5)                   # Verweis, Bericht und Fremdformat bleiben außen vor
        self.assertTrue(names["aktion_core_update_20261102-090000.txt"]["newest"])
        self.assertFalse(names["aktion_core_update_20261101-100000.txt"]["newest"])
        self.assertTrue(names["aktion_clean_tmp_20261031-120000.txt"]["newest"])
        self.assertTrue(names["aktion_delete_old_backups_20261101-110000.txt"]["newest"])
        self.assertEqual(len(actions.deletable_local_logs(d)), 2)

    def test_delete_never_removes_newest_or_foreign(self):
        d = logdir()
        res = actions.delete_local_logs(d, ["aktion_core_update_20261102-090000.txt", "aktion_core_update_20261030-080000.txt",
                                            "bericht_20261101.html", "../x.txt", 5])
        self.assertEqual(res["deleted"], ["aktion_core_update_20261030-080000.txt"])
        self.assertTrue(os.path.exists(os.path.join(d, "aktion_core_update_20261102-090000.txt")))
        self.assertTrue(os.path.exists(os.path.join(d, "bericht_20261101.html")))

    def test_available_offers_only_when_something_deletable(self):
        d = logdir()
        info = {"cms": "joomla"}
        scan = {"backups": [], "local_logs": actions.list_local_logs(d), "log_dir": d}
        ids = [a["id"] for a in actions.available([], info, "", {}, scan)]
        self.assertIn("delete_old_backups", ids)
        d2 = tempfile.mkdtemp(prefix="claudia_logs_")
        mk(d2, "aktion_core_update_20261102-090000.txt")
        scan = {"backups": [], "local_logs": actions.list_local_logs(d2), "log_dir": d2}
        ids = [a["id"] for a in actions.available([], info, "", {}, scan)]
        self.assertNotIn("delete_old_backups", ids)

    def test_preview_and_selection_filter(self):
        d = logdir()
        params = {"backups": [], "logs": actions.list_local_logs(d), "log_dir": d,
                  "selected_logs": ["aktion_core_update_20261030-080000.txt", "aktion_core_update_20261102-090000.txt", "evil.txt"]}
        cmds = actions.commands_preview("delete_old_backups", params, [])
        self.assertEqual(len(cmds), 1)
        self.assertIn("aktion_core_update_20261030-080000.txt", cmds[0])

    def test_run_logs_only_without_server_contact(self):
        d = logdir()
        params = {"backups": [], "logs": actions.list_local_logs(d), "log_dir": d, "selected_logs": ["aktion_core_update_20261030-080000.txt"]}
        res = actions.run_action(None, "html", "delete_old_backups", params, [])
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(os.path.join(d, "aktion_core_update_20261030-080000.txt")))
        self.assertTrue(os.path.exists(os.path.join(d, "aktion_core_update_20261101-100000.txt")))
        self.assertIn("1 Protokoll", res["message"])

    def test_run_newest_in_selection_is_ignored_and_nothing_selected_fails(self):
        d = logdir()
        params = {"backups": [], "logs": actions.list_local_logs(d), "log_dir": d, "selected_logs": ["aktion_core_update_20261102-090000.txt"]}
        res = actions.run_action(None, "html", "delete_old_backups", params, [])
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.exists(os.path.join(d, "aktion_core_update_20261102-090000.txt")))

    def test_run_backups_and_logs_together(self):
        r, w = t2.world()
        home = w["home"]
        old = (OLD + "-sicherung-tmp-20261001-100000")
        new = (OLD + "-sicherung-tmp-20261102-100000")
        for n in (old, new):
            os.makedirs(os.path.join(home, n))
            mk(os.path.join(home, n), "tmp.tgz")
        d = logdir()
        bks = [{"name": new, "mtime": 2, "kb": 1, "kind": "tmp", "files": []}, {"name": old, "mtime": 1, "kb": 1, "kind": "tmp", "files": []}]
        params = {"backups": bks, "selected_backups": [old], "logs": actions.list_local_logs(d), "log_dir": d,
                  "selected_logs": ["aktion_core_update_20261030-080000.txt", "aktion_core_update_20261101-100000.txt"]}
        res = actions.run_action(r, w["site_rel"], "delete_old_backups", params, [])
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(os.path.join(home, old)))
        self.assertTrue(os.path.exists(os.path.join(home, new)))
        left = sorted(e["name"] for e in actions.list_local_logs(d))
        self.assertEqual(len(left), 3)
        self.assertIn("2 Protokoll", res["message"])
        self.assertIn("1 Sicherung", res["message"])


if __name__ == "__main__":
    unittest.main()
