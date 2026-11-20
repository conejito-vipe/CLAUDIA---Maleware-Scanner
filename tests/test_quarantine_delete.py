"""2.3.3: Quarantäne-Ordner im Programm löschen (Aktion delete_quarantine)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from test_quarantine import move, put, restore  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


def delete(r, w, names):
    return actions.run_action(r, w["site_rel"], "delete_quarantine", {"selected_pick": ["k:" + n for n in names]}, [])


class DeleteQuarantine(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]
        put(self.s, "images/a.php", "<?php 1;")
        put(self.s, "images/b.php", "<?php 2;")
        self.q1 = move(self.r, self.w, ["./images/a.php"])["backup_dir"]
        self.q2 = move(self.r, self.w, ["./images/b.php"])["backup_dir"]
        self.sc = actions.scan_server(self.r, self.w["site_rel"])

    def test_scan_offers_action_nothing_preselected(self):
        self.assertEqual(sorted(q["name"] for q in self.sc["quarantine_dirs"]), sorted(os.path.basename(x) for x in (self.q1, self.q2)))
        a = [x for x in actions.available([], {"cms": "joomla"}, "8.3", scan=self.sc) if x["id"] == "delete_quarantine"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["risk"], "hoch")
        self.assertTrue(all(not x["pre"] for x in a[0]["params"]["pick"]))
        self.assertTrue(any("images/a.php" in x["label"] for x in a[0]["params"]["pick"]))
        self.assertFalse([x for x in actions.available([], {"cms": "joomla"}, "8.3", scan={}) if x["id"] == "delete_quarantine"])

    def test_preview_shows_rm_without_running_it(self):
        n = os.path.basename(self.q1)
        pv = actions.commands_preview("delete_quarantine", {"quarantine_dirs": self.sc["quarantine_dirs"], "selected_pick": ["k:" + n]}, [])
        self.assertTrue(any(l.startswith("rm -rf -- ~/" + n) and "nicht mehr zurückholbar" in l for l in pv))
        self.assertTrue(os.path.isdir(self.q1))

    def test_deletes_only_the_picked_folder(self):
        res = delete(self.r, self.w, [os.path.basename(self.q1)])
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(self.q1))
        self.assertTrue(os.path.isdir(self.q2))
        self.assertEqual(os.listdir(os.path.join(self.q2, "d")), ["0001.q"])               # die andere Quarantäne bleibt zurückholbar
        self.assertTrue(restore(self.r, self.w, ["q:%s/0001" % os.path.basename(self.q2)])["ok"])

    def test_deleted_files_cannot_be_restored_any_more(self):
        n = os.path.basename(self.q1)
        self.assertTrue(delete(self.r, self.w, [n])["ok"])
        res = restore(self.r, self.w, ["q:%s/0001" % n])
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.exists(os.path.join(self.s, "images", "a.php")))

    def test_empty_folder_after_full_restore_is_listed_and_deletable(self):
        n = os.path.basename(self.q1)
        self.assertTrue(restore(self.r, self.w, ["q:%s/0001" % n])["ok"])
        sc = actions.scan_server(self.r, self.w["site_rel"])
        self.assertIn(n, [q["name"] for q in sc["quarantine_dirs"]])
        self.assertTrue(delete(self.r, self.w, [n])["ok"])

    def test_foreign_and_unmarked_folders_are_never_touched(self):
        home = self.w["home"]
        fremd = os.path.join(home, (OLD + "-quarantaene-20200101-000000"))                    # passender Name, aber ohne Liste
        os.makedirs(fremd)
        open(os.path.join(fremd, "wichtig.txt"), "w").write("x")
        res = delete(self.r, self.w, [(OLD + "-quarantaene-20200101-000000")])
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.exists(os.path.join(fremd, "wichtig.txt")))
        self.assertIn("nicht von diesem Programm", res["error"])
        lst = os.path.join(self.q2, "QUARANTAENE.txt")                                     # Liste einer anderen Seite
        open(lst, "w", encoding="utf-8").write(open(lst, encoding="utf-8").read().replace("# Seitenordner: ", "# Seitenordner: /anderswo"))
        res = delete(self.r, self.w, [os.path.basename(self.q2)])
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.isdir(self.q2))
        self.assertNotIn(os.path.basename(self.q2), [q["name"] for q in actions.scan_server(self.r, self.w["site_rel"])["quarantine_dirs"]])

    def test_symlink_and_bad_names_are_ignored(self):
        home = self.w["home"]
        target = os.path.join(home, "wichtig")
        os.makedirs(target)
        open(os.path.join(target, "f.txt"), "w").write("x")
        os.symlink(target, os.path.join(home, (OLD + "-quarantaene-20210101-000000")))
        res = actions.run_action(self.r, self.w["site_rel"], "delete_quarantine",
                                 {"selected_pick": ["k:" + OLD + "-quarantaene-20210101-000000", "k:../wichtig", "k:" + OLD + "-quarantaene-1/../../wichtig", "f:./x"]}, [])
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.exists(os.path.join(target, "f.txt")))
        res = actions.run_action(self.r, self.w["site_rel"], "delete_quarantine", {"selected_pick": ["k:../wichtig"]}, [])
        self.assertFalse(res["ok"])
        self.assertIn("nichts verändert", res["error"])

    def test_catalog_knows_action(self):
        cat = {c["id"]: c for c in actions.catalog()}
        self.assertIn("delete_quarantine", cat)
        self.assertEqual(actions.sicherung_info("delete_quarantine")["art"], "keine")
        self.assertIn("rm -rf", cat["delete_quarantine"]["how"])


if __name__ == "__main__":
    unittest.main()
