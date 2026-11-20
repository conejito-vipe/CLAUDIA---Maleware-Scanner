"""2.3.2: Quarantäne mit Verschieben (statt Löschen) und Rückholen. Sonderfälle: Namensgleichheit, Verweise, anderes Dateisystem, belegter Ursprungsort,
veränderte Prüfsumme, fehlender Ordner, Home-Verzeichnis im Web-Ordner."""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


def put(site, rel, text="<?php eval(1);", mode=0o644):
    p = os.path.join(site, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    os.chmod(p, mode)
    return p


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def move(r, w, files, **kw):
    params = {"files": files, "images": False, "selected_pick": ["f:" + f for f in files]}
    return actions.run_action(r, w["site_rel"], "remove_shells", params, [], allowed_files=files, **kw)


def keys_of(r, w):
    sc = actions.scan_server(r, w["site_rel"])
    return sc, ["q:%s/%s" % (q["name"], e["id"]) for q in sc["quarantines"] for e in q["entries"]]


def restore(r, w, keys):
    return actions.run_action(r, w["site_rel"], "restore_quarantine", {"selected_pick": list(keys)}, [])


class Move(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]

    def test_moves_instead_of_deleting_with_list_and_rights(self):
        src = put(self.s, "images/a.php", "<?php system($_GET[1]);", 0o755)
        want = sha(src)
        res = move(self.r, self.w, ["./images/a.php"])
        self.assertTrue(res["ok"], res)
        q = res["backup_dir"]
        self.assertTrue(os.path.basename(q).startswith("claudia-quarantaene-"))
        self.assertFalse(os.path.exists(src))                                        # Ursprung leer
        self.assertEqual(os.listdir(os.path.join(q, "d")), ["0001.q"])                 # nichts gelöscht: Datei liegt in der Quarantäne
        held = os.path.join(q, "d", "0001.q")
        self.assertEqual(sha(held), want)
        self.assertEqual(os.stat(held).st_mode & 0o777, 0o600)                         # ohne Ausführrecht
        self.assertEqual(os.stat(q).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(q, "d")).st_mode & 0o777, 0o700)
        self.assertTrue(q.startswith(self.w["home"] + "/"))                           # außerhalb des Seitenordners
        self.assertFalse(q.startswith(self.s))
        rows = [l.split("\t") for l in open(os.path.join(q, "QUARANTAENE.txt"), encoding="utf-8").read().splitlines() if l and not l.startswith("#")]
        self.assertEqual(len(rows), 1)
        nr, h, size, mode, owner, mt, origin = rows[0]
        self.assertEqual((nr, h, size, mode, origin), ("0001", want, str(len("<?php system($_GET[1]);")), "755", "./images/a.php"))
        self.assertIn(":", owner)
        self.assertIn("# Seitenordner: " + os.path.realpath(self.s), open(os.path.join(q, "QUARANTAENE.txt"), encoding="utf-8").read())
        self.assertTrue(os.path.exists(os.path.join(q, ".htaccess")))

    def test_same_names_from_different_folders_stay_distinct(self):
        put(self.s, "images/a/x.php", "<?php 1;")
        put(self.s, "images/b/x.php", "<?php 2;")
        res = move(self.r, self.w, ["./images/a/x.php", "./images/b/x.php"])
        self.assertTrue(res["ok"], res)
        d = os.path.join(res["backup_dir"], "d")
        self.assertEqual(sorted(os.listdir(d)), ["0001.q", "0002.q"])
        self.assertEqual({open(os.path.join(d, f)).read() for f in os.listdir(d)}, {"<?php 1;", "<?php 2;"})

    def test_two_runs_in_the_same_second_get_separate_folders(self):
        put(self.s, "images/a.php", "<?php 1;")
        put(self.s, "images/b.php", "<?php 2;")
        r1 = move(self.r, self.w, ["./images/a.php"])
        r2 = move(self.r, self.w, ["./images/b.php"])
        self.assertTrue(r1["ok"] and r2["ok"])
        self.assertNotEqual(r1["backup_dir"], r2["backup_dir"])
        self.assertEqual(len(os.listdir(os.path.join(r1["backup_dir"], "d"))), 1)

    def test_symlinks_are_skipped_and_nothing_outside_changes(self):
        outside = tempfile.mkdtemp(prefix="claudia_out_")
        evil = os.path.join(outside, "evil.php")
        open(evil, "w").write("<?php 9;")
        os.symlink(outside, os.path.join(self.s, "images_link"))                      # Ordner-Verweis aus der Seite hinaus
        os.symlink(evil, os.path.join(self.s, "images", "l.php")) if os.path.isdir(os.path.join(self.s, "images")) else None
        put(self.s, "images/ok.php", "<?php 1;")
        res = move(self.r, self.w, ["./images_link/evil.php", "./images/l.php", "./images/ok.php"])
        self.assertTrue(os.path.exists(evil))                                          # außerhalb unangetastet
        self.assertEqual(open(evil).read(), "<?php 9;")
        self.assertTrue(os.path.islink(os.path.join(self.s, "images_link")))
        self.assertFalse(res["ok"])                                                    # nicht alles verschoben
        self.assertEqual(res["quarantine"]["moved"], ["./images/ok.php"])
        self.assertIn("./images_link/evil.php", res["error"])
        self.assertEqual(len(os.listdir(os.path.join(res["backup_dir"], "d"))), 1)

    def test_only_skipped_files_means_no_change_and_no_empty_folder(self):
        outside = tempfile.mkdtemp(prefix="claudia_out_")
        open(os.path.join(outside, "evil.php"), "w").write("<?php 9;")
        os.symlink(outside, os.path.join(self.s, "images_link"))
        before = set(os.listdir(self.w["home"]))
        res = move(self.r, self.w, ["./images_link/evil.php"])
        self.assertFalse(res["ok"])
        self.assertFalse(res.get("backup_dir"))
        self.assertEqual({n for n in os.listdir(self.w["home"]) if n.startswith("claudia-quarantaene")}, {n for n in before if n.startswith("claudia-quarantaene")})

    def test_other_file_system_copies_verifies_then_removes_original(self):
        if not os.path.isdir("/dev/shm") or os.stat("/dev/shm").st_dev == os.stat(self.s).st_dev:
            self.skipTest("kein zweites Dateisystem verfügbar")
        shm = tempfile.mkdtemp(prefix="claudia_shm_", dir="/dev/shm")
        self.addCleanup(shutil.rmtree, shm, True)
        r2 = LocalRunner(shm)
        src = put(self.s, "images/a.php", "<?php 3;", 0o644)
        res = actions.run_action(r2, os.path.abspath(self.s), "remove_shells", {"files": ["./images/a.php"], "images": False, "selected_pick": ["f:./images/a.php"]}, [], allowed_files=["./images/a.php"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["backup_dir"].startswith(shm))
        self.assertFalse(os.path.exists(src))
        held = os.path.join(res["backup_dir"], "d", "0001.q")
        self.assertEqual(open(held).read(), "<?php 3;")
        self.assertEqual(os.stat(held).st_mode & 0o777, 0o600)
        # Rückholen über das Dateisystem hinweg
        sc = actions.scan_server(r2, os.path.abspath(self.s))
        ks = ["q:%s/%s" % (q["name"], e["id"]) for q in sc["quarantines"] for e in q["entries"]]
        res = actions.run_action(r2, os.path.abspath(self.s), "restore_quarantine", {"selected_pick": ks}, [])
        self.assertTrue(res["ok"], res)
        self.assertEqual(open(src).read(), "<?php 3;")
        self.assertFalse(os.path.exists(held))

    def test_hardlink_gets_a_note(self):
        a = put(self.s, "images/a.php", "<?php 4;")
        os.link(a, os.path.join(self.s, "images", "a2.php"))
        res = move(self.r, self.w, ["./images/a.php"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(any("Hardlinks" in s["output"] for s in res["steps"]), res["steps"])
        self.assertTrue(os.path.exists(os.path.join(self.s, "images", "a2.php")))     # der andere Name bleibt, der Hinweis nennt ihn

    def test_home_inside_site_folder_aborts_without_change(self):
        a = put(self.s, "images/a.php", "<?php 5;")
        r2 = LocalRunner(self.s)                                                       # Home = Seitenordner = Web-Ordner
        res = actions.run_action(r2, ".", "remove_shells", {"files": ["./images/a.php"], "images": False, "selected_pick": ["f:./images/a.php"]}, [], allowed_files=["./images/a.php"])
        self.assertFalse(res["ok"])
        self.assertIn("nichts verändert", res["error"])
        self.assertTrue(os.path.exists(a))
        self.assertEqual([n for n in os.listdir(self.s) if n.startswith("claudia-quarantaene")], [])


class Restore(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.s = self.w["site"]
        self.a = put(self.s, "images/a.php", "<?php 1;", 0o640)
        self.b = put(self.s, "images/b.php", "<?php 2;", 0o664)
        res = move(self.r, self.w, ["./images/a.php", "./images/b.php"])
        self.assertTrue(res["ok"], res)
        self.q = res["backup_dir"]
        self.sc, self.keys = keys_of(self.r, self.w)

    def test_scan_lists_entries_and_offers_action_unselected(self):
        q = self.sc["quarantines"][0]
        self.assertEqual([e["origin"] for e in q["entries"]], ["./images/a.php", "./images/b.php"])
        self.assertEqual([e["state"] for e in q["entries"]], ["frei", "frei"])
        self.assertEqual(q["entries"][0]["mode"], "640")
        a = [x for x in actions.available([], {"cms": "joomla"}, "8.3", scan=self.sc) if x["id"] == "restore_quarantine"]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["risk"], "hoch")
        self.assertTrue(all(not x["pre"] for x in a[0]["params"]["pick"]))            # nichts vorausgewählt
        self.assertEqual([x["key"] for x in a[0]["params"]["pick"]], self.keys)
        self.assertFalse([x for x in actions.available([], {"cms": "joomla"}, "8.3", scan={}) if x["id"] == "restore_quarantine"])

    def test_restore_puts_files_back_with_original_rights_and_log(self):
        res = restore(self.r, self.w, self.keys)
        self.assertTrue(res["ok"], res)
        self.assertEqual(open(self.a).read(), "<?php 1;")
        self.assertEqual(os.stat(self.a).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(self.b).st_mode & 0o777, 0o664)
        self.assertEqual(os.listdir(os.path.join(self.q, "d")), [])
        log = open(os.path.join(self.q, "ZURUECK.txt"), encoding="utf-8").read()
        self.assertIn("./images/a.php", log)
        self.assertEqual(actions.scan_server(self.r, self.w["site_rel"])["quarantines"], [])     # nichts mehr zurückholbar

    def test_occupied_origin_is_skipped_per_file_and_never_overwritten(self):
        open(self.a, "w").write("NEU eigene Datei")
        os.symlink("/nonexistent", self.b)                                              # auch ein (hängender) Verweis zählt als belegt
        sc, keys = keys_of(self.r, self.w)
        self.assertEqual([e["state"] for e in sc["quarantines"][0]["entries"]], ["belegt", "belegt"])
        pv = actions.commands_preview("restore_quarantine", {"quarantines": sc["quarantines"], "selected_pick": keys}, [])
        self.assertEqual(sum("wird übersprungen" in l for l in pv), 2)
        res = restore(self.r, self.w, keys)
        self.assertFalse(res["ok"])
        self.assertEqual(open(self.a).read(), "NEU eigene Datei")
        self.assertTrue(os.path.islink(self.b))
        self.assertEqual(sorted(os.listdir(os.path.join(self.q, "d"))), ["0001.q", "0002.q"])    # bleibt in der Quarantäne
        self.assertIn("nichts wird überschrieben", res["error"])

    def test_one_occupied_one_free_restores_only_the_free_one(self):
        open(self.a, "w").write("belegt")
        res = restore(self.r, self.w, self.keys)
        self.assertFalse(res["ok"])
        self.assertEqual(res["restored"], ["./images/b.php"])
        self.assertEqual(open(self.b).read(), "<?php 2;")
        self.assertEqual(os.listdir(os.path.join(self.q, "d")), ["0001.q"])

    def test_changed_checksum_blocks_restore(self):
        open(os.path.join(self.q, "d", "0001.q"), "a").write("# manipuliert")
        res = restore(self.r, self.w, [self.keys[0]])
        self.assertFalse(res["ok"])
        self.assertIn("Prüfsumme weicht", res["error"])
        self.assertFalse(os.path.exists(self.a))

    def test_missing_origin_folder_is_not_created(self):
        shutil.rmtree(os.path.join(self.s, "images"))
        res = restore(self.r, self.w, self.keys)
        self.assertFalse(res["ok"])
        self.assertIn("wird nicht neu angelegt", res["error"])
        self.assertFalse(os.path.exists(os.path.join(self.s, "images")))

    def test_tampered_list_cannot_point_outside_the_site(self):
        lst = os.path.join(self.q, "QUARANTAENE.txt")
        txt = open(lst, encoding="utf-8").read().replace("\t./images/a.php", "\t./../evil.php")
        open(lst, "w", encoding="utf-8").write(txt)
        res = restore(self.r, self.w, [self.keys[0]])
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.s), "evil.php")))
        self.assertIn("ungültiger Ursprungspfad", res["error"])

    def test_list_of_another_site_is_refused(self):
        lst = os.path.join(self.q, "QUARANTAENE.txt")
        txt = open(lst, encoding="utf-8").read()
        open(lst, "w", encoding="utf-8").write(txt.replace("# Seitenordner: ", "# Seitenordner: /anderswo"))
        res = restore(self.r, self.w, [self.keys[0]])
        self.assertFalse(res["ok"])
        self.assertIn("anderen Seite", res["error"])
        self.assertEqual(actions.scan_server(self.r, self.w["site_rel"])["quarantines"], [])    # fremde Quarantäne wird nicht angeboten

    def test_invalid_keys_are_ignored_and_empty_selection_changes_nothing(self):
        res = actions.run_action(self.r, self.w["site_rel"], "restore_quarantine", {"selected_pick": ["q:../../etc/0001", "q:" + OLD + "-quarantaene-1/0001", "f:./x.php"]}, [])
        self.assertFalse(res["ok"])
        self.assertIn("nichts verändert", res["error"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.q, "d"))), ["0001.q", "0002.q"])

    def test_preview_lists_commands_without_running_them(self):
        pv = actions.commands_preview("restore_quarantine", {"quarantines": self.sc["quarantines"], "selected_pick": self.keys}, [])
        self.assertTrue(any(l.startswith("mv -n -- ~/%s/d/0001.q ./images/a.php" % os.path.basename(self.q)) for l in pv))
        self.assertTrue(any("chmod 640 ./images/a.php" in l for l in pv))
        self.assertTrue(any("Ursprungsort leer" in l for l in pv))
        self.assertFalse(os.path.exists(self.a))                                       # Vorschau ändert nichts


class Catalog(unittest.TestCase):
    def test_catalog_plan_and_recheck_know_the_new_action(self):
        ids = [c["id"] for c in actions.catalog()]
        self.assertIn("restore_quarantine", ids)
        cat = {c["id"]: c for c in actions.catalog()}
        self.assertIn("mv -n", cat["restore_quarantine"]["how"])
        self.assertIn("mv -n", cat["remove_shells"]["how"])
        self.assertNotIn("rm -f", cat["remove_shells"]["how"])
        self.assertIn("restore_quarantine", actions.RECHECK)
        self.assertEqual(actions.sicherung_info("restore_quarantine")["art"], "protokoll")
        acts = [{"id": "restore_quarantine", "title": "x", "why": "", "hidden": False}]
        self.assertEqual([p for p in actions.build_plan(acts, []) if p.get("id") == "restore_quarantine"], [])    # kein nummerierter Schritt der Reihenfolge


if __name__ == "__main__":
    unittest.main()
