"""Sicherungen: Angabe je Aktion, Schutz im öffentlichen Bereich, MANIFEST.txt, Cluster in beiden Systemen."""
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from claudia import actions, registry  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.actions import OLD_ID as OLD  # noqa: E402  (Kennung früherer Versionen)


class Table(unittest.TestCase):
    def test_every_action_declares_backup_kind(self):
        for aid, a in actions.ACTIONS.items():
            art, text = actions.SICHERUNG[aid]
            self.assertIn(art, ("voll", "gezielt", "protokoll", "keine"), aid)
            self.assertTrue(text.strip(), aid)
            self.assertEqual(bool(a["backup"]), art == "voll", aid)          # 'backup' = volle Sicherung, alles andere ist eine eigene Angabe
        self.assertEqual(set(actions.SICHERUNG), set(actions.ACTIONS))

    def test_catalog_and_list_carry_it(self):
        for item in actions.catalog():
            self.assertEqual(item["backup"], actions.sicherung_info(item["id"])["text"])

    def test_clusters_for_both_systems(self):
        known = set(registry.CLUSTERS)
        for cms in ("joomla", "wordpress"):
            for c in registry.ordered(cms):
                k = c.public(cms)["cluster"]
                self.assertIn(k, known, (cms, c.id))
        for d in registry.cluster_title_defs("wordpress"):
            self.assertNotIn("Joomla", d["title"] + d["text"], d["id"])

    def test_name_pattern_accepts_random_part(self):
        self.assertTrue(actions.BACKUP_NAME_RE.match((OLD + "-sicherung-20250101-000000-ab12cd34")))
        self.assertTrue(actions.BACKUP_NAME_RE.match((OLD + "-sicherung-tmp-20250101-000000")))
        self.assertFalse(actions.BACKUP_NAME_RE.match((OLD + "-sicherung-20250101-000000-XYZ")))


class Location(unittest.TestCase):
    def make(self, home_is_site: bool):
        base = tempfile.mkdtemp(prefix="claudia_home_")
        site = base if home_is_site else os.path.join(base, "public_html")
        os.makedirs(site, exist_ok=True)
        return LocalRunner(base), base, site

    def traced(self, runner, aid="clean_tmp"):
        t = actions.Traced(runner, lambda k, x: None)
        t.meta = {"aid": aid, "title": actions.ACTIONS[aid]["title"], "befund": "kritisch: 2, Warnung: 1"}
        return t

    def test_outside_webroot_plain_name_and_manifest(self):
        r, base, site = self.make(False)
        out = actions._mkdir_backup(self.traced(r), site, "tmp")
        self.assertTrue(re.search(r"claudia-sicherung-tmp-\d{8}-\d{6}$", out), out)
        self.assertFalse(os.path.exists(os.path.join(out, ".htaccess")))
        txt = open(os.path.join(out, "MANIFEST.txt"), encoding="utf-8").read()
        for want in ("CLAUDIA", "Zeitpunkt", "Temp-Ordner", "kritisch: 2, Warnung: 1", "Schadcode", "Gezielt"):
            self.assertIn(want, txt)
        self.assertNotIn("ACHTUNG", txt)
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o700")

    def test_inside_webroot_protected(self):
        r, base, site = self.make(True)
        t = self.traced(r)
        out = actions._mkdir_backup(t, site, "tmp")
        self.assertRegex(out, r"claudia-sicherung-tmp-\d{8}-\d{6}-[0-9a-f]{8}$")
        ht = open(os.path.join(out, ".htaccess"), encoding="utf-8").read()
        self.assertIn("Require all denied", ht)
        self.assertIn("Deny from all", ht)
        self.assertTrue(os.path.exists(os.path.join(out, "index.html")))
        self.assertIn("ACHTUNG", open(os.path.join(out, "MANIFEST.txt"), encoding="utf-8").read())
        self.assertTrue(t.notes and "öffentlich" in t.notes[0])
        self.assertTrue(actions.BACKUP_NAME_RE.match(os.path.basename(out)))

    def test_listing_marks_malware_content(self):
        txt = "@@BACKUPS\n%s-sicherung-20250101-000000\t1\t5\tdb.sql.gz,\n%s-sicherung-wpconfig-20250101-000001\t2\t1\tx,\n@@END\n" % (OLD, OLD)
        res = actions.parse_scan(txt)
        flags = {b["name"]: b["malware"] for b in res["backups"]}
        self.assertTrue(flags[(OLD + "-sicherung-20250101-000000")])
        self.assertFalse(flags[(OLD + "-sicherung-wpconfig-20250101-000001")])


if __name__ == "__main__":
    unittest.main()
