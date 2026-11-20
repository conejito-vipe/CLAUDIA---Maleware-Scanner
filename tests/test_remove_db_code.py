"""2.4.0 / B7: Schadcode in der Datenbank entfernen: nur schädliche Skript-/Frame-Blöcke, Sicherung des alten Werts, Sonderfälle."""
import json
import os
import re
import sqlite3
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402

BAD_SCRIPT = "<script>var _0x4f2a=['x'];eval(atob('ZXZpbA=='));</script>"
EVIL_HOST = '<script src="https://evil-cdn.example/x.js"></script>'
GOOD = '<p>Hallo</p><script src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEFGH12"></script>'
HIDDEN = '<iframe src="https://spam.example/" style="display:none"></iframe>'


class Clean(unittest.TestCase):
    def test_removes_only_flagged_blocks(self):
        r = actions.dbcode_clean("<p>Text</p>" + BAD_SCRIPT + GOOD + EVIL_HOST + HIDDEN + "<p>Ende</p>", "x.example", ["googletagmanager.com"], [])
        self.assertEqual(len(r["removed"]), 3)
        self.assertIn("<p>Text</p>", r["new"])
        self.assertIn("googletagmanager", r["new"])
        self.assertNotIn("evil-cdn", r["new"])
        self.assertNotIn("_0x4f2a", r["new"])
        self.assertNotIn("spam.example", r["new"])
        self.assertTrue(r["new"].endswith("<p>Ende</p>"))

    def test_nothing_clear_means_skip(self):
        r = actions.dbcode_clean("<p>Hallo</p><script>console.log(1)</script>", "x.example", [], [])
        self.assertTrue(r["skip"])
        self.assertEqual(r["new"], "<p>Hallo</p><script>console.log(1)</script>")

    def test_ioc_string_is_flagged(self):
        r = actions.dbcode_clean("<script>window.MARKER_XYZ=1</script>", "x.example", [], ["MARKER_XYZ"])
        self.assertEqual(len(r["removed"]), 1)

    def test_serialized_php_is_refused(self):
        r = actions.dbcode_clean('a:1:{s:4:"text";s:30:"<script>eval(1)</script>";}', "x.example", [], [])
        self.assertIn("serialisiert", r["skip"])

    def test_json_params_are_cleaned_as_json(self):
        orig = json.dumps({"customcode": "<p>a</p>" + BAD_SCRIPT, "n": 3, "ü": "x"}, separators=(",", ":")).replace("/", "\\/")
        r = actions.dbcode_clean(orig, "x.example", [], [])
        obj = json.loads(r["new"])
        self.assertEqual(obj["customcode"], "<p>a</p>")
        self.assertEqual(obj["n"], 3)
        self.assertIn("\\/", orig)
        self.assertNotIn("_0x", r["new"])

    def test_leftover_is_reported(self):
        r = actions.dbcode_clean(BAD_SCRIPT + " und eval(foo) im Text", "x.example", [], [])
        self.assertTrue(r["leftover"])


class Run(unittest.TestCase):
    def setUp(self):
        self.r, self.w = t2.world()
        self.db = self.w["db"]
        con = sqlite3.connect(self.db)
        self.mod = "<p>Willkommen</p>" + BAD_SCRIPT + "<p>Ende</p>"
        con.execute("INSERT INTO j_modules (id, title, module, content, params, published) VALUES (801, 'Evil', 'mod_custom', ?, '{}', 1)", (self.mod,))
        con.execute("INSERT INTO j_content (id, title, introtext, `fulltext`, state) VALUES (802, 'Clean', '<p>nur Text</p>', '', 1)")
        con.commit()
        con.close()
        self.base = {"cms": "joomla", "own_host": "x.example", "allow": [], "ioc": []}

    def val(self, table, col, rid, idc="id"):
        con = sqlite3.connect(self.db)
        v = con.execute("SELECT `%s` FROM %s WHERE %s = ?" % (col, table, idc), (rid,)).fetchone()[0]
        con.close()
        return v

    def go(self, keys, **kw):
        params = dict(self.base, selected_pick=list(keys), **kw)
        return actions.run_action(self.r, self.w["site_rel"], "remove_db_code", params, [])

    def test_removes_block_and_backs_up_old_value(self):
        res = self.go(["x:modules.content:801"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.val("j_modules", "content", 801), "<p>Willkommen</p><p>Ende</p>")
        bk = os.path.join(self.w["home"], os.path.basename(res["backup_dir"]))
        sql = open(os.path.join(bk, "rueckgaengig.sql")).read()
        self.assertIn("UPDATE `j_modules` SET `content` = UNHEX('", sql)
        self.assertIn(self.mod.encode().hex().upper(), sql)
        # Rückgängig: der gesicherte Befehl stellt den alten Wert wieder her
        con = sqlite3.connect(self.db)
        for line in sql.splitlines():
            if line.startswith("UPDATE"):
                con.create_function("UNHEX", 1, lambda h: bytes.fromhex(h).decode("utf-8"))
                con.execute(line)
        con.commit()
        con.close()
        self.assertEqual(self.val("j_modules", "content", 801), self.mod)

    def test_nothing_to_remove_changes_nothing_and_no_backup(self):
        res = self.go(["x:content.introtext:802"])
        self.assertTrue(res["ok"])
        self.assertFalse(res.get("backup_dir"))
        self.assertEqual(self.val("j_content", "introtext", 802), "<p>nur Text</p>")

    def test_invalid_keys_are_refused(self):
        for bad in ("x:users.password:1", "x:modules.content:1;DROP", "x:modules.title:801", "x:modules.content:abc"):
            res = self.go([bad])
            self.assertFalse(res["ok"], bad)
            self.assertEqual(self.val("j_modules", "content", 801), self.mod)

    def test_preview_is_read_only(self):
        p = actions.dbcode_preview(self.r, self.w["site_rel"], dict(self.base, selected_pick=["x:modules.content:801"]))
        self.assertEqual(self.val("j_modules", "content", 801), self.mod)
        it = p["items"][0]
        self.assertEqual(len(it["removed"]), 1)
        self.assertLess(it["size_new"], it["size_old"])

    def test_backup_failure_aborts_before_change(self):
        orig = actions._mkdir_backup
        actions._mkdir_backup = lambda r, s, label: "/nonexistent/dir"
        try:
            res = self.go(["x:modules.content:801"])
        finally:
            actions._mkdir_backup = orig
        self.assertFalse(res["ok"])
        self.assertEqual(self.val("j_modules", "content", 801), self.mod)

    def test_available_builds_pick_from_findings(self):
        items = ["modules #801 'Evil' (content): " + BAD_SCRIPT[:60] + "  -> verschleierter Code", "content #1 'X' (hits): foo", "users #5 'x' (password): y"]
        res = [{"id": "db_content", "title": "t", "findings": [{"sev": "crit", "title": "1 Fund(e) mit verdächtigem Code in der Datenbank", "items": items}]}]
        out = actions.available(res, {"joomla": "5.0.0"}, scan={})
        acts = out["actions"] if isinstance(out, dict) else out
        a = [x for x in acts if x["id"] == "remove_db_code"][0]
        self.assertEqual([c["key"] for c in a["params"]["pick"]], ["x:modules.content:801"])
        self.assertFalse(a["params"]["pick"][0]["pre"])


if __name__ == "__main__":
    unittest.main()


class ManualSql(unittest.TestCase):
    """B7 Teil 1: Auch bei funktionierendem Datenbankzugriff liefert der Bericht Abfragen zu den DB-Funden (phpmyadmin_abfragen.sql)."""

    def test_content_finding_adds_select_to_sql_file(self):
        import tempfile
        import threading
        import fixture
        from claudia import report
        from claudia.engine import Engine, Settings
        from claudia.registry import load_all
        from claudia.runner import LocalRunner
        from test_checks import ADV
        load_all()
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_b7s_"), False)
        con = sqlite3.connect(w["db"])
        con.execute("INSERT INTO j_modules (id, title, module, content, params, published) VALUES (901, 'Evil', 'mod_custom', ?, '{}', 1)", (BAD_SCRIPT,))
        con.commit()
        con.close()
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="https://x.example", log_dir="logs", opts={}, allow_hosts=[]), ADV)
        results = eng.run(["db_content"], lambda e: None, threading.Event())
        raw = (results[0].raw or {}).get("sql_manuell", "")
        self.assertIn("SELECT `id`, `content` FROM j_modules WHERE `id` = 901", raw)
        self.assertIn("-- Fund: Eingeschleuster Code in der Datenbank", raw)
        self.assertTrue(any(f.sev == "crit" for f in results[0].findings))
