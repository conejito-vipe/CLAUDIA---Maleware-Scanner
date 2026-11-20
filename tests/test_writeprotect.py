"""D5: Schreibschutz wird vor jeder Änderung erkannt (Ordner nicht beschreibbar): nichts wird verändert, klare Meldung."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402

# Als root gilt jeder Ordner als beschreibbar. Darum meldet `[ -w ... ]` hier für bestimmte Namen "nicht beschreibbar" (Bash-Funktion überlagert den Test).
PRE = ('[() { local a=("$@") neg="" r; if builtin test "${a[${#a[@]}-1]}" = "]"; then unset "a[${#a[@]}-1]"; fi; '
       'if builtin test "${a[0]}" = "!"; then neg=1; a=("${a[@]:1}"); fi; '
       'if builtin test "${a[0]}" = "-w"; then case "${a[1]}" in *roset*|images) r=1;; *) builtin test "${a[@]}"; r=$?;; esac; else builtin test "${a[@]}"; r=$?; fi; '
       'if builtin test -n "$neg"; then if builtin test $r -eq 0; then return 1; else return 0; fi; fi; return $r; }; ')


class Wrap:
    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, n):
        return getattr(self.inner, n)

    def sh(self, cwd, script, timeout=120, stdin=None):
        return self.inner.sh(cwd, PRE + script, timeout, stdin=stdin)


class ReadOnly(unittest.TestCase):
    def setUp(self):
        r, self.w = t2.world()
        self.r = Wrap(r)
        self.s = self.w["site"]

    def test_remove_shells_skips_files_in_protected_folders(self):
        os.makedirs(os.path.join(self.s, "roset"), exist_ok=True)
        open(os.path.join(self.s, "roset", "x.php"), "w").write("<?php eval(1);")
        open(os.path.join(self.s, "mac.php"), "w").write("<?php eval(2);")
        params = {"files": ["./roset/x.php", "./mac.php"], "images": False}
        res = actions.run_action(self.r, self.w["site_rel"], "remove_shells", params, [], allowed_files=params["files"])
        self.assertFalse(os.path.exists(os.path.join(self.s, "mac.php")))
        self.assertTrue(os.path.exists(os.path.join(self.s, "roset", "x.php")))
        self.assertEqual(res.get("readonly"), ["./roset/x.php"])

    def test_remove_shells_aborts_if_all_protected(self):
        os.makedirs(os.path.join(self.s, "roset"), exist_ok=True)
        open(os.path.join(self.s, "roset", "x.php"), "w").write("<?php eval(1);")
        params = {"files": ["./roset/x.php"], "images": False}
        res = actions.run_action(self.r, self.w["site_rel"], "remove_shells", params, [], allowed_files=params["files"])
        self.assertFalse(res["ok"])
        self.assertIn("nicht schreiben darf", res["error"])
        self.assertTrue(os.path.exists(os.path.join(self.s, "roset", "x.php")))
        self.assertFalse(res.get("backup_dir"))                      # nicht einmal eine Sicherung angelegt

    def test_block_php_stops_before_any_change(self):
        os.makedirs(os.path.join(self.s, "images"), exist_ok=True)
        ht = os.path.join(self.s, "images", ".htaccess")
        if os.path.lexists(ht):
            os.remove(ht)
        res = actions.run_action(self.r, self.w["site_rel"], "block_php_uploads", {"upload_dir": "images"}, [], context={"url": "https://example.org"})
        self.assertFalse(res["ok"])
        self.assertIn("schreibgeschützt", res["error"])
        self.assertFalse(os.path.exists(ht))

    def test_warning_mentions_file_watchers_only_for_file_actions(self):
        res = [{"id": "webshells", "findings": [{"sev": "crit", "title": "1 Datei(en) mit typischen Hintertür-Mustern", "items": ["./mac.php - 3:eval(base64_decode("]}]}]
        av = {a["id"]: a for a in actions.available(res, {"php": ""}, "8.3")}
        self.assertIn("Dateiwächter", av["remove_shells"]["warning"])
        self.assertNotIn("Dateiwächter", av.get("clear_cache", {"warning": ""})["warning"])


if __name__ == "__main__":
    unittest.main()
