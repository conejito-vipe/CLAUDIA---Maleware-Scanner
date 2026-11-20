"""2.4.0 / A8: PHP-Code in Nicht-PHP-Dateien (Bildkopf, include auf Bild-/Textdateien) in der Prüfung 'webshells'."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from test_checks import ADV, has, titles  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


def run_webshells(extra):
    load_all()
    base = tempfile.mkdtemp(prefix="claudia_a8_")
    w = fixture.make_world(base, False)
    for rel, data in extra.items():
        p = os.path.join(w["site"], rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="", log_dir="logs", opts={}, allow_hosts=[]), ADV)
    return {r.id: r for r in eng.run(["webshells"], lambda e: None, threading.Event())}["webshells"]


class A8(unittest.TestCase):
    def test_clean_site_has_no_a8_findings(self):
        r = run_webshells({"components/com_x/ok.php": "<?php\ninclude 'header.php';\nrequire_once __DIR__ . '/lib.php';\n$t = file_get_contents('license.txt');\necho $t;\n",
                           "components/com_x/tpl.php": "<?php include 'a.php' ?><img src=\"logo.png\"><?php echo 1;",
                           "images/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00binary"})
        self.assertFalse(has(r, "Bildkopf"), titles(r))
        self.assertFalse(has(r, "Bilddateien"), titles(r))
        self.assertFalse(has(r, "Text-/Datendateien"), titles(r))
        self.assertTrue(has(r, "Keine Hintertür-Muster", "ok"), titles(r))

    def test_image_header_with_php_code_is_critical(self):
        r = run_webshells({"images/cache.php": b"GIF89a\n<?php echo 1; ?>", "media/x.php": b"\x89PNG\r\n<?php echo 2;",
                           "tmp/y.php": b"\xff\xd8\xff\xe0JFIF<?= 3 ?>", "images/real.gif": b"GIF89a\x01\x00\x01\x00"})
        f = [x for x in r.findings if "Bildkopf" in x.title]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].sev, "crit")
        text = " ".join(f[0].items)
        self.assertIn("cache.php", text)
        self.assertIn("x.php", text)
        self.assertIn("y.php", text)
        self.assertIn("3 PHP-Datei", f[0].title)
        self.assertNotIn("real.gif", text)                 # echtes Bild ohne PHP bleibt unauffällig

    def test_include_of_image_is_critical_text_is_warning(self):
        r = run_webshells({"components/com_x/loader.php": "<?php\n@include('../../images/favicon.ico');\n",
                           "components/com_x/l2.php": "<?php\neval(file_get_contents('x.jpg'));\n",
                           "components/com_x/l3.php": "<?php\nrequire_once $dir . '/data.log';\n"})
        crit = [x for x in r.findings if "Bilddateien" in x.title]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].sev, "crit")
        self.assertIn("loader.php", " ".join(crit[0].items))
        self.assertIn("l2.php", " ".join(crit[0].items))
        warn = [x for x in r.findings if "Text-/Datendateien" in x.title]
        self.assertEqual(len(warn), 1)
        self.assertEqual(warn[0].sev, "warn")
        self.assertIn("l3.php", " ".join(warn[0].items))
        self.assertIn("Zeile 2", " ".join(crit[0].items))

    def test_big_files_and_libraries_are_skipped(self):
        big = "<?php\ninclude 'x.png';\n" + "// " + "a" * (2100 * 1024)
        r = run_webshells({"components/com_x/big.php": big, "libraries/vendor/lib/a.php": "<?php include 'x.png';"})
        self.assertFalse(has(r, "Bilddateien"), titles(r))


if __name__ == "__main__":
    unittest.main()
