"""Verbindungstest: PHP-Version und Datenbank-Programm, auch wenn 'php -v' auf dem Server hängt."""
import os
import stat
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixture  # noqa: E402
import phpshadow  # noqa: E402
from claudia import probe  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def runner_with(fakes):
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_p_"), False)
    extra = tempfile.mkdtemp(prefix="claudia_bin_")
    for name, body in fakes.items():
        script(os.path.join(extra, name), body)
    phpshadow.shadow_real_php(extra, keep=tuple(fakes))  # echtes PHP des Testrechners ausblenden
    return LocalRunner(w["home"], extra_path=extra + os.pathsep + w["bin"]), w


class Probe(unittest.TestCase):
    def test_hanging_php_does_not_block_and_candidate_wins(self):
        r, w = runner_with({"php": "sleep 100", "php8.3": 'echo "PHP 8.3.6 (cli) (built: x)"'})
        t0 = time.time()
        info = probe.probe(r, w["site_rel"])
        took = time.time() - t0
        self.assertLess(took, 20, "Test darf nicht an php -v hängen bleiben (%.1f s)" % took)
        self.assertEqual(info["php"], "PHP 8.3.6")
        self.assertEqual(info["php_source"], "php8.3")
        self.assertTrue(info["mysql"], "mysql-Shim muss gefunden werden")
        self.assertTrue(info["mysql_path"])
        self.assertEqual(info["joomla"], "6.2.0")
        self.assertTrue(info["site_found"])

    def test_several_versions_are_not_guessed(self):
        # wie bei hosting.de: 'php' antwortet nicht, php-8.5/8.4/8.3 sind da. Die Webseite kann eine beliebige davon nutzen.
        r, w = runner_with({"php": "sleep 100", "php8.5": 'echo "PHP 8.5.12 (cli)"', "php8.4": 'echo "PHP 8.4.27 (cli)"',
                            "php8.3": 'echo "PHP 8.3.36 (cli)"'})
        info = probe.probe(r, w["site_rel"])
        self.assertEqual(info["php"], "", "bei mehreren Versionen darf nicht die höchste als 'die' Version ausgegeben werden")
        self.assertEqual(info["php_installed"], ["PHP 8.5.12", "PHP 8.4.27", "PHP 8.3.36"])
        self.assertIn("mehrere PHP-Versionen", info["php_note"])
        self.assertIn("8.3.36", info["php_note"])

    def test_hanging_php_without_candidates_gives_note(self):
        # alle versionierten Programme überdecken (die Testumgebung hat selbst ein echtes php8.3)
        fakes = {"php": "sleep 100"}
        fakes.update({"php" + v: "sleep 100" for v in ("8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4")})
        r, w = runner_with(fakes)
        t0 = time.time()
        info = probe.probe(r, w["site_rel"])
        self.assertLess(time.time() - t0, 30, "Zeitgrenzen müssen greifen")
        self.assertEqual(info["php"], "")
        self.assertIn("5 Sekunden", info["php_note"])
        self.assertTrue(info["mysql"])           # darf nicht vom hängenden php abhängen
        self.assertEqual(info["joomla"], "6.2.0")

    def test_working_php(self):
        r, w = runner_with({"php": 'echo "PHP 8.3.14 (cli) (built: x)"'})
        info = probe.probe(r, w["site_rel"])
        self.assertEqual(info["php"], "PHP 8.3.14")
        self.assertEqual(info["php_source"], "php")
        self.assertEqual(info["php_note"], "")

    def test_wrong_folder_lists_folders(self):
        r, w = runner_with({})
        info = probe.probe(r, "gibt/es/nicht")
        self.assertFalse(info["site_found"])
        self.assertIn("existiert nicht", info.get("error", ""))
        self.assertIn("html", info["folders"])

    def test_progress_and_deadline_callbacks(self):
        r, w = runner_with({"php": 'echo "PHP 8.3.1 (cli)"'})
        seen = []
        probe.probe(r, w["site_rel"], lambda sid, msg: seen.append(sid), time.monotonic() + 30)
        self.assertEqual(seen, ["folder", "joomla", "db", "php"])


if __name__ == "__main__":
    unittest.main()
