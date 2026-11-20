"""2.4.1 Joomla-Kern: Entwicklungsdateien von Bibliotheken im Ordner vendor (z. B. .php-cs-fixer.dist.php) sind kein Einbruchszeichen,
solange Name, Ort UND Inhalt unauffällig sind. Beispiel aus einem echten Bericht (Joomla 6.2.0: php-sequence-matcher, php-diff, phpmailer)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia.checks import joomla_core  # noqa: E402
from test_joomla_core import Env, sha, titles  # noqa: E402

VENDOR = "libraries/vendor/jfcherng/php-sequence-matcher"
FIXER = "<?php\n\n$finder = PhpCsFixer\\Finder::create()->in(__DIR__);\nreturn (new PhpCsFixer\\Config())->setRules(['@PSR12' => true]);\n"
OAUTH = "<?php\nrequire 'vendor/autoload.php';\nsession_start();\nif (!isset($_GET['code'])) { header('Location: ' . $url); exit; }\n$token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);\n"


def add_vendor(e, files):
    """Legt Dateien auf dem Server an; die Bibliothek (mit einer Paketdatei) steht im Original, die übrigen Dateien nicht."""
    for pkg in (VENDOR + "/src/Differ.php", VENDOR + "/LICENSE", "libraries/vendor/phpmailer/phpmailer/LICENSE", "libraries/vendor/phpmailer/phpmailer/src/PHPMailer.php"):
        os.makedirs(os.path.dirname(e.path(pkg)), exist_ok=True)
        with open(e.path(pkg), "w") as fh:
            fh.write("Bibliothek\n")
        e.ref["files"][pkg] = sha(b"Bibliothek\n")
    for rel, text in files.items():
        os.makedirs(os.path.dirname(e.path(rel)), exist_ok=True)
        with open(e.path(rel), "w") as fh:
            fh.write(text)


class VendorDev(unittest.TestCase):
    def test_pattern_needs_name_and_place(self):
        for ok in (VENDOR + "/.php-cs-fixer.dist.php", "libraries/vendor/phpmailer/phpmailer/get_oauth_token.php", "libraries/vendor/jfcherng/php-color-output/demo.php",
                   "libraries/vendor/a/b/examples/x.php"):
            self.assertTrue(joomla_core.is_vendor_dev(ok), ok)
        for bad in ("layouts/joomla/demo.php", "libraries/vendor/a/b/src/evil.php", "libraries/vendor/a/demo.php", "plugins/system/x/.php-cs-fixer.dist.php",
                    "libraries/vendor/a/b/c/d/demo.php", "libraries/vendor/a/b/demo.php.txt"):
            self.assertFalse(joomla_core.is_vendor_dev(bad), bad)

    def test_harmless_files_are_info_not_critical(self):
        e = Env(self)
        add_vendor(e, {VENDOR + "/.php-cs-fixer.dist.php": FIXER, "libraries/vendor/phpmailer/phpmailer/get_oauth_token.php": OAUTH})
        r = e.run_check()
        t = titles(r)
        self.assertIn(("info", "2 Entwicklungsdatei(en) von Bibliotheken im Ordner vendor"), t, t)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertTrue(any(s == "ok" for s, _ in t), t)

    def test_same_name_with_dangerous_content_stays_critical(self):
        e = Env(self)
        add_vendor(e, {VENDOR + "/.php-cs-fixer.dist.php": FIXER, VENDOR + "/demo.php": "<?php\n@eval(base64_decode($_POST['x']));\n"})
        r = e.run_check()
        t = titles(r)
        crit = [f for f in r.findings if f.sev == "crit" and "unbekannte" in f.title]
        self.assertEqual(len(crit), 1, t)
        self.assertEqual(crit[0].items, [VENDOR + "/demo.php  [enthält gefährlichen Ausdruck, Zeile 2]"])   # seit 2.5.0 mit Zeilenangabe; die Stelle ist im Codeauszug rot markiert
        self.assertTrue(crit[0].evidence)
        self.assertIn(("info", "1 Entwicklungsdatei(en) von Bibliotheken im Ordner vendor"), t)

    def test_other_unknown_php_in_vendor_stays_critical(self):
        e = Env(self)
        add_vendor(e, {VENDOR + "/src/shell.php": "<?php\necho 1;\n"})
        t = titles(e.run_check())
        self.assertTrue(any(s == "crit" and "unbekannte" in x for s, x in t), t)
        self.assertFalse(any("Entwicklungsdatei" in x for _, x in t))


if __name__ == "__main__":
    unittest.main()
