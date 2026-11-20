"""D2: Regel-Blöcke von Plugins in der .htaccess ('# BEGIN/END Name') werden gekennzeichnet, der Inhalt aber weiter bewertet."""
import json
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import wpfixture  # noqa: E402
from claudia.checks import config  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))
load_all()

HT = """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule ^index\\.php$ - [L]
</IfModule>
# END WordPress
# BEGIN Wordfence WAF
<IfModule LiteSpeed>
php_value auto_prepend_file '/home/x/wordfence-waf.php'
</IfModule>
# END Wordfence WAF
# BEGIN Mein Hoster-Tool
Header set X-Frame-Options SAMEORIGIN
# END Mein Hoster-Tool
# BEGIN Boeser Block
RewriteCond %{HTTP_USER_AGENT} googlebot [NC]
RewriteRule ^(.*)$ http://spam.example.net/ [R=302,L]
# END Boeser Block
"""


def run(ht):
    w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_ht_"), False)
    open(os.path.join(w["site"], ".htaccess"), "w").write(ht)
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="wordpress", url="", allow_hosts=ADV["allow_hosts"])
    return Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV).run(["htaccess"], lambda e: None, threading.Event())[0]


class Names(unittest.TestCase):
    def test_known_and_unknown(self):
        self.assertEqual(config._ht_block_name("Wordfence WAF"), "Wordfence")
        self.assertEqual(config._ht_block_name("WordPress"), "WordPress (Kern: Permalinks)")
        self.assertEqual(config._ht_block_name("iThemes Security"), "Solid Security (iThemes Security)")
        self.assertEqual(config._ht_block_name("BULLETPROOF SECURE .HTACCESS"), "BulletProof Security")
        self.assertEqual(config._ht_block_name("Mein Hoster-Tool"), "")
        self.assertEqual(config._ht_block_name("WordPress Evil"), "")

    def test_blocks_need_end(self):
        b = config._ht_blocks([("a", 1, "BEGIN", "X"), ("a", 5, "END", "X"), ("a", 7, "BEGIN", "Y")])
        self.assertEqual(b, {"a": [(1, 5, "X")]})


class Check(unittest.TestCase):
    def setUp(self):
        self.r = run(HT)
        self.txt = {f.title: "\n".join(f.items) for f in self.r.findings}

    def test_known_blocks_listed(self):
        k = [t for t in self.txt if "bekannten Programmen" in t]
        self.assertTrue(k, list(self.txt))
        self.assertIn("Wordfence", self.txt[k[0]])
        self.assertIn("WordPress (Kern", self.txt[k[0]])

    def test_unknown_blocks_listed(self):
        u = [t for t in self.txt if "unbekannter Herkunft" in t]
        self.assertTrue(u)
        self.assertIn("Mein Hoster-Tool", self.txt[u[0]])
        self.assertIn("Boeser Block", self.txt[u[0]])

    def test_block_name_never_softens_severity(self):
        crit = [f for f in self.r.findings if f.sev == "crit" and "gefährliche" in f.title]
        self.assertTrue(crit)
        line = [i for i in crit[0].items if "auto_prepend_file" in i][0]
        self.assertIn("Block 'Wordfence WAF' von Wordfence", line)
        warn = "\n".join("\n".join(f.items) for f in self.r.findings if f.sev == "warn")
        self.assertIn("Block 'Boeser Block' unbekannter Herkunft", warn)

    def test_no_blocks_no_block_findings(self):
        r = run("RewriteEngine On\n")
        self.assertFalse([f for f in r.findings if "Regel-Block" in f.title])


if __name__ == "__main__":
    unittest.main()
