"""A10: Dateien mit führendem Punkt (.htaccess, .user.ini) behalten ihren Namen beim Lesen der Prüfsummen."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from claudia import wpsums  # noqa: E402

H = "a" * 64


class DotFiles(unittest.TestCase):
    def test_leading_dot_kept(self):
        ref = wpsums.parse_reference(json.dumps({"files": {".htaccess": {"md5": "b" * 32, "sha256": H}, "./x.php": {"sha256": H}, "inc/.user.ini": {"sha256": H}}}))
        self.assertIn(".htaccess", ref)
        self.assertIn("x.php", ref)
        self.assertIn("inc/.user.ini", ref)
        self.assertNotIn("htaccess", ref)

    def test_no_false_extra_for_known_htaccess(self):
        ref = wpsums.parse_reference(json.dumps({"files": {".htaccess": {"sha256": H}}}))
        res = wpsums.compare({".htaccess": H}, ref)
        self.assertEqual(res, {"changed": [], "extra": [], "missing": []})

    def test_changed_htaccess_reported(self):
        ref = wpsums.parse_reference(json.dumps({"files": {".htaccess": {"sha256": H}}}))
        res = wpsums.compare({".htaccess": "c" * 64}, ref)
        self.assertEqual(res["changed"], [".htaccess"])


if __name__ == "__main__":
    unittest.main()
