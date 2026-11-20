"""2.4.0: Zeilenzähler für die Fußzeile (nur reiner Python-Code)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import count_loc  # noqa: E402

SRC = '''"""Modul-Docstring
über zwei Zeilen"""
import os  # Kommentar

# reiner Kommentar
def f(x):
    """Docstring"""
    s = """a
b
c"""
    return s.replace("a",
                     "b")
'''


class Loc(unittest.TestCase):
    def test_counts_only_code_lines(self):
        self.assertEqual(count_loc.count_source(SRC), 5)        # import, def, s = (Skript zählt als eine Zeile), return, Fortsetzung

    def test_blank_and_comment_only_is_zero(self):
        self.assertEqual(count_loc.count_source("\n# x\n\n"), 0)

    def test_project_count_is_plausible_and_excludes_tests(self):
        n = count_loc.count()
        self.assertGreater(n, 5000)
        total_raw = sum(len(open(os.path.join(d, f), encoding="utf-8").read().splitlines())
                        for sub in ("claudia", "tools") for d, _, fs in os.walk(os.path.join(ROOT, sub)) for f in fs if f.endswith(".py"))
        self.assertLess(n, total_raw)


if __name__ == "__main__":
    unittest.main()
