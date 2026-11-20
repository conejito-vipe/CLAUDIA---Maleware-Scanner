"""Paket und GitHub-Dateien: Versionen stimmen überein, nötige Dateien sind da, CHANGELOG ist aktuell, keine Geheimnisse im Paket."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from claudia import __version__, helpdocs  # noqa: E402

REQUIRED = ["README.md", "README.de.md", "LICENSE", "LIZENZ.txt", "SECURITY.md", "SICHERHEIT.txt", "CONTRIBUTING.md", ".gitignore", ".gitattributes",
            "pyproject.toml", "requirements.txt", "start.bat", "pruefen.bat", "Anleitung.txt", ".github/workflows/ci.yml",
            ".github/PULL_REQUEST_TEMPLATE.md", ".github/ISSUE_TEMPLATE/bug_report.md", "tools/i18n.py", "tools/build_docs.py", "tools/build_release.py",
            "claudia/docs/handbuch.de.txt", "claudia/docs/handbuch.en.txt", "claudia/docs/aenderungen.de.txt", "claudia/docs/aenderungen.en.txt",
            "claudia/lang/de.json", "claudia/lang/en.json"]


def read(p):
    return open(os.path.join(ROOT, p), encoding="utf-8").read()


class Release(unittest.TestCase):
    def test_required_files(self):
        for f in REQUIRED:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), "fehlt: " + f)

    def test_versions_consistent(self):
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', read("pyproject.toml"))
        self.assertEqual(m.group(1), __version__)
        self.assertEqual(helpdocs.changelog("de")[0]["version"], __version__)
        self.assertEqual(helpdocs.changelog("en")[0]["version"], __version__)

    def test_changelog_md_up_to_date(self):
        import build_release
        p = os.path.join(ROOT, "CHANGELOG.md")
        self.assertTrue(os.path.isfile(p), "CHANGELOG.md fehlt: python tools/build_release.py")
        self.assertEqual(read("CHANGELOG.md"), build_release.changelog_md("en"), "CHANGELOG.md veraltet: python tools/build_release.py")

    def test_license_texts_agree(self):
        self.assertIn("without any warranty", read("LICENSE"))
        self.assertIn("ohne jegliche Gewährleistung", read("LICENSE"))
        self.assertIn("Freeware", read("LIZENZ.txt"))

    def test_gitignore_blocks_private_data(self):
        g = read(".gitignore")
        for s in ("profile.json", "bekannte_server.json", "berichte/", ".venv/"):
            self.assertIn(s, g)

    def test_no_secrets_in_package(self):
        bad = re.compile(r"AIza[0-9A-Za-z_-]{30,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----|ghp_[0-9A-Za-z]{30,}")
        for d, dirs, fs in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x not in ("__pycache__", ".git", ".venv")]
            for f in fs:
                if f.endswith((".py", ".js", ".json", ".txt", ".md", ".html", ".bat", ".yml", ".toml")):
                    try:
                        t = open(os.path.join(d, f), encoding="utf-8").read()
                    except (OSError, UnicodeDecodeError):
                        continue
                    self.assertIsNone(bad.search(t), os.path.join(d, f))

    def test_start_bat_is_only_start_file(self):
        bats = sorted(f for f in os.listdir(ROOT) if f.lower().endswith(".bat"))
        self.assertEqual(bats, ["pruefen.bat", "start.bat"])


if __name__ == "__main__":
    unittest.main()
