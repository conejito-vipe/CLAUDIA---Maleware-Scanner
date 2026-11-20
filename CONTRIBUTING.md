# Contributing / Mitwirken

Thanks for helping! Rules that keep the project trustworthy:

1. **Checks are read-only.** New checks use the runner's read methods only; anything that changes a server must be a whitelisted action with preview, confirmation and backup.
2. **Encrypted connections only.** No plain HTTP/FTP/Telnet paths.
3. **No secrets** in code, logs, reports, tests or issues.
4. **German is the source language** of all texts. Put new sentences in the code in German; run `python tools/i18n.py sync` and translate the empty entries in `claudia/lang/*.json` (`python tools/i18n.py check <code>` must stay clean).
5. **Documentation:** add an entry to `claudia/docs/aenderungen.de.txt` and `.en.txt` (what / why / how) and to the manual when behaviour changes. Bump `claudia/__version__` and `pyproject.toml` together (`tests/test_release.py` checks it).
6. **Tests:** `cd tests && PYTHONPATH=fake_paramiko:.. python -m unittest discover -s . -p "test_*.py"`. Add a test for every new check, including a false-positive case.
7. Standard library only, plus `paramiko`. UI is plain JavaScript/CSS without build step.

Pull requests: describe what changed and why; mention how you tested it.

License note / Lizenzhinweis: CLAUDIA is not open source (see LICENSE). Changes are only allowed to send them to the author as an issue or pull request; with a submission you grant the author the right to use it free of charge. / CLAUDIA ist nicht Open Source (siehe LICENSE). Änderungen sind nur erlaubt, um sie dem Urheber als Issue oder Pull Request zu übermitteln; mit der Übermittlung räumst du dem Urheber das Recht ein, sie unentgeltlich zu nutzen.
