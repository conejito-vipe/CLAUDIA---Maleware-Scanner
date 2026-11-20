# Security policy / Sicherheitshinweise

**Reporting a vulnerability in CLAUDIA itself** (e.g. a way to reach the local interface from another machine, to leak a password into a report, or to make a check change the server): please do **not** open a public issue. Use GitHub's private vulnerability reporting ("Security" tab -> "Report a vulnerability") or contact the maintainer privately. Include version, steps to reproduce and impact.

**Design guarantees that count as bugs if broken:**
- Checks are read-only (the test `test_readonly.py` guards this).
- Connections are encrypted only.
- No passwords or API keys are stored, logged or exported.
- The local server listens on 127.0.0.1 only and requires its access token on every API call.

Findings *about a scanned site* are not vulnerabilities of CLAUDIA. False positives and missed traces are welcome as normal issues (please remove secrets and domain names from logs).
