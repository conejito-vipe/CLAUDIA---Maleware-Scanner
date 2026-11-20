"""2.4.1 Punkt 7 (Umgebung): SPF, DMARC und DKIM der Domain. DNS-Antworten sind nachgebildet (ein selbstgebautes 'dig' im Testordner); echte DNS-Server sind NICHT getestet."""
import os
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia.checks import mail_dns as md  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

DIG = """#!/bin/sh
# Test-dig: Antworten stehen in $FAKE_DNS_DIR/<Name>; fehlt die Datei, ist die Antwort leer (kein Eintrag).
n="$5"
[ -z "$n" ] && n="$4"
for a in "$@"; do n="$a"; done
echo "$n" >> "$FAKE_DNS_DIR/_gefragt"
[ -f "$FAKE_DNS_DIR/$n" ] && cat "$FAKE_DNS_DIR/$n"
exit 0
"""


def run(w, url, dns, cms="joomla"):
    load_all()
    d = tempfile.mkdtemp(prefix="claudia_dns_")
    for name, text in dns.items():
        open(os.path.join(d, name), "w").write(text)
    dig = os.path.join(w["bin"], "dig")
    open(dig, "w").write(DIG)
    os.chmod(dig, os.stat(dig).st_mode | stat.S_IEXEC)
    st = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url=url, allow_hosts=ADV["allow_hosts"], opts={})
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), st, ADV)
    try:
        with mock.patch.dict(os.environ, {"FAKE_DNS_DIR": d}):
            r = {x.id: x for x in eng.run(["mail_dns"], lambda e: None, threading.Event())}["mail_dns"]
    finally:
        os.remove(dig)
    asked = open(os.path.join(d, "_gefragt")).read().split() if os.path.exists(os.path.join(d, "_gefragt")) else []
    return r, asked


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class Pure(unittest.TestCase):
    def test_org_domain_and_host(self):
        self.assertEqual(md.org_domain("www.example.org"), "example.org")
        self.assertEqual(md.org_domain("shop.example.org"), "example.org")
        self.assertEqual(md.org_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(md.clean_host("https://WWW.Example.org/pfad?x=1"), "www.example.org")
        for bad in ("http://127.0.0.1/", "https://localhost", "https://192.168.1.5", "https://a;b.de", "https://x$(id).de", "https://[::1]/"):
            self.assertEqual(md.clean_host(bad), "", bad)
        self.assertEqual(md.clean_host("https://bücher.de"), "xn--bcher-kva.de")

    def test_parse_formats_of_dig_host_nslookup(self):
        out = ('@@TOOL dig\n@@Q example.org\n"v=spf1 include:a.net -all"\n@@Q _dmarc.example.org\n'
               '"v=DMARC1; p=reject" \n@@Q x._domainkey.example.org\n"v=DKIM1; k=rsa; " "p=ABC"\n@@Q y._domainkey.example.org\n;; connection timed out; no servers could be reached\n')
        t, r = md.parse_dns(out)
        self.assertEqual(t, "dig")
        self.assertEqual(r["example.org"], ["v=spf1 include:a.net -all"])
        self.assertEqual(r["x._domainkey.example.org"], ["v=DKIM1; k=rsa; p=ABC"])
        self.assertIsNone(r["y._domainkey.example.org"])
        t, r = md.parse_dns('@@TOOL host\n@@Q example.org\nexample.org descriptive text "v=spf1 mx ~all"\n@@Q a\nHost a not found: 3(NXDOMAIN)\n@@Q b\nHost b not found: 2(SERVFAIL)\n')
        self.assertEqual(r["example.org"], ["v=spf1 mx ~all"])
        self.assertEqual(r["a"], [])
        self.assertIsNone(r["b"])
        t, r = md.parse_dns('@@TOOL nslookup\n@@Q example.org\nServer:\t1.1.1.1\nexample.org\ttext = "v=spf1 -all"\n')
        self.assertEqual(r["example.org"], ["v=spf1 -all"])

    def test_spf_verdicts(self):
        j = lambda *r: md.judge_spf(list(r))[:2]                                                    # noqa: E731
        self.assertEqual(j("v=spf1 include:_spf.x.net -all")[0], "ok")
        self.assertEqual(j("v=spf1 mx ~all")[0], "ok")
        self.assertEqual(j("v=spf1 +all")[0], "crit")
        self.assertEqual(j("v=spf1 all")[0], "crit")
        self.assertEqual(j("v=spf1 a ?all")[0], "warn")
        self.assertEqual(j("v=spf1 a -all", "v=spf1 mx -all")[0], "warn")
        self.assertEqual(j("v=spf1 a")[0], "info")
        self.assertEqual(j("irgendein text")[0], "warn")
        self.assertEqual(md.judge_spf(None)[0], "info")
        many = "v=spf1 " + " ".join("include:s%d.net" % i for i in range(11)) + " -all"
        self.assertEqual(md.judge_spf([many])[0], "warn")

    def test_dmarc_verdicts(self):
        self.assertEqual(md.judge_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.de"])[0], "ok")
        self.assertEqual(md.judge_dmarc(["v=DMARC1; p=quarantine; pct=50"])[1], "DMARC mit Richtlinie quarantine, gilt für 50 % der Mails")
        self.assertEqual(md.judge_dmarc(["v=DMARC1; p=none"])[0], "info")
        self.assertEqual(md.judge_dmarc(["v=DMARC1; rua=mailto:a@b.de"])[0], "info")
        self.assertEqual(md.judge_dmarc([])[0], "info")
        self.assertEqual(md.judge_dmarc(None)[0], "info")

    def test_script_quotes_domain_and_is_limited(self):
        s = md.dns_script("example.org", md.DKIM_SELECTORS)
        self.assertEqual(s.count("sq") + s.count("example.org"), s.count("example.org"))
        self.assertLessEqual(len(md.DKIM_SELECTORS) + 2, 10)
        for word in ("rm ", "curl", "wget", ">/", " > "):
            self.assertNotIn(word, s.replace(">/dev/null", ""))


class Check(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_mail_"))

    def test_good_setup_is_green_and_asks_at_most_ten_names(self):
        r, asked = run(self.w, "https://www.example.org/", {
            "example.org": '"v=spf1 include:_spf.x.net -all"\n',
            "_dmarc.example.org": '"v=DMARC1; p=reject"\n',
            "selector1._domainkey.example.org": '"v=DKIM1; k=rsa; p=MIGf"\n'})
        t = titles(r)
        self.assertIn(("ok", "SPF-Eintrag vorhanden (-all: fremde Absender abweisen)"), t)
        self.assertIn(("ok", "DMARC mit Richtlinie reject"), t)
        self.assertIn(("ok", "DKIM-Eintrag gefunden (selector1)"), t)
        self.assertEqual(sorted(asked), sorted(set(asked)))
        self.assertLessEqual(len(asked), 10)
        self.assertTrue(all(n.endswith("example.org") for n in asked))
        self.assertFalse(any(f.sev in ("warn", "crit") for f in r.findings))

    def test_missing_records_warn_only_for_spf_and_dkim_is_never_a_finding(self):
        r, _ = run(self.w, "https://shop.example.org", {})
        t = titles(r)
        self.assertIn(("warn", "Kein SPF-Eintrag gefunden"), t)
        self.assertIn(("info", "Kein DMARC-Eintrag gefunden"), t)
        self.assertIn(("info", "Kein DKIM-Eintrag unter gängigen Namen gefunden"), t)
        self.assertEqual(r.findings[0].items[0], "Geprüfte Domain: example.org (Hauptdomain von shop.example.org)")
        self.assertTrue(any(f.hint for f in r.findings if f.title == "Kein SPF-Eintrag gefunden"))

    def test_skipped_without_public_domain(self):
        for url in ("", "http://127.0.0.1:8080", "https://localhost", "https://10.0.0.5"):
            r, _ = run(self.w, url, {})
            self.assertEqual(r.status, "skipped", url)

    def test_no_dns_tool_is_reported_honestly(self):
        load_all()
        st = Settings(site_dir=self.w["site_rel"], log_dir="logs", cms="joomla", url="https://example.org", allow_hosts=ADV["allow_hosts"], opts={})
        eng = Engine(LocalRunner(self.w["home"], extra_path=self.w["bin"]), st, ADV)
        with mock.patch("claudia.checks.mail_dns.dns_script", return_value="echo '@@NOTOOL'"):
            r = {x.id: x for x in eng.run(["mail_dns"], lambda e: None, threading.Event())}["mail_dns"]
        self.assertEqual(titles(r)[0], ("info", "SPF, DMARC und DKIM nicht prüfbar"))
        self.assertFalse(any(f.sev in ("warn", "crit") for f in r.findings))

    def test_registered_for_joomla_and_wordpress_in_cluster_umfeld(self):
        load_all()
        for cms in ("joomla", "wordpress"):
            c = {x.id: x for x in ordered(cms)}["mail_dns"]
            self.assertEqual(c.needs, "ssh")
            self.assertEqual(c.cluster_wp if cms == "wordpress" else c.cluster, "umfeld")


if __name__ == "__main__":
    unittest.main()
