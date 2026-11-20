"""2.5.0 / 2.13: DNS-Änderungen gegen lokal gespeicherte Basis (nur öffentliche DNS-Daten). DNS-Antworten sind nachgebildet (selbstgebautes 'dig' im Testordner);
die Ausgabeformate von host und nslookup stammen aus dem Gedächtnis und sind NICHT gegen echte Ausgaben geprüft; echte DNS-Server sind NICHT getestet."""
import json
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
from test_checks import ADV  # noqa: E402
from claudia import baseline  # noqa: E402
from claudia.registry import ordered  # noqa: E402
from claudia.checks import mail_dns as md  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

DIG = """#!/bin/sh
# Test-dig: Antwort steht in $FAKE_DNS_DIR/<Art>_<Name>; fehlt die Datei, ist die Antwort leer.
for a in "$@"; do t="$n"; n="$a"; done
echo "$t $n" >> "$FAKE_DNS_DIR/_gefragt"
f="$FAKE_DNS_DIR/${t}_$n"
[ -f "$f" ] && cat "$f"
exit 0
"""
GOOD = {
    "NS_example.org": "ns1.hoster.net.\nns2.hoster.net.\n",
    "MX_example.org": "10 mx1.mail.net.\n20 mx2.mail.net.\n",
    "TXT_example.org": '"google-site-verification=abc"\n"v=spf1 include:_spf.mail.net -all"\n',
    "TXT__dmarc.example.org": '"v=DMARC1; p=reject"\n',
    "A_www.example.org": "203.0.113.10\n",
    "AAAA_www.example.org": "2001:db8::10\n",
}


def run(w, dns, save=False, url="https://www.example.org/", key=None, bl=None):
    load_all()
    d = tempfile.mkdtemp(prefix="claudia_dnsc_")
    for name, text in dns.items():
        open(os.path.join(d, name), "w").write(text)
    dig = os.path.join(w["bin"], "dig")
    open(dig, "w").write(DIG)
    os.chmod(dig, os.stat(dig).st_mode | stat.S_IEXEC)
    key = key or baseline.make_key("h.example", "u", w["site_rel"])
    st = Settings(site_dir=w["site_rel"], log_dir="logs", cms="joomla", url=url, allow_hosts=ADV["allow_hosts"], opts={"dns_changes": {"save": save}},
                  baseline_dir=bl if bl is not None else w["bl"], baseline_key=key, baseline_label="h.example : site")
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), st, ADV)
    try:
        with mock.patch.dict(os.environ, {"FAKE_DNS_DIR": d}):
            r = {x.id: x for x in eng.run(["dns_changes"], lambda e: None, threading.Event())}["dns_changes"]
    finally:
        os.remove(dig)
    asked = open(os.path.join(d, "_gefragt")).read().splitlines() if os.path.exists(os.path.join(d, "_gefragt")) else []
    return r, asked, key


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class Pure(unittest.TestCase):
    def test_parse_dig(self):
        out = ('@@TOOL dig\\n').replace("\\n", "\n") + ('@@Q NS example.org\nNS1.Hoster.net.\nns2.hoster.net.\n@@Q MX example.org\n20 mx2.mail.net.\n10 mx1.mail.net.\n'
               '@@Q TXT example.org\n"google-site-verification=x"\n"v=spf1 a -all"\n@@Q TXT _dmarc.example.org\n"v=DMARC1; p=none"\n'
               '@@Q A www.example.org\n203.0.113.10\n@@Q AAAA www.example.org\n2001:DB8::10\n')
        t, r = md.parse_records(out)
        self.assertEqual(t, "dig")
        self.assertEqual(r["NS"], ["ns1.hoster.net", "ns2.hoster.net"])
        self.assertEqual(r["MX"], ["10 mx1.mail.net", "20 mx2.mail.net"])
        self.assertEqual(r["TXT"], ["v=spf1 a -all"], "nur SPF, keine Verifizierungs-Einträge")
        self.assertEqual(r["DMARC"], ["v=dmarc1; p=none"])
        self.assertEqual(r["A"], ["203.0.113.10"])
        self.assertEqual(r["AAAA"], ["2001:db8::10"])

    def test_parse_host_and_nslookup_formats(self):
        host = ("@@TOOL host\n@@Q NS example.org\nexample.org name server ns1.hoster.net.\n@@Q MX example.org\nexample.org mail is handled by 10 mx1.mail.net.\n"
                '@@Q TXT example.org\nexample.org descriptive text "v=spf1 -all"\n@@Q TXT _dmarc.example.org\n@@Q A www.example.org\nwww.example.org has address 203.0.113.10\n'
                "@@Q AAAA www.example.org\nwww.example.org has IPv6 address 2001:db8::10\n")
        t, r = md.parse_records(host)
        self.assertEqual((r["NS"], r["MX"], r["TXT"], r["DMARC"], r["A"], r["AAAA"]),
                         (["ns1.hoster.net"], ["10 mx1.mail.net"], ["v=spf1 -all"], [], ["203.0.113.10"], ["2001:db8::10"]))
        ns = ("@@TOOL nslookup\n@@Q NS example.org\nServer:\t\t192.168.0.1\nAddress:\t192.168.0.1#53\n\nNon-authoritative answer:\nexample.org\tnameserver = ns1.hoster.net.\n"
              "@@Q MX example.org\nexample.org\tmail exchanger = 10 mx1.mail.net.\n@@Q A www.example.org\nServer:\t\t192.168.0.1\nAddress:\t192.168.0.1#53\n\n"
              "Non-authoritative answer:\nName:\twww.example.org\nAddress: 203.0.113.10\n")
        t, r = md.parse_records(ns)
        self.assertEqual((r["NS"], r["MX"], r["A"]), (["ns1.hoster.net"], ["10 mx1.mail.net"], ["203.0.113.10"]), "der Auflöser (Address ...#53) zählt nicht")

    def test_failure_is_none_and_empty_is_empty_list(self):
        t, r = md.parse_records("@@TOOL dig\n@@Q NS example.org\n;; connection timed out; no servers could be reached\n@@Q MX example.org\n@@Q A www.example.org\n@@ERR\n")
        self.assertIsNone(r["NS"])
        self.assertEqual(r["MX"], [])
        self.assertIsNone(r["A"])

    def test_diff(self):
        base = {"NS": ["a", "b"], "MX": ["10 m"], "A": ["1.1.1.1"]}
        ch, unk = md.diff_records(base, {"NS": ["a", "b"], "MX": ["10 x"], "A": None, "AAAA": ["::1"]})
        self.assertEqual(ch, [("MX", ["10 m"], ["10 x"])])
        self.assertEqual(unk, ["A"])
        self.assertEqual(md.diff_records(base, {"NS": ["b", "a"], "MX": ["10 m"], "A": ["1.1.1.1"]}), ([], []))
        self.assertEqual(md.diff_records({}, {"NS": ["a"]}), ([], []), "nicht in der Basis = nicht verglichen")

    def test_script_is_read_only_with_six_queries_and_quotes_names(self):
        s = md.records_script("example.org", "www.example.org")
        self.assertEqual(s.count("@@Q"), 6)
        for word in ("rm ", "curl", "wget", "> /", ">>", "chmod", "tee "):
            self.assertNotIn(word, s.replace(">/dev/null", ""))

    def test_dns_base_file_roundtrip_and_validation(self):
        d = tempfile.mkdtemp(prefix="claudia_dnsb_")
        key = baseline.make_key("h", "u", "x")
        self.assertIsNone(baseline.load_dns(d, key))
        baseline.save_dns(d, key, "example.org", {"NS": ["b", "a", "a"], "MX": []})
        b = baseline.load_dns(d, key)
        self.assertEqual(b["records"], {"NS": ["a", "b"], "MX": []})
        self.assertEqual(set(b), {"version", "saved", "domain", "records"}, "nur öffentliche Daten, nichts anderes")
        with self.assertRaises(ValueError):
            baseline.save_dns(d, "../x", "example.org", {})
        open(os.path.join(d, key + ".dns.json"), "w").write(json.dumps({"version": 1, "records": {"NS": "kein-list"}}))
        self.assertIsNone(baseline.load_dns(d, key), "kaputte Datei wird ignoriert")
        open(os.path.join(d, key + ".dns.json"), "w").write("{kaputt")
        self.assertIsNone(baseline.load_dns(d, key))

    def test_delete_removes_dns_base_too(self):
        d = tempfile.mkdtemp(prefix="claudia_dnsb_")
        key = baseline.make_key("h", "u", "x")
        baseline.save_dns(d, key, "example.org", {"NS": ["a"]})
        self.assertTrue(baseline.delete(d, key))
        self.assertIsNone(baseline.load_dns(d, key))


class Check(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_dnsw_"), False)
        self.w["bl"] = tempfile.mkdtemp(prefix="claudia_dnsbl_")

    def test_flow_no_base_save_unchanged_changed(self):
        r, asked, key = run(self.w, GOOD)
        self.assertEqual(titles(r)[0], ("info", "Noch keine DNS-Basis vorhanden"))
        self.assertEqual(len(asked), 6)
        self.assertIsNone(baseline.load_dns(self.w["bl"], key), "ohne Häkchen wird nichts gespeichert")
        r, _, _ = run(self.w, GOOD, save=True)
        self.assertIn(("ok", "DNS-Basis gespeichert"), titles(r))
        b = baseline.load_dns(self.w["bl"], key)
        self.assertEqual(b["records"]["TXT"], ["v=spf1 include:_spf.mail.net -all"])
        self.assertEqual(b["domain"], "example.org")
        r, _, _ = run(self.w, GOOD)
        self.assertEqual(titles(r), [("ok", "Keine DNS-Änderung seit der Basis")])
        bad = dict(GOOD, **{"NS_example.org": "ns1.fremd.example.\n", "MX_example.org": "10 mx1.mail.net.\n20 mx2.mail.net.\n30 mail.phish.example.\n",
                            "TXT_example.org": '"v=spf1 +all"\n'})
        r, _, _ = run(self.w, bad)
        t = titles(r)
        self.assertIn(("warn", "Nameserver hat sich geändert"), t)
        self.assertIn(("warn", "Mail-Server hat sich geändert"), t)
        self.assertIn(("warn", "SPF-Eintrag hat sich geändert"), t)
        self.assertNotIn(("ok", "Keine DNS-Änderung seit der Basis"), t)
        ns = [f for f in r.findings if f.title.startswith("Nameserver")][0]
        self.assertIn("neu: ns1.fremd.example", ns.items)
        self.assertIn("entfernt: ns1.hoster.net", ns.items)
        self.assertTrue(ns.hint)

    def test_unanswered_query_is_not_compared_and_not_saved(self):
        run(self.w, GOOD, save=True)
        part = dict(GOOD, **{"MX_example.org": "connection timed out; no servers could be reached\n"})
        r, _, key = run(self.w, part)
        t = titles(r)
        self.assertIn(("info", "Nicht alle DNS-Einträge waren abfragbar"), t)
        self.assertFalse(any(s in ("warn", "crit") for s, _ in t), "Fehlschlag ist keine Änderung")
        before = baseline.load_dns(self.w["bl"], key)
        r, _, _ = run(self.w, part, save=True)
        self.assertIn(("warn", "DNS-Basis wurde nicht gespeichert"), titles(r))
        self.assertEqual(baseline.load_dns(self.w["bl"], key), before, "unvollständige Abfrage ersetzt die Basis nicht")

    def test_only_bases_of_same_connection_are_used(self):
        run(self.w, GOOD, save=True)
        other = baseline.make_key("anderer.example", "u", "x")
        r, _, _ = run(self.w, dict(GOOD, **{"NS_example.org": "x.example.\n"}), key=other)
        self.assertEqual(titles(r)[0], ("info", "Noch keine DNS-Basis vorhanden"))

    def test_skipped_without_public_domain_or_baseline(self):
        for url in ("", "http://127.0.0.1:8080", "https://localhost", "https://10.0.0.5"):
            r, _, _ = run(self.w, {}, url=url)
            self.assertEqual(r.status, "skipped", url)
        load_all()
        st = Settings(site_dir=self.w["site_rel"], log_dir="logs", cms="joomla", url="https://example.org", allow_hosts=ADV["allow_hosts"], opts={})
        r = {x.id: x for x in Engine(LocalRunner(self.w["home"], extra_path=self.w["bin"]), st, ADV).run(["dns_changes"], lambda e: None, threading.Event())}["dns_changes"]
        self.assertEqual(r.status, "skipped")

    def test_no_dns_tool_and_no_answers_are_reported_honestly(self):
        load_all()
        st = Settings(site_dir=self.w["site_rel"], log_dir="logs", cms="joomla", url="https://example.org", allow_hosts=ADV["allow_hosts"], opts={},
                      baseline_dir=self.w["bl"], baseline_key=baseline.make_key("h", "u", "x"))
        eng = Engine(LocalRunner(self.w["home"], extra_path=self.w["bin"]), st, ADV)
        with mock.patch("claudia.checks.mail_dns.records_script", return_value="echo '@@NOTOOL'"):
            r = {x.id: x for x in eng.run(["dns_changes"], lambda e: None, threading.Event())}["dns_changes"]
        self.assertEqual(titles(r)[0], ("info", "DNS-Änderungen nicht prüfbar"))
        r, _, _ = run(self.w, {k: "connection timed out; no servers could be reached\n" for k in GOOD})
        self.assertEqual(titles(r)[0], ("info", "DNS-Änderungen nicht prüfbar"))

    def test_registered_for_both_systems_in_cluster_umfeld(self):
        load_all()
        for cms in ("joomla", "wordpress"):
            c = {x.id: x for x in ordered(cms)}["dns_changes"]
            self.assertEqual(c.needs, "ssh")
            self.assertEqual(c.cluster_wp if cms == "wordpress" else c.cluster, "umfeld")
            self.assertEqual([o.key for o in c.options], ["save"])


if __name__ == "__main__":
    unittest.main()
