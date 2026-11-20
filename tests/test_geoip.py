"""Herkunft der Absender: nur gekürztes Netz, nur Regional-Registries, Flagge vor der Adresse."""
import json
import os
import sys
import unittest
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from claudia import geoip  # noqa: E402
from claudia.checks import logs  # noqa: E402
from claudia.util import mask_ip  # noqa: E402

BOOT4 = {"services": [[["136.0.0.0/8"], ["https://rdap.arin.net/registry/"]], [["185.0.0.0/8"], ["https://rdap.db.ripe.net/"]], [["95.0.0.0/8"], ["https://evil.example/"]]]}
ARIN = {"name": "ORACLE-BMC", "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Oracle Corporation"], ["adr", {}, "text", ["", "", "", "Austin", "TX", "78741", "US"]]]]}]}
RIPE = {"name": "SOME-NET", "country": "NL"}


class Calls:
    def __init__(self):
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        if url.endswith("ipv4.json"):
            return json.dumps(BOOT4).encode()
        if "arin" in url:
            return json.dumps(ARIN).encode()
        if "ripe" in url:
            return json.dumps(RIPE).encode()
        raise AssertionError(url)


class Ctx:
    def __init__(self, geo):
        self.shared = {"_geo": geo}

    def mask(self, t):
        return mask_ip(t)


class GeoTests(unittest.TestCase):
    def test_flag_and_network(self):
        self.assertEqual(geoip.flag("de"), "\U0001F1E9\U0001F1EA")
        self.assertEqual(geoip.network_of("136.80.159.77"), "136.80.159.0")
        self.assertEqual(geoip.network_of("2a02:c207:2332:1::5"), "2a02:c207:2332::")
        for bad in ("10.1.2.3", "127.0.0.1", "abc", "192.168.0.9"):
            self.assertIsNone(geoip.network_of(bad))

    def test_only_truncated_network_is_sent_and_only_rir_hosts(self):
        c = Calls()
        g = geoip.Geo(c, True)
        self.assertEqual(g.lookup("136.80.159.77")["cc"], "US")                    # Land aus der Kontakt-Adresse (vCard)
        self.assertEqual(g.lookup("185.156.44.9")["cc"], "NL")                     # Land direkt im Netz-Objekt
        self.assertEqual(g.lookup("95.70.149.3"), {})                              # Bootstrap-Eintrag zeigt nicht auf eine Registry: nie abgefragt
        asked = [u for u in c.urls if "/ip/" in u]
        self.assertEqual(asked, ["https://rdap.arin.net/registry/ip/136.80.159.0", "https://rdap.db.ripe.net/ip/185.156.44.0"])
        self.assertFalse(any("136.80.159.77" in u or "185.156.44.9" in u for u in c.urls))
        n = len(c.urls)
        g.lookup("136.80.159.200")                                                  # gleiches Netz: aus dem Zwischenspeicher
        self.assertEqual(len(c.urls), n)

    def test_limit_and_failure(self):
        def boom(url):
            raise geoip.coreref.RefError("offline")
        g = geoip.Geo(boom, True)
        self.assertEqual(g.lookup("136.80.159.1"), {})
        self.assertIn("offline", g.error)
        c = Calls()
        g = geoip.Geo(c, True)
        for i in range(30):
            g.lookup("136.%d.1.1" % i)
        self.assertLessEqual(len(g.cache), geoip.MAX_NETS)
        self.assertEqual(geoip.Geo(c, False).lookup("136.80.159.1"), {})            # abgeschaltet

    def test_senders_show_flag_before_masked_ip(self):
        g = geoip.Geo(Calls(), True)
        shown, rows = logs.senders(Ctx(g), Counter({"136.80.159.7": 72, "185.156.44.2": 68, "10.0.0.1": 3}))
        self.assertTrue(shown.startswith("\U0001F1FA\U0001F1F8 136.80.159.x (72x), \U0001F1F3\U0001F1F1 185.156.44.x (68x), 10.0.0.x (3x)"), shown)
        self.assertIn("USA (US), Netz ORACLE-BMC, Oracle Corporation", rows[0])
        self.assertEqual(len(rows), 2)
        shown2, _ = logs.senders(Ctx(g), Counter({"136.80.159.x": 5}))              # schon gekürzt (Protokoll auf dem PC)
        self.assertTrue(shown2.startswith("\U0001F1FA\U0001F1F8 136.80.159.x"), shown2)


if __name__ == "__main__":
    unittest.main()
