"""Hilfsprogramm: führt Tests gegen die künstliche Seite aus und druckt die Befunde."""
import json, os, sys, tempfile, threading
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import fixture
from claudia.engine import Engine, Settings
from claudia.runner import LocalRunner

def world(infected=True, base=None):
    base = base or tempfile.mkdtemp(prefix="claudia_w_")
    return fixture.make_world(base, infected)

def run(ids, infected=True, settings=None, w=None):
    w = w or world(infected)
    adv = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
    s = settings or Settings(site_dir=w["site_rel"], log_dir="logs")
    if not s.allow_hosts:
        s.allow_hosts = adv["allow_hosts"]
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, adv)
    return eng.run(ids, lambda e: None, threading.Event()), w

def show(results, raw=False):
    for r in results:
        print("=== [%s] %s  (%s, %.1fs) %s" % (r.status.upper(), r.title, r.id, r.seconds, r.message))
        for f in r.findings:
            print("  - [%s] %s" % (f.sev, f.title))
            if f.detail: print("      %s" % f.detail[:160])
            for it in f.items[:6]: print("        * %s" % it[:170])
            if len(f.items) > 6: print("        ... +%d" % (len(f.items) - 6))
            if f.hint: print("      -> %s" % f.hint[:120])
        if raw:
            for k, v in r.raw.items(): print("  RAW[%s]: %s" % (k, v[:600].replace("\n", " | ")))

if __name__ == "__main__":
    infected = "--clean" not in sys.argv
    ids = [a for a in sys.argv[1:] if not a.startswith("--")]
    from claudia.registry import load_all, ORDER
    load_all()
    res, w = run(ids or ORDER, infected)
    show(res, raw="--raw" in sys.argv)
