"""Neue Prüfungen 2.5.0 gegen die Test-Welt: Joomla-Einstellungen aus der Datenbank, Umgebung, Mailversand. Nur lesend, keine Geheimnisse im Ergebnis."""
import json
import os
import sqlite3
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_konto as k  # noqa: E402
from claudia.checks import mail_send  # noqa: E402
from claudia.registry import CLUSTERS, ordered  # noqa: E402

NEW_IDS = ["db_textfilter", "db_upload_ext", "db_registration", "db_mfa", "db_admin_logins", "db_ext_age", "plaintext_creds", "backup_age", "tls_protocols", "cookie_flags", "js_libs", "mail_send"]


def seeded(settings=True):
    w = k.world(True)
    con = sqlite3.connect(w["db"])
    con.executescript("CREATE TABLE IF NOT EXISTS j_assets (id INTEGER PRIMARY KEY, name TEXT, rules TEXT);"
                      "CREATE TABLE IF NOT EXISTS j_user_mfa (id INTEGER PRIMARY KEY, user_id INTEGER, method TEXT);")
    if settings:
        con.execute("INSERT INTO j_assets VALUES (1,'root.1','{\"core.login.admin\":{\"7\":1,\"8\":1}}')")
        for el, params in (("com_users", {"allowUserRegistration": "1", "new_usertype": "8", "useractivation": "0"}),
                           ("com_config", {"filters": {"1": {"filter_type": "NH"}, "2": {"filter_type": "NONE"}}}),
                           ("com_media", {"upload_extensions": "bmp,gif,php,jpg", "ignore_extensions": "", "restrict_uploads": "1", "check_mime": "1"})):
            con.execute("INSERT INTO j_extensions (name,type,element,folder,client_id,enabled,params) VALUES (?,?,?,?,1,1,?)", (el, "component", el, "", json.dumps(params)))
    con.commit()
    con.close()
    return w


class Registered(unittest.TestCase):
    def test_all_new_checks_are_registered_for_joomla(self):
        ids = {c.id for c in ordered("joomla")}
        self.assertEqual([i for i in NEW_IDS if i not in ids], [])

    def test_wordpress_gets_its_own(self):
        ids = {c.id for c in ordered("wordpress")}
        for i in ("wp_2fa", "plaintext_creds", "backup_age", "mail_send"):
            self.assertIn(i, ids)
        self.assertNotIn("db_textfilter", ids)

    def test_cluster_exists(self):
        self.assertIn("joomla_einst", CLUSTERS)


class Settings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = seeded()
        cls.r = {i: k.run(cls.w, i) for i in ("db_textfilter", "db_upload_ext", "db_registration", "db_mfa")}

    def test_textfilter_off_for_a_group(self):
        self.assertIn(("warn", "Textfilter ist für 1 Benutzergruppe(n) ausgeschaltet"), k.tt(self.r["db_textfilter"]))

    def test_upload_php_is_critical(self):
        f = [f for f in self.r["db_upload_ext"].findings if f.sev == "crit"]
        self.assertTrue(f and "php" in f[0].items, k.tt(self.r["db_upload_ext"]))

    def test_registration_into_admin_group_is_critical(self):
        self.assertEqual(self.r["db_registration"].findings[0].sev, "crit")

    def test_admins_without_second_factor(self):
        f = self.r["db_mfa"].findings[0]
        self.assertEqual(f.sev, "warn")
        self.assertIn("2 Administrator", f.title)

    def test_mfa_set_up_lowers_the_finding(self):
        w = seeded()
        con = sqlite3.connect(w["db"])
        con.execute("INSERT INTO j_user_mfa (user_id, method) VALUES (1, 'totp')")
        con.execute("INSERT INTO j_user_mfa (user_id, method) VALUES (2, 'totp')")
        con.commit()
        con.close()
        r = k.run(w, "db_mfa")
        self.assertNotIn("2 Administrator(en) ohne Zwei-Faktor-Anmeldung", [t for _, t in k.tt(r)])

    def test_missing_tables_do_not_crash(self):
        w = seeded(settings=False)
        for cid in ("db_textfilter", "db_upload_ext", "db_registration", "db_mfa", "db_admin_logins", "db_ext_age"):
            r = k.run(w, cid)
            self.assertNotEqual(getattr(r, "status", "ok"), "error", cid)
            self.assertTrue(r.findings or getattr(r, "status", "") == "skipped", cid)

    def test_no_secret_in_results(self):
        for r in self.r.values():
            self.assertNotIn(k.SEC, k.blob(r))


class Environment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = seeded()

    def test_world_readable_credentials_file_is_critical(self):
        r = k.run(self.w, "plaintext_creds")
        self.assertEqual(r.findings[0].sev, "crit")
        self.assertNotIn(k.SEC, k.blob(r))

    def test_no_backup_is_reported_not_crashed(self):
        r = k.run(self.w, "backup_age")
        self.assertTrue(r.findings)

    def test_js_libs_runs(self):
        self.assertTrue(k.run(self.w, "js_libs").findings)


class MailJudges(unittest.TestCase):
    def test_sendmail_path_to_tmp_is_critical(self):
        rows = mail_send.judge_php_mail({"sendmail_path": "/tmp/.x/run.sh -t", "mail.log": "", "mail.add_x_header": "0"})
        self.assertEqual(rows[0][0], "crit")

    def test_standard_sendmail_is_fine(self):
        rows = mail_send.judge_php_mail({"sendmail_path": "/usr/sbin/sendmail -t -i", "mail.log": "", "mail.add_x_header": "1"})
        self.assertNotIn("crit", [r[0] for r in rows])

    def test_unusable_input_never_crashes(self):
        for bad in (None, "x", 5, [], {}):
            self.assertIsInstance(mail_send.judge_php_mail(bad), list)
            self.assertIsInstance(mail_send.judge_mailer(bad, "example.org"), list)
        self.assertIsInstance(mail_send.judge_queue(None), list)

    def test_mail_log_from_upload_dir_is_critical(self):
        out = "mail() on [/var/www/html/images/x.php:12]: To: a@b.c"
        paths = mail_send.parse_mail_log(out)
        self.assertEqual(paths, ["/var/www/html/images/x.php"])
        self.assertEqual(mail_send.judge_mail_log(paths)[0][0], "crit")

    def test_big_queue_is_flagged(self):
        self.assertEqual(mail_send.parse_queue("1234\n"), 1234)
        self.assertNotEqual(mail_send.judge_queue(1234)[0][0], "ok")


if __name__ == "__main__":
    unittest.main()
