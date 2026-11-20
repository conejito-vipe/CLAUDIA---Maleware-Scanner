"""2.3.0: Konten sperren, Tokens widerrufen, Sitzungen beenden, Erweiterungen ausschalten (Joomla per SQL, WordPress per WP-CLI-Attrappe)."""
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
import test_wp  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError  # noqa: E402

CH = [{"name": "php8.3", "version": "8.3.6", "default": True}]


def q(w, sql, *a):
    c = sqlite3.connect(w["db"])
    r = c.execute(sql, a).fetchall()
    c.commit()
    c.close()
    return r


def run(r, w, aid, pick, **extra):
    p = {"selected_pick": pick, "php": "php8.3"}
    p.update(extra)
    return actions.run_action(r, w["site_rel"], aid, p, CH)


class Marks(unittest.TestCase):
    def test_pick_from_items(self):
        it = ["sysop  (sys@mail.example.net) - angelegt 2026-10-27  [ID 4]", "Chef  [ID 1]", "    Hinweis ohne Marke", "ohne Marke"]
        p = actions.pick_from_items(it, "u")
        self.assertEqual([x["key"] for x in p], ["u:4", "u:1"])
        self.assertNotIn("[ID", p[0]["label"])
        e = actions.pick_from_items(["Foo 1.0 (x.xml), behoben ab 2.0  [Kennung: component/-/com_foo]", "Bar  [Kennung: plugin/system/bar]"], "e")
        self.assertEqual([x["key"] for x in e], ["e:component/-/com_foo", "e:plugin/system/bar"])

    def test_hostile_keys_are_ignored(self):
        self.assertEqual(actions._picked_ids({"selected_pick": ["u:1; DROP TABLE x", "u:7", "e:7", "u:7"]}), [7])
        self.assertEqual(actions._picked({"selected_pick": ["e:component/-/com_a b", "e:plugin/system/ok"]}, "e"), ["component/-/com_a b", "plugin/system/ok"])
        self.assertFalse(actions.EXT_KEY_RE.match("component/-/com_a b"))
        self.assertFalse(actions.EXT_KEY_RE.match("plugin/system/x'; --"))


class Offer(unittest.TestCase):
    def av(self, results, cms="joomla", scan=None):
        info = {"cms": cms, "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
        return {a["id"]: a for a in actions.available(results, info, "8.3", {}, scan or {})}

    def test_users_and_tokens_offered_only_with_marked_items(self):
        res = [{"id": "db_users", "title": "x", "status": "warn", "findings": [
            {"sev": "warn", "title": "1 Administrator-Konto/Konten in den letzten 120 Tagen angelegt", "items": ["sysop  (a@b) - angelegt 2026-10-27  [ID 4]"]},
            {"sev": "warn", "title": "1 Benutzer mit aktivem API-Token", "items": ["sysop  [Super Users]  [ID 4]"]}]}]
        av = self.av(res)
        self.assertEqual([x["key"] for x in av["block_users"]["params"]["pick"]], ["u:4"])
        self.assertEqual([x["key"] for x in av["revoke_tokens"]["params"]["pick"]], ["u:4"])
        self.assertIn("end_sessions", av)
        self.assertNotIn("deactivate_extension", av)
        av = self.av([{"id": "db_users", "title": "x", "status": "ok", "findings": [{"sev": "ok", "title": "Alles gut", "items": []}]}])
        for a in ("block_users", "revoke_tokens", "end_sessions", "deactivate_extension", "wp_deactivate_plugin"):
            self.assertNotIn(a, av)

    def test_extension_actions_split_by_cms(self):
        j = [{"id": "extensions_fs", "title": "x", "status": "crit", "findings": [
            {"sev": "crit", "title": "1 Erweiterung(en) mit bekannter Sicherheitslücke", "items": ["Foo 1.0 (x.xml), behoben ab 2.0  [Kennung: component/-/com_foo]"]}]}]
        av = self.av(j)
        self.assertIn("deactivate_extension", av)
        self.assertNotIn("wp_deactivate_plugin", av)
        w = [{"id": "wp_plugins", "title": "x", "status": "crit", "findings": [
            {"sev": "crit", "title": "1 Plugin(s) mit bekannter Sicherheitslücke", "items": ["Foo 1.0 (CVE), behoben in 2.0: x  [Kennung: foo-plugin]"]}]}]
        av = self.av(w, "wordpress", {"wpcli": "/h/wp-cli.phar"})
        self.assertIn("wp_deactivate_plugin", av)
        self.assertEqual(av["wp_deactivate_plugin"]["params"]["pick"][0]["key"], "p:foo-plugin")
        self.assertNotIn("deactivate_extension", av)
        self.assertIn("WP-CLI", self.av(w, "wordpress", {})["wp_deactivate_plugin"]["reason"])

    def test_preview_needs_selection(self):
        with self.assertRaises(actions.ApiError if hasattr(actions, "ApiError") else actions.ActionError):
            actions.commands_preview("block_users", {"cms": "joomla"}, CH)
        txt = "\n".join(actions.commands_preview("block_users", {"cms": "joomla", "selected_pick": ["u:3"]}, CH))
        self.assertIn("UPDATE #__users SET block = 1 WHERE id IN (3)", txt)
        txt = "\n".join(actions.commands_preview("wp_deactivate_plugin", {"selected_pick": ["p:foo"], "wpcli": "/h/wp", "php": "php8.3"}, CH))
        self.assertIn("plugin deactivate foo", txt)


class JoomlaRun(unittest.TestCase):
    def test_block_user_with_backup_and_undo_file(self):
        r, w = t2.world()
        q(w, "INSERT INTO j_session (session_id, client_id, guest, time, data, userid, username) VALUES ('s1',1,0,'1',' ',3,'leser'),('s2',1,0,'1',' ',1,'chef')")
        res = run(r, w, "block_users", ["u:3"], cms="joomla")
        self.assertTrue(res["ok"], res)
        self.assertEqual(q(w, "SELECT block FROM j_users WHERE id=3")[0][0], 1)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_session WHERE userid=3")[0][0], 0)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_session WHERE userid=1")[0][0], 1)          # Sitzung des anderen bleibt
        self.assertTrue(os.path.getsize(os.path.join(res["backup_dir"], "benutzer.sql.gz")) > 20)
        txt = open(os.path.join(res["backup_dir"], "rueckgaengig.sql")).read()
        self.assertIn("UPDATE j_users SET block = 0 WHERE id IN (3);", txt)
        self.assertIn("MANIFEST.txt", os.listdir(res["backup_dir"]))

    def test_last_active_admin_is_protected(self):
        r, w = t2.world()                       # Super User 1 aktiv, Super User 2 gesperrt
        res = run(r, w, "block_users", ["u:1"], cms="joomla")
        self.assertFalse(res["ok"])
        self.assertIn("alle Administratoren", res["error"])
        self.assertEqual(q(w, "SELECT block FROM j_users WHERE id=1")[0][0], 0)
        self.assertFalse(res.get("backup_dir"))                     # vor der Prüfung wird nichts angelegt

    def test_end_sessions(self):
        r, w = t2.world()
        q(w, "INSERT INTO j_session (session_id, client_id, guest, time, data, userid, username) VALUES ('s1',1,0,'1',' ',3,'a'),('s2',0,1,'1',' ',0,'')")
        res = actions.run_action(r, w["site_rel"], "end_sessions", {"cms": "joomla"}, CH)
        self.assertTrue(res["ok"], res)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_session")[0][0], 0)
        self.assertIn("Passwörter ändern", res["message"])

    def test_revoke_tokens_only_selected(self):
        r, w = t2.world()
        q(w, "INSERT INTO j_user_profiles VALUES (3,'joomlatoken.token','x',1),(3,'joomlatoken.enabled','1',2),(1,'joomlatoken.token','y',1),(3,'profile.city','Berlin',3)")
        res = run(r, w, "revoke_tokens", ["u:3"], cms="joomla")
        self.assertTrue(res["ok"], res)
        keys = {(a, b) for a, b in q(w, "SELECT user_id, profile_key FROM j_user_profiles")}
        self.assertEqual(keys, {(1, "joomlatoken.token"), (3, "profile.city")})
        self.assertTrue(os.path.exists(os.path.join(res["backup_dir"], "benutzerprofile.sql.gz")))

    def test_deactivate_skips_protected_ones(self):
        r, w = t2.world()
        q(w, "INSERT INTO j_extensions (extension_id,name,type,element,folder,client_id,enabled,manifest_cache,params,protected) VALUES "
             "(801,'Fremd','component','com_fremd','',1,1,'{\"author\":\"Eine Firma\"}','',0),"
             "(802,'Kern','component','com_kernig','',1,1,'{\"author\":\"Joomla! Project\"}','',0),"
             "(803,'Geschützt','plugin','sys','system',0,1,'{}','',1),"
             "(804,'Anmeldung','plugin','pwd','authentication',0,1,'{}','',0),"
             "(805,'Akeeba Backup','component','com_akeebabackup','',1,1,'{}','',0)")
        keys = ["e:component/-/com_fremd", "e:component/-/com_kernig", "e:plugin/system/sys", "e:plugin/authentication/pwd", "e:component/-/com_akeebabackup"]
        res = run(r, w, "deactivate_extension", keys)
        self.assertTrue(res["ok"], res)
        st = dict(q(w, "SELECT extension_id, enabled FROM j_extensions WHERE extension_id BETWEEN 801 AND 805"))
        self.assertEqual(st, {801: 0, 802: 1, 803: 1, 804: 1, 805: 1})
        txt = open(os.path.join(res["backup_dir"], "rueckgaengig.sql")).read()
        self.assertIn("SET enabled = 1 WHERE extension_id IN (801)", txt)

    def test_nothing_to_do_changes_nothing(self):
        r, w = t2.world()
        q(w, "INSERT INTO j_extensions (extension_id,name,type,element,folder,client_id,enabled,manifest_cache,params,protected) VALUES (806,'Aus','component','com_aus','',1,0,'{}','',0)")
        res = run(r, w, "deactivate_extension", ["e:component/-/com_aus"])
        self.assertTrue(res["ok"])
        self.assertFalse(res.get("backup_dir"))
        self.assertIn("nichts auszuschalten", res["message"])

    def test_no_backup_no_change(self):
        r, w = t2.world()
        broken = tempfile.mkdtemp(prefix="claudia_nodump_")
        t2.script(os.path.join(broken, "mysqldump"), "echo kaputt >&2; exit 2")
        r2 = LocalRunner(w["home"], extra_path=broken + os.pathsep + w["bin"])
        res = run(r2, w, "block_users", ["u:3"], cms="joomla") if False else actions.run_action(r2, w["site_rel"], "block_users", {"selected_pick": ["u:3"]}, CH)
        self.assertFalse(res["ok"])
        self.assertEqual(q(w, "SELECT block FROM j_users WHERE id=3")[0][0], 0)


def wp_world():
    r, w = test_wp.cli_world()
    b = w["bin"]
    open(os.path.join(w["home"], "active.txt"), "w").write("foo-plugin\nupdraftplus\nbar-plugin\n")
    test_wp.script(os.path.join(b, "php8.3"), r'''
if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
echo "php $*" >> "$HOME/php_calls.txt"
S="$HOME/active.txt"
case "$*" in
  *"plugin is-active "*) N=$(echo "$*" | sed 's/.*plugin is-active //; s/ .*//'); grep -qx "$N" "$S";;
  *"plugin deactivate "*) N=$(echo "$*" | sed 's/.*plugin deactivate //; s/ .*//'); grep -vx "$N" "$S" > "$S.n"; mv "$S.n" "$S"; echo "Success: Plugin '$N' deactivated.";;
  *) echo ok;;
esac''')
    return r, w


class WordPressRun(unittest.TestCase):
    def test_block_wp_user_removes_roles_and_password(self):
        r, w = wp_world()
        res = run(r, w, "block_users", ["u:3"], cms="wordpress")
        self.assertTrue(res["ok"], res)
        self.assertEqual(q(w, "SELECT meta_value FROM wp_usermeta WHERE user_id=3 AND meta_key='wp_capabilities'")[0][0], "a:0:{}")
        self.assertTrue(q(w, "SELECT user_pass FROM wp_users WHERE ID=3")[0][0].startswith("!"))
        self.assertEqual(q(w, "SELECT COUNT(*) FROM wp_usermeta WHERE user_id=3 AND meta_key IN ('session_tokens','_application_passwords')")[0][0], 0)
        self.assertNotEqual(q(w, "SELECT meta_value FROM wp_usermeta WHERE user_id=1 AND meta_key='wp_capabilities'")[0][0], "a:0:{}")
        self.assertTrue(os.path.exists(os.path.join(res["backup_dir"], "benutzer.sql.gz")))

    def test_wp_never_blocks_all_admins(self):
        r, w = wp_world()
        res = run(r, w, "block_users", ["u:1", "u:3", "u:4"], cms="wordpress")
        self.assertFalse(res["ok"])
        self.assertEqual(q(w, "SELECT COUNT(*) FROM wp_usermeta WHERE meta_key='wp_capabilities' AND meta_value='a:0:{}'")[0][0], 0)

    def test_wp_revoke_app_passwords_and_end_sessions(self):
        r, w = wp_world()
        res = run(r, w, "revoke_tokens", ["u:3"], cms="wordpress")
        self.assertTrue(res["ok"], res)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM wp_usermeta WHERE meta_key='_application_passwords' AND user_id=3")[0][0], 0)
        res = actions.run_action(r, w["site_rel"], "end_sessions", {"cms": "wordpress"}, CH)
        self.assertTrue(res["ok"], res)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM wp_usermeta WHERE meta_key='session_tokens'")[0][0], 0)

    def test_deactivate_plugin_protects_security_tools(self):
        r, w = wp_world()
        wpcli = os.path.join(w["home"], "wp-cli.phar")
        res = run(r, w, "wp_deactivate_plugin", ["p:foo-plugin", "p:updraftplus", "p:not-active", "p:Bad Name; rm"], wpcli=wpcli)
        self.assertTrue(res["ok"], res)
        act = open(os.path.join(w["home"], "active.txt")).read().split()
        self.assertEqual(sorted(act), ["bar-plugin", "updraftplus"])                 # nur foo-plugin ist aus; Sicherungs-Plugin bleibt
        self.assertIn("plugin activate foo-plugin", open(os.path.join(res["backup_dir"], "rueckgaengig.txt")).read())
        self.assertTrue(os.path.exists(os.path.join(res["backup_dir"], "options.sql.gz")))


class Server(unittest.TestCase):
    def test_pick_validation_in_extra(self):
        from claudia.server import App
        app = App.__new__(App)
        a = {"id": "block_users", "params": {"pick": [{"key": "u:3"}, {"key": "u:4"}]}}
        out = app._extra(a, {"pick": ["u:3", "u:99", "x", "u:3"]})
        self.assertEqual(out["selected_pick"], ["u:3"])
        with self.assertRaises(ApiError):
            app._extra(a, {"pick": ["u:99"]})


if __name__ == "__main__":
    unittest.main()
