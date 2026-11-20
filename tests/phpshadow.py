"""Hilfe für Tests mit gespielten PHP-Programmen: ein auf dem Testrechner echt installiertes PHP (z. B. php8.5 auf einem
GitHub-Runner) darf die Ergebnisse nicht verändern. Für jedes echt gefundene versionierte PHP legt die Hilfe in 'extra' eine
stumme Attrappe an, die nichts ausgibt; die gewünschten Attrappen ('keep') bleiben unberührt."""
import os
import shutil
import stat

VERSIONS = ("8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4")


def shadow_real_php(extra, keep=()):
    for v in VERSIONS:
        for name in ("php" + v, "php-" + v, "php" + v.replace(".", "")):
            if name in keep or os.path.exists(os.path.join(extra, name)):
                continue
            if shutil.which(name):
                path = os.path.join(extra, name)
                with open(path, "w") as fh:
                    fh.write("#!/bin/sh\nexit 1\n")
                os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
