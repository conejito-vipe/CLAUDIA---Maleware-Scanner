#!/bin/bash
# CLAUDIA: Startdatei für den Mac (Doppelklick im Finder oder: bash start.command im Terminal).
# Sie richtet alles selbst ein (Python, Bausteine, Startbildschirm) und startet CLAUDIA. Es muss nichts von Hand installiert werden.
# Protokoll: ~/Library/Application Support/CLAUDIA/start.log
# Beim ersten Öffnen fragt macOS evtl. nach, weil die Datei aus dem Internet stammt: Rechtsklick > Öffnen > Öffnen.
cd "$(dirname "$0")" || exit 1
LOGDIR="$HOME/Library/Application Support/CLAUDIA"
LOG="$LOGDIR/start.log"
mkdir -p "$LOGDIR" 2>/dev/null

logline() { printf '%s start.command: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null; }
pause_exit() { echo; read -r -n 1 -s -p "  Beliebige Taste zum Schließen ..."; echo; exit "$1"; }

if [ ! -f claudia/launcher.py ]; then
    echo
    echo "  CLAUDIA wurde nicht aus einem entpackten Ordner gestartet."
    echo "  Bitte die ZIP-Datei zuerst entpacken (Doppelklick auf die ZIP-Datei im Finder)"
    echo "  und dann start.command im entpackten Ordner öffnen."
    pause_exit 1
fi

# Python 3.9 oder neuer suchen. Das Python des Systems (/usr/bin/python3) wird nur benutzt, wenn die Entwicklerwerkzeuge schon installiert sind,
# sonst würde macOS ein Installationsfenster dafür öffnen.
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' >/dev/null 2>&1; }
find_python() {
    PY=""
    local c
    for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3 \
             /opt/homebrew/bin/python3 /usr/local/bin/python3 \
             /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
             /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
             /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
             /Library/Frameworks/Python.framework/Versions/3.10/bin/python3 \
             /Library/Frameworks/Python.framework/Versions/3.9/bin/python3 \
             /usr/bin/python3; do
        case "$c" in
            /*) [ -x "$c" ] || continue ;;
            *) command -v "$c" >/dev/null 2>&1 || continue; c="$(command -v "$c")" ;;
        esac
        if [ "$c" = "/usr/bin/python3" ] && ! xcode-select -p >/dev/null 2>&1; then
            continue
        fi
        if py_ok "$c"; then
            PY="$c"
            return 0
        fi
    done
    return 1
}

install_python() {
    local ver="3.12.10" name url tmp pkg sig
    name="python-$ver-macos11.pkg"
    url="https://www.python.org/ftp/python/$ver/$name"
    echo
    echo "  CLAUDIA"
    echo "  -----------------------"
    echo "  Python 3.9 oder neuer wurde nicht gefunden."
    echo "  CLAUDIA lädt Python jetzt automatisch von python.org herunter (ca. 45 MB),"
    echo "  prüft die digitale Signatur und installiert es. Dafür fragt macOS gleich"
    echo "  nach deinem Mac-Passwort (Administrator). Das dauert ein bis zwei Minuten."
    echo "  Bitte dieses Fenster offen lassen, es geht danach von selbst weiter."
    echo
    logline "Python nicht gefunden, Installation wird versucht ($ver)"
    if [ -n "$CLAUDIA_START_DRYRUN" ]; then echo "INSTALL $url"; return 0; fi
    tmp="$(mktemp -d)" || return 1
    pkg="$tmp/$name"
    if ! curl -fL --proto '=https' --tlsv1.2 -o "$pkg" "$url" >>"$LOG" 2>&1; then
        logline "Download fehlgeschlagen"
        rm -rf "$tmp"
        return 1
    fi
    sig="$(pkgutil --check-signature "$pkg" 2>&1)"
    if ! printf '%s' "$sig" | grep -q "Python Software Foundation" || ! printf '%s' "$sig" | grep -qi "signed by"; then
        logline "Die digitale Signatur des Installers ist nicht in Ordnung. Der Installer wird nicht ausgeführt."
        echo "  Die digitale Signatur des Installers ist nicht in Ordnung. Er wird nicht ausgeführt."
        rm -rf "$tmp"
        return 1
    fi
    echo "  Signatur geprüft: Python Software Foundation, gültig."
    logline "Signatur geprüft: Python Software Foundation, gültig"
    if ! osascript -e "do shell script \"/usr/sbin/installer -pkg '$pkg' -target /\" with administrator privileges" >>"$LOG" 2>&1; then
        logline "Installer meldete einen Fehler oder wurde abgebrochen"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    # Zertifikate für sichere Verbindungen einrichten (empfohlener Schritt von python.org)
    cert="/Applications/Python 3.12/Install Certificates.command"
    [ -x "$cert" ] && "$cert" >>"$LOG" 2>&1 </dev/null
    echo python.org > "$LOGDIR/python_von_claudia_pyorg.txt" 2>/dev/null
    echo "  Python ist installiert. CLAUDIA startet jetzt automatisch weiter."
    echo
    logline "Python installiert"
    return 0
}

python_failed() {
    echo
    echo "  Python konnte nicht automatisch eingerichtet werden."
    echo "  Mögliche Ursachen: keine Internetverbindung, eine Firewall blockiert den Download"
    echo "  von python.org, oder die Passwortabfrage wurde abgebrochen."
    echo "  Das Protokoll steht in: $LOG"
    echo
    echo "  Wenn sich das nicht beheben lässt, bitte Python von Hand installieren:"
    echo "  https://www.python.org/downloads/macos/  und danach start.command erneut öffnen."
    pause_exit 1
}

find_python
if [ -z "$PY" ]; then
    install_python
    find_python
fi
if [ -n "$CLAUDIA_START_DRYRUN" ]; then echo "PY=$PY"; exit 0; fi
[ -n "$PY" ] || python_failed
logline "Python: $PY"

# Beim allerersten Start: Startbildschirm (PySide6) einmalig einrichten, damit alle Fenster gleich aussehen
if [ ! -f .venv/qt.ok ]; then
    echo
    echo "  CLAUDIA richtet beim ersten Start einmalig den Startbildschirm ein"
    echo "  (Download von pypi.org, ca. 80 MB). Bitte warten. Danach öffnet sich CLAUDIA von selbst."
    echo
    "$PY" -m claudia.launcher --bootstrap
fi

nohup "$PY" -m claudia.launcher >/dev/null 2>&1 &
disown 2>/dev/null
echo "  CLAUDIA startet in einem eigenen Fenster. Dieses Terminal-Fenster kann geschlossen werden."
exit 0
