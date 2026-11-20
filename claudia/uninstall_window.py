"""Deinstallations-Fenster im gleichen Aussehen wie der Startbildschirm (PySide6, siehe splash_qt.py; ohne PySide6 tkinter im gleichen Stil, siehe tkskin.py).

Die Datei wird samt splash_qt.py, tkskin.py und den Logos in einen Temp-Ordner kopiert und von dort gestartet, damit sie auch läuft, wenn der Programmordner gelöscht wird.
Läuft sie in der Python-Umgebung (.venv) des Programms (dort liegt PySide6), lässt sich diese Umgebung erst nach dem Schließen des Fensters löschen:
Ein unsichtbarer Hilfsprozess entfernt sie dann zusammen mit dem Programmordner. Aufruf: python uninstall_window.py plan.json"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List

TITLE = "CLAUDIA deinstallieren"

WINGET_ID_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)          # SYNCHRONIZE
            if not h:
                return False
            alive = ctypes.windll.kernel32.WaitForSingleObject(h, 0) == 0x102       # WAIT_TIMEOUT: läuft noch
            ctypes.windll.kernel32.CloseHandle(h)
            return alive
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_for(pids: List[int], log: Callable[[str], None], limit: float = 60.0) -> None:
    t0 = time.time()
    while any(pid_alive(p) for p in pids) and time.time() - t0 < limit:
        time.sleep(0.5)
    if any(pid_alive(p) for p in pids):
        log("Hinweis: Das Programm läuft noch. Es wird trotzdem weitergemacht.")


def _onerror(func, path, _exc) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def safe_path(p: str) -> bool:
    """Schutz gegen ein verändertes Skript: nur absolute, eindeutige Pfade, keine Laufwerks-/Home-Wurzel."""
    if not isinstance(p, str) or len(p) < 8 or any(c in p for c in '"\n\r\0') or not os.path.isabs(p):
        return False
    ap = os.path.normcase(os.path.abspath(p))
    if os.path.dirname(ap) == ap or ap == os.path.normcase(os.path.expanduser("~")):
        return False
    return not os.path.islink(p)


def remove_item(it: Dict[str, Any]) -> bool:
    p = it["path"]
    if not os.path.lexists(p):
        return True
    if os.path.isdir(p) and not os.path.islink(p):
        shutil.rmtree(p, onerror=_onerror)
    else:
        try:
            os.remove(p)
        except OSError:
            _onerror(os.remove, p, None)
    return not os.path.lexists(p)


def _inside(path: str, base: str) -> bool:
    a, b = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(base))
    return a == b or a.startswith(b + os.sep)


def running_prefix() -> str:
    """Läuft dieses Fenster in einer virtuellen Umgebung (.venv), deren Dateien in Benutzung sind? Dann deren Ordner (sonst leer)."""
    return sys.prefix if getattr(sys, "base_prefix", sys.prefix) != sys.prefix else ""


CLEANUP = r"""
import os, sys, time, shutil
pid = int(sys.argv[1])
def alive(p):
    if os.name == "nt":
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, p)
        if not h:
            return False
        r = ctypes.windll.kernel32.WaitForSingleObject(h, 0)
        ctypes.windll.kernel32.CloseHandle(h)
        return r == 258
    try:
        os.kill(p, 0)
        return True
    except OSError:
        return False
for _ in range(120):
    if not alive(pid):
        break
    time.sleep(0.5)
def rm(p):
    for _ in range(40):
        shutil.rmtree(p, ignore_errors=True)
        if not os.path.exists(p):
            return
        time.sleep(0.5)
for p in sys.argv[3:]:
    rm(p)
try:
    os.rmdir(sys.argv[2])
except OSError:
    pass
"""


def start_cleanup(paths: List[str], data_dir: str) -> bool:
    """Entfernt nach dem Schließen dieses Fensters, was in Benutzung war (Python-Umgebung, Programmordner), mit einem unsichtbaren Hilfsprozess."""
    paths = [p for p in paths if safe_path(p)]
    if not paths:
        return False
    exe = getattr(sys, "_base_executable", "") or sys.executable
    if os.name == "nt" and os.path.isfile(os.path.join(os.path.dirname(exe), "pythonw.exe")):
        exe = os.path.join(os.path.dirname(exe), "pythonw.exe")
    try:
        subprocess.Popen([exe, "-c", CLEANUP, str(os.getpid()), data_dir] + paths, cwd=os.path.dirname(os.path.abspath(data_dir)) or None, close_fds=True,
                         **({"creationflags": 0x00000008 | 0x08000000} if os.name == "nt" else {"start_new_session": True, "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}))
        return True
    except OSError:
        return False


def execute(items: List[Dict[str, Any]], pids: List[int], data_dir: str, log: Callable[[str], None], progress: Callable[[int, str, str], None], windows: bool = True,
            busy_prefix: str = "") -> Dict[str, Any]:
    """Löscht die Einträge nacheinander und meldet jeden Schritt. Rückgabe: {done, failed, winget, deferred}.
    busy_prefix = Ordner der Python-Umgebung, in der dieses Fenster selbst läuft: Sie lässt sich nicht löschen, solange sie benutzt wird;
    sie (und der Programmordner um sie herum) landen in 'deferred' und werden nach dem Schließen des Fensters entfernt."""
    n = max(1, len(items))
    progress(2, "Warte, bis CLAUDIA beendet ist ...", "Das Programm wird geschlossen, danach beginnt das Löschen.")
    wait_for(pids, log)
    done: List[str] = []
    failed: List[str] = []
    deferred: List[str] = []
    winget = False
    for k, it in enumerate(items):
        pct = 5 + int(90 * k / n)
        label = it.get("label", "?")
        if it.get("kind") == "winget":
            winget = True
            log("Python (winget): wird zum Schluss in einem eigenen Fenster entfernt.")
            continue
        progress(pct, "Entferne: %s" % label, it.get("path", ""))
        if not safe_path(it.get("path", "")):
            failed.append(label)
            log("ÜBERSPRUNGEN (unsicherer Pfad): %s" % label)
            continue
        ok = False
        try:
            if busy_prefix and _inside(busy_prefix, it["path"]):
                if os.path.normcase(os.path.abspath(busy_prefix)) != os.path.normcase(os.path.abspath(it["path"])) and os.path.isdir(it["path"]):
                    for name in os.listdir(it["path"]):                      # Programmordner: alles außer dem Zweig mit der benutzten Umgebung sofort löschen
                        child = os.path.join(it["path"], name)
                        if not _inside(busy_prefix, child):
                            remove_item({"path": child})
                deferred.append(it["path"])
                log("danach     %s  (wird nach dem Schließen dieses Fensters entfernt, weil das Fenster selbst darin läuft)" % label)
                done.append(label)
                continue
            ok = remove_item(it)
        except OSError as e:
            log("   Fehler: %s" % e)
        (done if ok else failed).append(label)
        log("%s  %s" % ("erledigt " if ok else "FEHLER   ", label) + ("" if ok else "  (bitte von Hand löschen: %s)" % it.get("path", "")))
    if not deferred:
        try:
            os.rmdir(data_dir)
        except OSError:
            pass
    progress(100, "Fertig" if not failed else "Fertig, aber nicht alles ließ sich entfernen", "%d Einträge entfernt, %d nicht." % (len(done), len(failed)))
    return {"done": done, "failed": failed, "winget": winget, "deferred": deferred}


def start_winget(pid_id: str) -> None:
    if os.name != "nt" or not pid_id or any(c not in WINGET_ID_OK for c in pid_id):
        return
    subprocess.Popen(["cmd", "/c", "timeout /t 6 /nobreak >nul & winget uninstall -e --id %s & pause" % pid_id], creationflags=0x00000010, close_fds=True)


def summary_text(res: Dict[str, Any]) -> str:
    lines = ["%d Einträge entfernt." % len(res["done"])]
    if res.get("deferred"):
        lines.append("Die Python-Umgebung und der Programmordner werden gleich nach dem Schließen dieses Fensters im Hintergrund entfernt.")
    if res["failed"]:
        lines.append("Nicht entfernt (bitte von Hand löschen): " + ", ".join(res["failed"]))
    if res.get("winget"):
        lines.append("Python wird anschließend in einem eigenen Fenster mit winget entfernt.")
    return "\n".join(lines)


def run_qt(items: List[Dict[str, Any]], pids: List[int], data_dir: str, winget_id: str) -> int:
    """Deinstallationsfenster im Layout des Startbildschirms (PySide6, siehe splash_qt.py)."""
    import splash_qt as sq
    from PySide6.QtCore import QObject, Qt, Signal, Slot
    from PySide6.QtWidgets import QApplication, QMessageBox

    class Bridge(QObject):
        update = Signal(int, str)
        done = Signal(object)

    app = QApplication.instance() or QApplication(sys.argv[:1])
    win = sq.Splash()
    win.setWindowTitle(TITLE)
    bridge = Bridge()
    state = {"finished": False}
    bridge.update.connect(win.set_progress)
    win.closed_by_user.connect(lambda: app.quit() if state["finished"] else win.set_status("Bitte warten, bis die Deinstallation fertig ist."))
    result: Dict[str, Any] = {}

    def work() -> None:
        res = execute(items, pids, data_dir, lambda s: None, lambda p, t, d: bridge.update.emit(int(p), t + ((" - " + d) if d else "")), busy_prefix=running_prefix())
        bridge.done.emit(res)

    @Slot(object)
    def finish(res: Dict[str, Any]) -> None:
        result.update(res)
        state["finished"] = True
        win.setWindowFlag(Qt.WindowStaysOnTopHint, False)
        win.hide()
        box = QMessageBox(QMessageBox.Warning if res["failed"] else QMessageBox.Information, TITLE, summary_text(res))
        box.exec()
        if res.get("deferred"):
            start_cleanup(res["deferred"], data_dir)
        if res["winget"]:
            start_winget(winget_id)
        app.quit()

    bridge.done.connect(finish)
    threading.Thread(target=work, daemon=True).start()
    win.fade_in()
    app.exec()
    return 0


def run_tk(items: List[Dict[str, Any]], pids: List[int], data_dir: str, winget_id: str) -> int:
    """Ersatz, wenn PySide6 fehlt: tkinter im gleichen Aussehen (tkskin.py)."""
    import queue
    import tkinter as tk
    import tkskin
    q: "queue.Queue" = queue.Queue()
    root = tk.Tk()
    root.title(TITLE)
    try:
        scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
    except Exception:
        scale = 1.0
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    w, h = min(int(765 * scale), sw - 60), min(int(560 * scale), sh - 100)
    root.geometry("%dx%d+%d+%d" % (w, h, max(0, (sw - w) // 2), max(0, (sh - h) // 2 - 20)))
    root.minsize(int(620 * scale), int(460 * scale))
    skin = tkskin.Skin(root, scale, os.path.dirname(os.path.abspath(__file__)), True, "Bereit")
    close_btn = skin.button(skin.buttons, "Schließen", root.destroy, "disabled")
    close_btn.pack(side="right")
    result: Dict[str, Any] = {}

    def work() -> None:
        result.update(execute(items, pids, data_dir, lambda s: q.put(("log", s)), lambda p, t, d: q.put(("update", (p, t, d))), busy_prefix=running_prefix()))
        q.put(("end", None))

    def poll() -> None:
        try:
            while True:
                kind, data = q.get_nowait()
                if kind == "update":
                    skin.set_pct(data[0])
                    skin.title_var.set(data[1])
                    skin.detail_var.set(data[2])
                elif kind == "log":
                    skin.add_log(data, "bad" if data.startswith(("FEHLER", "ÜBERSPRUNGEN")) else ("ok" if data.startswith("erledigt") else ()))
                elif kind == "end":
                    close_btn.configure(state="normal")
                    if result.get("deferred"):
                        start_cleanup(result["deferred"], data_dir)
                        skin.detail_var.set(summary_text(result))
                    if result.get("winget"):
                        skin.detail_var.set("Python wird jetzt in einem eigenen Fenster mit winget entfernt. Dieses Fenster schließt sich gleich.")
                        start_winget(winget_id)
                        root.after(4000, root.destroy)
                    return
        except queue.Empty:
            pass
        root.after(80, poll)

    threading.Thread(target=work, daemon=True).start()
    root.after(80, poll)
    root.mainloop()
    return 0


def main(argv: List[str]) -> int:
    with open(argv[1], encoding="utf-8") as fh:
        plan = json.load(fh)
    items, pids, data_dir = plan["items"], [int(p) for p in plan["pids"]], plan["data_dir"]
    winget_id = plan.get("winget_id", "")
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    code = None
    try:
        import splash_qt  # noqa: F401
        have_qt = True
    except Exception:
        have_qt = False
    if have_qt:
        code = run_qt(items, pids, data_dir, winget_id)
    else:
        try:
            import tkskin  # noqa: F401
            have_tk = True
        except Exception:
            have_tk = False
        if have_tk:
            code = run_tk(items, pids, data_dir, winget_id)
        else:
            res = execute(items, pids, data_dir, print, lambda p, t, d: print("%3d %%  %s" % (p, t)))
            if res["winget"]:
                start_winget(winget_id)
            code = 0 if not res["failed"] else 1
    for p in {argv[1], os.path.abspath(__file__)}:
        try:
            os.remove(p)
        except OSError:
            pass
    if os.path.basename(here).startswith("claudia-deinstallation-"):          # nur der eigene Temp-Ordner, nie ein Quellordner
        shutil.rmtree(here, ignore_errors=True)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
