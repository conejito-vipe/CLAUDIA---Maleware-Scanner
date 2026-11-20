"""Ausführung von Befehlen: per SSH (paramiko) oder lokal (nur für Tests/Demo).

Es werden ausschließlich lesende Befehle abgesetzt. Der Runner selbst kennt keine
Schreiboperationen auf dem Server.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, Optional

from . import secure
from .util import atomic_write, sq

MAX_OUTPUT = 12 * 1024 * 1024   # Schutz: mehr als 12 MB Ausgabe pro Befehl werden abgeschnitten


class RunnerError(Exception):
    pass


class MissingDependency(RunnerError):
    pass


class ConnectFailed(RunnerError):
    pass


class AuthFailed(RunnerError):
    pass


class WeakCrypto(RunnerError):
    """Der Server beherrscht keines der modernen Verfahren. Verbunden wird nur nach ausdrücklicher Bestätigung."""


class HostKeyUnknown(RunnerError):
    def __init__(self, fingerprint: str, key_type: str):
        super().__init__("Unbekannter Server-Schlüssel")
        self.fingerprint = fingerprint
        self.key_type = key_type


class HostKeyChanged(RunnerError):
    def __init__(self, known: str, seen: str):
        super().__init__("Der Server-Schlüssel hat sich geändert")
        self.known = known
        self.seen = seen


class ShResult:
    __slots__ = ("out", "err", "rc", "timed_out", "truncated")

    def __init__(self, out: str = "", err: str = "", rc: int = 0, timed_out: bool = False, truncated: bool = False):
        self.out, self.err, self.rc, self.timed_out, self.truncated = out, err, rc, timed_out, truncated

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


class FetchResult:
    __slots__ = ("nbytes", "err", "rc", "timed_out", "cancelled", "too_big")

    def __init__(self, nbytes: int = 0, err: str = "", rc: int = 0, timed_out: bool = False, cancelled: bool = False, too_big: bool = False):
        self.nbytes, self.err, self.rc = nbytes, err, rc
        self.timed_out, self.cancelled, self.too_big = timed_out, cancelled, too_big

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not (self.timed_out or self.cancelled or self.too_big)


def wrap_script(site_dir: str, script: str, nice: bool = True) -> str:
    """Packt ein Bash-Skript so ein, dass es im Joomla-Verzeichnis läuft (niedrige Priorität)."""
    prefix = "cd -- %s 2>/dev/null || { echo 'CLAUDIA_NO_SITE_DIR' >&2; exit 97; }; export LC_ALL=C; " % sq(site_dir)
    cmd = "bash -c " + sq(prefix + script)
    if nice:
        cmd = "nice -n 15 " + cmd
    return cmd


class Runner:
    """Basisklasse."""
    label = "runner"

    def run(self, command: str, timeout: float = 120.0, stdin: Optional[str] = None) -> ShResult:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        pass

    def sh(self, site_dir: str, script: str, timeout: float = 120.0, stdin: Optional[str] = None) -> ShResult:
        return self.run(wrap_script(site_dir, script), timeout, stdin)

    def fetch(self, command: str, fh, timeout: float = 600.0, max_bytes: int = 0,
              cancel: Optional[threading.Event] = None, progress=None) -> "FetchResult":  # pragma: no cover
        """Führt einen lesenden Befehl aus und schreibt dessen BINÄRE Ausgabe in die offene Datei 'fh' (für Protokoll-Downloads)."""
        raise NotImplementedError


# ------------------------------------------------------------------ lokal (Tests/Demo)
class LocalRunner(Runner):
    """Führt Befehle lokal aus. 'home' ersetzt das Home-Verzeichnis des SSH-Benutzers."""
    label = "local"

    def __init__(self, home: str, extra_path: Optional[str] = None):
        self.home = home
        self.extra_path = extra_path

    def run(self, command: str, timeout: float = 120.0, stdin: Optional[str] = None) -> ShResult:
        env = dict(os.environ)
        env["HOME"] = self.home
        if self.extra_path:
            env["PATH"] = self.extra_path + os.pathsep + env.get("PATH", "")
        try:
            p = subprocess.run(
                ["bash", "-c", command], cwd=self.home, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                input=(stdin or "").encode("utf-8"),
            )
        except subprocess.TimeoutExpired as e:
            return ShResult((e.stdout or b"").decode("utf-8", "replace"), (e.stderr or b"").decode("utf-8", "replace"), 124, True)
        out = p.stdout
        trunc = False
        if len(out) > MAX_OUTPUT:
            out, trunc = out[:MAX_OUTPUT], True
        return ShResult(out.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), p.returncode, False, trunc)


    def fetch(self, command, fh, timeout=600.0, max_bytes=0, cancel=None, progress=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        if self.extra_path:
            env["PATH"] = self.extra_path + os.pathsep + env.get("PATH", "")
        n = 0
        start = time.monotonic()
        timed_out = cancelled = too_big = False
        with tempfile.TemporaryFile() as errf:
            p = subprocess.Popen(["bash", "-c", command], cwd=self.home, env=env, stdout=subprocess.PIPE, stderr=errf)
            try:
                while True:
                    d = p.stdout.read(65536)
                    if not d:
                        break
                    fh.write(d)
                    n += len(d)
                    if progress:
                        progress(n)
                    if max_bytes and n > max_bytes:
                        too_big = True
                        break
                    if cancel is not None and cancel.is_set():
                        cancelled = True
                        break
                    if time.monotonic() - start > timeout:
                        timed_out = True
                        break
            finally:
                if timed_out or cancelled or too_big:
                    p.kill()
                p.stdout.close()
                rc = p.wait()
            errf.seek(0)
            err = errf.read(4096)
        return FetchResult(n, err.decode("utf-8", "replace"), 124 if timed_out else rc, timed_out, cancelled, too_big)


# ------------------------------------------------------------------ Host-Key-Speicher
class KnownHosts:
    """Eigene, einfache Liste vertrauter Server-Fingerabdrücke (JSON)."""

    def __init__(self, path: Optional[str]):
        self.path = path
        self._lock = threading.Lock()
        self._data: Dict[str, str] = {}
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self._data = json.load(fh)
            except (OSError, ValueError):
                self._data = {}

    def get(self, host_id: str) -> Optional[str]:
        return self._data.get(host_id)

    def set(self, host_id: str, fp: str) -> None:
        with self._lock:
            self._data[host_id] = fp
            if self.path:
                try:
                    os.makedirs(os.path.dirname(self.path), exist_ok=True)
                    atomic_write(self.path, json.dumps(self._data, indent=2))
                except OSError:
                    pass


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


# ------------------------------------------------------------------ SSH
class SSHRunner(Runner):
    label = "ssh"

    def __init__(self, host: str, port: int, user: str, password: str = "", key_file: str = "",
                 key_pass: str = "", known_hosts: Optional[KnownHosts] = None, trusted_fp: str = "",
                 timeout: float = 25.0, allow_weak: bool = False):
        self.host, self.port, self.user = host.strip(), int(port or 22), user.strip()
        self.password, self.key_file, self.key_pass = password, key_file.strip(), key_pass
        self.known = known_hosts or KnownHosts(None)
        self.trusted_fp = trusted_fp
        self.allow_weak = allow_weak
        self.timeout = timeout
        self.client = None
        self.fp = ""

    @property
    def host_id(self) -> str:
        return "%s:%d" % (self.host.lower(), self.port)

    def connect(self) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as e:
            raise MissingDependency(
                "Das Python-Paket 'paramiko' fehlt. Bitte das Programm über start.bat bzw. start.command starten "
                "(installiert es automatisch) oder 'pip install paramiko' ausführen."
            ) from e

        runner = self

        class Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):  # noqa: N802 (paramiko API)
                fp = fingerprint(key)
                runner.fp = fp
                known = runner.known.get(runner.host_id)
                if known:
                    if known == fp:
                        return
                    raise HostKeyChanged(known, fp)
                if runner.trusted_fp and runner.trusted_fp == fp:
                    runner.known.set(runner.host_id, fp)
                    return
                raise HostKeyUnknown(fp, key.get_name())

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(Policy())
        kwargs = dict(
            hostname=self.host, port=self.port, username=self.user,
            timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
            allow_agent=False, look_for_keys=False,
        )
        if self.password:
            kwargs["password"] = self.password
        if self.key_file:
            kwargs["key_filename"] = self.key_file
            if self.key_pass:
                kwargs["passphrase"] = self.key_pass
        # Zuerst nur moderne Verfahren zulassen. Sehr alte Server, die nichts anderes können, werden nur nach ausdrücklicher Bestätigung (allow_weak) zugelassen.
        self.weak_fallback = False
        kwargs["disabled_algorithms"] = dict(secure.STRICT_DISABLED)
        try:
            try:
                client.connect(**kwargs)
            except paramiko.SSHException as e:
                if isinstance(e, paramiko.AuthenticationException) or not re.search(r"incompatible|no acceptable|unable to agree|negotiat", str(e), re.I):
                    raise
                client.close()
                if not self.allow_weak:
                    raise WeakCrypto("Der Server bietet nur veraltete Verschlüsselungsverfahren an (%s)." % str(e)[:160]) from e
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(Policy())
                kwargs.pop("disabled_algorithms", None)
                self.weak_fallback = True
                client.connect(**kwargs)
        except (HostKeyUnknown, HostKeyChanged):
            client.close()
            raise
        except paramiko.AuthenticationException as e:
            client.close()
            raise AuthFailed("Anmeldung abgelehnt (Benutzername oder Passwort falsch?).") from e
        except socket.gaierror as e:
            client.close()
            raise ConnectFailed("Der Servername '%s' wurde nicht gefunden." % self.host) from e
        except (socket.timeout, TimeoutError) as e:
            client.close()
            raise ConnectFailed("Zeitüberschreitung beim Verbinden (Host/Port richtig? Firewall?).") from e
        except ConnectionRefusedError as e:
            client.close()
            raise ConnectFailed("Verbindung abgelehnt (läuft SSH auf Port %d?)." % self.port) from e
        except paramiko.SSHException as e:
            client.close()
            raise ConnectFailed("SSH-Fehler: %s" % e) from e
        except OSError as e:
            client.close()
            raise ConnectFailed("Netzwerkfehler: %s" % e) from e
        try:
            tr = client.get_transport()
            if tr:
                tr.set_keepalive(30)
        except Exception:  # pragma: no cover
            pass
        self.client = client

    def security_info(self) -> Dict[str, Any]:
        """Wie ist die Verbindung geschützt? (Verfahren und Fingerabdruck des Servers, keine Geheimnisse)"""
        info: Dict[str, Any] = {"protocol": "SSH-2", "cipher": "", "mac": "", "host_key_type": "", "server": "", "weak": []}
        try:
            tr = self.client.get_transport() if self.client else None
            if tr is not None:
                info.update(secure.describe_transport(tr))
        except Exception:
            pass
        info["fingerprint"] = self.fp
        info["weak_fallback"] = bool(getattr(self, "weak_fallback", False))
        info["encrypted"] = True
        return info

    def run(self, command: str, timeout: float = 120.0, stdin: Optional[str] = None) -> ShResult:
        if self.client is None:
            raise RunnerError("Keine SSH-Verbindung.")
        tr = self.client.get_transport()
        if tr is None or not tr.is_active():
            raise RunnerError("Die SSH-Verbindung wurde getrennt.")
        chan = tr.open_session()
        chan.settimeout(0.5)
        chan.exec_command(command)
        if stdin:
            chan.sendall(stdin.encode("utf-8"))   # z. B. Datenbankpasswort: nie in der Befehlszeile
        try:
            chan.shutdown_write()
        except Exception:  # pragma: no cover
            pass
        out, err = bytearray(), bytearray()
        start = time.monotonic()
        timed_out = truncated = False
        while True:
            got = False
            if chan.recv_ready():
                d = chan.recv(65536)
                if d:
                    got = True
                    if len(out) < MAX_OUTPUT:
                        out += d
                    else:
                        truncated = True
            if chan.recv_stderr_ready():
                d = chan.recv_stderr(65536)
                if d:
                    got = True
                    if len(err) < 1024 * 1024:
                        err += d
            if time.monotonic() - start > timeout:
                timed_out = True
                break
            if not got:
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                time.sleep(0.03)
        rc = 124 if timed_out else chan.recv_exit_status()
        try:
            chan.close()
        except Exception:  # pragma: no cover
            pass
        return ShResult(out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), rc, timed_out, truncated)

    def fetch(self, command, fh, timeout=600.0, max_bytes=0, cancel=None, progress=None):
        if self.client is None:
            raise RunnerError("Keine SSH-Verbindung.")
        tr = self.client.get_transport()
        if tr is None or not tr.is_active():
            raise RunnerError("Die SSH-Verbindung wurde getrennt.")
        chan = tr.open_session()
        chan.settimeout(0.5)
        chan.exec_command(command)
        try:
            chan.shutdown_write()
        except Exception:  # pragma: no cover
            pass
        err = bytearray()
        n = 0
        start = time.monotonic()
        timed_out = cancelled = too_big = False
        while True:
            got = False
            if chan.recv_ready():
                d = chan.recv(65536)
                if d:
                    got = True
                    fh.write(d)
                    n += len(d)
                    if progress:
                        progress(n)
                    if max_bytes and n > max_bytes:
                        too_big = True
                        break
            if chan.recv_stderr_ready():
                d = chan.recv_stderr(65536)
                if d:
                    got = True
                    if len(err) < 4096:
                        err += d
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            if time.monotonic() - start > timeout:
                timed_out = True
                break
            if not got:
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                time.sleep(0.01)
        rc = 124 if (timed_out or cancelled or too_big) else chan.recv_exit_status()
        try:
            chan.close()
        except Exception:  # pragma: no cover
            pass
        return FetchResult(n, err.decode("utf-8", "replace"), rc, timed_out, cancelled, too_big)

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:  # pragma: no cover
                pass
            self.client = None
