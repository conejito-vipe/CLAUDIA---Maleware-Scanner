"""Test-Attrappe für 'paramiko' (nur zum Testen des Adapters ohne echten SSH-Server).

Bildet die Teile der paramiko-Schnittstelle nach, die claudia/runner.py benutzt, und führt die
Befehle lokal mit bash aus. Das echte paramiko wird von start.bat auf dem PC installiert.
"""
import os
import socket
import subprocess
import threading
import time


class SSHException(Exception):
    pass


class AuthenticationException(SSHException):
    pass


class MissingHostKeyPolicy:
    def missing_host_key(self, client, hostname, key):  # pragma: no cover
        raise NotImplementedError


class _Key:
    def __init__(self, data=b"fake-host-key-bytes"):
        self._data = data

    def get_name(self):
        return "ssh-ed25519"

    def asbytes(self):
        return self._data


CONFIG = {
    "home": "/tmp",
    "password": "pw",
    "host_key": b"fake-host-key-bytes",
    "known_host": "fake.example.org",
    "extra_path": "",
    "fail": None,   # "dns" | "timeout" | "refused"
}


class _Channel:
    def __init__(self):
        self._out = b""
        self._err = b""
        self._rc = None
        self._proc = None
        self._lock = threading.Lock()

    def settimeout(self, t):
        pass

    def exec_command(self, command):
        env = dict(os.environ)
        env["HOME"] = CONFIG["home"]
        if CONFIG["extra_path"]:
            env["PATH"] = CONFIG["extra_path"] + os.pathsep + env.get("PATH", "")
        self._stdin = b""
        self._stdin_done = threading.Event()
        self._proc = subprocess.Popen(["bash", "-c", command], cwd=CONFIG["home"], env=env,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=self._pump, daemon=True).start()

    def sendall(self, data):
        self._stdin += data

    def shutdown_write(self):
        self._stdin_done.set()

    def _pump(self):
        self._stdin_done.wait(5)
        out, err = self._proc.communicate(self._stdin)
        with self._lock:
            self._out, self._err = out, err
            self._rc = self._proc.returncode

    def recv_ready(self):
        with self._lock:
            return bool(self._out)

    def recv_stderr_ready(self):
        with self._lock:
            return bool(self._err)

    def recv(self, n):
        with self._lock:
            d, self._out = self._out[:n], self._out[n:]
            return d

    def recv_stderr(self, n):
        with self._lock:
            d, self._err = self._err[:n], self._err[n:]
            return d

    def exit_status_ready(self):
        with self._lock:
            return self._rc is not None

    def recv_exit_status(self):
        while True:
            with self._lock:
                if self._rc is not None:
                    return self._rc
            time.sleep(0.01)

    def close(self):
        if self._proc and self._proc.poll() is None:
            self._proc.kill()


class _Transport:
    def __init__(self):
        self.active = True

    def is_active(self):
        return self.active

    def open_session(self):
        return _Channel()

    def set_keepalive(self, n):
        pass

    remote_cipher = "aes256-ctr"
    remote_mac = "hmac-sha2-256"
    remote_version = "SSH-2.0-OpenSSH_9.6"

    def get_remote_server_key(self):
        return _Key(CONFIG["host_key"])


class SSHClient:
    def __init__(self):
        self._policy = None
        self._transport = None

    def set_missing_host_key_policy(self, policy):
        self._policy = policy

    def connect(self, hostname, port=22, username=None, password=None, timeout=None, banner_timeout=None,
                auth_timeout=None, allow_agent=True, look_for_keys=True, key_filename=None, passphrase=None, disabled_algorithms=None):
        if CONFIG["fail"] == "dns":
            raise socket.gaierror(-2, "Name or service not known")
        if CONFIG["fail"] == "timeout":
            raise socket.timeout("timed out")
        CONFIG.setdefault("seen_disabled", []).append(disabled_algorithms)
        if CONFIG["fail"] == "legacy" and disabled_algorithms:
            raise SSHException("Incompatible ssh peer (no acceptable kex algorithm)")
        if CONFIG["fail"] == "refused":
            raise ConnectionRefusedError()
        self._policy.missing_host_key(self, hostname, _Key(CONFIG["host_key"]))
        if password != CONFIG["password"]:
            raise AuthenticationException("Authentication failed.")
        self._transport = _Transport()

    def get_transport(self):
        return self._transport

    def close(self):
        if self._transport:
            self._transport.active = False
        self._transport = None
