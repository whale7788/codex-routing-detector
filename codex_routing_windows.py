"""Temporarily route packaged Codex Desktop through the monitor without changing the system proxy."""
from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

if os.name == "nt":
    import winreg

INTERNET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_NAMES = ("ProxyEnable", "ProxyServer", "AutoConfigURL")
ENVIRONMENT = "Environment"
DESKTOP_ENV_NAMES = ("WS_PROXY", "WSS_PROXY", "ws_proxy", "wss_proxy", "CODEX_CA_CERTIFICATE")
DOTENV_PROXY_NAMES = frozenset(("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "WS_PROXY", "WSS_PROXY",
                                 "http_proxy", "https_proxy", "all_proxy", "ws_proxy", "wss_proxy"))
_DOTENV_KEY = re.compile(rb"^\s*(?:export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*=")


def _backup_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return root / "codex-routing-detector" / "desktop-session.json"


def _dotenv_path() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / ".env"


def _line_key(line: bytes) -> Optional[str]:
    match = _DOTENV_KEY.match(line)
    if match:
        key = match.group(1).decode("ascii")
        if key in DOTENV_PROXY_NAMES:
            return key
    return None


def _line_ending(line: bytes) -> bytes:
    return b"\r\n" if line.endswith(b"\r\n") else (b"\n" if line.endswith(b"\n") else b"")


def _write_dotenv(path: Path, data: bytes) -> None:
    """Replace the file atomically, leaving the old bytes intact if writing fails."""
    if path.is_symlink():
        raise RuntimeError(f"{path} is a symlink; cannot safely edit it")
    mode = stat.S_IMODE(path.stat().st_mode)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".crd-env-", suffix=".tmp",
                                         delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _plan_dotenv(path: Path, url: str) -> Tuple[Optional[dict], Optional[bytes]]:
    """Change only proxy entries already present; retain no_proxy and every other line."""
    if not path.exists():
        return None, None
    if path.is_symlink():
        raise RuntimeError(f"{path} is a symlink; cannot safely edit it")
    original = path.read_bytes()
    lines = original.splitlines(keepends=True)
    saved = {}
    patched = []
    for line in lines:
        key = _line_key(line)
        if key:
            if key in saved:
                raise RuntimeError(f"duplicate {key} in {path}; cannot safely monitor Desktop")
            saved[key] = base64.b64encode(line).decode("ascii")
            line = key.encode("ascii") + b"=" + url.encode("ascii") + _line_ending(line)
        patched.append(line)
    if not saved:
        return None, None
    return {"path": str(path), "url": url, "original": saved,
            "before_sha256": hashlib.sha256(original).hexdigest()}, b"".join(patched)


def _restore_dotenv(snapshot: Optional[dict]) -> None:
    if not snapshot:
        return
    path = Path(snapshot["path"])
    if not path.exists():
        return
    original = snapshot["original"]
    expected = {key: key.encode("ascii") + b"=" + snapshot["url"].encode("ascii")
                for key in original}
    changed = False
    restored = []
    for line in path.read_bytes().splitlines(keepends=True):
        key = _line_key(line)
        ending = _line_ending(line)
        body = line[:-len(ending)] if ending else line
        if key in expected and body == expected[key]:
            line = base64.b64decode(original[key], validate=True)
            changed = True
        restored.append(line)
    if changed:
        _write_dotenv(path, b"".join(restored))


def _read_values(key: str, names: tuple) -> dict:
    out = {name: None for name in names}
    try:
        handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)
    except FileNotFoundError:
        return out
    with handle:
        for name in names:
            try:
                value, kind = winreg.QueryValueEx(handle, name)
                out[name] = [value, kind]
            except FileNotFoundError:
                pass
    return out


def _write_values(key: str, values: dict) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as handle:
        for name, entry in values.items():
            if entry is None:
                try:
                    winreg.DeleteValue(handle, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(handle, name, 0, entry[1], entry[0])


def _broadcast_environment() -> None:
    user32 = ctypes.windll.user32
    user32.SendMessageTimeoutW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_wchar_p,
        ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_size_t)]
    user32.SendMessageTimeoutW.restype = ctypes.c_void_p
    result = ctypes.c_size_t()
    if not user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 2000,
                                     ctypes.byref(result)):
        raise RuntimeError("Windows did not broadcast the proxy environment change")


def _proxy_address(value: str) -> Optional[Tuple[str, int]]:
    """Read the HTTPS hop from a WinINet ProxyServer value or an HTTP_PROXY URL."""
    parts = dict((key.lower(), val) for part in value.split(";") if "=" in part
                 for key, val in [part.split("=", 1)])
    raw = parts.get("https") or parts.get("http") or (value if "=" not in value else "")
    if not raw:
        return None
    parsed = urlsplit(raw if "://" in raw else "http://" + raw)
    if parsed.scheme != "http" or not parsed.hostname or not parsed.port or parsed.username:
        return None
    return parsed.hostname, parsed.port


def previous_proxy() -> Optional[Tuple[str, int]]:
    if os.name != "nt":
        raise RuntimeError("Desktop monitoring requires Windows")
    settings = _read_values(INTERNET, PROXY_NAMES)
    if settings["ProxyEnable"] and settings["ProxyEnable"][0]:
        value = settings["ProxyServer"]
        if value:
            found = _proxy_address(str(value[0]))
            if found:
                return found
            raise RuntimeError("the current Windows proxy is not an HTTP proxy")
    if settings["AutoConfigURL"]:
        raise RuntimeError("a Windows PAC proxy is active; Desktop monitoring cannot preserve its routing")
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        value = os.environ.get(name, "")
        found = _proxy_address(value)
        if found:
            return found
        if value:
            raise RuntimeError(f"{name} is not an HTTP proxy")
    return None


def desktop_app_id() -> str:
    """Return the installed MSIX application ID for Shell activation."""
    if os.name != "nt":
        raise RuntimeError("Codex Desktop launching requires Windows")
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
               "(Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | "
               "Select-Object -First 1).PackageFamilyName"]
    run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    if run.returncode or not run.stdout.strip():
        raise RuntimeError("Codex Desktop package was not found")
    return run.stdout.strip().splitlines()[-1] + "!App"


def activate_desktop() -> str:
    app_id = desktop_app_id()
    os.startfile("shell:AppsFolder\\" + app_id)
    return app_id


def desktop_running() -> bool:
    """Desktop and its app-server must exit before their proxy and CA are discarded."""
    if os.name != "nt":
        return False
    run = subprocess.run(["tasklist", "/FI", "IMAGENAME eq ChatGPT.exe", "/FO", "CSV", "/NH"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
                         creationflags=subprocess.CREATE_NO_WINDOW)
    if run.returncode:
        raise RuntimeError(f"could not check Codex Desktop processes: {run.stderr.strip()}")
    if any(row and row[0].lower() == "chatgpt.exe" for row in csv.reader(run.stdout.splitlines())):
        return True
    app_server = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name = 'codex.exe'\" | "
         "Where-Object { $_.CommandLine -match '(?<!\\S)app-server(?!\\S)' } | "
         "Select-Object -First 1 -ExpandProperty ProcessId"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if app_server.returncode:
        raise RuntimeError(f"could not check Codex app-server processes: {app_server.stderr.strip()}")
    return bool(app_server.stdout.strip())


def _parent_alive(pid: int) -> bool:
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.OpenProcess(0x00100000, False, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(handle, 0) == 0x102
    finally:
        kernel32.CloseHandle(handle)


def restore(path: Path) -> None:
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    _write_values(ENVIRONMENT, data["environment"])
    _broadcast_environment()
    _restore_dotenv(data.get("dotenv"))
    path.unlink(missing_ok=True)


def watchdog(path: Path) -> int:
    while path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not _parent_alive(int(data["pid"])):
                restore(path)
                return 0
        except (OSError, ValueError, KeyError, RuntimeError):
            pass
        time.sleep(2)
    return 0


class WindowsDesktopSession:
    """Own the temporary Desktop environment and Codex .env proxy overrides."""

    def __init__(self, port: int, cert_path: Path) -> None:
        self.port = port
        self.cert_path = cert_path
        self.path = _backup_path()
        self.active = False

    def start(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Desktop monitoring requires Windows")
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if _parent_alive(int(data["pid"])):
                raise RuntimeError("another Desktop monitor is already active")
            restore(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        url = f"http://127.0.0.1:{self.port}"
        dotenv, patched_dotenv = _plan_dotenv(_dotenv_path(), url)
        backup = {"pid": os.getpid(), "environment": _read_values(ENVIRONMENT, DESKTOP_ENV_NAMES),
                  "dotenv": dotenv}
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(backup), encoding="utf-8")
        temp.replace(self.path)
        if getattr(sys, "frozen", False):
            command = [sys.executable, "--desktop-watchdog", str(self.path)]
        else:
            command = [sys.executable, "-m", "codex_routing_windows", "--watchdog", str(self.path)]
        try:
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
                             close_fds=True)
            values = {name: [url, winreg.REG_SZ] for name in DESKTOP_ENV_NAMES
                      if name != "CODEX_CA_CERTIFICATE"}
            values["CODEX_CA_CERTIFICATE"] = [str(self.cert_path), winreg.REG_SZ]
            _write_values(ENVIRONMENT, values)
            _broadcast_environment()
            if patched_dotenv is not None:
                dotenv_path = Path(dotenv["path"])
                if hashlib.sha256(dotenv_path.read_bytes()).hexdigest() != dotenv["before_sha256"]:
                    raise RuntimeError(f"{dotenv_path} changed while starting Desktop monitoring")
                _write_dotenv(dotenv_path, patched_dotenv)
            self.active = True
        except Exception:
            restore(self.path)
            raise

    def stop(self) -> None:
        if self.active:
            restore(self.path)
            self.active = False


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--watchdog":
    sys.exit(watchdog(Path(sys.argv[2])))
