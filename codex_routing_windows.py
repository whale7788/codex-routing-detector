"""Temporary Windows proxy and CA settings for watching Codex Desktop.

The backup is written before changing user settings. A small child process restores it
if the GUI disappears without calling stop(). No changes are made on import.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

if os.name == "nt":
    import winreg

INTERNET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ENVIRONMENT = "Environment"
PROXY_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect")
ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "WS_PROXY", "WSS_PROXY",
             "http_proxy", "https_proxy", "all_proxy", "ws_proxy", "wss_proxy",
             "CODEX_CA_CERTIFICATE")


def _backup_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return root / "codex-routing-detector" / "desktop-session.json"


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


def _refresh() -> None:
    # Let WinINet clients and Explorer learn about both the proxy and environment change.
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, 39, None, 0)
    wininet.InternetSetOptionW(None, 37, None, 0)
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 2000,
                                             ctypes.byref(result))


def _certutil(*args: str) -> None:
    run = subprocess.run(["certutil", "-user", *args], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, timeout=30,
                         creationflags=subprocess.CREATE_NO_WINDOW)
    if run.returncode:
        raise RuntimeError(f"certutil failed ({run.returncode}): {run.stdout[-500:]}")


def _cert_in_store(thumbprint: str) -> bool:
    key = rf"Software\Microsoft\SystemCertificates\Root\Certificates\{thumbprint}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key):
            return True
    except FileNotFoundError:
        return False


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


def desktop_executable() -> Path:
    """Find the installed Codex Desktop executable without assuming a package version."""
    if os.name != "nt":
        raise RuntimeError("Codex Desktop launching requires Windows")
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
               "(Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | "
               "Select-Object -First 1).InstallLocation"]
    run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    if run.returncode or not run.stdout.strip():
        raise RuntimeError("Codex Desktop package was not found")
    executable = Path(run.stdout.strip().splitlines()[-1]) / "app" / "ChatGPT.exe"
    if not executable.is_file():
        raise RuntimeError(f"Codex Desktop executable was not found: {executable}")
    return executable


def _parent_alive(pid: int) -> bool:
    kernel = ctypes.windll.kernel32
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        return False
    try:
        return kernel.WaitForSingleObject(handle, 0) == 0x102  # WAIT_TIMEOUT
    finally:
        kernel.CloseHandle(handle)


def restore(path: Path) -> None:
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    _write_values(INTERNET, data["internet"])
    _write_values(ENVIRONMENT, data["environment"])
    _refresh()
    if data.get("thumbprint") and _cert_in_store(data["thumbprint"]):
        _certutil("-delstore", "Root", data["thumbprint"])
    path.unlink(missing_ok=True)


def watchdog(path: Path) -> int:
    while path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not _parent_alive(int(data["pid"])):
                restore(path)
                return 0
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    return 0


class WindowsDesktopSession:
    def __init__(self, port: int, cert_path: Path, thumbprint: str) -> None:
        self.port = port
        self.cert_path = cert_path
        self.thumbprint = thumbprint
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
        backup = {"pid": os.getpid(), "thumbprint": self.thumbprint,
                  "internet": _read_values(INTERNET, PROXY_NAMES),
                  "environment": _read_values(ENVIRONMENT, ENV_NAMES)}
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
            _certutil("-addstore", "-f", "Root", str(self.cert_path))
            address = f"127.0.0.1:{self.port}"
            _write_values(INTERNET, {"ProxyEnable": [1, winreg.REG_DWORD],
                                     "ProxyServer": [address, winreg.REG_SZ],
                                     "AutoConfigURL": None, "AutoDetect": [0, winreg.REG_DWORD]})
            url = f"http://{address}"
            _write_values(ENVIRONMENT, {name: [url, winreg.REG_SZ] for name in ENV_NAMES
                                        if name != "CODEX_CA_CERTIFICATE"})
            _write_values(ENVIRONMENT, {"CODEX_CA_CERTIFICATE": [str(self.cert_path), winreg.REG_SZ]})
            _refresh()
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
