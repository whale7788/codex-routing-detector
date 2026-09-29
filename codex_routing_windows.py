"""Read the existing Windows proxy and locate Codex Desktop without changing user settings."""
from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

if os.name == "nt":
    import winreg

INTERNET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_NAMES = ("ProxyEnable", "ProxyServer", "AutoConfigURL")


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
