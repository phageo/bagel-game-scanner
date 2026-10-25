"""Where malware lives on a PC: autostart entries, running programs and the
folders downloads land in. Windows-specific parts degrade to empty results on
other systems. Standard library only (``winreg`` and ``ctypes``)."""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/system.py")

import os
import re
import sys
import tempfile
from typing import Dict, List, Optional

from .models import Category, Finding, Severity

_RUN_KEYS = (r"Software\Microsoft\Windows\CurrentVersion\Run",
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
             r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
_DOWNLOADS = "{374DE290-123F-4565-9164-39C4925E467B}"
_EXECUTABLE = re.compile(r"\.(?:exe|com|scr|bat|cmd|vbs|vbe|js|jse|wsf|ps1|hta|lnk|dll|pif)$", re.I)
_SCRIPT_HOST = re.compile(_IND[0], re.I)
_HIDDEN_PS = re.compile(_IND[1], re.I)
_VOLATILE = re.compile(r"\\(?:temp|tmp|downloads)\\|\\appdata\\local\\temp\\|\\users\\public\\"
                       r"|\\\$recycle\.bin\\", re.I)


def known_folders() -> Dict[str, str]:
    """Downloads / Desktop / Startup, honouring redirected (OneDrive) folders."""
    home = os.path.expanduser("~")
    out = {"Downloads": os.path.join(home, "Downloads"), "Desktop": os.path.join(home, "Desktop")}
    if sys.platform == "win32":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SHELL_FOLDERS) as key:
                for name, value in (("Downloads", _DOWNLOADS), ("Desktop", "Desktop"),
                                    ("Startup", "Startup")):
                    try:
                        out[name] = os.path.expandvars(winreg.QueryValueEx(key, value)[0])
                    except OSError:
                        pass
        except OSError:
            pass
        common = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                              r"Microsoft\Windows\Start Menu\Programs\Startup")
        out["Common Startup"] = common
    return {k: v for k, v in out.items() if os.path.isdir(v)}


def quick_scan_targets() -> List[str]:
    """The places new threats usually arrive in or start from."""
    targets = list(known_folders().values()) + [tempfile.gettempdir()]
    return list(dict.fromkeys(os.path.normpath(t) for t in targets if os.path.isdir(t)))


def fixed_drives() -> List[str]:
    if sys.platform != "win32":
        return ["/"]
    import ctypes
    mask, out = ctypes.windll.kernel32.GetLogicalDrives(), []
    for i in range(26):
        root = "%s:\\" % chr(65 + i)
        if mask >> i & 1 and ctypes.windll.kernel32.GetDriveTypeW(root) == 3:   # DRIVE_FIXED
            out.append(root)
    return out


def command_target(command: str) -> Optional[str]:
    """The file an autostart command line actually launches."""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        first = command[1:end] if end > 0 else command[1:]
    else:
        parts = command.split(" ")
        first = parts[0]
        for i in range(1, len(parts) + 1):       # unquoted paths may contain spaces
            candidate = " ".join(parts[:i])
            if os.path.isfile(candidate) or _EXECUTABLE.search(candidate):
                first = candidate
                break
    return os.path.normpath(first) if first else None


def startup_entries() -> List[Dict[str, str]]:
    """Programs set to start with Windows: ``name``, ``location``, ``command``, ``path``."""
    out: List[Dict[str, str]] = []
    if sys.platform == "win32":
        import winreg
        for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for sub in _RUN_KEYS:
                try:
                    with winreg.OpenKey(hive, sub) as key:
                        for i in range(winreg.QueryInfoKey(key)[1]):
                            name, value, _kind = winreg.EnumValue(key, i)
                            out.append({"name": name, "location": "%s\\%s" % (label, sub),
                                        "command": str(value),
                                        "path": command_target(str(value)) or ""})
                except OSError:
                    continue
    folders = known_folders()
    for label in ("Startup", "Common Startup"):
        folder = folders.get(label)
        if not folder:
            continue
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            if os.path.isfile(path) and name.lower() != "desktop.ini":
                out.append({"name": name, "location": label + " folder", "command": path,
                            "path": path})
    return out


def running_executables() -> List[str]:
    """Image paths of the processes this user is allowed to inspect."""
    if sys.platform != "win32":
        return []
    import ctypes
    from ctypes import wintypes

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = k32.CreateToolhelp32Snapshot(2, 0)                  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return []
    paths, entry = set(), Entry()
    entry.dwSize = ctypes.sizeof(Entry)
    try:
        more = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            handle = k32.OpenProcess(0x1000, False, entry.th32ProcessID)   # QUERY_LIMITED_INFORMATION
            if handle:
                buf, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
                if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    paths.add(buf.value)
                k32.CloseHandle(handle)
            more = k32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return sorted(p for p in paths if os.path.isfile(p))


def autorun_findings(entries: List[Dict[str, str]]) -> List[Finding]:
    """Heuristics on the autostart entries themselves (not on the files)."""
    out: List[Finding] = []
    for e in entries:
        command, path = e["command"], e["path"]

        def make(rule_id, title, severity, confidence, reason):
            return Finding(rule_id=rule_id, title=title, category=Category.PERSISTENCE,
                           severity=severity, file="%s : %s" % (e["location"], e["name"]),
                           line=None, snippet=command, evidence=command[:200],
                           confidence=confidence, reason=reason, handler="autoruns",
                           path=path if os.path.isfile(path) else "", chainable=False)

        if _SCRIPT_HOST.search(path) and _HIDDEN_PS.search(command):
            out.append(make("AUTORUN-002", "Autostart runs a hidden or encoded script",
                            Severity.HIGH, 0.8,
                            "Something starts with Windows through a script interpreter using "
                            "hidden, encoded or download-and-run arguments."))
        elif _VOLATILE.search(path + "\\"):
            out.append(make("AUTORUN-001", "Autostart from a temporary location",
                            Severity.MEDIUM, 0.55,
                            "A program that starts with Windows lives in a temp, downloads or "
                            "public folder - legitimate software installs elsewhere."))
        elif path and _EXECUTABLE.search(path) and not os.path.isfile(path) \
                and not _SCRIPT_HOST.search(path) and os.path.isabs(path):
            out.append(make("AUTORUN-003", "Autostart entry points to a missing file",
                            Severity.LOW, 0.3,
                            "An autostart entry refers to a program that no longer exists - "
                            "often a leftover of removed software or of cleaned malware."))
    return out


def system_scan_targets() -> List[str]:
    """Files worth scanning for a system check: autostart targets + running programs."""
    files = [e["path"] for e in startup_entries() if e["path"] and os.path.isfile(e["path"])]
    return list(dict.fromkeys(files + running_executables()))
