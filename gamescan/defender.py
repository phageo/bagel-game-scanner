"""Windows Defender as a component, not a competitor.

Two independent, optional integrations. Neither needs administrator rights,
and both degrade gracefully: if Defender (or AMSI) is missing, disabled or
replaced by another antivirus, the caller gets a reason string to record as
an INFO note and the scan simply continues without them.

:class:`Amsi`
    Hands text the scanner has already *extracted* - code recovered from
    ``.rpyc`` files, scripts from inside archives, strings from .NET metadata -
    to the installed antimalware engine through the Antimalware Scan
    Interface. Defender normally never sees this content, because on disk it
    is compressed, pickled or encrypted inside another file. Nothing is
    executed; AMSI only inspects the buffer.

:class:`DefenderScan`
    Runs ``MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation``
    and reads its verdict. ``-DisableRemediation`` is always passed and never
    dropped: Defender must not quarantine or delete anything on the scanner's
    behalf. If the installed version does not accept the flag, the scan is
    reported as unavailable - it is *not* retried without it.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

AMSI_DETECTED = 32768                    # AMSI_RESULT_DETECTED
_CHUNK = 8 * 1024 * 1024                 # bytes handed to AMSI per call
_MAX_CHUNKS = 4
_OVERLAP = 4096


class Amsi:
    """One AMSI session. ``available`` is False (with ``problem`` set) when the
    interface cannot be used; ``scan`` then returns None."""

    def __init__(self, app_name: str = "GameSafetyScanner") -> None:
        self.available, self.problem = False, ""
        self.calls = 0
        self._lib = self._context = self._session = None
        self._lock = threading.Lock()
        try:
            self._open(app_name)
            self.available = True
        except Exception as exc:                  # no DLL, no provider, not Windows...
            self.problem = "%s" % (exc or type(exc).__name__)

    # -- the only two methods that touch the operating system --------------------
    def _open(self, app_name: str) -> None:
        if sys.platform != "win32":
            raise OSError("AMSI exists only on Windows")
        import ctypes
        from ctypes import wintypes
        lib = ctypes.WinDLL("amsi")
        handle = ctypes.c_void_p
        lib.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(handle)]
        lib.AmsiInitialize.restype = ctypes.c_long
        lib.AmsiOpenSession.argtypes = [handle, ctypes.POINTER(handle)]
        lib.AmsiOpenSession.restype = ctypes.c_long
        lib.AmsiScanBuffer.argtypes = [handle, ctypes.c_void_p, wintypes.ULONG, wintypes.LPCWSTR,
                                       handle, ctypes.POINTER(ctypes.c_int)]
        lib.AmsiScanBuffer.restype = ctypes.c_long
        lib.AmsiCloseSession.argtypes = [handle, handle]
        lib.AmsiCloseSession.restype = None
        lib.AmsiUninitialize.argtypes = [handle]
        lib.AmsiUninitialize.restype = None
        context, session = handle(), handle()
        code = lib.AmsiInitialize(app_name, ctypes.byref(context))
        if code < 0:
            raise OSError("AmsiInitialize failed (0x%08X)" % (code & 0xFFFFFFFF))
        code = lib.AmsiOpenSession(context, ctypes.byref(session))
        if code < 0:
            lib.AmsiUninitialize(context)
            raise OSError("AmsiOpenSession failed (0x%08X)" % (code & 0xFFFFFFFF))
        self._lib, self._context, self._session = lib, context, session

    def _scan_buffer(self, data: bytes, name: str) -> int:
        """AMSI_RESULT for one buffer; raises OSError if the engine cannot scan."""
        import ctypes
        result = ctypes.c_int(0)
        buffer = ctypes.create_string_buffer(data, len(data))
        code = self._lib.AmsiScanBuffer(self._context, buffer, len(data), name, self._session,
                                        ctypes.byref(result))
        if code < 0:
            raise OSError("AmsiScanBuffer failed (0x%08X)" % (code & 0xFFFFFFFF))
        return result.value

    # -- public API ---------------------------------------------------------------
    def scan(self, text: str, name: str) -> Optional[int]:
        """Highest AMSI_RESULT for ``text`` (>= AMSI_DETECTED means malware), or
        None if AMSI is unavailable. Large content is scanned in bounded chunks."""
        if not self.available or not text:
            return None
        data = text.encode("utf-16-le", "replace")       # what script hosts submit
        worst = 0
        with self._lock:
            try:
                for i in range(_MAX_CHUNKS):
                    start = i * (_CHUNK - _OVERLAP)
                    if start >= len(data):
                        break
                    self.calls += 1
                    worst = max(worst, self._scan_buffer(data[start:start + _CHUNK], name))
                    if worst >= AMSI_DETECTED:
                        break
            except Exception as exc:              # engine stopped answering: stop using it
                self.available, self.problem = False, "%s" % (exc or type(exc).__name__)
                return None
        return worst

    def close(self) -> None:
        with self._lock:
            if self._lib is not None and self._context is not None:
                try:
                    self._lib.AmsiCloseSession(self._context, self._session)
                    self._lib.AmsiUninitialize(self._context)
                except Exception:
                    pass
            self._lib = self._context = self._session = None
            self.available = False


# -- MpCmdRun ------------------------------------------------------------------------
Runner = Callable[[List[str], float, Optional[threading.Event]], Tuple[Optional[int], str]]
_THREAT = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$", re.M)
_RESOURCE = re.compile(r"^\s*(?:file|containerfile|behavior|process)\s*:\s*(.+?)\s*$", re.M | re.I)
_BLOCK = re.compile(r"-+\s*Threat information\s*-+(.*?)(?=-+\s*Threat information\s*-+|\Z)", re.S)


@dataclass
class DefenderResult:
    status: str                          # clean | threats | unavailable | timeout | error
    detail: str = ""
    threats: List[Tuple[str, List[str]]] = field(default_factory=list)   # (name, [paths])


def find_mpcmdrun() -> Optional[str]:
    """Newest ``MpCmdRun.exe``: the updated platform folder, else Program Files."""
    candidates = []
    platform = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                            "Microsoft", "Windows Defender", "Platform")
    try:
        for name in sorted(os.listdir(platform), reverse=True):
            candidates.append(os.path.join(platform, name, "MpCmdRun.exe"))
    except OSError:
        pass
    candidates.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                   "Windows Defender", "MpCmdRun.exe"))
    return next((c for c in candidates if os.path.isfile(c)), None)


def _run(command: List[str], timeout: float,
         cancel: Optional[threading.Event]) -> Tuple[Optional[int], str]:
    """Run ``command``; ``(None, output)`` means it was stopped (timeout / cancel)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, creationflags=flags)
    deadline = time.time() + timeout
    while True:
        try:
            out, _ = process.communicate(timeout=0.5)
            return process.returncode, out.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            if time.time() >= deadline or (cancel is not None and cancel.is_set()):
                process.kill()
                out, _ = process.communicate()
                return None, out.decode("utf-8", "replace")


class DefenderScan:
    def __init__(self, exe: Optional[str] = None, timeout: float = 900.0,
                 runner: Optional[Runner] = None) -> None:
        self.exe = exe if exe is not None else find_mpcmdrun()
        self.timeout, self._runner = timeout, runner or _run

    def command(self, path: str) -> List[str]:
        return [self.exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]

    def scan(self, path: str, cancel: Optional[threading.Event] = None) -> DefenderResult:
        if not self.exe or (self._runner is _run and not os.path.isfile(self.exe)):
            return DefenderResult("unavailable", "MpCmdRun.exe was not found")
        try:
            code, output = self._runner(self.command(path), self.timeout, cancel)
        except (OSError, ValueError) as exc:
            return DefenderResult("unavailable", "MpCmdRun.exe could not be started (%s)"
                                  % type(exc).__name__)
        if code is None:
            return DefenderResult("timeout", "the Defender scan was stopped after %d s"
                                  % self.timeout)
        threats = []
        for block in _BLOCK.findall(output):
            name = _THREAT.search(block)
            if name:
                threats.append((name.group(1), _RESOURCE.findall(block)))
        if threats:
            return DefenderResult("threats", "%d threat(s)" % len(threats), threats)
        if code == 0:
            return DefenderResult("clean")
        # Any other outcome (flag not understood, service stopped, another
        # antivirus in charge...) is reported, never retried without the flag.
        last = [line.strip() for line in output.splitlines() if line.strip()][-1:]
        return DefenderResult("error", "MpCmdRun exit code %s%s"
                              % (code, ": " + last[0][:160] if last else ""))
