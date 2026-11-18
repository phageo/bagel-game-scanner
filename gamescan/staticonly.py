"""Only static reading - the measurement switch (phase D, session R1; phageo, 2026-11-10).

Gates, benchmarks and round 5 judge the scanner by what it reads, never by what an outside service or the
PC's own antivirus says: such answers change from day to day and from PC to PC. Every runner
(``tools/fp_benchmark.py``, the malicious-sample runner, ``tools/heldout.py``, ``tools/run_gate.py``)
calls :func:`enable` in each of its processes; it sets ``models.STATIC_ONLY`` and switches on a guard:

* **no network call is possible**: an audit hook refuses every socket, name lookup, HTTP / URL request
  (Python's own audit events) - so no VirusTotal lookup and no abuse.ch list update;
* **no AMSI** (``amsi.dll`` may not be loaded) and **no Windows Defender pass** (``MpCmdRun`` may not
  be started);
* a :class:`~gamescan.scanner.Scanner` given a VirusTotal client, a Defender pass, AMSI or a hash
  blocklist database refuses to scan (:func:`check_scanner`).

A refused attempt raises :class:`Refused` - a ``BaseException``, so that no "one bad file must not end
the scan" handler of the scanner can swallow it - and is counted in :data:`ATTEMPTS`; a runner ends with
a non-zero exit code when the count is not 0 and prints :func:`summary_line` (``lookups refused 0``).
Users never meet the switch: the window and the CLI never call :func:`enable`, and nothing in the package does.

Python's audit hooks cannot be removed: the hook stays installed for the rest of the process and does
nothing while ``models.STATIC_ONLY`` is off (:func:`disable` - for tests).
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/staticonly.py")

import contextlib
import os
import sys
from typing import Iterator, List

from . import models

# the audit events that reach out of the PC (socket.* and the standard library's protocol clients)
NETWORK_EVENTS = frozenset({
    "socket.__new__", "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
    "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
    "socket.getservbyname", "socket.getservbyport",
    "urllib.Request", "http.client.connect", "http.client.send", "ftplib.connect", "smtplib.connect",
    "poplib.connect", "imaplib.open", "nntplib.connect", "telnetlib.Telnet.open", "webbrowser.open"})
# program starts the guard looks at (only the Defender command-line scanner is refused)
_STARTS = frozenset({_IND[0], _IND[1], "os.startfile", "os.startfile/2", "os.spawn", "os.exec",
                     "os.posix_spawn", _IND[2]})
# Windows' own network libraries, loaded through ctypes (a call there would pass the socket events by)
_NETWORK_LIBRARIES = ("winhttp", "wininet", "urlmon", "ws2_32", "wsock32")
SUMMARY = ("static reading only: lookups refused %d (network calls, AMSI, Windows Defender, VirusTotal and the "
           "hash blocklist are all off)")

ATTEMPTS: List[str] = []
_hook = {"installed": False, "from": 0}      # from: len(ATTEMPTS) when the switch was last turned on


class Refused(BaseException):
    """A lookup was attempted while static reading only is on. (Not an ``Exception``: the scanner's
    per-file error handlers must not turn it into a "could not be read" note.)"""


def refuse(what: str) -> None:
    """Count the attempt and raise :class:`Refused`."""
    ATTEMPTS.append(what)
    raise Refused("static reading only: %s was refused" % what)


def _audit(event: str, args) -> None:
    if not models.STATIC_ONLY:
        return
    if event in NETWORK_EVENTS:
        refuse("a network call (%s)" % event)
    elif event == "ctypes.dlopen":
        name = os.path.basename(str(args[0] if args else "")).lower()
        if name.startswith("amsi"):
            refuse("the Windows antimalware engine (amsi.dll)")
        elif name.startswith(_NETWORK_LIBRARIES):
            refuse("a network library (%s)" % name)
    elif event in _STARTS:
        # (the program and its command line; not the environment a Popen also passes)
        if "mpcmdrun" in " ".join(str(a) for a in args[:2]).lower():
            refuse("a Windows Defender scan (MpCmdRun)")


def enable() -> None:
    """Switch static reading only on in this process (and install the guard once)."""
    if not _hook["installed"]:
        sys.addaudithook(_audit)
        _hook["installed"] = True
    if not models.STATIC_ONLY:
        _hook["from"] = len(ATTEMPTS)
    models.STATIC_ONLY = True


def refused() -> int:
    """Attempts refused since the switch was last turned on (a runner's own count; also those some handler
    caught instead of letting them rise)."""
    return max(0, len(ATTEMPTS) - _hook["from"])


def check_refused() -> None:
    """Raise :class:`Refused` if anything was refused since the switch went on - for the end of a worker or child
    process, so that an attempt caught on the way still ends the run."""
    if refused():
        raise Refused("static reading only: %d lookup(s) were refused (%s)" % (refused(), ATTEMPTS[-1]))


def disable() -> None:
    """Switch it off again (tests); the installed hook then does nothing."""
    models.STATIC_ONLY = False


@contextlib.contextmanager
def switched_on() -> Iterator[None]:
    """On for the ``with`` block, then as before - for a runner's ``main`` that tests call in their own process."""
    was = models.STATIC_ONLY
    enable()
    try:
        yield
    finally:
        models.STATIC_ONLY = was


def check_scanner(scanner) -> None:
    """Refuse a scan by ``scanner`` that would ask anything outside its own reading."""
    if not models.STATIC_ONLY:
        return
    if getattr(scanner, "reputation", None) is not None:
        refuse("a VirusTotal lookup")
    if getattr(scanner, "defender", None) is not None:
        refuse("a Windows Defender scan")
    if getattr(scanner, "signatures", None) is not None:
        refuse("a hash blocklist database")
    if getattr(scanner, "_amsi", False) not in (False, None) or getattr(scanner.rules, "amsi", None) is not None:
        refuse("the Windows antimalware engine (AMSI)")


def summary_line() -> str:
    """The runner's last line: ``static reading only: network calls 0, ...``."""
    return SUMMARY % refused()
