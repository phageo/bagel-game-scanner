"""Official redistributable downloads (Visual C++, DirectX, .NET, OpenAL).

Real game installers download and run these. An installer script that
downloads from one of the addresses below and starts the result gets a
visible LOW note instead of ``CHAIN-REMOTE-CODE`` (phageo, 2026-10-11).

The list is kept by hand. Nothing a scanned file says can add to it: it is a
constant of the code, an entry is an exact host and the beginning of the
path, and only ``https`` counts. Every entry names the vendor's own page it
was read from and the day it was read.
"""
from __future__ import annotations

import re
from typing import NamedTuple, Optional
from urllib.parse import parse_qsl, urlsplit


class Entry(NamedTuple):
    host: str           # exact, lower case
    prefix: str         # the path begins with this
    what: str
    source: str         # where the address was read
    checked: str


OFFICIAL = (
    Entry("aka.ms", "/vs/", "Microsoft Visual C++ Redistributable",
          "older Microsoft link, no longer on the vendor page (kept by decision, phageo, 2026-10-11: "
          "aka.ms/vs/<version>/release/vc_redist.<arch>.exe, the permanent links of Visual Studio 2015-2022)",
          "2026-10-11: not on the vendor page any more"),
    Entry("aka.ms", "/vc14/", "Microsoft Visual C++ Redistributable",
          "learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist (the permalinks of the latest "
          "supported v14 version: aka.ms/vc14/vc_redist.<arch>.exe)",
          "2026-10-11"),
    Entry("download.microsoft.com", "/download/", "Microsoft download (DirectX, Visual C++, .NET Framework)",
          "www.microsoft.com/en-us/download/details.aspx?id=35 (DirectX End-User Runtime Web Installer) and "
          "learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist (Visual C++ 2008 - 2012)",
          "2026-10-11"),
    Entry("builds.dotnet.microsoft.com", "/dotnet/", "Microsoft .NET runtime",
          "dotnet.microsoft.com/en-us/download/dotnet (the direct link of a runtime installer) and "
          "devblogs.microsoft.com/dotnet/critical-dotnet-install-links-are-changing",
          "2026-10-11"),
    Entry("www.openal.org", "/downloads/", "OpenAL installer",
          "www.openal.org/downloads/ (oalinst.zip)", "2026-10-11"),
)
# not seen with this exact beginning on a vendor page: stays off (phageo, 2026-10-11)
PENDING = (
    Entry("download.visualstudio.microsoft.com", "/download/pr/", "Microsoft Visual C++ / .NET",
          "devblogs.microsoft.com/dotnet/critical-dotnet-install-links-are-changing names the host only",
          "2026-10-11: host named, path not seen"),
)
# go.microsoft.com/fwlink forwards to wherever its number says: exact numbers only.
# {link id: (what, source page, checked)} - starts empty (phageo, 2026-10-11)
FWLINK_IDS: dict = {}
_FWLINK_PATHS = frozenset({"/fwlink", "/fwlink/", "/fwlink/p", "/fwlink/p/"})
_MAX_ADDRESS = 2048
_PLAIN = re.compile(r"[\x21-\x7e]+\Z")      # no blanks, no control characters, ASCII only


def official(address: str) -> Optional[Entry]:
    """The entry ``address`` belongs to (None = not an official redistributable
    address). Strict on purpose: ``https`` only, the host exactly as listed, no
    user name, no port, no ``..`` and nothing encoded in the path, and no part
    that is only known when the installer runs."""
    if not address or len(address) > _MAX_ADDRESS or not _PLAIN.match(address) \
            or "\\" in address or "$" in address or "{" in address:     # ($x / {x}: filled in at run time)
        return None
    try:
        parts = urlsplit(address)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or "@" in parts.netloc or port is not None:
        return None
    host, path = parts.netloc.lower(), parts.path
    if ".." in path or "%" in path or "//" in path:
        return None
    if host == "go.microsoft.com" and path.lower() in _FWLINK_PATHS:
        ids = [value for key, value in parse_qsl(parts.query) if key.lower() == "linkid"]
        if len(ids) == 1 and ids[0] in FWLINK_IDS:
            what, source, checked = FWLINK_IDS[ids[0]]
            return Entry(host, path, what, source, checked)
        return None
    for entry in OFFICIAL:
        if host == entry.host and path.startswith(entry.prefix) and len(path) > len(entry.prefix):
            return entry
    return None
