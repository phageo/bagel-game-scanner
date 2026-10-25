"""A credential stealer across the members of one Electron app (phageo, 2026-10-15, forty-ninth message).

``CHAIN-STEALER`` (CRITICAL) is made after the scan when one app holds all three:

1. an add-on that can decrypt what Windows stores for the user (``ADDON-DECRYPT-001``),
2. a script that names a store of a browser, of Discord or of a crypto wallet (``STORES`` -
   the places only; generic words such as "token" or "password" do not count), and
3. a script with an active network finding.

"One app" is everything behind one ``resources/app.asar`` / ``app.asar.unpacked`` /
``resources/app`` (``electron_windows.app_root``). The verified Electron runtime is a program,
not a script or an add-on, and takes no part. Nothing here says that the stored data reaches the
network - the three parts are where a stealer's work happens, not a traced flow.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/stealer.py")

import re
from typing import Dict, List, Optional

from .models import Category, Finding, Severity

RULE = "CHAIN-STEALER"
DECRYPT = "ADDON-DECRYPT-001"
SCRIPTS = (".js", ".mjs", ".cjs", ".jse", ".html", ".htm")
# A network call of a script: a request, a resolved address that is fetched, a download chain, or an
# address stealers send to. (A hard-coded URL alone, URL-001, is an address, not a call.) A call in a
# file trusted for its origin - a published npm package, an official library - counts too: the
# library is the app's way out all the same (its single finding is lowered, what it adds up to is not).
NETWORK_CALLS = frozenset({"JS-NET-001", "DF-URL-001", "CHAIN-REMOTE-CODE", "CHAIN-REMOTE-LOAD", "CHAIN-REMOTE-ARG",
                           "CHAIN-FETCHRUN", "NET-EXFIL-001", "URL-IP-001"})
_BY_ORIGIN = "Engine / library baseline"
MAX_APPS = 64                 # apps whose store names are kept in one scan
MAX_FILES = 16                 # scripts kept per app (the first ones in reading order)

_SEP = r"[\\/]{1,4}"
# The stores, by kind. Browser profiles (Chromium's and Firefox's credential, cookie and key
# files), Discord's own local storage, and wallets (files, folders, and the browser-extension ids
# of MetaMask and Phantom). Left out on purpose: "Local Storage/leveldb" alone (every Chromium
# and Electron profile has one, the app's own too), words like "discord_token" / "token_grab",
# Telegram, Steam, SSH and cloud keys (not his three kinds).
_KINDS = (
    ("browser", _IND[0] + _SEP
                + r"Default" + _SEP + r"(?:Network" + _SEP + _IND[1]
                + r"|(?<![\w-])key[34]\.db\b"),
    (_IND[2], _IND[3] + _SEP + _IND[4]),
    ("wallet", _IND[5] + _SEP + _IND[6] + _SEP + r"wallets\b"
               + _IND[7] + _SEP + _IND[8] + _SEP + _IND[9]
               + _IND[10] + _SEP + _IND[11] + _SEP
               + _IND[12]),
)
STORES = re.compile("|".join("(?P<%s>%s)" % (kind.lower(), pattern) for kind, pattern in _KINDS), re.IGNORECASE)
_NAMES = {kind.lower(): kind for kind, _pattern in _KINDS}

REASON = (_IND[13])


# Every store name holds one of these words: the pattern is tried only around them (the whole
# pattern over a 20 MB bundle takes seconds; a search for plain words does not).
_ANCHORS = (_IND[14], _IND[15], _IND[16], _IND[17], _IND[18], "key3.db", _IND[19],
            _IND[20], _IND[21], _IND[22], _IND[23], "ethereum", _IND[24], _IND[25], _IND[26],
            _IND[27], "bfnaelmomeimhlpmgjnjophhpkkoljpa")
_AROUND = 120                  # characters on each side of a word that are tried
MAX_PLACES = 2000              # places tried per word and text


def store_kinds(text: str) -> List[str]:
    """The kinds of store (``browser``, ``Discord``, ``wallet``) ``text`` names, in that order."""
    low = text.lower()
    found = set()
    if len(low) != len(text):              # a letter whose lower case is longer: places would shift
        for match in STORES.finditer(text):
            found.add(match.lastgroup)
        return [kind for kind, _pattern in _KINDS if kind.lower() in found]
    for anchor in _ANCHORS:
        at, places = low.find(anchor), 0
        while at >= 0 and places < MAX_PLACES and len(found) < len(_KINDS):
            places += 1
            lo = max(0, at - _AROUND)
            for match in STORES.finditer(text, lo, at + len(anchor) + _AROUND):
                if match.start() <= at < match.end() or at <= match.start() < at + len(anchor):
                    found.add(match.lastgroup)
            at = low.find(anchor, at + len(anchor))
    return [kind for kind, _pattern in _KINDS if kind.lower() in found]


def network_call(f: Finding) -> bool:
    """Is ``f`` a network call of a script (``NETWORK_CALLS``), shown or lowered for its file's origin?"""
    return f.rule_id in NETWORK_CALLS and f.file.lower().endswith(SCRIPTS) and (
        not f.suppressed or f.suppression_reason.startswith(_BY_ORIGIN))


def chains(findings: List[Finding], stores: Dict[str, Dict[str, List[str]]], app_root) -> List[Finding]:
    """One ``CHAIN-STEALER`` per app that holds the three parts. ``stores``: app -> {script: kinds},
    kept while the app's scripts were scanned."""
    network_files: Dict[str, set] = {}
    for f in findings:
        if network_call(f):
            root = app_root(f.file)
            if root is not None:
                network_files.setdefault(root, set()).add(f.file)
    out: List[Finding] = []
    seen = set()
    for f in findings:
        if f.rule_id != DECRYPT:
            continue
        root: Optional[str] = app_root(f.file)
        if root is None or root in seen or not stores.get(root) or not network_files.get(root):
            continue
        seen.add(root)
        named = stores[root]
        kinds = [kind for kind, _pattern in _KINDS if any(kind in found for found in named.values())]
        first = sorted(named)[0]
        out.append(Finding(
            rule_id=RULE, title="Credential stealer", category=Category.CREDENTIALS,
            severity=Severity.CRITICAL, file=f.file, line=None, snippet="",
            evidence="decrypting add-on: %s; store named (%s) in %s%s; scripts of the app with a "
                     "network call: %d" % (f.file, ", ".join(kinds), first,
                                           " and %d more script(s)" % (len(named) - 1) if len(named) > 1 else "",
                                           len(network_files[root])),
            confidence=0.8, reason=REASON, handler="scanner", sha256=f.sha256, path=f.path,
            chainable=False, context={"across_app": True}))
    return out
