"""Count what a stealer chain across the members of an Electron app would rest on.

A measurement, not a rule (phageo, 2026-10-13): nothing here changes a verdict.
For one package - a folder of a clean sample, or a real sample the positive
benchmark's runner holds in memory - three things are counted while the
scanner reads it the usual way:

1. **Add-ons that can decrypt stored secrets**: native add-ons (``.node``
   files) whose import table names the Windows function that decrypts what
   browsers and chat programs store (``CryptUnprotectData``). The Electron
   program itself imports it too and is not counted.
2. **Names of stores**: scripts in which a browser's, Discord's or a wallet's
   store is named - in the script's text as it stands, and only in what the
   data-flow reading resolved or decoded (a name that is not there as plain
   text). The same for the texts of add-ons.
3. **Network sinks**: scripts with a network call the rules or the data-flow
   reading found (not inside quoted text), and add-ons that import a network
   library.

Numbers only: no name, no path, no content of the package is printed.

    python tools/stealer_count.py <folder of one clean sample> [...]

Real samples: ``tools/positive_benchmark.py <folders> --stealer-count``.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Callable, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SEP = r"[\\/]{1,4}"
STORES = re.compile(
    r"Login Data\b|Local State\b|Web Data\b|cookies\.sqlite|logins\.json|key[34]\.db|User Data" + _SEP
    + r"|Google" + _SEP + r"Chrome|BraveSoftware|Opera Software|Microsoft" + _SEP + r"Edge|Mozilla" + _SEP + r"Firefox"
    + r"|Yandex" + _SEP + r"YandexBrowser|Vivaldi" + _SEP
    + r"|discord(?:canary|ptb|development)?" + _SEP + r"Local Storage|Local Storage" + _SEP + r"leveldb|discord[_-]?token"
    + r"|Telegram Desktop" + _SEP + r"tdata|loginusers\.vdf"
    + r"|wallet\.dat|Exodus" + _SEP + r"|exodus\.wallet|Electrum" + _SEP + r"wallets|atomic" + _SEP + r"Local Storage"
    + r"|Ethereum" + _SEP + r"keystore|Coinomi|com\.liberty\.jaxx|Guarda" + _SEP + r"|nkbihfbeogaeaoehlefnkodbefgpgknn"
    + r"|bfnaelmomeimhlpmgjnjophhpkkoljpa|\.ssh" + _SEP + r"id_(?:rsa|ed25519)|\.aws" + _SEP + r"credentials",
    re.IGNORECASE)
DECRYPT = frozenset({"cryptunprotectdata"})
NETWORK_LIBRARIES = frozenset({"ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll"})
NETWORK_RULES = frozenset({"JS-NET-001", "DF-URL-001", "CHAIN-REMOTE-CODE", "CHAIN-REMOTE-LOAD", "NET-EXFIL-001",
                           "URL-IP-001"})
SCRIPTS = frozenset({".js", ".mjs", ".cjs", ".jse", ".html", ".htm"})
COLUMNS = ("add-ons", "add-ons importing the decrypt function", "add-ons importing a network library",
           "add-ons whose texts name a store", "scripts", "scripts naming a store in their text",
           "scripts naming a store only after resolving", "scripts with a network call")


def count(scanner, scan: Callable[[], object]) -> Dict[str, int]:
    """Run ``scan()`` (which must scan with ``scanner``) and return the numbers of ``COLUMNS``."""
    import gamescan.dataflow as dataflow
    from gamescan.pe import extract_strings
    out = {column: 0 for column in COLUMNS}
    resolved_names: List[bool] = []
    real_scan, real_analyse = scanner._scan_one, dataflow.analyse

    def analyse(text, language):
        result = real_analyse(text, language)
        if language == "js":
            resolved_names.append(any(STORES.search(hit.value) for hit in result.resolved)
                                  or any(STORES.search(code) for _line, _language, code in result.payloads))
        return result

    def watched(ctx, depth: int = 0):
        del resolved_names[:]
        found = real_scan(ctx, depth)
        ext = os.path.splitext(ctx.name)[1].lower()
        if ext == ".node" and ctx.pe is not None:
            out["add-ons"] += 1
            names = {name.lower() for imported in ctx.pe.imports.values() for name in imported}
            out["add-ons importing the decrypt function"] += bool(names & DECRYPT)
            out["add-ons importing a network library"] += bool(set(ctx.pe.imports) & NETWORK_LIBRARIES)
            out["add-ons whose texts name a store"] += any(STORES.search(text) for text in extract_strings(ctx.data))
        elif ext in SCRIPTS:
            out["scripts"] += 1
            plain = STORES.search(ctx.text()) is not None
            out["scripts naming a store in their text"] += plain
            out["scripts naming a store only after resolving"] += (not plain) and any(resolved_names)
            out["scripts with a network call"] += any(
                f.rule_id in NETWORK_RULES and not f.suppressed for f in found or ())
            # ... and the network calls that were lowered, by the first words of why (no names)
            for f in found or ():
                if f.rule_id in NETWORK_RULES and f.suppressed:
                    why = "lowered: " + f.suppression_reason.split(":", 1)[0][:60]
                    out[why] = out.get(why, 0) + 1
        return found

    scanner._scan_one, dataflow.analyse = watched, analyse
    try:
        scan()
    finally:
        del scanner._scan_one
        dataflow.analyse = real_analyse
    return out


def line(numbers: Dict[str, int]) -> str:
    return "; ".join("%s: %d" % (column, numbers[column]) for column in
                     list(COLUMNS) + sorted(key for key in numbers if key not in COLUMNS))


def main(argv: List[str]) -> int:
    from gamescan import neutral_scanner
    if not argv:
        print(__doc__)
        return 2
    for folder in argv:
        if not os.path.isdir(folder):
            print("not a folder: %s" % folder)
            return 2
        scanner = neutral_scanner()
        print("%s | %s" % (os.path.basename(os.path.normpath(folder)), line(count(scanner, lambda: scanner.scan(folder)))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
