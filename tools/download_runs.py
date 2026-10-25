"""Measure the "download and run" chains of JavaScript samples: what a self-update policy would rest on.

A measurement, not a rule (phageo, 2026-10-14, forty-second message: "for each real download-run
chain report: URL constant?, HTTPS?, same host as the app?, does a signature check gate the
run? - propose a self-update policy from that table; build the path tracking, not the policy").
While the scanner reads a sample the usual way, every hit of the JavaScript download-and-run
reading (``remote.study``) that runs what was downloaded - a file that is written and started
(``dropper``), a downloaded command (``command``), downloaded code (``code``), a script loaded
from an address (``loader``) - is described by four answers:

``address``    constant - written out in the script; settings - its server comes from a JSON
               file of the app itself (``require("./config.json")``); runtime - a part of the
               server only exists when the script runs.
``https``      yes / no / not known (``https.get`` is HTTPS whatever its address says).
``same host``  the server of the download and a server the app names for itself (its
               ``package.json``: homepage, repository, bugs, author, the updater's ``publish``;
               an ``app-update.yml``) have the same last two names - yes / no / not known.
``signed``     a signature check stands on every way the reading found from the download to
               the start (``remote._SIGNATURE_CHECK``): yes / partly (some ways) / no.

Numbers and these words only: no name, no path, no address of a sample is printed.

    python tools/download_runs.py <folder of one clean sample> [...]

Real samples: ``tools/positive_benchmark.py <folders> --download-runs``.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RUNS = ("dropper", "command", "code", "loader")
_SETTINGS = re.compile(r"\A‹\.?/?([\w.-]+\.json)\.([\w.$]+)›")
_YML_URL = re.compile(r"(?m)^\s*url:\s*['\"]?(\S+?)['\"]?\s*$")
_MAX_KEPT = 256 * 1024
# a signature check named anywhere in a file of another language (Python, Ruby, the shells)
_ANY_CHECK = re.compile(r"gnupg|\bgpg\b|openpgp|\.verify\s*\(|verify_signature|WinVerifyTrust|Get-AuthenticodeSignature"
                        r"|signtool|ed25519|nacl\.signing", re.I)


def _host(address: str) -> str:
    try:
        return (urlsplit(address).hostname or "").lower()
    except ValueError:
        return ""


def _domain(host: str) -> str:
    return ".".join(host.split(".")[-2:]) if host else ""


class Recorder:
    """Wraps ``remote.study`` and the scan of each file while a scan runs: the hits that run
    something downloaded are kept, and so are the small JSON / YAML files of the sample (to
    read an address out of the app's own settings and the app's own servers)."""

    def __init__(self) -> None:
        from gamescan.dataflow import remote as R
        from gamescan import scanner as S
        from gamescan.handlers import base as B
        self.R, self.S, self.B = R, S, B
        self.real_findings, self.real_scan = B.BaseHandler._remote_findings, S.Scanner._scan_one
        self.hits: List[tuple] = []                      # (language, hit)
        self.arguments = 0
        self.files: Dict[str, List[str]] = {}            # file name -> texts (several apps may share one)

    def __enter__(self) -> "Recorder":
        recorder = self

        def findings(handler, ctx, hits, decoded_at=0, note=""):
            # (every hit of every language's reading becomes findings here)
            language = "JavaScript" if ctx.ext in (".js", ".mjs", ".cjs", ".html", ".htm", ".jse", ".wsf", ".hta") \
                else "Python" if ctx.ext in (".py", ".pyw", ".rpy", ".rpyc", ".pyo", ".pyc", ".rpym") else "other"
            for hit in hits:
                if hit.how in RUNS and not hit.weak:
                    # (the other languages' readings do not look for a check: whether the file
                    # names one anywhere is said instead)
                    named = language == "JavaScript" or bool(_ANY_CHECK.search(ctx.text()))
                    recorder.hits.append((language if named else language + "-", hit))
                elif hit.how == "argument":
                    recorder.arguments += 1
            return recorder.real_findings(handler, ctx, hits, decoded_at, note)

        def scan_one(scanner, ctx, depth=0):
            name = ctx.name
            if name.endswith((".json", ".yml", ".yaml")) and len(ctx.data) <= _MAX_KEPT \
                    and "node_modules" not in ctx.key:
                recorder.files.setdefault(name, []).append(ctx.text())
            return recorder.real_scan(scanner, ctx, depth)
        self.B.BaseHandler._remote_findings, self.S.Scanner._scan_one = findings, scan_one
        return self

    def __exit__(self, *_exc) -> None:
        self.B.BaseHandler._remote_findings, self.S.Scanner._scan_one = self.real_findings, self.real_scan

    # -- the four answers ----------------------------------------------------------------------
    def _settings(self, address: str) -> Optional[str]:
        """``‹./config.json.builds_dir›/...``: the address with that value of the app's own file."""
        m = _SETTINGS.match(address)
        if not m:
            return None
        for text in self.files.get(m.group(1).rsplit("/", 1)[-1].lower(), ()):
            try:
                value = json.loads(text)
            except ValueError:
                continue
            for part in m.group(2).split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if isinstance(value, str):
                return value + address[m.end():]
        return None

    def app_hosts(self) -> set:
        hosts = set()
        for text in self.files.get("package.json", ()):
            try:
                data = json.loads(text)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            places = [data.get("homepage"), data.get("repository"), data.get("bugs"), data.get("author")]
            build = data.get("build") if isinstance(data.get("build"), dict) else {}
            publish = build.get("publish")
            places += publish if isinstance(publish, list) else [publish]
            for place in places:
                if isinstance(place, dict):
                    place = place.get("url") or place.get("homepage")
                if isinstance(place, str):
                    host = _host(re.sub(r"\A(?:git\+|github:)", "https://", place))
                    if host:
                        hosts.add(host)
        for name in ("app-update.yml", "dev-app-update.yml"):
            for text in self.files.get(name, ()):
                hosts.update(_host(url) for url in _YML_URL.findall(text) if _host(url))
        return hosts

    def describe(self, language: str, hit) -> Dict[str, str]:
        R = self.R
        address = hit.address or ""
        settings = self._settings(address)
        resolved = settings or address
        if hit.kind == R.REMOTE and "‹" not in address:
            kind = "constant"
        elif settings is not None and "‹" not in urlsplit(settings).netloc:
            kind = "settings"
        elif hit.kind == R.HIDDEN:
            kind = "decoded"
        else:
            kind = "runtime"
        scheme = resolved.split(":", 1)[0].lower() if re.match(r"[A-Za-z]+:", resolved) else ""
        https = "yes" if scheme in ("https", "wss") or hit.source.startswith("https") else \
            "no" if scheme in ("http", "ws") or hit.source.startswith("http.") else "not known"
        host = _host(resolved) if "‹" not in urlsplit(resolved).netloc else ""
        own = self.app_hosts()
        same = "not known" if not host or not own else "yes" if _domain(host) in {_domain(h) for h in own} else "no"
        if language.endswith("-"):
            signed = "no (none in the file)"
        elif language != "JavaScript":
            signed = "maybe (one in the file)"          # (only the JavaScript reading follows the way)
        elif hit.how == "dropper" and hit.ways:
            signed = "yes" if hit.checked_ways == hit.ways else "partly" if hit.checked_ways else "no"
        else:
            signed = "yes" if getattr(hit, "checked", False) else "no"
        return {"how": hit.how, "address": kind, "https": https, "same host": same, "signed": signed,
                "followed": "path followed, %d way(s), %d signed" % (hit.ways, hit.checked_ways)
                if getattr(hit, "route", "") else ""}

    def lines(self) -> List[str]:
        out = ["download-and-run hits: %d (data handed to a program, not counted: %d); app servers named: %d" % (
            len(self.hits), self.arguments, len(self.app_hosts()))]
        for language, hit in self.hits:
            row = self.describe(language, hit)
            out.append("  %-10s %-7s | address %-8s | https %-9s | same host %-9s | signature check %-8s%s" % (
                language.rstrip("-"), row["how"], row["address"], row["https"], row["same host"], row["signed"],
                " | " + row["followed"] if row["followed"] else ""))
        return out


def main(argv: List[str]) -> int:
    from gamescan.scanner import neutral_scanner
    for folder in argv:
        with Recorder() as recorder:
            report = neutral_scanner().scan(folder)
        print("== %s: %s" % (os.path.basename(os.path.normpath(folder)), getattr(report, "verdict", "")))
        for line in recorder.lines():
            print("   " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
