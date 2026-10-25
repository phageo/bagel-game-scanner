"""A checked self-update of an Electron app (phageo, 2026-10-14, forty-third message).

An app that downloads a new version of itself and starts it is, to the data-flow reading, a
``CHAIN-REMOTE-CODE``: a download is written to a file and that file is started. phageo's
policy (strict): such a chain is a *checked self-update* - its own name, MEDIUM, the launcher
asks once - only when **all** of these hold:

1. what is run is a file the download was written to (not downloaded code given to ``eval``
   or a runtime), found by following the file's path (``remote.Hit.route``);
2. **every** way the reading found from the write to the start passes a signature check -
   also through a marker file the app writes only after a check (``RemoteFlow._gated``). A
   check is a real crypto verification (phageo, 2026-10-15, two messages; ``RemoteFlow._checked``):
   Get-AuthenticodeSignature in a command the app starts, WinVerifyTrust, a verified updater
   library's check, or the verify call of a crypto library (openpgp.verify, node's
   crypto.verify / createVerify) with the public key written out in the app - and the start
   is reached only on its success (in the success branch, behind a guard that leaves on
   failure, or behind a check that throws on failure); a start on the failure branch is no
   check, nor is a function only named like a check. The check's own start of PowerShell is
   no start of the file (``_only_check``);
3. the script was read to its end (no limit, no failed reading, not code decoded out of it);
4. the server is written out in the script, or comes from a JSON settings file packed with the
   app itself (``require("./config.json")``);
5. HTTPS;
6. the server is one the app names for itself (its ``package.json``: homepage, repository,
   bugs, author, the updater's ``publish``; an ``app-update.yml``) - the same last two names.

Anything else stays CRITICAL. The same server, HTTPS or an address written out are not enough
alone: without the signature check on every way it stays CRITICAL (his words). Only for the
scripts of an Electron app (``electron_windows.app_root``): the app's own files are what (4)
and (6) are read from.

What this cannot see (README): the checked file and the marker lie where the app put them -
in the temporary folder, as a rule - and another program could change them between the check
and the start; which way the check's answer points is read from the text (a condition, a
guard, an awaited throw), not run; whether the key written in the app belongs to the app's
maker is not read. The crypto library must itself be verified (phageo, 2026-10-15, forty-sixth
message; ``libraries``): OpenPGP as the files of the published npm package in the app's own
``node_modules/openpgp/``, node's crypto through a verified Electron runtime. Which of several
copies ``require`` would load is not worked out: every copy of the app has to be the published
one.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

SELF_UPDATE = "self_update"         # Finding.context: a dropper chain that may be a checked self-update
RULE = "CHAIN-SELF-UPDATE"
MAX_FILE = 256 * 1024               # bytes of one settings file that are kept
MAX_FILES = 2_000                   # settings files of one scan that are kept
_SETTINGS = re.compile(r"\A‹\.?/?((?:[\w.-]+/)*[\w.-]+\.json)\.([\w.$]+)›")
_YML_URL = re.compile(r"(?m)^\s*url:\s*['\"]?(\S+?)['\"]?\s*$")
KEPT = (".json", ".yml", ".yaml")
REASON = (
    "This app downloads a new version of itself and starts it. Every way from the download to "
    "the start that the scanner found passes a real check of the file's digital signature - "
    "Windows' own, or a cryptographic check with a public key written in the app - and the file "
    "is started only when that check passes; the "
    "download uses an encrypted connection (HTTPS), and the server is the app's own - written "
    "in the app or in its own settings, and the one its package names. That is how a careful "
    "updater is built. It still means the app can run a program after this scan that the scan "
    "never saw; the scanner reads where the signature is checked, not whether the check is "
    "right, and the downloaded file waits in a folder other programs can write to.")


def candidate(hit) -> Optional[dict]:
    """What a ``remote.Hit`` brings to the policy - None when (1) or (2) fails already."""
    if hit.how != "dropper" or hit.weak or not hit.route or hit.ways <= 0 or hit.checked_ways != hit.ways:
        return None
    return {"address": hit.address or "", "source": hit.source or "", "ways": hit.ways,
            "checks": list(getattr(hit, "checks", ()) or ())}


# The crypto library a check is made with must itself be verified (phageo, 2026-10-15, forty-sixth
# message): the OpenPGP library a verified npm file (every script file of the app's own
# node_modules/openpgp/ is a file of the published package, by its SHA-256), node's crypto the
# one of a verified Electron runtime (the app's program, by the Electron table). A library only
# named like one - a folder called openpgp, a copy bundled into the app's own script - does not
# count.
CRYPTO_PACKAGES = {"pgp": "openpgp"}
_PACKAGE_FILE = re.compile(r"(?:\A|[/!])node_modules/(openpgp)/(?:[^!]*/)?[^/!]+\.(?:c?js|mjs)\Z")


def crypto_package(relpath: str) -> str:
    """The crypto package (``openpgp``) a script file of an app's ``node_modules`` belongs to
    ("": none)."""
    m = _PACKAGE_FILE.search(relpath.replace("\\", "/").lower())
    return m.group(1) if m else ""


def libraries(checks, packages: Dict[str, List[int]], runtime: bool) -> Tuple[bool, str]:
    """``(the crypto libraries the checks rely on are verified, why not)``. ``packages``: per
    package ``[verified files, other files]`` of the app's ``node_modules``; ``runtime``: the
    app's Electron program is verified."""
    for kind in checks or ():
        package = CRYPTO_PACKAGES.get(kind)
        if package is not None:
            verified, other = (packages.get(package) or (0, 0))[:2]
            if not verified:
                return False, "the %s library it checks with is not a verified file of the published package" % package
            if other:
                return False, "the app's %s library holds files that are not those of the published package" % package
        elif kind == "node" and not runtime:
            return False, "it checks with node's crypto, and the app's Electron runtime is not verified"
    return True, ""


def _host(address: str) -> str:
    try:
        return (urlsplit(address).hostname or "").lower()
    except ValueError:
        return ""


def _domain(host: str) -> str:
    return ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else ""


def _settings(address: str, files: Dict[str, List[str]]) -> Optional[str]:
    """``‹./config.json.builds_dir›/...``: the address with that value of the app's own file
    (None: not such an address, or the value is not one text in every copy of the file)."""
    m = _SETTINGS.match(address)
    if not m:
        return None
    found = set()
    for text in files.get(m.group(1).rsplit("/", 1)[-1].lower(), ()):
        try:
            value = json.loads(text)
        except ValueError:
            continue
        for part in m.group(2).split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if not isinstance(value, str):
            return None
        found.add(value)
    return found.pop() + address[m.end():] if len(found) == 1 else None


def app_hosts(files: Dict[str, List[str]]) -> set:
    """The servers an app names for itself."""
    hosts = set()
    for text in files.get("package.json", ()):
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
                host = _host(re.sub(r"\A(?:git\+|github:)", "https://", place.strip()))
                if host:
                    hosts.add(host)
    for name in ("app-update.yml", "dev-app-update.yml"):
        for text in files.get(name, ()):
            hosts.update(_host(url) for url in _YML_URL.findall(text) if _host(url))
    return hosts


def judge(mark: dict, files: Dict[str, List[str]]) -> Tuple[bool, str]:
    """``(a checked self-update, why not / what holds)`` for conditions (4) to (6)."""
    address = mark["address"]
    settings = _settings(address, files)
    if settings is not None:
        resolved, where = settings, "from the app's own settings file"
    elif re.match(r"[A-Za-z]+://", address):        # (the server written out; a path may vary)
        resolved, where = address, "written out"
    else:
        return False, "the server is only known at run time"
    if "‹" in urlsplit(resolved).netloc:
        return False, "the server is only known at run time"
    if resolved.split(":", 1)[0].lower() != "https":
        return False, "not HTTPS"
    host = _host(resolved)
    own = {_domain(h) for h in app_hosts(files)} - {""}
    if not host or not own:
        return False, "the app names no server of its own"
    if _domain(host) not in own:
        return False, "the server is not one the app names for itself"
    return True, "server %s, HTTPS, the app's own" % where
