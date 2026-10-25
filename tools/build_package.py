"""Build the user package of Bagel: one zip that runs without an installed Python.

    python tools/build_package.py --inputs <folder> --names <mapping file> --out <folder>

(backlog, item 19 (d); phageo, 2026-10-12 and 2026-10-24.) Layout, under one top folder
``Bagel-<version>/``:

    Bagel.exe                  the one start program (tools/build_launcher.py): starts the window with
    python/                    Python 3.13.16 64-bit, python.org's embeddable package (the tested
                               version), plus tkinter and Tcl/Tk from python.org's full package of
                               the same version
    app/GameSafetyScanner.pyw  the launcher
    app/gamescan/              the scanner, its tables and kept readings, and bagel.ico (the icon of
                               the window, the taskbar, the right-click menu and the installer)
    app/package_files.json     SHA-256 of every other file; the window checks them at start
    LICENSE                    the project's MIT licence (phageo)
    README.md                  the user part of the project's README.md
    THIRD-PARTY-NOTICES.txt    the licence of every bundled part, with python.org's notices
    RELEASE-NOTES.md           docs/RELEASE_NOTES.md: what 0.9-beta does and does not (EN / TR)

What it takes and refuses:

- **Inputs** are the two rows of ``tools/manifest_package.json`` (fetched before by
  ``fetch.py --manifest tools/manifest_package.json --to <inputs> --fetch``); each is compared with
  its row (size and SHA-256 as python.org states it) and refused on any difference. Nothing is
  downloaded, unpacked to disk or run here: members are copied from zip to zip.
- **The app** is ``GameSafetyScanner.pyw`` and ``gamescan/`` only (phageo, 2026-10-12): never
  ``tests/``, ``tests/_tools``, ``engine_archives``, ``docs/benchmark``, ``docs/memory``, the
  experimental behaviour monitor (``known_findings.NOT_SCAN_CODE``: the "Protection" window and
  real-time protection, hidden in 0.9-beta), ``__pycache__``, or a file of another kind than the
  allowlist names.
- **Every name of the zip is checked against the allowlist** (``ALLOWED``), the refused parts
  (``REFUSED``), and by content against every file of ``tests/`` and ``engine_archives`` (same size,
  then same SHA-256); one hit refuses the whole package.
- **No real game name** (CLAUDE.md, rule 11): the names come from the mapping file outside the
  project (``--names``), every text of the package is searched for them as whole words; a hit
  refuses the package and is reported by sample code and file only - a name is never printed.
- The zip is the same bytes for the same inputs (fixed order and time stamps).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html.parser
import io
import os
import re
import sys
import zipfile
from typing import Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fetch                                              # noqa: E402
import source_form                                        # noqa: E402
from gamescan import known_findings, models               # noqa: E402

MANIFEST = os.path.join(HERE, "manifest_package.json")
EMBED = "python-3.13.16-embeddable-amd64.zip"
FULL = "python-3.13.16-amd64.zip"
ENGINE_ARCHIVES = os.path.join(os.path.dirname(ROOT), "engine_archives")
START = "Bagel.exe"                                      # tools/launcher/Bagel.exe (build_launcher.py)
STAMP = (2026, 10, 24, 0, 0, 0)                          # every member's time: the same zip each build

# what the full package gives: tkinter, its library, Tcl/Tk and their script libraries
# (Tcl's own extensions dde / reg, build files and the Tk demos are not needed by the window)
FROM_FULL = ("Lib/tkinter/*", "DLLs/_tkinter.pyd", "DLLs/tcl86t.dll", "DLLs/tk86t.dll",
             "DLLs/zlib1.dll", "tcl/tcl8.6/*", "tcl/tk8.6/*", "tcl/tcl8/*")
NOT_FROM_FULL = ("tcl/tk8.6/demos/*",)

# the licence notes at the top of the package (packaging session 2, phageo 2026-10-24): the project's
# own MIT licence, the user part of README.md, and the notices of every bundled part
LICENSE = "LICENSE"
README = "README.md"
NOTICES = "THIRD-PARTY-NOTICES.txt"
HASHES = "app/package_files.json"                          # gamescan/selfcheck.py reads it at start
RELEASE_NOTES = "RELEASE-NOTES.md"                         # from docs/RELEASE_NOTES.md (session 3)
SHIPPED_PRINT = "app/gamescan/" + known_findings.SHIPPED_PRINT   # the project's code fingerprint
USER_START, USER_END = "<!-- user-section-start -->", "<!-- user-section-end -->"
ICON = "bagel.ico"                                          # tools/build_icon.py writes it (polish, 2026-10-25)

# every name the zip may hold (below its top folder)
ALLOWED = (START, LICENSE, README, NOTICES, HASHES, RELEASE_NOTES, SHIPPED_PRINT, "python/*", "app/GameSafetyScanner.pyw",
           "app/gamescan/*.py", "app/gamescan/*.bin", "app/gamescan/known_findings.json.gz",
           "app/gamescan/" + ICON)
# never in the zip, wherever they would stand (phageo, 2026-10-12 and 2026-10-24)
REFUSED = ("tests", "_tools", "engine_archives", "docs/benchmark", "docs/memory", "__pycache__",
           "yara_rules")
APP_KINDS = (".py", ".bin", ".json.gz", ".ico")


class PackageError(Exception):
    pass


def package_name() -> str:
    """``Bagel-<version>``: the version of ``models.TOOL_VERSION``, its one place."""
    return "Bagel-" + models.TOOL_VERSION


# -- what goes in --------------------------------------------------------------------------------
def app_files(root: str = ROOT) -> List[Tuple[str, str]]:
    """``(name in the zip, path)`` of the launcher and of ``gamescan/``, without the experimental
    behaviour monitor, caches and files of another kind."""
    out = [("app/GameSafetyScanner.pyw", os.path.join(root, "GameSafetyScanner.pyw"))]
    package = os.path.join(root, "gamescan")
    for base, dirs, files in os.walk(package):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            if not name.endswith(APP_KINDS):
                continue
            if base == package and name in known_findings.NOT_SCAN_CODE:
                continue
            path = os.path.join(base, name)
            out.append(("app/gamescan/" + os.path.relpath(path, package).replace("\\", "/"), path))
    return out


def _wanted(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def python_members(embed: zipfile.ZipFile, full: zipfile.ZipFile) -> List[Tuple[str, zipfile.ZipFile, str]]:
    """``(name in the zip, source zip, member)``: the whole embeddable package, then tkinter and
    Tcl/Tk from the full one (its ``DLLs`` beside ``python.exe``, ``Lib/tkinter`` as ``tkinter``,
    ``tcl`` as ``tcl`` - where ``_tkinter`` looks for it: ``sys.prefix``/tcl)."""
    out = [("python/" + i.filename, embed, i.filename) for i in embed.infolist() if not i.is_dir()]
    for info in full.infolist():
        name = info.filename
        if info.is_dir() or not _wanted(name, FROM_FULL) or _wanted(name, NOT_FROM_FULL):
            continue
        if name.startswith("DLLs/"):
            target = name[len("DLLs/"):]
        elif name.startswith("Lib/"):
            target = name[len("Lib/"):]
        else:
            target = name
        out.append(("python/" + target, full, name))
    names = [n for n, _z, _m in out]
    if len(set(n.lower() for n in names)) != len(names):
        raise PackageError("two members of the Python parts have the same name")
    return out


# -- the checks ----------------------------------------------------------------------------------
def refusal(name: str) -> str:
    """Why ``name`` (below the top folder) may not be in the package ("": it may)."""
    parts = name.split("/")
    if not name or name.startswith("/") or "\\" in name or any(p in ("", ".", "..") for p in parts):
        return "not a plain name"
    for refused in REFUSED:
        bits = refused.split("/")
        if any(parts[i:i + len(bits)] == bits for i in range(len(parts))):
            return "refused part: " + refused
    if name.startswith("app/gamescan/") and "/" not in name[len("app/gamescan/"):] \
            and parts[-1] in known_findings.NOT_SCAN_CODE:
        return "the experimental behaviour monitor (hidden in 0.9-beta)"
    if not _wanted(name, ALLOWED):
        return "not in the allowlist"
    return ""


def check_names(names: Iterable[str]) -> List[str]:
    """Every refusal of a list of names, as ``"name: why"``."""
    return ["%s: %s" % (n, refusal(n)) for n in names if refusal(n)]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def same_content(files: Dict[str, bytes], folders: Iterable[str]) -> Dict[str, List[str]]:
    """``{folder: [names]}``: the package files whose bytes equal a file in one of ``folders``
    (sizes first; only a file of a matching size is hashed)."""
    by_size: Dict[int, Dict[str, List[str]]] = {}
    for name, data in files.items():
        by_size.setdefault(len(data), {}).setdefault(_sha256(data), []).append(name)
    found: Dict[str, List[str]] = {}
    for folder in folders:
        found[folder] = []
        for base, _dirs, names in os.walk(folder):
            for n in names:
                path = os.path.join(base, n)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size not in by_size:
                    continue
                with open(path, "rb") as fh:
                    hits = by_size[size].get(_sha256(fh.read()), [])
                found[folder] += [h for h in hits if h not in found[folder]]
    return found


_CODE = re.compile(r"^\s*([A-Z]{2,4}\d?-\d{2})\s*(\||=)\s*(.*)$")
# samples that are official tool packages, not games: the names of their tools stand in the code
# on purpose (Inno Setup, NSIS, the Cpp2IL test builds, python.org's / Microsoft's packages)
_NOT_GAMES = ("INS-01", "INS-02", "IL2-", "MSI-")
_QUOTED = re.compile(r'"([^"]{4,120})"')


def real_names(mapping: str) -> Dict[str, List[str]]:
    """``{sample code: [names]}`` of the game samples in the mapping file (outside the project):
    the name column or the text after ``CODE =``, without a version or a note in brackets, and the
    file names quoted beside it. Never printed."""
    with open(mapping, encoding="utf-8-sig", errors="replace") as fh:
        lines = fh.read().splitlines()
    out: Dict[str, List[str]] = {}
    for line in lines:
        m = _CODE.match(line)
        if not m or m.group(1).startswith(_NOT_GAMES):
            continue
        code, rest = m.group(1), m.group(3)
        first = rest.split("|")[0] if m.group(2) == "|" else rest
        first = re.sub(r"^\s*(folder|klas\w*)\s+", "", first, flags=re.IGNORECASE)   # 'HO2-01 = folder "..."'
        # quoted texts beside a name are file names ('"Game-1.0-pc.zip"'); a quoted plain word is a note
        quoted = _QUOTED.findall(rest)
        head = re.split(r"\s+\(|,|\"", first)[0]
        if not head.strip() and quoted:             # 'HO2-01 = folder "<name>"': the name is quoted
            head = quoted[0]
        candidates = [head] + [q for q in quoted if re.search(r"[._\d-]", q)]
        for text in candidates:
            for name in (text, re.sub(r"[\s_-]*v?\d+(\.\d+)+.*$", "", text)):
                name = " ".join(name.replace("_", " ").split()).strip(" .-'")
                if len(name) >= 4 and re.search(r"[A-Za-z]{3}", name) and name not in out.get(code, []):
                    out.setdefault(code, []).append(name)
    return out


def name_hits(files: Dict[str, bytes], names: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """``(sample code, package file)`` for every real name found as whole words: as written
    (``_`` / ``-`` / spaces between its words count as the same), and in any case when its words
    are joined without a space (``quiet_field``, ``QuietField``) - so that a name made of plain
    words ("Quiet Field") does not refuse the English of a comment ("a quiet field")."""
    patterns = []
    for code, found in names.items():
        for name in found:
            words = [re.escape(w) for w in re.split(r"[\s_-]+", name) if w]
            edge = r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])"
            patterns.append((code, re.compile(edge % r"[\s_-]*".join(words))))
            if len(words) == 1:
                patterns.append((code, re.compile(edge % words[0], re.IGNORECASE)))
            else:
                patterns.append((code, re.compile(edge % r"[_-]?".join(words), re.IGNORECASE)))
    hits = []
    for file_name, data in sorted(files.items()):
        text = data.decode("latin-1")
        for code, pattern in patterns:
            if pattern.search(text) and (code, file_name) not in hits:
                hits.append((code, file_name))
    return hits


# -- the texts at the top of the package ---------------------------------------------------------
def user_readme(root: str = ROOT) -> bytes:
    """The user part of README.md (between ``USER_START`` and ``USER_END``), as the package's
    README.md: how to start, the verdicts, the right-click menu, the 0.9 limits, the licence."""
    with open(os.path.join(root, README), encoding="utf-8") as fh:
        text = fh.read()
    start, end = text.find(USER_START), text.find(USER_END)
    if start < 0 or end < start:
        raise PackageError("README.md has no user section (%s ... %s)" % (USER_START, USER_END))
    body = text[start + len(USER_START):end].strip("\n")
    return ("# Bagel %s\n\n%s\n" % (models.TOOL_VERSION, body)).encode("utf-8")


class _Text(html.parser.HTMLParser):
    """Plain text of one ``<section id=...>`` of an HTML page (python.org's license.html)."""

    def __init__(self, section: str) -> None:
        super().__init__(convert_charrefs=True)
        self.section, self.depth, self.pre, self.out = section, 0, 0, []

    def handle_starttag(self, tag, attrs):
        if self.depth:
            self.depth += tag == "section"
            if tag == "pre":
                self.pre += 1
            if tag in ("p", "h2", "h3", "pre", "li"):
                self.out.append("\n\n" + ("-- " if tag == "h3" else ""))
        elif tag == "section" and dict(attrs).get("id") == self.section:
            self.depth = 1

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= tag == "section"
            self.pre -= tag == "pre"

    def handle_data(self, data):
        if self.depth and data != "¶":                     # the pilcrow of each heading link
            if self.pre:
                self.out.append(data)
            elif data.strip():                                  # one space where the page had any
                lead = data[0].isspace() and self.out and not self.out[-1].endswith((" ", "\n"))
                self.out.append((" " if lead else "") + " ".join(data.split())
                                + (" " if data[-1].isspace() else ""))
            elif data and self.out and not self.out[-1].endswith((" ", "\n")):
                self.out.append(" ")

    def text(self) -> str:
        lines = "".join(self.out).replace("¶", "").splitlines()
        return re.sub(r"\n{3,}", "\n\n", "\n".join(l.rstrip() for l in lines)).strip() + "\n"


def incorporated(full: zipfile.ZipFile) -> str:
    """python.org's "Licenses and Acknowledgements for Incorporated Software" (Doc/html/license.html
    of the full package), as plain text."""
    page = _Text("licenses-and-acknowledgements-for-incorporated-software")
    page.feed(full.read("Doc/html/license.html").decode("utf-8"))
    text = page.text()
    if "zlib" not in text or "expat" not in text:
        raise PackageError("license.html of the full package has no list of incorporated software")
    return text


NOTICES_HEAD = """Bagel %(version)s - notices of the parts shipped in this package
=============================================================================

Bagel itself (app/ and the start file) is under the MIT licence:
see LICENSE ("Copyright (c) 2026 phageo").

The python/ folder is not ours. It is python.org's Python 3.13.16 for 64-bit Windows,
unchanged: the embeddable package, plus tkinter and Tcl/Tk copied from python.org's
full package of the same version. Each part keeps its own licence:

  Part (file in python/)                         Licence                          Full text
  Python 3.13.16 (python.exe, python313.dll,     PSF License Version 2;           python/LICENSE.txt
    python313.zip, *.pyd)                        Zero-Clause BSD for doc code
  Microsoft C runtime (vcruntime140*.dll)        Microsoft Distributable Code     python/LICENSE.txt,
                                                 terms                            "Additional Conditions"
  OpenSSL 3.5 (libcrypto-3.dll, libssl-3.dll)    Apache License 2.0               python/LICENSE.txt
  bzip2 1.0.8 (in _bz2.pyd)                      bzip2 licence (BSD-style)        python/LICENSE.txt
  libffi (libffi-8.dll)                          MIT                              python/LICENSE.txt
  Tcl 8.6 (tcl86t.dll, tcl/tcl8.6, tcl/tcl8)     Tcl/Tk licence (BSD-style)       python/LICENSE.txt
  Tk 8.6 (tk86t.dll, tcl/tk8.6)                  Tcl/Tk licence (BSD-style)       python/LICENSE.txt,
                                                                                  python/tcl/tk8.6/license.terms
  tkinter (tkinter/, _tkinter.pyd)               PSF License Version 2            python/LICENSE.txt
  zlib (zlib1.dll; also inside python313.dll)    zlib licence                     below
  Expat 2.8 (in pyexpat.pyd)                     MIT                              below
  libmpdec 4.0 (in _decimal.pyd)                 BSD 2-clause                     below
  mimalloc, SipHash, Mersenne Twister, dtoa,     their own permissive terms       below
    and the other code python.org lists
  SQLite 3.50 (sqlite3.dll)                      public domain                    (no licence needed;
                                                                                  sqlite.org/copyright.html)
  liblzma of XZ Utils (in _lzma.pyd)             public domain (up to 5.4) or     (the file does not state
                                                 0BSD (5.6 and later)             its version)
  Time zone data of Tcl (tcl/tcl8.6/tzdata)      public domain                    -

None of these licences asks for the source code of Bagel or limits its
MIT licence; together they only ask that their notices stay with the files - which
python/LICENSE.txt, python/tcl/tk8.6/license.terms and this file do. The Microsoft
terms also forbid using the C runtime in malicious, deceptive or unlawful programs.

Below, word for word: python.org's "Licenses and Acknowledgements for Incorporated
Software" (Doc/html/license.html of python-3.13.16-amd64.zip), as plain text.

=============================================================================

"""


def notices(full: zipfile.ZipFile) -> bytes:
    return ((NOTICES_HEAD % {"version": models.TOOL_VERSION}) + incorporated(full)).encode("utf-8")


def hash_list(files: Dict[str, bytes]) -> bytes:
    """``app/package_files.json``: the SHA-256 of every other file of the package."""
    import json
    data = {"about": "SHA-256 of every file of this package, written when it was built "
                     "(tools/build_package.py). The window compares the files with it at start "
                     "(gamescan/selfcheck.py): it finds damage, it cannot prove that nobody "
                     "changed the package on purpose.",
            "version": models.TOOL_VERSION,
            "files": {name: _sha256(data) for name, data in sorted(files.items()) if name != HASHES}}
    return (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8")


def private_names(env: Optional[Dict[str, str]] = None) -> List[str]:
    """The Windows user name of the PC that builds the package (``USERNAME``, the last part of
    ``USERPROFILE``) and that profile folder itself: none may stand in the package (packaging
    session 3, phageo: the author is phageo, never a real name; paths say %USERPROFILE%)."""
    env = os.environ if env is None else env
    names = []
    profile = env.get("USERPROFILE", "")
    for name in (env.get("USERNAME", ""), os.path.basename(profile.rstrip("\\/")), profile):
        if len(name) >= 3 and name.lower() not in [n.lower() for n in names]:
            names.append(name)
    return names


def private_hits(files: Dict[str, bytes], env: Optional[Dict[str, str]] = None) -> List[str]:
    """Package files that hold a name of ``private_names`` (whole word, any case; a profile path
    also with ``/`` or doubled ``\\``)."""
    patterns = []
    for name in private_names(env):
        text = re.escape(name).replace(r"\\", r"[\\/]+")
        patterns.append(re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % text, re.IGNORECASE))
    return [file_name for file_name, data in sorted(files.items())
            if any(p.search(data.decode("latin-1")) for p in patterns)]


# -- the build -----------------------------------------------------------------------------------
def _checked_input(inputs: str, name: str, rows: Dict[str, dict]) -> str:
    path = os.path.join(inputs, name)
    if name not in rows:
        raise PackageError("not a row of %s: %s" % (os.path.basename(MANIFEST), name))
    problem = fetch.difference(rows[name], path)
    if problem:
        raise PackageError("%s is not the listed file (%s) - fetch it with fetch.py --manifest "
                           "tools/manifest_package.json" % (name, problem))
    return path


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def build(inputs: str, mapping: str, out_dir: str, say=print) -> str:
    """Write the package zip into ``out_dir`` (outside the project) and return its path."""
    if _inside(out_dir, ROOT):
        raise PackageError("the package is written outside the project: " + out_dir)
    if _inside(mapping, ROOT):
        raise PackageError("the mapping file must lie outside the project: " + mapping)
    rows = fetch.load(MANIFEST)
    embed_path = _checked_input(inputs, EMBED, rows)
    full_path = _checked_input(inputs, FULL, rows)
    say("inputs as listed (size and SHA-256 of python.org): %s, %s" % (EMBED, FULL))
    import build_launcher
    problem = build_launcher.check()
    if problem:
        raise PackageError(problem)
    with open(build_launcher.PROGRAM, "rb") as fh:
        files: Dict[str, bytes] = {START: fh.read()}
    say("start program %s: version %s, SHA-256 as in launcher.json" % (START, models.TOOL_VERSION))
    # modules without comments and docstrings (antivirus false positives, phageo 2026-10-24): the
    # same code by syntax tree (source_form.strip proves it); the project's source stays as it is
    for name, path in app_files():
        with open(path, "rb") as fh:
            files[name] = fh.read()
        if name.endswith((".py", ".pyw")):
            files[name] = source_form.strip(files[name])
            if source_form.strip(files[name]) != files[name]:
                raise PackageError("stripping %s twice does not give the same file" % name)
    say("modules shipped without comments and docstrings: %d" % sum(n.endswith((".py", ".pyw")) for n in files))
    # ... so the kept readings are tied to the project's fingerprint, written into the package
    files[SHIPPED_PRINT] = (known_findings.fingerprint() + "\n").encode("ascii")
    with open(os.path.join(ROOT, LICENSE), "rb") as fh:
        files[LICENSE] = fh.read()
    if b"MIT License" not in files[LICENSE] or b"Copyright (c) 2026 phageo" not in files[LICENSE]:
        raise PackageError("LICENSE is not the project's MIT licence of phageo")
    files[README] = user_readme()
    with open(os.path.join(ROOT, "docs", "RELEASE_NOTES.md"), "rb") as fh:
        files[RELEASE_NOTES] = fh.read()
    if ("Bagel " + models.TOOL_VERSION).encode() not in files[RELEASE_NOTES]:
        raise PackageError("docs/RELEASE_NOTES.md is not the notes of " + models.TOOL_VERSION)
    with zipfile.ZipFile(embed_path) as embed, zipfile.ZipFile(full_path) as full:
        for name, source, member in python_members(embed, full):
            files[name] = source.read(member)
        files[NOTICES] = notices(full)
    for needed in ("python/LICENSE.txt", "python/tcl/tk8.6/license.terms"):
        if needed not in files:
            raise PackageError("a licence text of the Python parts is missing: " + needed)
    # the indicator strings stand in gamescan/indicators.bin, compressed, not as text in a module
    # (antivirus false positives, phageo 2026-10-24; tools/move_indicators.py)
    import move_indicators
    plain = move_indicators.left_in(files)
    say("modules with an indicator string as plain text: %d" % len(plain))
    if plain:
        raise PackageError("indicator strings as text in: %s - run tools/move_indicators.py" % ", ".join(plain))
    files[HASHES] = hash_list(files)
    refused = check_names(files)
    if refused:
        raise PackageError("refused names:\n  " + "\n  ".join(refused))
    folders = [os.path.join(ROOT, "tests"), ENGINE_ARCHIVES]
    same = same_content(files, [f for f in folders if os.path.isdir(f)])
    for folder in folders:
        say("files with the content of a file in %s: %d" % (folder, len(same.get(folder, []))))
    if any(same.values()):
        raise PackageError("files from tests / engine_archives: " + ", ".join(sorted(
            n for names in same.values() for n in names)))
    names = real_names(mapping)
    hits = name_hits({n: d for n, d in files.items() if not n.startswith("python/")}, names)
    say("real game names searched: %d names of %d samples; found: %d" % (
        sum(len(v) for v in names.values()), len(names), len(hits)))
    if hits:
        raise PackageError("a real game name stands in the package: " + ", ".join(
            "%s in %s" % hit for hit in hits))
    private = private_hits({n: d for n, d in files.items() if not n.startswith("python/")})
    say("Windows user name of this PC (and its profile path) searched: found in %d file(s)" % len(private))
    if private:
        raise PackageError("the Windows user name of this PC stands in: " + ", ".join(private))
    os.makedirs(out_dir, exist_ok=True)
    top = package_name()
    target = os.path.join(out_dir, top + ".zip")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(top + "/" + name, STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, files[name])
    # the written zip is read back and checked once more against the allowlist
    with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as z:
        listed = [i.filename for i in z.infolist()]
    inner = [n[len(top) + 1:] if n.startswith(top + "/") else "" for n in listed]
    refused = check_names(inner)
    if refused or len(inner) != len(files):
        raise PackageError("the written zip does not match the allowlist: " + "; ".join(refused))
    with open(target, "wb") as fh:
        fh.write(buffer.getvalue())
    counts = {"python": sum(n.startswith("python/") for n in inner),
              "app": sum(n.startswith("app/") for n in inner), "start file": inner.count(START),
              "notes": sum(n in (LICENSE, README, NOTICES, RELEASE_NOTES) for n in inner)}
    say("%s: %d files (%s), %.1f MB unpacked, %.1f MB zip" % (
        target, len(inner), ", ".join("%s %d" % kv for kv in counts.items()),
        sum(len(d) for d in files.values()) / 1048576, os.path.getsize(target) / 1048576))
    return target


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--inputs", required=True, help="folder with the two python.org files of "
                    "tools/manifest_package.json (outside the project)")
    ap.add_argument("--names", required=True, help="the code -> real name mapping file (outside "
                    "the project): no real game name may stand in the package")
    ap.add_argument("--out", required=True, help="folder the zip is written to (outside the project)")
    args = ap.parse_args(argv)
    try:
        build(args.inputs, args.names, args.out)
    except (PackageError, fetch.FetchError, OSError, zipfile.BadZipFile) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
