"""Build ``gamescan/inno_official.py``: what is official in an Inno Setup installer.

Every installer made with Inno Setup carries programs of Inno Setup itself -
the setup engine (``Setup.e32``, ``SetupCustomStyle.e32``) and its loaders
(``SetupLdr.e32`` / ``.e64``) - and the standard messages of the languages it
was built with; an installer of Inno Setup itself carries the whole compiler.
None of that is the work of whoever made the installer. This tool writes two
tables the scanner compares with:

* the SHA-256 of every file of the official distributions (the compiler and
  its editor, the libraries, the setup engine and its loaders, the language
  files, the examples, the help);
* the standard message texts (the ``[Messages]`` entries of ``Default.isl``
  and of every bundled language file) in which the scanner's rule for system
  tools (``LOL-001``) finds a word - ``RegSvr32 failed with exit code %1``.
  Only these are kept: the table is for that rule. After a change to the
  rule's pattern, run this tool again.

The same rule as ``tools/build_engine_hashes.py``: official files only, never
a scanned sample. The source is the official installers of Inno Setup
themselves (``SOURCES``): 5.x from ``files.jrsoftware.org``, 6.x from the
releases of ``jrsoftware/issrc`` on GitHub, where jrsoftware.org sends its
downloads. They are kept in the folder of official archives; one that is
missing is downloaded - through ``tools/fetch.py`` (this tool has no
download of its own; only a row of ``tools/manifest.json`` with the recorded
SHA-256 is fetched). **An installer whose SHA-256 is not the recorded one
is refused** - the recorded value is the one GitHub shows for the release
(6.x) or the one the file had when it was first downloaded on 2026-10-11
(5.x: nothing is published for them). The installers are never run: their
files are read out of them in memory with the scanner's own reader
(``gamescan.unpack.inno``), each to the installer's own checksum, and only
hashed; nothing is unpacked to disk.

    python tools/build_inno_tables.py --archives C:\\somewhere\\engine_archives
    python tools/build_inno_tables.py --archives ... --offline     (never downloads)

A note about the sources (``inno-setup-SOURCES.txt``) is written beside the
installers. To cover another version, add it to ``SOURCES`` (at the end: the
table holds row numbers) and run again.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import sys
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT = os.path.join(ROOT, "gamescan", "inno_official.py")
NOTE = "inno-setup-SOURCES.txt"
_GITHUB = "https://github.com/jrsoftware/issrc/releases/download/is-%s/innosetup-%s.exe"

# (version, address, file name in the archives folder, SHA-256 of the installer)
SOURCES: List[Tuple[str, str, str, str]] = [
    ("5.5.9", "https://files.jrsoftware.org/is/5/innosetup-5.5.9-unicode.exe", "innosetup-5.5.9-unicode.exe",
     "5b51ae6977bebba937ac18e0e80c1899e37dfaa12f51ccd817978ef07ae19cb3"),
    ("5.6.1", "https://files.jrsoftware.org/is/5/innosetup-5.6.1-unicode.exe", "innosetup-5.6.1-unicode.exe",
     "27d49e9bc769e9d1b214c153011978db90dc01c2acd1ddcd9ed7b3fe3b96b538"),
    ("6.0.5", _GITHUB % ("6_0_5", "6.0.5"), "innosetup-6.0.5.exe",
     "ae6823b523df87e9441789e51845434e4e0e70aac0b88afe80f94f20f4b98acb"),
    ("6.2.2", _GITHUB % ("6_2_2", "6.2.2"), "innosetup-6.2.2.exe",
     "8117d10d00a2ad33a1390978ea3872861c330e087914410a6377b22c4c5b8563"),
    ("6.4.3", _GITHUB % ("6_4_3", "6.4.3"), "innosetup-6.4.3.exe",
     "f3c42116542c4cc57263c5ba6c4feabfc49fe771f2f98a79d2f7628b8762723b"),
    ("6.7.3", _GITHUB % ("6_7_3", "6.7.3"), "innosetup-6.7.3.exe",
     "9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732"),
]

RULE = "LOL-001"
MAX_INSTALLER = 64 * 1024 * 1024         # one downloaded installer
MAX_FILES = 5000                         # files in one installer
MAX_FILE = 64 * 1024 * 1024              # one of them
MAX_MESSAGE = 4096
_CHUNK = 1 << 20
_CODEPAGE = re.compile(r"(?im)^\s*LanguageCodePage\s*=\s*(\d+)")


class BuildError(Exception):
    pass


def download(url: str, target: str, recorded: str, say=print) -> None:
    """Through ``tools/fetch.py`` - this tool has no download of its own (phageo,
    2026-10-12): only the row of ``tools/manifest.json`` with this address and
    the recorded SHA-256 is fetched; a download that is not that file is
    refused and deleted there."""
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    try:
        fetch.fetch(fetch.listed(url, recorded), target, say=say)
    except fetch.FetchError as exc:
        raise BuildError(str(exc))


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def check(path: str, recorded: str) -> None:
    """Refuse an installer whose SHA-256 is not the recorded one."""
    found = sha256_of(path)
    if found != recorded:
        raise BuildError("%s: SHA-256 %s is not the recorded %s - refused"
                         % (os.path.basename(path), found, recorded))


def files_of(path: str) -> Dict[str, bytes]:
    """``{name: content}`` of every file the installer at ``path`` installs, read
    in memory with the scanner's own reader - byte-identical to what the
    installer would write, by its own checksums. Nothing is run."""
    from gamescan.pe import parse_pe
    from gamescan.unpack import inno
    if os.path.getsize(path) > MAX_INSTALLER:
        raise BuildError("installer too large: " + path)
    with open(path, "rb") as fh:
        data = fh.read()
    pe = parse_pe(data)
    if pe is None:
        raise BuildError("not a program: " + path)
    try:
        installer = inno.Installer(lambda: io.BytesIO(data), inno.find(data, pe.overlay_offset),
                                   pe.overlay_offset, inno.chunks(data, pe.overlay_offset))
        if len(installer.entries) > MAX_FILES:
            raise BuildError("too many files in " + path)
        problems: List[str] = []
        out: Dict[str, bytes] = {}
        for name, content in installer.members(lambda name, size: size <= MAX_FILE, problems=problems):
            if not isinstance(content, bytes):          # (kept in a temporary file: a large member)
                whole = content.read()
                content.release()
                content = whole
            out[name] = content
    except inno.InnoError as exc:
        raise BuildError("%s could not be read: %s" % (os.path.basename(path), exc))
    if problems or len(out) != len(installer.entries):
        raise BuildError("%s: not every file was read (%s)" % (os.path.basename(path),
                                                               "; ".join(problems) or "%d of %d" % (
                                                                   len(out), len(installer.entries))))
    return out


def read_text(raw: bytes) -> str:
    """A language file: UTF-8 (with or without its mark), or the code page it names."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        page = _CODEPAGE.search(raw.decode("latin-1"))
        number = int(page.group(1)) if page else 0
        try:
            return raw.decode("cp%d" % (number or 1252))
        except (LookupError, UnicodeDecodeError):
            return raw.decode("cp1252", "replace")


def messages(text: str) -> List[str]:
    """The texts of the ``[Messages]`` section, cut at their line breaks (``%n``):
    that is how an installer stores them."""
    out, inside = [], False
    for line in text.splitlines():
        line = line.strip("\ufeff")
        if line.lstrip().startswith("["):
            inside = line.strip().lower() == "[messages]"
            continue
        if not inside or not line.strip() or line.lstrip().startswith(";") or "=" not in line:
            continue
        for part in line.split("=", 1)[1].split("%n"):
            if part.strip() and len(part) <= MAX_MESSAGE:
                out.append(part)
    return out


def _language_file(name: str) -> bool:
    lower = name.lower()
    return lower == "default.isl" or (lower.startswith("languages/") and lower.rsplit(".", 1)[-1] in ("isl", "islu"))


def build(folder: str, offline: bool = False, say=print):
    """Returns ``(archives, files, texts)``: the rows of ``ARCHIVES``,
    ``{sha256: (file name, indexes of the installers that hold it)}`` and the
    sorted message texts."""
    from gamescan.rules import RuleEngine
    pattern = next(rule for rule in RuleEngine().rules if rule.id == RULE).regex
    archives, files, texts = [], {}, {}
    for version, url, file_name, recorded in SOURCES:
        path = os.path.join(folder, file_name)
        say("Inno Setup %s: %s" % (version, file_name))
        if not os.path.isfile(path):
            if offline:
                raise BuildError("missing (offline): " + path)
            download(url, path, recorded, say)
        check(path, recorded)
        inside = files_of(path)
        if "ISCC.exe" not in inside or "Default.isl" not in inside:
            raise BuildError("%s is not an installer of the Inno Setup compiler" % file_name)
        archives.append((version, url, recorded))
        count = languages = 0
        for name in sorted(inside):
            digest = hashlib.sha256(inside[name]).hexdigest()
            known = files.get(digest)
            if known is None:
                files[digest] = (name, (len(archives) - 1,))
            elif known[1][-1] != len(archives) - 1:
                files[digest] = (known[0], known[1] + (len(archives) - 1,))
            if _language_file(name):
                languages += 1
                for message in messages(read_text(inside[name])):
                    if pattern.search(message):
                        texts.setdefault(message, len(archives) - 1)
                        count += 1
        say("  %d files, %d language files, %d messages with a word of %s" % (len(inside), languages, count, RULE))
    return archives, files, sorted(texts)


def write_note(folder: str, archives) -> None:
    with open(os.path.join(folder, NOTE), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("Official installers of the Inno Setup compiler, kept for tools/build_inno_tables.py\n"
                 "(GameSafetyScanner). Read only; never run. 5.x: files.jrsoftware.org. 6.x: the releases of\n"
                 "jrsoftware/issrc on GitHub, where jrsoftware.org sends its downloads; their SHA-256 is the\n"
                 "one GitHub shows for the release. 5.x: nothing is published - the value of the first\n"
                 "download on 2026-10-11.\n\n")
        for (version, url, digest), source in zip(archives, SOURCES):
            fh.write("%s\n  Inno Setup %s\n  %s\n  SHA-256 %s\n" % (source[2], version, url, digest))


def render(archives, files, texts) -> str:
    lines = [
        '"""Official parts of Inno Setup installers, recognised by their exact content.',
        "",
        "GENERATED by tools/build_inno_tables.py - do not edit by hand.",
        "",
        "Every installer made with Inno Setup carries Inno Setup's own programs - the",
        "setup engine and its loaders - and the standard messages of its languages;",
        "an installer of Inno Setup itself carries the whole compiler. A file whose",
        "SHA-256 is in ``FILES`` *is*, byte for byte, a file of an official Inno",
        "Setup distribution: it was read out of the official installer named in",
        "``ARCHIVES`` (address and SHA-256; an installer with another SHA-256 is",
        "refused when the table is built). ``MESSAGES`` holds the standard message",
        "texts (``[Messages]`` of ``Default.isl`` and the bundled language files) in",
        "which the rule LOL-001 finds the name of a system tool. Nothing here was",
        "taken from a scanned sample.",
        "",
        "Genuine does not mean harmless in every use: what an installer does with its",
        'engine - its ``[Code]``, its ``[Run]`` rows, its files - is scanned on its own.',
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Optional",
        "",
        "# version, address of the official installer, its SHA-256",
        "ARCHIVES = (",
    ]
    lines += ["    %r," % (row,) for row in archives]
    lines += [")", "",
              "# SHA-256 of the file -> (its name in the distribution, indexes into ARCHIVES of every",
              "# installer that holds it). The table is the official distribution - every file of it,",
              "# on purpose (phageo, 2026-10-11); the scanner asks it for programs only.",
              "FILES = {"]
    lines += ["    %r: %r," % (digest, entry)
              for digest, entry in sorted(files.items(), key=lambda kv: (kv[1][1], kv[1][0], kv[0]))]
    lines += ["}", "",
              "# standard message texts with a word of LOL-001 in them, as an installer stores them",
              "MESSAGES = frozenset({"]
    lines += ["    %s," % ascii(text) for text in texts]
    lines += ["})", "", "",
              "def verified(sha256: str) -> Optional[str]:",
              '    """What official Inno Setup file has this SHA-256 (None: not in the table):',
              "    its name and the versions that hold it - ``6.2.2-6.7.3`` for a row of versions",
              '    of the table, single versions with commas between them otherwise."""',
              '    entry = FILES.get((sha256 or "").lower())',
              "    if entry is None:",
              "        return None",
              "    name, held = entry",
              "    if len(held) > 1 and held[-1] - held[0] == len(held) - 1:",
              '        versions = "%s-%s" % (ARCHIVES[held[0]][0], ARCHIVES[held[-1]][0])',
              "    else:",
              '        versions = ", ".join(ARCHIVES[index][0] for index in held)',
              '    return "%s - Inno Setup %s" % (name, versions)',
              "", "",
              "def standard_message(text: str) -> bool:",
              '    """Is ``text`` exactly a standard message of Inno Setup (of the kind kept here)?"""',
              "    return text in MESSAGES",
              ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True, help="folder the official installers are kept in")
    parser.add_argument("--offline", action="store_true", help="never download; fail when an installer is missing")
    parser.add_argument("--out", default=OUT, help="the table to write (default: %(default)s)")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.archives):
        parser.error("not a folder: %s" % args.archives)
    try:
        archives, files, texts = build(args.archives, args.offline)
    except BuildError as exc:
        print("STOPPED: %s" % exc)
        return 1
    write_note(args.archives, archives)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(archives, files, texts))
    print("%d files, %d messages -> %s" % (len(files), len(texts), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
