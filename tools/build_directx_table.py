"""Build ``gamescan/directx_official.py``: the libraries of the DirectX June 2010 package.

Games ship DirectX's redistributable libraries (``d3dx9_43.dll``, ``xinput1_3.dll``,
``xaudio2_7.dll`` ...) beside their programs. On disk Windows can check Microsoft's
signature on them; a library inside an archive that is read in memory cannot be
checked that way. This table lets the scanner recognise them there too, by SHA-256
(phageo, 2026-10-17; ``SIDELOAD-001``).

The source is one file: Microsoft's "DirectX End-User Runtimes (June 2010)"
redistributable package, a row of ``tools/manifest.json`` (Microsoft publishes no
SHA-256: the row holds the value of the first download, 2026-10-17). It comes
through ``tools/fetch.py`` only, and is kept in the folder of official archives.

What the builder checks, and stops on - nothing is written then:

- the package's own signature is a valid one of Microsoft (Windows' check);
- the package is a cabinet behind a small program, and every cabinet inside it is
  read to its end (the scanner's own cabinet reader since 2026-10-19 - Windows'
  ``cabinet.dll`` before -, in memory: nothing of it is unpacked to disk, nothing
  is run);
- **every library** (``.dll``) is checked for a valid signature of Microsoft. One
  that has none goes into a table of its own, ``FROM_SIGNED_PACKAGE``, tagged "from
  signed package" with the package's SHA-256 as its source (phageo, 2026-10-17: it
  came out of the package whose signature was verified; until then such libraries
  were left out), and is named in the builder's output. Windows
  checks signatures on files only, so each library is written for that check alone
  into a folder of its own in the temporary folder - under a name that cannot be run -
  and deleted right after; it is never run.

A developer's tool: the scanner never uses it, and it is not shipped.

    python tools/build_directx_table.py --archives C:\\somewhere\\engine_archives
    python tools/build_directx_table.py --archives ... --offline     (never downloads)
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import sys
import tempfile
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "gamescan", "directx_official.py")
URL = ("https://download.microsoft.com/download/8/4/a/84a35bf1-dafe-4ae8-82af-ad2ae20b6b14/"
       "directx_Jun2010_redist.exe")
FILE = "directx_Jun2010_redist.exe"
WHAT = "DirectX End-User Runtimes (June 2010)"
MICROSOFT = "Microsoft"
MAX_PACKAGE = 128 * 1024 * 1024          # the package itself
MAX_CABINET = 64 * 1024 * 1024           # one cabinet inside it
MAX_TOTAL = 1024 * 1024 * 1024           # everything unpacked, in memory


class BuildError(Exception):
    pass


def obtain(path: str, offline: bool, say=print) -> str:
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    try:
        return fetch.obtain(URL, path, offline=offline, say=say)["sha256"]
    except fetch.FetchError as exc:
        raise BuildError(str(exc))


def signer_of(data: bytes, name: str, folder: str) -> str:
    """The publisher on the valid signature of ``data`` ("" = none). Windows checks a
    file, so the bytes lie in ``folder`` for the check only, under a name nothing runs."""
    from gamescan import trust
    path = os.path.join(folder, hashlib.sha256(data).hexdigest()[:16] + ".check")
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        return trust.signer_name(path) or ""
    finally:
        os.remove(path)


def members(data: bytes, what: str) -> List[Tuple[str, bytes]]:
    """Every member of the cabinet(s) in ``data``, in memory (the scanner's own cabinet reader;
    Windows' ``cabinet.dll`` until 2026-10-19)."""
    from gamescan.unpack import cab, spool
    found = cab.find(data, limit=8)
    if not found:
        raise BuildError("%s holds no cabinet" % what)
    out: List[Tuple[str, bytes]] = []
    spool.DISK = False                           # (nothing of it on disk)
    total = 0
    for offset, size in found:
        notes: List[str] = []
        try:
            for name, blob in cab.members(cab.Window(io.BytesIO(data), offset, size),
                                          lambda name, length: length <= MAX_CABINET,
                                          memory=MAX_CABINET, notes=notes):
                if not isinstance(blob, (bytes, bytearray)):
                    raise BuildError("%s: a member did not stay in memory: %s" % (what, name))
                total += len(blob)
                if total > MAX_TOTAL:
                    raise BuildError("%s: more than %d MB unpacked" % (what, MAX_TOTAL >> 20))
                out.append((name, bytes(blob)))
        except (cab.CabError, spool.SpoolError) as exc:
            raise BuildError("%s could not be read to its end: %s" % (what, exc))
        if notes:
            raise BuildError("%s could not be read cleanly: %s" % (what, "; ".join(notes)))
    return out


def build(folder: str, offline: bool = False, say=print):
    """Returns ``(package SHA-256, {library SHA-256: (library name, cabinet name)},
    {library SHA-256: (library name, cabinet name, package SHA-256)})`` - the second for the
    libraries validly signed by Microsoft, the third for those of the package that are not."""
    path = os.path.join(folder, FILE)
    digest = obtain(path, offline, say)
    if os.path.getsize(path) > MAX_PACKAGE:
        raise BuildError("the package is larger than %d MB" % (MAX_PACKAGE >> 20))
    from gamescan import trust
    who = trust.signer_name(path) or ""
    if not who.startswith(MICROSOFT):
        raise BuildError("the package is not validly signed by Microsoft (%r)" % who)
    with open(path, "rb") as fh:
        data = fh.read()
    outer = members(data, FILE)
    cabinets = [(name, blob) for name, blob in outer if name.lower().endswith(".cab")]
    say("%s: %d members, %d cabinets inside" % (FILE, len(outer), len(cabinets)))
    if not cabinets:
        raise BuildError("no cabinet inside the package")
    files: Dict[str, Tuple[str, str]] = {}
    packaged: Dict[str, Tuple[str, str, str]] = {}
    left_out: List[str] = []
    check = tempfile.mkdtemp(prefix="gss-directx-check-")
    try:
        for cab_name, blob in sorted(cabinets):
            for name, member in members(blob, cab_name):
                if not name.lower().endswith(".dll"):
                    continue
                who = signer_of(member, name, check)
                sha, leaf = hashlib.sha256(member).hexdigest(), name.rsplit("/", 1)[-1].lower()
                if not who.startswith(MICROSOFT):
                    # (a table of its own, tagged, and said: it rests on the package's signature)
                    left_out.append("%s in %s (%s)" % (name, cab_name, who or "no valid signature"))
                    packaged.setdefault(sha, (leaf, cab_name, digest))
                    continue
                files.setdefault(sha, (leaf, cab_name))
    finally:
        shutil.rmtree(check, ignore_errors=True)
    for sha in set(packaged) & set(files):           # (the same bytes signed elsewhere in the package)
        del packaged[sha]
    say("  %d libraries, each validly signed by Microsoft; %d without a valid signature of Microsoft, "
        "taken as \"from signed package\"" % (len(files), len(packaged)))
    for line in left_out:
        say("    from signed package: " + line)
    return digest, files, packaged


def render(digest: str, files, packaged) -> str:
    lines = [
        '"""The libraries of the DirectX June 2010 redistributable package, by exact content.',
        "",
        "GENERATED by tools/build_directx_table.py - do not edit by hand.",
        "",
        "Every library of Microsoft's \"%s\" package: read out of the package (address" % WHAT,
        "and SHA-256 in ``PACKAGE``; it is a row of tools/manifest.json, and the package carries a",
        "valid signature of Microsoft). Each library was checked once, when this table was built:",
        "``FILES`` holds those that carry a valid signature of Microsoft themselves,",
        "``FROM_SIGNED_PACKAGE`` those that do not - tagged \"from signed package\", their source the",
        "package's SHA-256 (phageo, 2026-10-17). A file whose SHA-256 is in either *is* that library,",
        "byte for byte - also where its signature cannot be checked (inside an archive read in",
        "memory). Nothing here was taken from a scanned sample.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Optional",
        "",
        "PACKAGE = (%r, %r, %r)" % (WHAT, URL, digest),
        "",
        "# SHA-256 of the library -> (its file name, the cabinet of the package it is in)",
        "FILES = {",
    ]
    lines += ["    %r: %r," % (sha, entry) for sha, entry in sorted(files.items(), key=lambda kv: (kv[1], kv[0]))]
    lines += ["}", "",
              "# libraries of the package without a valid signature of Microsoft of their own:",
              "# SHA-256 of the library -> (its file name, the cabinet, the SHA-256 of the signed package)",
              "FROM_SIGNED_PACKAGE = {"]
    lines += ["    %r: %r," % (sha, entry) for sha, entry in sorted(packaged.items(), key=lambda kv: (kv[1], kv[0]))]
    lines += ["}", "", "",
              "def verified(sha256: str) -> Optional[str]:",
              '    """Which library of the package has this SHA-256 (None: not in the table)."""',
              '    sha256 = (sha256 or "").lower()',
              "    entry = FILES.get(sha256)",
              "    if entry is not None:",
              '        return "%s - DirectX June 2010 (%s)" % entry',
              "    entry = FROM_SIGNED_PACKAGE.get(sha256)",
              "    if entry is not None:",
              '        return "%s - DirectX June 2010 (%s; from signed package %s)" % entry',
              "    return None",
              ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True, help="folder the official archives are kept in")
    parser.add_argument("--offline", action="store_true", help="never download; fail when the package is missing")
    parser.add_argument("--out", default=OUT, help="the table to write (default: %(default)s)")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.archives):
        parser.error("not a folder: %s" % args.archives)
    try:
        digest, files, packaged = build(args.archives, args.offline)
    except (BuildError, OSError) as exc:
        print("STOPPED: %s" % exc)
        return 1
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(digest, files, packaged))
    print("%d + %d libraries -> %s" % (len(files), len(packaged), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
