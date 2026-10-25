"""Export the source release of Bagel from the project folder (source release, phageo 2026-10-25).

    python tools/export_source.py --project <project folder> --to <repository folder>
    python tools/export_source.py --strip <picture.png> ...     take the metadata out of PNGs (in place)

Copies only what ``ALLOWED`` names, never what ``NEVER`` names, and changes nothing in the
project. The project and the repository hold the same files (phageo, 2026-10-25: "stay in
sync") - the repository's own ones too (the workflow, SECURITY.md, the public CHANGELOG.md, this
tool ...). The export holds no file of ``engine_archives``, ``tests/_tools``, the packages, the
backups, no ``__pycache__`` / ``.pyc``, no sample and nothing derived from a sample, no scratch
file, no ``Bagel.exe`` (built from its source: ``tools/build_launcher.py``), and none of the
project's private notes (``CLAUDE.md``, ``docs/CHANGELOG.md``, ``docs/memory``,
``docs/benchmark``). What it changes while copying:

- the rows of ``tools/manifest.json`` in the group ``samples`` (clean benchmark games, fetched
  from their own sites) are left out, and so is a server of ``tools/fetch.py`` that only those
  rows used - a sample's name or address is never exported.

Every picture it exports (``.png``, ``.ico``) must hold only its picture chunks - no text, time,
colour profile or content-credential chunk - or the export stops; ``--strip`` makes a PNG so.
An export into the repository leaves ``.git`` and the files built there (``BUILT``) as they are.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import struct
import sys
from typing import List, Optional, Tuple

# what may be exported (paths below the project, "/" as separator)
ALLOWED = (
    "GameSafetyScanner.pyw", "Run Scanner.bat", "LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md",
    "THIRD-PARTY-NOTICES.txt", ".gitignore", ".gitattributes", ".github/workflows/*.yml",
    "gamescan/*.py", "gamescan/*/*.py", "gamescan/*.bin", "gamescan/known_findings.json.gz",
    "gamescan/bagel.ico",
    "yara_rules/*.yar",
    "tools/*.py", "tools/*.json", "tools/npm_packages.txt", "tools/indicator_select.bin",
    "tools/launcher/Bagel.cs", "tools/launcher/launcher.json",
    "tests/test_gamescan.py", "tests/build_*.py",
    "tests/fixtures_cs/*.cs", "tests/fixtures_cs/fixtures.json", "tests/fixtures_msi/fixtures.json",
    "tests/fixtures_screnc/fixtures.json",
    "docs/RELEASE_NOTES.md", "docs/RELEASE_CHECKLIST.md", "docs/CODE_SIGNING.md",
    "assets/icon/README.md", "assets/icon/bagel_pixel.png", "assets/icon/bagel_ai.png",
)
# never exported, wherever they stand (checked again on every path)
NEVER = ("engine_archives", "_tools", "packages", "packages_test", "package_proof", "yedekler",
         "__pycache__", "benchmark", "memory", "scanner_samples", "infected files", ".git")
NEVER_KINDS = (".pyc", ".pyo", ".tmp", ".log", ".bak", ".orig", ".exe", ".dll", ".zip", ".csv")
NEVER_NAMES = ("CLAUDE.md", "docs/CHANGELOG.md")       # the project's private notes
SAMPLE_GROUP = "samples"
# what is built inside the repository and never committed (.gitignore)
BUILT = ("tools/launcher/Bagel.exe", "assets/icon/bagel_256_clean.png")
PNG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = (b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND")


class ExportError(Exception):
    pass


def chosen(project: str) -> List[str]:
    out = []
    for base, dirs, files in os.walk(project):
        dirs[:] = sorted(d for d in dirs if d not in NEVER)
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(base, name), project).replace("\\", "/")
            if any(fnmatch.fnmatchcase(rel, p) for p in ALLOWED):
                out.append(rel)
    for rel in out:
        parts = rel.split("/")
        if any(p in NEVER for p in parts) or rel.lower().endswith(NEVER_KINDS) or rel in NEVER_NAMES:
            raise ExportError("refused by NEVER: " + rel)
    return out


def stripped_png(data: bytes) -> bytes:
    """The PNG with only its picture chunks (``PNG_KEEP``): no text, time, EXIF, colour profile,
    content-credential or other metadata chunk. The pixels are the same bytes."""
    if not data.startswith(PNG):
        raise ExportError("not a PNG")
    out, pos = [PNG], 8
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        if pos + 12 + length > len(data):
            raise ExportError("a damaged PNG")
        if kind in PNG_KEEP:
            out.append(data[pos:pos + 12 + length])
        pos += 12 + length
        if kind == b"IEND":
            return b"".join(out)
    raise ExportError("a PNG without its end")


def picture_metadata(data: bytes) -> bool:
    """Does any PNG inside ``data`` (a PNG, or the PNG pictures of an ``.ico``) hold more than its
    picture chunks?"""
    at = data.find(PNG)
    while at >= 0:
        end = data.find(b"IEND", at)
        if end < 0:
            return True
        piece = data[at:end + 8]
        if stripped_png(piece) != piece:
            return True
        at = data.find(PNG, end)
    return False


def _manifest_without_samples(data: bytes) -> Tuple[bytes, int, List[str]]:
    manifest = json.loads(data.decode("utf-8"))
    rows = manifest["files"]
    kept = [r for r in rows if SAMPLE_GROUP not in r.get("groups", [])]
    gone = [r for r in rows if SAMPLE_GROUP in r.get("groups", [])]
    hosts = sorted({r["url"].split("/")[2] for r in gone})
    still = {r["url"].split("/")[2] for r in kept}
    manifest["files"] = kept
    text = json.dumps(manifest, indent=1, ensure_ascii=False) + "\n"
    return text.encode("utf-8"), len(gone), [h for h in hosts if h not in still]


def _present(target: str) -> List[str]:
    out = []
    for base, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d != ".git"]
        out += [os.path.relpath(os.path.join(base, n), target).replace("\\", "/") for n in files]
    return out


def export(project: str, target: str, say=print) -> dict:
    """Copy the allowed files of ``project`` into ``target`` (which may hold ``.git``, an earlier
    export - replaced - and ``BUILT`` files). A file the project no longer has is reported, never
    deleted here."""
    project, target = os.path.abspath(project), os.path.abspath(target)
    if os.path.normcase(target).startswith(os.path.normcase(project) + os.sep):
        raise ExportError("the export must lie outside the project")
    names = chosen(project)
    for rel in names:
        if rel.lower().endswith((".png", ".ico")):
            with open(os.path.join(project, *rel.split("/")), "rb") as fh:
                if picture_metadata(fh.read()):
                    raise ExportError("a picture with metadata: %s - tools/export_source.py --strip" % rel)
    stale = sorted(set(_present(target)) - set(names) - set(BUILT))
    if stale:
        say("in the export but not exported now (left as they are, check them): %s" % ", ".join(stale))
    with open(os.path.join(project, "tools", "manifest.json"), "rb") as fh:
        original = fh.read()
    manifest, dropped, hosts = _manifest_without_samples(original)
    # written back in the original's own layout, so that only the dropped rows differ
    unmarked = original.replace(b'"%s"' % SAMPLE_GROUP.encode(), b'"-"')
    if _manifest_without_samples(unmarked)[0] != unmarked:
        raise ExportError("manifest.json is not in the layout this tool writes back")
    for rel in names:
        source = os.path.join(project, *rel.split("/"))
        dest = os.path.join(target, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if rel == "tools/manifest.json":
            with open(dest, "wb") as fh:
                fh.write(manifest)
        elif rel == "tools/fetch.py":
            with open(source, "rb") as fh:
                text = fh.read().decode("utf-8")
            for host in hosts:
                lines = [l for l in text.split("\n") if '"%s",' % host in l]
                if len(lines) != 1:
                    raise ExportError("fetch.py: the host of the sample rows is not on one line")
                text = text.replace(lines[0] + "\n", "", 1)
            with open(dest, "wb") as fh:
                fh.write(text.encode("utf-8"))
        else:
            shutil.copyfile(source, dest)
    size = sum(os.path.getsize(os.path.join(target, *r.split("/"))) for r in names)
    say("exported %d files, %.1f MB; manifest.json: %d sample row(s) left out, %d host(s) of fetch.py; "
        "pictures checked: %d, none with metadata" % (len(names), size / 1048576, dropped, len(hosts),
                                                     sum(n.lower().endswith((".png", ".ico")) for n in names)))
    return {"files": names, "dropped_rows": dropped, "dropped_hosts": len(hosts)}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project")
    ap.add_argument("--to")
    ap.add_argument("--strip", nargs="+", metavar="PNG", help="take the metadata out of these PNG files")
    args = ap.parse_args(argv)
    try:
        if args.strip:
            for path in args.strip:
                with open(path, "rb") as fh:
                    data = fh.read()
                with open(path, "wb") as fh:
                    fh.write(stripped_png(data))
                print("%s: %d -> %d bytes" % (path, len(data), os.path.getsize(path)))
            return 0
        if not (args.project and args.to):
            ap.error("--project and --to are needed")
        export(args.project, args.to)
    except (ExportError, OSError, ValueError) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
