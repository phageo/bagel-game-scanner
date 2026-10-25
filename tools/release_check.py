"""The release checklist of the user package, run on a finished zip (packaging session 3, phageo;
the list: ``docs/RELEASE_CHECKLIST.md``).

    python tools/release_check.py <package zip> --names <mapping file> [--samples <folder> ...]

One line per check, PASS or FAIL, and exit code 0 only when every line passes. It reads the zip in
memory (nothing is unpacked or run) and checks:

 1. version     the top folder, the README title and ``models.TOOL_VERSION`` inside say 0.9.0-beta
 2. names       every name is on the builder's allowlist; nothing of tests/, tests/_tools,
                engine_archives, docs, tools, yara_rules, the behaviour monitor, no compiled file
 3. dev content no file has the bytes of a file in tests/ or engine_archives
 4. samples     no app or note file has the bytes of a file in a clean sample folder
                (``--samples`` or ``BAGEL_SAMPLE_FOLDERS``, no default path; the malicious samples
                are never read - CLAUDE.md, rule 19)
 5. game names  no real game name of the mapping file (outside the project) in app or notes
 6. user name   no Windows user name / profile path of this PC in app or notes
 7. file list   the zip holds exactly the files of ``app/package_files.json`` and that list
 8. self-check  every file's SHA-256 is the one in ``app/package_files.json``
 9. licences    LICENSE (MIT, phageo), THIRD-PARTY-NOTICES.txt, python/LICENSE.txt,
                python/tcl/tk8.6/license.terms
10. notes       README.md and RELEASE-NOTES.md (English and Turkish)
11. icon        app/gamescan/bagel.ico with the sizes 16, 24, 32, 48, 64, 128 and 256
12. start       Bagel.exe: a windowed program (no console) whose version information says Bagel
                (FileDescription, ProductName), phageo and 0.9.0-beta, with every picture of the icon
13. images      no picture of Bagel's own files (icon, Bagel.exe, any PNG) holds metadata - only
                the picture chunks IHDR, PLTE, tRNS, IDAT, IEND (python.org's files not looked at)
14. installer   (with ``--installer``) ``Bagel-<version>-setup.exe`` installs exactly the files of
                the zip, byte for byte - read in memory by the scanner's own Inno Setup reader
                (``build_inno_tables.files_of``), nothing run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_package as B                                  # noqa: E402

VERSION = B.models.TOOL_VERSION


def read(zip_path: str) -> Tuple[str, Dict[str, bytes]]:
    """``(top folder, {name below it: bytes})``."""
    with zipfile.ZipFile(zip_path) as z:
        names = [i.filename for i in z.infolist() if not i.is_dir()]
        top = names[0].split("/")[0] if names else ""
        return top, {n[len(top) + 1:]: z.read(n) for n in names if n.startswith(top + "/")}


def checks(top: str, files: Dict[str, bytes], mapping: str, samples: List[str],
           env: Optional[Dict[str, str]] = None) -> List[Tuple[str, bool, str]]:
    """``[(check, passed, detail)]`` - the ten lines of the module text."""
    out = []
    own = {n: d for n, d in files.items() if not n.startswith("python/")}
    models = files.get("app/gamescan/models.py", b"").decode("utf-8", "replace")
    stated = re.search(r'^TOOL_VERSION\s*=\s*"([^"]+)"', models, re.MULTILINE)
    readme = files.get(B.README, b"").decode("utf-8", "replace")
    found = (top, readme.splitlines()[0] if readme else "", stated.group(1) if stated else "")
    out.append(("version", top == "Bagel-" + VERSION and found[1] == "# Bagel "
                + VERSION and found[2] == VERSION, "%s | %s | %s" % found))
    refused = B.check_names(files) + [n for n in files if n.endswith((".pyc", ".pyo"))]
    out.append(("names", not refused, "%d files, %d refused%s" % (
        len(files), len(refused), (": " + ", ".join(refused[:5])) if refused else "")))
    folders = [f for f in (os.path.join(B.ROOT, "tests"), B.ENGINE_ARCHIVES) if os.path.isdir(f)]
    same = B.same_content(files, folders)
    hits = sorted(n for v in same.values() for n in v)
    out.append(("dev content", not hits and len(folders) == 2, "%d same as tests/ or engine_archives "
                "(%d of 2 folders read)%s" % (len(hits), len(folders), (": " + ", ".join(hits[:5])) if hits else "")))
    present = [s for s in samples if os.path.isdir(s)]
    same = B.same_content(own, present)
    hits = sorted(n for v in same.values() for n in v)
    out.append(("samples", not hits and bool(present) and len(present) == len(samples),
                "%d app / note files same as a sample file (%d of %d sample folders read)"
                % (len(hits), len(present), len(samples))))
    names = B.real_names(mapping)
    hits2 = B.name_hits(own, names)
    out.append(("game names", not hits2 and bool(names), "%d names of %d samples searched, %d found%s" % (
        sum(len(v) for v in names.values()), len(names), len(hits2),
        (": " + ", ".join("%s in %s" % h for h in hits2[:5])) if hits2 else "")))
    private = B.private_hits(own, env)
    out.append(("user name", not private and bool(B.private_names(env)), "%d searched, found in %d file(s)%s" % (
        len(B.private_names(env)), len(private), (": " + ", ".join(private[:5])) if private else "")))
    try:
        listed = json.loads(files[B.HASHES].decode("utf-8"))["files"]
    except (KeyError, ValueError):
        listed = {}
    extra = sorted(set(files) - set(listed) - {B.HASHES})
    missing = sorted(set(listed) - set(files))
    out.append(("file list", bool(listed) and not extra and not missing,
                "%d in the zip, %d in the list, %d not listed, %d listed but absent"
                % (len(files), len(listed), len(extra), len(missing))))
    wrong = sorted(n for n, h in listed.items() if n in files and hashlib.sha256(files[n]).hexdigest() != h)
    out.append(("self-check", bool(listed) and not wrong, "%d of %d SHA-256 differ" % (len(wrong), len(listed))))
    licence = files.get(B.LICENSE, b"")
    need = [n for n in (B.LICENSE, B.NOTICES, "python/LICENSE.txt", "python/tcl/tk8.6/license.terms")
            if n not in files]
    ok = not need and licence.startswith(b"MIT License") and b"Copyright (c) 2026 phageo" in licence
    out.append(("licences", ok, "missing: %s; LICENSE MIT phageo: %s" % (", ".join(need) or "none",
                licence.startswith(b"MIT License") and b"phageo" in licence)))
    notes = files.get(B.RELEASE_NOTES, b"").decode("utf-8", "replace")
    ok = bool(readme) and "## English" in notes and "## Türkçe" in notes and VERSION in notes
    out.append(("notes", ok, "README.md %s, RELEASE-NOTES.md %s (English %s, Turkish %s)" % (
        "present" if readme else "MISSING", "present" if notes else "MISSING",
        "## English" in notes, "## Türkçe" in notes)))
    import build_icon
    try:
        sizes = build_icon.read_ico_sizes(files.get("app/gamescan/" + B.ICON, b""))
    except (build_icon.IconError, struct.error):
        sizes = []
    want = list(build_icon.SMALL + build_icon.LARGE)
    out.append(("icon", sizes == want, "app/gamescan/%s sizes %s" % (B.ICON, sizes or "MISSING")))
    out.append(start_check(files))
    out.append(image_check(files))
    return out


PNG = b"\x89PNG\r\n\x1a\n"
PNG_PLAIN = (b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND")


def png_metadata(data: bytes) -> List[str]:
    """The chunk types other than the picture's own (``PNG_PLAIN``) of every PNG inside ``data``
    - a PNG file, the 256 picture of an ``.ico``, the icon inside a program."""
    extra = []
    at = data.find(PNG)
    while at >= 0:
        pos = at + 8
        while pos + 8 <= len(data):
            length, kind = struct.unpack_from(">I4s", data, pos)
            if not kind.isalpha() or pos + 12 + length > len(data):
                break
            if kind not in PNG_PLAIN:
                extra.append(kind.decode("ascii"))
            pos += 12 + length
            if kind == b"IEND":
                break
        at = data.find(PNG, at + 8)
    return extra


def image_check(files: Dict[str, bytes]) -> Tuple[str, bool, str]:
    """Line 14 (source release, phageo 2026-10-25): no picture of Bagel's own files - the icon,
    ``Bagel.exe``, any PNG - holds metadata (text, time, EXIF, colour profile, content credentials):
    only the picture chunks. python.org's files (``python/``) are theirs and not looked at."""
    own = {n: d for n, d in files.items() if not n.startswith("python/")}
    pictures = sum(d.count(PNG) for d in own.values())
    found = {n: sorted(set(png_metadata(d))) for n, d in sorted(own.items())}
    found = {n: kinds for n, kinds in found.items() if kinds}
    return ("images", not found and pictures > 0, "%d PNG pictures in %d own files, %d with metadata%s" % (
        pictures, len(own), len(found), (": " + "; ".join("%s %s" % (n, ",".join(k)) for n, k in found.items()))
        if found else ""))


def ico_images(ico: bytes) -> List[bytes]:
    """The pictures of an ``.ico`` file, as stored."""
    count = struct.unpack_from("<H", ico, 4)[0] if len(ico) >= 6 else 0
    out = []
    for i in range(count):
        size, offset = struct.unpack_from("<II", ico, 6 + 16 * i + 8)
        out.append(ico[offset:offset + size])
    return out


def version_texts(data: bytes) -> Dict[str, str]:
    """The texts of a program's version information this line checks (a key, its end and the
    padding to four bytes - one to three wide zeros - then its value)."""
    out: Dict[str, str] = {}
    for key in ("FileDescription", "ProductName", "CompanyName", "ProductVersion", "FileVersion"):
        m = re.search(b"\x00" + key.encode("utf-16-le") + rb"(?:\x00\x00){1,3}((?:[\x20-\x7e]\x00){1,80})", data)
        if m:
            out[key] = m.group(1).decode("utf-16-le")
    return out


def start_check(files: Dict[str, bytes]) -> Tuple[str, bool, str]:
    """Line 12: ``Bagel.exe`` - a windowed program (no console) with Bagel's version information
    and every picture of ``bagel.ico`` (0.9-beta final polish, phageo 2026-10-25)."""
    data = files.get(B.START, b"")
    from gamescan import pe
    info = pe.parse_pe(data) if data[:2] == b"MZ" else None
    if info is None:
        return ("start", False, "%s %s" % (B.START, "MISSING" if not data else "is no Windows program"))
    head = struct.unpack_from("<I", data, 0x3C)[0]
    subsystem = struct.unpack_from("<H", data, head + 24 + 68)[0]
    strings = version_texts(data)
    stated = strings.get("ProductVersion", "")
    try:
        images = ico_images(files.get("app/gamescan/" + B.ICON, b""))
    except struct.error:
        images = []
    icon = bool(images) and all(image in data for image in images)
    ok = (subsystem == 2 and strings.get("FileDescription") == "Bagel" and strings.get("ProductName") == "Bagel"
          and strings.get("CompanyName") == "phageo" and stated == VERSION and icon)
    return ("start", ok, "%s: %s, FileDescription %r, ProductName %r, CompanyName %r, version %r, icon %s" % (
        B.START, "windowed" if subsystem == 2 else "subsystem %d" % subsystem, strings.get("FileDescription"),
        strings.get("ProductName"), strings.get("CompanyName"), stated,
        "all %d pictures" % len(images) if icon else "MISSING"))


def installer_check(path: str, files: Dict[str, bytes]) -> Tuple[str, bool, str]:
    """Line 13: the installer's files against the zip's (names and bytes)."""
    import build_inno_tables
    name = os.path.basename(path)
    try:
        inside = build_inno_tables.files_of(path)
    except (build_inno_tables.BuildError, OSError) as exc:
        return ("installer", False, "%s could not be read: %s" % (name, exc))
    missing = sorted(set(files) - set(inside))
    extra = sorted(set(inside) - set(files))
    wrong = sorted(n for n in set(files) & set(inside) if files[n] != inside[n])
    ok = name == "Bagel-%s-setup.exe" % VERSION and not (missing or extra or wrong)
    return ("installer", ok, "%s: %d files, %d of the zip missing, %d not in the zip, %d differ%s" % (
        name, len(inside), len(missing), len(extra), len(wrong),
        (": " + ", ".join((missing + extra + wrong)[:5])) if not ok else ""))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("zip")
    ap.add_argument("--names", required=True, help="the code -> real name mapping file (outside the project)")
    ap.add_argument("--samples", action="append", default=None,
                    help="a clean sample folder (repeatable); without it the folders of the variable "
                         "BAGEL_SAMPLE_FOLDERS (separated by ';'). No default path: line 4 fails without one")
    ap.add_argument("--installer", help="Bagel-<version>-setup.exe built from this zip (line 12)")
    args = ap.parse_args(argv)
    samples = args.samples or [f for f in os.environ.get("BAGEL_SAMPLE_FOLDERS", "").split(os.pathsep) if f.strip()]
    top, files = read(args.zip)
    lines = checks(top, files, args.names, samples)
    if args.installer:
        lines.append(installer_check(args.installer, files))
    for i, (name, passed, detail) in enumerate(lines, 1):
        print("%2d. %-4s %-11s %s" % (i, "PASS" if passed else "FAIL", name, detail))
    print("release checklist: %s" % ("all %d lines pass" % len(lines) if all(p for _n, p, _d in lines)
                                    else "%d of %d lines fail" % (sum(not p for _n, p, _d in lines), len(lines))))
    return 0 if all(p for _n, p, _d in lines) else 1


if __name__ == "__main__":
    sys.exit(main())
