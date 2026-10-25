"""Build ``Bagel.exe``, the package's start program, from ``tools/launcher/Bagel.cs``.

    python tools/build_launcher.py            build it (needs Windows' own csc.exe)
    python tools/build_launcher.py --check    is the kept Bagel.exe the one of launcher.json?

(0.9-beta final polish, phageo 2026-10-25.) Dev-only, like the C# test fixtures: the .NET
Framework's own C# compiler (``csc.exe``, already on Windows) builds a small windowed program with
Bagel's icon (``gamescan/bagel.ico``) and version information (``FileDescription`` and
``ProductName`` "Bagel", version ``models.TOOL_VERSION``, company "phageo"). The compiler gives
other bytes on every run, so the program is built once and kept, with its SHA-256, in
``tools/launcher/`` (``Bagel.exe``, ``launcher.json``); ``tools/build_package.py`` takes exactly that
file and refuses it when its SHA-256 or version does not match. Nothing is run here but the compiler.

Deterministic, no paths (source release, phageo 2026-10-25): Windows' csc is the C# 5 compiler,
which has no ``/deterministic`` or ``/pathmap``. ``/debug-`` writes no PDB and no debug directory
(so no source or PDB path), and ``deterministic()`` then replaces the two fields that change on
every run - the file's time stamp and the module id (MVID) - by values taken from the file's own
SHA-256 with both zeroed, the way Roslyn's ``/deterministic`` does. The same source, icon and
compiler give the same bytes; ``check()`` refuses a program with a debug directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from gamescan import models                                  # noqa: E402

FOLDER = os.path.join(HERE, "launcher")
SOURCE = os.path.join(FOLDER, "Bagel.cs")
PROGRAM = os.path.join(FOLDER, "Bagel.exe")
RECORD = os.path.join(FOLDER, "launcher.json")
ICON = os.path.join(ROOT, "gamescan", "bagel.ico")
FRAMEWORK = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Microsoft.NET", "Framework64", "v4.0.30319")
CSC = os.path.join(FRAMEWORK, "csc.exe")
NAME, COMPANY = "Bagel", "phageo"


class LauncherError(Exception):
    pass


def numeric(version: str) -> str:
    """``0.9.0-beta`` -> ``0.9.0.0`` (the four numbers of a Windows version)."""
    return ".".join((version.split("-")[0].split(".") + ["0", "0", "0", "0"])[:4])


def assembly_info(version: str = models.TOOL_VERSION) -> str:
    """The version information, written beside the source for the compiler. ``FileDescription``
    comes from the title; the file and product version texts say ``version`` itself."""
    return "\r\n".join([
        "using System.Reflection;",
        '[assembly: AssemblyTitle("%s")]' % NAME,
        '[assembly: AssemblyProduct("%s")]' % NAME,
        '[assembly: AssemblyCompany("%s")]' % COMPANY,
        '[assembly: AssemblyCopyright("Copyright (c) 2026 %s")]' % COMPANY,
        '[assembly: AssemblyVersion("%s")]' % numeric(version),
        '[assembly: AssemblyFileVersion("%s")]' % version,
        '[assembly: AssemblyInformationalVersion("%s")]' % version,
        ""])


def sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _pe_places(image: bytes) -> dict:
    """File offsets of the time stamp, the debug directory entry and the MVID (the one GUID of the
    ``#GUID`` heap) of a .NET program written by csc."""
    if image[:2] != b"MZ":
        raise LauncherError("not a Windows program")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe:pe + 4] != b"PE\0\0":
        raise LauncherError("not a Windows program")
    sections, optional = struct.unpack_from("<H", image, pe + 6)[0], struct.unpack_from("<H", image, pe + 20)[0]
    magic = struct.unpack_from("<H", image, pe + 24)[0]
    directories = pe + 24 + (96 if magic == 0x10B else 112)
    table = pe + 24 + optional

    def offset(rva: int) -> int:
        for n in range(sections):
            size, start, raw_size, raw = struct.unpack_from("<IIII", image, table + 40 * n + 8)
            if start <= rva < start + max(size, raw_size):
                return raw + rva - start
        raise LauncherError("address outside the sections")

    cli = offset(struct.unpack_from("<I", image, directories + 14 * 8)[0])
    meta = offset(struct.unpack_from("<I", image, cli + 8)[0])
    if image[meta:meta + 4] != b"BSJB":
        raise LauncherError("no .NET metadata")
    at = meta + 16 + struct.unpack_from("<I", image, meta + 12)[0]
    streams = struct.unpack_from("<H", image, at + 2)[0]
    at += 4
    guid = None
    for _ in range(streams):
        start, size = struct.unpack_from("<II", image, at)
        end = image.index(b"\0", at + 8)
        name = image[at + 8:end]
        at = (end + 4) & ~3
        if name == b"#GUID":
            if size != 16:
                raise LauncherError("the #GUID heap holds %d bytes, not one MVID" % size)
            guid = meta + start
    if guid is None:
        raise LauncherError("no #GUID heap")
    return {"stamp": pe + 8, "debug": directories + 6 * 8, "mvid": guid}


def deterministic(image: bytes) -> bytes:
    """``image`` with its time stamp and MVID taken from its own SHA-256 (both zeroed first)."""
    places = _pe_places(image)
    out = bytearray(image)
    out[places["stamp"]:places["stamp"] + 4] = bytes(4)
    out[places["mvid"]:places["mvid"] + 16] = bytes(16)
    digest = hashlib.sha256(bytes(out)).digest()
    out[places["mvid"]:places["mvid"] + 16] = digest[:16]
    # a time stamp with the top bit set cannot be read as a real date (Roslyn does the same)
    out[places["stamp"]:places["stamp"] + 4] = struct.pack("<I", struct.unpack("<I", digest[16:20])[0] | 0x80000000)
    return bytes(out)


def has_debug_directory(image: bytes) -> bool:
    place = _pe_places(image)["debug"]
    return struct.unpack_from("<II", image, place) != (0, 0)


def record() -> dict:
    with open(RECORD, encoding="utf-8") as fh:
        return json.load(fh)


def check(path: str = PROGRAM) -> str:
    """Why the kept program may not be used ("" when it may)."""
    try:
        kept = record()
    except (OSError, ValueError) as exc:
        return "no launcher.json (%s) - run tools/build_launcher.py" % exc
    if kept.get("version") != models.TOOL_VERSION:
        return "Bagel.exe is of version %s, not %s - run tools/build_launcher.py" % (
            kept.get("version"), models.TOOL_VERSION)
    if not os.path.isfile(path):
        return "Bagel.exe is missing - run tools/build_launcher.py"
    if sha256(path) != kept.get("sha256"):
        return "Bagel.exe is not the file of launcher.json (SHA-256 differs)"
    with open(path, "rb") as fh:
        image = fh.read()
    try:
        if has_debug_directory(image) or deterministic(image) != image:
            return "Bagel.exe is not a deterministic build without debug data - run tools/build_launcher.py"
    except LauncherError as exc:
        return "Bagel.exe cannot be read (%s)" % exc
    with open(SOURCE, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != kept.get("source_sha256"):
            return "Bagel.cs changed since Bagel.exe was built - run tools/build_launcher.py"
    return ""


def build(say=print, target: Optional[str] = None) -> str:
    """Compile Bagel.exe; ``target`` (a trial build elsewhere) leaves the kept file and record alone."""
    if not os.path.isfile(CSC):
        raise LauncherError("Windows' own C# compiler is missing: " + CSC)
    work = tempfile.mkdtemp(prefix="bagel_launcher_")
    try:
        # the same short file names in a fresh folder, compiled from inside it: nothing of the
        # project's or the user's folder can reach the program
        for name, source in (("Bagel.cs", SOURCE), ("bagel.ico", ICON)):
            shutil.copyfile(source, os.path.join(work, name))
        with open(os.path.join(work, "AssemblyInfo.cs"), "w", encoding="utf-8", newline="") as fh:
            fh.write(assembly_info())
        args = [CSC, "/nologo", "/target:winexe", "/platform:anycpu", "/optimize+", "/debug-",
                "/win32icon:bagel.ico", "/out:Bagel.exe", "Bagel.cs", "AssemblyInfo.cs"]
        done = subprocess.run(args, capture_output=True, text=True, cwd=work)
        out = os.path.join(work, "Bagel.exe")
        if done.returncode != 0 or not os.path.isfile(out):
            raise LauncherError("csc failed (%d): %s%s" % (done.returncode, done.stdout, done.stderr))
        warnings = [line for line in done.stdout.splitlines() if "warning" in line]
        with open(out, "rb") as fh:
            image = fh.read()
        if has_debug_directory(image):
            raise LauncherError("csc wrote debug data in spite of /debug-")
        with open(target or PROGRAM, "wb") as fh:
            fh.write(deterministic(image))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if target:
        say("%s: %d bytes, SHA-256 %s" % (target, os.path.getsize(target), sha256(target)))
        return target
    with open(SOURCE, "rb") as fh:
        source_hash = hashlib.sha256(fh.read()).hexdigest()
    data = {"about": "Bagel.exe, the package's start program, built by tools/build_launcher.py with "
                     "Windows' own csc.exe (dev-only); tools/build_package.py takes exactly this file.",
            "version": models.TOOL_VERSION, "sha256": sha256(PROGRAM), "size": os.path.getsize(PROGRAM),
            "source_sha256": source_hash, "compiler": CSC.replace(os.environ.get("WINDIR", r"C:\Windows"), "%WINDIR%"),
            "deterministic": True}
    with open(RECORD, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for line in warnings:
        say("csc: " + line.strip())
    say("%s: %d bytes, SHA-256 %s" % (PROGRAM, data["size"], data["sha256"]))
    return PROGRAM


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="only check the kept program (offline, nothing run)")
    ap.add_argument("--out", help="write a trial build here; the kept Bagel.exe and launcher.json stay as they are")
    args = ap.parse_args(argv)
    if args.check:
        problem = check()
        print(problem or "Bagel.exe is the file of launcher.json (version %s)" % models.TOOL_VERSION)
        return 1 if problem else 0
    try:
        build(target=args.out)
    except (LauncherError, OSError) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
