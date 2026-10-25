"""Build real Inno Setup and NSIS installers of a dummy RPG Maker game.

The scanner's installer readers were written against the formats' layouts;
this script produces the real thing to test them on, with the vendors' own
compilers:

1. downloads the official command-line compilers (once, into ``tests/_tools``):
   NSIS as its portable zip, Inno Setup through its own installer in
   *portable* mode (no registry entries, nothing outside the tools folder);
   the downloads go through ``tools/fetch.py`` - only what
   ``tools/manifest.json`` lists, with the SHA-256 pinned below, anything
   else is refused -, and the Inno Setup installer must carry a valid
   digital signature before it is run;
2. writes a small dummy game (RPG Maker XP layout: ``Game.exe``, ``Game.ini``,
   ``Game.rgssad``, a runtime DLL, loose data, a picture, a sound, a script);
3. compiles it into installers in several variants (compression method,
   solid / non-solid, Unicode / ANSI).

``build_all(folder)`` returns ``(game files, {variant name: installer path})``.
Run as a script it prints what it built:  ``python tests/build_installers.py [folder]``

The compilers are real programs from the internet and are *run* here - that
is what this script is for, and why the test that uses it is opt-in.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from typing import Dict, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TOOLS = os.environ.get("GSS_TEST_TOOLS", os.path.join(HERE, "_tools"))
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

NSIS_URL = "https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip"
NSIS_SHA256 = "ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8"
INNO_URL = "https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe"
INNO_SHA256 = "9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732"
INNO_SIGNER = "Pyrsys"  # the signer of the pinned installer (see INNO_OLD_SIGNERS for the source)

# Older Inno Setup compilers, one of each line of versions, to see which of them the
# scanner's readers read (phageo, 2026-10-11: download allowed for this). 5.x from
# files.jrsoftware.org; 6.x from the releases of jrsoftware/issrc on GitHub, where
# jrsoftware.org sends its downloads since March 2026 (files.jrsoftware.org/is/6/readme.txt)
# and where the pinned 6.7.3 comes from. The SHA-256 of the 6.x files is the one GitHub
# shows for the release asset; for the 5.x files nothing is published, so theirs is what
# the file had when it was first downloaded here (2026-10-11, over HTTPS, valid signature).
INNO_OLD = {                 # version: (address, SHA-256)
    "5.5.9": ("https://files.jrsoftware.org/is/5/innosetup-5.5.9-unicode.exe",
              "5b51ae6977bebba937ac18e0e80c1899e37dfaa12f51ccd817978ef07ae19cb3"),
    "5.6.1": ("https://files.jrsoftware.org/is/5/innosetup-5.6.1-unicode.exe",
              "27d49e9bc769e9d1b214c153011978db90dc01c2acd1ddcd9ed7b3fe3b96b538"),
    "6.0.5": ("https://github.com/jrsoftware/issrc/releases/download/is-6_0_5/innosetup-6.0.5.exe",
              "ae6823b523df87e9441789e51845434e4e0e70aac0b88afe80f94f20f4b98acb"),
    "6.2.2": ("https://github.com/jrsoftware/issrc/releases/download/is-6_2_2/innosetup-6.2.2.exe",
              "8117d10d00a2ad33a1390978ea3872861c330e087914410a6377b22c4c5b8563"),
    "6.4.3": ("https://github.com/jrsoftware/issrc/releases/download/is-6_4_3/innosetup-6.4.3.exe",
              "f3c42116542c4cc57263c5ba6c4feabfc49fe771f2f98a79d2f7628b8762723b"),
}
# Whose valid signature a downloaded compiler installer must carry before anything is taken
# out of it. This list is used here only - to check the test compilers; it is not the
# scanner's list of trusted publishers and has no part in how a scanned file is judged.
# Sources: jrsoftware.org/isinfo.php names Jordan Russell and Martijn Laan as the authors
# of Inno Setup (read 2026-10-11). "Pyrsys B.V." is not named on that page: it is the
# signer found on the 6.4.3 and 6.7.3 installers, whose SHA-256 are the ones the
# jrsoftware/issrc releases on GitHub show.
INNO_OLD_SIGNERS = ("Jordan Russell", "Martijn Laan", "Pyrsys")

NSIS_VARIANTS = {            # name: (SetCompressor line, Unicode)
    "nsis-lzma-solid": ("/SOLID lzma", "true"),
    "nsis-lzma": ("lzma", "true"),
    "nsis-zlib": ("zlib", "true"),
    "nsis-zlib-solid-ansi": ("/SOLID zlib", "false"),
    "nsis-bzip2": ("bzip2", "true"),
}
INNO_VARIANTS = {            # name: (Compression, SolidCompression)
    "inno-lzma2-solid": ("lzma2", "yes"),
    "inno-lzma2": ("lzma2", "no"),
    "inno-lzma": ("lzma", "no"),
    "inno-zip": ("zip", "no"),
    "inno-none": ("none", "no"),
}


class BuildError(RuntimeError):
    pass


# -- the compilers ------------------------------------------------------------------------
def _download(url: str, path: str, pinned: str) -> str:
    """Bring a compiler package to ``path`` - through ``tools/fetch.py`` (phageo,
    2026-10-12): only a file that ``tools/manifest.json`` lists with this address and
    this SHA-256 is downloaded, and a download that is not that file is refused and
    deleted there. This script has no download of its own any more."""
    tools = os.path.join(os.path.dirname(HERE), "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    try:
        entry = fetch.listed(url, pinned)
        fetch.fetch(entry, path, say=lambda line: None)
    except fetch.FetchError as exc:
        raise BuildError(str(exc))
    return entry["sha256"]


def tools_ready() -> bool:
    """Are both compilers already in the tools folder (nothing to download)?"""
    nsis = any("makensis.exe" in names for _b, _d, names in os.walk(os.path.join(TOOLS, "nsis")))
    return nsis and os.path.isfile(os.path.join(TOOLS, "innosetup", "ISCC.exe"))


def nsis_compiler() -> str:
    """Path of ``makensis.exe`` (downloaded and unpacked on first use)."""
    home = os.path.join(TOOLS, "nsis")
    for base, _dirs, names in os.walk(home):
        if "makensis.exe" in names:
            return os.path.join(base, "makensis.exe")
    os.makedirs(home, exist_ok=True)
    package = os.path.join(home, "nsis.zip")
    _download(NSIS_URL, package, NSIS_SHA256)
    with zipfile.ZipFile(package) as z:
        z.extractall(home)
    os.remove(package)
    return nsis_compiler()


def inno_compiler() -> str:
    """Path of ``ISCC.exe`` (downloaded and set up in portable mode on first use)."""
    home = os.path.join(TOOLS, "innosetup")
    compiler = os.path.join(home, "ISCC.exe")
    if os.path.isfile(compiler):
        return compiler
    os.makedirs(TOOLS, exist_ok=True)
    package = os.path.join(TOOLS, "innosetup-setup.exe")
    _download(INNO_URL, package, INNO_SHA256)
    try:
        from gamescan import trust
        signer = trust.signer_name(package)
        if not signer or INNO_SIGNER.lower() not in signer.lower():
            raise BuildError("the Inno Setup installer is not validly signed by %s (signer: %r)"
                             % (INNO_SIGNER, signer))
        # /PORTABLE=1 is Inno Setup's own switch for a self-contained copy: no
        # uninstall entry, no file associations, nothing outside /DIR
        done = subprocess.run([package, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                               "/CURRENTUSER", "/PORTABLE=1", "/DIR=" + home],
                              timeout=300, creationflags=FLAGS)
        if done.returncode or not os.path.isfile(compiler):
            raise BuildError("Inno Setup could not be set up (exit code %d)" % done.returncode)
    finally:
        if os.path.isfile(package):
            os.remove(package)
    return compiler


def old_inno_ready(version: str) -> bool:
    return os.path.isfile(os.path.join(TOOLS, "innosetup-" + version, "ISCC.exe"))


def old_inno_compiler(version: str) -> str:
    """Path of the ``ISCC.exe`` of an older Inno Setup (``INNO_OLD``). On first use its
    installer is downloaded, compared with the pinned SHA-256, checked for a valid
    signature of its publisher - and then *not run*: its files are taken out of it with
    the scanner's own reader (each one byte-identical to what the installer would write,
    by the installer's own checksums) into ``tests/_tools/innosetup-<version>``. Only the
    compiler is run afterwards. Raises BuildError when the reader cannot take the
    installer apart."""
    import io
    home = os.path.join(TOOLS, "innosetup-" + version)
    compiler = os.path.join(home, "ISCC.exe")
    if os.path.isfile(compiler):
        return compiler
    address, pinned = INNO_OLD[version]
    os.makedirs(TOOLS, exist_ok=True)
    package = os.path.join(TOOLS, "innosetup-%s-setup.exe" % version)
    digest = _download(address, package, pinned)
    try:
        from gamescan import trust
        from gamescan.pe import parse_pe
        from gamescan.unpack import inno
        signer = trust.signer_name(package)
        if not signer or not any(name.lower() in signer.lower() for name in INNO_OLD_SIGNERS):
            raise BuildError("the Inno Setup %s installer is not validly signed by its publisher "
                             "(signer: %r)" % (version, signer))
        with open(package, "rb") as fh:
            data = fh.read()
        first = parse_pe(data).overlay_offset
        try:
            installer = inno.Installer(lambda: io.BytesIO(data), inno.find(data, first), first,
                                       inno.chunks(data, first))
            problems: list = []
            files = dict(installer.members(lambda name, size: True, problems=problems))
        except (inno.InnoError, OSError) as exc:
            raise BuildError("Inno Setup %s: the installer could not be taken apart (%s)" % (version, exc))
        if problems or "ISCC.exe" not in files:
            raise BuildError("Inno Setup %s: files missing after taking the installer apart (%s)"
                             % (version, "; ".join(problems) or "no ISCC.exe"))
        for name, content in files.items():
            if ".." in name or ":" in name:
                continue
            path = os.path.join(home, name.replace("/", os.sep))
            if not os.path.abspath(path).startswith(os.path.abspath(home) + os.sep):
                continue                                    # nothing is written outside its folder
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(content if isinstance(content, bytes) else content.read())
            if not isinstance(content, bytes):
                content.release()
        with open(os.path.join(home, "SOURCE.txt"), "w", encoding="utf-8") as fh:
            fh.write("%s\nSHA-256 %s\nsigner %s\n" % (address, digest, signer))
    finally:
        if os.path.isfile(package):
            os.remove(package)
    return compiler


# -- the dummy game -------------------------------------------------------------------------
def _program(marker: bytes, dll: bool = False) -> bytes:
    """A small, well-formed PE32 whose code is full of CALL / JMP opcodes, so
    an installer's executable filter has something to rewrite."""
    code = bytearray()
    for i in range(400):
        code += b"\x55\x8b\xec\xe8" + struct.pack("<i", (i * 37) % 3000 - 1500)     # call rel32
        code += b"\x85\xc0\x0f\x84" + struct.pack("<i", i * 5) + b"\xe9" + struct.pack("<i", -i * 9)
        code += b"\xc3" + marker[:4]
    code += b"\0" * (-len(code) % 0x200)
    rva, raw = 0x1000, 0x200
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, len(code), 0, 0, rva,
                      rva, 0, 0x400000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                      rva + 0x4000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\0" * 128
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(opt), 0x2102 if dll else 0x0102)
    section = struct.pack("<8sIIIIIIHHI", b".text", len(code), rva, len(code), raw, 0, 0, 0, 0,
                          0x60000020)
    head = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + section
    return head + b"\0" * (raw - len(head)) + bytes(code) + b"overlay:" + marker


def _marshal_int(n: int) -> bytes:
    if n == 0:
        return b"\0"
    if 0 < n < 123:
        return bytes([n + 5])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    return bytes([len(raw)]) + raw


def scripts_table(scripts) -> bytes:
    """``Data/Scripts.rxdata``: Ruby Marshal of ``[[id, name, deflated source], ...]``."""
    def text(raw):
        return b'"' + _marshal_int(len(raw)) + raw
    rows = b"".join(b"[" + _marshal_int(3) + b"i" + _marshal_int(1000 + i) + text(name.encode())
                    + text(zlib.compress(source.encode())) for i, (name, source) in enumerate(scripts))
    return b"\x04\x08[" + _marshal_int(len(scripts)) + rows


def rgssad(members: Dict[str, bytes]) -> bytes:
    """An RPG Maker XP archive (``Game.rgssad``)."""
    from gamescan.unpack import rgss
    out, key = bytearray(b"RGSSAD\0\x01"), 0xDEADCAFE
    step = lambda k: (k * 7 + 3) & 0xFFFFFFFF                                  # noqa: E731
    for name, data in members.items():
        raw = name.encode()
        out += struct.pack("<I", len(raw) ^ key)
        key = step(key)
        for b in raw:
            out.append(b ^ (key & 0xFF))
            key = step(key)
        out += struct.pack("<I", len(data) ^ key)
        key = step(key)
        out += rgss.encrypt_for_tests(data, key)
    return bytes(out)


def _png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0")) + chunk(b"IEND", b""))


def dummy_game() -> Dict[str, bytes]:
    """``{relative path: content}`` of a dummy RPG Maker XP game. One script in
    the archive is deliberately suspicious, so a scan has something to find."""
    scripts = [("Game_Temp", "class Game_Temp\n  attr_accessor :map_bgm\nend\n"),
               ("Updater", "require 'net/http'\ndata = Net::HTTP.get(URI(u))\n"
                           "system(\"cmd /c \" + data)\n"),
               ("Main", "begin\n  $scene = Scene_Title.new\nend\n")]
    archive = rgssad({"Data\\Scripts.rxdata": scripts_table(scripts),
                      "Data\\Map001.rxdata": b"\x04\x08[\x06i\x06",
                      "Graphics\\Titles\\title.png": _png()})
    return {
        "Game.exe": _program(b"GAME"),
        "Game.ini": b"[Game]\r\nLibrary=RGSS104E.dll\r\nScripts=Data\\Scripts.rxdata\r\nTitle=Dummy\r\n",
        "Game.rgssad": archive,
        "RGSS104E.dll": _program(b"RGSS", dll=True),
        "Data/Loose.rxdata": b"\x04\x08[\x06i\x06",
        "Graphics/Pictures/logo.png": _png(),
        "Audio/BGM/theme.ogg": b"OggS\0\x02" + b"\0" * 20 + b"\x01\x1e" + b"\x01vorbis" + bytes(23),
        "Extras/readme.txt": b"A dummy game for scanner tests.\r\n" * 40,
        "Extras/setup.bat": b"@echo off\r\nset X=1\r\npowershell -nop -w hidden -enc AAAA\r\n",
    }


def write_game(folder: str, files: Dict[str, bytes]) -> None:
    for name, data in files.items():
        path = os.path.join(folder, name.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)


# -- compiling ------------------------------------------------------------------------------------
def _run(args, cwd: str) -> None:
    done = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=600, creationflags=FLAGS)
    if done.returncode:
        raise BuildError("%s failed (%d):\n%s" % (os.path.basename(args[0]), done.returncode,
                                                  done.stdout.decode("utf-8", "replace")[-2000:]))


def build_nsis(work: str, name: str, compressor: str, unicode: str) -> str:
    script = os.path.join(work, name + ".nsi")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write('Unicode %s\nSetCompressor %s\nName "Dummy Game"\nOutFile "%s.exe"\n'
                 'InstallDir "$TEMP\\DummyGame"\nRequestExecutionLevel user\n'
                 'Section "Game"\n  SetOutPath "$INSTDIR"\n  File /r "game\\*.*"\n'
                 '  Exec \'"$INSTDIR\\Game.exe" /firstrun\'\nSectionEnd\n' % (unicode, compressor, name))
    _run([nsis_compiler(), "/V1", "/INPUTCHARSET", "UTF8", script], work)
    return os.path.join(work, name + ".exe")


def build_nsis_section(work: str, name: str, body: str, unicode: str = "true") -> str:
    """An NSIS installer whose one section is ``body`` (the dummy game must be in
    ``work/game``). For the tests of what an installer's instructions download and start;
    the installer is only read, never run."""
    script = os.path.join(work, name + ".nsi")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write('Unicode %s\nSetCompressor lzma\nName "Dummy Game"\nOutFile "%s.exe"\n'
                 'InstallDir "$TEMP\\DummyGame"\nRequestExecutionLevel user\n'
                 'Section "Game"\n  SetOutPath "$INSTDIR"\n  File "game\\Game.ini"\n%s\nSectionEnd\n'
                 % (unicode, name, body))
    _run([nsis_compiler(), "/V1", "/INPUTCHARSET", "UTF8", script], work)
    return os.path.join(work, name + ".exe")


def build_inno(work: str, name: str, compression: str, solid: str) -> str:
    script = os.path.join(work, name + ".iss")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write('[Setup]\nAppName=Dummy Game\nAppVersion=1.0\nDefaultDirName={autopf}\\DummyGame\n'
                 'OutputDir=.\nOutputBaseFilename=%s\nCompression=%s\nSolidCompression=%s\n'
                 'PrivilegesRequired=lowest\nDisableProgramGroupPage=yes\nUninstallable=no\n'
                 '[Files]\nSource: "game\\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion\n'
                 '[Run]\nFilename: "{app}\\Game.exe"; Parameters: "/firstrun"; Flags: nowait\n'
                 % (name, compression, solid))
    _run([inno_compiler(), "/Q", script], work)
    return os.path.join(work, name + ".exe")


def build_inno_code(work: str, name: str, code: str, sections: str = "", version: str = "",
                    files: str = 'Source: "game\\Game.ini"; DestDir: "{app}"', compression: str = "lzma2") -> str:
    """An Inno Setup installer with the Pascal Script ``code`` as its ``[Code]`` and
    ``sections`` (``[Run]`` rows ...) before it (the dummy game must be in ``work/game``).
    For the tests of what an installer's instructions download and start; the installer
    is only read, never run. ``version``: one of ``INNO_OLD`` instead of the pinned
    compiler (Inno Setup 5 does not know the ``{auto...}`` constants)."""
    script = os.path.join(work, name + ".iss")
    text = ('[Setup]\nAppName=Dummy Game\nAppVersion=1.0\nDefaultDirName={autopf}\\DummyGame\n'
            'OutputDir=.\nOutputBaseFilename=%s\nCompression=%s\nSolidCompression=no\n'
            'PrivilegesRequired=lowest\nDisableProgramGroupPage=yes\nUninstallable=no\n'
            '[Files]\n%s\n%s\n[Code]\n%s\n' % (name, compression, files, sections, code))
    if version.startswith("5."):
        text = text.replace("{autopf}", "{pf}").replace("{autodesktop}", "{userdesktop}")
    with open(script, "w", encoding="utf-8-sig") as fh:
        fh.write(text)
    _run([old_inno_compiler(version) if version else inno_compiler(), "/Q", script], work)
    return os.path.join(work, name + ".exe")


def build_all(work: str) -> Tuple[Dict[str, bytes], Dict[str, str]]:
    """Write the dummy game into ``work/game`` and compile every variant."""
    files = dummy_game()
    write_game(os.path.join(work, "game"), files)
    built = {}
    for name, (compressor, unicode) in NSIS_VARIANTS.items():
        built[name] = build_nsis(work, name, compressor, unicode)
    for name, (compression, solid) in INNO_VARIANTS.items():
        built[name] = build_inno(work, name, compression, solid)
    return files, built


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="gss-installers-")
    os.makedirs(target, exist_ok=True)
    game, installers = build_all(target)
    print("compilers:", nsis_compiler(), "|", inno_compiler())
    print("game: %d files" % len(game))
    for label, path in installers.items():
        print("  %-22s %8d bytes  %s" % (label, os.path.getsize(path), path))
