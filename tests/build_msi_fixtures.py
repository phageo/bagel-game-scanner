"""Build the Windows Installer test fixtures of ``tests/fixtures_msi`` - run once, by hand.

    python tests/build_msi_fixtures.py

Makes small MSI databases with Windows' own Windows Installer object (``WindowsInstaller.
Installer``, reached through PowerShell; allowed by phageo on 2026-10-17 for test fixtures
only, like the Script Encoder before - CLAUDE.md, rule 14) and writes each, compressed,
with the SHA-256 of the database, into ``tests/fixtures_msi/fixtures.json``. The tests
read that file and never need Windows Installer.

The object only writes database files: nothing is installed, no package is opened for
installation, and nothing of what the tables name exists or is run (the "programs" and
"scripts" in them are short harmless texts; addresses are under ``example.invalid``). A
fixture that is in the file already is kept as it is; only new ones are built.

Since 2026-10-19 (part 2 of the MSI reader) the cabinets inside packages are real ones, made
by Windows' own ``makecab.exe`` (allowed by phageo the same day for these test fixtures only,
dev-only - CLAUDE.md, rule 14): one MSZIP, one LZX, of the same three harmless files
(:data:`CAB_FILES`). They are kept as fixtures of their own (``CAB_MSZIP``, ``CAB_LZX``) and
inside the packages ``MSZIP``, ``LZX`` (embedded) and ``ACTIONS`` (whose cabinet lies beside
it). The tests need neither tool.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures_msi", "fixtures.json")

LONG_VALUE = "".join("%05d " % k for k in range(12000))          # 72,000 characters: over 64 KB
TABLES = [
    "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE "
    "PRIMARY KEY `Property`)",
    "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), "
    "`DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)",
    "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) "
    "NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)",
    "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL "
    "LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, "
    "`Sequence` SHORT NOT NULL PRIMARY KEY `File`)",
    "CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) "
    "LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)",
    "CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)",
    "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), "
    "`Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)",
    "CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT "
    "PRIMARY KEY `Action`)",
]
SCRIPT_TEXT = 'Set shell = CreateObject("WScript.Shell")\r\nshell.Run "notepad.exe readme.txt", 1, False\r\n'
FULL = TABLES + [
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["ProductName", "Fixture Game"]),
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["ProductCode",
                                                                         "{11111111-2222-3333-4444-555555555555}"]),
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["LongNote", LONG_VALUE]),
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('TARGETDIR', '', 'SourceDir')",
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('INSTALLDIR', 'TARGETDIR', "
    "'GAME|Fixture Game')",
    "INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath`) VALUES "
    "('Main', '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}', 'INSTALLDIR', 0, 'game.exe')",
    "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES "
    "('game.exe', 'Main', 'GAME.EXE|Game.exe', 1234567, 1)",
    "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES "
    "('data.pak', 'Main', 'data.pak', 7654321, 2)",
    "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES "
    "('readme.txt', 'Main', 'README.TXT|Read me.txt', 300, 3)",
    "INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (1, 2, '#game1.cab')",
    "INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (2, 3, 'disk2.cab')",
    ("stream", "INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)", ["game1.cab"],
     b"a placeholder for an embedded cabinet " * 200),
    ("stream", "INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)", ["HelperProgram"], b"not a program " * 700),
    ("stream", "INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)", ["Check.vbs"], SCRIPT_TEXT.encode("ascii")),
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('RunHelper', 2, 'HelperProgram', "
    "'/quiet')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('RunCheck', 6, 'Check.vbs', 'Main')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('StartGame', 34, 'INSTALLDIR', "
    "'\"[INSTALLDIR]Game.exe\" --first-run')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Inline', 38, '', "
    "'MsgBox \"https://files.example.invalid/hello\"')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetFolder', 51, 'GAMEFOLDER', "
    "'[INSTALLDIR]')",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('CostInitialize', 800)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFiles', 4000)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ('RunHelper', 'NOT Installed', "
    "6600)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('StartGame', 6700)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetFolder', 1001)",
    ("summary", {2: "Fixture Game", 7: "x64;1033", 9: "{99999999-8888-7777-6666-555555555555}", 14: 200, 15: 2}),
]
# more than 65,535 texts: the pool switches to text numbers of three bytes
_BIG = "Name\tValue\r\ns72\ts72\r\nBig\tName\r\n" + "".join("n%06d\tv%06d\r\n" % (k, k) for k in range(34000))
LONGREFS = [
    TABLES[0],
    ("import", "Big.idt", _BIG),
    "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Many Texts')",
]
# a database whose texts are UTF-8 (code page 65001): Turkish and Japanese names
UNICODE = [
    ("import", "_ForceCodepage.idt", "\r\n\r\n65001\t_ForceCodepage\r\n"),
    TABLES[0], TABLES[3],
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["ProductName", "Oyun çıktı"]),
    ("row", "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES (?, ?, ?, ?, ?)",
     ["f1", "Main", "OYUN~1.TXT|ğüşıöç 日本.txt", 42, 1]),
]
# a transform (.mst): the differences between two databases, not a database of its own
TRANSFORM = [
    TABLES[0],
    "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Patched')",
    ("transform", [TABLES[0], "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Original')"]),
]
# -- part 2 (2026-10-19): real cabinets, by makecab.exe -------------------------------------------
# the files of the cabinets, under the keys of the File table (a cabinet of a package names its
# files by those keys): a read-me long enough for several MSZIP blocks (32 KB each, each block's
# window carried on from the one before), a batch file, a VBScript - all harmless
README_TEXT = "".join("line %05d of the read-me text of the fixture game\r\n" % k for k in range(4000))
CAB_FILES = [("filReadme", README_TEXT.encode("ascii")),
             ("filStart", b"@echo off\r\necho Starting the fixture game\r\n"),
             ("filHelper", b'Dim greeting\r\ngreeting = "hello from the fixture"\r\n')]
_TREE = [
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('TARGETDIR', '', 'SourceDir')",
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('ProgramFilesFolder', "
    "'TARGETDIR', 'PFiles')",
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('INSTALLDIR', "
    "'ProgramFilesFolder', 'GAME|Fixture Game')",
    "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('DOCS', 'INSTALLDIR', 'docs')",
    "INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath`) VALUES "
    "('Main', '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEE1}', 'INSTALLDIR', 0, 'filStart')",
    "INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath`) VALUES "
    "('Docs', '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEE2}', 'DOCS', 0, 'filReadme')",
    ("row", "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES (?, ?, ?, ?, ?)",
     ["filReadme", "Docs", "README.TXT|Read me.txt", len(CAB_FILES[0][1]), 1]),
    ("row", "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES (?, ?, ?, ?, ?)",
     ["filStart", "Main", "start.bat", len(CAB_FILES[1][1]), 2]),
    ("row", "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Sequence`) VALUES (?, ?, ?, ?, ?)",
     ["filHelper", "Main", "HELPER.TXT|helper.txt", len(CAB_FILES[2][1]), 3]),
]
_SEQUENCE = [
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFiles', 4000)",
]
# a package with its cabinet inside it (MSZIP), and custom actions a game installer has: it shows
# its read-me, runs its helper script (an installed file run as a VBScript) - nothing else
MSZIP = TABLES + _TREE + _SEQUENCE + [
    "INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (1, 3, '#data.cab')",
    ("cabinet", "data.cab", "MSZIP"),
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('ShowReadme', 34, 'INSTALLDIR', "
    "'\"[INSTALLDIR]start.bat\" \"[#filReadme]\"')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('RunHelper', 22, 'filHelper', '')",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('ShowReadme', 6600)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('RunHelper', 6700)",
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["ProductName", "Fixture Game"]),
]
# the same, with an LZX cabinet: not decoded - said
LZX = TABLES + _TREE + _SEQUENCE + [
    "INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (1, 3, '#data.cab')",
    ("cabinet", "data.cab", "LZX"),
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["ProductName", "Fixture Game"]),
]
# the cabinet lies beside the package; custom actions of every kind part 2 reads
ACTIONS = TABLES + _TREE + _SEQUENCE + [
    "INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (1, 3, 'outside.cab')",
    ("row", "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", ["TOOLPATH", "[INSTALLDIR]tool.exe"]),
    ("stream", "INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)", ["CaDll"], b"not a library " * 50),
    ("stream", "INSERT INTO `Binary` (`Name`, `Data`) VALUES (?, ?)", ["Greeter"],
     b'Dim answer\r\nanswer = "hello from the Binary table"\r\n'),
    # a deferred library action and what it is handed (CustomActionData: a property of its own name)
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Deferred', 1025, 'CaDll', 'Run')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetDeferred', 51, 'Deferred', "
    "'\"[INSTALLDIR]start.bat\" --deferred')",
    # a program whose path a property holds; a JScript written in the table; a VBScript of the Binary
    # table; a script in a property that is set only while installing
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('RunTool', 50, 'TOOLPATH', '--check')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Inline', 37, '', 'var greeting = 1;')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Greet', 6, 'Greeter', 'Main')",
    "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Later', 54, 'LATERSCRIPT', '')",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetDeferred', 5000)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('Deferred', 5001)",
    "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('RunTool', 5002)",
]

# -- the LZX decoder (2026-10-19): cabinets at three window sizes, of text, noise that does not
# shrink, bytes with many E8 values (the call translation), an empty file. (Measured: makecab
# writes aligned-offset blocks only, also for the noise - the verbatim and stored blocks are
# tested with a small encoder in the tests.) All generated here, all harmless: no program, no script.
def _noise(size: int, seed: int) -> bytes:
    out, x = bytearray(), seed
    while len(out) < size:
        x = (x * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out += (x >> 32).to_bytes(4, "little")
    return bytes(out[:size])


def _calls(count: int) -> bytes:
    out = bytearray()
    for k in range(count):
        out += b"rec%05d:" % k + b"\xe8" + ((k * 7919) % 300000 - 1000).to_bytes(4, "little", signed=True)
        out += b"\x00\xe8" + (k * 13).to_bytes(4, "little") + bytes([k & 0xFF, 0xE8]) + b"--"
    return bytes(out)


LZX_FILES = [("text.txt", README_TEXT.encode("ascii")[:150000]), ("noise.bin", _noise(40000, 7)),
             ("calls.bin", _calls(9000)), ("empty.txt", b""), ("tail.txt", README_TEXT.encode("ascii")[:999])]
FIXTURES = {"FULL": FULL, "LONGREFS": LONGREFS, "UNICODE": UNICODE, "TRANSFORM": TRANSFORM,
            "CAB_MSZIP": [("cabinet file", "MSZIP")], "CAB_LZX": [("cabinet file", "LZX")],
            "MSZIP": MSZIP, "LZX": LZX, "ACTIONS": ACTIONS,
            "CAB_LZX15": [("cabinet file", "LZX", 15, LZX_FILES)], "CAB_LZX18": [("cabinet file", "LZX", 18, LZX_FILES)],
            "CAB_LZX21": [("cabinet file", "LZX", 21, LZX_FILES)]}
CABINETS = ("CAB_MSZIP", "CAB_LZX", "CAB_LZX15", "CAB_LZX18", "CAB_LZX21")   # (cabinets, not packages)


def cabinet(method: str, folder: str, window: int = 21, files=None) -> bytes:
    """A cabinet of ``files`` (:data:`CAB_FILES` unless given), made by Windows' own ``makecab.exe``
    (``MSZIP``, or ``LZX`` with a window of 2^``window`` bytes). Its files are harmless data;
    nothing is run but makecab."""
    files = CAB_FILES if files is None else files
    source = os.path.join(folder, "cab-" + method)
    os.makedirs(source, exist_ok=True)
    for name, data in files:
        with open(os.path.join(source, name), "wb") as fh:
            fh.write(data)
    out = os.path.join(folder, "out-" + method)
    os.makedirs(out, exist_ok=True)
    lines = [".OPTION EXPLICIT", ".Set CabinetNameTemplate=fixture.cab", ".Set DiskDirectoryTemplate=" + out,
             ".Set CompressionType=" + method, ".Set Cabinet=on", ".Set Compress=on", ".Set MaxDiskSize=0",
             ".Set RptFileName=" + os.path.join(folder, "makecab.rpt"),
             ".Set InfFileName=" + os.path.join(folder, "makecab.inf"), ".Set SourceDir=" + source]
    if method == "LZX":
        lines.insert(4, ".Set CompressionMemory=%d" % window)
    lines += ['"%s"' % name for name, _data in files]
    directives = os.path.join(folder, "fixture-%s.ddf" % method)
    with open(directives, "w", encoding="ascii", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")
    done = subprocess.run(["makecab.exe", "/F", directives], capture_output=True, text=True, timeout=300, cwd=folder)
    path = os.path.join(out, "fixture.cab")
    if done.returncode or not os.path.isfile(path):
        raise SystemExit("makecab failed: %s" % (done.stderr or done.stdout)[-600:])
    with open(path, "rb") as fh:
        return fh.read()

_PS = r"""
$ErrorActionPreference = "Stop"
$i = New-Object -ComObject WindowsInstaller.Installer
function Plain($a) { if ($null -eq $a -or $a.Count -eq 0) { return $null }
  [object[]]$o = @(foreach ($x in $a) { if ($x -is [psobject]) { $x.psobject.BaseObject } else { $x } }); return ,$o }
function Call($obj, $name, $a) { $obj.GetType().InvokeMember($name, "InvokeMethod", $null, $obj, (Plain $a)) }
function SetProp($obj, $name, $a) { [void]$obj.GetType().InvokeMember($name, "SetProperty", $null, $obj, (Plain $a)) }
function Text($b) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) }
$db = Call $i "OpenDatabase" @((Text '%s'), 3)
function Sql($q) { $v = Call $db "OpenView" @($q); [void](Call $v "Execute" @()); [void](Call $v "Close" @()) }
function Row($q, $values, $stream) {
  $r = Call $i "CreateRecord" @($values.Count + [int]($null -ne $stream))
  for ($k = 0; $k -lt $values.Count; $k++) {
    if ($values[$k] -is [int]) { SetProp $r "IntegerData" @(($k + 1), $values[$k]) }
    else { SetProp $r "StringData" @(($k + 1), $values[$k]) } }
  if ($null -ne $stream) { [void](Call $r "SetStream" @(($values.Count + 1), $stream)) }
  $v = Call $db "OpenView" @($q); [void](Call $v "Execute" @($r)); [void](Call $v "Close" @()) }
%s
[void](Call $db "Commit" @())
"""


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _value(v) -> str:
    return str(v) if isinstance(v, int) else "(Text '%s')" % _b64(v)


def build(steps, folder: str) -> bytes:
    if steps and not isinstance(steps[0], str) and steps[0][0] == "cabinet file":
        return cabinet(*steps[0][1:2], folder, *steps[0][2:])
    path = os.path.join(folder, "fixture.msi")
    lines = []
    for n, step in enumerate(steps):
        if not isinstance(step, str) and step[0] == "cabinet":      # an embedded cabinet: a stream of its own
            step = ("stream", "INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)", [step[1]],
                    cabinet(step[2], folder))
        if isinstance(step, str):
            lines.append("Sql (Text '%s')" % _b64(step))
        elif step[0] == "row":
            lines.append("Row (Text '%s') @(%s) $null" % (_b64(step[1]), ", ".join(_value(v) for v in step[2])))
        elif step[0] == "stream":
            data = os.path.join(folder, "stream%d.bin" % n)
            with open(data, "wb") as fh:
                fh.write(step[3])
            lines.append("Row (Text '%s') @(%s) (Text '%s')" % (_b64(step[1]), ", ".join(_value(v) for v in step[2]),
                                                                   _b64(data)))
        elif step[0] == "import":
            with open(os.path.join(folder, step[1]), "w", encoding="utf-8", newline="") as fh:
                fh.write(step[2])
            lines.append("[void](Call $db \"Import\" @((Text '%s'), (Text '%s')))" % (_b64(folder), _b64(step[1])))
        elif step[0] == "summary":
            lines.append("$s = $db.GetType().InvokeMember(\"SummaryInformation\", \"GetProperty\", $null, $db, "
                         "[object[]]@(20))")
            for pid, value in step[1].items():
                lines.append("SetProp $s \"Property\" @(%d, %s)" % (pid, _value(value)))
            lines.append("[void](Call $s \"Persist\" @())")
        elif step[0] == "transform":          # (the last step) the output is the transform
            reference = os.path.join(folder, "reference.msi")
            path = os.path.join(folder, "fixture.mst")
            lines.append("[void](Call $db \"Commit\" @())")
            lines.append("$changed = $db; $db = Call $i \"OpenDatabase\" @((Text '%s'), 3)" % _b64(reference))
            lines.extend("Sql (Text '%s')" % _b64(q) for q in step[1])
            lines.append("[void](Call $db \"Commit\" @())")
            lines.append("[void](Call $changed \"GenerateTransform\" @($db, (Text '%s')))" % _b64(path))
    script = os.path.join(folder, "build.ps1")
    with open(script, "w", encoding="utf-8-sig") as fh:
        fh.write(_PS % (_b64(os.path.join(folder, "fixture.msi")), "\n".join(lines)))
    done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                           script], capture_output=True, text=True, timeout=600)
    if done.returncode or not os.path.isfile(path):
        raise SystemExit("Windows Installer failed: %s" % (done.stderr or done.stdout)[-600:])
    with open(path, "rb") as fh:
        return fh.read()


def load() -> dict:
    """name -> the database's bytes (what the tests use; checked against the SHA-256)."""
    with open(OUT, encoding="utf-8") as fh:
        kept = json.load(fh)["fixtures"]
    out = {}
    for name, item in kept.items():
        data = zlib.decompress(base64.b64decode(item["zlib"]))
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("fixture %s does not match its SHA-256" % name)
        out[name] = data
    return out


def main() -> int:
    kept = {}
    if os.path.isfile(OUT):
        with open(OUT, encoding="utf-8") as fh:
            kept = json.load(fh)["fixtures"]
    built = 0
    for name, steps in FIXTURES.items():
        if name in kept:
            continue
        folder = tempfile.mkdtemp(prefix="gss-msi-")
        try:
            data = build(steps, folder)
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        kept[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "zlib": base64.b64encode(zlib.compress(data, 9)).decode("ascii")}
        built += 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"maker": "WindowsInstaller.Installer (Windows Installer), through PowerShell",
                   "fixtures": kept}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("%d new, %d kept -> %s" % (built, len(kept) - built, OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
