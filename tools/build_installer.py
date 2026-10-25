"""Build Bagel's per-user installer (Inno Setup) from the portable package zip.

    python tools/build_installer.py --package <Bagel-<version>.zip> [--out <folder>]

(0.9-beta polish, phageo, 2026-10-24.) Dev-only: the official Inno Setup 6.7.3 compiler pinned in
``tests/_tools/innosetup`` (``tests/build_installers.py``; CLAUDE.md rule 14 and the polish task)
compiles a script written here. The installer holds exactly the files of the portable zip (the same
bytes), so its start-up self-check is the zip's. What the installer does:

- **Only for me, or for all users** (final polish, phageo 2026-10-25): Inno Setup's own question
  (``PrivilegesRequired=lowest`` + ``PrivilegesRequiredOverridesAllowed=dialog``). Only for me needs
  no administrator: ``%LOCALAPPDATA%\\Programs\\Bagel``, the menu below HKCU; for all users needs
  one: ``%ProgramFiles%\\Bagel``, the menu below HKLM (``HKA``: Inno picks by the choice). The folder
  page is shown, with that folder as its default. Only for me, a folder only an administrator may
  write to (Program Files ...) is refused on the folder page with a plain message in the setup's
  language that suggests installing for all users (source release, phageo 2026-10-25) - before,
  Setup stopped with an error while copying.
- **Start menu shortcut** "Bagel" to ``Bagel.exe`` (the package's start program, with the icon) and
  Bagel's AppUserModelID (``gui.APP_ID``).
- **Right-click menu at install:** one entry "Bagel" with the icon and a submenu - "Scan" on folders
  and files, "Scan" and "Safe launch" on programs: the keys and commands of ``gamescan/shellmenu.py``
  (built with its own ``command_line``), labels in the installer's language from ``i18n.py``. An
  entry an older copy added under the same keys is deleted first, and so is the separate "Safe
  launch" entry of older copies (``shellmenu.OLD_VERBS``).
- **Uninstall leaves nothing, and only what it installed:** the entries (``uninsdeletekey``), each
  parent key the install had to create only while empty (``uninsdeletekeyifempty``), the shortcut,
  every installed file, Python's ``__pycache__`` folders inside the package's folders, the folders
  the install made once empty, and the uninstaller itself - never other files in a folder the user
  chose. Bagel's data folder in the profile (``%USERPROFILE%\\.game_safety_scanner``: settings, scan
  memory, quarantine) after one question, default No; a silent uninstall keeps it unless ``/PURGE``
  is given.
- **Unsigned:** Windows SmartScreen may warn (README).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from typing import List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from gamescan import gui, i18n, models, shellmenu          # noqa: E402

COMPILER = os.path.join(ROOT, "tests", "_tools", "innosetup", "ISCC.exe")
APP_ID = "{{9AF30A74-67D5-48BF-B8D7-B236A2341EFD}"           # fixed: upgrades replace, never pile up
APP_DIR = r"{autopf}\Bagel"            # only for me: %LOCALAPPDATA%\Programs; all users: %ProgramFiles%
START = r"{app}\Bagel.exe"                                  # the package's start program (its icon too)
DATA = r"{%USERPROFILE}\.game_safety_scanner"
PURGE_KEY = ("Also delete Bagel's settings, scan memory and quarantine folder?\n\n%1\n\n"
             "Files in quarantine are deleted for good. Choose No to keep them.")
ADMIN_KEY = ("Bagel cannot be installed “only for me” in this folder:\n\n%1\n\n"
             "Only an administrator may write there (Program Files is such a folder). Choose a folder of "
             "your own - the suggested one is fine - or close Setup, start it again and choose to install "
             "for all users.")
PROBE = "bagel-write-test.tmp"           # written and deleted at once by the folder check
_FAKE = "C:\\BAGELAPP"                                      # stands for {app} while shellmenu builds


class InstallerError(Exception):
    pass


def setup_name() -> str:
    return "Bagel-%s-setup" % models.TOOL_VERSION


def _quote(value: str) -> str:
    """One Inno Setup parameter value: in double quotes, inner quotes doubled."""
    return '"' + value.replace('"', '""') + '"'


def _message(text: str) -> str:
    """A [CustomMessages] value: Inno's %n for a line break."""
    return text.replace("\n", "%n")


def menu_entries() -> List[tuple]:
    """``(submenu item below Software\\Classes, command, what)`` of the installed copy - the
    commands of ``shellmenu.command_line`` with ``Bagel.exe``, so the installed window counts the
    entries as its own."""
    program = os.path.join(_FAKE, shellmenu.START_PROGRAM)
    return [(shellmenu.sub_key(key, what),
             shellmenu.command_line(program, None, "%1", what).replace(_FAKE, "{app}"), what)
            for key, subs in shellmenu.entries() for what in subs]


def cache_folders(source: str) -> List[str]:
    """``{app}\\...\\__pycache__`` for every folder of the package that holds Python modules: what
    Python itself may write there, removed by the uninstaller (nothing else of the folder)."""
    out = []
    for base, dirs, files in os.walk(source):
        dirs.sort()
        if any(n.endswith(".py") for n in files):
            rel = os.path.relpath(base, source)
            out.append("{app}" + ("" if rel == "." else "\\" + rel) + "\\__pycache__")
    return sorted(out)


def script(source: str, version: str = models.TOOL_VERSION) -> str:
    """The Inno Setup script for the unpacked package folder ``source``."""
    labels = {}
    for lang in ("en", "tr"):
        i18n.set_language(lang)
        labels[lang] = (i18n.t(shellmenu.SCAN_LABEL), i18n.t(shellmenu.LAUNCH_LABEL), i18n.t(PURGE_KEY),
                        i18n.t(ADMIN_KEY))
    i18n.set_language("en")
    numeric = ".".join((version.split("-")[0].split(".") + ["0", "0", "0"])[:3]) + ".0"
    lines = [
        "; Bagel %s - written by tools/build_installer.py; do not edit by hand" % version,
        "[Setup]",
        "AppId=" + APP_ID,
        "AppName=Bagel",
        "AppVersion=" + version,
        "AppVerName=Bagel " + version,
        "AppPublisher=phageo",
        "VersionInfoVersion=" + numeric,
        "DefaultDirName=" + APP_DIR,
        "DisableDirPage=no",
        "DisableProgramGroupPage=yes",
        # "only for me" (no administrator) by default; "for all users" asks for one
        "PrivilegesRequired=lowest",
        "PrivilegesRequiredOverridesAllowed=dialog",
        "ArchitecturesAllowed=x64compatible",
        "ArchitecturesInstallIn64BitMode=x64compatible",
        "MinVersion=6.3",
        "UninstallFilesDir={app}\\uninstall",
        "UninstallDisplayName=Bagel",
        "UninstallDisplayIcon=" + START,
        "SetupIconFile=" + os.path.join(source, "app", "gamescan", "bagel.ico"),
        "LicenseFile=" + os.path.join(source, "LICENSE"),
        "OutputBaseFilename=" + setup_name(),
        "Compression=lzma2/max",
        "SolidCompression=yes",
        "WizardStyle=modern",
        "ChangesAssociations=yes",
        "CloseApplications=yes",
        "",
        "[Languages]",
        'Name: "en"; MessagesFile: "compiler:Default.isl"',
        'Name: "tr"; MessagesFile: "compiler:Languages\\Turkish.isl"',
        "",
        "[CustomMessages]",
    ]
    for lang in ("en", "tr"):
        scan, launch, purge, admin = labels[lang]
        lines += ["%s.ScanLabel=%s" % (lang, scan), "%s.LaunchLabel=%s" % (lang, launch),
                  "%s.PurgeQuestion=%s" % (lang, _message(purge)), "%s.NeedsAdmin=%s" % (lang, _message(admin))]
    lines += [
        "",
        "[Files]",
        "Source: %s; DestDir: \"{app}\"; Flags: recursesubdirs createallsubdirs ignoreversion"
        % _quote(os.path.join(source, "*")),
        "",
        "[Icons]",
        "Name: \"{autoprograms}\\Bagel\"; Filename: %s; WorkingDir: \"{app}\"; IconFilename: %s; "
        "AppUserModelID: %s" % (_quote(START), _quote(START), _quote(gui.APP_ID)),
        "",
        "[Registry]",
    ]
    # HKA: below HKCU when installed only for me, below HKLM for all users. The parents first:
    # the uninstaller works backwards, so they are looked at after the entries
    parents = []
    for key, _subs in shellmenu.entries():
        bits = key.split("\\")[:-1]
        for depth in range(1, len(bits) + 1):
            parent = "\\".join(bits[:depth])
            if parent not in parents:
                parents.append(parent)
    for parent in parents:
        lines.append("Root: HKA; Subkey: %s; ValueType: none; Flags: uninsdeletekeyifempty"
                     % _quote("Software\\Classes\\" + parent))
    commands = {key: command for key, command, _what in menu_entries()}
    for key, subs in shellmenu.entries():
        sub = _quote("Software\\Classes\\" + key)
        lines += [
            # deletekey: an older entry under this key goes first
            "Root: HKA; Subkey: %s; ValueType: string; ValueName: \"MUIVerb\"; ValueData: %s; "
            "Flags: deletekey uninsdeletekey" % (sub, _quote(shellmenu.MENU_LABEL)),
            "Root: HKA; Subkey: %s; ValueType: string; ValueName: \"Icon\"; ValueData: %s" % (sub, _quote(START)),
            "Root: HKA; Subkey: %s; ValueType: string; ValueName: \"SubCommands\"; ValueData: \"\"" % sub,
        ]
        for what in subs:
            item = shellmenu.sub_key(key, what)
            label = "{cm:LaunchLabel}" if what == shellmenu.LAUNCH else "{cm:ScanLabel}"
            lines += [
                "Root: HKA; Subkey: %s; ValueType: string; ValueName: \"MUIVerb\"; ValueData: %s"
                % (_quote("Software\\Classes\\" + item), _quote(label)),
                "Root: HKA; Subkey: %s; ValueType: string; ValueName: \"\"; ValueData: %s"
                % (_quote("Software\\Classes\\" + item + "\\command"), _quote(commands[item])),
            ]
    lines += ["", "[UninstallDelete]"]
    lines += ["Type: filesandordirs; Name: %s" % _quote(folder) for folder in cache_folders(source)]
    lines += [
        "Type: dirifempty; Name: \"{app}\"",
        "",
        "[Code]",
        "{ only for me: a folder only an administrator may write to (Program Files ...) gets a plain",
        "  message on the folder page instead of an error while installing }",
        "function CanWriteBelow(Dir: String): Boolean;",
        "var",
        "  Probe: String;",
        "begin",
        "  Dir := RemoveBackslashUnlessRoot(Dir);",
        "  while (not DirExists(Dir)) and (ExtractFileDir(Dir) <> Dir) do",
        "    Dir := ExtractFileDir(Dir);",
        "  { a drive that is not there: Setup's own check speaks }",
        "  Result := not DirExists(Dir);",
        "  if not Result then",
        "  begin",
        "    Probe := AddBackslash(Dir) + '%s';" % PROBE,
        "    Result := SaveStringToFile(Probe, '', False);",
        "    if Result then",
        "      DeleteFile(Probe);",
        "  end;",
        "end;",
        "",
        "function NextButtonClick(CurPageID: Integer): Boolean;",
        "begin",
        "  Result := True;",
        "  { a silent setup has no page to stay on: PrepareToInstall refuses the folder there }",
        "  if (CurPageID = wpSelectDir) and (not WizardSilent) and (not IsAdminInstallMode)",
        "     and (not CanWriteBelow(WizardDirValue)) then",
        "  begin",
        "    SuppressibleMsgBox(FmtMessage(CustomMessage('NeedsAdmin'), [WizardDirValue]), mbError, MB_OK, IDOK);",
        "    Result := False;",
        "  end;",
        "end;",
        "",
        "{ before anything is installed (also when silent): the same check; a text here stops Setup }",
        "function PrepareToInstall(var NeedsRestart: Boolean): String;",
        "begin",
        "  Result := '';",
        "  if (not IsAdminInstallMode) and (not CanWriteBelow(WizardDirValue)) then",
        "    Result := FmtMessage(CustomMessage('NeedsAdmin'), [WizardDirValue]);",
        "end;",
        "",
        "procedure CurStepChanged(CurStep: TSetupStep);",
        "begin",
        "  if CurStep = ssInstall then",
        "  begin",
        "    { the separate \"Safe launch\" entry of older copies }",
    ]
    for parent, verb in shellmenu.OLD_VERBS:
        lines.append("    RegDeleteKeyIncludingSubkeys(HKA, '%s');" % ("Software\\Classes\\" + parent + "\\" + verb))
    lines += [
        "  end;",
        "end;",
        "",
        "procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);",
        "var",
        "  Data: String;",
        "begin",
        "  if CurUninstallStep = usPostUninstall then",
        "  begin",
        "    Data := ExpandConstant('%s');" % DATA,
        "    if DirExists(Data) then",
        "      if (Pos('/PURGE', Uppercase(GetCmdTail)) > 0) or",
        "         ((not UninstallSilent) and (MsgBox(FmtMessage(CustomMessage('PurgeQuestion'), [Data]),",
        "                                           mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES)) then",
        "        DelTree(Data, True, True, True);",
        "  end;",
        "end;",
        "",
    ]
    return "\r\n".join(lines)


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build(package: str, out_dir: Optional[str] = None, say=print) -> str:
    """Unpack ``package`` beside the output, compile the installer, remove the unpacked copy."""
    out_dir = os.path.abspath(out_dir or os.path.dirname(os.path.abspath(package)))
    root = os.path.normcase(ROOT) + os.sep
    if os.path.normcase(out_dir + os.sep).startswith(root):
        raise InstallerError("the installer is written outside the project: " + out_dir)
    if not os.path.isfile(COMPILER):
        raise InstallerError("the pinned Inno Setup compiler is missing: " + COMPILER)
    top = "Bagel-" + models.TOOL_VERSION
    work = os.path.join(out_dir, "_installer_work")
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    try:
        with zipfile.ZipFile(package) as z:
            names = z.namelist()
            if not names or any(not n.startswith(top + "/") or ".." in n.split("/") for n in names):
                raise InstallerError("not the package of %s: %s" % (top, package))
            z.extractall(work)
        source = os.path.join(work, top)
        iss = os.path.join(work, "bagel.iss")
        with open(iss, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(script(source))
        say("package %s: %d files unpacked to %s" % (os.path.basename(package), len(names), work))
        result = subprocess.run([COMPILER, "/Q", "/O" + out_dir, iss], capture_output=True, text=True)
        if result.returncode != 0:
            raise InstallerError("the Inno Setup compiler failed (%d): %s" % (
                result.returncode, (result.stderr or result.stdout).strip()[-2000:]))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    target = os.path.join(out_dir, setup_name() + ".exe")
    say("%s: %.1f MB, SHA-256 %s" % (target, os.path.getsize(target) / 1048576, sha256(target)))
    return target


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--package", required=True, help="the portable zip of tools/build_package.py")
    ap.add_argument("--out", help="folder of the installer (default: the zip's folder)")
    args = ap.parse_args(argv)
    try:
        build(args.package, args.out)
    except (InstallerError, OSError, zipfile.BadZipFile) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
