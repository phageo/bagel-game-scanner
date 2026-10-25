"""The Explorer right-click menu: one entry "Bagel" with Bagel's icon and a submenu - "Scan" on
folders and files, "Scan" and "Safe launch" on programs (``.exe``). (One entry with a submenu since
the 0.9-beta final polish, phageo 2026-10-25; before that two separate entries.)

(Criterion 5 (g); in 0.9-beta by phageo's word, 2026-10-24.) Opt-in only: a button in the window and
in Settings adds and removes it. Current user only - ``HKEY_CURRENT_USER\\Software\\Classes``, never
written to HKLM, no admin rights. The entry is never the default action of a file or folder (no
default verb is set). Its commands open the window with the clicked path and nothing else:

    "<Bagel.exe>" "%1"                  Scan
    "<Bagel.exe>" --launch "%1"         Safe launch (the secure launcher in the window)

- ``Bagel.exe`` is the package's start program (``tools/launcher/``); a copy without it (the project
  folder) runs ``"<pythonw.exe>" -I "<GameSafetyScanner.pyw>"`` instead. The paths are those of the
  running copy; a path with a quote, a percent sign or a line break is refused, so Explorer's ``%1``
  stays the only argument it fills in. The clicked path reaches the window as a path only
  (``gui.main``), never as an option.
- One verb key ``GameSafetyScanner`` below each place (``Directory\\shell``, ``*\\shell`` and, for
  programs, ``SystemFileAssociations\\.exe\\shell``): ``MUIVerb`` "Bagel", ``Icon``, an empty
  ``SubCommands`` and the submenu in its own ``shell`` key. On a program Explorer takes the verb of
  the ``.exe`` place and leaves out the same verb name of ``*`` (the more specific place wins), so a
  program shows one "Bagel" entry, not two.
- Every key this module made - also a parent ``shell`` / ``Directory`` / ``*`` key that did not
  exist before - is written down in the entry itself (``CREATED``) and removed again by ``remove``;
  a parent is removed only while it is empty. After ``remove`` no key of ours is left. The separate
  "Safe launch" entry of older copies (``OLD_VERBS``) is removed too.
- When the package folder moves, the entry still names the old place: ``state`` tells it, and the
  window offers to point it to the running copy (``gui.App._startup_checks``).
- The installer (``tools/build_installer.py``) writes the same keys with the same commands at install
  and removes them at uninstall, so the installed copy sees them as its own. An installation "for all
  users" writes them below HKLM instead: ``machine_wide`` reads that (read only).
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional, Tuple

CLASSES = r"Software\Classes"
VERB = "GameSafetyScanner"
OLD_VERBS = ((r"SystemFileAssociations\.exe\shell", "GameSafetyScannerLaunch"),)   # before 2026-10-25
CREATED = "GameSafetyScannerCreated"     # the parent keys this entry had to make (REG_MULTI_SZ)
SCAN, LAUNCH = "scan", "launch"
MENU_LABEL = "Bagel"                     # the entry itself (a name: never translated)
SCAN_LABEL, LAUNCH_LABEL = "Scan", "Safe launch"
# the submenu's keys: Explorer lists them by name, so the digit keeps "Scan" first
SUBKEYS = {SCAN: "1scan", LAUNCH: "2launch"}
START_PROGRAM = "Bagel.exe"              # the package's start program, beside app\ and python\
# (parent of the verb, what its submenu holds). "Safe launch" (packaging session 3, phageo): on
# programs only, through Windows' own per-extension place, so the .exe class is not touched
TARGETS = ((r"Directory\shell", (SCAN,)), (r"*\shell", (SCAN,)),
           (r"SystemFileAssociations\.exe\shell", (SCAN, LAUNCH)))


class MenuError(Exception):
    pass


def _winreg():
    if sys.platform != "win32":
        raise MenuError("the right-click menu exists on Windows only")
    import winreg
    return winreg


def app_paths() -> Tuple[str, str]:
    """``(pythonw.exe, GameSafetyScanner.pyw)`` of the running copy."""
    exe = sys.executable
    windowed = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.basename(exe).lower() == "python.exe" and os.path.isfile(windowed):
        exe = windowed
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "GameSafetyScanner.pyw")
    return os.path.abspath(exe), script


def start_program() -> Optional[str]:
    """The package's ``Bagel.exe`` when this copy runs from a package (``app\\`` and the Python
    that runs it in ``python\\``, both beside it), else ``None``."""
    python, script = app_paths()
    top = os.path.dirname(os.path.dirname(script))
    program = os.path.join(top, START_PROGRAM)
    same = os.path.normcase(os.path.dirname(os.path.dirname(python))) == os.path.normcase(top)
    return program if same and os.path.isfile(program) else None


def icon_path() -> Optional[str]:
    """Bagel's icon beside this module (``tools/build_icon.py``), or ``None`` (then Python's)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bagel.ico")
    return path if os.path.isfile(path) and not any(ch in path for ch in '"%\r\n\x00') else None


def command_line(program: str, script: Optional[str], item: str = "%1", what: str = SCAN) -> str:
    """The command Explorer runs: ``"<program>" -I "<script>"`` (Python and the launcher) or, with
    no ``script``, ``"<program>"`` (``Bagel.exe``); refuses a path that could change what Explorer
    fills in. "Safe launch" puts the fixed word ``--launch`` before the clicked program."""
    for path in (program,) + ((script,) if script is not None else ()):
        if not os.path.isabs(path) or any(ch in path for ch in '"%\r\n\x00'):
            raise MenuError("this path cannot be used in the right-click menu: %r" % path)
    head = '"%s"' % program if script is None else '"%s" -I "%s"' % (program, script)
    return '%s %s"%s"' % (head, "--launch " if what == LAUNCH else "", item)


def entries() -> List[Tuple[str, Tuple[str, ...]]]:
    """``(verb key below Software\\Classes, what its submenu holds)``."""
    return [(parent + "\\" + VERB, subs) for parent, subs in TARGETS]


def sub_key(key: str, what: str) -> str:
    """The submenu item ``what`` of the verb key ``key``."""
    return key + "\\shell\\" + SUBKEYS[what]


def wanted() -> List[Tuple[str, str, str]]:
    """``(submenu item below Software\\Classes, command, what)`` for the running copy."""
    program = start_program()
    if program is None:
        program, script = app_paths()
    else:
        script = None
    return [(sub_key(key, what), command_line(program, script, "%1", what), what)
            for key, subs in entries() for what in subs]


def _read_command(reg, root, base: str, key: str) -> Optional[str]:
    try:
        with reg.OpenKey(root, base + "\\" + key + r"\command") as handle:
            value, _kind = reg.QueryValueEx(handle, "")
            return value
    except OSError:
        return None


def _exists(reg, path: str, root=None) -> bool:
    try:
        reg.CloseKey(reg.OpenKey(reg.HKEY_CURRENT_USER if root is None else root, path))
        return True
    except OSError:
        return False


def _state(reg, root, base: str) -> Tuple[bool, bool, List[str]]:
    found, current = [], True
    for key, command, _what in wanted():
        old = _read_command(reg, root, base, key)
        if old is None and not _exists(reg, base + "\\" + key, root):
            current = False
            continue
        found.append(old or "")
        current = current and old == command
    # an entry of an older copy (one item per entry, no submenu) counts as "added elsewhere"
    for key, _subs in entries():
        old = _read_command(reg, root, base, key)
        if old is not None:
            found.append(old)
            current = False
    for parent, verb in OLD_VERBS:
        old = _read_command(reg, root, base, parent + "\\" + verb)
        if old is not None:
            found.append(old)
            current = False
    return bool(found), bool(found) and current, found


def state(base: str = CLASSES) -> Tuple[bool, bool, List[str]]:
    """``(added, points here, commands found)``: ``added`` when any entry of ours exists, ``points
    here`` when every submenu item runs the running copy."""
    reg = _winreg()
    return _state(reg, reg.HKEY_CURRENT_USER, base)


def machine_wide() -> bool:
    """Did an installation "for all users" add the menu for this copy (below HKLM, read only)?"""
    reg = _winreg()
    return _state(reg, reg.HKEY_LOCAL_MACHINE, CLASSES)[1]


def add(label: str = SCAN_LABEL, base: str = CLASSES, launch_label: str = LAUNCH_LABEL) -> None:
    """Add (or point to this copy) the entry "Bagel": "Scan" (``label``) on folders and files,
    and on programs also "Safe launch" (``launch_label``)."""
    reg = _winreg()
    commands = {key: command for key, command, _what in wanted()}
    for parent, verb in OLD_VERBS:
        _remove_one(reg, base, parent + "\\" + verb)
    icon = icon_path() or next(iter(commands.values())).split('"')[1]
    for key, subs in entries():
        if _exists(reg, base + "\\" + key):
            _remove_one(reg, base, key)               # a fresh entry: no value of an older copy
        made = []
        parts = key.split("\\")
        for depth in range(1, len(parts)):            # the parents below Software\Classes
            parent = base + "\\" + "\\".join(parts[:depth])
            if not _exists(reg, parent):
                made.append("\\".join(parts[:depth]))
        with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, base + "\\" + key, 0, reg.KEY_WRITE) as handle:
            reg.SetValueEx(handle, "MUIVerb", 0, reg.REG_SZ, MENU_LABEL)
            reg.SetValueEx(handle, "Icon", 0, reg.REG_SZ, icon)
            reg.SetValueEx(handle, "SubCommands", 0, reg.REG_SZ, "")
            reg.SetValueEx(handle, CREATED, 0, reg.REG_MULTI_SZ, made)
        for what in subs:
            item = sub_key(key, what)
            with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, base + "\\" + item, 0, reg.KEY_WRITE) as handle:
                reg.SetValueEx(handle, "MUIVerb", 0, reg.REG_SZ, launch_label if what == LAUNCH else label)
            with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, base + "\\" + item + r"\command", 0,
                                 reg.KEY_WRITE) as handle:
                reg.SetValueEx(handle, "", 0, reg.REG_SZ, commands[item])


def _empty(reg, path: str) -> bool:
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path) as handle:
            subkeys, values, _time = reg.QueryInfoKey(handle)
            return subkeys == 0 and values == 0
    except OSError:
        return False


def _delete_tree(reg, path: str) -> None:
    """``path`` and everything below it (only keys of this entry are passed here)."""
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path) as handle:
            children = [reg.EnumKey(handle, i) for i in range(reg.QueryInfoKey(handle)[0])]
    except OSError:
        return
    for child in children:
        _delete_tree(reg, path + "\\" + child)
    try:
        reg.DeleteKey(reg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def _remove_one(reg, base: str, key: str) -> None:
    made: List[str] = []
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, base + "\\" + key) as handle:
            made = list(reg.QueryValueEx(handle, CREATED)[0] or [])
    except OSError:
        pass
    _delete_tree(reg, base + "\\" + key)
    for parent in sorted(made, key=len, reverse=True):     # deepest first, only while empty
        if _empty(reg, base + "\\" + parent):
            reg.DeleteKey(reg.HKEY_CURRENT_USER, base + "\\" + parent)


def remove(base: str = CLASSES) -> None:
    """Remove the entry, the separate entry of older copies, and every key they made."""
    reg = _winreg()
    for key, _subs in entries():                       # not wanted(): removing needs no paths
        _remove_one(reg, base, key)
    for parent, verb in OLD_VERBS:
        _remove_one(reg, base, parent + "\\" + verb)
