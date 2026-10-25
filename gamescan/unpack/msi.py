"""Windows Installer packages (MSI): the database inside the compound file.

An MSI is a compound file (``cfb.py``) holding a small relational database. Its streams
have packed names (two name characters in one, ``decode_name``); a table is one stream,
stored column by column; texts are numbers into one string pool (``_StringPool`` with the
lengths, ``_StringData`` with the texts); ``_Tables`` lists the tables and ``_Columns``
their columns. What an installer does stands in a few of them (phageo, 2026-10-17: build
it, part 1 of 2): ``File`` / ``Component`` / ``Media`` (what it installs, from which
cabinet), ``Binary`` (programs and scripts it carries for its own use), ``CustomAction``
and ``InstallExecuteSequence`` (what it runs, and when), ``Property``, and the streams
(``_Streams``) - an embedded cabinet among them.

Part 1 reads the database and says what the package holds - names and sizes only
(:func:`inventory`). Part 2 (phageo, 2026-10-19; :class:`Contents`) hands on what it carries,
to be scanned like the members of an archive: the files of its cabinets - embedded or
beside the package - under the names it installs them as; the programs, libraries and
scripts of its ``Binary`` table; the scripts its custom actions hold; and the command lines
its custom actions start, as one batch text for the shell chain. A cabinet is decompressed
by the scanner's own reader (stored, MSZIP - deflate, ``zlib`` - or LZX - the own decoder
``lzx``, since 2026-10-19); a Quantum cabinet is not decoded, and that is said.

Data only, standard library only, every loop bounded, every member held in memory - nothing
is written to disk, nothing is run; a damaged database raises :class:`MsiError`, a limit is
said with ``limits.hit`` (it reaches ``ARC-002``).
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/unpack/msi.py")

import re
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Dict, Iterator, List, Optional, Tuple, Union

from . import cab, cfb, limits, sniff, spool

TABLE_MARK = "䡀"                      # a stream name that begins with it is a table
_MAX_STRINGS = 1 << 20                     # strings in the pool
_MAX_POOL = 64 << 20                       # bytes of _StringPool / _StringData / one table stream
_MAX_TABLES = 4096
_MAX_COLUMNS = 64                          # (Windows Installer allows 32)
_MAX_ROWS = 1 << 20                        # rows of one table
_MAX_SHOWN = 400                           # lines of one kind in the inventory

# column types (_Columns.Type)
_STRING, _NULLABLE, _KEY, _TEMPORARY, _VALID = 0x0800, 0x1000, 0x2000, 0x4000, 0x0100
# the columns of _Columns itself: Table (text), Number, Name (text), Type
_COLUMNS = (("Table", _STRING | _KEY | _VALID | 64), ("Number", _KEY | _VALID | 2),
            ("Name", _STRING | _VALID | 64), ("Type", _VALID | 2))   # (a text of size 0 would be OBJECT)
TRANSFORM = "Windows Installer transform"
_KINDS = {                                 # the root's class: what the database is
    b"\x84\x10\x0c\x00": "Windows Installer package", b"\x86\x10\x0c\x00": "Windows Installer patch",
    b"\x82\x10\x0c\x00": TRANSFORM,
}
# custom actions: the low three bits say what runs, the next three where it comes from
_ACTION_RUNS = {1: "a library (DLL)", 2: "a program (EXE)", 3: "a message text", 5: "a JScript",
                6: "a VBScript", 7: "a nested install"}
_ACTION_FROM = {0x00: "the Binary table", 0x10: "an installed file", 0x20: "a text / a folder",
                0x30: "a property"}
_ACTION_SETS = {35: "sets a folder", 51: "sets a property", 19: "shows an error and stops"}


class MsiError(ValueError):
    """Not a Windows Installer database, or one that is damaged."""


def decode_name(name: str) -> str:
    """A stream name as Windows Installer wrote it, unpacked: characters 0x3800-0x47FF
    hold two characters of the set 0-9 A-Z a-z . _, 0x4800-0x483F one."""
    def char(x: int) -> str:
        return chr(x + 48 if x < 10 else x + 55 if x < 36 else x + 61 if x < 62 else (46 if x == 62 else 95))
    out = []
    for c in name:
        n = ord(c)
        if 0x3800 <= n < 0x4800:
            n -= 0x3800
            out.append(char(n & 0x3F) + char(n >> 6))
        elif 0x4800 <= n < 0x4840:
            out.append(char(n - 0x4800))
        else:
            out.append(c)
    return "".join(out)


@dataclass
class Column:
    name: str
    type: int
    number: int

    @property
    def stored(self) -> bool:
        return not self.type & _TEMPORARY

    @property
    def is_text(self) -> bool:
        return bool(self.type & _STRING)

    @property
    def is_stream(self) -> bool:            # an OBJECT column: the data is a stream of its own
        return (self.type & ~_NULLABLE) == (_STRING | _VALID)

    @property
    def is_key(self) -> bool:
        return bool(self.type & _KEY)

    def width(self, strref: int) -> int:
        if self.is_stream:
            return 2
        if self.is_text:
            return strref
        return 2 if (self.type & 0xFF) <= 2 else 4


@dataclass
class Stream:
    name: str                               # unpacked; storage names in front, "/" between
    size: int
    entry: cfb.Entry = field(repr=False)


class Database:
    """The tables of an MSI and its other streams.

    ``tables``: name -> columns (stored order); :meth:`rows` reads one table.
    ``streams``: unpacked name -> :class:`Stream`, every stream that is no table, the
    streams of substorages too ("<storage>/<name>")."""

    def __init__(self, data: Union[bytes, bytearray, memoryview, BinaryIO], size: Optional[int] = None) -> None:
        try:
            self.file = cfb.CompoundFile(data, size)
        except cfb.CfbError as exc:
            raise MsiError(str(exc))
        self.kind = _KINDS.get(self.file.root.clsid[:4], "")
        self._tables: Dict[str, cfb.Entry] = {}
        self.streams: Dict[str, Stream] = {}
        self.storages: List[str] = []
        for entry in self.file.entries[1:]:
            path = self.file.path(self.file.entry(entry.parent)) if entry.parent > 0 else ""
            name = decode_name(entry.name)
            if entry.kind == cfb.STORAGE:
                self.storages.append((path + "/" if path else "") + name)
            elif not path and name.startswith(TABLE_MARK):
                self._tables[name[1:]] = entry
            else:
                full = (path + "/" if path else "") + name
                self.streams[full] = Stream(full, entry.size, entry)
        self.strings: List[Optional[str]] = [None]
        self.strref = 2
        self.codepage = 0
        self.tables: Dict[str, List[Column]] = {}
        # a transform holds the differences to another database, table by table - in a form
        # of their own, so its streams are named, not read as tables
        self.changes = sorted((name, entry.size) for name, entry in self._tables.items()
                              if name not in ("_StringPool", "_StringData")) if self.kind == TRANSFORM else []
        if "_StringPool" in self._tables or "_StringData" in self._tables:
            self._load_strings()
            if self.kind != TRANSFORM:
                self._load_tables()

    # -- the string pool ------------------------------------------------------------------
    def _raw(self, name: str) -> bytes:
        entry = self._tables.get(name)
        if entry is None:
            return b""
        if entry.size > _MAX_POOL:
            raise MsiError(limits.hit("msi", "a table or text stream of more than %d bytes: not read" % _MAX_POOL))
        try:
            return self.file.stream(entry)
        except cfb.CfbError as exc:
            raise MsiError("%s: %s" % (name, exc))

    def _load_strings(self) -> None:
        pool, data = self._raw("_StringPool"), self._raw("_StringData")
        if len(pool) % 4:
            raise MsiError("the string pool is damaged")
        words = struct.unpack("<%dH" % (len(pool) // 2), pool)
        if len(words) >= 2:
            self.codepage = words[0] | ((words[1] & 0x7FFF) << 16)
            self.strref = 3 if words[1] & 0x8000 else 2
        encoding = "utf-8" if self.codepage == 65001 else "cp%d" % self.codepage if self.codepage else "cp1252"
        try:
            "".encode(encoding)
        except LookupError:
            encoding = "cp1252"
        at, i, count = 0, 1, len(words) // 2
        if count > _MAX_STRINGS:
            raise MsiError(limits.hit("msi", "more than %d texts in the string pool" % _MAX_STRINGS))
        while i < count:
            length, refs = words[2 * i], words[2 * i + 1]
            if length == 0 and refs == 0:               # an empty entry still has its number
                self.strings.append(None)
                i += 1
                continue
            if length == 0:                              # a text over 64 KB: two entries
                if i + 1 >= count:
                    raise MsiError("the string pool is damaged")
                length = (refs << 16) | words[2 * i + 2]
                i += 2
            else:
                i += 1
            if at + length > len(data):
                raise MsiError("the string pool names more text than it holds")
            self.strings.append(data[at:at + length].decode(encoding, "replace"))
            at += length

    def text(self, number: int) -> Optional[str]:
        if 0 < number < len(self.strings):
            return self.strings[number]
        if number:
            raise MsiError("a text number outside the string pool")
        return None

    # -- tables -----------------------------------------------------------------------------
    def _load_tables(self) -> None:
        names = self._raw("_Tables")
        if len(names) % self.strref:
            raise MsiError("the list of tables is damaged")
        if len(names) // self.strref > _MAX_TABLES:
            raise MsiError(limits.hit("msi", "more than %d tables" % _MAX_TABLES))
        listed = [self.text(int.from_bytes(names[k:k + self.strref], "little"))
                  for k in range(0, len(names), self.strref)]
        columns = [Column(name, kind, k + 1) for k, (name, kind) in enumerate(_COLUMNS)]
        found: Dict[str, List[Column]] = {}
        for row in self._read("_Columns", columns):
            table, number, name, kind = row["Table"], row["Number"], row["Name"], row["Type"]
            if table is None or number is None or name is None or kind is None:
                raise MsiError("a column without its table, number, name or type")
            found.setdefault(table, []).append(Column(name, kind & 0xFFFF, number))
        for table in listed:
            if table is None:
                raise MsiError("a table without a name")
            cols = sorted(found.get(table, ()), key=lambda c: c.number)
            if len(cols) > _MAX_COLUMNS:
                raise MsiError(limits.hit("msi", "table %s has more than %d columns" % (table, _MAX_COLUMNS)))
            if not cols or [c.number for c in cols] != list(range(1, len(cols) + 1)):
                raise MsiError("the columns of table %s are damaged" % table)
            self.tables[table] = cols

    def _read(self, table: str, columns: List[Column]) -> List[Dict[str, object]]:
        raw = self._raw(table)
        stored = [c for c in columns if c.stored]
        width = sum(c.width(self.strref) for c in stored)
        if not raw:
            return []
        if not width or len(raw) % width:
            raise MsiError("table %s is damaged (its size does not fit its columns)" % table)
        count = len(raw) // width
        if count > _MAX_ROWS:
            limits.hit("msi", "table %s has more than %d rows: the rest was not read" % (table, _MAX_ROWS))
        shown = min(count, _MAX_ROWS)
        rows: List[Dict[str, object]] = [{} for _ in range(shown)]
        at = 0
        for column in stored:                          # column by column
            size = column.width(self.strref)
            for i in range(shown):
                value = int.from_bytes(raw[at + i * size:at + (i + 1) * size], "little")
                if column.is_stream:
                    rows[i][column.name] = None             # (named below, from the keys)
                elif column.is_text:
                    rows[i][column.name] = self.text(value)
                elif not value:
                    rows[i][column.name] = None
                elif size == 2:
                    rows[i][column.name] = value - 0x8000
                else:
                    rows[i][column.name] = value - 0x80000000
            at += size * count
        for column in columns:
            if not column.stored:
                for row in rows:
                    row[column.name] = None
        streams = [c for c in columns if c.is_stream]
        if streams:
            keys = [c.name for c in columns if c.is_key]
            for row in rows:
                name = ".".join([table] + ["" if row[k] is None else str(row[k]) for k in keys])
                for column in streams:
                    row[column.name] = name if name in self.streams else None
        return rows

    def rows(self, table: str) -> List[Dict[str, object]]:
        """The rows of ``table`` ([] when the package has no such table): column name ->
        text, number, None for an empty value; an OBJECT column gives the name of its
        stream (a key of ``streams``), or None when there is none."""
        columns = self.tables.get(table)
        return self._read(table, columns) if columns else []

    def table_rows(self, table: str) -> int:
        """How many rows ``table`` has, without reading them."""
        columns = self.tables.get(table) or []
        width = sum(c.width(self.strref) for c in columns if c.stored)
        entry = self._tables.get(table)
        return entry.size // width if entry is not None and width else 0


# -- what a package holds ----------------------------------------------------------------------
@dataclass
class Package:
    kind: str
    tables: List[Tuple[str, int]]                    # (name, rows)
    files: List[Tuple[str, int]]                     # (installed name, declared size)
    cabinets: List[Tuple[str, str, int]]             # (name, "embedded" / "beside the package", size)
    binaries: List[Tuple[str, int]]                  # (Binary row, size of its stream)
    actions: List[Tuple[str, int, str, str, int]]    # (name, type, what it is, source name, length of its target)
    scheduled: List[str]                             # custom actions in InstallExecuteSequence
    properties: List[str]                            # property names
    streams: List[Tuple[str, int]]                   # every other stream
    storages: List[str]
    changes: List[Tuple[str, int]] = field(default_factory=list)   # a transform: (table, bytes of changes)
    problem: str = ""                                # "" = read to its end


def action_kind(kind: int) -> str:
    """What a custom action's type number says, in words."""
    base = kind & 0x3F
    if base in _ACTION_SETS:
        return _ACTION_SETS[base]
    runs, source = base & 0x07, base & 0x30
    if runs in _ACTION_RUNS:
        if runs in (5, 6) and source == 0x20:
            return "%s written in the table" % _ACTION_RUNS[runs]
        if runs == 2 and source == 0x20:
            return "a program started with a command line"
        return "%s from %s" % (_ACTION_RUNS[runs], _ACTION_FROM[source])
    return "an action of an unknown kind"


def _long_name(name: object) -> str:
    text = "" if name is None else str(name)
    return text.split("|", 1)[1] if "|" in text else text


def package(data: Union[bytes, bytearray, memoryview, BinaryIO], size: Optional[int] = None) -> Package:
    """What the MSI ``data`` holds. Raises :class:`MsiError` when its directory or its
    database cannot be read; a table that cannot be read leaves ``problem`` set."""
    db = Database(data, size)
    if not db.kind and not db.tables and not db.changes:
        raise MsiError("a compound file that is no Windows Installer database")
    out = Package(db.kind or "Windows Installer database", [], [], [], [], [], [], [], [], list(db.storages),
                  list(db.changes))
    problems: List[str] = []

    def rows(table: str) -> List[Dict[str, object]]:
        try:
            return db.rows(table)
        except MsiError as exc:
            problems.append(str(exc))
            return []

    out.tables = [(name, db.table_rows(name)) for name in db.tables]
    out.files = [(_long_name(r.get("FileName")), int(r.get("FileSize") or 0)) for r in rows("File")]
    used = set()
    for r in rows("Media"):
        cabinet = r.get("Cabinet")
        if not cabinet:
            continue
        cabinet = str(cabinet)
        if cabinet.startswith("#"):
            stream = db.streams.get(cabinet[1:])
            used.add(cabinet[1:])
            out.cabinets.append((cabinet[1:], "embedded" if stream else "embedded, missing",
                                 stream.size if stream else 0))
        else:
            out.cabinets.append((cabinet, "beside the package", 0))
    for r in rows("Binary"):
        stream = r.get("Data")
        used.add(str(stream))
        out.binaries.append((str(r.get("Name")), db.streams[stream].size if stream else 0))
    for r in rows("CustomAction"):
        kind = int(r.get("Type") or 0)
        target = r.get("Target")
        out.actions.append((str(r.get("Action")), kind, action_kind(kind), "" if r.get("Source") is None
                            else str(r.get("Source")), len(str(target)) if target is not None else 0))
    actions = {name for name, *_rest in out.actions}
    out.scheduled = [str(r.get("Action")) for r in sorted(rows("InstallExecuteSequence"),
                                                           key=lambda r: (r.get("Sequence") is None, r.get("Sequence") or 0))
                     if r.get("Action") in actions]
    out.properties = [str(r.get("Property")) for r in rows("Property")]
    out.streams = [(s.name, s.size) for s in db.streams.values() if s.name not in used]
    out.problem = "; ".join(dict.fromkeys(problems))
    return out


def summary(pkg: Package) -> str:
    """One line: what the package holds, in counts."""
    if pkg.kind == TRANSFORM:
        return ("changes to %d tables of another package (not read), %d streams"
                % (len(pkg.changes), len(pkg.streams)))
    return ("%d tables, %d installed files (%d bytes declared), %d cabinets (%d embedded), %d Binary streams, "
            "%d custom actions (%d scheduled), %d other streams"
            % (len(pkg.tables), len(pkg.files), sum(s for _n, s in pkg.files), len(pkg.cabinets),
               sum(1 for _n, where, _s in pkg.cabinets if where == "embedded"), len(pkg.binaries),
               len(pkg.actions), len(pkg.scheduled), len(pkg.streams)))


def inventory(pkg: Package) -> List[str]:
    """What the package holds, line by line - names and sizes only: no property value, no
    custom action's command line or script, nothing of a stream's content."""
    out = ["%s: %s" % (pkg.kind, summary(pkg))]
    if pkg.problem:
        out.append("could not be read: %s" % pkg.problem)

    def some(label: str, items: List[str]) -> None:
        for item in items[:_MAX_SHOWN]:
            out.append("%s %s" % (label, item))
        if len(items) > _MAX_SHOWN:
            out.append("%s ... and %d more" % (label, len(items) - _MAX_SHOWN))

    some("table", ["%s | %d rows" % (shown(name), count) for name, count in pkg.tables])
    some("changed table", ["%s | %d bytes" % (shown(name), size) for name, size in pkg.changes])
    some("cabinet", ["%s | %s | %d bytes" % (shown(name), where, size) for name, where, size in pkg.cabinets])
    some("binary", ["%s | %d bytes" % (shown(name), size) for name, size in pkg.binaries])
    some("custom action", ["%s | type %d: %s | source %s | target %d characters%s"
                           % (shown(name), kind, what, shown(source) or "-", target,
                              " | scheduled" if name in pkg.scheduled else "")
                           for name, kind, what, source, target in pkg.actions])
    some("file", ["%s | %d bytes" % (shown(name), size) for name, size in pkg.files])
    some("stream", ["%s | %d bytes" % (shown(name), size) for name, size in pkg.streams])
    some("storage", [shown(name) for name in pkg.storages])
    if pkg.properties:
        out.append("properties: %d (%s)" % (len(pkg.properties), ", ".join(shown(p) for p in pkg.properties[:40])
                                            + (" ..." if len(pkg.properties) > 40 else "")))
    return out


def shown(name: str) -> str:
    """A name as it is printed: control characters (the mark in front of
    ``SummaryInformation``, a line break planted in a name) written out, at most 120
    characters."""
    text = "".join(c if " " <= c != "\x7f" else "\\x%02x" % ord(c) for c in name)
    return text if len(text) <= 120 else text[:117] + "..."


# -- part 2: what the package carries and starts (phageo, 2026-10-19) -------------------------------
MAX_MEMBER = 256 << 20                     # one member, held in memory
MAX_UNPACKED = 4 << 30                     # unpacked from one package
_MAX_FOLDERS_DEEP = 32                     # folders inside folders (Directory)
_MAX_TEXT = 32768                          # a value or command line once its [names] are put in
_MAX_ROUNDS = 8                            # [names] inside values put in, round after round
_MAX_COMMANDS = 2000                       # command lines of custom actions
_MAX_NAME = 120                            # one part of a member's name
COMMANDS = "[custom action command lines].cmd"   # the command lines, one batch text (the shell chain)
SCRIPTS = "[custom action]"                # a script a custom action holds: "[custom action]/<action>.vbs"
BINARY = "[Binary]"                        # a stream of the Binary table: "[Binary]/<name>.dll"
STREAM = "[stream]"                        # any other stream that is not a table
MERGE_CABINET = "MergeModule.CABinet"      # a merge module's one cabinet (it has no Media table)
SIGNATURE = "\x05DigitalSignature"         # the stream of the package's Authenticode signature
_RUNS_SCRIPT = {5: ".js", 6: ".vbs"}       # custom action types: a JScript / a VBScript
_OWN_STREAMS = ("\x05SummaryInformation", "\x05DocumentSummaryInformation", "\x05DigitalSignature",
                "\x05MsiDigitalSignatureEx")
# Windows Installer's own folder properties, as the command lines of a custom action meet them
_STANDARD_FOLDERS = {
    "TARGETDIR": "%SystemDrive%\\", "ROOTDRIVE": "%SystemDrive%\\", "WindowsFolder": "%WINDIR%\\",
    "SystemFolder": "%WINDIR%\\System32\\", "System64Folder": "%WINDIR%\\System32\\",
    "System16Folder": "%WINDIR%\\System\\", "WindowsVolume": "%SystemDrive%\\", "TempFolder": "%TEMP%\\",
    "ProgramFilesFolder": "%ProgramFiles%\\", "ProgramFiles64Folder": "%ProgramFiles%\\",
    "CommonFilesFolder": "%CommonProgramFiles%\\", "CommonFiles64Folder": "%CommonProgramFiles%\\",
    "AppDataFolder": "%APPDATA%\\", "LocalAppDataFolder": "%LOCALAPPDATA%\\",
    "CommonAppDataFolder": "%ProgramData%\\", "PersonalFolder": "%USERPROFILE%\\Documents\\",
    "DesktopFolder": "%USERPROFILE%\\Desktop\\", "StartupFolder": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "StartMenuFolder": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\",
    "ProgramMenuFolder": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\",
    "FontsFolder": "%WINDIR%\\Fonts\\",
}
_REF = re.compile(r"\[([^\[\]]{1,200})\]")
# a command line that fetches or decodes something: never "the package's own start" (phageo, 2026-10-19)
FETCH_OR_DECODE = re.compile(
    _IND[0])
# where a member came from (Contents.origin)
EMBEDDED, BESIDE, PACKAGE = "embedded cabinet", "cabinet beside the package", "package"
_ENDING = re.compile(r"\.[A-Za-z0-9]{1,8}\Z")


def _program(line: str) -> str:
    """The program a command line starts: its first word, or its first quoted text."""
    line = line.strip()
    if line.startswith('"'):
        end = line.find('"', 1)
        return line[1:end] if end > 0 else line[1:]
    return line.split(None, 1)[0] if line else ""


def _part(name: str) -> str:
    """One part of a member's name: no folder marks, no control characters, not ".." ."""
    text = "".join(c for c in str(name) if c >= " " and c not in "\\/:*?\"<>|!").strip(" .")
    return (text or "_")[:_MAX_NAME]


class Contents:
    """What a package carries and starts, handed on as members (phageo, 2026-10-19: part 2).

    :meth:`members` gives ``(name, data)`` one at a time - the caller scans each like a
    member of an archive. Names: an installed file by the folders the ``Directory`` table
    gives it (``<folder>/<file>``); ``[Binary]/<name>`` with the ending its custom action
    names (a DLL, a program, a JScript, a VBScript) or its content says;
    ``[custom action]/<action>.vbs`` / ``.js`` for a script written in a custom action or a
    property; ``[stream]/<name>`` for any other stream; :data:`COMMANDS` for the command lines.

    ``beside(name)``: opens a cabinet that lies beside the package (None: not found, or the
    package was not read from a folder). ``problems``: what could not be read, each a
    sentence for the "could not be read" note; ``read``: what was read (names and counts,
    for the inventory)."""

    def __init__(self, db: Database, beside: Optional[Callable[[str], Optional[BinaryIO]]] = None) -> None:
        self.db, self.beside = db, beside
        self.problems: List[str] = []
        self.read: List[str] = []
        self.over: List[str] = []                 # members larger than MAX_MEMBER: not read
        self.unpacked = 0
        # where the member just handed on came from: (EMBEDDED / BESIDE / PACKAGE, the path of a
        # cabinet beside the package or "")
        self.origin: Tuple[str, str] = (PACKAGE, "")
        # the lines of COMMANDS that start a file of this package and fetch or decode nothing
        self.own_lines: List[int] = []
        self.properties: Dict[str, str] = {}
        for row in self._rows("Property"):
            if row.get("Property") is not None:
                self.properties[str(row["Property"])] = "" if row.get("Value") is None else str(row["Value"])
        self.names, self.paths = self._folders()  # Directory -> member path / path in a command line
        components = {str(r["Component"]): str(r.get("Directory_") or "") for r in self._rows("Component")
                      if r.get("Component") is not None}
        self.component_paths = {c: self.paths.get(d, "") for c, d in components.items()}
        self.files: Dict[str, str] = {}           # File key -> member name
        self.file_paths: Dict[str, str] = {}      # File key -> its path in a command line
        used = set()
        for row in self._rows("File"):
            key = row.get("File")
            if key is None:
                continue
            key, folder = str(key), components.get(str(row.get("Component_") or ""), "")
            leaf = _part(_long_name(row.get("FileName")) or key)
            where = self.names.get(folder, "")
            name = "%s/%s" % (where, leaf) if where else leaf
            if name.lower() in used:
                name = "%s/%s/%s" % (where, _part(key), leaf) if where else "%s/%s" % (_part(key), leaf)
            used.add(name.lower())
            self.files[key] = name
            self.file_paths[key] = self.paths.get(folder, "") + leaf
        self.actions = self._rows("CustomAction")
        # what custom actions of type 51 set while installing (a later one wins, as it runs later)
        self.sets: Dict[str, str] = {}
        for row in self._ordered():
            if int(row.get("Type") or 0) & 0x3F == 51 and row.get("Source") is not None:
                self.sets[str(row["Source"])] = "" if row.get("Target") is None else str(row["Target"])

    # -- the tables ---------------------------------------------------------------------------
    def _rows(self, table: str) -> List[Dict[str, object]]:
        try:
            return self.db.rows(table)
        except MsiError as exc:
            self.problems.append("table %s could not be read (%s)" % (table, exc))
            return []

    def _ordered(self) -> List[Dict[str, object]]:
        """The custom actions in the order they run: those of the sequence tables by their
        number, then the others (started from a dialog, or by another action) in table order."""
        order: Dict[str, float] = {}
        for table in ("InstallUISequence", "InstallExecuteSequence"):
            if table in self.db.tables:
                for row in self._rows(table):
                    if row.get("Action") is not None and row.get("Sequence") is not None:
                        order.setdefault(str(row["Action"]), float(row["Sequence"]))
        rows = list(self.actions)
        return sorted(rows, key=lambda r: (str(r.get("Action")) not in order, order.get(str(r.get("Action")), 0.0)))

    def _folders(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Directory -> its path as a member name ("Fixture Game/data"), and as a command line
        meets it (``%ProgramFiles%\\Fixture Game\\data\\`` - Windows Installer's own folders by
        their usual place). Bounded: ``_MAX_FOLDERS_DEEP`` folders, a loop stops the walk."""
        parent: Dict[str, str] = {}
        own: Dict[str, str] = {}
        for row in self._rows("Directory"):
            if row.get("Directory") is None:
                continue
            key = str(row["Directory"])
            up = row.get("Directory_Parent")
            parent[key] = "" if up in (None, "") or str(up) == key else str(up)
            target = str(row.get("DefaultDir") or "").split(":", 1)[0]
            name = _long_name(target)
            own[key] = "" if name in ("", ".", "SourceDir") or key == "TARGETDIR" else _part(name)
        names: Dict[str, str] = {}
        paths: Dict[str, str] = {}
        for key in own:
            chain, seen, at = [], set(), key
            while at and at not in seen and len(chain) < _MAX_FOLDERS_DEEP:
                seen.add(at)
                chain.append(at)
                if at in _STANDARD_FOLDERS:
                    break
                at = parent.get(at, "")
            names[key] = "/".join(own[k] for k in reversed(chain) if own.get(k))
            base = _STANDARD_FOLDERS.get(chain[-1], "") if chain else ""
            below = [own[k] for k in reversed(chain) if own.get(k) and k not in _STANDARD_FOLDERS]
            paths[key] = base + "".join(part + "\\" for part in below)
        return names, paths

    def format(self, text: str) -> str:
        """``text`` with the ``[names]`` of Windows Installer put in where the package says
        what they are: a property (the Property table, or a custom action that sets it), a
        folder (``[INSTALLDIR]``), an installed file (``[#key]``), a component's folder
        (``[$key]``), an environment variable (``[%NAME]`` -> ``%NAME%``); an escape
        (``[\\[]``). What is set only while installing stays as it was written. Bounded."""
        escaped = {"[\\[]": "\x01", "[\\]]": "\x02", "[~]": " "}
        for key, value in escaped.items():
            text = text.replace(key, value)

        def put(match: "re.Match") -> str:
            name = match.group(1)
            if name[:1] in "#!" and name[1:] in self.file_paths:
                return self.file_paths[name[1:]]
            if name[:1] == "$" and name[1:] in self.component_paths:
                return self.component_paths[name[1:]]
            if name[:1] == "%" and len(name) > 1:
                return "%" + name[1:] + "%"
            if name[:1] == "\\" and len(name) == 2:
                return name[1]
            for known in (self.sets, self.properties):
                if name in known:
                    return known[name]
            if name in self.paths:
                return self.paths[name]
            if name in _STANDARD_FOLDERS:
                return _STANDARD_FOLDERS[name]
            return "\x01" + name + "\x02"            # (not known: stays, and is not looked at again)

        for _ in range(_MAX_ROUNDS):
            done = _REF.sub(put, text)
            if len(done) > _MAX_TEXT:
                limits.hit("msi", "a value of more than %d characters once its [names] were put in: the rest "
                                  "was not read" % _MAX_TEXT)
                done = done[:_MAX_TEXT]
            if done == text:
                break
            text = done
        return text.replace("\x01", "[").replace("\x02", "]")

    def value(self, name: str) -> Optional[str]:
        """What the property ``name`` holds, as far as the package says it (None: nothing)."""
        for known in (self.sets, self.properties):
            if name in known:
                return self.format(known[name])
        return None

    # -- the members ------------------------------------------------------------------------------
    def members(self, want: Callable[[str, int], bool]) -> Iterator[Tuple[str, bytes]]:
        """Every member ``want(name, size)`` accepts, one at a time, each in memory."""
        endings, file_scripts, scripts, commands = self._actions()
        programs = {path.lower() for path in self.file_paths.values()}
        programs.update(("%s%s" % (_part(name), "" if _ENDING.search(name) else ".exe")).lower()
                        for name, ending in endings.items() if ending == ".exe")
        self.own_lines = [number for number, line in enumerate(commands, 1)
                          if _program(line).lower() in programs and not FETCH_OR_DECODE.search(line)]
        self.origin = (PACKAGE, "")
        if commands:
            text = "\r\n".join(commands).encode("utf-8")
            if want(COMMANDS, len(text)):
                yield COMMANDS, text
        for name, text in scripts:
            data = text.encode("utf-8")
            if want(name, len(data)):
                yield name, data
        used = set()
        for row in self._rows("Binary"):
            stream = row.get("Data")
            if stream is None or row.get("Name") is None:
                continue
            used.add(str(stream))
            yield from self._stream("%s/%s" % (BINARY, _part(str(row["Name"]))), self.db.streams[str(stream)],
                                    endings.get(str(row["Name"]), ""), want)
        cabinets = [str(r["Cabinet"]) for r in self._rows("Media") if r.get("Cabinet")]
        if not cabinets and MERGE_CABINET in self.db.streams:
            cabinets = ["#" + MERGE_CABINET]
        for cabinet in dict.fromkeys(cabinets):
            if cabinet.startswith("#"):
                used.add(cabinet[1:])
            yield from self._cabinet(cabinet, file_scripts, want)
        self.origin = (PACKAGE, "")
        for stream in list(self.db.streams.values()):
            if stream.name in used or stream.name in _OWN_STREAMS:
                continue
            yield from self._stream("%s/%s" % (STREAM, _part(stream.name)), stream, "", want)
        if self.db.storages:
            self.problems.append("%d storage(s) inside the package (embedded transforms or packages: %s) were not "
                                 "read" % (len(self.db.storages), ", ".join(shown(s) for s in self.db.storages[:5])))
        if self.over:
            self.problems.append("%d member(s) larger than %s were not read (the package's members are read in "
                                 "memory only): %s" % (len(self.over), "%d MB" % (MAX_MEMBER >> 20) if MAX_MEMBER >> 20
                                                       else "%d bytes" % MAX_MEMBER, ", ".join(self.over[:5])))

    def _actions(self):
        """What the custom actions say: the ending each Binary stream runs as, the installed
        files that are scripts, the scripts written in actions or properties, the command
        lines (in the order the actions run)."""
        endings: Dict[str, str] = {}
        file_scripts: Dict[str, Tuple[str, str]] = {}
        scripts: List[Tuple[str, str]] = []
        commands: List[str] = []
        names = {str(r.get("Action")) for r in self.actions}
        seen_scripts = set()
        for row in self._ordered():
            action = str(row.get("Action"))
            kind = int(row.get("Type") or 0) & 0x3F
            runs, source = kind & 0x07, kind & 0x30
            src = "" if row.get("Source") is None else str(row.get("Source"))
            target = "" if row.get("Target") is None else str(row.get("Target"))
            if kind in _ACTION_SETS:
                # what a deferred action is handed (CustomActionData: a property of its own name),
                # and WiX's quiet-start actions (a property ...CmdLine): a command line
                if kind == 51 and (src in names or src.lower().endswith("cmdline")) and target.strip():
                    commands.append(self.format(target))
                continue
            if runs in _RUNS_SCRIPT:
                ending = _RUNS_SCRIPT[runs]
                if source == 0x00:
                    endings.setdefault(src, ending)
                elif source == 0x10:
                    file_scripts.setdefault(src, (action, ending))
                else:
                    text = target if source == 0x20 else self.value(src)
                    name = "%s/%s%s" % (SCRIPTS, _part(action), ending)
                    if text is None:
                        self.problems.append("custom action %s runs a script held in property %s, which is set "
                                             "only while installing: not read" % (shown(action), shown(src)))
                    elif name.lower() not in seen_scripts:
                        seen_scripts.add(name.lower())
                        scripts.append((name, text))
            elif runs == 2:
                args = self.format(target)
                if source == 0x00:
                    endings.setdefault(src, ".exe")
                    commands.append(('"%s%s" %s' % (_part(src), "" if _ENDING.search(src) else ".exe", args)).strip())
                elif source == 0x10:
                    commands.append(('"%s" %s' % (self.file_paths.get(src, src), args)).strip())
                elif source == 0x20:
                    commands.append(args)
                else:
                    program = self.value(src)
                    commands.append(('"%s" %s' % (program if program is not None else "[%s]" % src, args)).strip())
            elif runs == 1 and source == 0x00:
                endings.setdefault(src, ".dll")
        commands = [line.replace("\r", " ").replace("\n", " ") for line in commands if line.strip()]
        if len(commands) > _MAX_COMMANDS:
            limits.hit("msi", "more than %d command lines of custom actions: the rest was not read" % _MAX_COMMANDS)
            commands = commands[:_MAX_COMMANDS]
        return endings, file_scripts, scripts, commands

    def _stream(self, name: str, stream: Stream, ending: str, want) -> Iterator[Tuple[str, bytes]]:
        """One stream of the package as a member, named by the ending its custom action runs
        it as, else by what its content is (a program, an archive ...)."""
        if stream.size > MAX_MEMBER:
            self.over.append(shown(name))
            return
        try:
            data = self.db.file.stream(stream.entry, MAX_MEMBER)
        except cfb.CfbError as exc:
            self.problems.append("stream %s could not be read (%s)" % (shown(name), exc))
            return
        if ending and not name.lower().endswith(ending):
            name += ending
        elif not ending and (data[:2] == b"MZ" or not _ENDING.search(name)):
            found = sniff.extension(data)
            if found and not name.lower().endswith(found):
                name += found
        if want(name, len(data)):
            yield name, data

    def _cabinet(self, cabinet: str, file_scripts, want) -> Iterator[Tuple[str, bytes]]:
        """The files of one cabinet - embedded ("#name": a stream of the package) or beside the
        package - under the names the package installs them as. Stored, MSZIP and (since
        2026-10-19, the own decoder ``lzx``) LZX folders are read; a Quantum folder is said
        (``problems``), never decoded."""
        embedded = cabinet.startswith("#")
        label = shown(cabinet[1:] if embedded else cabinet)
        if embedded:
            stream = self.db.streams.get(cabinet[1:])
            if stream is None:
                self.problems.append("the embedded cabinet %s is missing" % label)
                return
            opener = lambda: self.db.file.open(stream.entry)
        else:
            source = self.beside(cabinet) if self.beside is not None else None
            if source is None:
                self.problems.append("the cabinet %s that should lie beside the package %s" % (
                    label, "was not found" if self.beside is not None else
                    "could not be reached (the package was not read from a folder on disk)"))
                return
            opener = lambda: source

        def wanted(key: str, size: int) -> bool:
            name = self._file_name(key, cabinet, file_scripts)
            if size > MAX_MEMBER:
                self.over.append(shown(name))
                return False
            if self.unpacked + size > MAX_UNPACKED:
                limits.hit("msi", "more than %d MB unpacked from one package: the rest was not read" % (MAX_UNPACKED >> 20))
                return False
            return want(name, size)

        count = 0
        try:
            with opener() as fh:
                self.origin = (EMBEDDED, "") if embedded else (BESIDE, str(getattr(fh, "name", "")))
                kinds = cab.methods(fh)
                unread = [k for k in dict.fromkeys(kinds) if k not in ("stored", "MSZIP", "LZX")]
                if unread:
                    self.problems.append("cabinet %s: its files are compressed with %s, which the scanner does not "
                                         "decode - they could not be read" % (label, " and ".join(unread)))
                said: List[str] = []
                try:
                    for key, data in cab.members(fh, wanted, memory=MAX_MEMBER, notes=said):
                        size = spool.size_of(data)
                        self.unpacked += size
                        count += 1
                        yield self._file_name(key, cabinet, file_scripts), data
                finally:
                    self.problems.extend("cabinet %s: %s" % (label, note) for note in said)
        except cab.NeedTool as exc:
            if not any(p.startswith("cabinet %s:" % label) for p in self.problems):
                self.problems.append("cabinet %s needs %s: its files could not be read" % (label, exc))
        except (cab.CabError, cfb.CfbError, spool.SpoolError, OSError, struct.error) as exc:
            self.problems.append("cabinet %s could not be read (%s)" % (label, exc))
        self.read.append("cabinet %s (%s): %d file(s) read" % (label, "embedded" if embedded else "beside the package",
                                                              count))

    def _file_name(self, key: str, cabinet: str, file_scripts) -> str:
        if key in file_scripts:                   # an installed file a custom action runs as a script
            action, ending = file_scripts[key]
            return "%s/%s%s" % (SCRIPTS, _part(action), ending)
        if key in self.files:
            return self.files[key]
        return "%s/%s" % (_part(cabinet.lstrip("#")), _part(key))
