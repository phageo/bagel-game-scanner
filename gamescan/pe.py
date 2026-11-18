"""Minimal PE (Portable Executable) parser - headers, sections, import table."""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/pe.py")

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from .entropy import shannon as entropy

_EXECUTE, _WRITE = 0x20000000, 0x80000000
_ENTROPY_SAMPLE = 2 * 1024 * 1024
# addresses are found by the section sizes the Windows loader uses (PEInfo.section_at; 2026-11-02,
# round-4 bug 1). A switch by phageo's gate rule: off if it drops a malicious verdict without an
# official-hash reason.
LOADER_SECTION_SIZES = True

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense", ".petite": "Petite",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".enigma1": "Enigma", ".enigma2": "Enigma", "pec2": "PECompact", ".pec": "PECompact",
    ".packed": "generic packer", ".rlpack": "RLPack", ".y0da": "yoda's Crypter",
    ".boom": "The Boomerang", ".svmp": "SafeEngine", ".neolit": "NeoLite",
}


@dataclass
class Section:
    name: str
    vsize: int
    vaddr: int
    raw_size: int
    raw_ptr: int
    flags: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.flags & _EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.flags & _WRITE)


@dataclass
class PEInfo:
    is_64: bool = False
    is_dll: bool = False
    is_dotnet: bool = False
    has_signature: bool = False
    has_import_dir: bool = False
    entry_point: int = 0
    sections: List[Section] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    import_names: Set[str] = field(default_factory=set)   # incl. A/W-less forms
    packer: str = ""
    packed: bool = False
    data_dirs: List[Tuple[int, int]] = field(default_factory=list)
    overlay_offset: int = 0                 # data appended after the last section
    overlay_size: int = 0
    export_name: str = ""                   # what the library calls itself (export directory)
    exports: Set[str] = field(default_factory=set)        # names it exports (bounded)
    machine: int = 0
    section_alignment: int = 0

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())

    def section_at(self, rva: int) -> Optional[Section]:
        """The section that holds a virtual address, as the Windows loader sees it: a section takes
        the room of its virtual size, rounded up to the section alignment (no virtual size: its size
        in the file). Bytes in the file past that are not mapped, so they cannot swallow the sections
        behind them (2026-11-02: a data section of 8 bytes in memory and 108 MB in the file held
        every later address, and the import table was read as garbage). An address no section maps
        that way is looked up by the larger of the two sizes, as before."""
        if LOADER_SECTION_SIZES:
            for s in self.sections:
                # (never past the larger size: this only takes away what the loader does not map)
                room = _aligned(s.vsize, self.section_alignment) if s.vsize else s.raw_size
                if s.vaddr <= rva < s.vaddr + min(room, max(s.vsize, s.raw_size)):
                    return s
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return s
        return None

    def offset(self, rva: int) -> int:
        """File offset of a virtual address (raises ValueError if unmapped)."""
        s = self.section_at(rva)
        if s is None:
            raise ValueError("unmapped RVA 0x%x" % rva)
        return rva - s.vaddr + s.raw_ptr


STRINGS_LIMIT = 250_000            # distinct texts given back by extract_strings


# (phase C0, phageo 2026-11-03) the same list without the two regexes: the bytes are mapped to classes once
# (printable / zero / other) and C-speed ``find`` visits only real runs - about 5x faster on game asset data,
# where these two regexes took 87 % of a large Unity game's scan. Off: the regexes, as before.
FAST_STRINGS = True
_STR_MAX = 400                                     # longest piece; a longer run is cut into pieces of this
_CLASS_ASCII = bytes(80 if 0x20 <= b <= 0x7E else 88 for b in range(256))                       # P / X
_CLASS_WIDE = bytes(80 if 0x20 <= b <= 0x7E else 90 if b == 0 else 88 for b in range(256))      # P / Z / X


def _strings_regex(data: bytes, min_len: int) -> List[str]:
    n = str(min_len).encode()
    found = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{" + n + rb",400}", data)]
    found += [s.decode("utf-16-le") for s in
              re.findall(rb"(?:[\x20-\x7e]\x00){" + n + rb",400}", data)]
    return found


def _strings_fast(data: bytes, min_len: int) -> List[str]:
    """Exactly what :func:`_strings_regex` gives: every maximal run cut into pieces of at most 400 (the
    regex's greedy ``{n,400}`` from the run's start), a last piece under ``min_len`` dropped; ASCII first,
    then UTF-16LE, each in order of place. UTF-16 pairs of the two byte alignments can never overlap (a
    pair's second byte is zero, which no pair begins with), so each run is found from its first pair."""
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)                         # (a memoryview: translate needs bytes)
    out: List[str] = []
    if min_len < 1:
        return _strings_regex(data, min_len)
    cls, size = data.translate(_CLASS_ASCII), len(data)
    seed, pos = b"P" * min_len, 0
    while True:
        start = cls.find(seed, pos)
        if start < 0:
            break
        end = cls.find(b"X", start)
        end = size if end < 0 else end
        while end - start >= min_len:
            step = min(_STR_MAX, end - start)
            out.append(data[start:start + step].decode("ascii"))
            start += step
        pos = end
    del cls                                        # (one class map at a time: one copy of the data)
    cls = data.translate(_CLASS_WIDE)
    seed, pos = b"PZ" * min_len, 0
    while True:
        hit = cls.find(seed, pos)
        if hit < 0:
            break
        start = hit
        while start - 2 >= pos and cls[start - 2:start] == b"PZ":
            start -= 2
        end = hit + 2 * min_len
        while cls[end:end + 2] == b"PZ":
            end += 2
        while (end - start) // 2 >= min_len:
            step = min(_STR_MAX, (end - start) // 2)
            out.append(data[start:start + 2 * step].decode("utf-16-le"))
            start += 2 * step
        pos = end
    return out


def extract_strings(data: bytes, min_len: int = 5, limit: int = STRINGS_LIMIT) -> List[str]:
    """Printable ASCII and UTF-16LE strings, de-duplicated, order preserved. Of more than
    ``limit`` distinct strings only the first ``limit`` are given back, and the scan says so:
    :func:`strings_cut` (until 2026-10-29 the cut was silent)."""
    found = _strings_fast(data, min_len) if FAST_STRINGS else _strings_regex(data, min_len)
    unique = list(dict.fromkeys(found))
    if len(unique) > limit:
        strings_cut(len(data), limit)
    return unique[:limit]


def strings_cut(size: int, limit: int = STRINGS_LIMIT) -> None:
    """The texts of ``size`` bytes were cut at ``limit``: the rules did not search the texts after
    them. Said as a limit of the file being scanned (``unpack/limits.py``), which becomes its
    "not read" note (``ARC-002``) - phageo, 2026-10-29."""
    # (here, not at the top: unpack's readers import this module; the module itself, not the
    # package - gamescan/cache.py counts what a module imports)
    from .unpack.limits import hit
    hit("strings", "more than %d distinct texts in %d bytes: the texts after the first %d "
                   "were not searched" % (limit, size, limit))


_MAX_PLACES = 64                   # places of one text looked at


def only_in_code(data: bytes, pe: PEInfo, text: str) -> bool:
    """Does ``text`` stand only inside executable sections of a program, in every place it is found
    (ASCII and UTF-16)? Not found, or found more often than is looked at: no."""
    places = 0
    for raw in (text.encode("ascii", "ignore"), text.encode("utf-16-le")):
        at = data.find(raw)
        while at >= 0:
            places += 1
            home = next((s for s in pe.sections if s.raw_ptr <= at < s.raw_ptr + s.raw_size), None)
            if places > _MAX_PLACES or home is None or not home.executable:
                return False
            at = data.find(raw, at + 1)
    return places > 0


# -- a domain-suffix table ----------------------------------------------------------------------
_DOMAIN = re.compile(r"[!*]?(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
# entries of the Public Suffix List's country part, there since its first versions: a list of
# sites has none of them, because nobody can own a name of that form
_SUFFIXES = frozenset({"co.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "ne.jp", "or.jp", "com.br"})
_MIN_SUFFIXES = 6
_MIN_TABLE = 1000                  # entries; a program's own list of a few sites is no table
_AROUND = 6                        # entries looked at on each side of a line ...
_MIN_NEAR = 9                      # ... and how many of them must be domains


def in_suffix_table(strings: List[str], line: str) -> bool:
    """Is ``line``, a text of a program, an entry of a built-in public-suffix table (Qt carries one to
    tell who may set a cookie)? It must be one bare name, no address, standing among such names in a
    table of at least ``_MIN_TABLE`` of them that holds the country suffixes of ``_SUFFIXES``."""
    if not _DOMAIN.match(line) or line not in strings:
        return False
    if len(_SUFFIXES.intersection(strings)) < _MIN_SUFFIXES:
        return False
    if sum(1 for text in strings if _DOMAIN.match(text)) < _MIN_TABLE:
        return False
    at = strings.index(line)
    near = strings[max(at - _AROUND, 0):at] + strings[at + 1:at + 1 + _AROUND]
    return sum(1 for text in near if _DOMAIN.match(text)) >= _MIN_NEAR


def parse_pe(data: bytes) -> Optional[PEInfo]:
    try:
        return _parse(data)
    except (struct.error, IndexError, ValueError):
        return None


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off, off + 256)
    return data[off:end if end != -1 else off + 256].decode("latin-1")


def _parse(data: bytes) -> Optional[PEInfo]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    _machine, nsec, _ts, _sym, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt = pe_off + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        is_64, dd = False, opt + 96
    elif magic == 0x20B:
        is_64, dd = True, opt + 112
    else:
        return None
    info = PEInfo(is_64=is_64, is_dll=bool(chars & 0x2000), machine=_machine,
                  entry_point=struct.unpack_from("<I", data, opt + 16)[0],
                  section_alignment=struct.unpack_from("<I", data, opt + 32)[0])
    ndirs = min(struct.unpack_from("<I", data, dd - 4)[0], 16)
    dirs = [struct.unpack_from("<II", data, dd + 8 * i) for i in range(ndirs)]

    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        name, vsize, vaddr, rsize, rptr, _, _, _, _, flags = struct.unpack_from(
            "<8sIIIIIIHHI", data, sec_off + 40 * i)
        sec = Section(name.rstrip(b"\0").decode("latin-1"), vsize, vaddr, rsize, rptr, flags)
        if rsize:
            sec.entropy = entropy(data[rptr:rptr + min(rsize, _ENTROPY_SAMPLE)])
        info.sections.append(sec)
    info.data_dirs = dirs
    end = max((s.raw_ptr + s.raw_size for s in info.sections), default=0)
    sig_off = dirs[4][0] if len(dirs) > 4 and dirs[4][1] else len(data)
    if 0 < end < min(len(data), sig_off):   # the signature blob is not an overlay
        info.overlay_offset, info.overlay_size = end, min(len(data), sig_off) - end

    def rva2off(rva: int) -> Optional[int]:
        s = info.section_at(rva)
        if s is None:
            return None
        off = rva - s.vaddr + s.raw_ptr
        return off if off < len(data) else None

    info.is_dotnet = len(dirs) > 14 and dirs[14][0] != 0
    info.has_signature = len(dirs) > 4 and dirs[4][1] != 0
    if len(dirs) > 1 and dirs[1][0]:
        info.has_import_dir = True
        try:
            _read_imports(data, info, rva2off, dirs[1][0])
        except (struct.error, IndexError):
            pass                              # damaged table: keep what we got
    if dirs and dirs[0][0]:
        try:
            _read_exports(data, info, rva2off, dirs[0][0])
        except (struct.error, IndexError):
            pass
    for names in info.imports.values():
        for nm in names:
            info.import_names.add(nm)
            if nm[-1:] in "AW" and len(nm) > 3:
                info.import_names.add(nm[:-1])

    for s in info.sections:
        if s.name.lower() in PACKER_SECTIONS:
            info.packer = PACKER_SECTIONS[s.name.lower()]
            break
    hot = any(s.executable and s.entropy >= 7.2 for s in info.sections)
    info.packed = bool(info.packer) or (hot and info.import_count < 10 and not info.is_dotnet)
    return info


_MAX_EXPORTS = 20_000


def _read_exports(data: bytes, info: PEInfo, rva2off, rva: int) -> None:
    base = rva2off(rva)
    if base is None:
        return
    name_rva = struct.unpack_from("<I", data, base + 12)[0]
    count, names_rva = struct.unpack_from("<I", data, base + 24)[0], \
        struct.unpack_from("<I", data, base + 32)[0]
    off = rva2off(name_rva)
    if off is not None:
        info.export_name = _cstr(data, off)
    table = rva2off(names_rva)
    if table is None:
        return
    for i in range(min(count, _MAX_EXPORTS)):
        off = rva2off(struct.unpack_from("<I", data, table + 4 * i)[0])
        if off is not None:
            info.exports.add(_cstr(data, off))


def _read_imports(data: bytes, info: PEInfo, rva2off, rva: int) -> None:
    base = rva2off(rva)
    if base is None:
        return
    size, fmt, high = (8, "<Q", 1 << 63) if info.is_64 else (4, "<I", 1 << 31)
    for i in range(512):
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, base + 20 * i)
        if not (oft or name_rva or ft):
            break
        noff = rva2off(name_rva)
        if noff is None:
            break
        names = info.imports.setdefault(_cstr(data, noff).lower(), [])
        toff = rva2off(oft or ft)
        if toff is None:
            continue
        for j in range(8192):
            if toff + size * (j + 1) > len(data):
                break
            val = struct.unpack_from(fmt, data, toff + size * j)[0]
            if not val:
                break
            if val & high:
                names.append("#%d" % (val & 0xFFFF))
                continue
            hint = rva2off(val & 0x7FFFFFFF)
            if hint is None:
                break
            names.append(_cstr(data, hint + 2))


# -- a program compared without its resources ---------------------------------------------------
RESOURCES = ".rsrc"
_MAX_RESOURCES = 16 * 1024 * 1024
_MAX_FRAME = 512 * 1024 * 1024
_MAX_RESOURCE_KINDS = 64
# resource kinds by their number (winuser.h); a kind with a name of its own has no number
RESOURCE_KINDS = {1: "cursor", 2: "bitmap", 3: "icon", 4: "menu", 5: "dialog", 6: "string table",
                  7: "font directory", 8: "font", 9: "accelerator", 10: "raw data", 11: "message table",
                  12: "cursor group", 14: "icon group", 16: "version", 17: "dialog include",
                  19: "plug and play", 20: "VxD", 21: "animated cursor", 22: "animated icon", 23: "HTML",
                  24: "manifest"}


def _aligned(value: int, step: int) -> int:
    return (value + step - 1) // step * step if step else value


def resource_kinds(data: bytes, pe: PEInfo) -> Optional[List[int]]:
    """The kinds of resources a program holds - the numbers at the top of its resource
    tree, sorted; -1 stands for a kind with a name instead of a number. None: there is no
    resource section, or its top cannot be read. Only the top of the tree is read."""
    try:
        res = next((s for s in pe.sections if s.name == RESOURCES), None)
        if res is None or len(pe.data_dirs) < 3 or pe.data_dirs[2][0] != res.vaddr:
            return None
        named, numbered = struct.unpack_from("<HH", data, res.raw_ptr + 12)
        if named + numbered > _MAX_RESOURCE_KINDS or 16 + 8 * (named + numbered) > res.raw_size:
            return None
        out = []
        for i in range(named + numbered):
            ident = struct.unpack_from("<I", data, res.raw_ptr + 16 + 8 * i)[0]
            out.append(-1 if ident & 0x80000000 or i < named else ident)
        return sorted(out)
    except (struct.error, IndexError, ValueError):
        return None


_MAX_RESOURCE_ENTRIES = 4096


def resource_entries(data: bytes, pe: PEInfo) -> Optional[List[Tuple[object, object, int, int]]]:
    """Every resource of a program as ``(kind, name, offset in the file, size)`` - kind and
    name are a number, or a text (upper case, as the linker stores it) where the resource
    has a name of its own. The three levels of the tree are walked (kind, name, language);
    None: there is no resource section, or the tree is not the plain one (too many
    entries, a level missing or too deep, an entry outside the section). Nothing is run."""
    try:
        res = next((s for s in pe.sections if s.name == RESOURCES), None)
        if res is None or len(pe.data_dirs) < 3 or pe.data_dirs[2][0] != res.vaddr:
            return None
        base, size = res.raw_ptr, min(res.raw_size, len(data) - res.raw_ptr)

        def rows(offset: int) -> List[Tuple[object, int]]:
            if offset + 16 > size:
                raise ValueError("outside the section")
            named, numbered = struct.unpack_from("<HH", data, base + offset + 12)
            if named + numbered > _MAX_RESOURCE_ENTRIES or offset + 16 + 8 * (named + numbered) > size:
                raise ValueError("too many entries")
            out = []
            for i in range(named + numbered):
                ident, where = struct.unpack_from("<II", data, base + offset + 16 + 8 * i)
                if ident & 0x80000000:
                    at = ident & 0x7FFFFFFF
                    length = struct.unpack_from("<H", data, base + at)[0]
                    if at + 2 + 2 * length > size:
                        raise ValueError("outside the section")
                    ident = bytes(data[base + at + 2:base + at + 2 + 2 * length]).decode("utf-16-le", "replace")
                out.append((ident, where))
            return out

        found: List[Tuple[object, object, int, int]] = []
        for kind, names in rows(0):
            if not names & 0x80000000:
                return None
            for name, languages in rows(names & 0x7FFFFFFF):
                if not languages & 0x80000000:
                    return None
                for _language, leaf in rows(languages & 0x7FFFFFFF):
                    if leaf & 0x80000000 or leaf + 16 > size:
                        return None
                    rva, length = struct.unpack_from("<II", data, base + leaf)
                    offset = rva - res.vaddr + base
                    if rva < res.vaddr or offset + length > base + size:
                        return None
                    found.append((kind, name, offset, length))
                    if len(found) > _MAX_RESOURCE_ENTRIES:
                        return None
        return found
    except (struct.error, IndexError, ValueError):
        return None


ICON_KINDS = frozenset({3, 14})                    # icon, icon group


def resources_but_icons(data: bytes, pe: PEInfo) -> Optional[str]:
    """SHA-256 over every resource of a program that is not an icon or an icon group: kind,
    name, language, code page and content of each, in the order of the tree, and the head of
    every table of the tree outside the icons (phageo, 2026-10-26: a game's copy of an engine
    program may differ from the official file in its icons only - a changed manifest, version,
    dialog or an extra kind of resource is a difference). Two programs with the same frame key
    (:func:`resource_frame_key`) and the same value here differ in their icons alone.

    None - such a program is never taken for the official one: there is no resource section,
    the tree is not the plain one (see :func:`resource_entries`), a table head or an entry's
    code page / reserved field inside the icons is not zero, or a byte of the section that is
    neither the tree, a name in it nor a resource is not zero (nothing may hide beside them).
    Nothing is run."""
    import hashlib
    try:
        res = next((s for s in pe.sections if s.name == RESOURCES), None)
        if res is None or len(pe.data_dirs) < 3 or pe.data_dirs[2][0] != res.vaddr:
            return None
        base, size = res.raw_ptr, min(res.raw_size, len(data) - res.raw_ptr)
        if size > _MAX_RESOURCES:
            return None
        used: List[Tuple[int, int]] = []
        digest = hashlib.sha256()

        def mark(at: int, length: int) -> None:
            if at < 0 or at + length > size:
                raise ValueError("outside the section")
            used.append((at, at + length))

        def rows(offset: int, icons: bool) -> List[Tuple[object, int]]:
            if offset + 16 > size:
                raise ValueError("outside the section")
            head = bytes(data[base + offset:base + offset + 12])
            if icons and any(head):
                raise ValueError("data in a table of the icons")
            if not icons:
                digest.update(b"T" + head)
            named, numbered = struct.unpack_from("<HH", data, base + offset + 12)
            if named + numbered > _MAX_RESOURCE_ENTRIES:
                raise ValueError("too many entries")
            mark(offset, 16 + 8 * (named + numbered))
            out = []
            for i in range(named + numbered):
                ident, where = struct.unpack_from("<II", data, base + offset + 16 + 8 * i)
                if ident & 0x80000000:
                    at = ident & 0x7FFFFFFF
                    length = struct.unpack_from("<H", data, base + at)[0] if at + 2 <= size else 0
                    mark(at, 2 + 2 * length)
                    ident = bytes(data[base + at + 2:base + at + 2 + 2 * length]).decode("utf-16-le", "replace")
                out.append((ident, where))
            return out

        count = 0
        for kind, names in rows(0, False):
            if not names & 0x80000000:
                return None
            icons = kind in ICON_KINDS
            for name, languages in rows(names & 0x7FFFFFFF, icons):
                if not languages & 0x80000000:
                    return None
                for language, leaf in rows(languages & 0x7FFFFFFF, icons):
                    if leaf & 0x80000000 or leaf + 16 > size:
                        return None
                    mark(leaf, 16)
                    rva, length, page, reserved = struct.unpack_from("<IIII", data, base + leaf)
                    offset = rva - res.vaddr
                    if rva < res.vaddr or offset + length > size:
                        return None
                    mark(offset, length)
                    count += 1
                    if count > _MAX_RESOURCE_ENTRIES:
                        return None
                    if icons:
                        if page or reserved:
                            return None
                        continue
                    digest.update(repr((kind, name, language, page, reserved)).encode("utf-8"))
                    digest.update(hashlib.sha256(data[base + offset:base + offset + length]).digest())
        reached = 0
        for start, end in sorted(used) + [(size, size)]:
            if start > reached and bytes(data[base + reached:base + start]).strip(b"\0"):
                return None
            reached = max(reached, end)
        return digest.hexdigest()
    except (struct.error, IndexError, ValueError):
        return None


ASAR_INTEGRITY = ("INTEGRITY", "ELECTRONASAR")     # kind and name of Electron's integrity record
MAX_ASAR_INTEGRITY = 16 * 1024                     # bytes of that record
_MAX_INTEGRITY_ROWS = 32
_HEX_64 = re.compile(r"[0-9a-fA-F]{64}\Z")


def only_asar_integrity(data: bytes, pe: PEInfo) -> bool:
    """Is the one resource of a named kind in this program Electron's integrity record of
    the app archive - and nothing else (phageo, 2026-10-13)? The packaging tool writes it as
    kind ``INTEGRITY``, name ``ELECTRONASAR``: a JSON list of rows ``{"file": ..., "alg":
    "SHA256", "value": <64 hex digits>}`` - the checksum of each archive's list of files,
    which Electron compares before it loads the archive. Accepted is exactly that: one
    entry of that kind and name, at most ``MAX_ASAR_INTEGRITY`` bytes, valid JSON of that
    shape and nothing more. Any other named kind, a second entry, another name, other
    fields or anything that is not this JSON: False. Read as data only."""
    import json
    entries = resource_entries(data, pe)
    if entries is None:
        return False
    named = [entry for entry in entries if isinstance(entry[0], str)]
    if len(named) != 1 or (named[0][0], named[0][1]) != ASAR_INTEGRITY:
        return False
    _kind, _name, offset, size = named[0]
    if not 2 <= size <= MAX_ASAR_INTEGRITY:
        return False
    try:
        rows = json.loads(bytes(data[offset:offset + size]).decode("utf-8"))
    except (ValueError, RecursionError):
        return False
    if not isinstance(rows, list) or not 1 <= len(rows) <= _MAX_INTEGRITY_ROWS:
        return False
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"file", "alg", "value"}:
            return False
        if not isinstance(row["file"], str) or not 1 <= len(row["file"]) <= 260 or row["alg"] != "SHA256":
            return False
        if not isinstance(row["value"], str) or not _HEX_64.match(row["value"]):
            return False
    return True


# -- what a game's copy of an engine program may differ in (phageo, 2026-10-27) ----------------------
# One rule for every renamed engine program (nw.exe, Electron, Ren'Py, Unity): a resource may differ
# from the official program's only where the difference is proven harmless, per kind - icons, icon
# groups and the version are data only; the manifest only when it asks for no elevation and is
# otherwise the official one; Electron's integrity record only when its checksum is the one of the
# app archive beside the program; Ren'Py's own padding only as its icon tool writes it. Any other
# kind that differs, or any other byte beside the tree: no match.
RT_VERSION, RT_MANIFEST = 16, 24
DATA_ONLY_KINDS = frozenset({3, 14, RT_VERSION})       # icon, icon group, version
MAX_MANIFEST = 64 * 1024
RENPY_PADDING = b"RENPYVNE"
# Windows' resource updater (the UpdateResource functions, which Electron's packaging tools use; phageo,
# 2026-10-27, answer b): its filler beside the tree - before a resource's data, up to a step of four, the
# first bytes of UPDATER_FILLER; at the section's end, the same up to a step of four and then one of
# UPDATER_TAIL_WORDS repeated - and a code page field of the build PC's (one of ANSI_CODE_PAGES) where the
# official program has 0, the resource otherwise byte for byte the official one. Read on ELE-01..04.
UPDATER_FILLER = b"PADDINGXXPADDING"
UPDATER_TAIL_WORDS = (b"PADDINGXXPADDING", b"PADDINGX")
ANSI_CODE_PAGES = frozenset({874, 932, 936, 949, 950, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258})
# a resource tool's padding comment appended to a manifest (phageo, 2026-10-27, sixth fix session, answer a):
# allowed only as exactly these bytes, once, at the manifest's very end - with it taken out the manifest must
# be the official one byte for byte apart from its execution level. Read on ELE-03 (behind "</assembly>\n").
MANIFEST_PADDING_COMMENT = b"<!--Padding to make filesize even multiple of 4 XX -->"
# what an integrity check returns for an app archive that is compared after the scan (Electron inside an
# installer or archive: the app archive is another member of it - Scanner._runtime_integrity_notes)
LATER = "later"
ELEVATION = "the manifest asks for "                  # how the reasons for an elevation start


class Resource(NamedTuple):
    kind: object            # a number, or a text where the kind has a name of its own
    name: object
    language: object
    page: int               # the code page field of the entry
    reserved: int
    offset: int             # in the file
    size: int


def resource_layout(data: bytes, pe: PEInfo) -> Optional[Tuple[List[Resource], List[Tuple[int, int]], int, int]]:
    """``(resources, gaps, start, size)`` of a program's resource section: every resource of the
    tree (kind, name, language), the ranges ``(start, end)`` - counted from the section's start -
    of bytes that are neither the tree, a name in it nor a resource, and where the section starts
    in the file and how many of its bytes are there. None: no resource section, a section over
    16 MB, or a tree that is not the plain one (see :func:`resource_entries`). Nothing is run."""
    try:
        res = next((s for s in pe.sections if s.name == RESOURCES), None)
        if res is None or len(pe.data_dirs) < 3 or pe.data_dirs[2][0] != res.vaddr:
            return None
        base, size = res.raw_ptr, min(res.raw_size, len(data) - res.raw_ptr)
        if size > _MAX_RESOURCES or size < 16:
            return None
        used: List[Tuple[int, int]] = []

        def mark(at: int, length: int) -> None:
            if at < 0 or at + length > size:
                raise ValueError("outside the section")
            used.append((at, at + length))

        def rows(offset: int) -> List[Tuple[object, int]]:
            if offset + 16 > size:
                raise ValueError("outside the section")
            named, numbered = struct.unpack_from("<HH", data, base + offset + 12)
            if named + numbered > _MAX_RESOURCE_ENTRIES:
                raise ValueError("too many entries")
            mark(offset, 16 + 8 * (named + numbered))
            out = []
            for i in range(named + numbered):
                ident, where = struct.unpack_from("<II", data, base + offset + 16 + 8 * i)
                if ident & 0x80000000:
                    at = ident & 0x7FFFFFFF
                    length = struct.unpack_from("<H", data, base + at)[0] if at + 2 <= size else 0
                    mark(at, 2 + 2 * length)
                    ident = bytes(data[base + at + 2:base + at + 2 + 2 * length]).decode("utf-16-le", "replace")
                out.append((ident, where))
            return out

        found: List[Resource] = []
        for kind, names in rows(0):
            if not names & 0x80000000:
                return None
            for name, languages in rows(names & 0x7FFFFFFF):
                if not languages & 0x80000000:
                    return None
                for language, leaf in rows(languages & 0x7FFFFFFF):
                    if leaf & 0x80000000 or leaf + 16 > size:
                        return None
                    mark(leaf, 16)
                    rva, length, page, reserved = struct.unpack_from("<IIII", data, base + leaf)
                    if rva < res.vaddr or rva - res.vaddr + length > size:
                        return None
                    mark(rva - res.vaddr, length)
                    found.append(Resource(kind, name, language, page, reserved, base + rva - res.vaddr, length))
                    if len(found) > _MAX_RESOURCE_ENTRIES:
                        return None
        gaps, reached = [], 0
        for start, end in sorted(used) + [(size, size)]:
            if start > reached:
                gaps.append((reached, start))
            reached = max(reached, end)
        return found, gaps, base, size
    except (struct.error, IndexError, ValueError):
        return None


def _digest(rows: List[Tuple[Resource, bytes]], ansi_as_zero: bool = False) -> str:
    """SHA-256 over resources: kind, name, language, code page, reserved field and content of
    each, in a fixed order. ``ansi_as_zero``: a code page of ``ANSI_CODE_PAGES`` counts as 0 (what
    Windows' resource updater writes where the official program has 0)."""
    import hashlib
    digest = hashlib.sha256()
    for item, content in sorted(rows, key=lambda row: (repr(row[0].kind), repr(row[0].name), repr(row[0].language))):
        page = 0 if ansi_as_zero and item.page in ANSI_CODE_PAGES else item.page
        digest.update(repr((item.kind, item.name, item.language, page, item.reserved)).encode("utf-8"))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


_LEVEL = re.compile(r"<(?:[A-Za-z_][\w.-]*:)?requestedExecutionLevel\b([^<>]*?)"
                    r"(?:/>|>\s*</(?:[A-Za-z_][\w.-]*:)?requestedExecutionLevel\s*>)")
_ATTRIBUTE = re.compile(r"""\s*([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"<>]*)"|'([^'<>]*)')""")
_LEVEL_WORD = re.compile(r"requestedexecutionlevel", re.I)


def _manifest_text(content: bytes) -> Optional[str]:
    if len(content) > MAX_MANIFEST:
        return None
    try:
        return bytes(content).decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def manifest_problem(content: bytes) -> Optional[str]:
    """Why a game's manifest is not accepted, or None: it is UTF-8 text of at most 64 KB and
    every ``requestedExecutionLevel`` in it asks for ``asInvoker`` - or there is none - with
    ``uiAccess`` absent or false (phageo, 2026-10-27). A level written any other way (another
    case, an entity, a duplicate attribute, another attribute) is not read: refused."""
    text = _manifest_text(content)
    if text is None:
        return "a manifest that is not UTF-8 text of at most %d KB" % (MAX_MANIFEST >> 10)
    elements = list(_LEVEL.finditer(text))
    if sum(len(_LEVEL_WORD.findall(m.group(0))) for m in elements) != len(_LEVEL_WORD.findall(text)):
        return "an execution level written in a form that is not read"
    for match in elements:
        attributes, rest = {}, match.group(1)
        while rest.strip():
            attribute = _ATTRIBUTE.match(rest)
            if attribute is None or attribute.group(1) in attributes:
                return "an execution level written in a form that is not read"
            attributes[attribute.group(1)] = attribute.group(2) if attribute.group(2) is not None else attribute.group(3)
            rest = rest[attribute.end():]
        if set(attributes) - {"level", "uiAccess"}:
            return "an execution level written in a form that is not read"
        if attributes.get("level") != "asInvoker":
            return "the manifest asks for the execution level %r" % attributes.get("level")
        if attributes.get("uiAccess", "false") != "false":
            return "the manifest asks for uiAccess"
    return None


def _manifest_rest(content: bytes) -> bytes:
    """The manifest with every execution level taken out (what must be the official one's,
    byte for byte - a byte-order mark too)."""
    if _manifest_text(content) is None:
        return bytes(content)
    return _LEVEL.sub("", bytes(content).decode("utf-8")).encode("utf-8")


def without_padding_comment(content: bytes) -> Optional[bytes]:
    """The manifest with the resource tool's padding comment (``MANIFEST_PADDING_COMMENT``) taken
    out - when it stands exactly once, as the manifest's last bytes; else None."""
    content = bytes(content)
    if content.endswith(MANIFEST_PADDING_COMMENT) and content.count(MANIFEST_PADDING_COMMENT) == 1:
        return content[:-len(MANIFEST_PADDING_COMMENT)]
    return None


def official_resources(data: bytes, pe: PEInfo) -> Optional[Tuple[str, str]]:
    """What a game's copy of this official program must keep: ``(SHA-256 over every resource
    that is no icon, icon group, version or manifest, SHA-256 over the manifests with their
    execution level taken out)`` - the record of ``gamescan.program_resources``. None: the tree
    is not the plain one."""
    layout = resource_layout(data, pe)
    if layout is None:
        return None
    items = layout[0]
    others = [(item, bytes(data[item.offset:item.offset + item.size])) for item in items
              if item.kind not in DATA_ONLY_KINDS and item.kind != RT_MANIFEST]
    manifests = [(item, _manifest_rest(data[item.offset:item.offset + item.size])) for item in items
                 if item.kind == RT_MANIFEST]
    return _digest(others), _digest(manifests)


def _renpy_padding(data: bytes, base: int, size: int, start: int, end: int, starts: Set[int],
                   alignment: int, tail: bool) -> bool:
    """Are the bytes ``start:end`` of the section (beside the tree) what Ren'Py's icon tool
    writes (``launcher/game/change_icon.py`` of the official SDKs, ``Packer``)? Two forms: one
    ``P`` before a resource's data to put it on an even place (every version) - the last byte of
    the run, at an odd place, the data starting right behind it; and, up to Ren'Py 7.3.5 (``tail``:
    the program is one of those SDKs), the word ``RENPYVNE`` repeated from its start, cut so that
    the section ends on a step of the section alignment (``padding = b"RENPYVNE" * (pad / 8 + 1)``,
    ``padding[:pad]``) - the end of the section. Zero bytes before either. Nothing else."""
    run = bytes(data[base + start:base + end])
    first = len(run) - len(run.lstrip(b"\0"))
    written = run[first:]
    at = start + first
    if written == b"P" and end in starts and at % 2 == 1:
        return True
    return (tail and end == size and alignment > 0 and size % alignment == 0 and 0 < size - at < alignment
            and written == (RENPY_PADDING * ((size - at) // len(RENPY_PADDING) + 1))[:size - at])


def _updater_filler(data: bytes, base: int, size: int, start: int, end: int, starts: Set[int]) -> bool:
    """Are the bytes ``start:end`` of the section (beside the tree) the filler of Windows' resource
    updater (phageo, 2026-10-27, answer b)? Exactly two forms, no zero byte in either: (1) before a
    resource's data that starts on a step of four, 1 to 3 bytes - the first ones of ``PADDINGXXPADDING``
    (``P``, ``PA``, ``PAD``); (2) to the end of the section: the first bytes of ``PADDINGXXPADDING`` up to
    a step of four, then ``PADDINGXXPADDING`` or ``PADDINGX`` repeated from there, cut at the end.
    Anything else - another word, another place, a byte more or less: False."""
    run = bytes(data[base + start:base + end])
    lead = -start % 4
    if end in starts and end % 4 == 0 and 0 < end - start < 4:
        return run == UPDATER_FILLER[:end - start]
    if end != size or len(run) < lead or run[:lead] != UPDATER_FILLER[:lead]:
        return False
    rest = len(run) - lead
    return any(run[lead:] == (word * (rest // len(word) + 1))[:rest] for word in UPDATER_TAIL_WORDS)


def section_alignment(data: bytes) -> int:
    """The program's SectionAlignment header field (0: not readable)."""
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        return struct.unpack_from("<I", data, pe_off + 24 + 32)[0]
    except struct.error:
        return 0


def resource_differences(data: bytes, pe: PEInfo, official: Tuple[str, str], renpy_padding: bool = False,
                         renpy_tail: bool = False, integrity=None, updater: bool = False,
                         later: Optional[List[Tuple[str, str]]] = None) -> List[str]:
    """What keeps a game's copy of an official engine program - the same apart from its
    resources (:func:`resource_frame_key`) - from being taken for it: [] when every difference is
    of a kind proven harmless (phageo, 2026-10-27). ``official``: the record of the official
    program (:func:`official_resources`).

    Allowed: icons, icon groups, the version (data only). The manifest when it asks for no
    elevation (:func:`manifest_problem`) and is otherwise the official one, code page and
    language too. Electron's integrity record of the app archive (``integrity``: a function that
    gives the SHA-256 of an archive's header by the name the record holds, or None where there is
    none at hand; only for Electron) when it has its own exact form (:func:`only_asar_integrity`)
    and every checksum in it is the one of that archive. Bytes beside the tree: zero - or, with
    ``renpy_padding`` (a Ren'Py SDK program), Ren'Py's own padding (:func:`_renpy_padding`; its
    ``RENPYVNE`` end only with ``renpy_tail``: an SDK up to 7.3.5). With ``updater`` (Electron;
    phageo, 2026-10-27, answer b) also the filler of Windows' resource updater
    (:func:`_updater_filler`) and a code page of ``ANSI_CODE_PAGES`` where the official program has
    0, the resource otherwise byte for byte the official one; and (sixth fix session, answer a) a
    resource tool's padding comment, exactly, at the manifest's end (:func:`without_padding_comment`) -
    the manifest without it the official one apart from its execution level. ``integrity`` may answer ``LATER``
    for an archive that is compared after the scan: its ``(name, checksum)`` rows go into
    ``later``. Any resource of another kind - added, gone or changed, its code page too - and
    anything else: a reason in the list (an elevation's starts with ``ELEVATION``)."""
    layout = resource_layout(data, pe)
    if layout is None:
        return ["a resource tree that is not the plain one"]
    items, gaps, base, size = layout
    reasons: List[str] = []
    named = [item for item in items if isinstance(item.kind, str)]
    record = [item for item in named if (item.kind, item.name) == ASAR_INTEGRITY]
    checked = integrity is not None and record
    others = [(item, bytes(data[item.offset:item.offset + item.size])) for item in items
              if item.kind not in DATA_ONLY_KINDS and item.kind != RT_MANIFEST
              and not (checked and item in record)]
    manifests = [item for item in items if item.kind == RT_MANIFEST]
    if _digest(others) != official[0] and not (updater and _digest(others, ansi_as_zero=True) == official[0]):
        kinds = sorted({RESOURCE_KINDS.get(item.kind, str(item.kind)) for item, _content in others})
        reasons.append("resources of another kind than icon, version or manifest differ from the official "
                       "program's (here: %s)" % (", ".join(kinds) or "none"))
    for item in manifests:
        problem = manifest_problem(data[item.offset:item.offset + item.size])
        if problem:
            reasons.append(problem)
    rests = [(item, _manifest_rest(data[item.offset:item.offset + item.size])) for item in manifests]
    trimmed = rests
    if updater:
        # (a resource tool's padding comment, exactly, at the end: taken out before the comparison)
        trimmed = []
        for item in manifests:
            content = bytes(data[item.offset:item.offset + item.size])
            cut = without_padding_comment(content)
            trimmed.append((item, _manifest_rest(content if cut is None else cut)))
    if _digest(rests) != official[1] and not (updater and official[1] in (
            _digest(rests, ansi_as_zero=True), _digest(trimmed), _digest(trimmed, ansi_as_zero=True))):
        reasons.append("the manifest differs from the official program's in more than its execution level")
    if checked:
        import json
        if not only_asar_integrity(data, pe):
            reasons.append("an integrity record not in its own exact form")
        else:
            item = record[0]
            for row in json.loads(bytes(data[item.offset:item.offset + item.size]).decode("utf-8")):
                actual = integrity(row["file"])
                if actual == LATER and later is not None:
                    later.append((row["file"], row["value"].lower()))
                elif actual is None or actual == LATER:
                    reasons.append("the integrity record names an app archive that is not at hand")
                elif actual != row["value"].lower():
                    reasons.append("the integrity record's checksum is not the one of the app archive")
    starts = {item.offset - base for item in items}
    alignment = section_alignment(data)
    for start, end in gaps:
        if not bytes(data[base + start:base + end]).strip(b"\0"):
            continue
        if renpy_padding and _renpy_padding(data, base, size, start, end, starts, alignment, renpy_tail):
            continue
        if updater and _updater_filler(data, base, size, start, end, starts):
            continue
        reasons.append("bytes beside the resource tree that are not zero (%d at offset %d of the section)"
                       % (end - start, start))
        break
    return reasons


def signature_is_all_appended(data: bytes, pe: PEInfo) -> bool:
    """Is everything behind the last section the signature (certificate table) the headers
    name - or is nothing there at all? False: other data is appended, or the table is not
    where the file ends. (What stands *inside* the table is judged by ``sigblock``.)"""
    offset, size = pe.data_dirs[4] if len(pe.data_dirs) > 4 else (0, 0)
    if not offset and not size:
        return not pe.overlay_size
    end = max((s.raw_ptr + s.raw_size for s in pe.sections), default=0)
    if not end or not end <= offset < end + 8 or offset + size != len(data):
        return False
    return not any(data[end:offset])        # (the table starts on a step of eight: zeros between)


def resource_frame_key(data: bytes, pe: Optional[PEInfo] = None, signature: bool = False) -> Optional[str]:
    """SHA-256 over everything of a program except its resource section: the
    headers and every other section, byte for byte. Two programs with the same
    key differ in their resources only (RPG Maker MV puts the game's icon into
    NW.js's ``nw.exe``; nothing else changes).

    Replacing the resources changes a few header fields, and only these are
    left out: the three sizes that sum up the sections (initialised data, the
    image, the checksum), the size of the resource directory, the size of the
    resource section, and - for sections *behind* the resources, which move
    when the resources shrink or grow - where they start. Such a section still
    has to start exactly where the resources end, in the file and in memory,
    and a header entry pointing into it is compared by its place inside it.
    Everything else has to be the same: entry point, every flag (also each
    section's, the resource section's included), every other directory, every
    byte of code and data.

    ``signature``: the entry of the headers that says where a signature
    (certificate table) is appended is left out too - the maker of a game may
    sign a program that the engine's project publishes unsigned. The table
    itself is appended data, which this key never covers.

    None: no ordinary program with one resource section, appended data aside;
    or the layout is not the plain one a linker writes. Nothing is executed."""
    import hashlib
    if pe is None:
        pe = parse_pe(data)
    if pe is None or len(data) > _MAX_FRAME:
        return None
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        opt = pe_off + 24
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        dd = opt + (112 if pe.is_64 else 96)
        section_align, file_align = struct.unpack_from("<II", data, opt + 32)
        table = opt + opt_size
        count = len(pe.sections)
        end_of_headers = table + 40 * count
        if count != struct.unpack_from("<H", data, pe_off + 6)[0] or not 2 <= count <= 32:
            return None
        named = [i for i, s in enumerate(pe.sections) if s.name == RESOURCES]
        if len(named) != 1 or len(pe.data_dirs) < 6:
            return None
        at = named[0]
        res = pe.sections[at]
        # (a writable resource section is accepted - the GNU linker writes one, as in Ren'Py's SDK
        # programs 7.3.5 to 8.0.3; phageo, 2026-10-18: every section's flags are in the key, so the
        # flags must be exactly those of the official file. An executable one is never accepted.)
        if (pe.data_dirs[2][0] != res.vaddr or res.executable
                or res.raw_size > _MAX_RESOURCES or pe.data_dirs[2][1] > max(res.vsize, res.raw_size)):
            return None
        # a plain layout: sections in order, one behind the other, nothing between them
        first = min(s.raw_ptr for s in pe.sections if s.raw_size)
        # (the first section starts where the headers end - rounded up, or where the headers
        # say they end: a linker may leave room for more rows. All of it is in the key.)
        if first < end_of_headers or first not in (_aligned(end_of_headers, file_align),
                                                   struct.unpack_from("<I", data, opt + 60)[0]):
            return None
        where, memory = first, None
        for s in pe.sections:
            if s.raw_size and (s.raw_ptr != where or s.raw_ptr + s.raw_size > len(data)):
                return None
            if memory is not None and s.vaddr != memory:
                return None
            where = s.raw_ptr + s.raw_size if s.raw_size else where
            memory = _aligned(s.vaddr + max(s.vsize, 1), section_align)
        header = bytearray(data[:first])
        for offset in (opt + 8, opt + 56, opt + 64, dd + 8 * 2 + 4):
            header[offset:offset + 4] = b"\0\0\0\0"
        if signature:
            header[dd + 8 * 4:dd + 8 * 5] = b"\0" * 8
        header[table + 40 * at + 8:table + 40 * at + 12] = b"\0\0\0\0"        # its size in memory
        header[table + 40 * at + 16:table + 40 * at + 20] = b"\0\0\0\0"       # its size in the file
        behind = pe.sections[at + 1:]
        for index, s in enumerate(behind, at + 1):
            header[table + 40 * index + 12:table + 40 * index + 16] = b"\0\0\0\0"   # where it starts in memory
            header[table + 40 * index + 20:table + 40 * index + 24] = b"\0\0\0\0"   # ... and in the file
        for number, (rva, _size) in enumerate(pe.data_dirs):
            if number in (2, 4) or not rva:
                continue                     # (4, the signature, is a file offset: compared as it is)
            for index, s in enumerate(behind, at + 1):
                if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                    struct.pack_into("<I", header, dd + 8 * number, (index << 24) | (rva - s.vaddr))
        digest = hashlib.sha256(bytes(header))
        for index, s in enumerate(pe.sections):
            if index != at:
                digest.update(hashlib.sha256(data[s.raw_ptr:s.raw_ptr + s.raw_size]).digest())
        return digest.hexdigest()
    except (struct.error, IndexError, ValueError):
        return None


def resources_of(data: bytes, pe: PEInfo) -> bytes:
    """The raw resource section (``b""``: there is none)."""
    for s in pe.sections:
        if s.name == RESOURCES:
            return data[s.raw_ptr:s.raw_ptr + s.raw_size]
    return b""


def program_inside(blob: bytes, limit: int = 4000) -> bool:
    """Is there a Windows program somewhere in ``blob`` (an MZ header that
    leads to a PE signature)?"""
    for n, m in enumerate(re.finditer(b"MZ", blob)):
        if n >= limit:
            return True                      # too many candidates to rule it out
        i = m.start()
        if i + 0x40 <= len(blob):
            lfanew = struct.unpack_from("<I", blob, i + 0x3C)[0]
            if lfanew < 0x1000 and blob[i + lfanew:i + lfanew + 4] == b"PE\0\0":
                return True
    return False


# -- import-table profile of Unity IL2CPP programs --------------------------------------------
class ImportNote(NamedTuple):
    category: str          # "tamper", "native", "network", "crypto", "system" or "other"
    dll: str
    name: str


# functions whose only use is to act on another process, or to take things from it
_TAMPER = re.compile(
    _IND[0])
# functions that start programs, change the system's configuration or watch the user
_SYSTEM = re.compile(
    _IND[1])
_NETWORK_DLLS = frozenset({
    "ws2_32.dll", "wsock32.dll", "mswsock.dll", "wininet.dll", "winhttp.dll", "urlmon.dll",
    "dnsapi.dll", "netapi32.dll", "wldap32.dll", "rasapi32.dll", "httpapi.dll", "websocket.dll",
    "iphlpapi.dll", "mpr.dll", "wlanapi.dll", "fwpuclnt.dll", "rpcrt4.dll"})
_CRYPTO_DLLS = frozenset({"crypt32.dll", "bcrypt.dll", "ncrypt.dll", "cryptsp.dll", _IND[2],
                          "cryptnet.dll", "wintrust.dll", "dpapi.dll", "secur32.dll", "sspicli.dll"})
_CRYPTO = re.compile(r"^(?:Crypt|BCrypt|NCrypt)\w+$")


def profile_il2cpp_imports(pe: PEInfo) -> List[ImportNote]:
    """Imports of an IL2CPP ``GameAssembly.dll`` that a standard Unity build
    does not have (see :mod:`gamescan.il2cpp_baseline`), each with what it
    is:

    ``tamper``   writes into, starts threads in, or dumps other processes
    ``native``   the undocumented native API (anything from ``ntdll.dll``)
    ``network``  a networking library, or a socket function beyond the four
                 the runtime itself imports
    ``crypto``   a cryptography library or function beyond random numbers
    ``system``   starts programs, changes services / registry / tokens, or
                 watches keyboard and clipboard
    ``other``    simply not in the baseline
    """
    from .il2cpp_baseline import IMPORTS, OWN_LIBRARIES
    out: List[ImportNote] = []
    for dll, names in pe.imports.items():
        if dll.startswith(OWN_LIBRARIES):
            continue
        known = IMPORTS.get(dll, frozenset())
        for name in dict.fromkeys(names):
            if name in known:
                continue
            if _TAMPER.match(name):
                category = "tamper"
            elif dll == "ntdll.dll":
                category = "native"
            elif dll in _NETWORK_DLLS:
                category = "network"
            elif dll in _CRYPTO_DLLS or _CRYPTO.match(name):
                category = "crypto"
            elif _SYSTEM.match(name):
                category = "system"
            else:
                category = "other"
            out.append(ImportNote(category, dll, name))
    return out
