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

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())

    def offset(self, rva: int) -> int:
        """File offset of a virtual address (raises ValueError if unmapped)."""
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return rva - s.vaddr + s.raw_ptr
        raise ValueError("unmapped RVA 0x%x" % rva)


def extract_strings(data: bytes, min_len: int = 5, limit: int = 250_000) -> List[str]:
    """Printable ASCII and UTF-16LE strings, de-duplicated, order preserved."""
    n = str(min_len).encode()
    found = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{" + n + rb",400}", data)]
    found += [s.decode("utf-16-le") for s in
              re.findall(rb"(?:[\x20-\x7e]\x00){" + n + rb",400}", data)]
    return list(dict.fromkeys(found))[:limit]


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
                  entry_point=struct.unpack_from("<I", data, opt + 16)[0])
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
        for s in info.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                off = rva - s.vaddr + s.raw_ptr
                return off if off < len(data) else None
        return None

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
_VERSION_KEY = re.compile(
    "(CompanyName|OriginalFilename|InternalName|ProductName|FileDescription)".encode("utf-16-le")
    + rb"(?:\x00\x00){1,3}((?:[\x20-\x7e]\x00){1,80})")


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


def version_strings(data: bytes) -> Dict[str, str]:
    """``CompanyName``, ``OriginalFilename``, ... from the version resource."""
    out: Dict[str, str] = {}
    for key, value in _VERSION_KEY.findall(data):
        out.setdefault(key.decode("utf-16-le"), value.decode("utf-16-le").strip())
    return out


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
