"""NSIS (Nullsoft) installer reader (standard library only).

An NSIS installer is a small program followed by: a 28-byte "first header",
the compressed installer script, and one data block per file it installs.
Both layouts are read - *solid* (everything is one compressed stream) and
*non-solid* (each block compressed by itself) - for the zlib and LZMA
methods. NSIS's own bzip2 variant is not in the standard library and
raises :class:`NeedTool`.

File names come from the installer script: its instruction table is read
for the two instructions that matter here - "set the output folder" and
"extract a file" - which pair every data block with the path it is written
to (:func:`file_names`). A block the script does not name (plug-ins the
installer uses itself) is named after what its content is (see
:mod:`sniff`). The script's strings - every command line the installer can
run - are returned as one text member. The instructions that download or
start something are read from the same table (:func:`instructions`).
"""
from __future__ import annotations

import lzma
import re
import struct
import zlib
from typing import BinaryIO, Callable, Dict, FrozenSet, Iterator, List, NamedTuple, Optional, Tuple

from ..pe import extract_strings
from . import limits, sniff, spool

SIGNATURE = b"\xef\xbe\xad\xdeNullsoftInst"
SCRIPT_NAME = "[installer script].bat"
_CHUNK = 1 << 20
_MAX_HEADER = 64 * 1024 * 1024
_MAX_BLOCKS = 100_000
_ERRORS = (lzma.LZMAError, zlib.error, EOFError)


class NsisError(ValueError):
    """The installer data is damaged or not NSIS."""


class NeedTool(NsisError):
    """Valid installer, but its compression is not in the standard library."""


def find(data: bytes, start: int = 0) -> int:
    """Offset of the first header in ``data`` (-1 = none)."""
    pos = data.find(SIGNATURE, start)
    return pos - 4 if pos >= 4 else -1


_STEP = 512                 # NSIS reads its own file in blocks of this size ...
_FLAGS = 15                 # ... and takes a block for the first header only with no other flag bit set


def first_header(data: bytes, end: Optional[int] = None) -> int:
    """Where NSIS itself finds its first header (-1 = none): it reads the
    whole file from its start in 512-byte steps and takes the first step at
    which a first header stands - wherever that is, also inside the program.
    ``data`` is the file from its start; only headers that begin before
    ``end`` are looked for."""
    end = len(data) if end is None else min(end, len(data))
    pos = data.find(SIGNATURE, 4, end + 4 + len(SIGNATURE))
    while pos >= 0:
        at = pos - 4
        if at < end and at % _STEP == 0 and not struct.unpack_from("<I", data, at)[0] & ~_FLAGS:
            return at
        pos = data.find(SIGNATURE, pos + 1, end + 4 + len(SIGNATURE))
    return -1


def _lzma_kind(p: bytes) -> int:
    """0 = not LZMA, 1 = LZMA, 2 = LZMA behind a one-byte filter flag."""
    def at(i: int) -> bool:
        return (len(p) >= i + 7 and p[i] == 0x5D and p[i + 1] == 0 and p[i + 2] == 0
                and p[i + 5] == 0 and not p[i + 6] & 0x80)
    return 1 if at(0) else 2 if p[:1] in (b"\0", b"\1") and at(1) else 0


def _lzma(head: bytes) -> Tuple[lzma.LZMADecompressor, int]:
    """``(decoder, bytes of ``head`` that belong to the stream header)``."""
    kind = _lzma_kind(head)
    skip = kind - 1
    prop, size = head[skip], struct.unpack_from("<I", head, skip + 1)[0]
    lc, rest = prop % 9, prop // 9
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": max(size, 4096), "lc": lc, "lp": rest % 5,
                "pb": rest // 5}]
    if skip and head[0] == 1:
        filters.insert(0, {"id": lzma.FILTER_X86})
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters), skip + 5


class _Inflate:
    """``read(n)`` over a compressed stream that is fed from ``stream``."""

    def __init__(self, stream: BinaryIO, left: int, head: bytes, deflate: bool) -> None:
        self.stream, self.left, self.buffer, self.pending = stream, left, b"", b""
        if deflate:
            self.decoder = zlib.decompressobj(-15)
        else:
            self.decoder, skip = _lzma(head)
            stream.seek(skip, 1)
            self.left -= skip

    def read(self, count: int) -> bytes:
        out = [self.buffer]
        have = len(self.buffer)
        while have < count:
            if getattr(self.decoder, "eof", False):
                break
            if isinstance(self.decoder, lzma.LZMADecompressor):
                if self.decoder.needs_input:
                    feed = self.stream.read(min(self.left, _CHUNK))
                    self.left -= len(feed)
                    if not feed:
                        break
                else:
                    feed = b""
                piece = self.decoder.decompress(feed, _CHUNK)
            else:
                feed = self.pending or self.stream.read(min(self.left, _CHUNK))
                if not self.pending:
                    self.left -= len(feed)
                if not feed:
                    break
                piece = self.decoder.decompress(feed, _CHUNK)
                self.pending = self.decoder.unconsumed_tail
            out.append(piece)
            have += len(piece)
        data = b"".join(out)
        self.buffer = data[count:]
        return data[:count]

    def skip(self, count: int) -> bool:
        while count > 0:
            got = len(self.read(min(count, _CHUNK)))
            if not got:
                return False
            count -= got
        return True


def _unpack(block: bytes, limit: int) -> bytes:
    """One compressed non-solid block (bounded)."""
    if block[:1] == b"\x31" and len(block) > 1 and block[1] < 14:
        raise NeedTool("NSIS bzip2 compression")
    if _lzma_kind(block):
        decoder, skip = _lzma(block)
        return decoder.decompress(block[skip:], limit)
    return zlib.decompressobj(-15).decompress(block, limit)


def _stored(stream: BinaryIO, size: int) -> Iterator[bytes]:
    while size > 0:
        piece = stream.read(min(size, _CHUNK))
        if not piece:
            raise NsisError("installer data is cut short")
        size -= len(piece)
        yield piece


def _unpack_stream(stream: BinaryIO, size: int, limit: int) -> Iterator[bytes]:
    """One compressed non-solid block of ``size`` bytes at the stream's
    position, unpacked piece by piece (at most ``limit`` bytes)."""
    head = stream.read(min(size, 16))
    if head[:1] == b"\x31" and len(head) > 1 and head[1] < 14:
        raise NeedTool("NSIS bzip2 compression")
    if _lzma_kind(head):
        decoder, skip = _lzma(head)
        feed = head[skip:]
    else:
        decoder, feed = zlib.decompressobj(-15), head
    left, produced = size - len(head), 0
    while produced < limit:
        if isinstance(decoder, lzma.LZMADecompressor):
            piece = decoder.decompress(feed, min(_CHUNK, limit - produced))
            more = not decoder.needs_input and not decoder.eof
        else:
            piece = decoder.decompress(feed, min(_CHUNK, limit - produced))
            more = bool(decoder.unconsumed_tail)
        produced += len(piece)
        if piece:
            yield piece
        if getattr(decoder, "eof", False):
            return
        if more:
            feed = b"" if isinstance(decoder, lzma.LZMADecompressor) else decoder.unconsumed_tail
            continue
        if left <= 0:
            return
        feed = stream.read(min(left, _CHUNK))
        if not feed:
            return
        left -= len(feed)


class Script(bytes):
    """The installer script's strings as text - and, beside them, the unpacked
    header they were read from (``header``), for :func:`instructions`."""

    header = b""


def _script(header: bytes) -> bytes:
    out = Script("\n".join(extract_strings(header, 4)).encode("utf-8", "replace"))
    out.header = header
    return out


_CREATE_DIR, _EXTRACT_FILE = 11, 20       # opcodes, the same in NSIS 2 and 3
# the instructions that download or start something, and what feeds them
ASSIGN, PUSH_POP, EXEC_SHELL, EXECUTE, CALL_DLL = 25, 31, 40, 41, 44
_READ = frozenset({ASSIGN, PUSH_POP, EXEC_SHELL, EXECUTE, CALL_DLL})
_MAX_INSTRUCTIONS = 1_000_000           # entries walked (file_names has the same limit)
_MAX_KEPT = 50_000                      # ... of which this many are kept
_VARIABLES = {20: "CMDLINE", 21: "INSTDIR", 22: "OUTDIR", 23: "EXEDIR", 24: "LANGUAGE", 25: "TEMP",
              26: "PLUGINSDIR", 27: "EXEPATH", 28: "EXEFILE", 29: "HWNDPARENT"}


class Instruction(NamedTuple):
    index: int                  # place in the instruction table
    code: int                   # ASSIGN, PUSH_POP, EXEC_SHELL, EXECUTE, CALL_DLL
    texts: Tuple[str, ...]      # the first four parameters read as texts ("" = none)
    numbers: Tuple[int, ...]    # all six parameters as stored


def variable(number: int) -> str:
    """``$0`` - ``$9``, ``$R0`` - ``$R9``, ``$TEMP`` ...: how variable ``number`` is written."""
    if 0 <= number < 10:
        return "$%d" % number
    if number < 20:
        return "$R%d" % (number - 10)
    return "$" + _VARIABLES.get(number, "var%d" % number)


def _text(table: bytes, offset: int, wide: bool) -> str:
    """The string at ``offset`` with its variables kept by name (``$TEMP\\x.exe``).
    A shell folder is ``$shell``; language strings are dropped."""
    out = []
    if wide:
        at = 2 * offset
        while at + 2 <= len(table) and len(out) < 1024:
            unit = table[at] | table[at + 1] << 8
            at += 2
            if unit == 0:
                break
            if unit < 5:
                if at + 2 > len(table):
                    break
                value = table[at] | table[at + 1] << 8
                at += 2
                if unit == 4:
                    out.append(chr(value))
                elif unit == 3:
                    out.append(variable((value & 0x7F) | ((value >> 8 & 0x7F) << 7)))
                elif unit == 2:
                    out.append("$shell")
                continue
            out.append(chr(unit))
    else:
        at = offset
        while 0 <= at < len(table) and len(out) < 1024:
            byte = table[at]
            at += 1
            if byte == 0:
                break
            if byte < 5 or byte >= 0xFC:
                if at + 2 > len(table):
                    break
                if byte in (3, 0xFD):
                    out.append(variable((table[at] & 0x7F) | ((table[at + 1] & 0x7F) << 7)))
                elif byte in (2, 0xFE):
                    out.append("$shell")
                at += 2
                continue
            out.append(chr(byte))
    return "".join(out)


def instructions(header: bytes) -> List[Instruction]:
    """The instructions of the script that download or start something, or hand
    a text on (``StrCpy``, ``Push`` / ``Pop``, ``ExecShell``, ``Exec``, a plug-in
    call), in the order of the table. Read as data; nothing is interpreted.
    ``[]`` when the table cannot be read."""
    out: List[Instruction] = []
    try:
        tables = [struct.unpack_from("<II", header, 4 + 8 * i) for i in range(8)]
        entries_at, count = tables[2]
        strings = header[tables[3][0]:tables[4][0]]
        if count > _MAX_INSTRUCTIONS:
            limits.hit("nsis", "more than %d instructions: none was read" % _MAX_INSTRUCTIONS)
        if not strings or entries_at + 28 * count > len(header) or count > _MAX_INSTRUCTIONS:
            return out
        wide = strings[:2] == b"\0\0" and strings[3:4] == b"\0"
        limit = len(strings) // 2 if wide else len(strings)
        for index in range(count):
            which = struct.unpack_from("<i", header, entries_at + 28 * index)[0]
            if which not in _READ:
                continue
            numbers = struct.unpack_from("<6i", header, entries_at + 28 * index + 4)
            texts = tuple(_text(strings, n, wide) if 0 < n < limit else "" for n in numbers[:4])
            out.append(Instruction(index, which, texts, numbers))
            if len(out) >= _MAX_KEPT:
                limits.hit("nsis", "more than %d instructions that start or download something: the rest was not read" % _MAX_KEPT)
                break
    except struct.error:
        return []
    return out


def _string(table: bytes, offset: int, wide: bool) -> str:
    """The string at ``offset`` of the string table. The codes that stand for
    a variable ($INSTDIR, ...) or a shell folder become ``$``; language-string
    codes are dropped."""
    out = []
    if wide:
        at = 2 * offset
        while at + 2 <= len(table) and len(out) < 1024:
            unit = table[at] | table[at + 1] << 8
            at += 2
            if unit == 0:
                break
            if unit < 5:                                    # code + one parameter unit
                if unit == 4 and at + 2 <= len(table):      # "skip": the next unit is literal
                    out.append(chr(table[at] | table[at + 1] << 8))
                elif unit in (2, 3):
                    out.append("$")
                at += 2
                continue
            out.append(chr(unit))
    else:
        at = offset
        while 0 <= at < len(table) and len(out) < 1024:
            byte = table[at]
            at += 1
            if byte == 0:
                break
            if byte < 5 or byte >= 0xFC:                    # NSIS 3 / NSIS 2 codes + two bytes
                if byte in (2, 3, 0xFD, 0xFE):
                    out.append("$")
                at += 2
                continue
            out.append(chr(byte))
    return "".join(out)


def _path(text: str) -> str:
    """``$\\Data\\x`` (``$`` = the install folder or another variable) -> ``Data/x``."""
    return text.replace("$", "").replace("\\", "/").strip("/")


def file_names(header: bytes) -> Dict[int, str]:
    """``{offset of a data block: path the installer writes it to}``.

    The header starts with a table of its blocks; the instruction block holds
    28-byte entries (opcode + six parameters). ``SetOutPath`` and ``File`` are
    read in program order; everything else is ignored."""
    out: Dict[int, str] = {}
    try:
        tables = [struct.unpack_from("<II", header, 4 + 8 * i) for i in range(8)]
        entries_at, count = tables[2]
        strings = header[tables[3][0]:tables[4][0]]
        if count > _MAX_INSTRUCTIONS:
            limits.hit("nsis", "more than %d instructions: the names of the files were not read" % _MAX_INSTRUCTIONS)
        if not strings or entries_at + 28 * count > len(header) or count > _MAX_INSTRUCTIONS:
            return out
        wide = strings[:2] == b"\0\0" and strings[3:4] == b"\0"     # UTF-16: "", then text
        folder = ""
        for index in range(count):
            which, a, b, c = struct.unpack_from("<4i", header, entries_at + 28 * index)
            if which == _CREATE_DIR and b:                  # SetOutPath
                folder = _path(_string(strings, a, wide))
            elif which == _EXTRACT_FILE and c >= 0:
                raw = _string(strings, b, wide)
                name = _path(raw)
                if name and all(ch >= " " for ch in name):
                    # "File /oname=$INSTDIR\\x\\y" carries its own folder
                    absolute = raw.startswith("$") or not folder
                    out.setdefault(c, name if absolute else folder + "/" + name)
    except struct.error:
        return {}
    return out


_VARIABLE_NAME = re.compile(r"\$(?:R?\d|[A-Za-z_]\w*)")
_PRINTABLE = re.compile(r"[\x20-\x7e]{4,400}")        # as extract_strings cuts the script's text


def installed_texts(header: bytes) -> FrozenSet[str]:
    """The texts the names of the files the installer installs stand as in the script's text
    (each a line of :class:`Script`): every ``File`` instruction's name, cut where a variable
    (``$INSTDIR`` ...) stands, as the strings of the header are cut. For the "file name, not an
    instruction" note (``ContextEngine._installed_name``). Empty: the table cannot be read."""
    out = set()
    try:
        tables = [struct.unpack_from("<II", header, 4 + 8 * i) for i in range(8)]
        entries_at, count = tables[2]
        strings = header[tables[3][0]:tables[4][0]]
        if not strings or entries_at + 28 * count > len(header) or count > _MAX_INSTRUCTIONS:
            return frozenset()
        wide = strings[:2] == b"\0\0" and strings[3:4] == b"\0"
        limit = len(strings) // 2 if wide else len(strings)
        for index in range(count):
            which, _a, b, c = struct.unpack_from("<4i", header, entries_at + 28 * index)
            if which == _EXTRACT_FILE and c >= 0 and 0 < b < limit:
                for piece in _VARIABLE_NAME.split(_text(strings, b, wide)):
                    out.update(_PRINTABLE.findall(piece))
    except struct.error:
        return frozenset()
    return frozenset(out)


def members(stream: BinaryIO, policy,
            tick: Optional[Callable[[float], None]] = None) -> Iterator[Tuple[str, bytes]]:
    """``(name, data)`` for the installer script and every data block the
    policy accepts (``policy.want(name, size)``; ``policy.limit(name)`` is the
    largest size it would accept for that kind of file). ``stream`` must
    start at the first header."""
    want = policy.want
    stream.seek(0)
    first = stream.read(28)
    if len(first) != 28 or first[4:20] != SIGNATURE:
        raise NsisError("not an NSIS installer")
    header_size, total = struct.unpack_from("<II", first, 20)
    end = min(stream.seek(0, 2), max(total, 28))
    if header_size > _MAX_HEADER:
        raise NsisError(limits.hit("nsis", "implausible script size (more than %d MB)" % (_MAX_HEADER >> 20)))
    if header_size <= 0:
        raise NsisError("implausible script size")
    stream.seek(28)
    head = stream.read(16)
    if len(head) < 8:
        raise NsisError("installer data is cut short")
    word = struct.unpack_from("<I", head)[0]
    if (head[:1] == b"\x31" and head[1] < 14) or (head[4:5] == b"\x31" and head[5] < 14
                                                  and word & 0x80000000):
        raise NeedTool("NSIS bzip2 compression")
    solid = bool(_lzma_kind(head)) or not (
        _lzma_kind(head[4:]) or word == header_size
        or (word & 0x80000000 and 28 + 4 + (word & 0x7FFFFFFF) <= end))
    count = 0
    names: Dict[int, str] = {}

    def name_of(offset: int, content: bytes) -> str:
        return names.get(offset) or "file_%04d%s" % (count, sniff.extension(content))

    try:
        if solid:
            stream.seek(28)
            source = _Inflate(stream, end - 28, head, deflate=not _lzma_kind(head))
            raw = source.read(4)
            if len(raw) != 4 or struct.unpack("<I", raw)[0] != header_size:
                raise NsisError("installer script could not be unpacked")
            header = source.read(header_size)
            names = file_names(header)
            if want(SCRIPT_NAME, len(header)):
                yield SCRIPT_NAME, _script(header)
            offset = 0                                      # of the block, in the data area
            while count < _MAX_BLOCKS:
                raw = source.read(4)
                if len(raw) != 4:
                    break
                size = struct.unpack("<I", raw)[0] & 0x7FFFFFFF
                count += 1
                # without a name, the kind of file is only known from its first bytes
                data = source.read(min(size, 64))
                name = name_of(offset, data)
                if want(name, size):
                    def rest(first=data, left=size - len(data)):
                        yield first
                        while left > 0:
                            piece = source.read(min(left, _CHUNK))
                            if not piece:
                                raise NsisError("installer data is cut short")
                            left -= len(piece)
                            yield piece
                    data = spool.collect(rest())
                    yield name_of(offset, spool.head_of(data)[:65536]), data
                elif not source.skip(size - len(data)):
                    break
                offset += 4 + size
                if tick is not None:
                    tick(min(1.0, stream.tell() / max(end, 1)))
            if count >= _MAX_BLOCKS:
                limits.hit("nsis", "more than %d data blocks: the rest was not read" % _MAX_BLOCKS)
            return
        pos, offset = 28, 0
        while pos + 4 <= end and count <= _MAX_BLOCKS:
            stream.seek(pos)
            word = struct.unpack("<I", stream.read(4))[0]
            size = word & 0x7FFFFFFF
            if pos + 4 + size > end:
                break                                       # trailing checksum / padding
            packed = bool(word & 0x80000000)
            if count == 0:                                  # the script comes first
                block = stream.read(size)
                header = _unpack(block, header_size + 1) if packed else block
                if len(header) != header_size:
                    raise NsisError("installer script could not be unpacked")
                names = file_names(header)
                if want(SCRIPT_NAME, len(header)):
                    yield SCRIPT_NAME, _script(header)
            else:
                named = names.get(offset)
                head = stream.read(size if named else min(size, 4096))
                probe = b""
                if not named:
                    probe = head
                    if packed:
                        try:
                            probe = _unpack(head, 64)
                        except _ERRORS:
                            probe = b""
                # the unpacked size is not stored: decode up to what the policy
                # would accept for this kind of file, plus one byte to notice more
                limit = policy.limit(name_of(offset, probe))
                stream.seek(pos + 4)
                data = spool.collect(_unpack_stream(stream, size, limit + 1) if packed
                                     else _stored(stream, size))
                name = name_of(offset, spool.head_of(data)[:65536])
                if want(name, spool.size_of(data)):
                    yield name, data
                elif isinstance(data, spool.Blob):
                    data.release()
                offset += 4 + size
            count += 1
            pos += 4 + size
            if tick is not None:
                tick(min(1.0, pos / max(end, 1)))
        if count > _MAX_BLOCKS:
            limits.hit("nsis", "more than %d data blocks: the rest was not read" % _MAX_BLOCKS)
    except _ERRORS as exc:
        raise NsisError("installer data is damaged (%s)" % exc)
