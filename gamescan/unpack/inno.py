"""Inno Setup installer reader (standard library only).

An Inno Setup installer carries, behind its program:

* ``setup-0`` - compressed blocks, announced by ``Inno Setup Setup Data
  (x.y.z)``: the setup script (file names, [Run] entries, Pascal code) and
  the *data entries*, one fixed-size record per installed file with its
  place in the data, its size and its checksum;
* ``setup-1`` - the files, packed into chunks that each start with
  ``zlb\x1a``. (It can also be in separate ``setup-N.bin`` files.)

:class:`Installer` rebuilds the installed files exactly:

* the data-entry records give every file's chunk, offset and size. Their
  layout differs between versions only in field widths and trailing fields,
  so it is *found* (the candidate that tiles the block and points at real
  chunks) instead of being tabulated per version;
* Inno Setup rewrites the CALL / JMP operands of programs before packing
  them. That filter is undone, and the result is accepted only if it has the
  checksum (CRC-32, MD5, SHA-1 or SHA-256) the installer stores for the
  file - so a rebuilt file is byte-identical to the installed one, and its
  SHA-256 is the real one;
* the destination names come from the file entries in the setup script. They
  are located by their shape (a run of length-prefixed strings followed by a
  fixed-size tail holding the data-entry index) and accepted only if the
  indexes found cover every data entry.

When that fails - an unknown layout, an encrypted installer - the older
path remains: :func:`payload` unpacks the chunks into one stream and the
caller finds programs, RPG Maker archives and text in it by content,
without names and without the filter undone.
"""
from __future__ import annotations

import lzma
import struct
import zlib
import hashlib
import re

from . import ifps, limits, spool
from typing import BinaryIO, Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple

SIGNATURE = b"Inno Setup Setup Data ("
CHUNK_MAGIC = b"zlb\x1a"
_CHUNK = 1 << 20
_MAX_SCRIPT = 64 * 1024 * 1024
_ERRORS = (lzma.LZMAError, zlib.error, EOFError, struct.error, ValueError)


class InnoError(ValueError):
    """The installer data is damaged or not Inno Setup."""


class NeedTool(InnoError):
    """Valid installer, but it cannot be unpacked with the standard library."""


def find(data: bytes, start: int = 0) -> int:
    """Offset of the setup script's signature at or after ``start`` (-1 = none).
    (The installer's own program contains the same text as a constant, which
    is why the search starts behind it.)"""
    pos = data.find(SIGNATURE, start)
    while pos >= 0:
        end = data.find(b")", pos, pos + 64)
        if end > 0 and data[pos + len(SIGNATURE):end].replace(b".", b"").isdigit():
            return pos
        pos = data.find(SIGNATURE, pos + 1)
    return -1


# The loader of an installer (its program) holds a small table that says where the setup
# header and the data are - that is how Inno Setup itself finds them. It begins with this
# mark; what follows differs between versions (32-bit numbers, since 6.5 also 64-bit ones).
LOADER_TABLE = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
_MAX_TABLE = 96                     # bytes of the table that are looked at
_MAX_TABLES = 16                    # places in the program where its mark is looked at
_MAX_MARKERS = 256                  # setup-header texts that are looked at when there is no table
AMBIGUOUS = -2                      # no table, and the header's text stands more than once


def _is_header(head: bytes) -> bool:
    end = head.find(b")", 0, 64)
    return head.startswith(SIGNATURE) and end > 0 and head[len(SIGNATURE):end].replace(b".", b"").isdigit()


def header(program: bytes, start: int, total: int, read: Callable[[int, int], bytes],
           markers: Optional[Callable[[], List[int]]] = None) -> int:
    """Where the setup header of an Inno Setup installer is (-1 = none).

    ``program`` is the installer's program (the file up to ``start``, where
    the data behind it begins), ``total`` the size of the file and
    ``read(offset, count)`` reads from anywhere in it.

    The place is taken from the loader's own table, as Inno Setup takes it:
    the number in the table that points at a setup header. The text that
    marks a setup header can stand in the data more than once - another
    installer packed inside, an uninstaller -, so the first one found is not
    taken for it. Only an installer without a readable table (a very old
    one, a damaged one) is searched: ``markers()`` gives the places of the
    text. One such place, with a setup script block behind it, is taken.
    Two or more: nothing says which of them the installer uses, so none is
    taken (:data:`AMBIGUOUS`) - the caller says that the installer was not
    read (phageo, 2026-10-11)."""
    at = program.find(LOADER_TABLE, 0, start if start > 0 else len(program))
    tried = 0
    while at >= 0 and tried < _MAX_TABLES:
        tried += 1
        table = program[at + len(LOADER_TABLE):at + len(LOADER_TABLE) + _MAX_TABLE]
        for skip in range(0, len(table) - 3, 4):
            for width, fmt in ((8, "<Q"), (4, "<I")):
                if skip + width > len(table):
                    continue
                place = struct.unpack_from(fmt, table, skip)[0]
                if start <= place <= total - 64 and _is_header(read(place, 64)):
                    return place
        at = program.find(LOADER_TABLE, at + 1, start if start > 0 else len(program))
    places = markers() if markers is not None else []
    found = [place for place in places[:_MAX_MARKERS] if place >= start and _is_header(read(place, 64))]
    if len(found) > 1 or (found and len(places) > _MAX_MARKERS):
        return AMBIGUOUS
    for place in found:
        window = read(place + 64, 4096)
        if any(_block_header(window, skip) for skip in range(max(len(window) - 8, 0))):
            return place
    return -1


def version(signature: bytes) -> Tuple[int, ...]:
    text = signature[len(SIGNATURE):signature.find(b")")]
    return tuple(int(part) for part in text.split(b".") if part.isdigit())


def _lzma1(props: bytes):
    if len(props) < 5 or props[0] >= 225:
        raise InnoError("bad LZMA properties")
    lc, rest = props[0] % 9, props[0] // 9
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": max(struct.unpack_from("<I", props, 1)[0], 4096),
        "lc": lc, "lp": rest % 5, "pb": rest // 5}])


def _lzma2(prop: int):
    if prop > 40:
        raise InnoError("bad LZMA2 properties")
    size = 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)
    return lzma.LZMADecompressor(lzma.FORMAT_RAW,
                                 filters=[{"id": lzma.FILTER_LZMA2, "dict_size": size}])


def _block_header(buffer: bytes, at: int) -> Optional[Tuple[int, bool, int]]:
    """``(stored size, packed, header length)`` if a script block starts at
    ``at``: a CRC over the fields that follow it, the size (32 bits; 64 bits
    since 6.5) and a "compressed" flag."""
    for length, fmt in ((9, "<IB"), (13, "<QB")):
        head = buffer[at:at + length]
        if len(head) == length and zlib.crc32(head[4:]) == struct.unpack_from("<I", head)[0]:
            size, packed = struct.unpack_from(fmt, head, 4)
            if 0 < size <= _MAX_SCRIPT and packed in (0, 1):
                return size, bool(packed), length
    return None


def blocks(stream: BinaryIO, pos: int) -> List[bytes]:
    """The unpacked blocks behind the 64-byte signature at ``pos``: the setup
    script first, then the data entries (newer versions add more).

    Each block is a small CRC-protected header and then the data in 4 KB
    pieces that carry their own CRC. Newer versions put further fixed-size
    records between the signature and the first block, so the block is looked
    for (its header CRC makes that reliable) rather than assumed to follow
    directly."""
    stream.seek(pos)
    signature = stream.read(64)
    ver = version(signature)
    out: List[bytes] = []
    at = pos + 64
    while len(out) < 4:
        stream.seek(at)
        window = stream.read(4096 if not out else 64)
        found = next(((skip,) + header for skip in range(max(len(window) - 8, 0))
                      for header in [_block_header(window, skip)] if header), None)
        if found is None:
            break
        skip, size, packed, length = found
        stream.seek(at + skip + length)
        raw = stream.read(size)
        pieces = []
        for i in range(0, len(raw), 4100):                  # [crc][up to 4096 bytes]
            piece = raw[i + 4:i + 4100]
            if len(raw) < i + 4 or zlib.crc32(piece) != struct.unpack_from("<I", raw, i)[0]:
                raise InnoError("setup script is damaged")
            pieces.append(piece)
        data = b"".join(pieces)
        if packed:
            try:
                if ver >= (4, 1, 6):
                    engine = _lzma1(data[:5])
                    data = engine.decompress(data[5:], _MAX_SCRIPT)
                    more = len(data) >= _MAX_SCRIPT and not engine.eof
                else:
                    engine = zlib.decompressobj()
                    data = engine.decompress(data, _MAX_SCRIPT)
                    more = bool(engine.unconsumed_tail)
                if more:
                    limits.hit("inno", "a setup script that unpacks to more than %d MB: the rest was not read"
                               % (_MAX_SCRIPT >> 20))
            except _ERRORS as exc:
                raise InnoError("setup script could not be unpacked (%s)" % exc)
        out.append(data)
        at += skip + length + size
    if not out:
        raise InnoError("setup script not found (damaged, or a version laid out differently)")
    return out


def script(stream: BinaryIO, pos: int) -> bytes:
    """All unpacked setup-script blocks as one piece (for reading its text)."""
    return b"\0".join(blocks(stream, pos)[:2])


def chunks(data: bytes, start: int = 0) -> List[int]:
    """Offsets of the data chunks in ``data``."""
    out, pos = [], data.find(CHUNK_MAGIC, start)
    while pos >= 0 and len(out) < 4096:
        out.append(pos)
        pos = data.find(CHUNK_MAGIC, pos + 4)
    return out


def _chunk_decoder(head: bytes):
    """``(decoder, header bytes to skip)`` guessed from the chunk's first bytes
    (the method is only named in the script, which is not interpreted)."""
    if head[:1] == b"\x78" and (head[0] << 8 | head[1]) % 31 == 0:
        return zlib.decompressobj(), 0
    if head[:3] == b"BZh":
        raise NeedTool("bzip2 (very old Inno Setup versions)")
    if (len(head) >= 6 and head[0] < 225 and head[5] == 0
            and struct.unpack_from("<I", head, 1)[0] in _DICT_SIZES):
        return _lzma1(head[:5]), 5
    if head and head[0] <= 40 and len(head) > 1 and head[1] in (0x01, 0x02, 0xE0, 0xE1, 0xE2,
                                                                 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                                                                 0xE8, 0xE9, 0xEA, 0xEB, 0xEC,
                                                                 0xED, 0xEE, 0xEF):
        return _lzma2(head[0]), 1
    return None, 0


_DICT_SIZES = frozenset(1 << n for n in range(12, 31)) | frozenset(3 << n for n in range(11, 30))


def payload(stream: BinaryIO, offsets: List[int], end: int, cancel=None,
            tick=None) -> Iterator[bytes]:
    """The unpacked content of the chunks at ``offsets`` (each ends where the
    next begins, the last one at ``end``), piece by piece.

    Raises :class:`NeedTool` for a chunk that is encrypted or of an unknown
    method - after everything before it has been produced."""
    bounds = list(offsets[1:]) + [end]
    for start, stop in zip(offsets, bounds):
        stream.seek(start + 4)
        head = stream.read(16)
        decoder, skip = _chunk_decoder(head)
        if decoder is None:
            raise NeedTool("a password, or an unknown compression method")
        stream.seek(start + 4 + skip)
        left = stop - start - 4 - skip
        produced = False
        while left > 0 and not (cancel is not None and cancel.is_set()):
            feed = stream.read(min(left, _CHUNK))
            if not feed:
                break
            left -= len(feed)
            try:
                while True:
                    piece = decoder.decompress(feed, _CHUNK)
                    if piece:
                        produced = True
                        yield piece
                    if decoder.eof:
                        break
                    if isinstance(decoder, lzma.LZMADecompressor):
                        if decoder.needs_input:
                            break
                        feed = b""
                    else:                                   # zlib keeps what it did not use
                        feed = decoder.unconsumed_tail
                        if not feed:
                            break
            except _ERRORS:
                # LZMA1 chunks have no end mark: what follows the last byte of
                # the stream is not valid data. Anything else is real damage.
                if not produced:
                    raise NeedTool("a password, or an unknown compression method")
                left = 0
            if getattr(decoder, "eof", False):
                break
            if tick is not None:
                tick(min(1.0, stream.tell() / max(end, 1)))


# -- exact reconstruction of the installed files ---------------------------------------------
class Entry(NamedTuple):
    """One data entry: where an installed file is, and what it must hash to."""
    slice: int
    start: int         # offset of its chunk in the data
    offset: int        # offset of the file inside the unpacked chunk
    size: int
    packed: int        # stored size of the chunk
    checksum: bytes    # CRC-32 (4), MD5 (16), SHA-1 (20) or SHA-256 (32 bytes)


_MAX_NAME = 1040
_JUMP = re.compile(rb"[\xe8\xe9]")


def data_entries(block: bytes, limit: Optional[int] = None) -> List[Entry]:
    """The records of the data-entries block.

    Since 4.0.1 a record starts with: first slice, last slice, chunk offset,
    offset in chunk, file size, chunk size, checksum. The widths of the chunk
    offset (32 or 64 bit) and of the checksum, and what follows it, depend on
    the version - so the layout taken is the one that tiles the block exactly
    and whose every record is plausible. ``limit``: the size of the installer
    when its data is inside it - no chunk lies or reaches beyond that (with a
    single record, two layouts tile the block, and only this tells them apart)."""
    for head, wide in (("<IIIQQQ", False), ("<IIQQQQ", True)):
        prefix = struct.calcsize(head)
        for digest in (32, 20, 16, 4):
            for tail in range(17, 41):
                size = prefix + digest + tail
                if not block or len(block) % size:
                    continue
                rows = []
                for at in range(0, len(block), size):
                    first, last, start, offset, length, packed = struct.unpack_from(head, block, at)
                    if first > last or last > 255 or max(start, offset, length, packed) > 1 << 40 \
                            or (limit is not None and start + packed > limit):
                        rows = None
                        break
                    rows.append(Entry(first, start, offset, length, packed,
                                      block[at + prefix:at + prefix + digest]))
                if rows:
                    return rows
    raise InnoError("data entries: record layout not recognised")


def _text_at(block: bytes, pos: int, wide: bool, limit: int = _MAX_NAME) -> Optional[Tuple[str, int]]:
    """``(text, position after it)`` of a length-prefixed string at ``pos``."""
    if pos + 4 > len(block):
        return None
    length = struct.unpack_from("<I", block, pos)[0]
    if length > limit or pos + 4 + length > len(block) or (wide and length & 1):
        return None
    raw = block[pos + 4:pos + 4 + length]
    try:
        text = raw.decode("utf-16-le") if wide else raw.decode("latin-1")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 for c in text):
        return None
    return text, pos + 4 + length


class Files(NamedTuple):
    """The file entries of the setup script, as far as they were walked."""
    names: Dict[int, str]                   # data-entry index -> destination name
    rows: Tuple[Tuple[str, str], ...]       # (source, destination) of every entry, as written;
    #                                         the source is empty for a file of the package
    marks: Tuple[int, ...]                  # where the destination of each of them ends in the block


def file_names(block: bytes, count: int, wide: bool) -> Dict[int, str]:
    """``{data-entry index: destination name}`` from the file entries."""
    return file_entries(block, count, wide).names


def header_end(block: bytes, count: int, version: Tuple[int, ...] = ()) -> int:
    """Where the setup header ends in ``block`` - behind its entry counts - as far
    as that can be said (0 = not found). The counts stand behind the compiled
    ``[Code]``, or behind its empty text; the place is taken when the number of
    data entries there is ``count`` and there are at least as many file entries.
    The file entries lie behind it: with a single file in the installer, texts
    of the header itself would otherwise pass for its file entry."""
    where = ifps.locate(block)
    if where is None and ifps.named(block):
        return 0
    for at, kinds, searched in _count_places(block, where[0] + where[1] if where else 0, len(block), version):
        if at + 4 * (kinds + 2 + _ENTRY_KINDS) > len(block):
            continue
        numbers = struct.unpack_from("<%dI" % (kinds + 2 + _ENTRY_KINDS), block, at)
        if numbers[kinds + 1] == count and count <= numbers[kinds] <= 1_000_000 and max(numbers) <= 1_000_000 \
                and (not searched or 1 <= numbers[0] <= _MAX_LANGUAGES):
            return at + 4 * (kinds + 2 + _ENTRY_KINDS)
    return 0


def file_entries(block: bytes, count: int, wide: bool, after: int = 0) -> Files:
    """The file entries (looked for from ``after`` on): names for the data
    entries, and every entry's source and destination.

    A file entry is a run of strings (source, destination, font name, ...
    conditions) and then a fixed-size tail that holds, among other things,
    the index of its data entry. How many strings and how long the tail is
    depends on the version, so both are searched for: the reading that walks
    entry after entry without a break and whose indexes cover *all* ``count``
    data entries is the right one - a wrong guess does not survive that."""
    marker = "{".encode("utf-16-le" if wide else "latin-1")
    starts = []
    at = block.find(marker)
    while at >= 0 and len(starts) < 4096:
        # the destination ("{app}\\...") follows an empty source string
        if at >= 8 + after and block[at - 8:at - 4] == b"\0\0\0\0" and _text_at(block, at - 4, wide):
            starts.append(at - 8)
        at = block.find(marker, at + 1)
    for start in starts:
        for strings in range(8, 20):
            first = _entry_strings(block, start, strings, wide)
            if first is None:
                continue
            for tail in range(30, 140):
                names, sources, tails, marks, pos = [], [], [], [], start
                while len(names) < 100_000:
                    entry = _entry_strings(block, pos, strings, wide)
                    if entry is None or entry[1] + tail > len(block):
                        break
                    names.append(entry[0])
                    sources.append(entry[2])
                    marks.append(entry[3])
                    tails.append(block[entry[1]:entry[1] + tail])
                    pos = entry[1] + tail
                if len(names) < count:
                    continue
                for where in range(0, tail - 3):
                    indexes = []
                    for t in tails:                         # (the walk may run past the last entry)
                        index = struct.unpack_from("<I", t, where)[0]
                        if index >= count and index != 0xFFFFFFFF:
                            break
                        indexes.append(index)
                    used = [i for i in indexes if i != 0xFFFFFFFF]
                    if len(set(used)) == count:
                        out: Dict[int, str] = {}
                        for index, name in zip(indexes, names):
                            if index != 0xFFFFFFFF:
                                out.setdefault(index, name)
                        # a file that is not in the package (it has a source) has no data
                        # entry, and every file has a destination: what has a source and a
                        # data entry, or no destination, is no file entry any more - the
                        # walk ran on
                        walked = next((i for i, index in enumerate(indexes)
                                       if not names[i] or (sources[i] and index != 0xFFFFFFFF)), len(indexes))
                        # (with few files more than one reading covers all indexes: the one
                        # that is taken names every data entry among its file entries)
                        if len({index for index in indexes[:walked] if index != 0xFFFFFFFF}) != count:
                            continue
                        return Files(out, tuple(zip(sources[:walked], names[:walked])),
                                     tuple(marks[:walked]))
    raise InnoError("file entries: layout not recognised")


def _entry_strings(block: bytes, pos: int, count: int, wide: bool) -> Optional[Tuple[str, int, str, int]]:
    """``(destination, position after the strings, source, position after the
    destination)`` of a file entry at ``pos``."""
    destination = source = ""
    mark = pos
    for index in range(count):
        found = _text_at(block, pos, wide)
        if found is None:
            return None
        if index == 0:
            source = found[0]
        elif index == 1:
            destination, mark = found
        pos = found[1]
    return destination, pos, source, mark


# -- the rows that start something ([Run], [UninstallRun]) -------------------------------------
_MAX_ROWS = 20_000                  # entries behind the file entries that are walked
_MAX_ROW_TEXT = 32 * 1024           # bytes of one text of such an entry (a long command line)
_MAX_ROW_STRINGS = 64               # texts of one entry
_MAX_ROW_TAIL = 200                 # bytes between the texts of two entries
_MAX_ROW_STEPS = 2_000_000          # texts read while looking for the entries
_MAX_ROW_SEARCH = 64 * 1024         # bytes behind the last file names in which the first entry is looked for
_MAX_HEADER_SEARCH = 4 * 1024 * 1024  # bytes of the setup header searched for the entry counts
_MAX_LANGUAGES = 4096
_ENTRY_KINDS = 7                    # icons, ini, registry, two kinds of deletion, run, uninstall-run


class Row(NamedTuple):
    """One ``[Run]`` or ``[UninstallRun]`` row: what it starts."""
    number: int                 # 1 = the first row
    filename: str
    parameters: str


def _run_of_texts(block: bytes, pos: int, wide: bool, marker: Optional[bytes],
                  steps: List[int]) -> Optional[Tuple[List[str], int]]:
    """``(texts, position behind them)`` of the texts that stand at ``pos``, up to
    where ``marker`` stands (None: as many as there are)."""
    texts: List[str] = []
    while len(texts) <= _MAX_ROW_STRINGS:
        if marker is not None and block[pos:pos + len(marker)] == marker:
            return texts, pos
        steps[0] -= 1
        if steps[0] == 0:
            limits.hit("inno", "more than %d texts read while looking for the [Run] rows: the search was given up"
                       % _MAX_ROW_STEPS)
        found = _text_at(block, pos, wide, _MAX_ROW_TEXT) if steps[0] > 0 else None
        if found is None:
            return (texts, pos) if marker is None else None
        texts.append(found[0])
        pos = found[1]
    return None


def _next_entry(block: bytes, pos: int, wide: bool, marker: bytes,
                steps: List[int]) -> Optional[Tuple[List[str], int]]:
    """The entry that begins at the first place from ``pos`` on from which texts
    lead up to ``marker``."""
    for gap in range(_MAX_ROW_TAIL):
        found = _run_of_texts(block, pos + gap, wide, marker, steps)
        if found is not None and any(found[0]):
            return found
        if steps[0] <= 0:
            return None
    return None


def _entries_behind(block: bytes, start: int, total: int, wide: bool,
                    steps: List[int]) -> Optional[List[List[str]]]:
    """The texts of the ``total`` entries that begin at ``start``.

    Every entry behind the file entries - a shortcut, an .ini or registry
    value, a deletion, a program to run - is a run of texts and then a few
    fixed-size fields, of which the first is the Windows version the entry is
    for. That field is the same in all of them and cannot be read as a text,
    so it marks where the texts of an entry end; the next entry begins at the
    first place behind it from which texts lead up to the same mark again.
    None unless exactly ``total`` entries are found this way - not one fewer,
    and not one more."""
    first = _run_of_texts(block, start, wide, None, steps)
    if first is None or not first[0] or not first[0][0]:
        return None
    # (a Windows version: build, minor and major number, then the service pack)
    marker = block[first[1]:first[1] + 6]
    if len(marker) != 6 or not 4 <= marker[3] <= 10 or marker[2] > 4 or marker[4] or marker[5] > 6:
        return None
    out, pos = [first[0]], first[1] + 6
    while len(out) < total:
        found = _next_entry(block, pos, wide, marker, steps)
        if found is None:
            return None
        out.append(found[0])
        pos = found[1] + 6
    if _next_entry(block, pos, wide, marker, steps) is not None or steps[0] <= 0:
        return None
    return out


def _count_places(block: bytes, code_end: int, end: int, version: Tuple[int, ...]):
    """``(offset, kinds in front of the files, found by search)`` of the places
    where the entry counts of the setup header can stand: right behind the
    compiled ``[Code]`` when there is one (it ends at ``code_end``); without
    ``[Code]`` its text is empty - four zero bytes - and the place is searched
    for in the first part of the block, up to ``end``."""
    before = (8, 7) if version >= (6, 5) else (7, 8)        # 6.5 added a kind in front of the files
    if code_end > 0:
        for skipped in (0, 32):                             # (a table that non-Unicode versions keep)
            for kinds in before:
                yield code_end + skipped, kinds, False
        return
    for at in range(4, min(end, _MAX_HEADER_SEARCH)):
        if block[at - 4:at] == b"\0\0\0\0":
            for skipped in (0, 32):
                for kinds in before:
                    yield at + skipped, kinds, True


def run_rows(block: bytes, code_end: int, files: Files, locations: int, wide: bool,
             version: Tuple[int, ...] = ()) -> Optional[List[Row]]:
    """The ``[Run]`` and ``[UninstallRun]`` rows of the setup script ``block``
    (None = they could not be found).

    The setup header says how many entries of each kind follow; these numbers
    stand right behind the compiled ``[Code]`` (``code_end``; 0 = the installer
    has none, and the numbers are looked for behind its empty text). They are
    accepted when the two that are known from elsewhere fit (file entries,
    data entries) and when exactly that many entries are then found behind the
    file entries. The rows are the last ones of them."""
    if not files.marks:
        return None
    used = max(len(files.names), 1)
    steps = [_MAX_ROW_STEPS]
    for at, kinds, searched in _count_places(block, code_end, len(block), version):
        if at + 4 * (kinds + 2 + _ENTRY_KINDS) > len(block):
            continue
        numbers = struct.unpack_from("<%dI" % (kinds + 2 + _ENTRY_KINDS), block, at)
        entries, data = numbers[kinds], numbers[kinds + 1]
        behind = numbers[kinds + 2:]
        if data != locations or not used <= entries <= 1_000_000 or max(numbers) > 1_000_000:
            continue
        if searched and not 1 <= numbers[0] <= _MAX_LANGUAGES:      # an installer has a language
            continue
        total, rows = sum(behind), behind[-2] + behind[-1]
        if not total:
            return []
        if total > _MAX_ROWS:
            limits.hit("inno", "more than %d entries behind the files: the [Run] rows were not read" % _MAX_ROWS)
            continue
        # where the file entries end is not known to the byte: the first entry behind them
        # is looked for from the last file name on - it begins with a text that is not empty
        begin = files.marks[min(entries, len(files.marks)) - 1]
        for start in range(begin, min(begin + _MAX_ROW_SEARCH, len(block) - 4)):
            if block[start:start + 4] == b"\0\0\0\0":
                continue
            found = _entries_behind(block, start, total, wide, steps)
            if steps[0] <= 0:
                return None
            if found is None:
                continue
            out: List[Row] = []
            for texts in found[len(found) - rows:] if rows else []:
                at_name = next(i for i, text in enumerate(texts) if text)
                out.append(Row(len(out) + 1, texts[at_name],
                               texts[at_name + 1] if at_name + 1 < len(texts) else ""))
            return out
    return None

_MAX_MESSAGE_LINES = 512            # lines that are compared with the standard messages
_MAX_MESSAGE_PLACES = 4096          # places in the block where one such line is looked at
_MAX_MESSAGE_UNITS = 4096           # characters of one stored text


def message_lines(block: bytes, lines, standard, code: Optional[Tuple[int, int]] = None) -> frozenset:
    """Those of ``lines`` (lines of the script's texts) that come from standard
    messages of Inno Setup and from nothing else in the setup script ``block``.

    An installer stores the messages of each of its languages one behind the
    other, each ended by a zero. A line counts when every place in the block
    where its text stands is inside such a stored text that is, as a whole,
    a standard message (``standard(text)``) - and not a text with its length
    in front of it (a custom message, a ``[Run]`` row, a file name), not
    inside the compiled ``[Code]`` (``code``: its offset and length), and not
    a text in single bytes."""
    out = set()
    for line in list(lines)[:_MAX_MESSAGE_LINES]:
        try:
            plain = line.encode("ascii")
        except UnicodeEncodeError:
            continue
        if len(plain) < 4 or plain in block:
            continue
        wide, places, good = line.encode("utf-16-le"), 0, True
        at = block.find(wide)
        while at >= 0 and good and places < _MAX_MESSAGE_PLACES:
            places += 1
            lo, hi = at, at + len(wide)
            while lo >= 2 and at - lo < 2 * _MAX_MESSAGE_UNITS and block[lo - 2] | block[lo - 1] << 8 >= 0x20:
                lo -= 2
            while hi + 2 <= len(block) and hi - at < 2 * _MAX_MESSAGE_UNITS and block[hi] | block[hi + 1] << 8 >= 0x20:
                hi += 2
            text = block[lo:hi].decode("utf-16-le", "replace")
            good = (standard(text)
                    and not (lo >= 4 and struct.unpack_from("<I", block, lo - 4)[0] == hi - lo)
                    and not (code is not None and lo < code[0] + code[1] and hi > code[0]))
            at = block.find(wide, at + 2)
        if good and 0 < places < _MAX_MESSAGE_PLACES:
            out.add(line)
    return frozenset(out)


class Script(bytes):
    """The setup script's strings as text - and, beside them, what the
    instructions of the installer are read from: the unpacked script ``block``
    (it holds the compiled ``[Code]``), the file entries (``files``: source and
    destination of each; None = not known) and the ``[Run]`` rows (``rows``;
    None = not found)."""

    block = b""
    files: Optional[Tuple[Tuple[str, str], ...]] = None
    rows: Optional[Tuple[Row, ...]] = None


def member_name(destination: str) -> str:
    """``{app}\\Data\\x.rxdata`` -> ``Data/x.rxdata``; other folders keep their
    constant as the first path element (``{sys}\\a.dll`` -> ``sys/a.dll``)."""
    name = destination.replace("\\", "/")
    name = re.sub(r"^\{app\}/?", "", name)
    name = re.sub(r"\{([^}]*)\}", lambda m: m.group(1).split(":")[0].split("|")[0], name)
    return name.lstrip("/") or "unnamed"


def _unfilter_4108(data: bytes, base: int) -> bytes:
    """Versions 4.1.8 - 5.1: every E8 / E9 operand had its position added."""
    out = bytearray(data)
    pos, end = 0, len(out)
    while True:
        hit = _JUMP.search(out, pos)
        if hit is None or hit.start() + 5 > end:
            return bytes(out)
        at = hit.start()
        struct.pack_into("<I", out, at + 1,
                         (struct.unpack_from("<I", out, at + 1)[0] - (at + base)) & 0xFFFFFFFF)
        pos = at + 5


def _unfilter_5200(data: bytes, flip: bool) -> bytes:
    """Versions 5.2+: only operands whose high byte is 00 / FF, 24 bits wide,
    never across a 64 KB block; 5.3.9+ also flips the high byte of backward
    jumps."""
    out = bytearray(data)
    pos, end = 0, len(out)
    while True:
        hit = _JUMP.search(out, pos)
        if hit is None:
            return bytes(out)
        at = hit.start()
        pos = at + 1
        if 0x10000 - (at % 0x10000) < 5 or at + 5 > end:
            continue
        pos = at + 5
        if out[at + 4] in (0x00, 0xFF):
            rel = (out[at + 1] | out[at + 2] << 8 | out[at + 3] << 16) - ((at + 5) & 0xFFFFFF)
            out[at + 1], out[at + 2], out[at + 3] = rel & 0xFF, rel >> 8 & 0xFF, rel >> 16 & 0xFF
            if flip and rel & 0x800000:
                out[at + 4] ^= 0xFF


def _checksum(data: bytes, length: int) -> bytes:
    if length == 32:
        return hashlib.sha256(data).digest()
    if length == 20:
        return hashlib.sha1(data).digest()
    if length == 16:
        return hashlib.md5(data).digest()
    return struct.pack("<I", zlib.crc32(data))


def restore(raw: bytes, expected: bytes) -> Optional[bytes]:
    """The file as it is installed: ``raw`` as stored, or with one of the
    executable filters undone - whichever has the checksum the installer
    stores. None if none has (encrypted, damaged, or an unknown filter)."""
    for undo in (lambda d: d, lambda d: _unfilter_5200(d, True), lambda d: _unfilter_5200(d, False),
                 lambda d: _unfilter_4108(d, 5), lambda d: _unfilter_4108(d, 0)):
        data = undo(raw)
        if _checksum(data, len(expected)) == expected:
            return data
        if raw[:2] != b"MZ":                                # only programs are filtered
            break
    return None


_MAX_FILTERED = 1 << 30              # a program this large is still unfiltered in memory


def _restore_any(raw, expected: bytes):
    """:func:`restore` for a member that may live in a temporary file.

    A large member is checked against the installer's checksum as it is
    stored, by reading the file; only a program (which may be filtered) is
    taken into memory, up to 1 GB. A temporary file that fails is removed."""
    if not isinstance(raw, spool.Blob):
        return restore(raw, expected)
    if len(expected) == 32 and raw.sha256 == expected.hex():
        return raw
    digest = {20: hashlib.sha1, 16: hashlib.md5}.get(len(expected))
    crc = 0
    with open(raw.path, "rb") as fh:
        state = digest() if digest else None
        for piece in iter(lambda: fh.read(_CHUNK), b""):
            if state is not None:
                state.update(piece)
            else:
                crc = zlib.crc32(piece, crc)
    if len(expected) != 32 and (state.digest() if state is not None
                                else struct.pack("<I", crc)) == expected:
        return raw
    data = None
    if raw.data[:2] == b"MZ" and raw.size > _MAX_FILTERED:
        limits.hit("inno", "a program of more than %d MB: it could not be put back into its original form"
                   % (_MAX_FILTERED >> 20))
    if raw.data[:2] == b"MZ" and raw.size <= _MAX_FILTERED:
        data = restore(raw.read(), expected)
    raw.release()
    return data


class Installer:
    """An Inno Setup installer whose layout was recognised.

    ``data`` is the installer as far as it is in memory, ``open_file()`` gives
    the whole file, ``signature`` is the offset of the setup signature and
    ``first`` the offset where the installer's own program ends. ``slices``
    opens ``setup-N.bin`` (N = 1, 2, ...) when the data is not in the
    installer itself. Raises :class:`InnoError` if anything does not fit."""

    def __init__(self, open_file: Callable[[], BinaryIO], signature: int, first: int,
                 chunk_offsets: List[int],
                 slices: Optional[Callable[[int], Optional[BinaryIO]]] = None) -> None:
        self.open_file, self.slices = open_file, slices
        with open_file() as stream:
            stream.seek(signature)
            head = stream.read(64)
            self.version = version(head)
            parts = blocks(stream, signature)
            size = stream.seek(0, 2)
        if len(parts) < 2:
            raise InnoError("data entries not found")
        self.script = parts[0]
        try:
            self.entries = data_entries(parts[1], size)
        except InnoError:                                   # (the data may be in setup-N.bin files)
            self.entries = data_entries(parts[1])
        self.wide = wide = b"(u)" in head or self.version >= (6, 0, 0)
        try:
            # (the file entries lie behind the setup header)
            self.files = file_entries(parts[0], len(self.entries), wide,
                                      header_end(parts[0], len(self.entries), self.version))
        except InnoError:
            self.files = file_entries(parts[0], len(self.entries), wide)
        self.names = {index: member_name(name) for index, name in self.files.names.items()}
        inside = [at for at in chunk_offsets if first <= at < signature] or chunk_offsets
        self.external = not inside
        if self.external:
            if slices is None:
                raise InnoError("the data is in separate setup-N.bin files that are not at hand")
            self.base = 0
        else:
            self.base = min(inside) - min(e.start for e in self.entries)
            if any(self.base + e.start not in inside for e in self.entries):
                raise InnoError("data entries do not point at the data chunks")

    def script_member(self, text: bytes) -> Script:
        """``text`` (the script's strings) with what the installer's instructions
        are read from beside it."""
        out = Script(text)
        out.block, out.files = self.script, self.files.rows
        where = ifps.locate(self.script)
        if where is not None or not ifps.named(self.script):
            rows = run_rows(self.script, where[0] + where[1] if where else 0, self.files,
                            len(self.entries), self.wide, self.version)
            out.rows = None if rows is None else tuple(rows)
        return out

    def members(self, want: Callable[[str, int], bool], cancel=None, tick=None,
                problems: Optional[List[str]] = None) -> Iterator[Tuple[str, bytes]]:
        """``(name, content)`` of every installed file ``want(name, size)``
        accepts - byte-identical to what the installer would write."""
        order = sorted(range(len(self.entries)), key=lambda i: (
            self.entries[i].slice, self.entries[i].start, self.entries[i].offset))
        wanted = [i for i in order if want(self.names.get(i, "unnamed_%d" % i),
                                           self.entries[i].size)]
        failed, at = 0, 0
        streams: Dict[int, BinaryIO] = {}
        try:
            while at < len(wanted) and not (cancel is not None and cancel.is_set()):
                head = self.entries[wanted[at]]
                group = [i for i in wanted[at:] if (self.entries[i].slice, self.entries[i].start)
                         == (head.slice, head.start)]
                at += len(group)
                stream = streams.get(head.slice)
                if stream is None:
                    stream = self.slices(head.slice + 1) if self.external else self.open_file()
                    if stream is None:
                        raise InnoError("setup-%d.bin is missing" % (head.slice + 1))
                    streams[head.slice] = stream
                entries = [self.entries[i] for i in group]
                for index, raw in self._cut(stream, head, entries, group):
                    entry = self.entries[index]
                    data = _restore_any(raw, entry.checksum) \
                        if spool.size_of(raw) == entry.size else None
                    if data is None and len(group) == 1:
                        # a chunk that only looked compressed: take it as stored
                        for _i, raw in self._cut(stream, head, entries, group, stored=True):
                            data = _restore_any(raw, entry.checksum) \
                                if spool.size_of(raw) == entry.size else None
                    if data is None:
                        failed += 1
                        continue
                    yield self.names.get(index, "unnamed_%d" % index), data
                if tick is not None:
                    tick(at / max(len(wanted), 1))
        finally:
            for stream in streams.values():
                stream.close()
        if failed and problems is not None:
            problems.append("%d file(s) could not be rebuilt to the installer's own checksum "
                            "(encrypted, or damaged)" % failed)

    def _cut(self, stream: BinaryIO, head: Entry, entries: List[Entry], indexes: List[int],
             stored: bool = False):
        """The stored bytes of the given files of one chunk, in order, while the
        chunk is unpacked piece by piece (a solid chunk can be gigabytes)."""
        start = self.base + head.start
        stream.seek(start)
        if stream.read(4) != CHUNK_MAGIC:
            return
        decoder, skip = (None, 0) if stored else _chunk_decoder(stream.read(16))
        end = start + 4 + head.packed
        yield from self._slice(self._pieces(stream, start + 4, end, decoder, skip), entries, indexes)

    @staticmethod
    def _pieces(stream: BinaryIO, start: int, end: int, decoder, skip: int) -> Iterator[bytes]:
        stream.seek(start + skip)
        left = end - start - skip
        try:
            while left > 0:
                feed = stream.read(min(left, _CHUNK))
                if not feed:
                    return
                left -= len(feed)
                if decoder is None:
                    yield feed
                    continue
                while True:
                    piece = decoder.decompress(feed, _CHUNK)
                    if piece:
                        yield piece
                    if decoder.eof:
                        return
                    if isinstance(decoder, lzma.LZMADecompressor):
                        if decoder.needs_input:
                            break
                        feed = b""
                    else:
                        feed = decoder.unconsumed_tail
                        if not feed:
                            break
        except _ERRORS:
            return

    @staticmethod
    def _slice(pieces: Iterator[bytes], entries: List[Entry], indexes: List[int]):
        position, current, parts = 0, 0, spool.Collector()
        for piece in pieces:
            lo = position
            position += len(piece)
            while current < len(entries):
                entry = entries[current]
                a, b = max(entry.offset, lo), min(entry.offset + entry.size, position)
                if b > a:
                    parts.write(piece[a - lo:b - lo])
                if entry.offset + entry.size > position:
                    break
                yield indexes[current], parts.result()
                parts, current = spool.Collector(), current + 1
            if current >= len(entries):
                return
