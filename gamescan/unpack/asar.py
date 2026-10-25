"""Electron's ``app.asar``: the archive an Electron game keeps its own code in.

Read as data, with the standard library only. The format is simple and has
no compression:

    4 bytes   the number 4
    4 bytes   size of the header block
    4 bytes   size of what follows in it
    4 bytes   length of the list of files
    ...       the list of files, as JSON text (padded to four bytes)
    ...       the files, back to back

The JSON is a tree: a folder is ``{"files": {...}}``, a file is ``{"size": n,
"offset": "n"}`` (the offset is a text, counted from the end of the header
block), a file that lies *beside* the archive (in ``app.asar.unpacked``) is
marked ``"unpacked": true``, a link is ``{"link": "path"}``.

Nothing is run and nothing is trusted: sizes and offsets are checked against
the archive before anything is read, the depth of folders and the number of
files are limited, and every limit that is reached says so
(:mod:`gamescan.unpack.limits`). An archive that is encrypted - some tools
scramble the list or the files - or damaged raises :class:`AsarError`; the
caller reports it as not read.
"""
from __future__ import annotations

import json
import struct
from typing import BinaryIO, List, NamedTuple

from . import limits, spool

_MAX_HEADER = 64 * 1024 * 1024          # the list of files, as JSON
_MAX_FILES = 200_000                    # files of one archive that are listed
_MAX_DEPTH = 64                         # folders inside folders
_MAX_NAME = 1024                        # characters of one path


class AsarError(ValueError):
    """Not an asar archive of the known layout, or a damaged one."""


class Entry(NamedTuple):
    name: str               # path inside the archive, with "/"
    size: int
    offset: int             # from the start of the archive file
    unpacked: bool          # the file is not in the archive: it lies beside it


def looks_like(head: bytes) -> bool:
    """Do the first 16 bytes read like the head of an asar archive?"""
    if len(head) < 16:
        return False
    four, block, inner, text = struct.unpack_from("<IIII", head)
    return four == 4 and 8 <= inner + 4 <= block + 4 and 2 <= text <= inner and block <= _MAX_HEADER + 16


def entries(stream: BinaryIO) -> List[Entry]:
    """The files of the archive, in the order of its list. ``stream`` must
    start at the archive. Raises :class:`AsarError`."""
    total = stream.seek(0, 2)
    stream.seek(0)
    head = stream.read(16)
    if not looks_like(head):
        raise AsarError("not an asar archive of the known layout (encrypted, or another format)")
    _four, block, _inner, length = struct.unpack_from("<IIII", head)
    if length > _MAX_HEADER:
        raise AsarError(limits.hit("asar", "a list of files larger than %d MB" % (_MAX_HEADER >> 20)))
    base = 8 + block                                    # where the files begin
    if base > total or 16 + length > total:
        raise AsarError("the archive is cut short (its list of files does not fit)")
    raw = stream.read(length)
    try:
        listing = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise AsarError("the list of files cannot be read (encrypted or damaged)")
    if not isinstance(listing, dict) or not isinstance(listing.get("files"), dict):
        raise AsarError("the list of files has an unknown form")
    out: List[Entry] = []
    stack = [("", listing["files"], 0)]
    while stack:
        prefix, folder, depth = stack.pop()
        if depth > _MAX_DEPTH:
            limits.hit("asar", "folders nested deeper than %d: what is below was not read" % _MAX_DEPTH)
            continue
        # (sorted backwards and taken from the end: the files come out in the order of their names)
        for name in sorted(folder, reverse=True):
            item = folder[name]
            if not isinstance(name, str) or not isinstance(item, dict):
                raise AsarError("the list of files has an unknown form")
            path = (prefix + name)[:_MAX_NAME]
            if isinstance(item.get("files"), dict):
                stack.append((path + "/", item["files"], depth + 1))
                continue
            if "link" in item:
                continue                                # a link names another file of the archive
            size, offset = item.get("size"), item.get("offset")
            unpacked = bool(item.get("unpacked"))
            if unpacked:
                out.append(Entry(path, size if isinstance(size, int) and size >= 0 else 0, 0, True))
                continue
            try:
                offset = int(offset)
            except (TypeError, ValueError):
                raise AsarError("a file without a place in the archive (encrypted or damaged)")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0 or offset < 0 \
                    or base + offset + size > total:
                raise AsarError("a file that does not fit into the archive (damaged)")
            if len(out) >= _MAX_FILES:
                limits.hit("asar", "more than %d files: the rest was not read" % _MAX_FILES)
                return out
            out.append(Entry(path, size, base + offset, False))
    return out


def read(stream: BinaryIO, entry: Entry):
    """The content of one file of the archive (``bytes``, or a
    :class:`spool.Blob` when it is large)."""
    if entry.unpacked:
        raise AsarError("the file lies beside the archive, not in it")
    stream.seek(entry.offset)

    def pieces():
        left = entry.size
        while left > 0:
            piece = stream.read(min(left, 1 << 20))
            if not piece:
                raise AsarError("a file of the archive is cut short")
            left -= len(piece)
            yield piece
    return spool.collect(pieces())
