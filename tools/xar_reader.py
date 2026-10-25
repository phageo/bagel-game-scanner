"""Read the programs out of a macOS installer package (``.pkg``) - for
``tools/build_engine_hashes.py`` only; the scanner does not use it.

Unity publishes the Windows player files for its macOS editor as such a
package. It is a xar archive: a fixed header, a zlib-compressed XML table of
contents, then the "heap" with the members' data. The files to install are in
members named ``Payload``: a cpio archive (the old ASCII form, ``070707``),
compressed with gzip or xz.

Standard library only. Nothing is unpacked to disk and nothing is run: the
payload is read as a stream, each program in it is hashed, everything else is
skipped. Every step has a limit. A package in another form - a ``pbzx``
payload, a binary or "new" cpio, another compression - is refused with
:class:`FormatError`; it is not guessed at.
"""
from __future__ import annotations

import gzip
import hashlib
import lzma
import struct
import time
import xml.etree.ElementTree as ET
import zlib
from typing import BinaryIO, Dict, Iterator, List, Tuple

MAGIC = b"xar!"
MAX_TOC = 64 * 1024 * 1024               # the table of contents, unpacked
MAX_TOC_PACKED = 16 * 1024 * 1024
MAX_ENTRIES = 100_000                    # members named in the table of contents
MAX_DEPTH = 32                           # folders inside folders in the table of contents
MAX_PAYLOADS = 16
MAX_MEMBERS = 200_000                    # files in one payload
MAX_NAME = 4096
MAX_MEMBER = 512 * 1024 * 1024           # one file of a payload
MAX_UNPACKED = 4 * 1024 * 1024 * 1024    # one payload, unpacked
MAX_SECONDS = 1800
_CHUNK = 1 << 20
PROGRAMS = (".exe", ".dll")


class FormatError(Exception):
    """The package is not in the one form this reader knows."""


class _Slice:
    """A file-like view of ``length`` bytes of ``stream`` from ``start``."""

    def __init__(self, stream: BinaryIO, start: int, length: int) -> None:
        self.stream, self.start, self.length, self.at = stream, start, length, 0

    def read(self, size: int = -1) -> bytes:
        left = self.length - self.at
        if size is None or size < 0 or size > left:
            size = left
        if size <= 0:
            return b""
        self.stream.seek(self.start + self.at)
        data = self.stream.read(size)
        self.at += len(data)
        return data

    def seekable(self) -> bool:
        return False

    def readable(self) -> bool:
        return True


def _entries(node, prefix: str, depth: int, out: List[Tuple[str, int, int, str]]) -> None:
    if depth > MAX_DEPTH:
        raise FormatError("the table of contents is nested too deeply")
    for child in node.findall("file"):
        if len(out) >= MAX_ENTRIES:
            raise FormatError("too many members in the table of contents")
        name = prefix + (child.findtext("name") or "")
        data = child.find("data")
        if data is not None:
            encoding = data.find("encoding")
            style = encoding.get("style", "") if encoding is not None else ""
            try:
                out.append((name, int(data.findtext("offset") or "-1"), int(data.findtext("length") or "-1"),
                            style))
            except ValueError:
                raise FormatError("a member's place is not a number: " + name)
        _entries(child, name + "/", depth + 1, out)


def table_of_contents(stream: BinaryIO) -> Tuple[int, List[Tuple[str, int, int, str]]]:
    """``(start of the heap, [(name, offset in the heap, stored length, how it
    is stored)])`` of a xar archive."""
    stream.seek(0)
    head = stream.read(28)
    if len(head) < 28 or head[:4] != MAGIC:
        raise FormatError("not a xar archive")
    header_size, _version, packed, unpacked, _checksum = struct.unpack(">HHQQI", head[4:28])
    if header_size < 28 or header_size > 4096 or packed > MAX_TOC_PACKED or unpacked > MAX_TOC:
        raise FormatError("the header of the archive is outside the limits")
    stream.seek(header_size)
    raw = stream.read(packed)
    if len(raw) != packed:
        raise FormatError("the table of contents is cut off")
    unpacker = zlib.decompressobj()
    try:
        text = unpacker.decompress(raw, MAX_TOC + 1)
    except zlib.error as exc:
        raise FormatError("the table of contents cannot be unpacked: %s" % exc)
    if len(text) > MAX_TOC or len(text) != unpacked:
        raise FormatError("the table of contents has another size than the header says")
    if b"<!DOCTYPE" in text or b"<!ENTITY" in text:
        raise FormatError("the table of contents declares entities")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise FormatError("the table of contents cannot be read: %s" % exc)
    toc = root.find("toc")
    if toc is None:
        raise FormatError("the archive has no table of contents")
    out: List[Tuple[str, int, int, str]] = []
    _entries(toc, "", 0, out)
    return header_size + packed, out


def _payload_stream(stream: BinaryIO, start: int, length: int, style: str):
    """The cpio archive of a ``Payload`` member, as a stream."""
    if style not in ("application/octet-stream", ""):
        raise FormatError("the payload is stored in another way than this reader knows: %s" % style)
    piece = _Slice(stream, start, length)
    stream.seek(start)
    magic = stream.read(6)
    if magic[:4] == b"pbzx":
        raise FormatError("the payload is in the pbzx form")
    if magic[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=piece, mode="rb")
    if magic == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(piece, "rb", format=lzma.FORMAT_XZ)
    if magic == b"070707":
        return piece
    raise FormatError("the payload is neither a gzip nor an xz stream (it starts with %r)" % magic)


def _exactly(source, size: int) -> bytes:
    out = b""
    while len(out) < size:
        block = source.read(size - len(out))
        if not block:
            raise FormatError("the payload ends in the middle of a file")
        out += block
    return out


def cpio_members(source, deadline: float) -> Iterator[Tuple[str, int, object]]:
    """``(name, size, reader)`` for each regular file of an ASCII cpio stream
    (``070707``). ``reader(n)`` gives the next bytes of that file; what is not
    read is skipped."""
    total = count = 0
    while True:
        head = _exactly(source, 76)
        if head[:6] != b"070707":
            raise FormatError("the payload is not an ASCII cpio archive (it has %r)" % head[:6])
        try:
            mode = int(head[18:24], 8)
            name_size = int(head[59:65], 8)
            size = int(head[65:76], 8)
        except ValueError:
            raise FormatError("a cpio header is not made of octal digits")
        if name_size < 1 or name_size > MAX_NAME or size > MAX_MEMBER:
            raise FormatError("a file of the payload is outside the limits")
        name = _exactly(source, name_size).rstrip(b"\x00").decode("utf-8", "replace")
        if name == "TRAILER!!!":
            return
        count += 1
        total += size
        if count > MAX_MEMBERS or total > MAX_UNPACKED:
            raise FormatError("the payload is outside the limits")
        if time.monotonic() > deadline:
            raise FormatError("reading the payload took too long")
        left = [size]

        def reader(wanted: int, left=left) -> bytes:
            data = source.read(min(wanted, left[0])) if left[0] else b""
            if left[0] and not data:
                raise FormatError("the payload ends in the middle of a file")
            left[0] -= len(data)
            return data
        yield name, (size if mode & 0o170000 == 0o100000 else -1), reader
        while left[0]:
            reader(_CHUNK)


def hash_programs(path: str) -> Dict[str, str]:
    """``{sha256: file name}`` of every Windows program and library (``.exe``,
    ``.dll``, starting with ``MZ``) in the payloads of a ``.pkg``."""
    out: Dict[str, str] = {}
    deadline = time.monotonic() + MAX_SECONDS
    with open(path, "rb") as stream:
        heap, entries = table_of_contents(stream)
        end = stream.seek(0, 2)
        payloads = [entry for entry in entries if entry[0].rsplit("/", 1)[-1] == "Payload"]
        if not payloads or len(payloads) > MAX_PAYLOADS:
            raise FormatError("expected one or a few payloads, found %d" % len(payloads))
        for name, offset, length, style in payloads:
            if offset < 0 or length <= 0 or heap + offset + length > end:
                raise FormatError("a payload lies outside the archive: " + name)
            source = _payload_stream(stream, heap + offset, length, style)
            try:
                for member, size, reader in cpio_members(source, deadline):
                    if size <= 0 or not member.lower().endswith(PROGRAMS):
                        continue
                    digest = hashlib.sha256()
                    head = b""
                    while True:
                        block = reader(_CHUNK)
                        if not block:
                            break
                        head = head or block[:2]
                        digest.update(block)
                    if head == b"MZ":                         # a Windows program, by content
                        out.setdefault(digest.hexdigest(), member.replace("\\", "/").rsplit("/", 1)[-1])
            except (OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
                raise FormatError("the payload cannot be unpacked: %s" % exc)
    return out
