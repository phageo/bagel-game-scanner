"""Unity asset unpacker: UnityFS bundle decompression and executable carving.

``.assets`` files are stored uncompressed; asset *bundles* (``UnityFS``) are
LZ4- or LZMA-compressed blocks. After decompression the content is scanned
for strings, and any Windows executable hidden inside is carved out so it
can be analysed like a normal file.

Everything here is *streaming*: a bundle is decoded one block at a time
(:class:`Stream`) and looked at through a sliding window (:class:`Carver`),
so a multi-gigabyte file is inspected from start to end while only a few
megabytes of it are in memory at any moment.
"""
from __future__ import annotations

import collections
import io
import lzma
import struct
from typing import Any, BinaryIO, Iterator, List, Optional, Tuple

from ..pe import parse_pe
from . import limits, lz4block

MAGIC = b"UnityFS\0"
CHUNK = 1 << 20                        # raw read size / largest piece a Stream yields at once
WINDOW = 8 * 1024 * 1024               # how much decoded content is looked at in one go
_MAX_OUT = 64 * 1024 * 1024            # unpack(): in-memory result; also one LZ4 block
_MAX_INFO = 64 * 1024 * 1024           # block table of a bundle
_MAX_STREAM = 64 << 30                 # decoded bytes of one bundle, absolute ...
_MAX_RATIO = 20                        # ... and relative to its size on disk (+ 1 GB)
_MAX_IMAGE = 32 * 1024 * 1024          # one carved executable
_MAX_CARVED = 128 * 1024 * 1024        # all carved executables of one file
_BATCH = 1024 * 1024                   # packed / decoded bytes handed to one worker at a time
_POOL_MIN = 48 * 1024 * 1024           # LZ4 data in a bundle that makes worker processes pay off
_OVERLAP = 16 * 1024                   # > a PE header probe; strings on a seam are seen whole
_MEDIA = (".ress", ".resource")       # raw texture / mesh / audio streams inside a bundle
_ERRORS = (struct.error, IndexError, ValueError, lzma.LZMAError, EOFError, OSError)


class UnityError(ValueError):
    """The bundle is damaged, of an unknown layout or over a limit."""


lz4_block = lz4block.block             # (kept under its old name)


def _lzma_decoder(props: bytes) -> lzma.LZMADecompressor:
    """Decoder for Unity's headerless LZMA: 1 properties byte + 4 bytes dictionary size."""
    if len(props) < 5:
        raise ValueError("truncated LZMA block")
    prop, dict_size = props[0], struct.unpack_from("<I", props, 1)[0]
    lc, rest = prop % 9, prop // 9
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": rest % 5, "pb": rest // 5}])


def _lzma_block(src: bytes, size: int) -> bytes:
    if size > _MAX_OUT:
        limits.hit("unity", "an LZMA block that claims more than %d MB: only that much was unpacked" % (_MAX_OUT >> 20))
    return _lzma_decoder(src[:5]).decompress(src[5:], max_length=min(size, _MAX_OUT))  # size is attacker-chosen


def _decompress(src: bytes, method: int, size: int) -> bytes:
    if method == 0:
        return src
    if method == 1:
        return _lzma_block(src, size)
    if method in (2, 3):
        return lz4_block(src)
    raise ValueError("unknown compression %d" % method)


def _cstr(data: bytes, pos: int) -> int:
    return data.index(b"\0", pos) + 1


def _exactly(fh: BinaryIO, count: int) -> bytes:
    data = fh.read(count)
    if len(data) != count:
        raise EOFError("unexpected end of bundle")
    return data


# -- streaming decoder ----------------------------------------------------------------
class Stream:
    """The content of a Unity file, piece by piece.

    Iterating yields ``bytes`` of at most a few megabytes each: the decoded
    blocks of a ``UnityFS`` bundle, or - for a plain ``.assets`` file, and for a
    bundle whose header cannot be read - the file as it is on disk.

    After (or during) iteration:
      ``bundle``    the file starts with the UnityFS magic
      ``decoded``   its block table was read, so the pieces are decoded content
      ``problem``   "" or why decoding stopped before the end
      ``produced``  bytes yielded so far
      ``consumed``  bytes of the file dealt with so far (``consumed / size`` = progress)
      ``media``     ``(start, end)`` ranges of the decoded content that the bundle's
                    directory lists as raw texture / mesh / audio streams
    """

    def __init__(self, fh: BinaryIO, size: Optional[int] = None, cancel: Any = None,
                 workers: Optional[int] = None) -> None:
        if size is None:
            size = fh.seek(0, 2)
        self.fh, self.size, self.cancel = fh, size, cancel
        self.bundle = self.decoded = False
        self.problem = ""
        self.produced = 0
        self.consumed = 0                  # bytes of the file dealt with so far (for progress)
        self.workers = workers             # LZ4 worker processes: None = decide, 0 = never
        self.media: List[Tuple[int, int]] = []
        self.limit = min(_MAX_STREAM, (1 << 30) + _MAX_RATIO * size)

    def _layout(self) -> Tuple[int, List[Tuple[int, int, int]]]:
        """``(offset of the first block, [(decoded size, stored size, flags)])``."""
        fh, size = self.fh, self.size
        fh.seek(0)
        head = fh.read(4096)
        pos = len(MAGIC)
        version = struct.unpack_from(">I", head, pos)[0]
        pos = _cstr(head, _cstr(head, pos + 4))            # unity version, revision
        _size, csize, usize, flags = struct.unpack_from(">qIII", head, pos)
        pos += 20
        if version >= 7:
            pos = (pos + 15) & ~15
        if csize > _MAX_INFO or usize > _MAX_INFO:
            raise ValueError(limits.hit("unity", "implausible block table size (more than %d MB)" % (_MAX_INFO >> 20)))
        if csize > size:
            raise ValueError("implausible block table size")
        if flags & 0x80:                                   # block info at end of file
            fh.seek(size - csize)
            body = pos
        else:
            fh.seek(pos)
            body = pos + csize
        if flags & 0x200:
            body = (body + 15) & ~15
        info = _decompress(_exactly(fh, csize), flags & 0x3F, usize)
        count = struct.unpack_from(">I", info, 16)[0]
        if count > (len(info) - 20) // 10:
            raise ValueError("block table is cut short")
        self.media = self._media(info, 20 + 10 * count)
        return body, [struct.unpack_from(">IIH", info, 20 + 10 * i) for i in range(count)]

    @staticmethod
    def _media(info: bytes, pos: int) -> List[Tuple[int, int]]:
        """Where the bundle's directory says its media streams are."""
        out: List[Tuple[int, int]] = []
        try:
            count = struct.unpack_from(">I", info, pos)[0]
            pos += 4
            for _ in range(min(count, 100_000)):
                offset, size, _flags = struct.unpack_from(">qqI", info, pos)
                end = info.index(b"\0", pos + 20)
                if info[pos + 20:end].lower().endswith(tuple(m.encode() for m in _MEDIA)):
                    out.append((offset, offset + size))
                pos = end + 1
        except (struct.error, ValueError):
            return []                                      # unknown directory: treat all as text
        return sorted(out)

    def split(self, offset: int, window: bytes) -> Tuple[bytes, bytes]:
        """``(asset data, media data)`` of ``window``, which starts at ``offset``
        of the decoded content: the parts that the bundle's directory lists as
        raw texture / mesh / audio streams, and everything else.

        Both are read. The split only decides *how*: asset data like any asset
        file; media streams - gigabytes of pixels and samples - with
        :func:`gamescan.unpack.media.runs`, which returns every printable run
        of eight or more characters and so reads a command line or script of
        any size between binary data without wading through shorter noise."""
        if not self.media:
            return window, b""
        plain, media, at, end = [], [], offset, offset + len(window)
        for start, stop in self.media:
            if stop <= at or start >= end:
                continue
            if start > at:
                plain.append(window[at - offset:start - offset])
            media.append(window[max(at, start) - offset:min(stop, end) - offset])
            at = max(at, stop)
            if at >= end:
                break
        if at < end:
            plain.append(window[at - offset:])
        return b"\0".join(plain), b"\0".join(media)

    def text_of(self, offset: int, window: bytes) -> bytes:
        """The asset-data part of ``window`` (see :meth:`split`)."""
        return self.split(offset, window)[0]

    def _cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def __iter__(self) -> Iterator[bytes]:
        fh = self.fh
        fh.seek(0)
        self.bundle = fh.read(len(MAGIC)) == MAGIC
        blocks = None
        if self.bundle:
            try:
                body, blocks = self._layout()
                self.decoded = True
            except _ERRORS as exc:                         # truncated / newer layout
                self.problem = "bundle header could not be read (%s)" % exc
        if blocks is None:                                 # plain file: as it is on disk
            fh.seek(0)
            while not self._cancelled():
                piece = fh.read(CHUNK)
                if not piece:
                    break
                self.produced += len(piece)
                self.consumed += len(piece)
                yield piece
            return
        packed = sum(csize for _usize, csize, flags in blocks if flags & 0x3F in (2, 3))
        pool = None
        if self.workers != 0 and not lz4block.native() and (
                packed >= _POOL_MIN or self.workers) and lz4block.default_workers() > 1:
            pool = lz4block.Pool(self.workers)             # pure Python, but on every core
        try:
            pieces = self._parallel(blocks, body, pool) if pool else self._serial(blocks, body)
            for piece in pieces:
                self.produced += len(piece)
                if self.produced > self.limit:
                    # (_MAX_STREAM, and _MAX_RATIO times the size on disk)
                    raise UnityError(limits.hit("unity", "bundle expands beyond the %d MB limit"
                                                % (self.limit >> 20)))
                yield piece
        except _ERRORS as exc:
            self.problem = "decoding stopped after %d MB (%s)" % (self.produced >> 20, exc)
        finally:
            if pool is not None:
                pool.close()

    def _serial(self, blocks, body: int) -> Iterator[bytes]:
        position = body
        for usize, csize, flags in blocks:
            if self._cancelled():
                return
            self.fh.seek(position)
            position += csize
            yield from self._block(usize, csize, flags & 0x3F)
            self.consumed = position

    def _parallel(self, blocks, body: int, pool: "lz4block.Pool") -> Iterator[bytes]:
        """Like :meth:`_serial`, with the LZ4 blocks decoded by worker processes.
        Blocks are read here, a few megabytes ahead, and come back in order."""
        fh = self.fh
        order: "collections.deque" = collections.deque()   # one entry per batch handed out
        failure: List[BaseException] = []

        def packed(first: int, specs):
            # one read per batch, not one per block: every read lets go of the
            # interpreter lock, and getting it back among the reply threads is slow
            fh.seek(first)
            raw = _exactly(fh, sum(csize for _usize, csize in specs))
            batch, at = [], 0
            for usize, csize in specs:
                batch.append((usize, raw[at:at + csize]))
                at += csize
            return batch

        def batches():
            position, first, specs, size, room = body, body, [], 0, 0
            try:
                for usize, csize, flags in blocks:
                    if self._cancelled():
                        break
                    method = flags & 0x3F
                    start, position = position, position + csize
                    inline = method not in (2, 3) or max(csize, usize) > _BATCH
                    if specs and (inline or size + csize > _BATCH or room + usize > _BATCH):
                        order.append((None, start))
                        yield packed(first, specs)
                        specs, size, room = [], 0, 0
                    if inline:
                        order.append(((usize, csize, method, start), position))
                        yield []                           # decoded in this process, in its turn
                    else:
                        if not specs:
                            first = start
                        specs.append((usize, csize))
                        size += csize
                        room += usize
                if specs:
                    order.append((None, position))
                    yield packed(first, specs)
            except _ERRORS as exc:                         # let what is in flight come out first
                failure.append(exc)
        for decoded in pool.map(batches()):
            other, position = order.popleft()
            if self._cancelled():
                return
            if other is not None:
                usize, csize, method, start = other
                fh.seek(start)
                yield from self._block(usize, csize, method)
            for piece in decoded:
                if piece is None:
                    raise UnityError("corrupt LZ4 block")
                yield piece
            self.consumed = position
        if failure:
            raise failure[0]

    def _block(self, usize: int, csize: int, method: int) -> Iterator[bytes]:
        fh = self.fh
        if method == 0:                                    # stored
            left = csize
            while left > 0 and not self._cancelled():
                piece = _exactly(fh, min(left, CHUNK))
                left -= len(piece)
                yield piece
        elif method == 1:                                  # LZMA: often ONE block for everything
            decoder = _lzma_decoder(_exactly(fh, min(5, csize)))
            left, out = csize - 5, 0
            while out < usize and not decoder.eof and not self._cancelled():
                if decoder.needs_input:
                    if left <= 0:
                        break
                    feed = _exactly(fh, min(left, CHUNK))
                    left -= len(feed)
                else:
                    feed = b""
                piece = decoder.decompress(feed, max_length=min(CHUNK, usize - out))
                out += len(piece)
                if piece:
                    yield piece
                elif not feed:
                    break                                  # no progress: damaged stream
        elif method in (2, 3):                             # LZ4 / LZ4HC: small independent blocks
            if csize > _MAX_OUT or usize > _MAX_OUT:
                raise UnityError(limits.hit("unity", "LZ4 block larger than %d MB" % (_MAX_OUT >> 20)))
            yield lz4_block(_exactly(fh, csize), usize)
        else:
            raise UnityError("unknown compression %d" % method)


def unpack(data: bytes) -> Tuple[bytes, bool]:
    """``(content, was_bundle)``: decompressed bundle payload, or the data as-is.

    In-memory convenience for small inputs; large files go through
    :class:`Stream` directly."""
    if not data.startswith(MAGIC):
        return data, False
    stream = Stream(io.BytesIO(data), len(data))
    out = bytearray()
    for piece in stream:
        out += piece
        if len(out) >= _MAX_OUT:
            limits.hit("unity", "a bundle read in memory unpacks to more than %d MB: the rest was not read" % (_MAX_OUT >> 20))
            break
    if stream.problem:
        return data, True                                  # truncated / newer layout
    return bytes(out[:_MAX_OUT]), True


# -- executable carving ---------------------------------------------------------------
def _candidates(data, end: int, limit: int = 200_000) -> Iterator[int]:
    """Positions of ``MZ`` before ``end``. (``find`` is several times faster than a
    regex here, and a file of "MZMZMZ..." is still finite work.)"""
    pos = data.find(b"MZ", 0, end)
    while pos >= 0 and limit > 0:
        yield pos
        limit -= 1
        pos = data.find(b"MZ", pos + 2, end)


def _image_at(data, pos: int) -> Optional[Tuple[int, bool]]:
    """``(size, is_dll)`` if a Windows executable starts at ``pos``."""
    if pos + 0x40 > len(data):
        return None
    lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
    if not 0x40 <= lfanew <= 0x1000 or data[pos + lfanew:pos + lfanew + 4] != b"PE\0\0":
        return None
    pe = parse_pe(bytes(data[pos:pos + 4096 + lfanew]))
    if pe is None or not pe.sections:
        return None
    return max(s.raw_ptr + s.raw_size for s in pe.sections), pe.is_dll


def carve_executables(data: bytes, limit: int = 16) -> List[Tuple[int, bytes, bool]]:
    """``(offset, image, is_dll)`` for each Windows executable embedded in ``data``."""
    out: List[Tuple[int, bytes, bool]] = []
    for pos in _candidates(data, len(data)):
        if pos + 0x40 > len(data):
            break
        image = _image_at(data, pos)
        if image is None:
            continue
        out.append((pos, data[pos:pos + image[0]], image[1]))
        if len(out) >= limit:
            break
    return out


class Carver:
    """Sliding window over a stream of pieces.

    ``for offset, window in carver.windows(pieces)`` hands out the content in
    overlapping windows of about ``window`` bytes for string scanning, and
    collects every embedded Windows executable in ``carver.images`` as
    ``(offset in the stream, image, is_dll)`` - including images that lie
    across the seam between two windows, which are held back until they are
    complete. Memory use is bounded by ``window`` plus one image.
    """

    def __init__(self, window: int = WINDOW, limit: int = 16) -> None:
        self.window, self.limit = max(window, 4 * _OVERLAP), limit
        self.images: List[Tuple[int, bytes, bool]] = []
        self._carved = 0

    def windows(self, pieces) -> Iterator[Tuple[int, bytes]]:
        held: List[bytes] = []                 # carried-over tail + pieces not looked at yet
        filled, base = 0, 0                    # bytes in ``held``; stream offset of held[0]
        scanned = 0                            # stream offset up to which windows were yielded
        need = self.window                     # fill level that triggers the next round
        for piece in pieces:
            held.append(piece)
            filled += len(piece)
            if filled < need:
                continue
            buffer = b"".join(held)            # one copy per window, not one per piece
            keep = self._carve(buffer, base, final=False)
            start = max(0, scanned - base - _OVERLAP)
            yield base + start, buffer[start:] if start else buffer
            scanned = base + len(buffer)
            # an image that starts at ``keep`` is not complete yet: read on
            # until it is (bounded by _MAX_IMAGE), then look again
            need = self.window if keep is None else keep[1] + _OVERLAP
            cut = len(buffer) - _OVERLAP if keep is None else keep[0]
            held = [buffer[cut:]]
            filled = len(held[0])
            base += cut
        buffer = b"".join(held)
        self._carve(buffer, base, final=True)
        if base + len(buffer) > scanned:
            start = max(0, scanned - base - _OVERLAP)
            yield base + start, buffer[start:]

    def _carve(self, buffer: bytes, base: int, final: bool) -> Optional[Tuple[int, int]]:
        """Collect the images in ``buffer``. Returns ``(position, size)`` of an
        image that has to wait for more data, else None."""
        # candidates in the last _OVERLAP bytes are carried over to the next round
        # (+ 1: an "MZ" whose Z is the first carried byte still belongs to this one)
        end = len(buffer) if final else len(buffer) - _OVERLAP + 1
        if self._carved >= _MAX_CARVED:
            limits.hit("unity", "more than %d MB of programs inside one file: further ones were not taken out" % (_MAX_CARVED >> 20))
        if len(self.images) >= self.limit or self._carved >= _MAX_CARVED:
            return None
        for pos in _candidates(buffer, max(end, 0)):
            if len(self.images) >= self.limit or self._carved >= _MAX_CARVED:
                break
            image = _image_at(buffer, pos)
            if image is None:
                continue
            if image[0] > _MAX_IMAGE:
                limits.hit("unity", "a program of more than %d MB inside the file: only its start was taken out" % (_MAX_IMAGE >> 20))
            size = min(image[0], _MAX_IMAGE)
            if pos + size > len(buffer) and not final:
                return pos, size
            data = bytes(buffer[pos:pos + size])
            self._carved += len(data)
            self.images.append((base + pos, data, image[1]))
        return None
