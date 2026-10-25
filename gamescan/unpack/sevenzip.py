"""7z archive reader (standard library only).

Reads the archive's header and decodes its folders with the codecs Python
ships: LZMA, LZMA2, BCJ (x86) and Delta filters, Deflate, BZip2 and Copy.
That covers what 7-Zip produces by default. Archives that need something
else - PPMd, Deflate64, AES encryption - raise :class:`NeedTool`, and the
caller reports it (since 2026-10-20 no installed extractor gets a 7z archive -
phageo; BCJ2 has been read here since early October).

A solid folder is decoded once, from start to end, and cut into its files
on the way; members nobody asked for are decoded (there is no other way to
reach the next one) but never kept.

Every folder is decoded piece by piece - also a BCJ2 folder of programs
(since 2026-10-17, fifty-eighth message: before, it was decoded whole, about
three copies of it in memory at once). What the reader holds unpacked at one
time is bounded by ``_MAX_HELD``: BCJ2's three side streams (the moved CALL /
JMP targets and the range coder's bits, which are needed in step with the
code) and the piece in flight. The member being collected is the spool's
(``spool.MEMORY``).
"""
from __future__ import annotations

import bz2
import lzma
import re
import struct
import zlib
from typing import BinaryIO, Callable, Iterator, List, Optional, Tuple

from . import limits, spool

MAGIC = b"7z\xbc\xaf\x27\x1c"
_CHUNK = 1 << 20
_MAX_HEADER = 64 * 1024 * 1024
_MAX_DICT = 512 * 1024 * 1024          # liblzma allocates the dictionary up front
_MAX_FILES = 200_000
_MAX_BCJ2 = 256 * 1024 * 1024         # a BCJ2 folder (work: BCJ2 is undone in Python)
_MAX_HELD = 256 * 1024 * 1024         # unpacked and held at once: BCJ2's side streams together


class SevenZipError(ValueError):
    """The archive is damaged or not a 7z archive."""


class NeedTool(SevenZipError):
    """Valid archive, but it uses a method the standard library cannot decode."""


def valid_at(data: bytes, pos: int) -> bool:
    """Is there a real 7z start header at ``pos`` (magic + matching CRC)?"""
    head = data[pos:pos + 32]
    return (len(head) == 32 and head[:6] == MAGIC
            and zlib.crc32(head[12:32]) == struct.unpack_from("<I", head, 8)[0])


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise SevenZipError("truncated header")
        self.pos += 1
        return self.data[self.pos - 1]

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise SevenZipError("truncated header")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def number(self) -> int:
        first = self.byte()
        mask, value = 0x80, 0
        for i in range(8):
            if not first & mask:
                return value | (first & (mask - 1)) << (8 * i)
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def bits(self, count: int) -> List[bool]:
        raw = self.take((count + 7) // 8)
        return [bool(raw[i >> 3] & (0x80 >> (i & 7))) for i in range(count)]

    def defined(self, count: int) -> List[bool]:
        return [True] * count if self.byte() else self.bits(count)


class _Folder:
    def __init__(self) -> None:
        self.coders: List[Tuple[bytes, bytes, int, int]] = []   # id, props, inputs, outputs
        self.binds: List[Tuple[int, int]] = []
        self.packed: List[int] = []
        self.sizes: List[int] = []
        self.has_crc = False
        self.pack_at = 0                    # index of its first packed stream
        self.files: List[int] = []          # sizes of the files it holds

    @property
    def size(self) -> int:
        """Size of the folder's final output."""
        bound = {out for _inp, out in self.binds}
        for index, size in enumerate(self.sizes):
            if index not in bound:
                return size
        raise SevenZipError("folder without an output")


def _limited(count: int, what: str) -> int:
    if count > _MAX_FILES:
        raise SevenZipError(limits.hit("7z", "implausible number of %s (more than %d)" % (what, _MAX_FILES)))
    return count


def _streams_info(r: _Reader):
    pack_pos, pack_sizes, folders = 0, [], []
    kind = r.byte()
    if kind == 0x06:                                        # PackInfo
        pack_pos = r.number()
        count = _limited(r.number(), "streams")
        kind = r.byte()
        while kind != 0x00:
            if kind == 0x09:
                pack_sizes = [r.number() for _ in range(count)]
            elif kind == 0x0A:
                r.take(4 * sum(r.defined(count)))
            else:
                raise SevenZipError("unexpected pack property")
            kind = r.byte()
        kind = r.byte()
    if kind == 0x07:                                        # UnpackInfo
        if r.byte() != 0x0B:
            raise SevenZipError("folder list expected")
        count = _limited(r.number(), "folders")
        if r.byte():
            raise NeedTool("external folder data")
        at = 0
        for _ in range(count):
            folder = _Folder()
            total_in = total_out = 0
            for _ in range(_limited(r.number(), "coders")):
                flag = r.byte()
                coder_id = r.take(flag & 0x0F)
                inputs, outputs = (r.number(), r.number()) if flag & 0x10 else (1, 1)
                props = r.take(r.number()) if flag & 0x20 else b""
                if flag & 0x80:
                    raise NeedTool("alternative coder methods")
                folder.coders.append((coder_id, props, inputs, outputs))
                total_in += inputs
                total_out += outputs
            folder.binds = [(r.number(), r.number()) for _ in range(max(total_out - 1, 0))]
            packed = total_in - len(folder.binds)
            folder.packed = [0] if packed == 1 else [r.number() for _ in range(packed)]
            folder.sizes = [0] * total_out
            folder.pack_at = at
            at += packed
            folders.append(folder)
        kind = r.byte()
        while kind != 0x00:
            if kind == 0x0C:
                for folder in folders:
                    folder.sizes = [r.number() for _ in folder.sizes]
            elif kind == 0x0A:
                for folder, has in zip(folders, r.defined(len(folders))):
                    folder.has_crc = has
                    if has:
                        r.take(4)
            else:
                raise SevenZipError("unexpected folder property")
            kind = r.byte()
        kind = r.byte()
    counts = [1] * len(folders)
    if kind == 0x08:                                        # SubStreamsInfo
        kind = r.byte()
        if kind == 0x0D:
            counts = [_limited(r.number(), "files") for _ in folders]
            kind = r.byte()
        for folder, count in zip(folders, counts):
            folder.files = []
            if count:
                rest = folder.size
                if kind == 0x09:
                    for _ in range(count - 1):
                        size = r.number()
                        folder.files.append(size)
                        rest -= size
                if rest < 0:
                    raise SevenZipError("file sizes exceed their folder")
                folder.files.append(rest)
        if kind == 0x09:
            kind = r.byte()
        if kind == 0x0A:
            need = sum(count for folder, count in zip(folders, counts)
                       if not (count == 1 and folder.has_crc))
            r.take(4 * sum(r.defined(need)))
            kind = r.byte()
        if kind != 0x00:
            raise SevenZipError("unexpected substream property")
        kind = r.byte()
    else:
        for folder in folders:
            folder.files = [folder.size]
    if kind != 0x00:
        raise SevenZipError("unterminated stream info")
    return pack_pos, pack_sizes, folders


def _lzma2_dict(prop: int) -> int:
    if prop > 40:
        raise SevenZipError("bad LZMA2 dictionary size")
    return 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)


_BCJ2 = b"\x03\x03\x01\x1b"
_AES = b"\x06\xf1\x07\x01"


def _codec(main_id: bytes, props: bytes, filters=()):
    """Decoder for one codec, optionally followed by BCJ / Delta filters."""
    filters = list(filters)
    if main_id == b"\x21" and len(props) == 1:
        size = _lzma2_dict(props[0])
        main = {"id": lzma.FILTER_LZMA2, "dict_size": size}
    elif main_id == b"\x03\x01\x01" and len(props) == 5:
        lc, rest = props[0] % 9, props[0] // 9
        size = struct.unpack_from("<I", props, 1)[0]
        main = {"id": lzma.FILTER_LZMA1, "dict_size": size, "lc": lc, "lp": rest % 5,
                "pb": rest // 5}
    elif main_id == b"\x00" and not filters:
        return _Copy()
    elif main_id == b"\x04\x01\x08" and not filters:
        return _Wrap(zlib.decompressobj(-15))
    elif main_id == b"\x04\x02\x02" and not filters:
        return _Wrap(bz2.BZ2Decompressor())
    elif main_id == _AES:
        raise NeedTool("a password (the archive is encrypted)")
    else:
        raise NeedTool("compression method %s" % (main_id.hex() or "?"))
    if size > _MAX_DICT:
        raise NeedTool(limits.hit("7z", "a %d MB dictionary" % (size >> 20)))
    try:
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters[::-1] + [main])
    except (lzma.LZMAError, ValueError) as exc:
        raise NeedTool("this filter combination (%s)" % exc)


def _decoder(folder: _Folder):
    """An object with ``decompress(data, max_length)`` for a folder whose
    coders form a simple chain (one stream in, one stream out each)."""
    # order the chain from the packed stream to the final output
    feeds = {inp: out for inp, out in folder.binds}        # coder ``inp`` reads coder ``out``
    order = [i for i in range(len(folder.coders)) if i not in feeds]
    if len(order) != 1:
        raise NeedTool("an unusual coder chain")
    while len(order) < len(folder.coders):
        nxt = [inp for inp, out in feeds.items() if out == order[-1]]
        if len(nxt) != 1:
            raise NeedTool("an unusual coder chain")
        order.append(nxt[0])
    chain = [folder.coders[i][:2] for i in order]
    if any(coder_id == _AES for coder_id, _props in chain):
        # (anywhere in the chain - usually it stands first, on the packed stream; until
        # 2026-10-23 the coder after it was named instead: "filter 030101")
        raise NeedTool("a password (the archive is encrypted)")
    main_id, props = chain[0] if chain else (b"\x00", b"")
    filters = []
    for coder_id, coder_props in chain[1:]:                 # applied after the main codec
        if coder_id in (b"\x03\x03\x01\x03", b"\x04"):
            filters.append({"id": lzma.FILTER_X86})
        elif coder_id == b"\x03" and len(coder_props) == 1:
            filters.append({"id": lzma.FILTER_DELTA, "dist": coder_props[0] + 1})
        elif coder_id == _AES:
            raise NeedTool("a password (the archive is encrypted)")
        elif coder_id != b"\x00":
            raise NeedTool("filter %s" % coder_id.hex())
    return _codec(main_id, props, filters)


_CALLS = re.compile(rb"[\xe8\xe9]")                # CALL / JMP
_JCC = re.compile(rb"\x0f[\x80-\x8f]")              # a conditional jump (its 8x is the opcode)
_WINDOW = 1 << 22                                   # bytes of ``main`` whose opcodes are listed at once


class _Full(Exception):
    """The output has the size it was asked for."""


def bcj2(main: bytes, call: bytes, jump: bytes, rc: bytes, size: int) -> bytes:
    """Undo 7-Zip's BCJ2 filter: put the CALL / JMP targets, which the packer
    moved into separate streams, back into the x86 code in ``main``.

    A range-coded bit after every E8 / E9 / 0F 8x opcode says whether its
    4-byte operand was moved; the code between two such opcodes is copied
    as it is.

    The opcodes are listed a window at a time by two plain searches (``_CALLS``,
    ``_JCC``), and only the places where a moved operand goes back are kept; the
    output is put together once at the end (2026-10-15: before, every opcode cost
    a search with a look-behind and a copy - 68 of ELE-04's 78 seconds in its
    7z). The one opcode the searches cannot see - an 8x right behind a moved
    operand whose last byte is 0F - is looked at where it can stand. The result
    is the same, byte for byte."""
    probs = [1024] * 258
    code = int.from_bytes(rc[1:5], "big")
    rng, rc_at, call_at, jump_at = 0xFFFFFFFF, 5, 0, 0
    end = len(main)
    places: List[Tuple[int, bytes]] = []        # (where in main a moved operand goes, its 4 bytes)
    pos = prev = shift = 0                      # shift: what the moved operands added so far
    try:
        for start in range(0, end, _WINDOW):
            stop = min(end, start + _WINDOW)
            hits = [m.start() for m in _CALLS.finditer(main, start, stop)]
            hits += [m.end() - 1 for m in _JCC.finditer(main, max(0, start - 1), stop)]
            hits.sort()
            for hit in hits:
                while True:
                    if hit != pos:
                        prev = main[hit - 1]
                    b = main[hit]
                    pos = hit + 1
                    if pos + shift >= size:
                        raise _Full
                    index = prev if b == 0xE8 else 256 if b == 0xE9 else 257
                    prob = probs[index]
                    bound = (rng >> 11) * prob
                    if code < bound:                        # operand was left in place
                        rng = bound
                        probs[index] = prob + ((2048 - prob) >> 5)
                        if rng < 0x1000000:
                            rng <<= 8
                            code = ((code << 8) | rc[rc_at]) & 0xFFFFFFFF
                            rc_at += 1
                        prev = b
                        break
                    rng -= bound
                    code -= bound
                    probs[index] = prob - (prob >> 5)
                    if rng < 0x1000000:
                        rng <<= 8
                        code = ((code << 8) | rc[rc_at]) & 0xFFFFFFFF
                        rc_at += 1
                    if b == 0xE8:
                        raw = call[call_at:call_at + 4]
                        call_at += 4
                    else:
                        raw = jump[jump_at:jump_at + 4]
                        jump_at += 4
                    if len(raw) != 4:
                        raise IndexError
                    target = (int.from_bytes(raw, "big") - (pos + shift + 4)) & 0xFFFFFFFF
                    places.append((pos, target.to_bytes(4, "little")))
                    shift += 4
                    prev = target >> 24
                    if prev == 0x0F and pos < end and main[pos] & 0xF0 == 0x80:
                        hit = pos                   # 0F (the operand's last byte) 8x
                        continue
                    break
    except _Full:
        pass
    except IndexError:
        raise SevenZipError("damaged BCJ2 data") from None
    out, at = bytearray(), 0
    for where, operand in places:
        out += main[at:where]
        out += operand
        at = where
        if len(out) >= size:
            break
    if len(out) < size:
        out += main[at:at + size - len(out)]
    return bytes(out[:size])


def bcj2_pieces(main_pieces, call: bytes, jump: bytes, rc: bytes, size: int) -> Iterator[bytes]:
    """:func:`bcj2`, with the code stream ``main`` coming in pieces and the output going out
    in pieces: the same bytes, without the whole folder in memory (2026-10-17). What one
    piece cannot finish by itself is carried to the next: the last code byte (an ``0F``
    there and an ``8x`` at the start of the next piece is a jump), and a moved operand
    whose last byte is ``0F`` standing right at the end of a piece."""
    probs = [1024] * 258
    code = int.from_bytes(rc[1:5], "big")
    rng, rc_at, call_at, jump_at = 0xFFFFFFFF, 5, 0, 0
    pos = prev = shift = 0                      # (as in bcj2: positions in the whole code stream)
    base = produced = 0                         # where this piece starts; bytes given out
    last, pending, full = -1, False, False      # last code byte; 0F operand at a piece's end
    for piece in main_pieces:
        if produced >= size:
            return
        end = base + len(piece)
        places: List[Tuple[int, bytes]] = []
        if not full and piece:
            hits = [m.start() + base for m in _CALLS.finditer(piece)]
            hits += [m.end() - 1 + base for m in _JCC.finditer(piece)]
            if (pending or last == 0x0F) and piece[0] & 0xF0 == 0x80:
                hits.append(base)
            hits.sort()
            pending = False
            try:
                for hit in hits:
                    while True:
                        if hit != pos:
                            prev = piece[hit - 1 - base] if hit > base else last
                        b = piece[hit - base]
                        pos = hit + 1
                        if pos + shift >= size:
                            raise _Full
                        index = prev if b == 0xE8 else 256 if b == 0xE9 else 257
                        prob = probs[index]
                        bound = (rng >> 11) * prob
                        if code < bound:                    # operand was left in place
                            rng = bound
                            probs[index] = prob + ((2048 - prob) >> 5)
                            if rng < 0x1000000:
                                rng <<= 8
                                code = ((code << 8) | rc[rc_at]) & 0xFFFFFFFF
                                rc_at += 1
                            prev = b
                            break
                        rng -= bound
                        code -= bound
                        probs[index] = prob - (prob >> 5)
                        if rng < 0x1000000:
                            rng <<= 8
                            code = ((code << 8) | rc[rc_at]) & 0xFFFFFFFF
                            rc_at += 1
                        if b == 0xE8:
                            raw = call[call_at:call_at + 4]
                            call_at += 4
                        else:
                            raw = jump[jump_at:jump_at + 4]
                            jump_at += 4
                        if len(raw) != 4:
                            raise IndexError
                        target = (int.from_bytes(raw, "big") - (pos + shift + 4)) & 0xFFFFFFFF
                        places.append((pos, target.to_bytes(4, "little")))
                        shift += 4
                        prev = target >> 24
                        if prev == 0x0F:
                            if pos < end and piece[pos - base] & 0xF0 == 0x80:
                                hit = pos               # 0F (the operand's last byte) 8x
                                continue
                            pending = pos == end        # ... or the 8x opens the next piece
                        break
            except _Full:
                full = True
            except IndexError:
                raise SevenZipError("damaged BCJ2 data") from None
        out, at = bytearray(), base
        for where, operand in places:
            out += piece[at - base:where - base]
            out += operand
            at = where
        out += piece[at - base:]
        if produced + len(out) > size:
            del out[size - produced:]
        produced += len(out)
        if out:
            yield bytes(out)
        if piece:
            last = piece[-1]
        base = end


class _Copy:
    eof = needs_input = False

    @staticmethod
    def decompress(data: bytes, max_length: int = -1) -> bytes:
        return data


class _Wrap:
    """zlib / bz2 behind the LZMADecompressor interface."""

    def __init__(self, inner) -> None:
        self.inner, self.held = inner, b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        data = self.held + data
        if hasattr(self.inner, "unconsumed_tail"):
            out = self.inner.decompress(data, max(max_length, 0))
            self.held = self.inner.unconsumed_tail
        else:
            out = self.inner.decompress(data, max_length)
            self.held = b""
        return out


class Archive:
    """An open 7z archive. ``stream`` must start at the 7z signature."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        stream.seek(0)
        head = stream.read(32)
        if not valid_at(head, 0):
            raise SevenZipError("not a 7z archive")
        offset, size, crc = struct.unpack_from("<QQI", head, 12)
        if size > _MAX_HEADER:
            raise SevenZipError(limits.hit("7z", "implausible header size (more than %d MB)" % (_MAX_HEADER >> 20)))
        stream.seek(32 + offset)
        raw = stream.read(size)
        if len(raw) != size or zlib.crc32(raw) != crc:
            raise SevenZipError("header is damaged or the archive is cut short")
        self.names: List[str] = []
        self.empty: List[bool] = []
        self.folders: List[_Folder] = []
        self.pack_pos, self.pack_sizes = 0, []
        r = _Reader(raw)
        kind = r.byte() if raw else 0
        if kind == 0x17:                                    # the header itself is packed
            self.pack_pos, self.pack_sizes, folders = _streams_info(r)
            if len(folders) == 1 and folders[0].size > _MAX_HEADER:
                raise SevenZipError(limits.hit("7z", "a packed header larger than %d MB" % (_MAX_HEADER >> 20)))
            if len(folders) != 1:
                raise SevenZipError("unexpected packed header")
            self.folders = folders
            raw = b"".join(self._decode(folders[0]))
            r = _Reader(raw)
            kind = r.byte()
            self.folders, self.pack_sizes = [], []
        if kind != 0x01:
            if not raw:
                return                                      # empty archive
            raise SevenZipError("header expected")
        kind = r.byte()
        if kind == 0x02:                                    # archive properties
            while r.byte() != 0x00:
                r.take(r.number())
            kind = r.byte()
        if kind == 0x03:
            raise NeedTool("additional streams")
        if kind == 0x04:
            self.pack_pos, self.pack_sizes, self.folders = _streams_info(r)
            kind = r.byte()
        if kind == 0x05:
            count = _limited(r.number(), "files")
            self.empty = [False] * count
            while True:
                kind = r.byte()
                if kind == 0x00:
                    break
                body = _Reader(r.take(r.number()))
                if kind == 0x0E:
                    self.empty = body.bits(count)
                elif kind == 0x11:
                    if body.byte():
                        raise NeedTool("external file names")
                    text = body.data[body.pos:].decode("utf-16-le", "replace")
                    self.names = [n.replace("\\", "/") for n in text.split("\0")[:count]]
            self.names += [""] * (count - len(self.names))

    def _decode(self, folder: _Folder) -> Iterator[bytes]:
        """The folder's output, piece by piece."""
        if any(inputs != 1 or outputs != 1 for _i, _p, inputs, outputs in folder.coders):
            return self._decode_bcj2(folder)
        if len(folder.packed) != 1:
            raise NeedTool("an unusual coder chain")
        return self._drain(_decoder(folder), folder.pack_at + folder.packed[0], folder.size)

    def _decode_bcj2(self, folder: _Folder) -> Iterator[bytes]:
        """A folder of executables: three packed streams (code, CALL targets,
        JMP targets) plus a raw range-coder stream, joined again by BCJ2. The
        three side streams are read first and held (together at most
        ``_MAX_HELD``); the code stream is then decoded and joined piece by
        piece (:func:`bcj2_pieces`)."""
        last = len(folder.coders) - 1
        if (folder.coders[last][0] != _BCJ2 or folder.coders[last][2:] != (4, 1)
                or any(c[2:] != (1, 1) for c in folder.coders[:last])
                or folder.size > _MAX_BCJ2 or len(folder.sizes) != last + 1):
            if folder.size > _MAX_BCJ2:
                limits.hit("7z", "an executable folder larger than %d MB" % (_MAX_BCJ2 >> 20))
            raise NeedTool("an unusual multi-stream filter")
        feeds = dict(folder.binds)                          # in-stream <- out-stream
        streams = []                                        # (decoder, packed stream, size)
        for inp in range(last, last + 4):                   # BCJ2's four inputs, in order
            coder, source = None, inp
            if inp in feeds:                                # produced by one of the simple coders
                coder = source = feeds[inp]                 # (its own input has the same index)
                if not 0 <= coder < last:
                    raise NeedTool("an unusual multi-stream filter")
            if source in feeds or source not in folder.packed:
                raise NeedTool("an unusual multi-stream filter")
            index = folder.pack_at + folder.packed.index(source)
            if coder is None:
                decoder = _Copy()
                size = self.pack_sizes[index] if index < len(self.pack_sizes) else 0
            else:
                decoder, size = _codec(*folder.coders[coder][:2]), folder.sizes[coder]
            if size > _MAX_BCJ2:
                raise NeedTool(limits.hit("7z", "an unusually large executable folder (more than %d MB)" % (_MAX_BCJ2 >> 20)))
            streams.append((decoder, index, size))
        if sum(size for _decoder, _index, size in streams[1:]) > _MAX_HELD:
            raise NeedTool(limits.hit("7z", "an executable folder whose side streams hold more than %d MB "
                                            "(unpacked and held at once)" % (_MAX_HELD >> 20)))
        side = [b"".join(self._drain(*stream)) for stream in streams[1:]]
        return bcj2_pieces(self._drain(*streams[0]), side[0], side[1], side[2], folder.size)

    def _drain(self, decoder, index: int, want: int) -> Iterator[bytes]:
        """``want`` bytes of one packed stream, run through ``decoder``."""
        if index >= len(self.pack_sizes):
            raise SevenZipError("missing packed stream")
        self.stream.seek(32 + self.pack_pos + sum(self.pack_sizes[:index]))
        left = self.pack_sizes[index]
        while want > 0:
            if getattr(decoder, "needs_input", True) or isinstance(decoder, _Copy):
                feed = self.stream.read(min(left, _CHUNK))
                left -= len(feed)
                if not feed and not getattr(decoder, "held", b""):
                    raise SevenZipError("packed data ends early")
            else:
                feed = b""
            try:
                piece = decoder.decompress(feed, min(want, _CHUNK))
            except (lzma.LZMAError, zlib.error, OSError, EOFError) as exc:
                raise SevenZipError("damaged packed data (%s)" % exc)
            if isinstance(decoder, _Copy):
                piece = piece[:want]
            want -= len(piece)
            if piece:
                yield piece

    def members(self, want: Callable[[str, int], bool],
                tick: Optional[Callable[[float], None]] = None,
                on_error: Optional[Callable[[str], None]] = None) -> Iterator[Tuple[str, bytes]]:
        """``(name, data)`` of every file ``want(name, size)`` accepts.

        A folder that cannot be decoded here raises :class:`NeedTool` (before
        anything of it was produced) unless ``on_error`` is given; then it is
        reported there and the remaining folders are still read."""
        names = [n for n, empty in zip(self.names, self.empty) if not empty]
        total = sum(f.size for f in self.folders) or 1
        at = done = 0
        for folder in self.folders:
            members = [(names[at + i] if at + i < len(names) else "", size)
                       for i, size in enumerate(folder.files)]
            at += len(members)
            wanted = [want(name, size) for name, size in members]
            if not any(wanted):
                continue
            held = spool.Collector()
            try:
                pieces = self._decode(folder)
                have = 0
                index = 0
                buffer = b""
                for piece in pieces:
                    buffer = piece
                    while index < len(members):
                        need = members[index][1] - have
                        part, buffer = buffer[:need], buffer[need:]
                        have += len(part)
                        if wanted[index] and part:
                            held.write(part)
                        if have < members[index][1]:
                            break
                        if wanted[index]:
                            yield members[index][0], held.result()
                        held, have = spool.Collector(), 0
                        index += 1
                    if tick is not None:
                        done += len(piece)
                        tick(min(1.0, done / total))
                while index < len(members) and members[index][1] == 0:
                    if wanted[index]:
                        yield members[index][0], b""
                    index += 1
                held.discard()
            except SevenZipError as exc:
                held.discard()
                if on_error is None:
                    raise
                on_error(str(exc))
            except BaseException:
                held.discard()
                raise
