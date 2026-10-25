"""Media files, read by their structure - not by what they look like.

Images and audio are where a game's bulk is, and a convenient place to park
a payload: behind the picture, in a metadata field, in a chunk of its own.
Nothing here guesses whether a region "looks like text". Two exact methods
are used instead:

* **Structure.** :func:`parse` walks the container exactly as its format
  defines it - PNG chunks (with their CRCs), JPEG segments, GIF blocks, Ogg
  pages, RIFF chunks (WAV / WebP / AVI), MP4 boxes (M4A / MP4), BMP, MP3
  frames with their ID3 / APE tags, MIDI chunks, Matroska / WebM elements - and
  reports where the media really ends. Whatever lies after that point, or at
  a place where the structure breaks, is not part of the picture or sound.
  Metadata that the format stores compressed (PNG ``zTXt`` / ``iTXt`` /
  ``iCCP``) is inflated, so it can be read as well.
* **Sliding window.** :func:`runs` returns *every* run of eight or more
  printable characters (ASCII or UTF-16, line breaks included) in a block of
  bytes. Applied to the whole file / stream, a command line or script of any
  size between binary data is read - there is no minimum share of text.

What no static reader can see: data hidden *inside* validly coded pixels or
samples (steganography), or a payload that is itself encrypted.
"""
from __future__ import annotations

import re
import struct
import zlib
from typing import List, NamedTuple, Optional, Tuple

from . import limits

_MAX_INFLATE = 4 * 1024 * 1024
_MAX_PARTS = 4096
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_CLASSES = bytes(0x70 if b in _PRINTABLE else 0x7A if b == 0 else 0x6E for b in range(256))
_P8, _PZ8 = b"p" * 8, b"pz" * 8                  # eight characters in a row: ASCII, UTF-16LE
_P_RUN = re.compile(rb"p{8,4096}")
_PZ_RUN = re.compile(rb"(?:pz){8,4096}")
_BLANK = bytes(range(0x21)) + b"\xff"            # padding: control characters, spaces, 0xFF


class Media(NamedTuple):
    kind: str                        # "PNG image", "Ogg audio", ...
    end: int                         # offset where the media ends by its own structure
    texts: List[Tuple[str, bytes]]   # (where, content) of metadata / non-media parts
    problem: str                     # "" or what is wrong with the structure


def runs(data: bytes, limit: int = 250_000) -> List[str]:
    """Every run of 8+ printable characters in ``data`` (ASCII and UTF-16LE,
    tabs and line breaks included, so a multi-line script stays one run)."""
    # Exact, and fast enough for gigabytes: one pass turns every byte into its
    # class (p = printable, z = zero, n = anything else); a plain substring
    # search then finds each place where eight printable characters start,
    # and only there is the run measured.
    classes = data.translate(_CLASSES)
    found: List[str] = []
    for needle, run, step, codec in ((_P8, _P_RUN, 1, "ascii"), (_PZ8, _PZ_RUN, 2, "utf-16-le")):
        pos = classes.find(needle)
        while pos >= 0 and len(found) < 4 * limit:
            end = run.match(classes, pos).end()
            found.append(data[pos:end].decode(codec))
            pos = classes.find(needle, end)
    return list(dict.fromkeys(found))[:limit]


def blank(data: bytes) -> bool:
    """Only padding (zero bytes, white space, 0xFF)?"""
    return not data.translate(None, _BLANK)


def _inflate(data: bytes) -> bytes:
    try:
        engine = zlib.decompressobj()
        out = engine.decompress(data, _MAX_INFLATE)
        if engine.unconsumed_tail:
            limits.hit("media", "a packed text in a picture unpacks to more than %d MB: the rest was not read" % (_MAX_INFLATE >> 20))
        return out
    except zlib.error:
        return b""


# -- PNG ---------------------------------------------------------------------------------------
_PNG = b"\x89PNG\r\n\x1a\n"
_PNG_PIXELS = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND", b"fdAT", b"fcTL", b"acTL", b"tRNS",
                         b"gAMA", b"cHRM", b"sRGB", b"sBIT", b"bKGD", b"hIST", b"pHYs", b"tIME",
                         b"sPLT", b"cICP", b"mDCV", b"cLLI"})


def _png(data: bytes, start: int = 0) -> Media:
    pos, texts, problem = start + 8, [], ""
    while len(texts) < _MAX_PARTS:
        if pos + 12 > len(data):
            problem = "the image is cut short (no end chunk)"
            break
        length, kind = struct.unpack_from(">I4s", data, pos)
        body = data[pos + 8:pos + 8 + length]
        if (not kind.isalpha() or pos + 12 + length > len(data)
                or zlib.crc32(kind + body) != struct.unpack_from(">I", data, pos + 8 + length)[0]):
            problem = "not a valid chunk at offset %d" % pos
            break
        pos += 12 + length
        if kind == b"IEND":
            break
        if kind == b"tEXt":
            texts.append(("tEXt", body))
        elif kind == b"zTXt" and b"\0" in body:
            key, rest = body.split(b"\0", 1)
            texts.append(("zTXt", key + b"\n" + _inflate(rest[1:])))
        elif kind == b"iTXt" and body.count(b"\0") >= 3:
            key, rest = body.split(b"\0", 1)
            packed = rest[:1] == b"\x01"
            _lang, _translated, text = (rest[2:].split(b"\0", 2) + [b"", b""])[:3]
            texts.append(("iTXt", key + b"\n" + (_inflate(text) if packed else text)))
        elif kind == b"iCCP" and b"\0" in body:
            texts.append(("iCCP", _inflate(body.split(b"\0", 1)[1][1:])))
        elif kind not in _PNG_PIXELS:
            texts.append(("chunk %s" % kind.decode("ascii"), body))
    if len(texts) >= _MAX_PARTS:
        limits.hit("media", "more than %d text parts in one picture: the rest was not read as parts" % _MAX_PARTS)
    return Media("PNG image", pos, texts, problem)


# -- JPEG --------------------------------------------------------------------------------------
_JPEG_NEXT = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")      # a marker inside coded picture data


def _jpeg(data: bytes) -> Media:
    pos, texts, problem, end = 0, [], "", 0
    while data[pos:pos + 2] == b"\xff\xd8":                 # (several pictures may follow each other)
        pos += 2
        while True:
            if pos + 2 > len(data) or data[pos] != 0xFF:
                problem = "not a valid segment at offset %d" % pos
                return Media("JPEG image", end or pos, texts, problem)
            marker = data[pos + 1]
            if marker not in (0xD9, 0xFF, 0x01) and not 0xD0 <= marker <= 0xD7 \
                    and pos + 4 > len(data):
                return Media("JPEG image", end or pos, texts, "the image is cut short")
            if marker == 0xD9:                              # end of image
                pos += 2
                break
            if marker == 0xFF:                              # fill byte
                pos += 1
                continue
            if 0xD0 <= marker <= 0xD7 or marker == 0x01:
                pos += 2
                continue
            length = struct.unpack_from(">H", data, pos + 2)[0]
            if length < 2 or pos + 2 + length > len(data):
                problem = "not a valid segment at offset %d" % pos
                return Media("JPEG image", end or pos, texts, problem)
            if (marker == 0xFE or 0xE0 <= marker <= 0xEF) and len(texts) < _MAX_PARTS:
                texts.append(("segment %02X" % marker, data[pos + 4:pos + 2 + length]))
            pos += 2 + length
            if marker == 0xDA:                              # coded data runs to the next marker
                found = _JPEG_NEXT.search(data, pos)
                if found is None:
                    return Media("JPEG image", len(data), texts, "the image is cut short")
                pos = found.start()
        end = pos
    return Media("JPEG image", end, texts, problem)


# -- GIF ---------------------------------------------------------------------------------------
def _gif(data: bytes) -> Media:
    texts, pos = [], 13
    try:
        if data[10] & 0x80:
            pos += 3 << ((data[10] & 7) + 1)

        def blocks(at: int) -> Tuple[int, bytes]:
            out = []
            while data[at]:
                out.append(data[at + 1:at + 1 + data[at]])
                at += 1 + data[at]
            return at + 1, b"".join(out)

        while True:
            kind = data[pos]
            if kind == 0x3B:
                return Media("GIF image", pos + 1, texts, "")
            if kind == 0x2C:
                flags = data[pos + 9]
                pos += 10 + ((3 << ((flags & 7) + 1)) if flags & 0x80 else 0) + 1
                pos, _pixels = blocks(pos)
            elif kind == 0x21:
                label = data[pos + 1]
                pos, body = blocks(pos + 2)
                if label in (0xFE, 0xFF, 0x01) and len(texts) < _MAX_PARTS:
                    texts.append(("extension %02X" % label, body))
            else:
                return Media("GIF image", pos, texts, "not a valid block at offset %d" % pos)
    except IndexError:
        return Media("GIF image", len(data), texts, "the image is cut short")


# -- Ogg ---------------------------------------------------------------------------------------
def _ogg(data: bytes) -> Media:
    pos, texts, pages = 0, [], 0
    while data[pos:pos + 4] == b"OggS":
        if pos + 27 > len(data) or data[pos + 4] != 0:
            break
        segments = data[pos + 26]
        table = data[pos + 27:pos + 27 + segments]
        size = 27 + segments + sum(table)
        if len(table) != segments or pos + size > len(data):
            return Media("Ogg audio", pos, texts, "the last page is cut short")
        if pages < 4:                                       # codec headers and comments
            texts.append(("page %d" % pages, data[pos + 27 + segments:pos + size]))
        pages += 1
        pos += size
    return Media("Ogg audio", pos, texts, "" if pages else "no valid page")


# -- RIFF (WAV, WebP, AVI) -----------------------------------------------------------------------
def _riff(data: bytes) -> Media:
    size, form = struct.unpack_from("<I4s", data, 4)
    kind = {b"WAVE": "WAV audio", b"WEBP": "WebP image", b"AVI ": "AVI video"}.get(form, "RIFF file")
    end = 8 + size + (size & 1)
    texts, pos, problem = [], 12, ""
    if end > len(data):                                     # common in sloppy files; nothing extra
        end = len(data)
    while pos + 8 <= end and len(texts) < _MAX_PARTS:
        name, length = struct.unpack_from("<4sI", data, pos)
        if not name.strip().isalnum() or pos + 8 + length > end + 1:
            problem = problem or "not a valid chunk at offset %d" % pos
            # (the RIFF size still says where the file ends; what is left of it from the
            # break on is no known part, so it is read as text - 2026-10-23)
            texts.append(("after the broken chunk", data[pos:pos + min(end - pos, _MAX_INFLATE)]))
            break
        if name not in (b"data", b"movi", b"VP8 ", b"VP8L", b"ALPH", b"ANMF", b"idx1", b"fmt "):
            texts.append(("chunk %s" % name.decode("ascii", "replace").strip(),
                          data[pos + 8:pos + 8 + min(length, _MAX_INFLATE)]))
        pos += 8 + length + (length & 1)
    return Media(kind, min(end, len(data)), texts, problem)


# -- MP4 family (M4A, MP4, MOV) ------------------------------------------------------------------
def _mp4(data: bytes) -> Media:
    pos, texts, problem = 0, [], ""
    while pos + 8 <= len(data):
        size, name = struct.unpack_from(">I4s", data, pos)
        head = 8
        if size == 1 and pos + 16 <= len(data):
            size, head = struct.unpack_from(">Q", data, pos + 8)[0], 16
        elif size == 0:
            size = len(data) - pos
        if size < head or not all(0x20 <= b < 0x7F or b == 0xA9 for b in name):
            break                                           # not a box: the media ended before
        if pos + size > len(data):
            problem = "the last box is cut short"
            pos = len(data)
            break
        if name in (b"moov", b"meta", b"udta", b"uuid", b"free", b"skip") and len(texts) < 64:
            texts.append(("box %s" % name.decode("latin-1"),
                          data[pos + head:pos + min(size, _MAX_INFLATE)]))
        pos += size
    return Media("MP4 audio/video", pos, texts, problem)


def _bmp(data: bytes) -> Media:
    size = struct.unpack_from("<I", data, 2)[0]
    if 26 <= size <= len(data):
        return Media("BMP image", size, [], "")
    return Media("BMP image", len(data), [], "declared size does not match the file")


# -- MP3 (MPEG audio frames, ID3v2 before, ID3v1 / APE / Lyrics3 tags behind) ---------------------
_BITRATES = {          # kbit/s by (MPEG version 1 or 2, layer)
    (1, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (1, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (1, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}


def _mpeg_frame(data: bytes, pos: int) -> int:
    """Length of the MPEG audio frame whose header is at ``pos`` (0 = none)."""
    if pos + 4 > len(data) or data[pos] != 0xFF or data[pos + 1] & 0xE0 != 0xE0:
        return 0
    version, layer = data[pos + 1] >> 3 & 3, 4 - (data[pos + 1] >> 1 & 3)
    rate_index, bitrate_index = data[pos + 2] >> 2 & 3, data[pos + 2] >> 4
    if version == 1 or layer == 4 or rate_index == 3 or bitrate_index in (0, 15):
        return 0
    bitrate = _BITRATES[(1 if version == 3 else 2, layer)][bitrate_index] * 1000
    rate, padding = _RATES[version][rate_index], data[pos + 2] >> 1 & 1
    if layer == 1:
        return (12 * bitrate // rate + padding) * 4
    if layer == 3 and version != 3:
        return 72 * bitrate // rate + padding
    return 144 * bitrate // rate + padding


def _id3v2(data: bytes, pos: int) -> int:
    """Size of the ID3v2 tag at ``pos`` (0 = none)."""
    head = data[pos:pos + 10]
    if len(head) < 10 or head[:3] != b"ID3" or head[3] == 0xFF or any(b & 0x80 for b in head[6:10]):
        return 0
    size = head[6] << 21 | head[7] << 14 | head[8] << 7 | head[9]
    return 10 + size + (10 if head[5] & 0x10 else 0)


def _mp3(data: bytes) -> Optional[Media]:
    texts, pos = [], 0
    while True:                                             # one or more ID3v2 tags
        size = _id3v2(data, pos)
        if not size:
            break
        texts.append(("ID3v2 tag", data[pos + 10:pos + size]))
        pos += size
    while pos < len(data) and data[pos] == 0:               # padding before the first frame
        pos += 1
    frames, start = 0, pos
    while True:
        length = _mpeg_frame(data, pos)
        if not length:
            break
        frames += 1
        pos += length
    if frames < 2 and not texts:
        return None                                         # not an MP3 after all
    if frames == 0:
        return Media("MP3 audio", start, texts, "no audio frame after the ID3 tag")
    pos = min(pos, len(data))                               # (a last frame may be cut short)
    while pos < len(data) and len(texts) < _MAX_PARTS:      # tags that belong behind the audio
        if data[pos:pos + 8] == b"APETAGEX" and pos + 32 <= len(data):
            size = struct.unpack_from("<I", data, pos + 12)[0]
            flags = struct.unpack_from("<I", data, pos + 20)[0]
            total = size + (32 if flags & 0x20000000 else 0)     # header + items + footer
            if not 32 <= total <= len(data) - pos:
                break
            texts.append(("APE tag", data[pos:pos + total]))
            pos += total
        elif data[pos:pos + 11] == b"LYRICSBEGIN":
            end = max(data.find(b"LYRICS200", pos), data.find(b"LYRICSEND", pos))
            if end < 0:
                break
            texts.append(("Lyrics3 tag", data[pos:end + 9]))
            pos = end + 9
        elif data[pos:pos + 3] == b"TAG" and len(data) - pos >= 128:
            texts.append(("ID3v1 tag", data[pos:pos + 128]))
            pos += 128
        elif _id3v2(data, pos):
            size = _id3v2(data, pos)
            texts.append(("ID3v2 tag", data[pos + 10:pos + size]))
            pos += size
        else:
            break
    return Media("MP3 audio", min(pos, len(data)), texts, "")


# -- MIDI ----------------------------------------------------------------------------------------------
def _midi(data: bytes) -> Media:
    if len(data) < 14 or struct.unpack_from(">I", data, 4)[0] < 6:
        return Media("MIDI music", 0, [], "the header is damaged")
    length, _format, tracks = struct.unpack_from(">IHH", data, 4)
    pos, texts, problem = 8 + length, [], ""
    for number in range(tracks):
        if data[pos:pos + 4] != b"MTrk" or pos + 8 > len(data):
            problem = "track %d of %d is missing at offset %d" % (number + 1, tracks, pos)
            break
        size = struct.unpack_from(">I", data, pos + 4)[0]
        if pos + 8 + size > len(data):
            return Media("MIDI music", len(data), texts, "the last track is cut short")
        if len(texts) < _MAX_PARTS:
            texts.append(("track %d" % (number + 1), data[pos + 8:pos + 8 + min(size, _MAX_INFLATE)]))
        pos += 8 + size
    return Media("MIDI music", pos, texts, problem)


# -- Matroska / WebM (EBML) ----------------------------------------------------------------------------
_EBML, _SEGMENT = 0x1A45DFA3, 0x18538067
_LEVEL1 = frozenset({0x114D9B74, 0x1549A966, 0x1654AE6B, 0x1F43B675, 0x1C53BB6B, 0x1941A469,
                     0x1043A770, 0x1254C367, 0xEC, 0xBF, 0x1F43B675})
_EBML_TEXT = {0x1549A966: "Info", 0x1254C367: "Tags", 0x1941A469: "Attachments",
              0x1043A770: "Chapters"}


def _ebml_element(data: bytes, pos: int) -> Optional[Tuple[int, int, int]]:
    """``(id, size or -1 for "unknown", header length)`` of the element at ``pos``."""
    if pos >= len(data) or not data[pos]:
        return None
    id_length = 9 - data[pos].bit_length()
    if id_length > 4 or pos + id_length >= len(data) or not data[pos + id_length]:
        return None
    element = int.from_bytes(data[pos:pos + id_length], "big")
    first = data[pos + id_length]
    size_length = 9 - first.bit_length()
    raw = data[pos + id_length:pos + id_length + size_length]
    if len(raw) != size_length:
        return None
    size = int.from_bytes(raw, "big") & ((1 << (7 * size_length)) - 1)
    if size == (1 << (7 * size_length)) - 1:
        size = -1
    return element, size, id_length + size_length


def _webm(data: bytes) -> Media:
    pos, texts, problem = 0, [], ""
    while True:                                             # (files can be chained)
        head = _ebml_element(data, pos)
        if head is None or head[0] != _EBML or head[1] < 0:
            break
        pos += head[2] + head[1]
        segment = _ebml_element(data, pos)
        if segment is None or segment[0] != _SEGMENT:
            return Media("Matroska / WebM video", pos, texts, "no segment after the EBML header")
        pos += segment[2]
        end = len(data) if segment[1] < 0 else pos + segment[1]
        if end > len(data):
            problem, end = "the segment is cut short", len(data)
        while pos < end:                                    # the segment's own elements
            child = _ebml_element(data, pos)
            if child is None or child[0] not in _LEVEL1:
                if segment[1] >= 0:
                    problem = problem or "not a valid element at offset %d" % pos
                    return Media("Matroska / WebM video", pos, texts, problem)
                break                                       # unknown size: this is the end
            size = child[1]
            if size < 0:                                    # an open-ended cluster: to the next one
                nxt = data.find(b"\x1f\x43\xb6\x75", pos + child[2])
                size = (nxt if nxt >= 0 else end) - pos - child[2]
            if pos + child[2] + size > end:
                return Media("Matroska / WebM video", len(data), texts, problem or
                             "the last element is cut short")
            if child[0] in _EBML_TEXT and len(texts) < _MAX_PARTS:
                texts.append((_EBML_TEXT[child[0]],
                              data[pos + child[2]:pos + child[2] + min(size, _MAX_INFLATE)]))
            pos += child[2] + size
    return Media("Matroska / WebM video", pos, texts, problem)


def parse(data: bytes) -> Optional[Media]:
    """Structure of the media file in ``data`` (None = not a format read here)."""
    try:
        if data[:8] == _PNG:                                # (``data`` may be a memory map)
            return _png(data)
        if data[:3] == b"\xff\xd8\xff":
            return _jpeg(data)
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return _gif(data)
        if data[:4] == b"OggS":
            return _ogg(data)
        if data[:4] == b"RIFF" and len(data) >= 12:
            return _riff(data)
        if data[4:8] == b"ftyp":
            return _mp4(data)
        if data[:2] == b"BM" and len(data) >= 26:
            return _bmp(data)
        if data[:4] == b"MThd":
            return _midi(data)
        if data[:4] == b"\x1a\x45\xdf\xa3":
            return _webm(data)
        if data[:3] == b"ID3" or (len(data) > 4 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0):
            return _mp3(data)
    except (struct.error, IndexError):
        return Media("media file", 0, [], "the header is damaged")
    return None


def embedded_png_texts(data: bytes, limit: int = 64) -> List[bytes]:
    """Metadata of every PNG that starts inside ``data`` (a stream of assets):
    compressed text chunks are invisible to a plain read of the stream."""
    out: List[bytes] = []
    pos = data.find(_PNG)
    while pos >= 0 and limit > 0:
        out += [content for _where, content in _png(data, pos).texts]
        limit -= 1
        pos = data.find(_PNG, pos + 8)
    return out
