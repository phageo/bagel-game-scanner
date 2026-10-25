"""Build Bagel's icon: one ``.ico`` for the window, the taskbar, the shortcuts and the installer.

    python tools/build_icon.py --inputs <package_inputs folder>

(0.9-beta polish, phageo, 2026-10-24.) Standard library only (``zlib``, ``struct``). Two pictures of
the inputs folder (outside the project):

- ``bagel_pixel.png`` gives the small sizes 16, 24 and 32: cut to the drawing, then nearest-neighbour
  (every pixel is a pixel of the drawing - crisp, never blurred).
- ``bagel_ai.png`` gives 48, 64, 128 and 256, after its black background is removed:

  1. flood fill from the edges over dark pixels -> transparent (the hole of the ring is reached
     through its gap, as any background is: only what touches the edges by dark pixels);
  2. small isolated islands (parts not joined to the bagel, mostly dim (``ISLAND_DARK``), under
     ``ISLAND`` pixels) -> transparent. A dark pixel inside the bagel is part of the bagel's own
     part and is never touched;
  3. the outer edge only (pixels beside the removed background, at most ``FRINGE`` deep, darker
     than the bagel's rim): the black mixed into them is taken out (colour to alpha), so no dark
     line is left around the bagel.

  then cut to the drawing, set on a square, and shrunk by area (premultiplied alpha).

Writes ``gamescan/bagel.ico`` (16, 24, 32, 48, 64, 128 as 32-bit pictures, 256 as PNG) and, for
phageo, the cleaned 256 picture ``bagel_256_clean.png`` into the inputs folder. The same inputs
give the same bytes.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib
from typing import List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ICO = os.path.join(ROOT, "gamescan", "bagel.ico")
PIXEL, AI, CLEAN = "bagel_pixel.png", "bagel_ai.png", "bagel_256_clean.png"
SMALL, LARGE = (16, 24, 32), (48, 64, 128, 256)
DARK = 48              # a pixel whose brightest channel is at most this is "dark" (background)
ISLAND = 400           # parts not joined to the bagel and smaller than this are specks ...
ISLAND_DARK = 128      # ... when most of their pixels are at most this bright (what the fill left
                       # is brighter than DARK by definition: dim noise in the black)
FRINGE = 2             # how deep the outer edge is unmixed from the black
MAX_SIDE = 4096        # limit of a picture read here (rule 3)

Pixel = Tuple[int, int, int, int]


class IconError(Exception):
    pass


# -- PNG -------------------------------------------------------------------------------------------
def read_png(path: str) -> Tuple[int, int, List[Pixel]]:
    """``(width, height, RGBA pixels row by row)`` of an 8-bit RGB / RGBA PNG without interlace."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise IconError("not a PNG: " + path)
    pos, idat, head = 8, [], None
    while pos + 8 <= len(data):
        size, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + size]
        if kind == b"IHDR":
            head = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
        pos += 12 + size
    if head is None:
        raise IconError("no IHDR: " + path)
    w, h, depth, ctype, _comp, _filt, interlace = head
    if depth != 8 or ctype not in (2, 6) or interlace or not (0 < w <= MAX_SIDE and 0 < h <= MAX_SIDE):
        raise IconError("only 8-bit RGB / RGBA, not interlaced, at most %d px: %s" % (MAX_SIDE, path))
    step = 4 if ctype == 6 else 3
    stride = w * step
    raw = zlib.decompressobj().decompress(b"".join(idat), (stride + 1) * h + 1)
    if len(raw) < (stride + 1) * h:
        raise IconError("PNG data too short: " + path)
    rows, prev = [], bytearray(stride)
    for y in range(h):
        kind, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - step] if i >= step else 0
            b, c = prev[i], prev[i - step] if i >= step else 0
            if kind == 1:
                line[i] = (line[i] + a) & 255
            elif kind == 2:
                line[i] = (line[i] + b) & 255
            elif kind == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
            elif kind != 0:
                raise IconError("unknown PNG filter %d: %s" % (kind, path))
        rows.append(line)
        prev = line
    px = []
    for line in rows:
        for x in range(w):
            q = line[x * step:(x + 1) * step]
            px.append((q[0], q[1], q[2], q[3] if step == 4 else 255))
    return w, h, px


def write_png(w: int, h: int, px: List[Pixel]) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    raw = b"".join(b"\x00" + bytes(c for p in px[y * w:(y + 1) * w] for c in p) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


# -- the picture -----------------------------------------------------------------------------------
def bbox(w: int, h: int, px: List[Pixel]) -> Optional[Tuple[int, int, int, int]]:
    """``(left, top, right, bottom)`` (right / bottom outside) of the pixels that are not transparent."""
    xs = [i % w for i, p in enumerate(px) if p[3]]
    ys = [i // w for i, p in enumerate(px) if p[3]]
    return (min(xs), min(ys), max(xs) + 1, max(ys) + 1) if xs else None


def square(w: int, h: int, px: List[Pixel], margin: float = 0.0) -> Tuple[int, List[Pixel]]:
    """The drawing cut to its pixels and set in the middle of a transparent square."""
    box = bbox(w, h, px)
    if box is None:
        raise IconError("the picture is empty")
    left, top, right, bottom = box
    side = max(right - left, bottom - top)
    side += 2 * int(round(side * margin))
    out = [(0, 0, 0, 0)] * (side * side)
    ox, oy = (side - (right - left)) // 2, (side - (bottom - top)) // 2
    for y in range(top, bottom):
        for x in range(left, right):
            out[(y - top + oy) * side + (x - left + ox)] = px[y * w + x]
    return side, out


def nearest(side: int, px: List[Pixel], size: int) -> List[Pixel]:
    """Nearest-neighbour: each pixel of the result takes the source pixel under its centre."""
    return [px[((2 * y + 1) * side // (2 * size)) * side + (2 * x + 1) * side // (2 * size)]
            for y in range(size) for x in range(size)]


def _weights(src: int, dst: int) -> List[List[Tuple[int, float]]]:
    """Box (area) weights: which source cells each result cell covers, and how much."""
    scale = src / dst
    out = []
    for i in range(dst):
        a, b = i * scale, (i + 1) * scale
        cells, j = [], int(a)
        while j < b and j < src:
            cover = min(b, j + 1) - max(a, j)
            if cover > 0:
                cells.append((j, cover / scale))
            j += 1
        out.append(cells)
    return out


def shrink(side: int, px: List[Pixel], size: int) -> List[Pixel]:
    """Area average with premultiplied alpha (no dark halo from transparent pixels)."""
    pre = [(r * a, g * a, b * a, a) for r, g, b, a in px]
    wx = _weights(side, size)
    rows = []
    for y in range(side):
        line = pre[y * side:(y + 1) * side]
        rows.append([tuple(sum(line[j][c] * f for j, f in cells) for c in range(4)) for cells in wx])
    out = []
    for cells in wx:                                   # the same weights downwards (a square)
        for x in range(size):
            acc = [sum(rows[j][x][c] * f for j, f in cells) for c in range(4)]
            a = acc[3]
            if a < 0.5:
                out.append((0, 0, 0, 0))
            else:
                out.append(tuple(min(255, int(round(acc[c] / a))) for c in range(3))
                           + (min(255, int(round(a))),))
    return out


def _dark(p: Pixel) -> bool:
    return max(p[0], p[1], p[2]) <= DARK


def remove_background(w: int, h: int, px: List[Pixel]) -> Tuple[List[Pixel], dict]:
    """Steps 1-3 of the module text; returns the new pixels and counts of what was done."""
    gone = bytearray(w * h)                            # 1 = background (made transparent)
    stack = [i for i in range(w * h) if (i % w in (0, w - 1) or i // w in (0, h - 1)) and _dark(px[i])]
    for i in stack:
        gone[i] = 1
    while stack:                                       # 1. flood fill from the edges over dark pixels
        i = stack.pop()
        x, y = i % w, i // w
        for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
            if 0 <= nx < w and 0 <= ny < h:
                j = ny * w + nx
                if not gone[j] and _dark(px[j]):
                    gone[j] = 1
                    stack.append(j)
    filled = sum(gone)
    part = [0] * (w * h)                               # 2. parts of what is left (8 neighbours)
    sizes, darks = [0], [0]
    for start in range(w * h):
        if gone[start] or part[start]:
            continue
        label = len(sizes)
        sizes.append(0)
        darks.append(0)
        part[start] = label
        stack = [start]
        while stack:
            i = stack.pop()
            sizes[label] += 1
            darks[label] += max(px[i][:3]) <= ISLAND_DARK
            x, y = i % w, i // w
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < w and 0 <= ny < h:
                        j = ny * w + nx
                        if not gone[j] and not part[j]:
                            part[j] = label
                            stack.append(j)
    bagel = max(range(1, len(sizes)), key=lambda k: sizes[k]) if len(sizes) > 1 else 0
    specks = {k for k in range(1, len(sizes))
              if k != bagel and sizes[k] < ISLAND and darks[k] * 2 >= sizes[k]}
    for i in range(w * h):
        if part[i] in specks:
            gone[i] = 1
    out = [(0, 0, 0, 0) if gone[i] else px[i] for i in range(w * h)]
    depth = [0] * (w * h)                              # 3. distance to the removed background
    ring = [i for i in range(w * h) if not gone[i] and any(
        gone[j] for j in _around(i, w, h))]
    for i in ring:
        depth[i] = 1
    for level in range(2, FRINGE + 3):
        ring = [j for i in ring for j in _around(i, w, h) if not gone[j] and not depth[j]]
        for j in ring:
            depth[j] = level
    rim = sorted(max(px[i][:3]) for i in range(w * h) if depth[i] in (FRINGE + 1, FRINGE + 2))
    ref = rim[len(rim) // 2] if rim else 255
    unmixed = 0
    for i in range(w * h):
        if 0 < depth[i] <= FRINGE and part[i] == bagel:
            r, g, b, a = px[i]
            level = max(r, g, b)
            if level < ref:
                alpha = level / ref
                out[i] = (min(255, int(round(r / alpha))) if alpha else 0,
                          min(255, int(round(g / alpha))) if alpha else 0,
                          min(255, int(round(b / alpha))) if alpha else 0,
                          int(round(a * alpha)))
                unmixed += 1
    return out, {"background": filled, "specks": len(specks),
                 "speck pixels": sum(sizes[k] for k in specks), "edge unmixed": unmixed,
                 "rim level": ref, "bagel part": sizes[bagel] if bagel else 0,
                 "dim pixels kept inside the bagel": darks[bagel] if bagel else 0}


def _around(i: int, w: int, h: int):
    x, y = i % w, i // w
    for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
        if 0 <= nx < w and 0 <= ny < h:
            yield ny * w + nx


# -- ICO -------------------------------------------------------------------------------------------
def _dib(size: int, px: List[Pixel]) -> bytes:
    """A 32-bit picture as an icon entry: BITMAPINFOHEADER, BGRA rows bottom-up, the AND mask."""
    head = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = b"".join(bytes(c for r, g, b, a in px[y * size:(y + 1) * size] for c in (b, g, r, a))
                    for y in reversed(range(size)))
    stride = ((size + 31) // 32) * 4
    mask = bytearray()
    for y in reversed(range(size)):
        line = bytearray(stride)
        for x in range(size):
            if px[y * size + x][3] == 0:
                line[x // 8] |= 0x80 >> (x % 8)
        mask += line
    return head + rows + bytes(mask)


def ico(pictures: List[Tuple[int, List[Pixel]]]) -> bytes:
    """An ``.ico``: 256 as PNG (Windows Vista and later), the smaller ones as 32-bit pictures."""
    bodies = [write_png(size, size, px) if size >= 256 else _dib(size, px) for size, px in pictures]
    out = struct.pack("<HHH", 0, 1, len(pictures))
    offset = 6 + 16 * len(pictures)
    for (size, _px), body in zip(pictures, bodies):
        out += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(body), offset)
        offset += len(body)
    return out + b"".join(bodies)


def read_ico_sizes(data: bytes) -> List[int]:
    """The sizes listed in an ``.ico`` (for the tests and the release checklist)."""
    if len(data) < 6:
        raise IconError("not an icon file")
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    if reserved or kind != 1 or len(data) < 6 + 16 * count:
        raise IconError("not an icon file")
    return [(data[6 + 16 * k] or 256) for k in range(count)]


def build(inputs: str, out: str = ICO, say=print) -> bytes:
    w, h, px = read_png(os.path.join(inputs, PIXEL))
    side, small = square(w, h, px)
    pictures = [(size, nearest(side, small, size)) for size in SMALL]
    say("%s: %dx%d, drawing %d px -> %s (nearest-neighbour)" % (PIXEL, w, h, side, SMALL))
    w, h, px = read_png(os.path.join(inputs, AI))
    clean, counts = remove_background(w, h, px)
    say("%s: %dx%d; %s" % (AI, w, h, ", ".join("%s %s" % kv for kv in counts.items())))
    side, big = square(w, h, clean, margin=0.02)
    for size in LARGE:
        pictures.append((size, shrink(side, big, size)))
    data = ico(pictures)
    with open(out, "wb") as fh:
        fh.write(data)
    with open(os.path.join(inputs, CLEAN), "wb") as fh:
        fh.write(write_png(256, 256, pictures[-1][1]))
    say("%s: %d bytes, sizes %s; cleaned 256 picture: %s" % (
        out, len(data), read_ico_sizes(data), os.path.join(inputs, CLEAN)))
    return data


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--inputs", required=True, help="folder with bagel_pixel.png and bagel_ai.png")
    ap.add_argument("--out", default=ICO, help="the icon file (default: gamescan/bagel.ico)")
    args = ap.parse_args(argv)
    try:
        build(args.inputs, args.out)
    except (IconError, OSError, zlib.error) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
