"""LZX decompression as Microsoft cabinets use it - pure Python, in memory (phageo, 2026-10-19).

LZX is Huffman-coded LZ77 with a sliding window of 2^15 .. 2^21 bytes. A cabinet folder is one
LZX stream: its data blocks (``CFDATA``) are read one after the other as one stream of 16-bit
little-endian words, and each data block gives one *frame* of output (at most 32 KB). The stream
holds:

* once, at its start: one bit, and when it is set the 32-bit "file size" of the x86 call
  translation (``E8``);
* LZX blocks, each with a 3-bit type and a 24-bit length - *verbatim*, *aligned offset* (both
  Huffman-coded) or *uncompressed* (stored bytes after the three repeated offsets). A block may
  run on over several frames; a match never runs over the end of a frame.

The Huffman trees are sent as the change of every code length from the block before (through a
"pretree" of 20 codes) - so the lengths are carried from block to block, like the window and the
three repeated match offsets. At the end of each frame the stream is aligned to 16 bits again and
the frame's ``E8`` calls are turned back from absolute to relative addresses.

Everything is bounded: a frame is at most 32 KB and every symbol writes at least one byte, so
the decoding loop of a frame ends; tree reading walks a fixed number of lengths; a code longer
than 16 bits, a tree that is not a prefix code, a match before the start of the output or beyond
the window, a frame that does not come out at its size, or data that runs out raise
:class:`LzxError` - never a wrong answer in silence where the format allows the check.

The format is described by Microsoft's "LZX DELTA Compression and Decompression" ([MS-PATCH]) and
the cabinet format documentation; the order of the steps follows them. Nothing here runs the
decoded data.
"""
from __future__ import annotations

from typing import Iterator, List, Optional

FRAME = 32768                        # output of one cabinet data block, at most
_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}    # window size (2^n bytes) -> offset slots
_VERBATIM, _ALIGNED, _UNCOMPRESSED = 1, 2, 3
_CODE_BITS = 16                      # the longest code; every tree is looked up 16 bits at a time
_PRETREE, _ALIGNED_TREE, _LENGTHS = 20, 8, 249
_SAFETY = 64                         # room behind a length table for a run that overshoots (as the format allows)

_EXTRA: List[int] = []
_BASE: List[int] = []
for _slot in range(51):
    _EXTRA.append(min(max(_slot // 2 - 1, 0), 17))
for _slot in range(51):
    _BASE.append(0 if not _slot else _BASE[-1] + (1 << _EXTRA[_slot - 1]))


class LzxError(ValueError):
    """The LZX data is damaged, or not what the cabinet says it is."""


def _table(lengths: List[int], count: int) -> Optional[List[int]]:
    """A 16-bit lookup table for a canonical Huffman code: entry = symbol << 5 | code length.
    None for a tree with no codes at all (allowed - the tree must then not be used); a set of
    lengths that is no prefix code raises."""
    size = 1 << _CODE_BITS
    table = [0] * size
    at = 0
    used = False
    for length in range(1, _CODE_BITS + 1):
        step = 1 << (_CODE_BITS - length)
        for symbol in range(count):
            if lengths[symbol] == length:
                if at + step > size:
                    raise LzxError("a Huffman tree is not a prefix code (too many codes)")
                table[at:at + step] = [symbol << 5 | length] * step
                at += step
                used = True
    if not used:
        return None
    if at != size:
        if sum(1 for symbol in range(count) if lengths[symbol]) == 1:
            return table[:at] + [0] * (size - at)          # one code only: the rest is no code
        raise LzxError("a Huffman tree is not complete")
    return table


class Decoder:
    """One LZX stream (one cabinet folder). ``chunks`` gives the compressed data blocks in
    order; :meth:`frame` gives the next frame of output, of the size the data block states."""

    def __init__(self, window_bits: int, chunks: Iterator[bytes]) -> None:
        if window_bits not in _SLOTS:
            raise LzxError("an LZX window of 2^%d bytes (cabinets use 2^15 to 2^21)" % window_bits)
        self.size = 1 << window_bits
        self.window = bytearray(self.size)
        self.slots = _SLOTS[window_bits]
        self.chunks = chunks
        self.data, self.pos = b"", 0             # input not yet read
        self.ended = False                      # no more chunks
        self.padded = 0                         # bytes of zeros given past the end
        self.bits, self.left = 0, 0             # bit buffer: ``left`` bits, the next one highest
        self.main_lengths = [0] * (256 + 8 * self.slots + _SAFETY)
        self.length_lengths = [0] * (_LENGTHS + _SAFETY)
        self.main = self.lengths = self.aligned = None
        self.block_type = 0
        self.block_left = self.block_length = 0
        self.r0 = self.r1 = self.r2 = 1
        self.header = False
        self.e8_size = 0
        self.e8_started = False
        self.e8_at = 0
        self.wpos = self.frame_start = 0        # where the next byte goes in the window
        self.done = 0                         # bytes of output so far
        self.frames = 0

    # -- input ----------------------------------------------------------------------------
    def pull(self) -> bool:
        """Take the next compressed chunk into the input; False when there is none."""
        if self.ended:
            return False
        try:
            chunk = next(self.chunks)
        except StopIteration:
            self.ended = True
            return False
        self.data = self.data[self.pos:] + chunk
        self.pos = 0
        return True

    def _word(self) -> int:
        if self.pos + 2 > len(self.data) and not self._more(2):
            self.padded += 2                    # reading ahead past the end gives zeros, as in the format
            if self.padded > 4:
                raise LzxError("the LZX data is cut short")
            return 0
        p = self.pos
        self.pos = p + 2
        return self.data[p] | self.data[p + 1] << 8

    def _more(self, need: int) -> bool:
        while self.pos + need > len(self.data):
            if not self.pull():
                return False
        return True

    def _need(self, n: int) -> None:
        while self.left < n:
            self.bits = (self.bits & ((1 << self.left) - 1)) << 16 | self._word()
            self.left += 16

    def _read(self, n: int) -> int:
        if not n:
            return 0
        self._need(n)
        self.left -= n
        return (self.bits >> self.left) & ((1 << n) - 1)

    def _symbol(self, table: Optional[List[int]]) -> int:
        if table is None:
            raise LzxError("an empty Huffman tree is used")
        self._need(_CODE_BITS)
        entry = table[(self.bits >> (self.left - _CODE_BITS)) & 0xFFFF]
        if not entry & 31:
            raise LzxError("a code that is in no Huffman tree")
        self.left -= entry & 31
        return entry >> 5

    def _byte(self) -> int:
        if self.pos >= len(self.data) and not self._more(1):
            raise LzxError("the LZX data is cut short")
        value = self.data[self.pos]
        self.pos += 1
        return value

    # -- trees ----------------------------------------------------------------------------
    def _lengths(self, lengths: List[int], first: int, last: int) -> None:
        pre = [self._read(4) for _ in range(_PRETREE)]
        tree = _table(pre, _PRETREE)
        limit = last + _SAFETY
        x = first
        while x < last:
            code = self._symbol(tree)
            if code == 17:
                run, value = self._read(4) + 4, 0
            elif code == 18:
                run, value = self._read(5) + 20, 0
            elif code == 19:
                run = self._read(1) + 4
                value = (lengths[x] - self._symbol(tree)) % 17
            else:
                run, value = 1, (lengths[x] - code) % 17
            if x + run > limit:
                raise LzxError("a run of code lengths goes past its table")
            lengths[x:x + run] = [value] * run
            x += run

    def _block_header(self) -> None:
        if self.block_type == _UNCOMPRESSED and self.block_length & 1:
            self._byte()                         # an odd stored block is followed by one pad byte
        self.block_type = self._read(3)
        self.block_left = self.block_length = self._read(16) << 8 | self._read(8)
        if self.block_type == _ALIGNED:
            self.aligned = _table([self._read(3) for _ in range(_ALIGNED_TREE)], _ALIGNED_TREE)
        if self.block_type in (_VERBATIM, _ALIGNED):
            self._lengths(self.main_lengths, 0, 256)
            self._lengths(self.main_lengths, 256, 256 + 8 * self.slots)
            self.main = _table(self.main_lengths, 256 + 8 * self.slots)
            if self.main_lengths[0xE8]:
                self.e8_started = True
            self._lengths(self.length_lengths, 0, _LENGTHS)
            self.lengths = _table(self.length_lengths, _LENGTHS)
        elif self.block_type == _UNCOMPRESSED:
            self.e8_started = True
            if self.left == 0:                   # align to 16 bits: 1 to 16 bits are dropped
                self._need(16)
            self.bits, self.left = 0, 0
            stored = bytes(self._byte() for _ in range(12))
            self.r0, self.r1, self.r2 = (int.from_bytes(stored[i:i + 4], "little") for i in (0, 4, 8))
        else:
            raise LzxError("an LZX block of unknown type %d" % self.block_type)

    # -- frames ---------------------------------------------------------------------------
    def frame(self, size: int) -> bytes:
        """The next ``size`` bytes of output (one cabinet data block: 1 .. 32768)."""
        if not 0 < size <= FRAME:
            raise LzxError("a data block of %d bytes (1 to %d)" % (size, FRAME))
        if not self.header:
            self.header = True
            if self._read(1):
                self.e8_size = self._read(16) << 16 | self._read(16)
        start = self.frame_start = self.wpos
        if start + size > self.size:
            raise LzxError("a frame runs over the end of the window")
        todo = size
        while todo > 0:
            if self.block_left == 0:
                self._block_header()
                if self.block_left == 0:
                    raise LzxError("an empty LZX block")
            run = min(self.block_left, todo)
            todo -= run
            self.block_left -= run
            if self.block_type == _UNCOMPRESSED:
                self._stored(run)
                continue
            over = self._coded(run, start + size)
            if over:
                if over > self.block_left:
                    raise LzxError("a match runs past the end of its block")
                self.block_left -= over
                todo -= over
        if self.wpos - start != size:
            raise LzxError("a frame does not come out at its stated size")
        if self.left & 15:                       # align to 16 bits for the next frame
            self.left -= self.left & 15
        out = self.window[start:start + size]
        if self.e8_started and self.e8_size and self.frames < 32768 and size > 10:
            out = self._e8(out)
        elif self.e8_size:
            self.e8_at += size
        self.frames += 1
        self.done += size
        self.wpos = 0 if self.wpos == self.size else self.wpos
        return bytes(out)

    def _stored(self, run: int) -> None:
        if self.left:
            raise LzxError("stored bytes that do not start on a byte")
        while run > 0:
            if self.pos >= len(self.data) and not self._more(1):
                raise LzxError("the LZX data is cut short")
            piece = self.data[self.pos:self.pos + run]
            self.window[self.wpos:self.wpos + len(piece)] = piece
            self.pos += len(piece)
            self.wpos += len(piece)
            run -= len(piece)

    def _coded(self, run: int, end: int) -> int:
        """Decode ``run`` bytes (a verbatim or aligned block); returns how far the last match went
        beyond ``run`` (it may, within the block and the frame)."""
        window, size = self.window, self.size
        main, lengths, aligned = self.main, self.lengths, self.aligned
        if main is None:
            raise LzxError("an empty Huffman tree is used")
        is_aligned = self.block_type == _ALIGNED
        r0, r1, r2 = self.r0, self.r1, self.r2
        wpos = self.wpos
        base = self.done - self.frame_start     # output so far = base + window position, in this frame
        need, bits_, extra_, base_ = self._need, _CODE_BITS, _EXTRA, _BASE
        target = wpos + run
        while wpos < target:
            if self.left < bits_:
                need(bits_)
            left = self.left
            entry = main[(self.bits >> (left - bits_)) & 0xFFFF]
            length = entry & 31
            if not length:
                raise LzxError("a code that is in no Huffman tree")
            self.left = left - length
            symbol = entry >> 5
            if symbol < 256:
                window[wpos] = symbol
                wpos += 1
                continue
            symbol -= 256
            match = symbol & 7
            if match == 7:
                match += self._symbol(lengths)
            match += 2
            slot = symbol >> 3
            if slot > 2:
                extra = extra_[slot]
                offset = base_[slot] - 2
                if is_aligned and extra >= 3:
                    if extra > 3:
                        offset += self._read(extra - 3) << 3
                    offset += self._symbol(aligned)
                elif extra:
                    offset += self._read(extra)
                else:
                    offset = 1
                r2, r1, r0 = r1, r0, offset
            elif slot == 0:
                offset = r0
            elif slot == 1:
                offset, r1, r0 = r1, r0, r1
            else:
                offset, r2, r0 = r2, r0, r2
            if wpos + match > end:
                raise LzxError("a match runs over the end of its frame")
            if offset > base + wpos or offset > size:
                raise LzxError("a match reaches before the start of the data")
            src = wpos - offset
            if src >= 0 and offset >= match:
                window[wpos:wpos + match] = window[src:src + match]
            elif src >= 0:
                piece = window[src:wpos]
                window[wpos:wpos + match] = (piece * (match // offset + 1))[:match]
            else:
                src += size                     # from the far end of the window
                for i in range(match):
                    window[wpos + i] = window[src]
                    src = src + 1 if src + 1 < size else 0
            wpos += match
        self.r0, self.r1, self.r2 = r0, r1, r2
        over = wpos - target
        self.wpos = wpos
        return over

    def _e8(self, out: bytearray) -> bytearray:
        """Undo the x86 call translation of one frame: a 32-bit value after an ``E8`` byte was
        made absolute by the compressor; it is made relative again."""
        size = len(out)
        limit = size - 10
        at, curpos, filesize = 0, self.e8_at, self.e8_size
        while True:
            found = out.find(0xE8, at, limit)
            if found < 0:
                break
            curpos += found - at
            value = int.from_bytes(out[found + 1:found + 5], "little", signed=True)
            if -curpos <= value < filesize:
                value = value - curpos if value >= 0 else value + filesize
                out[found + 1:found + 5] = (value & 0xFFFFFFFF).to_bytes(4, "little")
            at = found + 5
            curpos += 5
        self.e8_at += size
        return out
