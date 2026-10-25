"""Microsoft Script Encoder (``.vbe``, ``.jse``, and ``#@~^`` blocks inside ``.wsf`` /
``.hta`` / ``.html`` files): decoded as data, standard library only.

The Script Encoder hides a script from a casual reader; the Windows Script Host
decodes and runs it like a plain one. An encoded block is

    #@~^  LLLLLL==  <encoded text>  CCCCCC==  ^#~@

``LLLLLL`` is the length of the encoded text (in characters) and ``CCCCCC`` a
checksum of the decoded one - the sum of its ASCII characters - (both a 32-bit
number in Base64). Characters outside ASCII stand in the block as they are. Every character of the script is
replaced through one of three tables, which one is taken from a fixed pattern of
64 steps; ``<``, ``>``, ``@``, carriage return and line feed are written as
``@!``, ``@*``, ``@$``, ``@#``, ``@&``.

Nothing is run. A block is only accepted when its length fits and its checksum
is that of the decoded text; anything else is said to be unreadable
(:class:`Block` ``.problem``), so that the caller can say so (CLAUDE.md, rule 15).
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import List, NamedTuple, Tuple

from . import limits

MAX_BLOCKS = 256                    # encoded blocks of one file that are decoded
MAX_ENCODED = 16 * 1024 * 1024      # characters of one block
MARK = "#@~^"
END = "^#~@"

# for the characters 9, 32, 33 ... 126 in this order: what each of the three tables turns it
# into ("???": the character is never encoded this way - it is written as an escape)
_RAW = (
    "64 37 69|50 7E 2C|22 5A 65|4A 45 72|61 3A 5B|5E 79 66|5D 59 75|5B 27 4C|42 76 45|60 63 76|23 62 2A|65 4D 43|"
    "5F 51 33|7E 53 42|4F 52 20|52 20 63|7A 26 4A|21 54 5A|46 71 38|20 2B 79|26 66 32|63 2A 57|2A 58 6C|76 7F 2B|"
    "47 7B 46|25 30 52|2C 31 4F|29 6C 3D|69 49 70|3F 3F 3F|27 78 7B|3F 3F 3F|67 5F 51|3F 3F 3F|62 29 7A|41 24 7E|"
    "5A 2F 3B|66 39 47|32 33 41|73 6F 77|4D 21 56|43 75 5F|71 28 26|39 42 78|7C 46 6E|53 4A 64|48 5C 74|31 48 67|"
    "72 36 7D|6E 4B 68|70 7D 35|49 5D 22|3F 6A 55|4B 50 3A|6A 69 60|2E 23 6A|7F 09 71|28 70 6F|35 65 49|7D 74 5C|"
    "24 2C 5D|2D 77 27|54 44 59|37 3F 25|7B 6D 7C|3D 7C 23|6C 43 6D|34 38 28|6D 5E 31|4E 5B 39|2B 6E 7F|30 57 36|"
    "6F 4C 54|74 34 34|6B 72 62|4C 25 4E|33 56 30|56 73 5E|3A 68 73|78 55 09|57 47 4B|77 32 61|3B 35 24|44 2E 4D|"
    "2F 64 6B|59 4F 44|45 3B 21|5C 2D 37|68 41 53|36 61 58|58 7A 48|79 22 2E|09 60 50|75 6B 2D|38 4E 29|55 3D 3F")
_ESCAPED = frozenset("<>@")
# which table each step of 64 uses
_PICK = (1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
         1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2)
_UNESCAPE = {"&": "\n", "#": "\r", "*": ">", "!": "<", "$": "@"}


def _tables() -> Tuple[dict, dict, dict]:
    plain = [9] + list(range(32, 127))
    tables: Tuple[dict, dict, dict] = ({}, {}, {})
    for char, row in zip(plain, _RAW.split("|")):
        if chr(char) in _ESCAPED:
            continue
        for table, code in zip(tables, row.split()):
            table[chr(int(code, 16))] = chr(char)
    return tables


_DECODE = _tables()
_BLOCK = re.compile(re.escape(MARK) + r"([A-Za-z0-9+/]{6})==")


class Block(NamedTuple):
    start: int              # where the block begins in the file's text (at its mark)
    end: int                # ... and where it ends (behind its end mark; the end of the text when cut short)
    text: str               # the decoded script ("" when it could not be decoded)
    problem: str            # "" - or why the block could not be decoded


def _number(text: str) -> int:
    return int.from_bytes(base64.b64decode(text + "=="), "little")


def _decode(data: str) -> str:
    out: List[str] = []
    step, at, end = 0, 0, len(data)
    while at < end:
        char = data[at]
        at += 1
        if char == "@":
            if at >= end or data[at] not in _UNESCAPE:
                raise ValueError("an escape that the encoder does not write")
            out.append(_UNESCAPE[data[at]])
            at += 1
            step += 1                                   # (an escape moves the pattern on like any character)
            continue
        if ord(char) >= 128:
            # a character outside ASCII (Turkish, Japanese ...) is left as it is, and it does
            # not move the pattern on (checked against Windows' own encoder)
            out.append(char)
            continue
        plain = _DECODE[_PICK[step % 64]].get(char)
        if plain is None:
            raise ValueError("a character that the encoder does not write")
        out.append(plain)
        step += 1
    return "".join(out)


def blocks(text: str) -> List[Block]:
    """Every encoded block in ``text``, decoded (or with the reason why not)."""
    out: List[Block] = []
    for match in _BLOCK.finditer(text):
        if len(out) >= MAX_BLOCKS:
            out.append(Block(match.start(), len(text), "", limits.hit("screnc", "more than %d encoded blocks" % MAX_BLOCKS)))
            break
        if out and match.start() < out[-1].end:
            continue                                    # a mark inside a block that was already taken
        start = match.end()
        try:
            length = _number(match.group(1))
        except (binascii.Error, ValueError):
            out.append(Block(match.start(), len(text), "", "the length of the block cannot be read"))
            continue
        if length > MAX_ENCODED:
            out.append(Block(match.start(), len(text), "", limits.hit("screnc", "an encoded block larger than %d MB" % (MAX_ENCODED >> 20))))
            continue
        data, tail = text[start:start + length], text[start + length:start + length + 12]
        if len(data) < length or not re.fullmatch(r"[A-Za-z0-9+/]{6}==" + re.escape(END), tail):
            # where it ends is not known then: everything up to its end mark (or to the end of
            # the text) is left out - nothing of a damaged block is read as if it were plain
            close = text.find(END, start)
            out.append(Block(match.start(), close + len(END) if close >= 0 else len(text), "",
                             "the block is cut short, or its length does not fit"))
            continue
        end = start + length + 12
        try:
            decoded = _decode(data)
            wanted = _number(tail[:6])
        except (binascii.Error, ValueError) as exc:
            out.append(Block(match.start(), end, "", str(exc) or "the block cannot be decoded"))
            continue
        # (the checksum is the sum of the ASCII characters of the script; the others are not in it)
        if sum(ord(char) for char in decoded if ord(char) < 128) & 0xFFFFFFFF != wanted:
            out.append(Block(match.start(), end, "", "the checksum of the block does not fit what was decoded"))
            continue
        out.append(Block(match.start(), end, decoded, ""))
    return out


def decode(text: str) -> Tuple[str, List[str]]:
    """``(text with every encoded block replaced by its script, problems)``. A block that
    cannot be decoded is left out (its lines are kept empty, so that line numbers hold)."""
    found = blocks(text)
    if not found:
        return text, []
    out, at, problems = [], 0, []
    for block in found:
        out.append(text[at:block.start])
        if block.problem:
            problems.append(block.problem)
            out.append("\n" * text.count("\n", block.start, block.end))
        else:
            out.append(block.text)
        at = block.end
    out.append(text[at:])
    return "".join(out), problems


def encoded(text: str) -> bool:
    """Does ``text`` hold a Script Encoder block?"""
    return MARK in text
