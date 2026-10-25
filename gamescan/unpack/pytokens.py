"""Python source without its comments and spacing, as one key.

For one question: was an engine file changed in its code, or only in comments,
blank lines and spacing? The source is cut into tokens with the standard
library's ``tokenize`` - text only; nothing is compiled, imported or run - and
the key is a SHA-256 over the tokens that mean something: names, numbers,
texts, operators, the ends of statements and where a block begins and ends.
Left out: comments, blank lines, how wide an indentation is, the spaces
between tokens.

The engine files in question are Python 2, and the tokenizer is the one of
the Python that runs the scanner: some Python 2 spellings (``0777``,
backticks) are no tokens for it. Such a file gets no key - nothing is said
about it then. The official table (``compiled_hashes.SOURCES``) is built with
the same function, so a key is only ever compared with keys made the same way.

Limits: source size and number of tokens; one pass.
"""
from __future__ import annotations

import hashlib
import io
import struct
import tokenize
from typing import Optional

from . import limits

_MAX_SIZE = 16 * 1024 * 1024
_MAX_TOKENS = 2_000_000
_LEFT_OUT = frozenset({tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER})
# kept as a mark only: their text is spacing
_MARKS = {tokenize.NEWLINE: b"\n", tokenize.INDENT: b">", tokenize.DEDENT: b"<"}


def names(source: bytes) -> Optional[frozenset]:
    """Every name written in a Python source file - what the tokenizer calls
    a name: variables, functions, attributes, keywords (None: too large, or
    not readable as tokens). Names inside texts and comments do not count."""
    if len(source) > _MAX_SIZE:
        limits.hit("pyo", "a source file larger than %d MB: not compared" % (_MAX_SIZE >> 20))
        return None
    found = set()
    try:
        for count, token in enumerate(tokenize.tokenize(io.BytesIO(source).readline)):
            if count > _MAX_TOKENS:
                limits.hit("pyo", "a source file of more than %d tokens: not compared" % _MAX_TOKENS)
            if count > _MAX_TOKENS or token.type == tokenize.ERRORTOKEN:
                return None
            if token.type == tokenize.NAME:
                found.add(token.string)
    except (tokenize.TokenError, SyntaxError, ValueError, LookupError, RecursionError, MemoryError):
        return None
    return frozenset(found)


def token_key(source: bytes) -> Optional[str]:
    """SHA-256 over the tokens of a Python source file, comments and spacing
    left out (None: too large, or not readable as tokens)."""
    if len(source) > _MAX_SIZE:
        limits.hit("pyo", "a source file larger than %d MB: not compared" % (_MAX_SIZE >> 20))
        return None
    digest = hashlib.sha256(b"py-tokens-1\0")
    try:
        for count, token in enumerate(tokenize.tokenize(io.BytesIO(source).readline)):
            if count > _MAX_TOKENS:
                limits.hit("pyo", "a source file of more than %d tokens: not compared" % _MAX_TOKENS)
            if count > _MAX_TOKENS or token.type == tokenize.ERRORTOKEN:
                return None
            if token.type in _LEFT_OUT:
                continue
            mark = _MARKS.get(token.type)
            if mark is not None:
                digest.update(b"\0" + mark)
            else:
                text = token.string.encode("utf-8", "surrogatepass")
                digest.update(b"\1" + struct.pack("<I", len(text)) + text)
    except (tokenize.TokenError, SyntaxError, ValueError, LookupError, RecursionError, MemoryError):
        return None
    return digest.hexdigest()
