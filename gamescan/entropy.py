"""Statistical entropy analysis for spotting packed / encrypted payloads.

Shannon entropy says how unpredictable the bytes are (8.0 = pure noise). On
its own it cannot tell compression from encryption, so :func:`classify` also
uses a chi-square test of the byte histogram against a uniform distribution:
ciphertext is statistically flat, compressed data is merely close to it.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Tuple, Union

HIGH = 7.2                     # bits/byte: above this, data is packed or encrypted
_LITERAL = re.compile(r"""(['"`])([^'"`\s\\]{120,4000})\1""")
_BASE64 = re.compile(r"[A-Za-z0-9+/=]+\Z")


def shannon(buf: Union[bytes, str]) -> float:
    """Entropy in bits per symbol (bytes: 0-8)."""
    if not buf:
        return 0.0
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in Counter(buf).values())


def chi_square(buf: bytes) -> float:
    """Chi-square of the byte histogram vs. uniform (about 255 for random data)."""
    if not buf:
        return 0.0
    expected = len(buf) / 256.0
    counts = Counter(buf)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


@dataclass
class EntropyProfile:
    overall: float            # entropy of the whole sample
    mean: float               # mean entropy of the windows
    peak: float               # most random window
    high_fraction: float      # share of windows at or above HIGH
    chi2: float
    kind: str                 # "encrypted" | "compressed" | "plain"

    def describe(self) -> str:
        return ("entropy %.2f / 8.00, %d%% of blocks high-entropy, chi-square %.0f (%s)"
                % (self.overall, round(self.high_fraction * 100), self.chi2, self.kind))


def classify(overall: float, chi2: float) -> str:
    if overall >= 7.9 and chi2 < 500:
        return "encrypted"
    return "compressed" if overall >= HIGH else "plain"


def profile(data: bytes, window: int = 4096, max_windows: int = 1024,
            sample: int = 2 * 1024 * 1024) -> EntropyProfile:
    """Windowed entropy profile; large inputs are sampled evenly."""
    if not data:
        return EntropyProfile(0.0, 0.0, 0.0, 0.0, 0.0, "plain")
    count = max(1, len(data) // window)
    step = max(1, count // max_windows)
    values = [shannon(data[i * window:(i + 1) * window]) for i in range(0, count, step)]
    stride = max(1, len(data) // sample)
    body = data[::stride] if stride > 1 else data
    overall, chi2 = shannon(body), chi_square(body)
    # a 4 KB window can reach at most ~7.95 bits, so the per-window bar is lower
    high = sum(1 for v in values if v >= HIGH - 0.2) / len(values)
    return EntropyProfile(overall, sum(values) / len(values), max(values), high, chi2,
                          classify(overall, chi2))


def consecutive(body: str, share: float = 0.9) -> bool:
    """Is the text a run of neighbouring characters - each one the character
    right after the one before it ("abcdef...", a block of a character table)?
    Every character is different then, so the entropy is as high as it can
    be, and yet there is nothing in it: what comes next is always known. A
    payload cannot be written that way. ``share`` of the steps have to be
    exactly one; the rest may be gaps in the table."""
    if len(body) < 16:
        return False
    steps = sum(1 for a, b in zip(body, body[1:]) if ord(b) - ord(a) == 1)
    return steps >= share * (len(body) - 1)


def high_entropy_literals(text: str, threshold: float = 5.0,
                          limit: int = 400) -> List[Tuple[int, int, float]]:
    """``(start, end, entropy)`` of long, dense string literals in source text.

    English prose sits near 4.2 bits/char and hex at 4.0; encrypted or
    custom-encoded payloads are well above 5. Plain Base64 is left to the
    dedicated blob rule so it is not reported twice.
    """
    out = []
    for n, m in enumerate(_LITERAL.finditer(text)):
        if n >= limit:
            break
        body = m.group(2)
        if len(body) >= 240 and _BASE64.match(body):
            continue
        if consecutive(body):
            continue                             # an alphabet, not a payload
        value = shannon(body)
        if value >= threshold:
            out.append((m.start(), m.end(), value))
    return out
