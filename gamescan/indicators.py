"""The scanner's indicator strings, kept as compressed data instead of text in the modules.

(phageo, 2026-10-24, antivirus false positives.) The scanner has to know what malware looks
like: credential store paths, chat and wallet names, hook and download functions, pattern
texts. Written as plain strings in its own ``.py`` files, the package looked like a stealer
to several antivirus engines. So those strings live in one file beside this module,
``indicators.bin``, stored compressed; a module asks for its own strings once, at import::

    from .indicators import strings as _indicator_strings
    _IND = _indicator_strings("gamescan/rules.py")

and uses ``_IND[n]`` where the string stood. The values are exactly the ones the module had
(the tool that moved them, ``tools/move_indicators.py``, proves that by comparing the
modules' syntax trees), so nothing the scanner finds changes.

The format: ``MAGIC``, then raw deflate of UTF-8 JSON ``{"modules": {name: [value, ...]}}``;
a value is a JSON string, or ``{"b": base64}`` for bytes. It is read with ``zlib`` and
``json`` only - nothing in it is run (CLAUDE.md, rule 2) - and the decoded size is capped
(rule 3). This hides nothing from a person: ``tools/move_indicators.py --show`` prints it.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import zlib
from typing import Dict, Tuple, Union

MAGIC = b"GSS-INDICATORS 1\n"
FILE = "indicators.bin"
DECODED_CAP = 16 * 1024 * 1024        # the decoded JSON; the file is far smaller

_lock = threading.Lock()
_modules: Dict[str, Tuple[Union[str, bytes], ...]] = {}
_loaded = False


class IndicatorError(ValueError):
    """``indicators.bin`` is missing, damaged, or is not one."""


def _value(item) -> Union[str, bytes]:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and set(item) == {"b"} and isinstance(item["b"], str):
        return base64.b64decode(item["b"].encode("ascii"), validate=True)
    raise IndicatorError("not a string value")


def decode(data: bytes) -> Dict[str, Tuple[Union[str, bytes], ...]]:
    """``{module: (value, ...)}`` of the bytes of an indicator file."""
    if not data.startswith(MAGIC):
        raise IndicatorError("not an indicator file of this project")
    inflate = zlib.decompressobj(-15)
    try:
        text = inflate.decompress(data[len(MAGIC):], DECODED_CAP + 1)
    except zlib.error as exc:
        raise IndicatorError("the indicator file is damaged (%s)" % exc)
    if len(text) > DECODED_CAP or inflate.unconsumed_tail or not inflate.eof or inflate.unused_data:
        raise IndicatorError("the indicator file is too large or goes on behind its data")
    try:
        doc = json.loads(text.decode("utf-8"))
        return {str(name): tuple(_value(v) for v in values) for name, values in doc["modules"].items()}
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError) as exc:
        raise IndicatorError("the indicator file is not readable (%s)" % exc)


def encode(modules: Dict[str, Tuple[Union[str, bytes], ...]]) -> bytes:
    """The bytes of an indicator file holding ``modules`` (the tool's side; same order in, same
    bytes out)."""
    doc = {"modules": {name: [v if isinstance(v, str) else {"b": base64.b64encode(v).decode("ascii")}
                              for v in values] for name, values in modules.items()}}
    text = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pack = zlib.compressobj(9, zlib.DEFLATED, -15)
    return MAGIC + pack.compress(text) + pack.flush()


def path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), FILE)


def load() -> Dict[str, Tuple[Union[str, bytes], ...]]:
    """Every module's strings (read once, then kept)."""
    global _loaded
    with _lock:
        if not _loaded:
            try:
                with open(path(), "rb") as fh:
                    data = fh.read(DECODED_CAP + 1)
            except OSError as exc:
                raise IndicatorError("the indicator file could not be read (%s)" % exc)
            _modules.update(decode(data))
            _loaded = True
        return _modules


def strings(module: str) -> Tuple[Union[str, bytes], ...]:
    """The strings of ``module`` (its name in the package below ``app/``, as
    ``gamescan/dataflow/pyflow.py``), in the order its ``_IND[n]`` use them."""
    found = load().get(module)
    if found is None:
        raise IndicatorError("the indicator file has no strings of " + module)
    return found
