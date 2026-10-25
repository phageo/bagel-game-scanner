"""Protection for the API keys kept in the settings file.

On Windows a key is encrypted with DPAPI (``CryptProtectData``) before it is
written: the result can only be decrypted by the same Windows user account
on the same PC, with no password to manage and nothing but ``ctypes``
needed. A copy of ``settings.json`` taken to another machine or read by
another account is useless.

On other systems there is no such service in the standard library; there
the settings file itself is restricted to its owner (mode 0600, folder
0700) and the key is stored in it as it is.

A stored value looks like ``dpapi:<base64>``. Anything else found in the
file is taken to be a key saved in plain text by an earlier version; it is
used, and re-written protected on the next save.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/secrets_store.py")

import base64
import ctypes
import os
import sys
from typing import Optional

PREFIX = "dpapi:"
_PURPOSE = b"GameSafetyScanner settings v1"      # mixed in, so other programs' blobs do not open
_UI_FORBIDDEN = 0x1


class _Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """Is OS-level encryption available (Windows DPAPI)?"""
    return sys.platform == "win32"


def _call(function_name: str, data: bytes) -> Optional[bytes]:
    try:
        crypt32, kernel32 = ctypes.WinDLL("crypt32"), ctypes.WinDLL("kernel32")
        function = getattr(crypt32, function_name)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        source = _Blob(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                              ctypes.POINTER(ctypes.c_char)))
        purpose = _Blob(len(_PURPOSE), ctypes.cast(
            ctypes.create_string_buffer(_PURPOSE, len(_PURPOSE)), ctypes.POINTER(ctypes.c_char)))
        out = _Blob()
        if not function(ctypes.byref(source), None, ctypes.byref(purpose), None, None,
                        _UI_FORBIDDEN, ctypes.byref(out)):
            return None
        try:
            return ctypes.string_at(out.data, out.size)
        finally:
            kernel32.LocalFree(ctypes.cast(out.data, ctypes.c_void_p))
    except (OSError, AttributeError):
        return None


def protect(secret: str) -> Optional[str]:
    """The value to write to disk for ``secret``; None if it cannot be
    protected here (the caller must then not write it in plain text on
    Windows)."""
    if not secret:
        return ""
    if not available():
        return secret                              # the file's permissions are the protection
    sealed = _call(_IND[0], secret.encode("utf-8"))
    return None if sealed is None else PREFIX + base64.b64encode(sealed).decode("ascii")


def reveal(stored: str) -> str:
    """The secret behind a stored value ("" if it cannot be decrypted - another
    user, another PC, or a damaged value)."""
    if not isinstance(stored, str) or not stored.startswith(PREFIX):
        return stored if isinstance(stored, str) else ""
    try:
        opened = _call(_IND[1], base64.b64decode(stored[len(PREFIX):], validate=True))
    except ValueError:
        return ""
    try:
        return "" if opened is None else opened.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def is_protected(stored: str) -> bool:
    return isinstance(stored, str) and (stored.startswith(PREFIX) or not stored)


def restrict(path: str) -> None:
    """Owner-only access for a file or folder (meaningful off Windows; on
    Windows the profile folder is already private to the user and the keys
    are encrypted)."""
    try:
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
    except OSError:
        pass
