"""Authenticode verification through Windows' own trust provider.

``WinVerifyTrust`` checks that a file carries an embedded digital signature,
that the file has not been modified since it was signed, and that the
signing certificate chains to a root Windows trusts. No network access is
made (revocation lists are used only if already cached).

A valid signature says *who published the file and that it is unmodified*.
It does not say the publisher is benign - stolen and abused certificates
exist - so the scanner treats it like an engine baseline: it silences
heuristics, never CRITICAL findings or a blocklist hit.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/trust.py")

import os
import sys
from typing import Dict, Optional, Tuple

_cache: Dict[Tuple[str, int, int], bool] = {}


def is_signed_and_trusted(path: str) -> bool:
    """True if ``path`` has a valid, trusted embedded Authenticode signature."""
    if sys.platform != "win32":
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    # keyed by content identity, not just the path: a file replaced at the
    # same path (real-time protection sees this) must be verified again
    key = (os.path.normcase(path), st.st_mtime_ns, st.st_size)
    if key not in _cache:
        if len(_cache) > 20000:
            _cache.clear()
        try:
            _cache[key] = _verify(path)
        except Exception:                        # missing API, odd path, ...
            _cache[key] = False
    return _cache[key]


_names: Dict[Tuple[str, int, int], str] = {}


def signer_name(path: str) -> Optional[str]:
    """Publisher named on a file's valid signature.

    Returns None when the file has no valid, trusted signature, and "" when
    the signature is valid but the name could not be read.
    """
    if not is_signed_and_trusted(path):
        return None
    try:
        st = os.stat(path)
        key = (os.path.normcase(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    if key not in _names:
        try:
            _names[key] = _subject(path)
        except Exception:
            _names[key] = ""
    return _names[key]


def _subject(path: str) -> str:
    """Subject (organisation) of the signing certificate, via crypt32."""
    import ctypes
    from ctypes import wintypes

    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    void, dword = ctypes.c_void_p, wintypes.DWORD
    crypt.CryptQueryObject.argtypes = [dword, wintypes.LPCWSTR, dword, dword, dword,
                                       ctypes.POINTER(dword), ctypes.POINTER(dword),
                                       ctypes.POINTER(dword), ctypes.POINTER(void),
                                       ctypes.POINTER(void), void]
    crypt.CryptQueryObject.restype = wintypes.BOOL
    crypt.CryptMsgGetParam.argtypes = [void, dword, dword, void, ctypes.POINTER(dword)]
    crypt.CryptMsgGetParam.restype = wintypes.BOOL
    crypt.CertFindCertificateInStore.argtypes = [void, dword, dword, dword, void, void]
    crypt.CertFindCertificateInStore.restype = void
    crypt.CertGetNameStringW.argtypes = [void, dword, dword, void, wintypes.LPWSTR, dword]
    crypt.CertGetNameStringW.restype = dword
    crypt.CertFreeCertificateContext.argtypes = [void]
    crypt.CertCloseStore.argtypes = [void, dword]
    crypt.CryptMsgClose.argtypes = [void]

    store, message = void(), void()
    # CERT_QUERY_OBJECT_FILE, ..._PKCS7_SIGNED_EMBED, ..._FORMAT_FLAG_BINARY
    if not crypt.CryptQueryObject(1, path, 0x400, 2, 0, None, None, None,
                                  ctypes.byref(store), ctypes.byref(message), None):
        return ""
    cert = None
    try:
        size = dword(0)
        if not crypt.CryptMsgGetParam(message, 7, 0, None, ctypes.byref(size)):   # SIGNER_CERT_INFO
            return ""
        info = ctypes.create_string_buffer(size.value)
        if not crypt.CryptMsgGetParam(message, 7, 0, info, ctypes.byref(size)):
            return ""
        # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_FIND_SUBJECT_CERT
        cert = crypt.CertFindCertificateInStore(store, 0x10001, 0, 0xB0000, info, None)
        if not cert:
            return ""
        name = ctypes.create_unicode_buffer(256)
        crypt.CertGetNameStringW(cert, 4, 0, None, name, 256)      # SIMPLE_DISPLAY_TYPE
        return name.value.strip()
    finally:
        if cert:
            crypt.CertFreeCertificateContext(cert)
        crypt.CertCloseStore(store, 0)
        crypt.CryptMsgClose(message)


def _verify(path: str) -> bool:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    class FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class TrustData(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    (_IND[0], ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(FileInfo)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                  (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    info = FileInfo(ctypes.sizeof(FileInfo), path, None, None)
    data = TrustData()
    data.cbStruct = ctypes.sizeof(TrustData)
    data.dwUIChoice = 2                          # WTD_UI_NONE
    data.fdwRevocationChecks = 0                 # WTD_REVOKE_NONE
    data.dwUnionChoice = 1                       # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(info)
    data.dwStateAction = 0                       # WTD_STATEACTION_IGNORE
    data.dwProvFlags = 0x1000 | 0x10             # cache-only retrieval, no revocation check
    verify = ctypes.WinDLL("wintrust").WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    verify.restype = wintypes.LONG
    return verify(None, ctypes.byref(action), ctypes.byref(data)) == 0
