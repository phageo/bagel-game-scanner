"""Name a piece of content by what it is.

Some installers (NSIS, Inno Setup) are read here without their file tables,
so what comes out has no file name. The scanner routes files by extension,
and "a program whose name says otherwise" is itself a finding - so an
extracted piece gets the extension its content really has.
"""
from __future__ import annotations

import re
import struct

_SCRIPTS = (
    (".ps1", re.compile(rb"(?im)^\s*\$\w+\s*=|New-Object|Invoke-\w+|\bGet-\w+|\bSet-\w+|param\s*\(")),
    (".vbs", re.compile(rb"(?im)CreateObject\s*\(|WScript\.|^\s*Dim\s+\w+|^\s*On Error Resume")),
    (".bat", re.compile(rb"(?im)^\s*@?echo\b|%~dp0|^\s*(?:set|start|reg|cmd|powershell|call|goto|if)\b")),
    (".js", re.compile(rb"(?m)\bfunction\s*\w*\s*\(|\bvar\s+\w+\s*=|\brequire\s*\(|=>\s*\{")),
)
_TEXT = bytes(range(0x20, 0x7F)) + b"\t\r\n"

# -- formats the scanner has no reader for (phageo, 2026-10-17, fifty-eighth message) -----------
# A file of one of these kinds came out with no finding and no note: an MSI package, a disk
# image, a single compressed file ... Each gets the "could not be read" note now (ARC-002), so a
# scan holding one is at least REVIEW. By the first bytes, and by the ending for a file whose
# bytes say nothing (a raw disk image) or are cut off.
UNREAD_ENDINGS = {
    ".msi": "Windows Installer package", ".msp": "Windows Installer patch",
    ".msm": "Windows Installer merge module", ".mst": "Windows Installer transform",
    ".iso": "disk image (ISO)", ".udf": "disk image (UDF)", ".img": "disk image",
    ".vhd": "virtual hard disk", ".vhdx": "virtual hard disk", ".vmdk": "virtual machine disk",
    ".vdi": "virtual machine disk", ".qcow2": "virtual machine disk", ".dmg": "macOS disk image",
    ".wim": "Windows image (WIM)", ".swm": "Windows image (WIM)", ".esd": "Windows image (WIM)",
    ".chm": "compiled HTML help",
    ".gz": "gzip archive", ".tgz": "gzip archive", ".xz": "xz archive", ".txz": "xz archive",
    ".bz2": "bzip2 archive", ".tbz": "bzip2 archive", ".tbz2": "bzip2 archive", ".tar": "tar archive",
    ".zst": "Zstandard archive", ".tzst": "Zstandard archive", ".lzma": "LZMA archive", ".z": "compress archive",
    ".lz": "lzip archive", ".lzh": "LHA archive", ".lha": "LHA archive", ".arj": "ARJ archive",
    ".ace": "ACE archive", ".cpio": "cpio archive", ".xar": "xar archive", ".deb": "Debian package",
    ".rpm": "RPM package", ".squashfs": "SquashFS image", ".snap": "SquashFS image",
}
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# the class of an OLE file's root entry: Windows Installer database (84), patch (86), transform (82)
_MSI_CLASSES = {bytes([kind]) + b"\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46": what
                for kind, what in ((0x84, "Windows Installer package"), (0x86, "Windows Installer patch"),
                                   (0x82, "Windows Installer transform"))}
_UNREAD_MAGICS = (
    (0, b"\x1f\x8b\x08", "gzip archive"), (0, b"\xfd7zXZ\x00", "xz archive"),
    (0, b"(\xb5/\xfd", "Zstandard archive"), (0, b"MSWIM\x00\x00\x00", "Windows image (WIM)"),
    (0, b"ITSF\x03\x00\x00\x00", "compiled HTML help"), (0, b"vhdxfile", "virtual hard disk"),
    (0, b"conectix", "virtual hard disk"), (0, b"KDMV", "virtual machine disk"),
    (0, b"QFI\xfb", "virtual machine disk"), (0, b"xar!", "xar archive"),
    (0, b"!<arch>\ndebian-binary", "Debian package"), (0, b"\xed\xab\xee\xdb", "RPM package"),
    (0, b"hsqs", "SquashFS image"), (0, b"LZIP", "lzip archive"),
    (7, b"**ACE**", "ACE archive"), (0, b"070707", "cpio archive"), (0, b"070701", "cpio archive"),
    (0, b"070702", "cpio archive"),
    (257, b"ustar", "tar archive"),
    (0x8001, b"CD001", "disk image (ISO)"), (0x8801, b"CD001", "disk image (ISO)"),
    (0x9001, b"CD001", "disk image (ISO)"), (0x8001, b"BEA01", "disk image (UDF)"),
)
UNREAD_HEAD = 0x9006                    # the bytes :func:`unread_kind` looks at


def unread_kind(data: bytes, ending: str = "") -> str:
    """What ``data`` is, when it is a format the scanner has no reader for ("" = none of
    them): by its first bytes (``data`` may be only the head of the file - ``UNREAD_HEAD``
    bytes are enough), else by ``ending`` (lower case, with its dot)."""
    head = data[:UNREAD_HEAD]
    for at, magic, what in _UNREAD_MAGICS:
        if head[at:at + len(magic)] == magic:
            return what
    if head[:3] == b"BZh" and head[3:4] in b"123456789" and head[4:10] in (b"1AY&SY", b"\x17rE8P\x90"):
        return "bzip2 archive"
    if head[2:5] == b"-lh" and head[6:7] == b"-":
        return "LHA archive"
    if head[:2] == b"\x60\xea" and len(head) > 10 and head[10] == 2:      # ARJ: its main header
        return "ARJ archive"
    if head[:8] == _OLE and len(head) >= 512:
        shift = int.from_bytes(head[0x1E:0x20], "little")
        first = int.from_bytes(head[0x30:0x34], "little")
        if shift in (9, 12):
            at = ((first + 1) << shift) + 0x50
            what = _MSI_CLASSES.get(bytes(data[at:at + 16])) if first < 0xFFFFFFFA else None
            if what:
                return what
    return UNREAD_ENDINGS.get(ending, "")


def extension(data: bytes) -> str:
    """Extension for ``data`` ("" = nothing the scanner has a use for)."""
    head = data[:16]
    if head[:2] == b"MZ":
        try:
            lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            flags = struct.unpack_from("<H", data, lfanew + 22)[0]
            return ".dll" if flags & 0x2000 else ".exe"
        except struct.error:
            return ".exe"
    if head[:7] == b"RGSSAD\0":
        return ".rgss3a" if head[7:8] == b"\x03" else ".rgssad"
    if head[:4] == b"PK\x03\x04":
        return ".zip"
    if head[:4] == b"MSCF":
        return ".cab"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return ".7z"
    if head[:6] == b"Rar!\x1a\x07":
        return ".rar"
    if head[:8] == b"UnityFS\0":
        return ".bundle"
    if head[:8] == b"RENPY RP" or head[:4] == b"RPA-":
        return ".rpa" if head[:4] == b"RPA-" else ".rpyc"
    if head[:2] == b"\x04\x08" and len(data) > 8:           # Ruby Marshal: RPG Maker data
        return ".rvdata2" if b'I"' in data[:4096] else ".rxdata"
    sample = data[:65536]
    if sample and len(sample.translate(None, _TEXT)) * 20 <= len(sample):   # >= 95% text
        for ext, rx in _SCRIPTS:
            if len(rx.findall(sample)) >= 2:
                return ext
    return ""
