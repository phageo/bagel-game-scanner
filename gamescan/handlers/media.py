"""Images, audio and video: is there anything in the file besides the media?"""
from __future__ import annotations

import hashlib
import mmap
from typing import Iterable, Iterator, List

from ..models import Category, FileContext, Finding, Severity
from ..rules import RuleEngine
from ..unpack import media, sniff, unity
from .base import BaseHandler

EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ogg", ".oga", ".wav",
                        ".mp3", ".m4a", ".mp4", ".mov", ".avi", ".webm", ".mkv", ".mka", ".ogv", ".mid", ".midi"})
_WINDOW = 8 * 1024 * 1024
_MAX_APPENDED = 64 * 1024 * 1024       # of what follows the media, this much is analysed
_SEAM = 16 * 1024


class MediaHandler(BaseHandler):
    """Reads media files by their structure (see :mod:`gamescan.unpack.media`).

    * the container is walked as its format defines it; data after its end,
      or where its structure breaks, is not picture or sound and is analysed
      as what it is (program, archive, script, text);
    * metadata is read, including compressed PNG text chunks;
    * the rules read only the text parts (metadata, chunks that are not
      picture or sound) and what lies beyond the media's own structure (phageo,
      2026-10-23): the picture / sound data itself is random bytes, in which
      short words like ``wmic`` turn up by chance. A file whose format is not
      recognised has no such structure: it goes through a sliding window that
      returns every printable run, whatever its size;
    * a Windows program anywhere inside the file is carved out and analysed.
    """

    name = "media"
    engine = "Media"
    extensions = EXTENSIONS

    def can_handle(self, ctx: FileContext) -> bool:
        return ctx.ext in self.extensions and not ctx.is_pe

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if ctx.truncated and ctx.on_disk:
            # larger than what is loaded: its structure is read from a memory map of the file
            with open(ctx.path, "rb") as fh, \
                    mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                ctx.cache["streamed"] = True                # (all of it is at hand)
                return self._scan(ctx, rules, view)
        return self._scan(ctx, rules, ctx.data)

    def _scan(self, ctx: FileContext, rules: RuleEngine, data) -> List[Finding]:
        out: List[Finding] = []
        children: List[FileContext] = []
        info = media.parse(data)
        strings: List[str] = []
        if info is None:
            # the name says media, the content does not start like any format read here
            # (encrypted assets, MP3, MIDI, ...): fine, unless it is something runnable
            ext = sniff.extension(data[:_MAX_APPENDED])
            if ext:
                out.append(self.make(
                    ctx, "MEDIA-002", "Program, archive or script behind a media file",
                    Category.EVASION, Severity.HIGH, "The file is named like a picture or sound "
                    "but its content is something that can run or unpack.",
                    "%s: content is %s" % (ctx.name, ext), 0.8))
                children.append(self._child(ctx, "content" + ext, data[:_MAX_APPENDED]))
        else:
            for _where, content in info.texts:
                strings += media.runs(content)
            # what the format itself does not account for: everything behind the
            # media's end, or from the point where its structure breaks. (A file
            # that merely stops early has nothing extra in it.)
            rest = data[info.end:info.end + _MAX_APPENDED]
            if len(data) < ctx.size:                        # a member that is only partly at hand
                rest = b""
            else:
                strings += media.runs(rest)                 # beyond the structure: read as text
            if not media.blank(rest):
                ext = sniff.extension(rest)
                where = "%d bytes %s" % (len(rest), "from where the structure breaks (%s)"
                                         % info.problem if info.problem else
                                         "after the end of the %s at offset %d" % (info.kind, info.end))
                if ext:
                    out.append(self.make(
                        ctx, "MEDIA-002", "Program, archive or script behind a media file",
                        Category.EVASION, Severity.HIGH, "A valid picture or sound is followed "
                        "by something that can run or unpack. The file opens normally in a "
                        "viewer, and a loader can pull the hidden part out.",
                        "%s; it is %s content" % (where, ext), 0.8))
                    children.append(self._child(ctx, "appended" + ext, rest))
                else:
                    preview = " ".join(media.runs(rest[:4096])[:2])[:80]
                    out.append(self.make(
                        ctx, "MEDIA-001", "Data in a media file that is not part of the media",
                        Category.EVASION, Severity.LOW, "The picture or sound ends before the "
                        "file does, or its structure is broken at one point. Some editing tools "
                        "leave data there; it is also a place to park a payload. What is there "
                        "was read as text and searched for programs.",
                        where + (": " + preview if preview else ""), 0.35))
        if info is None:
            # no structure known: the whole file in a sliding window, every printable run
            for window in self._windows(ctx):
                strings += media.runs(window)
        text = "\n".join(dict.fromkeys(strings))
        out += rules.scan(text, "strings", ctx, self.name, numbered=False)
        if not children:
            for offset, image, is_dll in unity.carve_executables(data, limit=4):
                out.append(self.make(
                    ctx, "MEDIA-002", "Program, archive or script behind a media file",
                    Category.EVASION, Severity.HIGH, "A Windows program is stored inside a "
                    "file that is named, and may even open, as a picture or sound.",
                    "%s image at offset 0x%x, %d KB" % ("DLL" if is_dll else "EXE", offset,
                                                         len(image) // 1024), 0.8))
                children.append(self._child(ctx, "embedded_0x%x.%s" % (
                    offset, "dll" if is_dll else "exe"), image))
        ctx.cache["media_children"] = children
        return out

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        return ctx.cache.get("media_children", ())

    @staticmethod
    def _windows(ctx: FileContext) -> Iterator[bytes]:
        """The file in overlapping windows; a file too large to be loaded is
        read from disk, to its end."""
        if not (ctx.truncated and ctx.on_disk):
            data = ctx.data
            for start in range(0, len(data), _WINDOW):
                yield data[max(start - _SEAM, 0):start + _WINDOW]
            return
        ctx.cache["streamed"] = True
        with open(ctx.path, "rb") as fh:
            tail, done = b"", 0
            while not ctx.cancelled:
                block = fh.read(_WINDOW)
                if not block:
                    break
                done += len(block)
                ctx.tick(done / max(ctx.size, 1))
                yield tail + block
                tail = block[-_SEAM:]

    @staticmethod
    def _child(ctx: FileContext, name: str, data: bytes) -> FileContext:
        return FileContext(path=ctx.path, relpath="%s!%s" % (ctx.relpath, name), data=data,
                           size=len(data), sha256=hashlib.sha256(data).hexdigest())
