"""Unpacked data of any size, without holding it in memory.

An archive member used to be a ``bytes`` object, which is why members were
capped at 32 MB and a file's unpacked total at 1 GB. A :class:`Collector`
takes a member piece by piece instead: while it is small it stays in memory;
once it passes ``MEMORY`` it continues in a temporary file. The result
(:class:`Blob`) carries the size and SHA-256 of the whole member either way,
and is scanned like a large file on disk - streamed, not loaded.

About the temporary files:

* they hold exactly what the archive member holds, so they are named
  ``gss-*.part`` (never ``.exe`` or the like), created readable by the
  current user only, and are never executed or opened by anything but this
  scanner;
* each one is deleted as soon as the member has been scanned
  (:meth:`Blob.release`);
* before and while one is written, the free space of the temporary drive is
  checked: unpacking stops with :class:`SpoolError` rather than filling the
  disk (``RESERVE`` bytes are always left free);
* inside :func:`private_folder` (the secure launcher) they all go into one
  folder made for that scan, which is removed with whatever is left in it
  when the scan ends - also when it ends with an error.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from typing import List, Optional

MEMORY = 32 * 1024 * 1024            # larger members continue on disk
HEAD = 64 * 1024 * 1024              # what of a spooled member is kept in memory for the scan
RESERVE = 2 * 1024 * 1024 * 1024     # free space that is never used up
DISK = True                          # False: memory-only scan - nothing is written, anywhere
FOLDER: Optional[str] = None         # where temporary files go (None: the system's temporary folder)
_CHECK_EVERY = 64 * 1024 * 1024


class SpoolError(OSError):
    """A member could not be spooled (no space left to do it safely)."""


def free_space() -> int:
    try:
        return shutil.disk_usage(FOLDER or tempfile.gettempdir()).free
    except OSError:
        return 0


def temporary_file(suffix: str = ".part"):
    """``(handle, path)`` of a new temporary file of the scanner: readable by
    the current user only, named ``gss-*``. The default suffix cannot be run."""
    return tempfile.mkstemp(prefix="gss-", suffix=suffix, dir=FOLDER)


@contextlib.contextmanager
def private_folder():
    """A temporary folder of its own for the scans made inside the block (made
    for the current user only). It is removed with everything still in it when
    the block ends, however it ends."""
    global FOLDER
    previous = FOLDER
    FOLDER = tempfile.mkdtemp(prefix="gss-")
    try:
        yield FOLDER
    finally:
        folder, FOLDER = FOLDER, previous
        shutil.rmtree(folder, ignore_errors=True)


class Blob:
    """One unpacked member: in memory (``path`` is None) or in a temporary file."""

    __slots__ = ("data", "path", "size", "sha256")

    def __init__(self, data: bytes, path: Optional[str], size: int, sha256: str) -> None:
        self.data, self.path, self.size, self.sha256 = data, path, size, sha256

    def read(self) -> bytes:
        """The whole content (only for members known to be small enough)."""
        if self.path is None:
            return self.data
        with open(self.path, "rb") as fh:
            return fh.read()

    def release(self) -> None:
        if self.path is not None:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.path = None


class Collector:
    """Write-only buffer that moves to disk when it grows (file-like enough
    for the callers here: ``write`` and ``tell``)."""

    def __init__(self, memory: Optional[int] = None) -> None:
        self.memory = MEMORY if memory is None else memory
        self.parts: List[bytes] = []
        self.size = 0
        self.digest = hashlib.sha256()
        self.file = None
        self.path: Optional[str] = None
        self._checked = 0

    def write(self, data: bytes) -> int:
        if not data:
            return 0
        if self.file is None and self.size + len(data) > self.memory:
            self._to_disk()
        if self.file is not None:
            if self.size - self._checked >= _CHECK_EVERY:
                self._check(len(data))
            self.file.write(data)
        else:
            self.parts.append(bytes(data))
        self.digest.update(data)
        self.size += len(data)
        return len(data)

    def tell(self) -> int:
        return self.size

    def _check(self, more: int) -> None:
        self._checked = self.size
        if free_space() < RESERVE + more:
            self.discard()
            raise SpoolError("not enough free disk space to unpack this member safely")

    def _to_disk(self) -> None:
        if not DISK:
            raise SpoolError("larger than %d MB: not unpacked in a memory-only scan"
                             % (self.memory >> 20))
        if free_space() < RESERVE + self.size:
            raise SpoolError("not enough free disk space to unpack this member safely")
        handle, self.path = temporary_file()
        self.file = os.fdopen(handle, "wb")
        for part in self.parts:
            self.file.write(part)
        self.parts = []

    def discard(self) -> None:
        """Drop what was collected (an unwanted or failed member)."""
        if self.file is not None:
            self.file.close()
            self.file = None
        if self.path is not None:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.path = None
        self.parts = []

    def finish(self) -> Blob:
        """The member; after this the collector must not be written to."""
        if self.file is None:
            return Blob(b"".join(self.parts), None, self.size, self.digest.hexdigest())
        self.file.close()
        self.file = None
        with open(self.path, "rb") as fh:
            head = fh.read(HEAD)
        blob, self.path = Blob(head, self.path, self.size, self.digest.hexdigest()), None
        return blob

    def result(self):
        """``bytes`` for a member that stayed in memory, else its :class:`Blob`."""
        blob = self.finish()
        return blob.data if blob.path is None else blob


def collect(pieces, memory: Optional[int] = None):
    """``bytes`` or :class:`Blob` from an iterable of pieces."""
    collector = Collector(memory)
    try:
        for piece in pieces:
            collector.write(piece)
    except BaseException:
        collector.discard()
        raise
    return collector.result()


def size_of(data) -> int:
    return data.size if isinstance(data, Blob) else len(data)


def head_of(data) -> bytes:
    return data.data if isinstance(data, Blob) else data
