"""LZ4 block decoding with the standard library only - and on every CPU core.

Three ways to decode, fastest available first:

1. the native ``lz4`` package, *if* it happens to be installed (optional);
2. :class:`Pool` - the pure-Python decoder below, run in several worker
   processes at once. A Unity bundle is tens of thousands of independent
   128 KB blocks, so the work spreads over all cores;
3. :func:`block` in this process.

All three produce the same bytes and refuse the same damaged input: whatever
the native module rejects is decoded again by the pure-Python reader.

The workers are this very file started as a script (``python lz4block.py
--lz4-worker``). It therefore imports nothing from the package, and it only
ever talks to its parent: through its own stdin / stdout and two areas of
shared memory that the parent created for it.
"""
from __future__ import annotations

import collections
import os
import queue
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Iterator, List, Optional, Tuple

MAX_OUT = 64 * 1024 * 1024
_WORKER_FLAG = "--lz4-worker"

try:                                   # optional accelerator: pip install lz4
    from lz4 import block as _native
except Exception:                      # not installed (or broken): pure Python below
    _native = None


def native() -> bool:
    return _native is not None


def block(src: bytes, limit: int = MAX_OUT) -> bytes:
    """Decode one raw LZ4 block (ValueError if it is damaged or over ``limit``)."""
    if _native is not None and src:
        try:
            # LZ4 cannot expand more than 255x, so the buffer is small for a small block
            return _native.decompress(src, uncompressed_size=min(limit, 255 * len(src) + 64))
        except Exception:
            pass
    return pure(src, limit)


def pure(src: bytes, limit: int = MAX_OUT) -> bytes:
    """The pure-Python decoder."""
    dst = bytearray()
    i, n = 0, len(src)
    try:
        while i < n and len(dst) < limit:
            token = src[i]
            i += 1
            length = token >> 4
            if length == 15:
                while True:
                    b = src[i]
                    i += 1
                    length += b
                    if b != 255:
                        break
            dst += src[i:i + length]
            i += length
            if i >= n:
                break
            offset = src[i] | src[i + 1] << 8
            i += 2
            length = token & 15
            if length == 15:
                while True:
                    b = src[i]
                    i += 1
                    length += b
                    if b != 255:
                        break
            length += 4
            start = len(dst) - offset
            if offset == 0 or start < 0:
                raise ValueError("corrupt LZ4 block")
            if len(dst) + length > limit:          # a few bytes can ask for gigabytes
                raise ValueError("LZ4 block expands beyond the limit")
            if offset >= length:
                dst += dst[start:start + length]
            else:                                  # overlapping copy = repeat the tail
                chunk = bytes(dst[start:])
                dst += (chunk * (length // offset + 1))[:length]
    except IndexError:
        raise ValueError("truncated LZ4 block") from None
    return bytes(dst)


# -- worker processes -----------------------------------------------------------------
Batch = List[Tuple[int, bytes]]                    # [(decoded-size limit, packed block)]
CAPACITY = 8 * 1024 * 1024                         # packed, and decoded, bytes of one batch


def default_workers() -> int:
    try:
        cores = len(os.sched_getaffinity(0))       # the cores this process may really use
    except AttributeError:
        cores = os.cpu_count() or 1
    return max(1, min(cores - 1, 12))


class _Worker:
    """One worker process and the two shared-memory areas it exchanges data
    through. (A pipe moves a few kilobytes per system call; block data in
    shared memory is what lets the work really scale with the cores.) The
    pipe only carries the sizes."""

    def __init__(self) -> None:
        from multiprocessing import shared_memory
        self.inbox = shared_memory.SharedMemory(create=True, size=CAPACITY)
        try:
            self.outbox = shared_memory.SharedMemory(create=True, size=CAPACITY)
            self.proc = subprocess.Popen(
                [sys.executable, "-I", os.path.abspath(__file__), _WORKER_FLAG,
                 self.inbox.name, self.outbox.name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            self.close()
            raise

    def ask(self, batch: Batch) -> List[Optional[bytes]]:
        """One request / reply: the packed blocks go into ``inbox``, their
        ``(limit, size)`` over the pipe; the sizes (-1 = damaged) come back
        over the pipe and the decoded blocks lie in ``outbox``."""
        at, head = 0, [struct.pack("<I", len(batch))]
        for limit, packed in batch:
            self.inbox.buf[at:at + len(packed)] = packed
            at += len(packed)
            head.append(struct.pack("<II", limit, len(packed)))
        self.proc.stdin.write(b"".join(head))
        self.proc.stdin.flush()
        sizes = struct.unpack("<%di" % len(batch), _exactly(self.proc.stdout, 4 * len(batch)))
        out: List[Optional[bytes]] = []
        at = 0
        for (limit, _packed), size in zip(batch, sizes):
            if size > limit or at + max(size, 0) > CAPACITY:
                raise ValueError("worker reply out of range")
            out.append(None if size < 0 else bytes(self.outbox.buf[at:at + size]))
            at += max(size, 0)
        return out

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        proc = getattr(self, "proc", None)
        if proc is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            proc.stdout.close()
        for name in ("inbox", "outbox"):
            area = getattr(self, name, None)
            if area is not None:
                try:
                    area.close()
                    area.unlink()
                except (OSError, BufferError):
                    pass


class Pool:
    """Decode batches of LZ4 blocks in worker processes, results in order.

    Any trouble with a worker (it cannot start, it dies) only costs speed: the
    batch it was given is decoded in this process instead.
    """

    def __init__(self, workers: Optional[int] = None) -> None:
        self.size = workers or default_workers()
        self._free: "queue.Queue" = queue.Queue()
        self._workers: List[_Worker] = []
        self._threads = ThreadPoolExecutor(self.size)
        for _ in range(self.size):
            try:
                worker = _Worker()
                self._workers.append(worker)
            except Exception:                      # no shared memory / no interpreter to start
                worker = None
            self._free.put(worker)

    @property
    def alive(self) -> int:
        return sum(1 for w in self._workers if w.alive())

    def _run(self, batch: Batch) -> List[Optional[bytes]]:
        if not batch:
            return []
        worker = self._free.get()
        try:
            if (worker is not None and worker.alive()
                    and sum(len(packed) for _limit, packed in batch) <= CAPACITY
                    and sum(limit for limit, _packed in batch) <= CAPACITY):
                try:
                    return worker.ask(batch)
                except (OSError, ValueError, struct.error):
                    worker.proc.kill()             # out of step: never reuse it
            return _decode(batch)
        finally:
            self._free.put(worker)

    def map(self, batches: Iterable[Batch]) -> Iterator[List[Optional[bytes]]]:
        """Decoded blocks of each batch (``None`` = that block is damaged), in
        order. Only a few batches are in flight at any time."""
        pending: "collections.deque" = collections.deque()
        for batch in batches:
            pending.append(self._threads.submit(self._run, batch))
            if len(pending) >= 6 * self.size:
                yield pending.popleft().result()
        while pending:
            yield pending.popleft().result()

    def close(self) -> None:
        self._threads.shutdown(wait=True)
        for worker in self._workers:
            worker.close()

    def __enter__(self) -> "Pool":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _decode(batch: Batch) -> List[Optional[bytes]]:
    out: List[Optional[bytes]] = []
    for limit, packed in batch:
        try:
            data = block(packed, limit)
            out.append(data if len(data) <= limit else None)
        except ValueError:
            out.append(None)
    return out


def _exactly(stream, count: int) -> bytes:
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("worker pipe closed")
    return data


def _worker(inbox_name: str, outbox_name: str) -> None:
    from multiprocessing import shared_memory
    kwargs = {"track": False} if sys.version_info >= (3, 13) else {}
    inbox = shared_memory.SharedMemory(name=inbox_name, **kwargs)
    outbox = shared_memory.SharedMemory(name=outbox_name, **kwargs)
    if not kwargs and os.name != "nt":             # the parent owns them: do not unlink at exit
        from multiprocessing import resource_tracker
        for area in (inbox, outbox):
            resource_tracker.unregister(area._name, "shared_memory")
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    try:
        while True:
            head = stdin.read(4)
            if len(head) < 4:
                return                             # parent closed the pipe
            count = struct.unpack("<I", head)[0]
            spec = struct.unpack("<%dI" % (2 * count), _exactly(stdin, 8 * count))
            sizes, read_at, write_at = [], 0, 0
            for i in range(count):
                limit, size = spec[2 * i], spec[2 * i + 1]
                data = _decode([(limit, bytes(inbox.buf[read_at:read_at + size]))])[0]
                read_at += size
                if data is None or write_at + len(data) > CAPACITY:
                    sizes.append(-1)
                else:
                    outbox.buf[write_at:write_at + len(data)] = data
                    write_at += len(data)
                    sizes.append(len(data))
            stdout.write(struct.pack("<%di" % count, *sizes))
            stdout.flush()
    finally:
        inbox.close()
        outbox.close()


if __name__ == "__main__" and sys.argv[1:2] == [_WORKER_FLAG] and len(sys.argv) == 4:
    try:
        _worker(sys.argv[2], sys.argv[3])
    except (ValueError, OSError, KeyboardInterrupt):
        pass