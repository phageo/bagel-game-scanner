"""Real-time protection (user mode): watch folders, scan what appears.

This polls the watched folders and scans every new or changed file once it
has stopped growing. It reacts *after* a file is written - it cannot stop a
program from starting, which needs a kernel driver. It is the same idea as an
antivirus "download shield", not on-access blocking.
"""
from __future__ import annotations

import os
import threading
from typing import Callable, Dict, Iterable, Optional, Tuple

from .models import ScanReport

_PARTIAL = (".crdownload", ".part", ".partial", ".tmp", ".download", ".quar")
Signature = Tuple[int, int]                      # (mtime in ns, size)


class RealTimeMonitor:
    def __init__(self, folders: Iterable[str], scan_file: Callable[[str], ScanReport],
                 on_result: Callable[[str, ScanReport], None], interval: float = 2.0,
                 max_entries: int = 50_000) -> None:
        self.folders = [os.path.abspath(f) for f in folders if f and os.path.isdir(f)]
        self.scan_file, self.on_result = scan_file, on_result
        self.interval, self.max_entries = interval, max_entries
        self.scanned = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if not self.running and self.folders:
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="realtime-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _snapshot(self) -> Dict[str, Signature]:
        seen: Dict[str, Signature] = {}
        for root in self.folders:
            stack = [root]
            while stack and len(seen) < self.max_entries:
                try:
                    with os.scandir(stack.pop()) as entries:
                        for entry in entries:
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    stack.append(entry.path)
                                elif entry.is_file(follow_symlinks=False) and \
                                        not entry.name.lower().endswith(_PARTIAL):
                                    st = entry.stat()
                                    seen[entry.path] = (st.st_mtime_ns, st.st_size)
                            except OSError:
                                continue
                except OSError:
                    continue
        return seen

    def _run(self) -> None:
        known = self._snapshot()                 # what is already there is not re-scanned
        pending: Dict[str, Signature] = {}
        while not self._stop.wait(self.interval):
            current = self._snapshot()
            for path, sig in current.items():
                if known.get(path) == sig:
                    continue
                if pending.get(path) != sig:     # still being written: wait one more round
                    pending[path] = sig
                    continue
                del pending[path]
                known[path] = sig
                try:
                    report = self.scan_file(path)
                except Exception:                # locked, deleted meanwhile, ...
                    continue
                self.scanned += 1
                self.on_result(path, report)
                if self._stop.is_set():
                    return
            for path in [p for p in known if p not in current]:
                del known[path]                  # deleted files may come back later
            for path in [p for p in pending if p not in current]:
                del pending[path]
