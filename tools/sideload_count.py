"""Count what SIDELOAD-001 rests on (phageo, 2026-10-17): numbers only.

For one package - a folder of a clean sample, or a real sample the positive benchmark's
runner holds in memory - every library named like a part of Windows or a Microsoft
redistributable that lies beside a program importing it or loading it by name
(:mod:`gamescan.sideload`) is counted by what clears it:

* **in an official table** - by its SHA-256 a file of an official release
  (engine, Electron, Inno Setup, NSIS, a known library);
* **validly signed by Microsoft** - Windows' own check on a file on disk;
* **a signature naming Microsoft, not checked** - in a scan in memory Windows cannot
  check a signature; such a library is counted here when the certificate block it
  carries names Microsoft (only a name in the block: no proof);
* **neither** - SIDELOAD-001 is made for it.

Nothing else is printed: no name, no path, no content.

    python tools/sideload_count.py <folder of one clean sample> [...]

Real samples: ``tools/positive_benchmark.py <folders> --out <csv> --sideload-count``.
"""
from __future__ import annotations

import os
import sys
from typing import Callable, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

COLUMNS = ("programs asking for such a library", "libraries beside such a program", "in an official table",
           "validly signed by Microsoft", "a signature naming Microsoft, not checked (memory)",
           "signed by someone else", "no signature, or not a valid one", "SIDELOAD-001 made",
           "... of them: imported", "... of them: loaded by name")
_MICROSOFT = (b"Microsoft Corporation", b"Microsoft Code Signing PCA", b"Microsoft Windows Production PCA")


def count(scanner, scan: Callable[[], object]) -> Dict[str, int]:
    """Run ``scan()`` (which must scan with ``scanner``) and return the numbers of ``COLUMNS``."""
    from gamescan import sideload
    out = {column: 0 for column in COLUMNS}
    names_microsoft = set()
    real_note, real_join = scanner._note_sideload, scanner._join_local

    def note(ctx, handler):
        real_note(ctx, handler)
        pe = ctx.pe
        if sideload.kind_of(sideload.leaf_of(ctx.relpath)) and pe is not None and pe.has_signature \
                and len(pe.data_dirs) > 4:
            at, size = pe.data_dirs[4]          # the certificate table: a file offset, not an address
            block = bytes(ctx.data[at:at + min(size, 1 << 20)])
            if any(word in block for word in _MICROSOFT):
                names_microsoft.add(ctx.relpath)

    def join(findings):
        pairs = sideload.pairs(scanner._side_programs, scanner._side_libraries)
        out["programs asking for such a library"] = len({program.file for _l, program, _h in pairs})
        for library, _program, how in pairs:
            out["libraries beside such a program"] += 1
            if library.proof.startswith("a file of an official release"):
                out["in an official table"] += 1
            elif library.proof:
                out["validly signed by Microsoft"] += 1
            elif library.file in names_microsoft and "cannot check" in library.why:
                out["a signature naming Microsoft, not checked (memory)"] += 1
            elif library.why.startswith("it is signed by"):
                out["signed by someone else"] += 1
            else:
                out["no signature, or not a valid one"] += 1
            if not library.proof:
                out["SIDELOAD-001 made"] += 1
                out["... of them: imported" if how == "imports it" else "... of them: loaded by name"] += 1
        return real_join(findings)

    scanner._note_sideload, scanner._join_local = note, join
    try:
        scan()
    finally:
        del scanner._note_sideload, scanner._join_local
    return out


def line(numbers: Dict[str, int]) -> str:
    return "; ".join("%s: %d" % (column, numbers[column]) for column in COLUMNS)


def main(argv: List[str]) -> int:
    from gamescan import neutral_scanner
    if not argv:
        print(__doc__)
        return 2
    for folder in argv:
        if not os.path.isdir(folder):
            print("not a folder: %s" % folder)
            return 2
        scanner = neutral_scanner()
        print("%s | %s" % (os.path.basename(os.path.normpath(folder)), line(count(scanner, lambda: scanner.scan(folder)))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
