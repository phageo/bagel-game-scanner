""".NET assembly metadata decompiler (ECMA-335 ``#~`` tables).

Instead of guessing from loose strings, this reads what an assembly actually
references: every external type, every member it calls
(``System.Net.WebClient::DownloadFile``), every native function it imports
through P/Invoke (``kernel32.dll!VirtualAllocEx``) and every string literal
in its code. Method bodies (IL) are not disassembled.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional

from . import limits

_CODED = {
    "TypeDefOrRef": (2, [2, 1, 27]),
    "HasConstant": (2, [4, 8, 23]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35,
                               38, 39, 40, 42, 44, 43]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 32]),
    "MemberRefParent": (3, [2, 1, 26, 6, 27]),
    "HasSemantics": (1, [20, 23]),
    "MethodDefOrRef": (1, [6, 10]),
    "MemberForwarded": (1, [4, 6]),
    "CustomAttributeType": (3, [None, None, 6, 10, None]),
    "ResolutionScope": (2, [0, 26, 35, 1]),
    "Implementation": (2, [38, 35, 39]),
    "TypeOrMethodDef": (1, [2, 6]),
}
# column kinds: "2"/"4" fixed, S/G/B heap index, iN index into table N, cName coded
_TABLES = {
    0: ["2", "S", "G", "G", "G"], 1: ["cResolutionScope", "S", "S"],
    2: ["4", "S", "S", "cTypeDefOrRef", "i4", "i6"], 3: ["i4"], 4: ["2", "S", "B"],
    5: ["i6"], 6: ["4", "2", "2", "S", "B", "i8"], 7: ["i8"], 8: ["2", "2", "S"],
    9: ["i2", "cTypeDefOrRef"], 10: ["cMemberRefParent", "S", "B"],
    11: ["2", "cHasConstant", "B"], 12: ["cHasCustomAttribute", "cCustomAttributeType", "B"],
    13: ["cHasFieldMarshal", "B"], 14: ["2", "cHasDeclSecurity", "B"], 15: ["2", "4", "i2"],
    16: ["4", "i4"], 17: ["B"], 18: ["i2", "i20"], 19: ["i20"], 20: ["2", "S", "cTypeDefOrRef"],
    21: ["i2", "i23"], 22: ["i23"], 23: ["2", "S", "B"], 24: ["2", "i6", "cHasSemantics"],
    25: ["i2", "cMethodDefOrRef", "cMethodDefOrRef"], 26: ["S"], 27: ["B"],
    28: ["2", "cMemberForwarded", "S", "i26"],
    # the tables behind ImplMap: needed to reach NestedClass (41) and MethodSpec (43),
    # which the reader of method bodies asks for (:mod:`gamescan.unpack.dotnet_il`)
    29: ["4", "i4"], 30: ["4", "4"], 31: ["4"], 32: ["4", "2", "2", "2", "2", "4", "B", "S", "S"],
    33: ["4"], 34: ["4", "4", "4"], 35: ["2", "2", "2", "2", "4", "B", "S", "S", "B"],
    36: ["4", "i35"], 37: ["4", "4", "4", "i35"], 38: ["4", "S", "B"],
    39: ["4", "4", "S", "S", "cImplementation"], 40: ["4", "4", "S", "cImplementation"],
    41: ["i2", "i2"], 42: ["2", "2", "cTypeOrMethodDef", "S"], 43: ["cMethodDefOrRef", "B"],
    44: ["i42", "cTypeDefOrRef"],
}
_MAX_ROWS = 400_000
_MAX_STRINGS = 20_000


class _Metadata:
    def __init__(self, data: bytes, pe) -> None:
        clr = pe.offset(pe.data_dirs[14][0])
        md_rva = struct.unpack_from("<I", data, clr + 8)[0]
        root = pe.offset(md_rva)
        if data[root:root + 4] != b"BSJB":
            raise ValueError("no metadata root")
        vlen = struct.unpack_from("<I", data, root + 12)[0]
        pos = root + 16 + vlen
        nstreams = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        self.streams: Dict[str, bytes] = {}
        for _ in range(min(nstreams, 16)):
            off, size = struct.unpack_from("<II", data, pos)
            end = data.index(b"\0", pos + 8)
            name = data[pos + 8:end].decode("ascii", "replace")
            pos = (end + 4) & ~3
            self.streams[name] = data[root + off:root + off + size]
        tables = self.streams.get("#~") or self.streams.get("#-")
        if not tables:
            raise ValueError("no table stream")
        self.strings = self.streams.get("#Strings", b"")
        heap = tables[6]
        valid = struct.unpack_from("<Q", tables, 8)[0]
        self.rows: Dict[int, int] = {}
        pos = 24
        for t in range(64):
            if valid >> t & 1:
                self.rows[t] = struct.unpack_from("<I", tables, pos)[0]
                pos += 4
        wide = {"S": heap & 1, "G": heap & 2, "B": heap & 4}
        self.fmt: Dict[int, str] = {}
        self.base: Dict[int, int] = {}
        self.size: Dict[int, int] = {}
        for t in sorted(self.rows):
            if t not in _TABLES:
                break                         # later tables are never needed
            fmt = "<"
            for col in _TABLES[t]:
                if col in ("2", "4"):
                    fmt += "H" if col == "2" else "I"
                elif col in wide:
                    fmt += "I" if wide[col] else "H"
                elif col[0] == "i":
                    fmt += "I" if self.rows.get(int(col[1:]), 0) >= 1 << 16 else "H"
                else:
                    bits, targets = _CODED[col[1:]]
                    most = max(self.rows.get(x, 0) for x in targets if x is not None)
                    fmt += "I" if most >= 1 << (16 - bits) else "H"
            self.fmt[t], self.base[t], self.size[t] = fmt, pos, struct.calcsize(fmt)
            pos += self.size[t] * self.rows[t]
        self.tables = tables

    def row(self, table: int, index: int):
        """1-based row of ``table`` as a tuple of ints, or None."""
        if table not in self.fmt or not 1 <= index <= self.rows[table]:
            return None
        return struct.unpack_from(self.fmt[table], self.tables,
                                  self.base[table] + (index - 1) * self.size[table])

    def string(self, offset: int) -> str:
        end = self.strings.find(b"\0", offset)
        return self.strings[offset:end if end != -1 else offset].decode("utf-8", "replace")

    def type_name(self, table: int, index: int) -> str:
        row = self.row(table, index)
        if row is None:
            return "?"
        if table == 1:
            ns, name = self.string(row[2]), self.string(row[1])
        elif table == 2:
            ns, name = self.string(row[2]), self.string(row[1])
        elif table == 26:
            return self.string(row[0])
        else:
            return "?"
        return ns + "." + name if ns else name

    def user_strings(self) -> List[str]:
        heap, out, pos = self.streams.get("#US", b""), [], 1
        while pos < len(heap) and len(out) < _MAX_STRINGS:
            b = heap[pos]
            if b & 0x80 == 0:
                n, pos = b, pos + 1
            elif b & 0xC0 == 0x80:
                n, pos = (b & 0x3F) << 8 | heap[pos + 1], pos + 2
            else:
                n = (b & 0x1F) << 24 | heap[pos + 1] << 16 | heap[pos + 2] << 8 | heap[pos + 3]
                pos += 4
            if n > 1:
                text = heap[pos:pos + n - 1].decode("utf-16-le", "replace")
                if len(text) >= 4:
                    out.append(text[:400].replace("\n", " ").replace("\r", " "))
            pos += n
        if pos < len(heap) and len(out) >= _MAX_STRINGS:
            limits.hit("dotnet", "more than %d texts: the rest was not read" % _MAX_STRINGS)
        return out


def module_name(data: bytes, pe) -> Optional[str]:
    """The name the assembly's module carries ("UnityEngine.CoreModule.dll"),
    or None if the metadata cannot be read."""
    try:
        md = _Metadata(data, pe)
        if md.rows.get(0, 0) < 1:
            return None
        return md.string(md.row(0, 1)[1])
    except (struct.error, IndexError, ValueError, TypeError, KeyError):
        return None


def decompile(data: bytes, pe) -> Optional[str]:
    """Pseudo-source listing of a managed assembly, or None if unreadable."""
    try:
        md = _Metadata(data, pe)
        lines: List[str] = []
        for table in (1, 10, 28):
            if md.rows.get(table, 0) > _MAX_ROWS:
                limits.hit("dotnet", "a reference table of more than %d rows: the rest was not read" % _MAX_ROWS)
        for i in range(1, min(md.rows.get(1, 0), _MAX_ROWS) + 1):
            lines.append("typeref " + md.type_name(1, i))
        bits, targets = _CODED["MemberRefParent"]
        for i in range(1, min(md.rows.get(10, 0), _MAX_ROWS) + 1):
            parent, name, _sig = md.row(10, i)
            tag = parent & ((1 << bits) - 1)
            owner = md.type_name(targets[tag], parent >> bits) if tag < len(targets) else "?"
            lines.append("ref %s::%s" % (owner, md.string(name)))
        for i in range(1, min(md.rows.get(28, 0), _MAX_ROWS) + 1):
            _flags, _member, name, scope = md.row(28, i)
            lines.append("pinvoke %s!%s" % (md.type_name(26, scope).lower(), md.string(name)))
        lines.extend('string "%s"' % s for s in dict.fromkeys(md.user_strings()))
        return "\n".join(dict.fromkeys(lines))
    except (struct.error, IndexError, ValueError, TypeError, KeyError):
        return None                           # obfuscated or damaged metadata
