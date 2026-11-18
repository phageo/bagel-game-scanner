"""C5 (phase C native group, pre-registered in ``roadmap-1.0.md``): decoded or decrypted data in compiled C#
followed into code - ``CHAIN-DECODE-RUN`` (HIGH, tier CHAIN, cause ``DECODE-AND-RUN``), the rule C3 gives
for JavaScript.

The reading is :mod:`gamescan.dataflow.remote_cs`'s, with other sources: the tracer, its limits (steps,
hand-overs between methods, marks per value) and its way of following a value - over the stack, local
variables, the fields of one class, into and out of the methods of one program, into delegates, through
buffers a stream is read into and files that are written - are the same. A chain is

    decoded  ->  Assembly.Load(byte[]) / AppDomain.Load(byte[]) / Assembly.LoadModule(.., byte[])
    decoded  ->  written to a file  ->  that file is started or loaded (Process.Start, Assembly.LoadFrom, ...)

where "decoded" is what these hand back:

* ``Convert.FromBase64String`` / ``FromBase64CharArray``;
* a decryptor of the symmetric ciphers (Rijndael / Aes / DES / TripleDES / RC2: ``CreateDecryptor``, so its
  ``TransformFinalBlock`` and a ``CryptoStream`` made with it carry the mark; ``DecryptCbc`` / ``Ecb`` / ``Cfb``);
* a ``GZipStream`` / ``DeflateStream`` - **except** over an embedded resource (``GetManifestResourceStream``,
  ``ResourceManager.GetObject`` / ``GetStream``) or over an argument of the method (what its callers hand in
  may be such a resource): a compressed embedded-assembly loader (Costura and its kind) stays out, as
  pre-registered. A resource that is *decrypted* or Base64-decoded is decoded data;
* an XOR loop over a ``byte[]``: an ``xor`` whose result is stored into a byte array element (``stelem.i1``,
  or ``stind.i1`` / ``stobj`` through its address, with at most a byte conversion between - ``stobj`` only
  after one) inside a loop (a branch back over it).

A file read by its path gives back the file, not the path: a decoded *name* of a file does not make the
file's content decoded (``File.ReadAllBytes`` / ``OpenRead`` / ``Open``, ``FileStream``, a reader given a path).

Not chains: decoded data given straight to ``Process.Start`` (a decoded address or command line is no code
the scanner sees; only the start of a *written* file counts), ``Assembly.Load`` of a decoded *name*, decoded
text shown or saved and never started. Where the download reading already reports a chain at that place the
handler does not add this one (``handlers/dotnet.py``).

The across-libraries join of the download reading is not done for decoded data (one program at a time).
"""
from __future__ import annotations

import re
from typing import FrozenSet, List, Set

from ..unpack import dotnet_il as il
from . import remote_cs as rc

ON = True                               # the C5 switch: off -> no decode reading, findings as before
RULE = "CHAIN-DECODE-RUN"
TITLE = "Decoded data run as code"      # (the title C3 gives the rule: dataflow/decoderun.py)
# the source a value carries when it came out of an embedded resource: written in lower case so that it
# sorts after every decoder (``Type::Method``) - where a value carries both, the decoder is what is named
RESOURCE = "resource"
XOR_LOOP = "XOR loop over byte[]"
BYTES = "(byte[])"                      # added to a load that takes the code as bytes

_DECODE = re.compile(r"^(?:System\.Convert::FromBase64(?:String|CharArray)"
                     r"|System\.Security\.Cryptography\.\w+::(?:CreateDecryptor|Decrypt(?:Cbc|Ecb|Cfb)))$")
_DECOMPRESS = re.compile(r"^System\.IO\.Compression\.(?:GZipStream|DeflateStream)::\.ctor$")
_RESOURCE = re.compile(r"^(?:System\.Reflection\.Assembly::GetManifestResourceStream"
                       r"|System\.Resources\.ResourceManager::Get(?:Object|Stream))$")
# reads of a file by its path: what they give back is the file, not the path - a decoded *name* of a file
# (a mod loader's decrypted configuration) does not make the file's content decoded
_FILE_READ = re.compile(r"^System\.IO\.(?:File::(?:ReadAll\w+|OpenRead|OpenText|Open)"
                        r"|(?:FileStream|FileInfo)::\.ctor)$")
_PATH_CTOR = re.compile(r"^System\.IO\.(?:StreamReader|BinaryReader)::\.ctor$")   # ... when given a path
# a decompression over data carrying one of these marks adds no mark of its own (a marked value, an argument)
_NOT_OVER = (rc.DL, rc.PARAM)
_STORE_BYTE = 0x9C                      # stelem.i1
_STORE_BYTE_AT = 0x52                   # stind.i1 - ``data[i] ^= k`` stores through the element's address
_STORE_OBJ = 0x81                       # stobj - what the .NET Framework compiler writes there (after conv.u1)
_XOR = 0x61
_TO_BYTE = frozenset({0x67, 0xD2, 0x82, 0x86, 0xB3, 0xB4})   # conv.i1 conv.u1 conv.ovf.i1(.un) conv.ovf.u1(.un)


def xor_points(code: List[il.Instruction]) -> FrozenSet[int]:
    """Offsets of the ``xor`` instructions of a method whose result is stored into a byte array element
    (``stelem.i1``, or ``stind.i1`` through the element's address), inside a loop. A loop is a branch back
    over it; a loop built with ``switch`` (flattened control flow) is not seen."""
    backs = [(target, ins.offset) for ins in code
             for target in (il.target(ins),) if target is not None and target <= ins.offset]
    if not backs:
        return frozenset()
    out = set()
    for k, ins in enumerate(code):
        if ins.code != _XOR or k + 1 >= len(code):
            continue
        after = code[k + 1].code
        stores = (_STORE_BYTE, _STORE_BYTE_AT)
        # (stobj names its type by a token that is not resolved here: only right after a byte conversion)
        stored = after in stores or (after in _TO_BYTE and k + 2 < len(code)
                                     and code[k + 2].code in stores + (_STORE_OBJ,))
        if stored and any(start <= ins.offset < end for start, end in backs):
            out.add(ins.offset)
    return frozenset(out)


class _DecodeTrace(rc._Trace):
    """One reading of one method, following decoded data instead of downloads."""

    splits_arguments = False            # (B3 is a reading fix of the download reading only)

    def __init__(self, state, method, code) -> None:
        super().__init__(state, method, code)
        self.xors = xor_points(code)

    def combine(self, ins: il.Instruction, operands: FrozenSet[tuple]) -> FrozenSet[tuple]:
        out = super().combine(ins, operands)
        if ins.offset in self.xors:
            out = out | {(rc.DL, XOR_LOOP, 0)}
        return out

    def other(self, ins: il.Instruction) -> bool:
        """``stind.i1`` / ``stobj``: a value stored through an element's address (``ldelema``) - the array
        takes the mark of what is stored, as with ``stelem``."""
        if ins.code not in (_STORE_BYTE_AT, _STORE_OBJ):
            return False
        value, address = self.full(self.pop()), self.pop()
        source = rc._has(value, rc.DL)
        if source:
            for tag in address:
                if tag[0] == rc.BOX:
                    self.boxes.setdefault(tag[1], set()).add((rc.DL, source, 0))
                elif tag[0] == rc.ORIGIN:
                    self.taint(frozenset({tag}), source)
        return True

    def finish(self, name: str, callee: il.Callee, result: Set[tuple]) -> Set[tuple]:
        if _FILE_READ.match(name) or (_PATH_CTOR.match(name) and callee.shape.startswith("(String")):
            return {t for t in result if t[0] != rc.DL}
        return result

    def sink_label(self, name: str, callee: il.Callee, native: str) -> str:
        label = super().sink_label(name, callee, native)
        if label and rc._LOAD.match(name) and "Byte[]" in callee.shape:
            label += BYTES
        return label

    def sources(self, name: str, args: List[FrozenSet[tuple]], full: List[FrozenSet[tuple]],
                result: Set[tuple]) -> bool:
        if _RESOURCE.match(name):
            result.add((rc.DL, RESOURCE, 0))
            return True
        if _DECOMPRESS.match(name):
            # over data that already carries a mark (a resource, a decoded value) it adds none: a
            # decompressed resource stays a resource. Nor over an argument of the method: what its callers
            # hand in may be a resource (Costura's helpers) - Base64 / decrypted data keep their own mark
            if not any(t[0] in _NOT_OVER for tags in full for t in tags):
                result.add((rc.DL, rc._short(name), 0))
            return True
        if _DECODE.match(name):
            result.add((rc.DL, rc._short(name), 0))
            return True
        return False

    def reaches(self, tags: FrozenSet[tuple], sink: str, depth: int) -> None:
        # a resource that was not decoded is no source (the loader of embedded assemblies); a start, or a load
        # that takes no bytes, is reached only by a written file - so for those the decoded value itself is
        # left out and a written file it carries is still seen
        takes_bytes = sink.split(" via ", 1)[0].endswith(BYTES)
        super().reaches(frozenset(t for t in tags if not (t[0] == rc.DL and (t[1] == RESOURCE or not takes_bytes))),
                        sink, depth)

    def hit(self, how: str, source: str, sink: str) -> None:
        if source == RESOURCE:
            return
        if how == "loader" and not sink.split(" via ", 1)[0].endswith(BYTES):
            return                      # decoded data handed straight to a start, or a decoded name loaded
        super().hit(how, source, sink)


def _sink(name: str) -> bool:
    return bool(rc._LOAD.match(name) or rc._START.match(name) or rc._START_NATIVE.match(name))


class _Decoded(rc.Reading):
    trace = _DecodeTrace

    def wanted(self, module: il.Module, official: bool) -> bool:
        """Only a program that can load or start code is read (its references - or, when it is not an
        official engine file, what it defines itself, as the download reading)."""
        if any(_sink(name) for name in module.references()):
            return True
        return not official and any(_sink(name) for name in module.defined(rc._NAMED_TYPES.match))

    def source(self, name: str) -> bool:
        # (a method that reads a resource is read too: what it gives back must carry the resource mark,
        # or a decompression in its caller would look like decoding of something else)
        return bool(_DECODE.match(name) or _DECOMPRESS.match(name) or _RESOURCE.match(name))

    def source_in(self, code: List[il.Instruction]) -> bool:
        return bool(xor_points(code))


DECODED = _Decoded()


def analyse(data: bytes, pe, official: bool = False) -> rc.Found:
    """The decode-and-run chains in the methods of one managed program (``remote_cs.Found``; its
    ``shares`` are not used)."""
    return rc.analyse(data, pe, official=official, kind=DECODED)
