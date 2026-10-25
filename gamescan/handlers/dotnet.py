"""Unity / .NET: C# source, managed assemblies, IL2CPP metadata and Unity asset files."""
from __future__ import annotations

import hashlib
import io
import re
from typing import Iterable, List

from ..models import Category, FileContext, Finding, Severity
from ..pe import extract_strings
from ..rules import RuleEngine
from .. import cache, engine_hashes
from ..dataflow import remote_cs
from ..unpack import dotnet_meta, il2cpp, media, unity
from .base import FLOW_CUT, FLOW_READ, REMOTE_CODE_REASON, BaseHandler

_ASSETS = frozenset({".assets", ".bundle", ".unity3d", ".assetbundle"})
_MAX_FINDINGS = 2000                  # distinct raw findings kept from one streamed file
_MAX_METADATA = 1 << 30               # global-metadata.dat that is read into memory
_FRAMEWORK = re.compile(              # assemblies that are the engine / .NET, not the game
    r"(?i)^(?:mscorlib|netstandard|system(?:\..*)?|mono\..*|unityengine(?:\..*)?|unity\..*"
    r"|unityeditor(?:\..*)?|microsoft\..*|newtonsoft\..*|nunit.*|i18n.*|accessibility"
    r"|boo\..*|unityscript.*|__generated)(?:\.dll)?$")
_COMPILED_CS = "  [compiled C#]"
_COMPILED_CS_REASON = (" Here it was read from the compiled C# code of this library: the method named "
                       "below hands what it downloaded to a call that loads it as code or starts it.")
_ACROSS_LIBRARIES = "  [across two libraries]"
_ACROSS_LIBRARIES_REASON = (" Here the two halves are in two libraries of the game: one downloads, the other "
                            "loads or starts what it is given; they were matched by the name of the method "
                            "one calls in the other.")
_IN_FRAMEWORK = (" The name is in the engine / .NET framework code that is compiled into this "
                 "IL2CPP build; that the game itself uses it is not shown.")


class DotNetHandler(BaseHandler):
    name = "dotnet"
    engine = "Unity / .NET"
    extensions = frozenset({".cs"}) | _ASSETS
    magics = (unity.MAGIC, il2cpp.MAGIC)
    markers = (r"(^|/)unityplayer\.dll$", r"_data/managed/", r"_data/globalgamemanagers$",
               r"(^|/)gameassembly\.dll$", r"il2cpp_data/")
    baseline = (
        (r"_data/managed/(?:unityengine|unity\.|mscorlib|system|mono\.|netstandard|newtonsoft"
         r"|microsoft\.|nunit|i18n|accessibility|boo\.|unityscript)[^/]*\.dll$",
         "Unity engine / .NET framework assembly"),
    )

    def can_handle(self, ctx: FileContext) -> bool:
        if ctx.pe is not None:
            return ctx.pe.is_dotnet
        return not ctx.is_pe and (ctx.ext in self.extensions
                                  or ctx.data.startswith((unity.MAGIC, il2cpp.MAGIC)))

    def engine_for(self, key: str) -> str:
        if not self.detects_engine(key):
            return ""
        return "Unity (IL2CPP)" if "gameassembly.dll" in key or "il2cpp_data/" in key else self.engine

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if ctx.pe is not None:
            return self._assembly(ctx, rules)
        if ctx.data.startswith(il2cpp.MAGIC):
            return self._il2cpp(ctx, rules)
        if ctx.ext == ".cs":
            text = ctx.text()
            return (rules.scan(text, "csharp", ctx, self.name, comment_style="c")
                    + self.entropy_literals(ctx, text, "csharp"))
        return self._assets(ctx, rules)

    def _assembly(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        """Decompile the metadata: what the assembly really references."""
        out = self.pe_entropy(ctx)
        # (kept by the file's SHA-256, like the reading of its methods below - gamescan/cache.py)
        listing = cache.kept("dotnet-listing", ctx.sha256, "gamescan.unpack.dotnet_meta",
                             lambda: dotnet_meta.decompile(ctx.data, ctx.pe), extra=str(len(ctx.data)))
        if listing is None:
            # obfuscators deliberately damage metadata; fall back to raw strings
            out.append(self.make(ctx, "DN-META-001", "Assembly metadata could not be read",
                                 Category.PACKING, Severity.LOW,
                                 "The assembly's reference tables are damaged or protected, "
                                 "so only its raw strings could be inspected.", ctx.name, 0.3))
            listing = "\n".join(extract_strings(ctx.data))
        else:
            out += self.antimalware(ctx, rules, listing, "strings recovered from .NET metadata")
            out += self.managed_code(ctx)
        return out + rules.scan(listing, "dotnet", ctx, self.name, numbered=False)

    def managed_code(self, ctx: FileContext) -> List[Finding]:
        """CHAIN-REMOTE-CODE in compiled C#: what a method downloads and then loads
        or starts (:mod:`gamescan.dataflow.remote_cs` - inside one method and through
        the fields of one class).

        Decided by phageo on 2026-10-11: CRITICAL in the game's own code and in every
        library that is not verified - also one named like the engine's (a name
        proves nothing; ``mscorlib`` or ``UnityEngine.UI`` cannot be verified by
        the table). Hidden only in a file that is, byte for byte, a file of an
        official engine package, like the chain in Ren'Py's own updater."""
        out: List[Finding] = []
        if ctx.truncated:
            found = remote_cs.Found([], remote_cs.UNREAD, "only the first %d MB of the file were read"
                                    % (len(ctx.data) >> 20))
        else:
            official = bool(engine_hashes.verified(ctx.sha256))
            found = cache.kept("dotnet-il", ctx.sha256, "gamescan.dataflow.remote_cs",
                               lambda: remote_cs.analyse(ctx.data, ctx.pe, official=official),
                               extra="%d|%d" % (len(ctx.data), official),
                               encode=remote_cs.as_plain, decode=remote_cs.from_plain)
        if found.shares or found.shares.assembly:
            # what this library gives to, and relies on in, the other libraries of the game
            # (joined after every file was scanned: Scanner._join_managed) - and the name it
            # gives itself, by which a call from another library is resolved
            ctx.cache["managed"] = found.shares
        # read to its end or not: a chain of nearness its reading disproves (chains.NO_FLOW;
        # phageo, 2026-10-17, fifty-ninth message - as the JavaScript reading)
        ctx.cache[FLOW_READ if found.state == remote_cs.READ else FLOW_CUT] = True
        official = engine_hashes.verified(ctx.sha256) if found.hits else None
        for hit in found.hits:
            flow = "%s -> %s in %s" % (hit.source, hit.sink, hit.where)
            if hit.how == "dropper":
                flow += "; written to a file that is then started or loaded"
            if hit.address:
                flow += "; address: " + hit.address
            flow += _COMPILED_CS
            f = self.make(ctx, "CHAIN-REMOTE-CODE", "Attack chain: Remote code execution", Category.CHAIN,
                          Severity.CRITICAL, REMOTE_CODE_REASON + _COMPILED_CS_REASON, flow, 0.8, snippet=flow)
            f.chainable = False
            if official:
                f.suppress("%s: %s" % (engine_hashes.VERIFIED, official))
            out.append(f)
        if found.state != remote_cs.READ and not ctx.cache.get("managed_note"):
            ctx.cache["managed_note"] = True
            note = self.make(
                ctx, "DN-IL-001", ".NET library's code could not be fully read", Category.EVASION, Severity.LOW,
                "The methods of a .NET library (game code written in C#) are read instruction by "
                "instruction to see whether the library downloads something and then loads or starts "
                "it. Here that reading did not get to the end, so a download-and-run inside the library "
                "could have been missed. Its names and texts were scanned as usual.",
                ".NET method bodies: %s" % found.problem[:200], 0.3)
            note.chainable = False
            out.append(note)
        return out

    def joined_managed(self, ctx: FileContext, link, other_file: str, officials) -> Finding:
        """CHAIN-REMOTE-CODE across two libraries of one game (``remote_cs.Link``; ``ctx``
        is the library that loads or starts). The same finding as inside one library,
        and judged the same way: hidden only when *both* libraries are, byte for
        byte, files of an official engine package (``officials``: what each one is,
        or None)."""
        if link.returned:
            flow = "%s [in %s] -> returned by %s -> %s in %s" % (
                link.source, other_file, link.through, link.sink, link.where)
        else:
            flow = "%s in %s [in %s] -> handed to %s -> %s" % (
                link.source, link.where, other_file, link.through, link.sink)
        flow += _ACROSS_LIBRARIES + _COMPILED_CS
        f = self.make(ctx, "CHAIN-REMOTE-CODE", "Attack chain: Remote code execution", Category.CHAIN,
                      Severity.CRITICAL, REMOTE_CODE_REASON + _COMPILED_CS_REASON + _ACROSS_LIBRARIES_REASON,
                      flow, 0.7, snippet=flow)
        f.chainable = False
        if all(officials):
            f.suppress("%s: %s" % (engine_hashes.VERIFIED, "; ".join(officials)))
        return f

    def _il2cpp(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        """IL2CPP metadata: the only place where an IL2CPP game's names and
        string literals can be read (its code is native).

        The listing has the shape the rules for managed assemblies expect.
        What the game's own assemblies define is judged at full weight, and
        so are the string literals. Names from the engine / framework
        assemblies only show what is *present* in the build - a weak signal,
        reported as such."""
        data = ctx.data
        if ctx.truncated and ctx.on_disk and ctx.size <= _MAX_METADATA:
            with open(ctx.path, "rb") as fh:
                data = fh.read()
            ctx.cache["streamed"] = True
        try:
            meta = il2cpp.parse(data)
        except il2cpp.Il2CppError as exc:
            # protected games encrypt or scramble this file; then only its raw text is left
            text = "\n".join(media.runs(data))
            return [self.make(ctx, "IL2CPP-META-001", "IL2CPP metadata could not be read",
                              Category.OBFUSCATION, Severity.LOW,
                              "The file that names an IL2CPP game's code and holds its string "
                              "literals is encrypted, scrambled or of an unknown layout, so "
                              "only its raw text could be inspected.", str(exc), 0.3)] \
                + rules.scan(text, "strings", ctx, self.name, numbered=False)
        game, framework = [], []
        for image in meta.images:
            lines = framework if _FRAMEWORK.match(image.name) else game
            lines += ["typeref " + name for name in image.types]
            lines += ["ref " + name for name in image.methods]
            lines += ["pinvoke %s!%s" % (image.name.lower() or "il2cpp", name.split("::")[-1])
                      for name in image.pinvoke]
        literals = ['string "%s"' % s.replace("\n", " ").replace("\r", " ")[:400]
                    for s in dict.fromkeys(meta.literals)]
        listing = "\n".join(dict.fromkeys(game + literals))
        out = rules.scan(listing, "dotnet", ctx, self.name, numbered=False)
        for f in rules.scan("\n".join(dict.fromkeys(framework)), "dotnet", ctx, self.name,
                            numbered=False):
            if f.severity > Severity.LOW:
                f.severity = Severity.LOW
            f.confidence = min(f.confidence, 0.3)
            f.chainable = False
            f.reason += _IN_FRAMEWORK
            out.append(f)
        out += self.antimalware(ctx, rules, listing, "names and strings from IL2CPP metadata")
        if meta.notes:
            out.append(self.make(ctx, "IL2CPP-META-001", "IL2CPP metadata could not be read",
                                 Category.OBFUSCATION, Severity.LOW,
                                 "Part of this IL2CPP metadata file has a layout that was not "
                                 "recognised, so some names could not be related to each other.",
                                 "; ".join(meta.notes), 0.3))
        # the same text as a member, so that YARA rules and the blocklist see what was extracted
        ctx.cache["il2cpp_listing"] = (listing + "\n" + "\n".join(framework)).encode(
            "utf-8", "replace")[:64 * 1024 * 1024]
        return out

    def _assets(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        """Unpack the asset file / bundle piece by piece and scan what is inside.

        The file is never held in memory as a whole: blocks are decoded one
        at a time and looked at through a sliding window, so a bundle of
        several gigabytes is inspected to its end."""
        from_disk = ctx.truncated and ctx.on_disk
        out: List[Finding] = []
        seen = set()
        with (open(ctx.path, "rb") if from_disk else io.BytesIO(ctx.data)) as fh:
            stream = unity.Stream(fh, ctx.size if from_disk else len(ctx.data), ctx.cancel)
            carver = unity.Carver()
            for offset, window in carver.windows(stream):
                ctx.tick(stream.consumed / max(stream.size, 1))
                assets, streams = stream.split(offset, window)
                # asset data is read like any asset file; media streams through the
                # sliding window that returns every printable run; PNG files stored
                # in the content also give up their (compressed) text chunks
                found = extract_strings(assets) if assets else []
                found += media.runs(streams) if streams else []
                for content in media.embedded_png_texts(window):
                    found += media.runs(content)
                if not found:
                    continue
                text = "\n".join(found)
                for f in rules.scan(text, "strings", ctx, self.name, numbered=False):
                    key = (f.rule_id, f.context.get("match") or f.evidence)
                    if key not in seen and len(out) < _MAX_FINDINGS:
                        seen.add(key)
                        out.append(f)
        ctx.cache["streamed"] = from_disk
        carved = ctx.cache["carved"] = carver.images
        if stream.bundle and stream.problem:
            out.append(self.make(ctx, "UNITY-FMT-001", "Unity bundle could not be fully unpacked",
                                 Category.OBFUSCATION, Severity.LOW,
                                 "Part of this asset bundle could not be decompressed, so what "
                                 "is stored in that part was not inspected.", stream.problem, 0.3))
        return out + [self.make(ctx, "UNITY-PE-001", "Executable embedded in Unity asset",
                                Category.EVASION, Severity.MEDIUM,
                                "A Windows program is stored inside an asset file, where it is "
                                "invisible in the game folder. Used by mod loaders and by "
                                "droppers.",
                                "%s image at offset 0x%x, %d KB" % ("DLL" if is_dll else "EXE", off,
                                                                     len(image) // 1024), 0.5)
                      for off, image, is_dll in carved]

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        listing = ctx.cache.pop("il2cpp_listing", None)
        if listing:
            yield FileContext(path=ctx.path, relpath=ctx.relpath + "!names-and-strings.txt",
                              data=listing, size=len(listing),
                              sha256=hashlib.sha256(listing).hexdigest())
        for off, image, is_dll in ctx.cache.get("carved", ()):
            yield FileContext(path=ctx.path,
                              relpath="%s!embedded_0x%x.%s" % (ctx.relpath, off,
                                                                "dll" if is_dll else "exe"),
                              data=image, size=len(image),
                              sha256=hashlib.sha256(image).hexdigest())
