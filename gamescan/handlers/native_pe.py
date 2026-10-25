"""Native Windows executables: structure, packing, verified API usage."""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/handlers/native_pe.py")

import mmap
import os
import re
from typing import Iterable, List

from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..entropy import shannon
from ..pe import (extract_strings, profile_il2cpp_imports, program_inside, resource_frame_key,
                  only_asar_integrity, resource_kinds, resources_of, signature_is_all_appended)
from ..unpack import media
from ..rules import RuleEngine
from .. import cache, directx_official, electron_official, engine_hashes, inno_official, nsis_official, runtimes
from . import containers, engine_files
from .base import BaseHandler


_WINDOWS_DIRS = frozenset(os.path.normcase(d) for d in (
    "System32", "SysWOW64", "WinSxS", "SystemApps", "Microsoft.NET", "servicing",
    "ImmersiveControlPanel", "explorer.exe"))


_WINDOW, _SEAM = 8 * 1024 * 1024, 16 * 1024
_MAX_STRINGS = 2_000_000
_BLOCK, _MIN_ENCRYPTED = 16 * 1024, 256 * 1024       # entropy is measured per 16 KB block
_IMPORT_RULES = {      # category: rule, title, finding category, severity, confidence, reason
    "tamper": ("IAT-001", "IL2CPP program imports process-tampering functions", Category.EXECUTION,
               Severity.CRITICAL, 0.85,
               "The game's native code imports functions whose purpose is to write into other "
               "processes, start threads in them, hook the keyboard system-wide or dump their "
               "memory."),
    "native": ("IAT-002", "IL2CPP program imports the undocumented native API", Category.EVASION,
               Severity.HIGH, 0.75,
               "The game's native code calls ntdll.dll directly - the layer below the documented "
               "Windows API, used to avoid being observed."),
    "network": ("IAT-003", "IL2CPP program imports networking functions", Category.NETWORK,
                Severity.HIGH, 0.7,
                "The game's native code imports a networking library, or socket functions "
                "beyond the four that Unity's own runtime uses."),
    "crypto": ("IAT-004", "IL2CPP program imports cryptography functions", Category.OBFUSCATION,
               Severity.HIGH, 0.65,
               "The game's native code imports encryption functions beyond the random-number "
               "calls of Unity's runtime: what a program needs to unpack a hidden payload or to "
               "encrypt files."),
    "system": ("IAT-005", "IL2CPP program imports system-control functions", Category.PROCESS,
               Severity.HIGH, 0.7,
               "The game's native code imports functions that start programs, change services, "
               "the registry or access tokens, or read the keyboard and clipboard."),
    "other": ("IAT-006", "IL2CPP program imports functions outside the Unity baseline",
              Category.EVASION, Severity.LOW, 0.3,
              "The game's native code imports Windows functions that the surveyed standard "
              "builds do not. Often just another Unity version; worth a look next to other "
              "findings."),
}
RGSS_VERIFIED = "RPG Maker RGSS runtime (official build, verified by SHA-256)"


# INPUT-003 (see NativePEHandler._key_names)
# ADDON-DECRYPT-001: the functions that decrypt what Windows keeps for the signed-in user,
# and the baselines that are proof of where a file comes from
_DECRYPT_FUNCTIONS = frozenset({_IND[0]})
_KEY_NAME = re.compile(r"\[(ENTER|RETURN|BACKSPACE|BKSP|BACK|TAB|ESC|ESCAPE|CAPS ?LOCK|L?SHIFT|R?SHIFT|L?CTRL"
                       r"|R?CTRL|ALT|DEL|DELETE|SPACE|UP|DOWN|LEFT|RIGHT|HOME|END|INS|INSERT|WIN|PRTSC"
                       r"|F\d{1,2})\]", re.I)
_TYPING_KEYS = frozenset({"BACKSPACE", "BKSP", "CAPSLOCK", "DEL", "DELETE"})

class NativePEHandler(BaseHandler):
    name = "native-pe"
    engine = "Native PE"
    baseline = (
        (r"(^|[/!])(?:unityplayer\.dll|unitycrashhandler(?:32|64)\.exe)$", "Unity player runtime"),
        (r"(^|[/!])monobleedingedge/", "Unity Mono runtime"),
        (r"(^|[/!])(?:nw|node|ffmpeg|libegl|libglesv2|nw_elf|chrome_elf|vk_swiftshader|vulkan-1"
         r"|d3dcompiler_\d+|notification_helper)\.(?:dll|exe)$", "NW.js / Chromium runtime"),
        (r"(^|[/!])lib/(?:py\d?-|windows-|python)[^/]*/[^!]*$", "Ren'Py bundled Python runtime"),
        (r"(^|[/!])(?:python\d*|pythonw|libpython[\d.]+|vcruntime\d+(?:_\d)?|msvc[pr]\d+|ucrtbase"
         r"|api-ms-win-[\w-]+|concrt\d+)\.(?:dll|exe)$", "Python / MSVC runtime"),
        (_IND[1],
         "common game middleware library"),
    )

    def baseline_reason(self, ctx: FileContext) -> str:
        # Windows' own files are recognised by where they REALLY are on disk
        # (writing there needs administrator rights) - never by a relative
        # path, or a game could ship a folder named "Windows\System32".
        # CRITICAL findings and blocklist hits still apply; strict mode
        # ignores this entirely.
        # RPG Maker's runtime ships packed and unsigned. Its name proves
        # nothing, so it is recognised by its exact content only.
        if runtimes.named_like_rgss(ctx.key) and runtimes.verified_rgss(ctx.sha256):
            return RGSS_VERIFIED
        # NW.js and the Python runtime Ren'Py bundles are signed by nobody. A
        # file that is, byte for byte, a file of an official release is
        # recognised by its hash - whatever it is called (RPG Maker renames
        # nw.exe to Game.exe); the right name with any other content is not.
        if ctx.is_pe:
            # (the same for the programs every Inno Setup installer is built from - the
            # setup engine and its loaders: gamescan/inno_official.py - and for the programs
            # of the NSIS distribution - its compiler, the installer stubs, the plug-in
            # libraries an NSIS installer unpacks: gamescan/nsis_official.py)
            # (and for the files of the official Electron releases: gamescan/electron_official.py)
            # (and the libraries of Microsoft's DirectX June 2010 package - gamescan/directx_official.py,
            # each checked once to carry Microsoft's signature: recognised also inside an archive read
            # in memory, where a signature cannot be checked; phageo, 2026-10-17)
            official = (engine_hashes.verified(ctx.sha256) or inno_official.verified(ctx.sha256)
                        or nsis_official.verified(ctx.sha256) or electron_official.verified(ctx.sha256)
                        or directx_official.verified(ctx.sha256))
            if official:
                return "%s: %s" % (engine_hashes.VERIFIED, official)
            launcher = self._launcher(ctx)
            if launcher:
                return launcher
        windir = os.environ.get("WINDIR")
        if windir and "!" not in ctx.relpath:
            real = os.path.normcase(os.path.abspath(ctx.path))
            root = os.path.normcase(os.path.abspath(windir)) + os.sep
            if real.startswith(root) and real[len(root):].split(os.sep)[0] in _WINDOWS_DIRS:
                return "Windows system file"
        # RPG Maker MV/MZ ships NW.js's nw.exe renamed to Game.exe. It is not
        # signed, so it is recognised by what surrounds it: it sits next to
        # nw.dll and carries NW.js's own strings. (Imitable like every baseline,
        # which is why CRITICAL findings still show.)
        if (ctx.ext == ".exe" and "/" not in ctx.key and "!" not in ctx.key
                and b"nw_elf" in ctx.data
                and os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(ctx.path)), "nw.dll"))):
            if not engine_files.REQUIRE_VENDOR_SIGNATURE:
                return "NW.js launcher"
            # NW.js is not distributed signed: under the vendor-signature rule the
            # launcher is not exempted either (a valid signature of the game's own
            # publisher still counts, as for any program)
            ctx.cache["engine_unsigned"] = (
                "NW.js launcher", "this component is not distributed with a vendor signature, "
                "so that it is genuine cannot be verified")
            return ""
        return super().baseline_reason(ctx)

    @staticmethod
    def _launcher(ctx: FileContext) -> str:
        """The official NW.js launcher this program is apart from its resource
        section ("" = it is not one). RPG Maker MV / MZ put the game's icon into
        ``nw.exe``, so the file matches no official SHA-256 - but everything
        except the resources still can: headers, code, data, import table, byte
        for byte (:func:`gamescan.pe.resource_frame_key`). The resources and
        anything appended to the file are exactly what is *not* verified: a
        program in the resources refuses the match, and both are scanned again
        on their own, outside the trust the match gives (``scan``).

        The same for the program of an Electron game (``_electron``)."""
        if "launcher_frame" not in ctx.cache:
            pe, official = ctx.pe, None
            if (pe is not None and not ctx.truncated and not pe.is_dotnet and not pe.has_signature
                    and pe.entry_point in engine_hashes.LAUNCHER_ENTRY_POINTS):
                official = engine_hashes.verified_launcher(resource_frame_key(ctx.data, pe))
                if official and program_inside(resources_of(ctx.data, pe)):
                    official = None
            if official:
                official = "%s: %s" % (engine_hashes.LAUNCHER_VERIFIED, official)
            elif pe is not None and not pe.is_dotnet and pe.entry_point in electron_official.ENTRY_POINTS:
                official = NativePEHandler._electron(ctx)
            ctx.cache["launcher_frame"] = official or ""
        return ctx.cache["launcher_frame"]

    @staticmethod
    def _whole(ctx: FileContext):
        """``(content, close)``: all of the file - what is loaded, or, for a file larger than
        that, a read-only view of it on disk. ``(None, ...)``: it is not at hand."""
        if not ctx.truncated:
            return ctx.data, lambda: None
        if ctx.on_disk:
            try:
                fh = open(ctx.path, "rb")
                try:
                    view = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                except (OSError, ValueError):
                    fh.close()
                    raise
                return view, lambda: (view.close(), fh.close())
            except (OSError, ValueError):
                pass
        return None, lambda: None

    @staticmethod
    def _electron(ctx: FileContext) -> str:
        """The official Electron program this one is apart from what a game's maker puts
        into it ("" = it is not one; phageo, 2026-10-13). An Electron game's program is
        ``electron.exe`` under the game's name, with the game's icon, version text and
        manifest. Accepted when everything else is the official file, byte for byte:
        headers, code, data, import table (:func:`gamescan.pe.resource_frame_key` - the
        resource section, the checksum field and the place of a signature are left out).

        Not accepted - the program is then judged like any unknown one: another or an
        extra section, a changed byte anywhere else, data appended that is not the
        signature the headers name, a resource of a kind that neither the official
        program nor branding has (icon, icon group, version, manifest - and, since
        2026-10-13, Electron's integrity record of the app archive, exactly in its own
        form: ``pe.only_asar_integrity``), a program inside the resources. The resources are scanned again outside the acceptance, and what
        stands in the signature's area is judged by ``sigblock`` as for any program."""
        pe = ctx.pe
        data, close = NativePEHandler._whole(ctx)
        if data is None:
            return ""
        try:
            if not signature_is_all_appended(data, pe):
                return ""
            official = electron_official.verified_program(resource_frame_key(data, pe, signature=True))
            if official is None:
                return ""
            name, allowed = official
            kinds = resource_kinds(data, pe)
            if kinds is None or program_inside(resources_of(data, pe)):
                return ""
            # a kind with a name of its own is refused - except Electron's own integrity record
            # of the app archive, exactly as the packaging tool writes it (pe.only_asar_integrity)
            if -1 in kinds and only_asar_integrity(data, pe):
                kinds = [kind for kind in kinds if kind != -1]
            if not set(kinds) <= allowed:
                return ""
            return "%s: %s" % (electron_official.PROGRAM_VERIFIED, name)
        finally:
            close()

    def _unverified_parts(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        """The resources of a launcher that was accepted for everything else,
        and what is appended to it, scanned on their own: these findings are
        not covered by the acceptance (``context._baseline``)."""
        pe = ctx.pe
        data, close = self._whole(ctx)
        if data is None:
            return []
        try:
            parts = [("the resources", resources_of(data, pe))]
            if pe.overlay_size:
                parts.append(("the appended data", bytes(data[pe.overlay_offset:pe.overlay_offset + pe.overlay_size])))
        finally:
            close()
        out: List[Finding] = []
        for what, blob in parts:
            for f in rules.scan("\n".join(extract_strings(blob)), "strings", ctx, self.name, numbered=False):
                f.context["unverified_part"] = True
                f.evidence += "  [in %s, which the comparison with the official launcher does not cover]" % what
                out.append(f)
        return out

    def can_handle(self, ctx: FileContext) -> bool:
        return ctx.is_pe and not (ctx.pe is not None and ctx.pe.is_dotnet)

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        out: List[Finding] = []
        pe = ctx.pe
        if pe is None:
            out.append(self.make(ctx, "PE-FMT-001", "Malformed executable header",
                                 Category.EVASION, Severity.LOW,
                                 "The file starts like a Windows program but its headers "
                                 "cannot be parsed.", "MZ without valid PE header", 0.3))
        else:
            out += self._structure(ctx)
        if runtimes.named_like_rgss(ctx.key) and not runtimes.verified_rgss(ctx.sha256):
            out.append(self.make(
                ctx, "RGSS-RT-001", "Unrecognised RPG Maker runtime", Category.EVASION,
                Severity.LOW, "The file is named like RPG Maker's runtime library, but its "
                "content is not one of the official builds the scanner knows. It may be a "
                "version that is not on the list yet - or a different program using the name. "
                "It is therefore judged like any unknown program.",
                "%s, SHA-256 %s" % (ctx.name, ctx.sha256), 0.4))
        if containers.covers_overlay(ctx):
            # the appended data is an archive / installer payload that is opened
            # and looked into (anything that cannot be is reported separately),
            # so it is no longer "something hidden behind the program"
            out = [f for f in out if f.rule_id != "PE-ENT-001"]
        out += containers.scan_inno(self, ctx, rules)
        il2cpp = "il2cpp_init" in pe.exports if pe is not None else False
        if il2cpp:
            ctx.cache["resolves_by_name"] = True
            out += self._import_profile(ctx)
        # (kept by the file's SHA-256: the same bytes hold the same texts - gamescan/cache.py)
        strings = cache.kept("pe-strings", ctx.sha256, "gamescan.pe", lambda: extract_strings(ctx.data),
                             extra=str(len(ctx.data)))
        if ctx.truncated and ctx.on_disk:
            # a program larger than what is loaded: its strings are carved from disk,
            # to the end, and its sections are measured there too
            strings, extra = self._from_disk(ctx, strings, encrypted_blocks=il2cpp)
            out += extra
        elif il2cpp and pe is not None:
            out += self._encrypted_blocks(ctx, ctx.data)
        found = rules.scan("\n".join(strings), "strings", ctx, self.name, numbered=False)
        if pe is not None and ctx.cache.get("launcher_frame"):
            for f in out:
                if f.rule_id == "PE-ENT-001":           # appended data: not part of what was compared
                    f.context["unverified_part"] = True
            found += self._unverified_parts(ctx, rules)
        out += self._key_names(ctx, strings)
        out += self._addon_decrypt(ctx)
        if il2cpp:
            # the IL2CPP runtime itself queues APCs to interrupt its own threads; alone,
            # without a function that writes into another process, that is not injection
            inject = [f for f in found if f.rule_id == "INJ-001"]
            if inject and all(f.context.get("match") == "QueueUserAPC" for f in inject):
                for f in inject:
                    f.suppress("IL2CPP runtime: thread signalling (no other injection function "
                               "is imported)")
        return out + found

    def _addon_decrypt(self, ctx: FileContext) -> List[Finding]:
        """ADDON-DECRYPT-001 (HIGH; phageo, 2026-10-14): a native add-on of an app (``.node``)
        whose import table names the Windows function that decrypts what browsers and chat
        programs store for the user - and that is not a verified file (a published package's
        own, by SHA-256; a trusted signature). Counted first: such an add-on was in five of
        eight real Electron samples and in none of four clean ones. No chain is made of it
        yet; the scanner adds how many scripts of the same package have a network call."""
        if ctx.ext != ".node" or ctx.pe is None or ctx.baseline.startswith(engine_hashes.VERIFIED):
            return []
        names = sorted(name for imported in ctx.pe.imports.values() for name in imported
                       if name.lower() in _DECRYPT_FUNCTIONS)
        if not names:
            return []
        f = self.make(
            ctx, "ADDON-DECRYPT-001", "Native add-on that can decrypt stored secrets", Category.CREDENTIALS,
            Severity.HIGH,
            _IND[2],
            "%s imports %s%s" % (ctx.name, ", ".join(names),
                                 "; a file of %s" % ctx.baseline.split(": ", 1)[1] if ": npm package " in ctx.baseline else ""),
            0.6)
        f.chainable = False
        return [f]

    def _key_names(self, ctx: FileContext, strings: List[str]) -> List[Finding]:
        """INPUT-003: a table of key names in brackets, the way key loggers write down what
        was typed. Games show hints like "[ENTER] Confirm [ESC] Menu", so a few names are
        not a table: it takes six different ones, one of them a key that hints do not
        mention but a log of typed text needs."""
        names = {name.upper().replace(" ", "") for text in strings for name in _KEY_NAME.findall(text)}
        if len(names) < 6 or not names & _TYPING_KEYS:
            return []
        f = self.make(
            ctx, "INPUT-003", "Key-logging dictionary", Category.INPUT_CAPTURE, Severity.LOW,
            "The program contains a table of key names in brackets ([ENTER], [BACKSPACE] ...), "
            "which is how key loggers write down what was typed. By itself it proves nothing - "
            "help texts use the same notation - but together with an input hook or a known "
            "exfiltration address it is what separates a key logger from an ordinary program.",
            "%d different key names, e.g. %s" % (len(names), ", ".join("[%s]" % n for n in sorted(names)[:6])),
            0.4)
        f.context = {"match": "key names", "language": "strings"}
        return [f]

    def _import_profile(self, ctx: FileContext) -> List[Finding]:
        """What an IL2CPP ``GameAssembly.dll`` imports beyond what a standard
        Unity build imports. Its import table is written by Unity's runtime,
        not by the game's C# code, so anything extra was put there on purpose
        - by a native library linked into the program, or by tampering."""
        groups: dict = {}
        for note in profile_il2cpp_imports(ctx.pe):
            groups.setdefault(note.category, []).append("%s!%s" % (note.dll, note.name))
        out: List[Finding] = []
        for category, names in groups.items():
            rule, title, kind, severity, confidence, reason = _IMPORT_RULES[category]
            f = self.make(ctx, rule, title, kind, severity,
                          reason + " A standard Unity IL2CPP build does not import this.",
                          "%d import(s) outside the Unity IL2CPP baseline: %s%s" % (
                              len(names), ", ".join(names[:12]),
                              ", ..." if len(names) > 12 else ""), confidence)
            if category == "other":
                f.chainable = False
            out.append(f)
        return out

    def _from_disk(self, ctx: FileContext, strings: List[str], encrypted_blocks: bool):
        out: List[Finding] = []
        seen = dict.fromkeys(strings)
        with open(ctx.path, "rb") as fh:
            fh.seek(max(len(ctx.data) - _SEAM, 0))
            done = len(ctx.data)
            while not ctx.cancelled and len(seen) < _MAX_STRINGS:
                block = fh.read(_WINDOW)
                if len(block) <= _SEAM:
                    break
                seen.update(dict.fromkeys(media.runs(block)))
                done += len(block) - _SEAM
                ctx.tick(done / max(ctx.size, 1))
                fh.seek(-_SEAM, 1)
            if len(seen) >= _MAX_STRINGS and done < ctx.size:
                # the search for texts stopped before the end of the program: said (silent
                # until 2026-10-12)
                note = self.make(ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION,
                                 Severity.LOW, NOT_INSPECTED,
                                 "more than %d texts in this program: its last %d MB were not searched"
                                 % (_MAX_STRINGS, (ctx.size - done) >> 20), 0.3)
                note.chainable = False
                out.append(note)
            if encrypted_blocks:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                    out += self._encrypted_blocks(ctx, view)
        ctx.cache["streamed"] = True
        return list(seen), out

    def _encrypted_blocks(self, ctx: FileContext, data) -> List[Finding]:
        """Runs of statistically random data inside the data sections. Compiled
        C# has none; an embedded, encrypted payload is exactly that."""
        out: List[Finding] = []
        for s in ctx.pe.sections:
            if s.executable or s.name.lower() in (".rsrc", ".reloc", ".pdata") or s.raw_size < _BLOCK:
                continue
            start = run = 0
            end = min(s.raw_ptr + s.raw_size, len(data))
            for at in range(s.raw_ptr, end + _BLOCK, _BLOCK):
                block = data[at:min(at + _BLOCK, end)] if at < end else b""
                random = len(block) == _BLOCK and shannon(block) >= 7.9
                if random:
                    start, run = (start if run else at), run + 1
                    continue
                if run * _BLOCK >= _MIN_ENCRYPTED and len(out) < 4:
                    out.append(self.make(
                        ctx, "PE-ENT-003", "Encrypted block inside a data section",
                        Category.PACKING, Severity.MEDIUM, "A stretch of the program's data is "
                        "statistically random while the data around it is not: what an "
                        "embedded payload that is decrypted at run time looks like.",
                        "%s: %d KB at offset 0x%x" % (s.name or "(unnamed)", run * _BLOCK >> 10,
                                                      start), 0.45))
                run = 0
        return out

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        # self-extracting game / installer: the files it would unpack, read
        # without running it
        return containers.expand(ctx)

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        out = containers.findings(self, ctx)
        if ctx.pe is not None and ctx.pe.packed and not containers.detect(ctx):
            out.append(self._packed_unread(ctx))
        return out

    def _packed_unread(self, ctx: FileContext) -> Finding:
        """A packed program with nothing readable inside (phageo, 2026-10-17, fifty-eighth message):
        its code is compressed or encrypted and unpacked only when it runs, and no installer data
        or archive was found in it to read instead. Said like any content that could not be read
        (``ARC-002``, never hidden): at least REVIEW. (A packed program that carries an installer
        or archive that is opened is not noted - what it unpacks is read.)"""
        pe = ctx.pe
        hot = [s for s in pe.sections if s.executable and s.entropy >= 7.2]
        how = ("packer %s" % pe.packer if pe.packer else
               "code section %s entropy %.2f, %d imports" % (hot[0].name or "(unnamed)", hot[0].entropy,
                                                             pe.import_count) if hot else "packed")
        note = self.make(ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION, Severity.LOW,
                         NOT_INSPECTED,
                         "%s: a packed program (%s) with nothing readable inside - its real code is unpacked "
                         "only when it runs, so it was not inspected" % (ctx.name, how), 0.3)
        note.chainable = False
        return note

    def _structure(self, ctx: FileContext) -> List[Finding]:
        pe, out = ctx.pe, []
        if pe.packer:
            sev = Severity.MEDIUM if pe.packer == "UPX" else Severity.HIGH
            names = ", ".join(s.name for s in pe.sections)
            out.append(self.make(ctx, "PE-PACK-001", "Packed executable (%s)" % pe.packer,
                                 Category.PACKING, sev,
                                 "The program's real code is compressed/encrypted and only "
                                 "unpacked in memory, which hides it from inspection.",
                                 "sections: " + names, 0.8))
        out += self.pe_entropy(ctx)
        if pe.entry_point and pe.sections:
            home = next((s for s in pe.sections
                         if s.vaddr <= pe.entry_point < s.vaddr + max(s.vsize, s.raw_size)), None)
            if home is None or not home.executable:
                where = "outside every section" if home is None else \
                    "in non-executable section " + (home.name or "(unnamed)")
                out.append(self.make(ctx, "PE-EP-001", "Abnormal program entry point",
                                     Category.PACKING, Severity.MEDIUM,
                                     "The program starts running from a place compilers never "
                                     "use, which is typical of packed or patched executables.",
                                     "entry point 0x%x is %s" % (pe.entry_point, where), 0.55))
        for s in pe.sections:
            if s.executable and s.writable:
                out.append(self.make(ctx, "PE-PACK-003", "Writable + executable section",
                                     Category.PACKING, Severity.MEDIUM,
                                     "Code that can rewrite itself at runtime is typical "
                                     "of packers and self-modifying malware.",
                                     "section " + (s.name or "(unnamed)"), 0.5))
        if (pe.has_import_dir and pe.import_count < 5 and not ctx.truncated
                and any(s.executable for s in pe.sections)):
            imports = ", ".join(n for names in pe.imports.values() for n in names) or "none"
            out.append(self.make(ctx, "PE-PACK-004", "Minimal import table", Category.PACKING,
                                 Severity.MEDIUM,
                                 "The program declares almost no system functions, so it "
                                 "resolves what it really uses at runtime.",
                                 "imports: " + imports, 0.5))
        return out
