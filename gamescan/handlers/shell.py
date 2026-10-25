"""Shell droppers: batch, PowerShell, VBScript, HTA, POSIX shell, shortcuts."""
from __future__ import annotations

from typing import List

from .. import engine_hashes
from ..models import FileContext, Finding
from ..pe import extract_strings
from ..rules import RuleEngine
from ..dataflow import remote_sh
from .base import BaseHandler

_STYLE = {
    ".bat": "bat", ".cmd": "bat", ".ps1": "powershell", ".psm1": "powershell",
    ".vbs": "vbs", ".vbe": "vbs", ".wsf": "vbs", ".hta": "vbs", ".jse": "jse",
    ".sh": "sh", ".bash": "sh", ".command": "sh",
}
_FLOW = {"powershell": "powershell", "bat": "batch"}


class ShellHandler(BaseHandler):
    name = "shell"
    engine = "Shell script"
    extensions = frozenset(_STYLE) | frozenset({".lnk"})

    def baseline_reason(self, ctx: FileContext) -> str:
        # A Ren'Py game ships a copy of the SDK's renpy.sh under the game's name. A file
        # that is, byte for byte, that launcher of an official SDK is judged like the other
        # hash-verified engine files (phageo, 2026-10-12): what the rules find in it is
        # lowered; a CRITICAL finding or chain is still shown (CLAUDE.md, rule 13). The
        # name proves nothing - only the content does.
        if _STYLE.get(ctx.ext) == "sh":
            official = engine_hashes.verified_shell_launcher(ctx.sha256)
            if official:
                return "%s: %s" % (engine_hashes.VERIFIED, official)
        return super().baseline_reason(ctx)

    def official_script(self, ctx: FileContext) -> bool:
        return _STYLE.get(ctx.ext) == "sh" and bool(engine_hashes.verified_shell_launcher(ctx.sha256))

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if ctx.ext == ".lnk":                     # binary shortcut: command line as strings
            text = "\n".join(extract_strings(ctx.data, min_len=4))
            return rules.scan(text, "shell", ctx, self.name, numbered=False)
        # a .vbe / .jse file, or an encoded block inside a .wsf / .hta: decoded, then read as if plain
        text, notes = self.decode_script(ctx, ctx.text())
        if _STYLE[ctx.ext] == "jse":              # encoded JScript: the JavaScript rules and chains
            return (notes + rules.scan(text, "js", ctx, self.name, comment_style="c", quoted=True)
                    + self.entropy_literals(ctx, text, "js") + self.resolve_payloads(ctx, rules, text, "js"))
        out = notes + (rules.scan(text, "shell", ctx, self.name, comment_style=_STYLE[ctx.ext])
                       + self.entropy_literals(ctx, text, "shell"))
        if _STYLE[ctx.ext] in _FLOW:              # variables / encoded commands resolved
            out += self.resolve_payloads(ctx, rules, text, _FLOW[_STYLE[ctx.ext]])
        elif _STYLE[ctx.ext] == "sh":
            # a POSIX shell script has no tracer of its own; what it shares with the other
            # scripts of its folder is still read (dataflow/remote_sh.shared)
            share = remote_sh.shared(text, "sh", ctx.name)
            self._share(ctx, share)
            if share.cut:
                out += self.tracer_cut(ctx, share.cut)
        elif _STYLE[ctx.ext] == "vbs":
            wrapped = ctx.ext in (".wsf", ".hta")
            out += self.vbscript_code(ctx, text, wrapped)
            if wrapped:                           # ... and its JScript blocks (an .hta block that
                out += self.jscript_blocks(ctx, text, "js" if ctx.ext == ".hta" else "")   # names no language is JScript)
        return out
