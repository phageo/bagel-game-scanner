"""Cross-signal correlation: several weak signals in one file => attack chain."""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/chains.py")

from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

from .models import PACKED, STATEMENT, Category as C, FileContext, Finding, Severity as S

# -- what counts as spying (CHAIN-SPYWARE) -------------------------------------------------
# Reading the state of the keyboard is how games read input; a hook sees every key that is
# typed anywhere. The two are told apart by the function the finding matched.
_KEY_READING = frozenset({_IND[0], "getkeyboardstate"})
KEY_LOG_WORDS = "INPUT-003"        # a table of key names, or the word itself, inside a program
EXFILTRATION = "NET-EXFIL-001"     # an address stealers send their loot to
HOOK_ONLY = (" In a program this rests on its import table alone: it can install an input hook and "
             "it can use the network, which many ordinary windowed programs with an update check "
             "can too. CRITICAL needs two independent signs - a hook, a known exfiltration address, "
             "a key-logging dictionary - so it is reported as HIGH.")
KEYS_ONLY = (" Only the state of the keyboard is read here - no hook, no clipboard, no screen "
             "capture - so it is reported as HIGH, not CRITICAL.")


FILE_NAME_ONLY = "file_name"       # mark of ContextEngine._installed_name (context.FILE_NAME_ONLY)
FILE_NAME_CHAIN = (" Here one of the parts is only a word in the name of a file this installer installs - "
                   "file name, not an instruction - and without it there is no chain, so it is shown as a "
                   "LOW note.")


# -- a chain of nearness whose premise the data-flow reading disproved (phageo, 2026-10-14) -------
# "Download and run" by nearness says: something fetched from the network is run. When the
# data-flow reading of the script read the whole file and found no download that reaches code
# or a program start, that premise is statically disproven (CLAUDE.md, rule 13): the chain is
# reported under a name of its own - HIGH, and MEDIUM in a file of a published npm package
# (Scanner: library mechanism). A file that was not read to its end keeps the chain unchanged.
NO_FLOW = "CHAIN-NO-FLOW"
NO_FLOW_TITLE = "Attack chain: parts near each other, no flow between them"
NO_FLOW_RULES = ("CHAIN-DOWNLOADER", "CHAIN-FETCHRUN")
WAS_CRITICAL = "was_critical"
NO_FLOW_REASON = ("Network access and running code or starting programs appear near each other in this "
                  "script - the parts of a \"download and run\" chain. The scanner's data-flow reading read "
                  "the whole script and found no way for anything downloaded to reach the place where code "
                  "is run or a program is started, so it is not reported as that chain. The parts are "
                  "listed: look at what the script runs and starts.")
NO_FLOW_MANAGED = (" Here the script is the compiled C# of a .NET library: its methods were read instruction "
                   "by instruction to their end, so the level is MEDIUM.")


def _matched(f: Finding) -> str:
    return str(f.context.get("match", "")).lower()


def _reads_keys(f: Finding) -> bool:
    return f.rule_id == "INPUT-001" and _matched(f) in _KEY_READING


def _hooks(f: Finding) -> bool:
    return f.rule_id == "INPUT-001" and _matched(f).startswith(_IND[1])


def _key_log_words(f: Finding) -> bool:
    # (the word as a whole word: keylog, keylogger, keylogging ... - rules._names)
    return f.rule_id == KEY_LOG_WORDS or (f.rule_id == "INPUT-001" and _matched(f).startswith("keylog"))


def native_program(ctx: FileContext) -> bool:
    """A native program: what is known about it comes from its import table and strings."""
    return bool(ctx.is_pe) and not (ctx.pe is not None and ctx.pe.is_dotnet)


@dataclass(frozen=True)
class ChainRule:
    id: str
    title: str
    requires: Tuple[FrozenSet[C], ...]   # every group needs one finding
    severity: S
    reason: str
    supersedes: Tuple[str, ...] = ()     # weaker chains this one already implies


def _g(*cats: C) -> FrozenSet[C]:
    return frozenset(cats)


DEFAULT_CHAINS: List[ChainRule] = [
    ChainRule("CHAIN-DOWNLOADER", "Downloader / dropper",
              (_g(C.NETWORK), _g(C.OBFUSCATION), _g(C.EXECUTION, C.PROCESS)), S.CRITICAL,
              "Network access, a hidden payload and code execution appear together: "
              "the file can fetch something from the internet and run it.",
              ("CHAIN-FETCHRUN", "CHAIN-LOADER")),
    ChainRule("CHAIN-STEALER", "Credential stealer",
              (_g(C.CREDENTIALS), _g(C.NETWORK)), S.CRITICAL,
              "Reads credential / token stores and has a way to send them out."),
    ChainRule("CHAIN-SPYWARE", "Spyware / keylogger",
              (_g(C.INPUT_CAPTURE), _g(C.NETWORK)), S.CRITICAL,
              "Captures keystrokes, screen or clipboard and has a way to send them out."),
    ChainRule("CHAIN-BACKDOOR", "Persistent backdoor",
              (_g(C.PERSISTENCE), _g(C.NETWORK, C.PROCESS, C.EXECUTION)), S.HIGH,
              "Installs itself to start with the computer and can run commands or "
              "talk to the network."),
    ChainRule("CHAIN-FETCHRUN", "Download and run",
              (_g(C.NETWORK), _g(C.PROCESS)), S.HIGH,
              "Combines network access with launching external programs."),
    ChainRule("CHAIN-LOADER", "Obfuscated loader",
              (_g(C.OBFUSCATION), _g(C.EXECUTION)), S.HIGH,
              "Decodes hidden data next to dynamic code execution."),
    ChainRule("CHAIN-PACKED", "Packed binary with risky capability",
              (_g(C.PACKING), _g(C.NETWORK, C.PERSISTENCE, C.CREDENTIALS, C.INPUT_CAPTURE)),
              S.HIGH,
              "The binary hides its code with a packer and still exposes risky behaviour."),
    ChainRule("CHAIN-EVASIVE", "Evasive execution",
              (_g(C.EVASION), _g(C.NETWORK, C.PROCESS, C.PERSISTENCE)), S.HIGH,
              "Hides itself or disables protection while running commands or "
              "using the network."),
]


class ChainEngine:
    """Correlates the *active* findings of one file into attack chains.

    In text files the contributing findings must sit within ``proximity``
    lines of each other, so a large legitimate script that happens to use the
    network in one place and ``eval`` in another is not called a dropper.
    """

    def __init__(self, chains: Optional[List[ChainRule]] = None, proximity: int = 60) -> None:
        self.chains = list(DEFAULT_CHAINS if chains is None else chains)
        self.proximity = proximity
        self._packed: FrozenSet[int] = frozenset()
        # set by the scanner for one file: its data-flow reading read it to the end and found
        # no download that reaches a run (NO_FLOW)
        self.flowless = False

    def correlate(self, findings: List[Finding], ctx: FileContext,
                  also: Optional[Callable[[Finding], bool]] = None) -> List[Finding]:
        """Chains formed by the active findings of a file.

        ``also`` admits selected *suppressed* findings as well. The scanner
        uses it for files trusted only because of where they sit: one signal
        in an engine folder is expected, a complete attack chain is not.
        """
        by_cat: Dict[C, List[Finding]] = {}
        names: Dict[C, List[Finding]] = {}
        self._packed = ctx.cache.get(PACKED, frozenset())      # the lines of packed code (rules.py)
        for f in findings:
            if f.chainable and f.category is not C.CHAIN and (
                    not f.suppressed or (also is not None and also(f))):
                names.setdefault(f.category, []).append(f)
                if not f.context.get(FILE_NAME_ONLY):
                    by_cat.setdefault(f.category, []).append(f)
        out = self._chains(by_cat, ctx)
        if any(len(names[cat]) != len(by_cat.get(cat, ())) for cat in names):
            # a chain that only exists because of a word in the name of a file an installer
            # installs (ContextEngine._installed_name) is a note. CRITICAL wins: a chain
            # that would be CRITICAL is reported unchanged
            real = {chain.rule_id for chain in out}
            implied = {rule.id: rule.supersedes for rule in self.chains}
            for chain in self._chains(names, ctx):
                if chain.rule_id not in real:
                    if chain.severity < S.CRITICAL:
                        chain.severity = S.LOW
                        chain.reason += FILE_NAME_CHAIN
                        chain.evidence += "  [file name, not an instruction]"
                        chain.context[FILE_NAME_ONLY] = True
                    else:                       # ... and stands for the weaker chains it implies
                        out = [c for c in out if c.rule_id not in implied.get(chain.rule_id, ())]
                    out.append(chain)
        return out

    def _chains(self, by_cat: Dict[C, List[Finding]], ctx: FileContext) -> List[Finding]:
        out: List[Finding] = []
        skip = set()
        for rule in self.chains:
            if rule.id in skip:
                continue
            severity, note = rule.severity, ""
            if rule.id == "CHAIN-SPYWARE":
                picks, severity, note = self._spyware(rule, by_cat, ctx)
            else:
                picks = self._pick(rule, by_cat)
            if picks is None:
                continue
            evidence = " + ".join(
                "%s (%s%s)" % (p.rule_id, p.category.value,
                               ", line %d" % p.line if p.line else "") for p in picks)
            rule_id, title, reason = rule.id, "Attack chain: " + rule.title, rule.reason + note
            # in a program the parts come from its import table and strings: they show
            # what it can do. In a script the calls themselves were seen.
            # (parts: which findings it is made of - Scanner._fold_update)
            context = {"program": bool(ctx.is_pe), "parts": [(p.rule_id, p.category.value, p.line) for p in picks]}
            if self.flowless and rule.id in NO_FLOW_RULES and not native_program(ctx):
                # the premise is disproven: a name of its own, HIGH. What the disproven chain
                # implied is not implied any more - an obfuscated loader beside it still forms
                skip.update(s for s in rule.supersedes if s in NO_FLOW_RULES)
                context["near_chain"] = rule.id
                # (it stands where the CRITICAL stood: trust lowers it no further, except the
                # library mechanism of a published npm file - Scanner)
                context[WAS_CRITICAL] = severity is S.CRITICAL
                rule_id, title, reason, severity = NO_FLOW, NO_FLOW_TITLE, NO_FLOW_REASON, S.HIGH
                if ctx.is_pe:
                    # a .NET library whose methods were read to their end: MEDIUM (phageo,
                    # 2026-10-17, fifty-ninth message - "fully read: MEDIUM")
                    reason, severity = reason + NO_FLOW_MANAGED, S.MEDIUM
                    evidence += "  [would be %s; the library's code was read to its end and no download reaches a run]" % rule.id
                else:
                    evidence += "  [would be %s; the whole script was read and no download reaches a run]" % rule.id
            else:
                skip.update(rule.supersedes)
            lines = [p.line for p in picks if p.line is not None]
            conf = min(0.95, sum(p.confidence for p in picks) / len(picks) + 0.2)
            out.append(Finding(
                rule_id=rule_id, title=title, category=C.CHAIN,
                severity=severity, file=ctx.relpath, line=min(lines) if lines else None,
                snippet="\n".join(p.snippet for p in picks),
                evidence=evidence, confidence=conf, reason=reason, chainable=False,
                context=context,
            ))
        return out

    def _spyware(self, rule: ChainRule, by_cat: Dict[C, List[Finding]], ctx: FileContext):
        """``(findings, severity, note)`` of the spyware chain, or ``(None, ...)``.

        In a *script* the calls themselves are seen, next to each other: capturing
        (a hook library, the clipboard, the screen) plus the network is CRITICAL;
        reading the keyboard state plus the network alone is HIGH.

        In a *native program* only the import table is seen, and it shows what a
        program can do, not what it does - every windowed program imports the
        clipboard and drawing functions, every game reads the keyboard and uses
        the network. So: reading keys plus network is no chain; a hook plus
        network is HIGH; CRITICAL needs two independent strong signs out of three - a
        hook, a known exfiltration address, a key-logging dictionary. One of them is
        not enough: indie games post bug reports to a chat webhook, and show control
        hints like "[ENTER] Confirm".
        """
        captures, network = by_cat.get(C.INPUT_CAPTURE, []), by_cat.get(C.NETWORK, [])
        if not captures or not network:
            return None, rule.severity, ""
        if native_program(ctx):
            # the strong signs: an input hook, a known exfiltration address, a key-logging
            # dictionary. Reading the keyboard state or the clipboard is not one - every
            # game does the first, every program with a text box the second.
            hook = next((f for f in captures if _hooks(f)), None)
            words = next((f for f in captures if _key_log_words(f)), None)
            address = next((f for f in network if f.rule_id == EXFILTRATION), None)
            strong = [f for f in (hook, words, address) if f is not None]
            if len(strong) >= 2:
                picks = strong if address is not None else strong + [network[0]]
                return picks, S.CRITICAL, ""
            if hook is not None:
                return [hook, network[0]], S.HIGH, HOOK_ONLY
            return None, rule.severity, ""
        strong = [f for f in captures if not _reads_keys(f)]
        if strong:
            picks = self._pick(rule, {C.INPUT_CAPTURE: strong, C.NETWORK: network})
            if picks is not None:
                return picks, S.CRITICAL, ""
        picks = self._pick(rule, by_cat)
        if picks is not None:
            return picks, S.HIGH, KEYS_ONLY
        return None, rule.severity, ""

    def _pick(self, rule: ChainRule, by_cat: Dict[C, List[Finding]]) -> Optional[List[Finding]]:
        groups = [[f for cat in alt for f in by_cat.get(cat, ())] for alt in rule.requires]
        if any(not g for g in groups):
            return None
        packed = self._packed
        best: Optional[Tuple[int, List[Finding]]] = None
        for anchor in groups[0]:
            picks = [anchor]
            for group in groups[1:]:
                picks.append(min(group, key=lambda f: _distance(anchor, f, packed)))
            span = max(_distance(a, b, packed) for a in picks for b in picks)
            if best is None or span < best[0]:
                best = (span, picks)
        return best[1] if best and best[0] <= self.proximity else None


_FAR = 10 ** 9


def _distance(a: Finding, b: Finding, packed=frozenset()) -> int:
    """How far apart two findings stand, in lines. In packed code - a line of thousands of
    characters, where "the same line" or "the next line" says nothing - two findings are
    near only when they stand in the same statement; anything else there is far (phageo,
    2026-10-12). A real hand-over from a download to where it is run, across statements,
    is the business of the data-flow readers (CHAIN-REMOTE-CODE), not of nearness."""
    if a is b:
        return 0
    if a.line is None or b.line is None:
        return 0
    if a.line in packed or b.line in packed:
        sa, sb = a.context.get(STATEMENT), b.context.get(STATEMENT)
        return 0 if a.line == b.line and sa is not None and sa == sb else _FAR
    return abs(a.line - b.line)
