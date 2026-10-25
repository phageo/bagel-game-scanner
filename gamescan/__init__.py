"""Bagel - static malware triage for game folders.

A dependency-free (standard library only), object-oriented detection core:
one :class:`BaseHandler` subclass per engine family, a shared
:class:`RuleEngine`, a :class:`ContextEngine` that owns every false-positive
decision, a :class:`ChainEngine` for cross-signal attack chains and a
:class:`ScanReport` that serialises to JSON.
"""
from .chains import ChainEngine, ChainRule
from .context import ContextEngine, HashAllowlist
from .handlers import (BaseHandler, DotNetHandler, NativePEHandler, RenPyHandler,
                       RpgMakerHandler, ShellHandler, default_handlers)
from .models import (TOOL_NAME, TOOL_VERSION, Category, FileContext, Finding,
                     ScanReport, Severity)
from .memory import MemoryCenter
from .quarantine import Quarantine
from .reputation import VirusTotalClient
from .rules import Rule, RuleEngine
from .scanner import Scanner, neutral_scanner, scan_path
from .yara import YaraRuleSet

__version__ = TOOL_VERSION
__all__ = [
    "BaseHandler", "Category", "ChainEngine", "ChainRule", "ContextEngine",
    "DotNetHandler", "FileContext", "Finding", "HashAllowlist", "MemoryCenter", "NativePEHandler",
    "Quarantine", "RenPyHandler", "RpgMakerHandler", "Rule", "RuleEngine", "ScanReport",
    "Scanner", "Severity", "ShellHandler", "TOOL_NAME", "TOOL_VERSION", "VirusTotalClient",
    "YaraRuleSet", "default_handlers", "neutral_scanner", "scan_path",
]
