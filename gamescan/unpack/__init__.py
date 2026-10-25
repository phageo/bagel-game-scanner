"""Unpackers / decompilers that turn engine containers into scannable text.

Each module is pure (bytes in, text or bytes out) and never executes or
imports anything from the file being inspected. Handlers call them before
static analysis.
"""
from . import dotnet_meta, rgss, rpyc, unity

__all__ = ["dotnet_meta", "rgss", "rpyc", "unity"]
