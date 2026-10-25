"""Engine handlers. Register a new engine by adding it to ``default_handlers``."""
from typing import List

from .base import BaseHandler
from .documents import DocumentHandler
from .media import MediaHandler
from .dotnet import DotNetHandler
from .electron import ElectronHandler
from .native_pe import NativePEHandler
from .renpy import RenPyHandler
from .rgss import RgssHandler
from .rpgmaker import RpgMakerHandler
from .shell import ShellHandler
from .text import UnreadFormatHandler, UnreadProgramHandler

__all__ = ["BaseHandler", "DocumentHandler", "DotNetHandler", "ElectronHandler", "MediaHandler", "NativePEHandler",
           "RenPyHandler",
           "RgssHandler", "RpgMakerHandler", "ShellHandler", "default_handlers"]


def default_handlers() -> List[BaseHandler]:
    # order matters: binaries are routed by content before anything is
    # routed by file extension
    return [DotNetHandler(), NativePEHandler(), ShellHandler(), RenPyHandler(),
            RpgMakerHandler(), RgssHandler(), ElectronHandler(), UnreadProgramHandler(),
            UnreadFormatHandler(), DocumentHandler(), MediaHandler()]
