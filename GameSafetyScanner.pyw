"""Double-click to open the Bagel window.

pythonw has no console, so a startup error would otherwise just look like
"nothing happened". Any failure here is written to a log file and shown in a
message box. This file is deliberately written in very old-style Python so
that it still runs - and can explain itself - on interpreters older than 3.9.
"""
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(os.path.expanduser("~"), ".game_safety_scanner", "startup_error.log")
MINIMUM = (3, 9)

# The same keys are translated in gamescan/i18n.py. If that module cannot be
# imported (it may be the very thing that failed), both languages are shown.
KEY_OLD_PYTHON = ("Bagel needs Python %d.%d or newer, but this is Python %d.%d.\n"
                  "Install a newer Python from https://www.python.org/downloads/")
KEY_FAILED = ("Bagel could not start.\n"
              "The technical details were saved to:\n%s")
FALLBACK_TR = {
    KEY_OLD_PYTHON: ("Bagel icin Python %d.%d veya daha yenisi gerekir; bu surum "
                     "Python %d.%d.\nhttps://www.python.org/downloads/ adresinden daha yeni bir "
                     "Python kurun."),
    KEY_FAILED: "Bagel baslatilamadi.\nTeknik ayrintilar su dosyaya kaydedildi:\n%s",
}


def localized(key, args):
    try:
        sys.path.insert(0, HERE)
        from gamescan import i18n
        i18n.set_language(i18n.detect_default())
        return i18n.t(key, *args)
    except Exception:
        return (key % args) + "\n\n" + (FALLBACK_TR[key] % args)


def write_log(details, path=None):
    """Save ``details`` to the startup log; returns the path, or '' if that failed."""
    path = path or LOG
    try:
        folder = os.path.dirname(path)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder)
        with open(path, "w") as handle:
            handle.write("Python %s\n%s\n\n%s\n" % (sys.version, sys.executable, details))
        return path
    except (OSError, IOError):
        return ""


def show_error(message):
    """Message box on a hidden root window (best effort: tkinter may be missing)."""
    try:
        try:
            import tkinter
            from tkinter import messagebox
        except ImportError:                      # Python 2
            import Tkinter as tkinter
            import tkMessageBox as messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror("Bagel", message)
        root.destroy()
    except Exception:
        sys.stderr.write(message + "\n")


def run(launch=None, show=show_error, log_path=None):
    """Start the app; returns 0 on success, 1 if startup failed."""
    if sys.version_info < MINIMUM:
        show(localized(KEY_OLD_PYTHON, MINIMUM + tuple(sys.version_info[:2])))
        return 1
    try:
        if launch is None:
            sys.path.insert(0, HERE)
            from gamescan.gui import main as launch
        args = sys.argv[1:]
        if len(args) == 2 and args[0] == "--launch":
            # "Safe launch" of the right-click menu: the secure launcher in the window
            launch(args[1], True)
        else:
            launch(args[0] if args else None)
        return 0
    except Exception:
        saved = write_log(traceback.format_exc(), log_path) or "(the log could not be written)"
        show(localized(KEY_FAILED, (saved,)))
        return 1


if __name__ == "__main__":
    sys.exit(run())
