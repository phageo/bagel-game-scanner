"""The experimental "Protection" window (Koruma): PC scans, the known-malware hash list,
real-time protection - and the alert that real-time protection opens.

Hidden in 0.9-beta and left out of its package (phageo, 2026-10-24: never tested); switched on
only by ``models.EXPERIMENTAL_PROTECTION``. No module that scans imports this one."""
from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import i18n, settings as settings_store
from .dialogs import _Dialog
from .i18n import t
from .models import TOOL_NAME
from .quarantine import QuarantineError
from .signatures import DEFAULT_URL, SignatureError
from .widgets import (ACCENT, ACCENT_HI, BG, DANGER, DANGER_HI, FONT, LINE, MUTED, PANEL,
                      TEXT, HoverButton, make_check)


def signature_error_text(exc: SignatureError) -> str:
    """Translated, user-facing explanation of a failed signature update."""
    if exc.code == "no_key":
        return t("no abuse.ch Auth-Key is set. Get a free key at https://auth.abuse.ch/ and "
                 "enter it in Settings.")
    if exc.code == "rejected":
        return t("abuse.ch rejected the Auth-Key. Check the key in Settings.")
    if exc.code == "rate_limit":
        return t("the list was downloaded less than 5 minutes ago. Try again later.")
    if exc.code == "empty":
        return t("the server did not return a hash list. Nothing was changed.")
    return t("the download did not work (%s). Nothing was changed.", exc.detail or "?")


class ProtectionDialog(_Dialog):
    """Antivirus-style controls: real-time protection, PC scans, signature database."""

    EVENTS = (("time", "Time", 80), ("verdict", "Result", 150), ("file", "File", 400))

    def __init__(self, app) -> None:
        super().__init__(app, t("Protection"))
        px = app._px
        body = tk.Frame(self, bg=BG)
        body.pack(padx=px(22), pady=(px(6), px(18)))

        self.heading(body, t("Scan this PC"))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x")
        HoverButton(row, t("Startup items and running programs"),
                    lambda: self._run(app.scan_system), ACCENT, ACCENT_HI, "#ffffff").pack(side="left")

        self.heading(body, t("Known-malware database"))
        self.sig_info = self.hint(body, "")
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(6), 0))
        self.update_btn = HoverButton(row, t("Update from the internet"), self._update)
        self.update_btn.pack(side="left")
        HoverButton(row, t("Import hash list…"), self._import).pack(side="left", padx=px(8))

        # -- experimental: PC-wide features that duplicate Windows Security -------
        tk.Frame(body, bg=LINE, height=1).pack(fill="x", pady=(px(18), 0))
        self.heading(body, t("Experimental"))
        tk.Label(body, text=t("These features repeat what Windows Security already does, less "
                              "well, and cause false alarms outside game folders."),
                 font=(FONT, 9, "bold"), fg="#f2cc60", bg=BG, justify="left", anchor="w",
                 wraplength=px(520)).pack(anchor="w", fill="x")
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(8), 0))
        for label, action in ((t("Quick scan"), app.scan_quick), (t("Full scan"), app.scan_full)):
            HoverButton(row, label, lambda a=action: self._run(a)).pack(side="left", padx=(0, px(8)))
        self.hint(body, t("Quick scan covers Downloads, Desktop, the temp folder and the Startup "
                          "folders. A full scan reads every file on the fixed drives and can "
                          "take hours."))
        self.rt_var = tk.BooleanVar(value=bool(app.settings.get("realtime_enabled")))
        make_check(body, t("Real-time protection") + ": "
                   + t("Scan new and changed files in these folders automatically"),
                   self.rt_var, self._toggle_realtime).pack(anchor="w", pady=(px(10), 0))
        self.folders = self.hint(body, "")
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(6), 0))
        HoverButton(row, t("Add folder…"), self._add_folder).pack(side="left")
        HoverButton(row, t("Reset folders"), self._reset_folders).pack(side="left", padx=px(8))
        self.hint(body, t("Works while this window is open. Files are checked right after they "
                          "are written; a program cannot be blocked before it starts. Keep "
                          "Windows Security switched on."))

        self.heading(body, t("Recent real-time events"))
        frame = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        frame.pack(anchor="w")
        self.events = ttk.Treeview(frame, columns=[c[0] for c in self.EVENTS], show="headings",
                                   selectmode="browse", height=5)
        for cid, label, width in self.EVENTS:
            self.events.heading(cid, text=t(label), anchor="w")
            self.events.column(cid, width=px(width), anchor="w")
        self.events.pack()
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(16), 0))
        HoverButton(row, t("Close"), self.destroy).pack(side="right")
        self._worker = None
        self._refresh()
        self.show()

    def _refresh(self) -> None:
        app = self.app
        live = app.monitor is not None and app.monitor.running
        text = "\n".join(app.watch_dirs()) or t("No folder to watch.")
        if live:
            text += "\n" + t("Active · %d file(s) checked so far", app.monitor.scanned)
        self.folders.configure(text=text)
        db = app.signatures
        if db is None:
            self.sig_info.configure(text=t("The signature database is not available."))
        else:
            when = db.last_update()
            self.sig_info.configure(text=t(
                "%s known-malware hashes  ·  last update: %s", "{:,}".format(db.count()),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(when)) if when else t("never"))
                + "\n" + str(app.settings.get("signature_url", "")))
        self.events.delete(*self.events.get_children())
        for when, path, verdict, _action in reversed(app.rt_events[-50:]):
            self.events.insert("", "end", values=(time.strftime("%H:%M:%S", time.localtime(when)),
                                                  i18n.verdict_name(verdict), path))

    def _save(self) -> None:
        try:
            settings_store.save(self.app.settings)
        except OSError as exc:
            messagebox.showerror(TOOL_NAME, t("The settings could not be saved:\n\n%s", exc), parent=self)
        self.app.apply_settings()
        self._refresh()

    def _toggle_realtime(self) -> None:
        self.app.settings["realtime_enabled"] = self.rt_var.get()
        self._save()

    def _add_folder(self) -> None:
        path = filedialog.askdirectory(parent=self, title=t("Choose a folder to watch"))
        if path:
            dirs = self.app.watch_dirs()
            path = os.path.normpath(path)
            if path not in dirs:
                self.app.settings["watch_dirs"] = dirs + [path]
                self._save()

    def _reset_folders(self) -> None:
        self.app.settings["watch_dirs"] = None
        self._save()

    def _run(self, action) -> None:
        if self.app.scanning:
            return
        self.destroy()
        action()

    def _import(self) -> None:
        db = self.app.signatures
        path = filedialog.askopenfilename(parent=self, title=t("Choose a text or CSV file with "
                                                               "SHA-256 hashes"))
        if not path or db is None:
            return
        try:
            result = db.import_file(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror(TOOL_NAME, str(exc), parent=self)
            return
        self._refresh()
        self.sig_info.configure(text=t("%d hashes in the list, %d of them new.", result.listed,
                                       result.added) + "\n" + self.sig_info.cget("text"))

    def _update(self) -> None:
        """Download the hash list on a worker thread; the window stays responsive."""
        db = self.app.signatures
        if db is None or self._worker is not None:
            return
        result = {}

        def work():
            try:
                result["ok"] = db.update(self.app.settings.get("signature_url") or DEFAULT_URL,
                                         self.app.settings.get("abusech_key", ""))
            except SignatureError as exc:
                result["error"] = exc
            except Exception as exc:              # never leave the window stuck on "Downloading"
                result["error"] = SignatureError("network", type(exc).__name__)

        def poll():
            if not self.winfo_exists():
                return
            if self._worker.is_alive():
                self.after(150, poll)
                return
            self._worker = None
            self.update_btn.enable(True)
            self._refresh()
            if "error" in result:
                head = t("Update failed: %s", signature_error_text(result["error"]))
                self.sig_info.configure(fg=DANGER_HI)
            else:
                head = t("%d hashes in the list, %d of them new.", result["ok"].listed,
                         result["ok"].added)
            self.sig_info.configure(text=head + "\n" + self.sig_info.cget("text"))

        self.update_btn.enable(False)
        self.sig_info.configure(text=t("Downloading…"), fg=MUTED)
        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()
        self.after(150, poll)


class ThreatAlert(tk.Toplevel):
    """Non-modal warning shown when real-time protection finds a threat."""

    def __init__(self, app, path: str, report) -> None:
        super().__init__(app)
        self.app, self.path, self.report = app, path, report
        px = app._px
        self.title(TOOL_NAME)
        self.configure(bg=BG, highlightthickness=2, highlightbackground=DANGER)
        self.attributes("-topmost", True)
        self.resizable(False, False)
        body = tk.Frame(self, bg=BG)
        body.pack(padx=px(22), pady=px(18))
        name, _detail = i18n.verdict(report)
        tk.Label(body, text=t("Threat detected"), font=(FONT, 15, "bold"), fg=DANGER_HI,
                 bg=BG).pack(anchor="w")
        tk.Label(body, text=name + "  ·  " + path, font=(FONT, 10), fg=TEXT, bg=BG,
                 wraplength=px(520), justify="left").pack(anchor="w", pady=(px(4), px(10)))
        worst = sorted(report.active, key=lambda f: (-f.severity, -f.confidence))[:4]
        tk.Label(body, text="\n".join("• " + i18n.title(f) for f in worst), font=(FONT, 10),
                 fg=MUTED, bg=BG, justify="left", wraplength=px(520)).pack(anchor="w")
        self.state_lbl = tk.Label(body, text=t("The file has been moved to quarantine.")
                                  if report.quarantined else "", font=(FONT, 10, "bold"),
                                  fg=DANGER_HI, bg=BG)
        self.state_lbl.pack(anchor="w", pady=(px(10), 0))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(14), 0))
        HoverButton(row, t("Close"), self.destroy).pack(side="right")
        self.quar_btn = HoverButton(row, t("Quarantine file"), self._quarantine, DANGER,
                                    DANGER_HI, "#ffffff")
        self.quar_btn.pack(side="right", padx=px(8))
        self.quar_btn.enable(not report.quarantined and os.path.isfile(path))
        self.update_idletasks()
        self.geometry("+%d+%d" % (self.winfo_screenwidth() - self.winfo_width() - px(40),
                                  self.winfo_screenheight() - self.winfo_height() - px(100)))

    def _quarantine(self) -> None:
        active = self.report.active
        try:
            entry = self.app.quarantine.isolate(
                self.path, (f.rule_id for f in active),
                max(f.severity for f in active).name if active else "")
        except QuarantineError as exc:
            messagebox.showerror(TOOL_NAME, str(exc), parent=self)
            return
        self.report.quarantined.append(entry)
        self.quar_btn.enable(False)
        self.state_lbl.configure(text=t("The file has been moved to quarantine."))
