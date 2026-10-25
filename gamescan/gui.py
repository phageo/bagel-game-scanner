"""Tkinter front end. The scan runs on a worker thread; the UI only ever
touches results through a queue, so it stays responsive on large games."""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
import traceback
from tkinter import filedialog, font as tkfont, messagebox, simpledialog, ttk
from typing import List, Optional

from . import (export, i18n, launcher, models, selfcheck, settings as settings_store, shellmenu,
               system)
from .context import RESOLVED_FP, ContextEngine, HashAllowlist
from .defender import DefenderScan
from .dialogs import MemoryDialog, QuarantineDialog, SettingsDialog
from .i18n import t
from .memory import MemoryCenter, fingerprint
from .signatures import SignatureDatabase
from .models import TOOL_NAME, TOOL_VERSION, Finding, ScanReport, Severity
from .quarantine import Quarantine, QuarantineError
from .reputation import VirusTotalClient
from .rules import RuleEngine
from .scanner import Scanner
from .widgets import (ACCENT, ACCENT_HI, BG, DANGER, DANGER_HI, FONT, LINE, MONO, MUTED, OK, PANEL,
                      PANEL2, SEV_COLOR, SUPP, TEXT, VERDICT_COLOR, Card, HoverButton,
                      SmoothBar, make_check, make_entry)

MAX_ROWS = 5000
# one icon for the window, the taskbar, the shortcuts and the installer (tools/build_icon.py);
# the installer's Start menu shortcut carries the same AppUserModelID, so a pinned icon is Bagel's
ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bagel.ico")
APP_ID = "phageo.Bagel"


class App(tk.Tk):
    # (id, English header - translated when drawn, width, anchor)
    COLUMNS = (("sev", "Severity", 104, "w"), ("cat", "Category", 112, "w"),
               ("title", "Finding", 240, "w"), ("file", "File", 170, "w"),
               ("line", "Line", 52, "e"), ("conf", "Conf.", 58, "e"))

    def __init__(self):
        super().__init__()
        self.settings = settings_store.load()
        i18n.set_language(i18n.detect_default())
        self.title(TOOL_NAME)
        if sys.platform == "win32" and os.path.isfile(ICON):
            try:                                  # default=: every dialog of the window too
                self.iconbitmap(default=ICON)
            except tk.TclError:
                pass
        self.configure(bg=BG)
        self.scale = self.winfo_fpixels("1i") / 96.0
        self.geometry("%dx%d" % (min(self._px(1280), self.winfo_screenwidth() - 80),
                                 min(self._px(820), self.winfo_screenheight() - 120)))
        self.minsize(self._px(980), self._px(600))

        self.allowlist = HashAllowlist(HashAllowlist.default_path())
        self.quarantine = Quarantine()
        self.memory: Optional[MemoryCenter] = None
        self.signatures: Optional[SignatureDatabase] = None
        self.monitor = None                       # monitor.RealTimeMonitor, experimental only
        self.rt_events: List[tuple] = []          # (time, path, verdict, action)
        self.context = ContextEngine(self.allowlist)
        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.apply_settings()
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.findings: List[Finding] = []
        self.report: Optional[ScanReport] = None
        self._scan_label: Optional[str] = None
        self._scan_note: Optional[str] = None           # what the right-click "Scan" scanned
        self._clicked_program: Optional[str] = None
        self._machine_menu = False
        self.cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.scanning = False
        self.failed: Optional[str] = None
        self.sev_filter: Optional[Severity] = None
        self.sort_col, self.sort_rev = None, False
        self._rows: List[Finding] = []
        self._dirty, self._last_refresh, self._search_job = False, 0.0, None
        self._files_done, self._progress = 0, 0.0

        self.path_var = tk.StringVar()
        self.strict_var = tk.BooleanVar(value=False)
        self.supp_var = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._debounced_refresh())

        self._style()
        self._build()
        self._show_welcome()
        for keys, action in (("<F5>", self._toggle_scan), ("<Control-o>", self._open_report),
                             ("<Control-e>", self._export), ("<Control-f>", self._focus_filter),
                             ("<Escape>", self._clear_filters)):
            self.bind(keys, lambda e, action=action: action())
        self.after(30, self._pump)

    def _px(self, n: float) -> int:
        return int(round(n * self.scale))

    def apply_settings(self):
        """(Re)create what depends on settings: the memory center and its feedback loop."""
        self.memory = None
        if self.settings.get("memory_enabled", True):
            try:
                self.memory = MemoryCenter()
            except Exception:                     # unwritable profile: run without learning
                self.memory = None
        self.context = ContextEngine(self.allowlist, memory=self.memory)
        if self.signatures is None:
            try:
                self.signatures = SignatureDatabase()
            except Exception:
                self.signatures = None
        self._restart_monitor()

    def watch_dirs(self) -> List[str]:
        chosen = self.settings.get("watch_dirs")
        if not chosen:
            folders = system.known_folders()
            chosen = [folders[k] for k in ("Downloads", "Desktop") if k in folders]
        return [d for d in chosen if os.path.isdir(d)]

    def _make_scanner(self, cfg: dict, strict: bool, history: bool = True) -> Scanner:
        rules = RuleEngine()
        if cfg["yara_dir"] and os.path.isdir(cfg["yara_dir"]):
            rules.load_yara(cfg["yara_dir"])
        reputation = None
        if history and cfg["vt_enabled"] and cfg["vt_api_key"]:
            reputation = VirusTotalClient(
                cfg["vt_api_key"], os.path.join(settings_store.DIR, "virustotal_cache.json"))
        return Scanner(rules=rules, reputation=reputation, max_lookups=int(cfg["vt_max_lookups"]),
                       context=ContextEngine(
                           self.allowlist, strict=strict, memory=self.memory,
                           trusted_publishers=cfg.get("trusted_publishers"),
                           vt_min_age_days=float(cfg.get("vt_min_age_days", 30))),
                       memory=self.memory if history else False, signatures=self.signatures,
                       amsi=bool(cfg.get("amsi_enabled", True)),
                       defender=DefenderScan() if history and cfg.get("defender_scan") else None,
                       quarantine=self.quarantine, auto_quarantine=bool(cfg["auto_quarantine"]))

    def _restart_monitor(self):
        """Real-time protection follows the settings; it runs while the app is open.
        Only when the experimental features are on - never in 0.9-beta, whatever was saved."""
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        if models.EXPERIMENTAL_PROTECTION and self.settings.get("realtime_enabled"):
            from .monitor import RealTimeMonitor
            scanner = self._make_scanner(dict(self.settings), strict=False, history=False)
            self.monitor = RealTimeMonitor(
                self.watch_dirs(), scanner.scan,
                lambda path, report: self.q.put(("realtime", path, report)))
            self.monitor.start()
        shield = getattr(self, "shield", None)
        if shield is not None and shield.winfo_exists():
            live = self.monitor is not None and self.monitor.running
            shield.configure(text=t("● Protection on") if live else t("○ Protection off"))
            shield._fg = OK if live else MUTED
            shield.configure(fg=shield._fg)

    def _quit(self):
        """One click on X closes the window; a running scan is stopped first, after one question."""
        if self.scanning:
            if not messagebox.askyesno(TOOL_NAME, t("A scan is still running. Stop it and close "
                                                    "the window?"), parent=self):
                return
            self.cancel.set()
            if self._thread is not None:          # the scan ends at its next file; its temporary
                self._thread.join(5.0)            # files are removed on the way out
        if self.monitor is not None:
            self.monitor.stop()
        # Stop the animation / polling timers first, so none of them fires on a dead window.
        # "after cancel" only: after_cancel() would also delete each timer's Tcl command, which
        # its widget deletes again when destroyed - that error stopped destroy() half-way, after
        # the first rows of the window were gone, and a second click was needed (seen 2026-10-24).
        try:
            for job in self.tk.call("after", "info"):
                self.tk.call("after", "cancel", job)
        except tk.TclError:
            pass
        self.destroy()

    def _startup_checks(self):
        """Once after the window opens: the package's own files (``selfcheck``), then a
        right-click menu entry that names another copy (``shellmenu``)."""
        root = selfcheck.package_root()
        if root is not None:
            try:
                result = selfcheck.check(root)
            except (OSError, ValueError, KeyError) as exc:
                result = selfcheck.Result([], ["app/" + selfcheck.LIST_NAME + " (%s)" % exc], [])
            if not result.ok:
                names = (result.changed + result.missing + result.added)[:8]
                messagebox.showwarning(TOOL_NAME, t(
                    "Some files of this package are not as they were when it was built "
                    "(%d changed, %d missing, %d added). For example:\n\n%s\n\nThe package may be "
                    "damaged, or someone changed it. Download it again from where you got it. You "
                    "can still scan, but the results of a changed package may be wrong.",
                    len(result.changed), len(result.missing), len(result.added),
                    "\n".join(names)), parent=self)
        if sys.platform != "win32":
            return
        try:
            added, here, found = shellmenu.state()
        except (shellmenu.MenuError, OSError):
            return
        if added and not here and messagebox.askyesno(TOOL_NAME, t(
                "The Explorer right-click menu still opens Bagel from another "
                "place:\n\n%s\n\nPoint it to this copy now?", "\n".join(found)), parent=self):
            try:
                shellmenu.add(t("Scan"), launch_label=t("Safe launch"))
            except (shellmenu.MenuError, OSError) as exc:
                messagebox.showerror(TOOL_NAME, t("The right-click menu could not be changed:\n\n%s",
                                                  exc), parent=self)
            self._show_header_menu()

    def _menu_state(self):
        """``(added, points here, commands found)``; ``None`` when there is no right-click menu.
        An entry an installation "for all users" made for this copy counts as on (``_machine_menu``)."""
        self._machine_menu = False
        if sys.platform != "win32":
            return None
        try:
            state = shellmenu.state()
            if not state[0] and shellmenu.machine_wide():
                self._machine_menu = True
                return True, True, []
            return state
        except (shellmenu.MenuError, OSError):
            return None

    def _show_header_menu(self):
        """The main window's right-click menu button: what it does now, or hidden without a menu."""
        btn = getattr(self, "menu_btn", None)
        if btn is None or not btn.winfo_exists():
            return
        state = self._menu_state()
        if state is None:
            btn.pack_forget()
            return
        added, here, _found = state
        if added and here:
            text, fg = t("Right-click menu: on"), MUTED
        elif added:
            text, fg = t("Right-click menu: another copy"), ACCENT
        else:
            text, fg = t("Add to the right-click menu"), ACCENT
        btn._fg = fg
        btn.configure(text=text, fg=fg)

    def _header_menu(self):
        """Add, point to this copy, or remove - after one question that says what it does."""
        state = self._menu_state()
        if state is None:
            return
        added, here, found = state
        try:
            if self._machine_menu:
                messagebox.showinfo(TOOL_NAME, t(
                    "The right-click menu was added for all users when Bagel was installed. It is "
                    "removed when Bagel is uninstalled."), parent=self)
            elif added and here:
                if messagebox.askyesno(TOOL_NAME, t(
                        "Remove the “Bagel” entry from the right-click menu?"), parent=self):
                    shellmenu.remove()
            elif added:
                if messagebox.askyesno(TOOL_NAME, t(
                        "The Explorer right-click menu still opens Bagel from another "
                        "place:\n\n%s\n\nPoint it to this copy now?", "\n".join(found)), parent=self):
                    shellmenu.add(t("Scan"), launch_label=t("Safe launch"))
            elif messagebox.askyesno(TOOL_NAME, t(
                    "Adds one entry “Bagel” to the right-click menu, for your Windows account only (no "
                    "administrator rights): “Scan” on folders and files, and also “Safe launch” on "
                    "programs (.exe). Scan opens this window and scans what you clicked - for a "
                    "program, its game folder; Safe launch scans the program's folder first and then "
                    "starts the game, asks you, or refuses. On Windows 11 it is under “Show more "
                    "options”. Removing it leaves nothing behind.") + "\n\n" + t("Add it now?"),
                    parent=self):
                shellmenu.add(t("Scan"), launch_label=t("Safe launch"))
        except (shellmenu.MenuError, OSError) as exc:
            messagebox.showerror(TOOL_NAME, t("The right-click menu could not be changed:\n\n%s", exc),
                                 parent=self)
        self._show_header_menu()

    def _focus_filter(self):
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")

    def _clear_filters(self):
        try:
            focus = self.focus_get()
        except KeyError:                          # focus is inside a native popup
            return
        if focus is not None and focus.winfo_toplevel() is not self:
            return                                # Escape belongs to an open dialog
        self.sev_filter = None
        self.search_var.set("")
        self._refresh()

    # -- look ------------------------------------------------------------------
    def _style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        row = tkfont.Font(family=FONT, size=10).metrics("linespace") + self._px(12)
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                     rowheight=row, borderwidth=0, font=(FONT, 10))
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.map("Treeview", background=[("selected", "#22324f")], foreground=[("selected", TEXT)])
        st.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat",
                     borderwidth=0, font=(FONT, 9, "bold"), padding=(8, 7))
        st.map("Treeview.Heading", background=[("active", LINE)], foreground=[("active", TEXT)])
        for orient in ("Vertical", "Horizontal"):
            st.configure(orient + ".TScrollbar", background=LINE, troughcolor=PANEL,
                         bordercolor=PANEL, lightcolor=LINE, darkcolor=LINE, arrowcolor=MUTED,
                         relief="flat", arrowsize=self._px(12))
            st.map(orient + ".TScrollbar", background=[("active", "#3a455a")])
        st.configure("TPanedwindow", background=BG)
        st.configure("Sash", sashthickness=self._px(8), handlesize=0, background=BG,
                     bordercolor=BG, lightcolor=BG, darkcolor=BG)

    def _fit_columns(self, width: int):
        """Fixed columns keep their size; Finding and File share the rest."""
        fixed = sum(self._px(w) for cid, _, w, _ in self.COLUMNS if cid not in ("title", "file"))
        rest = max(self._px(240), width - fixed - 2)
        self.tree.column("title", width=int(rest * 0.58))
        self.tree.column("file", width=rest - int(rest * 0.58))

    # -- layout ----------------------------------------------------------------
    def _build(self):
        pad = self._px(18)
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=pad, pady=(pad, 0))
        tk.Label(head, text=TOOL_NAME, font=(FONT, 17, "bold"), fg=TEXT, bg=BG).pack(side="left")
        # the engine list has a line of its own: beside the title it pushed the buttons out of a
        # narrow window
        self.engines_lbl = tk.Label(
            self, text=t("Ren'Py  ·  RPG Maker  ·  Unity/.NET  ·  Electron/NW.js  ·  "
                         "installers (Inno, NSIS, MSI)  ·  native PE  ·  scripts"),
            font=(FONT, 10), fg=MUTED, bg=BG, anchor="w")
        self.engines_lbl.pack(fill="x", padx=pad, pady=(0, self._px(10)))
        other = "en" if i18n.language() == "tr" else "tr"
        for label, command in ((i18n.LANGUAGES[other], lambda: self._set_language(other)),
                               (t("Settings"), lambda: SettingsDialog(self)),
                               (t("Quarantine"), lambda: QuarantineDialog(self, self.quarantine)),
                               (t("Memory"), lambda: MemoryDialog(self))):
            btn = HoverButton(head, label, command, BG, PANEL2, MUTED)
            btn.configure(padx=10, pady=3, font=(FONT, 9))
            btn.pack(side="right")
        # the right-click menu on the main window, not only in Settings (phageo, 2026-10-24: it was
        # not found there); highlighted while it is not added
        self.menu_btn = HoverButton(head, "", self._header_menu, BG, PANEL2, ACCENT)
        self.menu_btn.configure(padx=10, pady=3, font=(FONT, 9, "bold"))
        self.menu_btn.pack(side="right")
        self._show_header_menu()
        self.shield = None
        if models.EXPERIMENTAL_PROTECTION:        # hidden in 0.9-beta (phageo, 2026-10-24)
            from .protection import ProtectionDialog
            live = self.monitor is not None and self.monitor.running
            shield = HoverButton(head, t("● Protection on") if live else t("○ Protection off"),
                                 lambda: ProtectionDialog(self), BG, PANEL2, OK if live else MUTED)
            shield.configure(padx=10, pady=3, font=(FONT, 9, "bold"))
            shield.pack(side="right")
            self.shield = shield
        tk.Label(head, text="v" + TOOL_VERSION, font=(FONT, 9), fg=SUPP, bg=BG).pack(
            side="right", padx=self._px(8))

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=pad)
        self.scan_btn = HoverButton(row, t("Scan"), self._toggle_scan, ACCENT, ACCENT_HI, "#ffffff", bold=True)
        self.scan_btn.pack(side="right")
        self.file_btn = HoverButton(row, t("File…"), self._pick_file)
        self.file_btn.pack(side="right", padx=(0, self._px(8)))
        self.dir_btn = HoverButton(row, t("Folder…"), self._pick_dir)
        self.dir_btn.pack(side="right", padx=self._px(8))
        self.path_entry = make_entry(row, self.path_var)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=self._px(7))
        self.path_entry.bind("<Return>", lambda e: self._toggle_scan())

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=pad, pady=(self._px(8), 0))
        make_check(row, t("Strict mode – do not trust engine / library file locations"),
                   self.strict_var).pack(side="left")
        self.status = tk.Label(row, text="", font=(FONT, 9), fg=MUTED, bg=BG, anchor="e")
        self.status.pack(side="right", fill="x", expand=True)

        self.bar = SmoothBar(self, height=self._px(4))
        self.bar.pack(fill="x", padx=pad, pady=(self._px(8), self._px(14)))

        cards = tk.Frame(self, bg=BG)
        cards.pack(fill="x", padx=pad)
        self.verdict = tk.Frame(cards, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        self.verdict.pack(side="left", fill="both", expand=True, padx=(0, self._px(10)))
        self.verdict_title = tk.Label(self.verdict, text=t("READY"), font=(FONT, 20, "bold"), fg=MUTED, bg=PANEL)
        self.verdict_title.pack(anchor="w", padx=14, pady=(9, 0))
        # the one sentence a non-technical user needs; empty until a scan finishes
        self.verdict_plain = tk.Label(self.verdict, text="", font=(FONT, 11, "bold"), fg=TEXT,
                                      bg=PANEL, anchor="w")
        self.verdict_plain.pack(anchor="w", fill="x", padx=14)
        self.verdict_sub = tk.Label(self.verdict, text=t("Choose a game folder or file to scan"),
                                    font=(FONT, 9), fg=MUTED, bg=PANEL, anchor="w")
        self.verdict_sub.pack(anchor="w", fill="x", padx=14, pady=(0, 9))
        self.cards = {}
        for sev in reversed(Severity):
            card = Card(cards, i18n.severity(sev, caption=True), SEV_COLOR[sev.name],
                        on_click=lambda s=sev: self._filter_severity(s))
            card.pack(side="left", padx=(0, self._px(10)), ipadx=self._px(14), fill="y")
            self.cards[sev] = card
        self.supp_card = Card(cards, t("Suppressed"), SUPP, on_click=self._toggle_suppressed)
        self.supp_card.pack(side="left", padx=(0, self._px(10)), ipadx=self._px(10), fill="y")
        self.files_card = Card(cards, t("Files scanned"), TEXT)
        self.files_card.pack(side="left", ipadx=self._px(10), fill="y")

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=pad, pady=(self._px(14), self._px(8)))
        tk.Label(row, text=t("Filter"), font=(FONT, 10), fg=MUTED, bg=BG).pack(side="left")
        self.search_entry = make_entry(row, self.search_var, width=34)
        self.search_entry.pack(side="left", padx=self._px(10), ipady=self._px(4))
        make_check(row, t("Show suppressed findings"), self.supp_var, self._refresh).pack(side="left")
        self.count_lbl = tk.Label(row, text="", font=(FONT, 9), fg=MUTED, bg=BG)
        self.count_lbl.pack(side="right")

        foot = tk.Frame(self, bg=BG)
        foot.pack(side="bottom", fill="x", padx=pad, pady=(self._px(10), pad))
        gap = self._px(8)
        self.load_btn = HoverButton(foot, t("Open report…"), self._open_report)
        self.load_btn.pack(side="left")
        self.export_btn = HoverButton(foot, t("Export…"), self._export)
        self.export_btn.pack(side="left", padx=gap)
        self.launch_btn = HoverButton(foot, t("Safe launch…"), self.safe_launch)
        self.launch_btn.pack(side="left")
        self.launch_btn.enable(False)
        self.copy_btn = HoverButton(foot, t("Copy details"), self._copy_details)
        self.copy_btn.pack(side="right")
        self.open_btn = HoverButton(foot, t("Open file location"), self._open_location)
        self.open_btn.pack(side="right", padx=gap)
        self.allow_btn = HoverButton(foot, t("Allowlist this file"), self._allowlist_selected)
        self.allow_btn.pack(side="right")
        self.quar_btn = HoverButton(foot, t("Quarantine file"), self._quarantine_selected,
                                    DANGER, DANGER_HI, "#ffffff")
        self.quar_btn.pack(side="right", padx=gap)
        self.tp_btn = HoverButton(foot, t("Confirm threat"), lambda: self._mark(False))
        self.tp_btn.pack(side="right")
        self.fp_btn = HoverButton(foot, t("False positive"), lambda: self._mark(True))
        self.fp_btn.pack(side="right", padx=gap)
        self._row_buttons = (self.allow_btn, self.open_btn, self.copy_btn, self.quar_btn,
                             self.tp_btn, self.fp_btn)
        for b in (self.export_btn,) + self._row_buttons:
            b.enable(False)
        self.menu = tk.Menu(self, tearoff=0, bg=PANEL2, fg=TEXT, activebackground=LINE,
                            activeforeground=TEXT, bd=0, font=(FONT, 10))
        for label, button in ((t("False positive"), self.fp_btn), (t("Confirm threat"), self.tp_btn),
                              (None, None), (t("Quarantine file"), self.quar_btn),
                              (t("Allowlist this file"), self.allow_btn), (None, None),
                              (t("Open file location"), self.open_btn),
                              (t("Copy details"), self.copy_btn)):
            if label is None:
                self.menu.add_separator()
            else:   # a menu entry does exactly what its button does, including being disabled
                self.menu.add_command(label=label, command=lambda b=button: b._enabled and b.command())

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=pad)
        left = tk.Frame(panes, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        self.tree = ttk.Treeview(left, columns=[c[0] for c in self.COLUMNS], show="headings",
                                 selectmode="browse")
        for cid, _label, width, anchor in self.COLUMNS:
            self.tree.heading(cid, anchor=anchor, command=lambda c=cid: self._sort_by(c))
            self.tree.column(cid, width=self._px(width), minwidth=self._px(50), anchor=anchor,
                             stretch=cid in ("title", "file"))
        self._draw_headings()
        for name, color in SEV_COLOR.items():
            self.tree.tag_configure(name, foreground=color)
        self.tree.tag_configure("suppressed", foreground=SUPP)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_selected())
        self.tree.bind("<Double-1>", lambda e: self._open_location())
        self.tree.bind("<Button-3>", self._popup)
        self.tree.bind("<Configure>", lambda e: self._fit_columns(e.width))
        panes.add(left, weight=5)

        right = tk.Frame(panes, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        self.detail = tk.Text(right, bg=PANEL, fg=TEXT, relief="flat", wrap="word", bd=0,
                              padx=self._px(16), pady=self._px(14), font=(FONT, 10), width=36,
                              highlightthickness=0, cursor="arrow", spacing1=1, spacing3=1)
        dsb = ttk.Scrollbar(right, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dsb.set, state="disabled")
        dsb.pack(side="right", fill="y")
        self.detail.pack(side="left", fill="both", expand=True)
        d = self.detail
        d.tag_configure("h", font=(FONT, 13, "bold"), spacing3=4)
        d.tag_configure("k", font=(FONT, 8, "bold"), foreground=MUTED, spacing1=10)
        d.tag_configure("muted", foreground=MUTED)
        d.tag_configure("mono", font=(MONO, 10), background=BG, lmargin1=8, lmargin2=8,
                        rmargin=8, spacing1=5, spacing3=5, wrap="char")
        d.tag_configure("supp", foreground="#d2a8ff")
        d.tag_configure("quar", foreground=DANGER_HI, font=(FONT, 10, "bold"))
        d.tag_configure("learn", foreground="#7ee0c3")
        for name, color in SEV_COLOR.items():
            d.tag_configure(name, foreground=color, font=(FONT, 10, "bold"))
        panes.add(right, weight=2)

    def _draw_headings(self):
        for cid, label, _, _ in self.COLUMNS:
            arrow = ("  ▾" if self.sort_rev else "  ▴") if cid == self.sort_col else ""
            self.tree.heading(cid, text=t(label) + arrow)

    def _set_language(self, code: str):
        """Switch language: rebuild the widgets, then put the current state back."""
        selected = self._selected()
        i18n.set_language(code)
        i18n.save_language()
        self.settings["language"] = code
        for child in self.winfo_children():
            child.destroy()
        self._build()
        self.files_card.set(self._files_done, snap=True)
        self._refresh(snap=True)
        if self.scanning:
            self._scanning_look()
            self.bar.set(self._progress, snap=True)
            self.status.configure(text=t("Scanning…"))
        elif self.failed:
            self._fail(self.failed)
        elif self.report is not None:
            self._done_look()
        for i, f in enumerate(self._rows):
            if f is selected:
                self.tree.selection_set(str(i))
                self.tree.see(str(i))
                break
        else:
            if not self.failed:
                self._show_welcome(t("Scanning… findings appear here as they are discovered.")
                                   if self.scanning else None)

    # -- scanning --------------------------------------------------------------
    def _pick_dir(self):
        path = filedialog.askdirectory(title=t("Choose a game folder"))
        if path:
            self.path_var.set(os.path.normpath(path))
            self._toggle_scan()

    def _pick_file(self):
        path = filedialog.askopenfilename(title=t("Choose a file to scan"))
        if path:
            self.path_var.set(os.path.normpath(path))
            self._toggle_scan()

    def scan_clicked(self, path: str):
        """The right-click "Scan" (0.9-beta final polish, phageo 2026-10-25): a program stands for
        its game, so its folder is scanned as Safe launch finds it; an installer or archive is
        scanned as itself (``launcher.scan_target``). The window says which it was."""
        path = os.path.abspath(path)
        target, why = launcher.scan_target(path)
        note = None
        if why == launcher.GAME_FOLDER:
            note = t("Scanned: the game folder of %s", os.path.basename(path))
        elif why == launcher.STANDALONE:
            note = t("Scanned: only %s (an installer or archive)", os.path.basename(path))
        self.path_var.set(target)
        self._toggle_scan(note, path if why == launcher.GAME_FOLDER else None)

    def _toggle_scan(self, note: Optional[str] = None, program: Optional[str] = None):
        if self.scanning:
            self.cancel.set()
            self.status.configure(text=t("Cancelling…"))
            return
        self._scan_note, self._clicked_program = note, program
        target = self.path_var.get().strip().strip('"')
        if not target:
            self._pick_dir()
            return
        if not os.path.exists(target):
            messagebox.showerror(TOOL_NAME, t("This path does not exist:\n\n%s", target))
            return
        self._start_scan([target])

    def scan_quick(self):
        self._start_scan(system.quick_scan_targets(), t("Quick scan"))

    def scan_system(self):
        entries = system.startup_entries()
        self._start_scan(system.system_scan_targets(), t("Startup items and running programs"),
                         system.autorun_findings(entries))

    def scan_full(self):
        self._start_scan(system.fixed_drives(), t("Full scan"))

    def _start_scan(self, targets: List[str], label: Optional[str] = None,
                    extra: Optional[List[Finding]] = None):
        if self.scanning:
            return
        self._prepare_scan(label)
        self._thread = threading.Thread(target=self._worker, daemon=True,
                                        args=(targets, label, extra, self.strict_var.get(),
                                              dict(self.settings)))
        self._thread.start()

    def _prepare_scan(self, label: Optional[str]):
        self._scan_label = label
        self.scanning, self.report, self.failed = True, None, None
        self.cancel.clear()
        self.findings.clear()
        self.sev_filter, self._files_done, self._progress = None, 0, 0.0
        self._scanning_look()
        self.bar.set(0.0, snap=True)
        self.status.configure(text=t("Listing files…"))
        self._refresh()
        self._show_welcome(t("Scanning… findings appear here as they are discovered."))

    # -- the secure launcher in the window (packaging session 3, phageo) ------------------------
    def _launchable(self) -> bool:
        """After a scan of one folder or program (not a PC-wide scan)."""
        target = self.path_var.get().strip().strip('"')
        return (self.report is not None and not self.scanning and self._scan_label is None
                and bool(target) and os.path.exists(target))

    def _launch_target(self) -> Optional[str]:
        target = self.path_var.get().strip().strip('"')
        program = self._clicked_program                    # the program whose folder "Scan" scanned
        if program and os.path.isfile(program) and \
                os.path.normcase(os.path.dirname(program)) == os.path.normcase(os.path.abspath(target)):
            return program
        if os.path.isdir(target):
            path = filedialog.askopenfilename(parent=self, initialdir=target,
                                              title=t("Choose the game's program to start"),
                                              filetypes=[(t("Programs"), "*.exe")])
            return os.path.normpath(path) if path else None
        return target or None

    def safe_launch(self, executable: Optional[str] = None):
        """The secure launcher (``launcher.secure_launch``) with the window's dialogs: the
        program's folder is scanned again the launcher's way (nothing of the profile can hide
        a finding), then the game is started, asked about, or refused - as on the command line."""
        if self.scanning:
            return
        executable = executable or self._launch_target()
        if not executable:
            return
        self._scan_note = None
        if not os.path.isfile(executable) or not executable.lower().endswith(".exe"):
            messagebox.showerror(TOOL_NAME, t("Only a program (.exe) can be started:\n\n%s", executable),
                                 parent=self)
            return
        self._prepare_scan(t("Safe launch: %s", os.path.basename(executable)))
        self._thread = threading.Thread(target=self._launch_worker, daemon=True,
                                        args=(executable, self.strict_var.get(), dict(self.settings)))
        self._thread.start()

    def _launch_worker(self, executable: str, strict: bool, cfg: dict):
        lines: List[str] = []
        try:
            scanner = launcher.launch_scanner(cfg, yara=cfg.get("yara_dir") or None, strict=strict)
            code = launcher.secure_launch(
                executable, scanner, out=lines.append, ask=lambda prompt: self._ask_ui(prompt, lines),
                show=lambda report: self.q.put(("done", report)), cancel=self.cancel,
                progress=lambda d, n, r: self.q.put(("progress", d, n, r)))
            self.q.put(("launched", code, list(lines)))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    def _ask_ui(self, prompt: str, lines: List[str]) -> Optional[str]:
        """The launcher's question, asked on the window's thread; the worker waits for it."""
        box: dict = {"answer": ""}
        done = threading.Event()
        self.q.put(("ask", prompt, list(lines), box, done))
        done.wait()
        return box["answer"]

    def _answer(self, prompt: str, lines: List[str], box: dict, done: threading.Event):
        text = launcher.dialog_text("\n".join(line for line in lines if line.strip()))
        try:
            if prompt == launcher.word_prompt():                  # SUSPICIOUS: the typed word
                box["answer"] = simpledialog.askstring(TOOL_NAME, text + "\n\n" + prompt,
                                                       parent=self) or ""
            else:                                                 # REVIEW / not all of it read
                yes = messagebox.askyesno(TOOL_NAME, text + "\n\n" + t("Start the game anyway?"),
                                          default=messagebox.NO, parent=self)
                box["answer"] = "y" if yes else "n"
        finally:
            done.set()

    def _launched(self, code: int, lines: List[str]):
        if self.scanning:                       # stopped before its scan (file missing / unreadable)
            self.scanning = False
            self.scan_btn.restyle(t("Scan"), ACCENT, ACCENT_HI)
            for b in (self.dir_btn, self.file_btn, self.load_btn):
                b.enable(True)
        said = [launcher.dialog_text(line) for line in lines if line.strip()]
        if said:
            self.status.configure(text=said[-1].strip())
        self._scan_label = None                 # the folder may be launched again
        self.launch_btn.enable(self._launchable())
        (messagebox.showinfo if code == 0 else messagebox.showwarning)(
            TOOL_NAME, "\n".join(said[-12:]) or t("The game was not started."), parent=self)

    def _scanning_look(self):
        self.scan_btn.restyle(t("Cancel"), DANGER, DANGER_HI)
        for b in (self.dir_btn, self.file_btn, self.export_btn, self.load_btn, self.launch_btn):
            b.enable(False)
        self.bar.set(self._progress, ACCENT)
        self.verdict_title.configure(text=t("SCANNING"), fg=ACCENT_HI)
        self.verdict_plain.configure(text="")
        sub = self._scan_label or self.path_var.get()
        if self._scan_note and not self._scan_label:
            sub = self._scan_note + "  ·  " + sub
        self.verdict_sub.configure(text=sub)
        self.verdict.configure(highlightbackground=LINE)

    def _worker(self, targets: List[str], label: Optional[str], extra, strict: bool, cfg: dict):
        try:
            scanner = self._make_scanner(cfg, strict)
            report = scanner.scan(
                targets if label else targets[0], cancel=self.cancel, label=label, extra=extra,
                progress=lambda d, n, r: self.q.put(("progress", d, n, r)),
                on_findings=lambda fs: self.q.put(("findings", fs)))
            self.q.put(("done", report))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    def _pump(self):
        """Drain worker messages; runs on the UI thread every 30 ms."""
        progress = None
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "progress":
                    progress = msg
                elif msg[0] == "findings":
                    self.findings.extend(msg[1])
                    self._dirty = True
                elif msg[0] == "done":
                    self._finish(msg[1])
                elif msg[0] == "error":
                    self.scanning, self.failed = False, msg[1]
                    self._fail(msg[1])
                elif msg[0] == "ask":
                    self._answer(*msg[1:])
                elif msg[0] == "launched":
                    self._launched(msg[1], msg[2])
                elif msg[0] == "realtime":
                    self._realtime_result(msg[1], msg[2])
        except queue.Empty:
            pass
        if progress and self.scanning:
            _, done, total, rel = progress
            self._progress = done / max(1, total)
            self.bar.set(self._progress)
            shown = rel if len(rel) < 70 else "…" + rel[-68:]
            self.status.configure(text="{:,} / {:,}   {}".format(done, total, shown))
            if not rel.startswith(("VirusTotal", "Windows Defender")):
                self._files_done = done
                self.files_card.set(done)
        if self._dirty and time.time() - self._last_refresh > 0.35:
            self._refresh()
        self.after(30, self._pump)

    def _realtime_result(self, path: str, report: ScanReport):
        """A file appeared in a watched folder and was scanned in the background."""
        worst = report.max_severity
        action = "quarantined" if report.quarantined else ""
        self.rt_events.append((time.time(), path, report.verdict, action))
        del self.rt_events[:-200]
        if worst is not None and worst >= Severity.HIGH:
            from .protection import ThreatAlert
            open_alerts = [w for w in self.winfo_children() if isinstance(w, ThreatAlert)]
            if len(open_alerts) < 4:              # a burst of detections must not bury the screen
                ThreatAlert(self, path, report)

    def _finish(self, report: ScanReport):
        self.scanning, self.report = False, report
        self.findings = list(report.findings)
        self._files_done = report.files_scanned
        self.files_card.set(report.files_scanned)
        self._refresh()
        self._done_look()
        if self._rows:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
        else:
            self._show_welcome()

    def _done_look(self):
        report = self.report
        self.scan_btn.restyle(t("Scan"), ACCENT, ACCENT_HI)
        for b in (self.dir_btn, self.file_btn, self.export_btn, self.load_btn):
            b.enable(True)
        self.launch_btn.enable(self._launchable())
        text = t("%s files inspected, %s not applicable  ·  %.1fs",
                 "{:,}".format(report.files_scanned), "{:,}".format(report.files_skipped),
                 report.duration)
        if report.cancelled:
            text = t("Cancelled  ·  ") + text
        if report.errors:
            text += t("  ·  %d read error(s)", len(report.errors))
        if report.quarantined:
            text += t("  ·  %d file(s) quarantined", len(report.quarantined))
        fresh = sum(1 for f in report.active if f.is_new)
        if fresh:
            text += t("  ·  %d new since last scan", fresh)
        if self._scan_note and not self._scan_label:      # what the right-click "Scan" scanned
            text = self._scan_note + "  ·  " + text
        self.status.configure(text=text)
        self._update_verdict()

    def _fail(self, trace: str):
        self.scan_btn.restyle(t("Scan"), ACCENT, ACCENT_HI)
        for b in (self.dir_btn, self.file_btn, self.load_btn):
            b.enable(True)
        self.verdict_title.configure(text=t("ERROR"), fg=SEV_COLOR["CRITICAL"])
        self.verdict_plain.configure(text="")
        self.verdict_sub.configure(text=t("The scan stopped unexpectedly"))
        self.status.configure(text="")
        self._set_detail([(t("Scan failed\n"), "h"), (trace, "mono")])

    def _update_verdict(self):
        report = self.report
        if report is None:
            return
        color = VERDICT_COLOR[report.verdict]
        name, detail = i18n.verdict(report)
        self.verdict_title.configure(text=name, fg=color)
        self.verdict_plain.configure(text=i18n.plain_verdict(report), fg=TEXT)
        engines = ", ".join(report.engines) or t("no known engine detected")
        self.verdict_sub.configure(text=t("%s  ·  risk %d/100  ·  %s", detail,
                                          report.risk_score, engines))
        self.verdict.configure(highlightbackground=color)
        self.bar.set(1.0, color)

    # -- table -----------------------------------------------------------------
    def _visible(self) -> List[Finding]:
        needle = self.search_var.get().strip().lower()
        out = []
        for f in self.findings:
            if f.suppressed and not self.supp_var.get():
                continue
            if self.sev_filter is not None and f.severity is not self.sev_filter:
                continue
            if needle and needle not in " ".join(
                    (f.title, i18n.title(f), f.file, f.rule_id, f.category.value,
                     i18n.category(f.category), f.evidence, f.severity.name,
                     i18n.severity(f.severity))).lower():
                continue
            out.append(f)
        keys = {"sev": lambda f: f.severity, "cat": lambda f: i18n.category(f.category),
                "title": lambda f: i18n.title(f).lower(), "file": lambda f: f.file.lower(),
                "line": lambda f: f.line or 0, "conf": lambda f: f.confidence}
        out.sort(key=lambda f: (f.suppressed, -f.severity, -f.confidence, f.file, f.line or 0))
        if self.sort_col:
            out.sort(key=keys[self.sort_col], reverse=self.sort_rev)
        return out

    def _refresh(self, snap: bool = False):
        self._dirty, self._last_refresh = False, time.time()
        selected = self._selected()
        rows = self._visible()
        self._rows = rows[:MAX_ROWS]
        self.tree.delete(*self.tree.get_children())
        for i, f in enumerate(self._rows):
            mark = "○ " if f.suppressed else "● "
            self.tree.insert("", "end", iid=str(i), tags=("suppressed" if f.suppressed else f.severity.name,),
                             values=(mark + i18n.severity(f.severity), i18n.category(f.category),
                                     (t("NEW · ") if f.is_new else "") + i18n.title(f),
                                     f.file, f.line or "",
                                     "%d%%" % round(f.confidence * 100)))
        if selected is not None:
            for i, f in enumerate(self._rows):
                if f is selected:
                    self.tree.selection_set(str(i))
                    self.tree.see(str(i))
                    break
        active = [f for f in self.findings if not f.suppressed]
        for sev, card in self.cards.items():
            card.set(sum(1 for f in active if f.severity is sev), snap)
            card.set_active(self.sev_filter is sev)
        self.supp_card.set(len(self.findings) - len(active), snap)
        self.supp_card.set_active(self.supp_var.get())
        text = t("%s of %s findings shown", "{:,}".format(len(self._rows)),
                 "{:,}".format(len(self.findings)))
        if len(rows) > MAX_ROWS:
            text += t("  (first %s shown)", "{:,}".format(MAX_ROWS))
        self.count_lbl.configure(text=text)

    def _debounced_refresh(self):
        if self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(160, self._refresh)

    def _sort_by(self, col: str):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = col, col in ("sev", "conf")
        self._draw_headings()
        self._refresh()

    def _filter_severity(self, sev: Severity):
        self.sev_filter = None if self.sev_filter is sev else sev
        self._refresh()

    def _toggle_suppressed(self):
        self.supp_var.set(not self.supp_var.get())
        self._refresh()

    def _selected(self) -> Optional[Finding]:
        sel = self.tree.selection()
        if sel and int(sel[0]) < len(self._rows):
            return self._rows[int(sel[0])]
        return None

    # -- detail pane -----------------------------------------------------------
    def _set_detail(self, parts):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        for text, tag in parts:
            self.detail.insert("end", text, tag)
        self.detail.configure(state="disabled")

    def _show_welcome(self, message: Optional[str] = None):
        for b in self._row_buttons:
            b.enable(False)
        if message:
            self._set_detail([(message, "muted")])
        elif self.report is not None:
            hidden = len(self.report.suppressed)
            parts = [
                (t("No active findings\n"), "h"),
                (t("Nothing in this scan needs your attention.\n\n"), "muted"),
                (t("%d finding(s) were suppressed as false positives. Tick “Show suppressed "
                   "findings” to see each one and why it was suppressed.", hidden) if hidden else
                 t("No rule matched any inspected file."), "muted")]
            if self.report.notes:
                parts += [(t("\nNOTES\n"), "k"), ("\n".join(self.report.notes), "muted")]
            self._set_detail(parts)
        else:
            self._set_detail([
                (t("How it works\n"), "h"),
                (t("Pick a game folder (or a single file) and press Scan. Nothing is executed; "
                   "files are only read.\n"), "muted"),
                (t("\nWHAT IS CHECKED\n"), "k"),
                (t("Dynamic code execution, encoded payloads, process spawning, network use, "
                   "file tampering, persistence, credential access, input capture, packed "
                   "binaries, and attack chains that combine them.\n"), ""),
                (t("\nFALSE POSITIVES\n"), "k"),
                (t("Engine files, comments, benign domains, save-data encoding and similar "
                   "known-good patterns are suppressed. Suppressed findings are kept, with "
                   "the reason, and can be shown at any time.\n"), ""),
                (t("\nLEARNING\n"), "k"),
                (t("Mark a finding as a false positive or a confirmed threat (buttons below, or "
                   "right-click). The scanner remembers your decisions and adjusts how much it "
                   "trusts each rule.\n"), ""),
                (t("\nLIMITS\n"), "k"),
                (t("This is static triage, not an antivirus. A clean result lowers the risk; "
                   "it does not prove a game is safe.\n"), "muted"),
                (t("\nSHORTCUTS\n"), "k"),
                (t("F5 scan  ·  Ctrl+O open report  ·  Ctrl+E export  ·  Ctrl+F filter  "
                   "·  Esc clear filters"), "muted")])

    def _show_selected(self):
        f = self._selected()
        if f is None:
            return
        on_disk = bool(f.path) and "!" not in f.file and not f.quarantined
        # A report opened from a file is somebody's claim about a scan, not
        # something this app observed: it may not teach the scanner or add to
        # the allowlist. (Quarantine re-checks the file's hash before acting.)
        live = not (self.report is not None and self.report.loaded)
        self.allow_btn.enable(bool(f.sha256) and not self.scanning and live)
        self.quar_btn.enable(on_disk and not f.suppressed and not self.scanning)
        self.open_btn.enable(bool(f.path))
        self.copy_btn.enable(True)
        can_learn = self.memory is not None and not self.scanning and live
        resolved = f.suppressed and f.suppression_reason == RESOLVED_FP
        self.fp_btn.enable(can_learn and not f.suppressed)
        self.tp_btn.enable(can_learn and (resolved or (not f.suppressed and f.learned != "confirmed")))
        where = f.file + (t("  :  line %d", f.line) if f.line else "")
        evidence = i18n.evidence(f)
        parts = [(i18n.title(f) + "\n", "h"),
                 ("● " + i18n.severity(f.severity), f.severity.name),
                 (t("   %s   ·   %d%% confidence   ·   %s\n", i18n.category(f.category),
                    round(f.confidence * 100), f.rule_id), "muted")]
        notes = []
        if f.is_new:
            notes.append(t("New since the last scan of this target."))
        if f.learned == "confirmed":
            notes.append(t("You confirmed this as a real threat."))
        elif f.learned and f.base_confidence is not None:
            wrong, right = (int(n) for n in f.learned.split("/"))
            notes.append(t("Confidence adjusted from %d%% by past feedback on this rule: "
                           "%d false positive(s), %d confirmed.", round(f.base_confidence * 100),
                           wrong, right))
        if self.memory is not None:
            try:
                seen, scans = self.memory.times_seen(fingerprint(f))
            except Exception:
                seen = scans = 0
            if scans > 1:
                notes.append(t("This exact code was seen %d times across %d scans.", seen, scans))
        if notes:
            parts.append(("\n" + "\n".join(notes) + "\n", "learn"))
        if f.quarantined:
            parts += [(t("\nThis file has been moved to quarantine.\n"), "quar")]
        if f.suppressed:
            parts += [(t("\nSUPPRESSED – NOT COUNTED\n"), "k"), (i18n.suppression(f) + "\n", "supp")]
        parts += [(t("\nWHAT DOES THIS MEAN\n"), "k"), (i18n.reason(f) + "\n", ""),
                  (t("\nWHAT SHOULD I DO\n"), "k"), (i18n.advice(f) + "\n", ""),
                  (t("\nLOCATION\n"), "k"), (where + "\n", ""),
                  (t("\nMATCHED EVIDENCE\n"), "k"), (evidence + "\n", "mono")]
        if f.snippet and f.snippet != f.evidence:
            parts += [(t("\nSNIPPET\n"), "k"), (f.snippet + "\n", "mono")]
        parts += [(t("\nSHA-256\n"), "k"), ((f.sha256 or t("n/a")) + "\n", "muted"),
                  (t("\nHANDLER\n"), "k"), (f.handler, "muted")]
        self._set_detail(parts)

    # -- reports ---------------------------------------------------------------
    def _filter_note(self) -> str:
        """Human description of the active filters, printed on exports."""
        parts = []
        if self.sev_filter is not None:
            parts.append(t("severity: %s", i18n.severity(self.sev_filter)))
        if self.search_var.get().strip():
            parts.append(t("text: %s", self.search_var.get().strip()))
        if self.supp_var.get():
            parts.append(t("including suppressed"))
        return ", ".join(parts)

    def _export(self):
        if self.report is None:
            return
        name = "scan-report-%s" % time.strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            title=t("Export report"), defaultextension=".pdf", initialfile=name,
            filetypes=[(t("PDF document"), "*.pdf"), (t("HTML page"), "*.html"),
                       (t("JSON data (complete report)"), "*.json")])
        if not path:
            return
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext == ".json":
                self.report.save(path)
            elif ext in (".html", ".htm"):
                export.export_html(self.report, self._visible(), path, self._filter_note())
            else:
                export.export_pdf(self.report, self._visible(), path, self._filter_note())
        except (OSError, ValueError) as exc:
            messagebox.showerror(TOOL_NAME, t("Could not save the report:\n\n%s", exc))
            return
        self.status.configure(text=t("Report saved to %s", path))

    def _open_report(self):
        if self.scanning:
            return
        path = filedialog.askopenfilename(title=t("Open a saved JSON report"),
                                          filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            report = ScanReport.load(path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            messagebox.showerror(TOOL_NAME, t("This file is not a scan report:\n\n%s", exc))
            return
        self.failed, self.sev_filter = None, None
        self._scan_note = self._clicked_program = None
        self.path_var.set(report.target)
        self._finish(report)
        self.status.configure(text=t("Loaded report %s", os.path.basename(path)))

    # -- actions ---------------------------------------------------------------
    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._show_selected()
            self.menu.tk_popup(event.x_root, event.y_root)

    @staticmethod
    def _sha256_of(path: str) -> str:
        import hashlib
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(block)
        except OSError:
            return ""
        return digest.hexdigest()

    def _mark(self, false_positive: bool):
        """Feedback loop: remember the user's resolution and apply it right away."""
        f = self._selected()
        if f is None or self.memory is None or self.scanning or (self.report and self.report.loaded):
            return
        try:
            self.context.learn(f, false_positive)
        except Exception as exc:
            messagebox.showerror(TOOL_NAME, t("The memory center could not be updated:\n\n%s", exc))
            return
        key = fingerprint(f)
        for other in self.findings:               # the same code elsewhere in this scan
            if fingerprint(other) != key:
                continue
            if false_positive:
                if not other.suppressed:
                    other.suppress(RESOLVED_FP)
            else:
                if other.suppressed and other.suppression_reason == RESOLVED_FP:
                    other.suppressed, other.suppression_reason = False, ""
                if other.base_confidence is None:
                    other.base_confidence = other.confidence
                other.confidence, other.learned = max(other.confidence, 0.9), "confirmed"
        self._refresh()
        self._update_verdict()
        self._show_selected() if self._selected() else self._show_welcome()
        self.status.configure(text=t("Remembered as a false positive") if false_positive
                              else t("Remembered as a confirmed threat"))

    def _quarantine_selected(self):
        f = self._selected()
        if f is None or self.scanning or not f.path or "!" in f.file:
            return
        # Act only on the file that was actually scanned: the path must still
        # hold the same bytes. This also stops a crafted report file from
        # pointing "Quarantine" at an unrelated document.
        if not f.sha256 or self._sha256_of(f.path) != f.sha256.lower():
            messagebox.showerror(TOOL_NAME, t(
                "The file at this location is not the file that was scanned (it has changed, "
                "is gone, or the report does not belong to this PC). Nothing was done.\n\n%s",
                f.path))
            return
        if not messagebox.askyesno(
                TOOL_NAME, t("Move this file to quarantine?\n\n%s\n\nIt is taken out of the game "
                             "folder and scrambled so it cannot run. You can restore it later "
                             "from the Quarantine window.", f.path)):
            return
        same = [o for o in self.findings if o.path == f.path and "!" not in o.file]
        try:
            entry = self.quarantine.isolate(
                f.path, (o.rule_id for o in same if not o.suppressed),
                max(o.severity for o in same).name)
        except QuarantineError as exc:
            messagebox.showerror(TOOL_NAME, t("The file could not be quarantined:\n\n%s", exc))
            return
        for other in same:
            other.quarantined = True
            if not other.suppressed and self.memory is not None:
                self.context.learn(other, False, "quarantine")    # isolating it = "this is real"
        if self.report is not None:
            self.report.quarantined.append(entry)
        self._show_selected()
        self.status.configure(text=t("Moved to quarantine: %s", f.file))

    def _allowlist_selected(self):
        f = self._selected()
        if f is None or not f.sha256 or self.scanning or (self.report and self.report.loaded):
            return
        if not messagebox.askyesno(
                TOOL_NAME, t("Trust this exact file?\n\n%s\n\nAll of its findings will be suppressed in "
                             "this and future scans. If the file changes in any way, it is checked "
                             "again.", f.file)):
            return
        self.allowlist.add(f.sha256, f.file)
        try:
            self.allowlist.save()
        except OSError as exc:
            messagebox.showwarning(TOOL_NAME, t("The allowlist could not be saved:\n\n%s", exc))
        for other in self.findings:
            if other.sha256 == f.sha256 and not other.suppressed:
                if self.memory is not None:       # trusting the file = "these were false alarms"
                    self.context.learn(other, True, "allowlist", 0.7)
                other.suppress("File SHA-256 is on the allowlist")
        self._refresh()
        self._update_verdict()
        self._show_selected() if self._selected() else self._show_welcome()

    def _open_location(self):
        f = self._selected()
        if f is None or not f.path:
            return
        folder = f.path if os.path.isdir(f.path) else os.path.dirname(f.path)
        # never open a network path taken from a report (it would hand this
        # account's Windows credentials to that server), nor a missing folder
        if folder.startswith(("\\\\", "//")) or not os.path.isdir(folder):
            return
        try:
            if sys.platform == "win32":
                os.startfile(folder)
            else:
                import webbrowser
                webbrowser.open("file://" + folder)
        except OSError as exc:
            messagebox.showerror(TOOL_NAME, t("Could not open the folder:\n\n%s", exc))

    def _copy_details(self):
        text = self.detail.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.configure(text=t("Details copied to clipboard"))


def main(initial_path: Optional[str] = None, launch: bool = False) -> int:
    """The window; with a path it scans that path at once, and with ``launch`` (the right-click
    "Safe launch") it runs the secure launcher on that program instead."""
    if sys.platform == "win32":
        try:                                  # crisp text on high-DPI displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        try:                                  # the taskbar shows Bagel's icon, not Python's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except (AttributeError, OSError):
            pass
    app = App()
    app.after(100, app._startup_checks)
    if initial_path and launch:
        path = os.path.abspath(initial_path)
        app.path_var.set(path)
        app.after(200, lambda: app.safe_launch(path))
    elif initial_path:
        app.after(200, lambda: app.scan_clicked(initial_path))
    app.mainloop()
    return 0
