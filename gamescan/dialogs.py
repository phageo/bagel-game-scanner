"""Modal windows: settings, memory and the quarantine manager."""
from __future__ import annotations

import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import i18n, settings as settings_store, shellmenu
from .context import TRUSTED_PUBLISHERS, ContextEngine
from .i18n import t
from .models import TOOL_NAME, Severity
from .quarantine import Quarantine, QuarantineError
from .rules import DEFAULT_RULES
from .widgets import (ACCENT, ACCENT_HI, BG, DANGER, DANGER_HI, FONT, LINE, MUTED, PANEL,
                      TEXT, HoverButton, make_check, make_entry)
from .yara import YaraRuleSet


class _Dialog(tk.Toplevel):
    def __init__(self, app, title: str) -> None:
        super().__init__(app)
        self.app = app
        self.title(title)
        self.configure(bg=BG)
        self.transient(app)
        self.resizable(False, False)
        self.bind("<Escape>", lambda e: self.destroy())

    def show(self) -> None:
        self.update_idletasks()
        x = self.app.winfo_rootx() + (self.app.winfo_width() - self.winfo_width()) // 2
        y = self.app.winfo_rooty() + (self.app.winfo_height() - self.winfo_height()) // 3
        self.geometry("+%d+%d" % (max(0, x), max(0, y)))
        self.grab_set()
        self.focus_set()

    def heading(self, parent, text: str) -> None:
        tk.Label(parent, text=text, font=(FONT, 11, "bold"), fg=TEXT, bg=BG).pack(
            anchor="w", pady=(self.app._px(14), self.app._px(4)))

    def hint(self, parent, text: str) -> tk.Label:
        lbl = tk.Label(parent, text=text, font=(FONT, 9), fg=MUTED, bg=BG, justify="left",
                       anchor="w", wraplength=self.app._px(520))
        lbl.pack(anchor="w", fill="x", pady=(self.app._px(2), 0))
        return lbl


class SettingsDialog(_Dialog):
    def __init__(self, app) -> None:
        super().__init__(app, t("Settings"))
        px, s = app._px, app.settings
        outer = tk.Frame(self, bg=BG)
        outer.pack(padx=px(22), pady=(px(8), px(18)))
        # two columns: one tall column no longer fits on a laptop screen
        columns = tk.Frame(outer, bg=BG)
        columns.pack()
        left = tk.Frame(columns, bg=BG)
        left.pack(side="left", anchor="n")
        right = tk.Frame(columns, bg=BG)
        right.pack(side="left", anchor="n", padx=(px(30), 0))
        body = left

        self.yara_var = tk.StringVar(value=s["yara_dir"])
        self.vt_on = tk.BooleanVar(value=bool(s["vt_enabled"]))
        self.vt_key = tk.StringVar(value=s["vt_api_key"])
        self.vt_max = tk.StringVar(value=str(s["vt_max_lookups"]))
        self.auto_q = tk.BooleanVar(value=bool(s["auto_quarantine"]))
        self.mem_on = tk.BooleanVar(value=bool(s.get("memory_enabled", True)))
        self.abuse_key = tk.StringVar(value=s.get("abusech_key", ""))
        self.amsi_on = tk.BooleanVar(value=bool(s.get("amsi_enabled", True)))
        self.defender_on = tk.BooleanVar(value=bool(s.get("defender_scan", False)))
        self.vt_age = tk.StringVar(value=str(s.get("vt_min_age_days", 30)))
        self.publishers = tk.StringVar(value=", ".join(
            s.get("trusted_publishers") or TRUSTED_PUBLISHERS))

        self.heading(body, t("YARA signatures"))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x")
        HoverButton(row, t("Browse…"), self._browse).pack(side="right", padx=(px(8), 0))
        make_entry(row, self.yara_var, width=52).pack(side="left", fill="x", expand=True, ipady=px(5))
        self.yara_info = self.hint(body, "")
        self.yara_var.trace_add("write", lambda *a: self._count_rules())
        self._count_rules()

        self.heading(body, t("Windows Defender"))
        make_check(body, t("Show unpacked content to the Windows antimalware engine (AMSI)"),
                   self.amsi_on).pack(anchor="w")
        make_check(body, t("Also let Windows Defender scan the game folder (detect only)"),
                   self.defender_on).pack(anchor="w")
        self.hint(body, t("Defender cannot see code hidden inside archives and compiled "
                          "scripts; the scanner unpacks it and shows it to Defender. Defender "
                          "is never allowed to remove anything, and a detection may appear in "
                          "Windows Security's history."))

        self.heading(body, t("VirusTotal"))
        make_check(body, t("Check executables on VirusTotal after each scan"), self.vt_on).pack(anchor="w")
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(6), 0))
        tk.Label(row, text=t("API key"), font=(FONT, 10), fg=MUTED, bg=BG).pack(side="left")
        make_entry(row, self.vt_key, show="•", width=46).pack(side="left", padx=px(10), ipady=px(5))
        tk.Label(row, text=t("Max. lookups"), font=(FONT, 10), fg=MUTED, bg=BG).pack(side="left")
        make_entry(row, self.vt_max, width=5).pack(side="left", padx=(px(10), 0), ipady=px(5))
        self.hint(body, t("Only the SHA-256 hash of each program is sent, never the file. "
                          "The free API allows 4 lookups per minute, so each new file adds "
                          "about 15 seconds. The key is stored unencrypted in your user profile."))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(6), 0))
        tk.Label(row, text=t("Trust a clean result only after (days)"), font=(FONT, 10),
                 fg=MUTED, bg=BG).pack(side="left")
        make_entry(row, self.vt_age, width=5).pack(side="left", padx=px(10), ipady=px(5))

        body = right
        self.heading(body, t("Trusted publishers"))
        make_entry(body, self.publishers, width=60).pack(fill="x", ipady=px(5))
        self.hint(body, t("Programs validly signed by these publishers are treated like engine "
                          "files. Any other valid signature only lowers a finding by one level. "
                          "Separate names with commas."))

        self.heading(body, t("Known-malware database"))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x")
        tk.Label(row, text=t("abuse.ch Auth-Key"), font=(FONT, 10), fg=MUTED, bg=BG).pack(side="left")
        make_entry(row, self.abuse_key, show="•", width=44).pack(side="left", padx=px(10), ipady=px(5))
        self.hint(body, t("Needed to download the known-malware hash list. The key is free at "
                          "https://auth.abuse.ch/ and is stored unencrypted in your user profile."))

        self.heading(body, t("Quarantine"))
        make_check(body, t("Automatically quarantine files with HIGH or CRITICAL findings"),
                   self.auto_q).pack(anchor="w")
        self.hint(body, t("Quarantined files are moved out of the game folder and scrambled so "
                          "they cannot run. The game may stop working until you restore them "
                          "from the Quarantine window."))

        self.heading(body, t("Memory"))
        make_check(body, t("Remember scans and learn from my feedback"), self.mem_on).pack(anchor="w")
        self.hint(body, t("Scan results, including the code snippets they contain, are kept in "
                          "a local database on this PC. Nothing is uploaded."))

        self.heading(body, t("Explorer right-click menu"))
        self.menu_button = HoverButton(body, "", self._toggle_menu)
        self.menu_button.pack(anchor="w")
        self.menu_info = self.hint(body, "")
        self._show_menu_state()

        row = tk.Frame(outer, bg=BG)
        row.pack(fill="x", pady=(px(20), 0))
        HoverButton(row, t("Save"), self._save, ACCENT, ACCENT_HI, "#ffffff", bold=True).pack(side="right")
        HoverButton(row, t("Cancel"), self.destroy).pack(side="right", padx=px(8))
        self.show()

    def _menu_state(self):
        """``(added, points here)``; ``None`` when the menu cannot be used here, ``"all"`` when an
        installation "for all users" added it (removed only by uninstalling)."""
        try:
            added, here, _found = shellmenu.state()
            if not added and shellmenu.machine_wide():
                return "all"
            return added, here
        except (shellmenu.MenuError, OSError):
            return None

    def _show_menu_state(self) -> None:
        state = self._menu_state()
        text = t("Adds one entry “Bagel” to the right-click menu, for your Windows account only (no "
                 "administrator rights): “Scan” on folders and files, and also “Safe launch” on "
                 "programs (.exe). Scan opens this window and scans what you clicked - for a "
                 "program, its game folder; Safe launch scans the program's folder first and then "
                 "starts the game, asks you, or refuses. On Windows 11 it is under “Show more "
                 "options”. Removing it leaves nothing behind.")
        if state is None or state == "all":
            self.menu_button.configure(text=t("Add to the right-click menu") if state is None
                                       else t("Right-click menu: on"))
            self.menu_button.enable(False)
            self.menu_info.configure(text=text + "\n" + t("Not available on this computer.") if state is None
                                     else t("The right-click menu was added for all users when Bagel "
                                            "was installed. It is removed when Bagel is uninstalled."))
            return
        added, here = state
        self.menu_button.configure(text=t("Remove from the right-click menu") if added
                                   else t("Add to the right-click menu"))
        if added and not here:
            text += "\n" + t("It now opens another copy of Bagel. Remove it and add "
                             "it again to use this copy.")
        elif added:
            text += "\n" + t("It is on.")
        self.menu_info.configure(text=text)

    def _toggle_menu(self) -> None:
        state = self._menu_state()
        if state is None or state == "all":
            return
        try:
            if state[0]:
                shellmenu.remove()
            else:
                shellmenu.add(t("Scan"), launch_label=t("Safe launch"))
        except (shellmenu.MenuError, OSError) as exc:
            messagebox.showerror(TOOL_NAME, t("The right-click menu could not be changed:\n\n%s", exc),
                                 parent=self)
        self._show_menu_state()
        refresh = getattr(self.app, "_show_header_menu", None)     # the main window's button
        if refresh is not None:
            refresh()

    def _browse(self) -> None:
        path = filedialog.askdirectory(parent=self, title=t("Choose the folder with YARA rules"))
        if path:
            self.yara_var.set(os.path.normpath(path))

    def _count_rules(self) -> None:
        path = self.yara_var.get().strip()
        rules = YaraRuleSet()
        if os.path.isdir(path):
            rules.load(path)
        text = t("%d signature(s) will be used, %d skipped as unsupported.",
                 len(rules), len(rules.skipped))
        if rules.skipped:
            text += "\n" + "\n".join("%s: %s" % item for item in rules.skipped[:3])
        self.yara_info.configure(text=text + "\n" + t("Put .yar / .yara files in this folder."))

    def _save(self) -> None:
        try:
            lookups = max(1, min(500, int(self.vt_max.get())))
        except ValueError:
            lookups = 20
        try:
            min_age = max(0, min(3650, int(float(self.vt_age.get()))))
        except ValueError:
            min_age = 30
        names = [p.strip() for p in self.publishers.get().split(",") if p.strip()]
        self.app.settings.update(
            vt_min_age_days=min_age,
            trusted_publishers=None if names == list(TRUSTED_PUBLISHERS) else names)
        if self.vt_on.get() and not self.vt_key.get().strip():
            messagebox.showwarning(TOOL_NAME, t("Enter a VirusTotal API key or switch the "
                                                "VirusTotal check off."), parent=self)
            return
        self.app.settings.update(
            yara_dir=self.yara_var.get().strip(), vt_enabled=self.vt_on.get(),
            vt_api_key=self.vt_key.get().strip(), vt_max_lookups=lookups,
            auto_quarantine=self.auto_q.get(), memory_enabled=self.mem_on.get(),
            abusech_key=self.abuse_key.get().strip(), amsi_enabled=self.amsi_on.get(),
            defender_scan=self.defender_on.get())
        try:
            settings_store.save(self.app.settings)
        except OSError as exc:
            messagebox.showerror(TOOL_NAME, t("The settings could not be saved:\n\n%s", exc), parent=self)
            return
        self.app.apply_settings()
        self.destroy()


class MemoryDialog(_Dialog):
    """What the memory center holds: learned rule adjustments and scan history."""

    LEARNED = (("rule", "Rule", 190), ("engine", "Engine", 110), ("fp", "False positives", 120),
               ("tp", "Confirmed", 100), ("shift", "Confidence", 150))
    HISTORY = (("time", "Date", 150), ("verdict", "Verdict", 150), ("findings", "Findings", 80),
               ("target", "Target", 290))

    def __init__(self, app) -> None:
        super().__init__(app, t("Memory"))
        px = app._px
        body = tk.Frame(self, bg=BG)
        body.pack(padx=px(18), pady=(px(4), px(16)))
        self.heading(body, t("What the scanner has learned"))
        self.learned = self._table(body, self.LEARNED, 7)
        self.learned_info = self.hint(body, "")
        self.heading(body, t("Scan history"))
        self.history = self._table(body, self.HISTORY, 7)
        self.history.bind("<Double-1>", lambda e: self._load_target())
        self.info = self.hint(body, "")
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(14), 0))
        HoverButton(row, t("Forget everything learned"), self._forget, DANGER, DANGER_HI,
                    "#ffffff").pack(side="left")
        HoverButton(row, t("Clear scan history"), self._clear).pack(side="left", padx=px(8))
        HoverButton(row, t("Close"), self.destroy).pack(side="right")
        self._fill()
        self.show()

    def _table(self, parent, columns, height: int) -> ttk.Treeview:
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        frame.pack()
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                            selectmode="browse", height=height)
        for cid, label, width in columns:
            tree.heading(cid, text=t(label), anchor="w")
            tree.column(cid, width=self.app._px(width), anchor="w")
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(side="left")
        return tree

    def _fill(self) -> None:
        memory = self.app.memory
        for tree in (self.learned, self.history):
            tree.delete(*tree.get_children())
        if memory is None:
            self.learned_info.configure(text=t("Learning is switched off in Settings."))
            self.info.configure(text="")
            return
        base = {rule.id: rule.confidence for rule in DEFAULT_RULES}
        stats = sorted(memory.rule_stats().items(),
                       key=lambda kv: -(kv[1].fp_count + kv[1].tp_count))
        for (rule_id, engine), s in stats:
            before = base.get(rule_id, 0.5)
            after = ContextEngine.learned_confidence(before, s.fp, s.tp)
            self.learned.insert("", "end", values=(
                rule_id, engine, s.fp_count, s.tp_count,
                "%d%%  →  %d%%" % (round(before * 100), round(after * 100))))
        self.learned_info.configure(text=t(
            "Each false positive lowers a rule's confidence for that engine and each confirmed "
            "threat raises it. Feedback slowly fades (half-life 180 days).") if stats else t(
            "Nothing learned yet. Mark findings as a false positive or a confirmed threat to "
            "teach the scanner."))
        for scan in memory.history(200):
            self.history.insert("", "end", values=(
                time.strftime("%Y-%m-%d %H:%M", time.localtime(scan["time"])),
                i18n.verdict_name(scan["verdict"] or ""), scan["findings"], scan["target"]))
        counts = memory.summary()
        self.info.configure(text=t("%d scans  ·  %d stored findings  ·  %d feedback entries",
                                   counts["scans"], counts["observations"], counts["feedback"])
                            + "\n" + t("Double-click a scan to put its folder in the scan box.")
                            + "\n" + memory.path)

    def _load_target(self) -> None:
        sel = self.history.selection()
        if sel:
            self.app.path_var.set(self.history.item(sel[0], "values")[3])
            self.destroy()

    def _forget(self) -> None:
        if self.app.memory is None or not messagebox.askyesno(
                TOOL_NAME, t("Forget every false-positive and confirmed-threat decision? Rule "
                             "confidence returns to its built-in values."), parent=self):
            return
        self.app.memory.clear_feedback()
        self.app.context.refresh_memory()
        self._fill()

    def _clear(self) -> None:
        if self.app.memory is None or not messagebox.askyesno(
                TOOL_NAME, t("Delete the stored scan history and code snippets? What the "
                             "scanner has learned is kept."), parent=self):
            return
        self.app.memory.clear_history()
        self._fill()


class QuarantineDialog(_Dialog):
    COLUMNS = (("time", "Date", 150), ("severity", "Severity", 90),
               ("original", "Original location", 430), ("reasons", "Reasons", 220))

    def __init__(self, app, quarantine: Quarantine) -> None:
        super().__init__(app, t("Quarantine"))
        self.quarantine = quarantine
        px = app._px
        body = tk.Frame(self, bg=BG)
        body.pack(padx=px(18), pady=px(16))
        frame = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        frame.pack()
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in self.COLUMNS], show="headings",
                                 selectmode="browse", height=10)
        for cid, label, width in self.COLUMNS:
            self.tree.heading(cid, text=t(label), anchor="w")
            self.tree.column(cid, width=px(width), anchor="w")
        bar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.tree.pack(side="left")
        self.info = tk.Label(body, text="", font=(FONT, 9), fg=MUTED, bg=BG, anchor="w")
        self.info.pack(fill="x", pady=(px(8), 0))
        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(px(12), 0))
        HoverButton(row, t("Restore to original location"), self._restore).pack(side="left")
        HoverButton(row, t("Delete permanently"), self._delete, DANGER, DANGER_HI, "#ffffff").pack(
            side="left", padx=px(8))
        HoverButton(row, t("Close"), self.destroy).pack(side="right")
        self._fill()
        self.show()

    def _fill(self) -> None:
        self.tree.delete(*self.tree.get_children())
        entries = self.quarantine.list()
        for e in reversed(entries):
            level = e.get("severity", "")
            if level in Severity.__members__:
                level = i18n.severity(Severity[level])
            self.tree.insert("", "end", iid=e["id"], values=(
                e.get("time", ""), level, e.get("original", ""),
                ", ".join(e.get("reasons", []))))
        self.info.configure(text=t("%d file(s) in quarantine  ·  %s", len(entries),
                                   self.quarantine.directory))

    def _selected(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _restore(self) -> None:
        entry = self._selected()
        if not entry:
            return
        if not messagebox.askyesno(TOOL_NAME, t("Put this file back into the game folder? Only "
                                                "do this if you are sure it is safe."), parent=self):
            return
        try:
            self.quarantine.restore(entry)
        except QuarantineError as exc:
            messagebox.showerror(TOOL_NAME, str(exc), parent=self)
        self._fill()

    def _delete(self) -> None:
        entry = self._selected()
        if not entry:
            return
        if not messagebox.askyesno(TOOL_NAME, t("Permanently delete this quarantined file? "
                                                "This cannot be undone."), parent=self):
            return
        try:
            self.quarantine.delete(entry)
        except QuarantineError as exc:
            messagebox.showerror(TOOL_NAME, str(exc), parent=self)
        self._fill()
