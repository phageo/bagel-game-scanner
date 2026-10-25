"""Theme constants and the small custom widgets shared by the GUI windows."""
from __future__ import annotations

import sys
import tkinter as tk
from typing import Optional

BG, PANEL, PANEL2, LINE = "#0e1117", "#161b22", "#1c2230", "#2a3242"
TEXT, MUTED, ACCENT, ACCENT_HI = "#e6edf3", "#8b949e", "#3b82f6", "#60a5fa"
OK, SUPP, DANGER, DANGER_HI = "#3fb950", "#6e7681", "#da3633", "#f85149"
SEV_COLOR = {"CRITICAL": "#ff5c6c", "HIGH": "#ff9550", "MEDIUM": "#f2cc60", "LOW": "#58a6ff"}
VERDICT_COLOR = {"CLEAN": OK, "LIKELY SAFE": "#58a6ff", "REVIEW": "#f2cc60",
                 "SUSPICIOUS": "#ff9550", "DANGEROUS": "#ff5c6c"}
FONT = "Segoe UI" if sys.platform == "win32" else "TkDefaultFont"
MONO = "Consolas" if sys.platform == "win32" else "TkFixedFont"


def mix(a: str, b: str, amount: float) -> str:
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * amount) for x, y in zip(ca, cb))


def make_entry(master, var, **kw) -> tk.Entry:
    return tk.Entry(master, textvariable=var, bg=PANEL2, fg=TEXT, insertbackground=TEXT,
                    relief="flat", font=(FONT, 10), highlightthickness=1,
                    highlightbackground=LINE, highlightcolor=ACCENT, **kw)


def make_check(master, text, var, command=None, bg=BG, wrap=0) -> tk.Label:
    """Checkbox drawn as text so the box scales with the display DPI."""
    lbl = tk.Label(master, bg=bg, font=(FONT, 10), cursor="hand2", justify="left",
                   anchor="w", wraplength=wrap)

    def paint(*_):
        if not lbl.winfo_exists():         # label of a window that was rebuilt / closed
            return
        on = var.get()
        lbl.configure(text=("☑  " if on else "☐  ") + text, fg=TEXT if on else MUTED)

    def click(_):
        var.set(not var.get())
        if command:
            command()

    var.trace_add("write", paint)
    lbl.bind("<Button-1>", click)
    paint()
    return lbl


class HoverButton(tk.Label):
    """Flat button whose colour fades on hover instead of snapping."""

    def __init__(self, master, text, command, base=PANEL2, hover=LINE, fg=TEXT, bold=False):
        super().__init__(master, text=text, bg=base, fg=fg, cursor="hand2", padx=14, pady=7,
                         font=(FONT, 10, "bold" if bold else "normal"))
        self.command, self._base, self._hover, self._fg = command, base, hover, fg
        self._t, self._goal, self._job, self._enabled = 0.0, 0.0, None, True
        self.bind("<Enter>", lambda e: self._fade(1.0))
        self.bind("<Leave>", lambda e: self._fade(0.0))
        self.bind("<ButtonRelease-1>", self._click)

    def _click(self, event):
        inside = 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()
        if self._enabled and inside:
            self.command()

    def _fade(self, goal):
        self._goal = goal if self._enabled else 0.0
        if self._job is None:
            self._step()

    def _step(self):
        if not self.winfo_exists():        # the window was rebuilt mid-animation
            return
        self._t += (self._goal - self._t) * 0.35
        if abs(self._goal - self._t) < 0.03:
            self._t, self._job = self._goal, None
        else:
            self._job = self.after(16, self._step)
        self._paint()

    def _paint(self):
        # a disabled button drops its accent colour so it does not invite a click
        base = self._base if self._enabled else PANEL2
        self.configure(bg=mix(base, self._hover, self._t))

    def restyle(self, text=None, base=None, hover=None):
        if text is not None:
            self.configure(text=text)
        self._base, self._hover = base or self._base, hover or self._hover
        self._paint()

    def enable(self, flag: bool):
        self._enabled = flag
        self.configure(fg=self._fg if flag else SUPP, cursor="hand2" if flag else "arrow")
        if not flag:
            self._t = self._goal = 0.0
        self._paint()


class SmoothBar(tk.Canvas):
    """Progress bar that eases towards its target value."""

    def __init__(self, master, height=4):
        super().__init__(master, height=height, bg=PANEL2, highlightthickness=0, bd=0)
        self._cur, self._goal = 0.0, 0.0
        self._rect = self.create_rectangle(0, 0, 0, height, fill=ACCENT, width=0)
        self.bind("<Configure>", lambda e: self._draw())
        self._tick()

    def set(self, fraction: float, color: Optional[str] = None, snap: bool = False):
        self._goal = max(0.0, min(1.0, fraction))
        if color:
            self.itemconfigure(self._rect, fill=color)
        if snap:
            self._cur = self._goal
            self._draw()

    def _draw(self):
        self.coords(self._rect, 0, 0, self.winfo_width() * self._cur, self.winfo_height())

    def _tick(self):
        if not self.winfo_exists():
            return
        if abs(self._goal - self._cur) > 0.0005:
            self._cur += (self._goal - self._cur) * 0.18
            self._draw()
        self.after(16, self._tick)


class Card(tk.Frame):
    """Summary tile with a count-up number; clickable ones act as filters."""

    def __init__(self, master, caption, color, on_click=None):
        super().__init__(master, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        self._color, self._value, self._goal, self._job = color, 0, 0, None
        self.num = tk.Label(self, text="0", font=(FONT, 20, "bold"), fg=color, bg=PANEL)
        self.cap = tk.Label(self, text=caption, font=(FONT, 9), fg=MUTED, bg=PANEL)
        self.num.pack(anchor="w", padx=14, pady=(9, 0))
        self.cap.pack(anchor="w", padx=14, pady=(0, 9))
        if on_click:
            for w in (self, self.num, self.cap):
                w.configure(cursor="hand2")
                w.bind("<Button-1>", lambda e: on_click())

    def set(self, value: int, snap: bool = False):
        self._goal = value
        if snap:
            self._value = value
            self.num.configure(text="{:,}".format(value))
        elif self._job is None:
            self._step()

    def _step(self):
        if not self.winfo_exists():
            return
        gap = self._goal - self._value
        if gap == 0:
            self._job = None
            return
        self._value += gap if abs(gap) < 3 else int(gap * 0.3) or (1 if gap > 0 else -1)
        self.num.configure(text="{:,}".format(self._value))
        self._job = self.after(22, self._step)

    def set_active(self, flag: bool):
        self.configure(highlightbackground=self._color if flag else LINE)
