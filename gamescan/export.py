"""HTML and PDF report export (standard library only).

Both exporters take the report plus the findings to include, so the caller
decides the filter (severity, search, suppressed). Text follows the current
interface language. The PDF writer embeds a TrueType font from the system so
non-ASCII text (Turkish) renders everywhere.
"""
from __future__ import annotations

import html
import os
import struct
import time
import zlib
from typing import Dict, List, Optional, Sequence, Tuple

from . import i18n
from .i18n import t
from .models import TOOL_NAME, TOOL_VERSION, Finding, ScanReport, Severity

_COLORS = {"CRITICAL": "#d1242f", "HIGH": "#bc4c00", "MEDIUM": "#9a6700", "LOW": "#0969da"}
_VERDICT = {"CLEAN": "#1a7f37", "LIKELY SAFE": "#0969da", "REVIEW": "#9a6700",
            "SUSPICIOUS": "#bc4c00", "DANGEROUS": "#d1242f"}
_GRAY, _INK, _PURPLE = "#57606a", "#1f2328", "#8250df"


def _summary(report: ScanReport) -> List[Tuple[str, str, str]]:
    """(label, value, colour) tiles shared by both formats."""
    counts = report.counts()
    tiles = [(i18n.severity(s, caption=True), str(counts[s.name]), _COLORS[s.name])
             for s in reversed(Severity)]
    tiles.append((t("Suppressed"), str(len(report.suppressed)), _GRAY))
    tiles.append((t("Files scanned"), "{:,}".format(report.files_scanned), _INK))
    return tiles


def _where(f: Finding) -> str:
    return f.file + (t("  :  line %d", f.line) if f.line else "")


def _when(report: ScanReport) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(report.finished_at or time.time()))


# -- HTML ----------------------------------------------------------------------
_CSS = """
*{box-sizing:border-box}body{font:15px/1.5 "Segoe UI",system-ui,sans-serif;color:#1f2328;
background:#f6f8fa;margin:0;padding:32px}main{max-width:980px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}.sub{color:#57606a;font-size:13px;word-break:break-all}
.verdict{margin:22px 0 14px;padding:16px 20px;background:#fff;border:1px solid #d0d7de;
border-left-width:6px;border-radius:8px}.verdict b{font-size:26px;letter-spacing:.5px}
.plain{font-size:18px;font-weight:600;margin:4px 0 6px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}
.tile{flex:1 1 120px;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:10px 14px}
.tile b{display:block;font-size:24px}.tile span{color:#57606a;font-size:12px}
h2{font-size:16px;margin:26px 0 10px}.note{color:#57606a;font-size:13px;margin:-4px 0 12px}
.f{background:#fff;border:1px solid #d0d7de;border-left-width:5px;border-radius:8px;
padding:14px 18px;margin-bottom:12px;page-break-inside:avoid}.f.s{opacity:.72}
.f h3{margin:0 0 2px;font-size:16px}.meta{color:#57606a;font-size:12.5px;margin-bottom:8px}
.sev{font-weight:700}.k{font-size:11px;font-weight:700;color:#57606a;text-transform:uppercase;
letter-spacing:.4px;margin:10px 0 3px}pre{background:#f6f8fa;border:1px solid #d8dee4;
border-radius:6px;padding:8px 10px;margin:0;font:12.5px/1.45 Consolas,monospace;
white-space:pre-wrap;word-break:break-all}.supp{color:#8250df}
ul{margin:0;padding-left:20px;color:#57606a;font-size:13px}
footer{color:#8c959f;font-size:12px;margin-top:28px;text-align:center}
@media print{body{background:#fff;padding:0}}
"""


def render_html(report: ScanReport, findings: Sequence[Finding], filter_note: str = "") -> str:
    e = html.escape
    name, detail = i18n.verdict(report)
    color = _VERDICT[report.verdict]
    out = ["<!doctype html><html lang='%s'><head><meta charset='utf-8'>" % i18n.language(),
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           "<title>%s - %s</title><style>%s</style></head><body><main>"
           % (e(TOOL_NAME), e(t("Scan report")), _CSS),
           "<h1>%s</h1><div class='sub'>%s &nbsp;&middot;&nbsp; %s</div>"
           % (e(t("Scan report")), e(report.target), e(_when(report))),
           "<div class='verdict' style='border-left-color:%s'><b style='color:%s'>%s</b>"
           "<div class='plain'>%s</div>%s"
           " &middot; %s %d/100 &middot; %s</div>"
           % (color, color, e(name), e(i18n.plain_verdict(report)), e(detail),
              e(t("Risk score")), report.risk_score,
              e(", ".join(report.engines) or t("no known engine detected"))),
           "<div class='tiles'>"]
    for label, value, tint in _summary(report):
        out.append("<div class='tile'><b style='color:%s'>%s</b><span>%s</span></div>"
                   % (tint, e(value), e(label)))
    out.append("</div><h2>%s</h2>" % e(t("Findings")))
    out.append("<div class='note'>%s%s</div>" % (
        e(t("Showing %d of %d findings", len(findings), len(report.findings))),
        e("  \u00b7  " + filter_note) if filter_note else ""))
    if not findings:
        out.append("<p class='note'>%s</p>" % e(t("No findings match the current filter.")))
    for f in findings:
        tint = _GRAY if f.suppressed else _COLORS[f.severity.name]
        out.append("<div class='f%s' style='border-left-color:%s'><h3>%s</h3>"
                   % (" s" if f.suppressed else "", tint, e(i18n.title(f))))
        out.append("<div class='meta'><span class='sev' style='color:%s'>%s</span> &middot; %s"
                   " &middot; %s %d%% &middot; %s &middot; %s%s</div>"
                   % (tint, e(i18n.severity(f.severity)), e(i18n.category(f.category)),
                      e(t("Confidence")), round(f.confidence * 100), e(f.rule_id), e(_where(f)),
                      " &middot; <b>%s</b>" % e(t("Quarantined")) if f.quarantined else ""))
        if f.suppressed:
            out.append("<div class='supp'>%s</div>" % e(t("Suppressed: %s", i18n.suppression(f))))
        out.append("<div class='k'>%s</div><div>%s</div>"
                   % (e(t("What does this mean")), e(i18n.reason(f))))
        out.append("<div class='k'>%s</div><div>%s</div>"
                   % (e(t("What should I do")), e(i18n.advice(f))))
        out.append("<div class='k'>%s</div><pre>%s</pre>" % (e(t("Evidence")), e(i18n.evidence(f))))
        if f.snippet and f.snippet != f.evidence:
            out.append("<div class='k'>%s</div><pre>%s</pre>" % (e(t("Snippet")), e(f.snippet)))
        out.append("</div>")
    if report.quarantined:
        out.append("<h2>%s</h2><ul>%s</ul>" % (e(t("Quarantined files")), "".join(
            "<li>%s</li>" % e(str(q.get("original", ""))) for q in report.quarantined)))
    if report.notes:
        out.append("<h2>%s</h2><ul>%s</ul>" % (e(t("Notes")), "".join(
            "<li>%s</li>" % e(n) for n in report.notes)))
    out.append("<footer>%s</footer></main></body></html>"
               % e(t("Generated by %s %s", TOOL_NAME, TOOL_VERSION)))
    return "".join(out)


def export_html(report: ScanReport, findings: Sequence[Finding], path: str,
                filter_note: str = "") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(report, findings, filter_note))


# -- PDF -----------------------------------------------------------------------
_FONT_DIRS = [os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"),
              "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/TTF",
              "/Library/Fonts", "/System/Library/Fonts/Supplemental"]
_FONT_FILES = {False: ("arial.ttf", "DejaVuSans.ttf", "Arial.ttf"),
               True: ("arialbd.ttf", "DejaVuSans-Bold.ttf", "Arial Bold.ttf")}


def _find_font(bold: bool) -> Optional[str]:
    for folder in _FONT_DIRS:
        for name in _FONT_FILES[bold]:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
    return None


class _TrueType:
    """A TrueType font embedded as a Type 0 / Identity-H composite font."""

    def __init__(self, path: str, name: str) -> None:
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.name = name
        d = self.data
        tables = {}
        for i in range(struct.unpack_from(">H", d, 4)[0]):
            tag, _sum, off, length = struct.unpack_from(">4sIII", d, 12 + 16 * i)
            tables[tag] = off
        self.units = struct.unpack_from(">H", d, tables[b"head"] + 18)[0]
        self.bbox = struct.unpack_from(">4h", d, tables[b"head"] + 36)
        self.ascent, self.descent = struct.unpack_from(">hh", d, tables[b"hhea"] + 4)
        self._nhm = struct.unpack_from(">H", d, tables[b"hhea"] + 34)[0]
        self._hmtx = tables[b"hmtx"]
        self.cmap: Dict[int, int] = {}
        self._read_cmap(tables[b"cmap"])
        self.used: Dict[int, int] = {}                    # glyph id -> code point
        self._fallback = self.cmap.get(ord("?"), 0)

    def _read_cmap(self, off: int) -> None:
        d, best = self.data, None
        for i in range(struct.unpack_from(">H", d, off + 2)[0]):
            plat, enc, sub = struct.unpack_from(">HHI", d, off + 4 + 8 * i)
            if (plat, enc) in ((3, 1), (0, 3), (0, 4)) and struct.unpack_from(">H", d, off + sub)[0] == 4:
                best = off + sub
                if plat == 3:
                    break
        if best is None:
            raise ValueError("font has no Unicode BMP cmap")
        segx2 = struct.unpack_from(">H", d, best + 6)[0]
        ends = best + 14
        starts, deltas, ranges = ends + segx2 + 2, ends + 2 * segx2 + 2, ends + 3 * segx2 + 2
        for i in range(segx2 // 2):
            end, start, delta, ro = (struct.unpack_from(">H", d, base + 2 * i)[0]
                                     for base in (ends, starts, deltas, ranges))
            if start == 0xFFFF:
                break
            for c in range(start, end + 1):
                if ro == 0:
                    g = (c + delta) & 0xFFFF
                else:
                    g = struct.unpack_from(">H", d, ranges + 2 * i + ro + 2 * (c - start))[0]
                    if g:
                        g = (g + delta) & 0xFFFF
                if g:
                    self.cmap[c] = g

    def _advance(self, gid: int) -> float:
        raw = struct.unpack_from(">H", self.data, self._hmtx + 4 * min(gid, self._nhm - 1))[0]
        return raw * 1000.0 / self.units

    def width(self, text: str, size: float) -> float:
        return sum(self._advance(self.cmap.get(ord(c), self._fallback)) for c in text) * size / 1000

    def encode(self, text: str) -> str:
        out = []
        for c in text:
            gid = self.cmap.get(ord(c))
            if gid is None:
                gid, c = self._fallback, "?"
            self.used.setdefault(gid, ord(c))
            out.append("%04X" % gid)
        return "".join(out)

    def objects(self, add) -> int:
        """Emit the font's PDF objects; returns the Type 0 font object number."""
        scale = 1000.0 / self.units
        stream = add(b"<< /Length %d /Length1 %d /Filter /FlateDecode >>",
                     zlib.compress(self.data, 6), raw=len(self.data))
        desc = add(("<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%d %d %d %d] "
                    "/ItalicAngle 0 /Ascent %d /Descent %d /CapHeight %d /StemV 80 /FontFile2 %d 0 R >>"
                    % ((self.name,) + tuple(round(v * scale) for v in self.bbox)
                       + (round(self.ascent * scale), round(self.descent * scale),
                          round(self.ascent * scale * 0.72), stream))).encode())
        widths = " ".join("%d [%d]" % (g, round(self._advance(g))) for g in sorted(self.used))
        cid = add(("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo "
                   "<< /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R "
                   "/DW 1000 /W [%s] /CIDToGIDMap /Identity >>" % (self.name, desc, widths)).encode())
        pairs = sorted(self.used.items())
        cmap = ["/CIDInit /ProcSet findresource begin 12 dict begin begincmap",
                "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
                "/CMapName /Adobe-Identity-UCS def /CMapType 2 def",
                "1 begincodespacerange <0000> <FFFF> endcodespacerange"]
        for i in range(0, len(pairs), 100):
            block = pairs[i:i + 100]
            cmap.append("%d beginbfchar" % len(block))
            cmap += ["<%04X> <%04X>" % p for p in block]
            cmap.append("endbfchar")
        cmap.append("endcmap CMapName currentdict /CMap defineresource pop end end")
        body = zlib.compress("\n".join(cmap).encode())
        uni = add(b"<< /Length %d /Filter /FlateDecode >>", body)
        return add(("<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H "
                    "/DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>" % (self.name, cid, uni)).encode())


class _CoreFont:
    """Fallback when no TrueType font is available: built-in Helvetica (Latin-1 only)."""

    def __init__(self, bold: bool) -> None:
        self.base = "Helvetica-Bold" if bold else "Helvetica"
        self._em = 0.56 if bold else 0.52

    def width(self, text: str, size: float) -> float:
        return len(text) * size * self._em

    def encode(self, text: str) -> str:
        return text.encode("cp1252", "replace").hex().upper()

    def objects(self, add) -> int:
        return add(("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>"
                    % self.base).encode())


def _load_font(bold: bool):
    path = _find_font(bold)
    if path:
        try:
            return _TrueType(path, "GSS-Bold" if bold else "GSS-Regular")
        except (OSError, ValueError, KeyError, struct.error):
            pass
    return _CoreFont(bold)


class _Pdf:
    W, H, M = 595.0, 842.0, 46.0                  # A4 in points, margin

    def __init__(self) -> None:
        self.fonts = {"R": _load_font(False), "B": _load_font(True)}
        self.pages: List[List[str]] = []
        self.y = 0.0
        self.new_page()

    @property
    def width(self) -> float:
        return self.W - 2 * self.M

    def new_page(self) -> None:
        self.pages.append([])
        self.y = self.H - self.M

    def ensure(self, height: float) -> None:
        if self.y - height < self.M + 14:
            self.new_page()

    @staticmethod
    def _rgb(color: str) -> str:
        return "%.3f %.3f %.3f" % tuple(int(color[i:i + 2], 16) / 255 for i in (1, 3, 5))

    def text(self, x: float, y: float, text: str, font: str = "R", size: float = 10,
             color: str = _INK) -> None:
        self.pages[-1].append("BT /F%s %.1f Tf %s rg %.2f %.2f Td <%s> Tj ET"
                              % (font, size, self._rgb(color), x, y, self.fonts[font].encode(text)))

    def rect(self, x: float, y: float, w: float, h: float, color: str) -> None:
        self.pages[-1].append("%s rg %.2f %.2f %.2f %.2f re f" % (self._rgb(color), x, y, w, h))

    def wrap(self, text: str, font: str, size: float, width: float) -> List[str]:
        fnt, lines = self.fonts[font], []
        for raw in text.replace("\t", "    ").replace("\r", "").split("\n"):
            line = ""
            for word in raw.split(" "):
                trial = word if not line else line + " " + word
                if fnt.width(trial, size) <= width:
                    line = trial
                    continue
                if line:
                    lines.append(line)
                while fnt.width(word, size) > width:          # break a long token
                    cut = max(1, int(len(word) * width / fnt.width(word, size)))
                    while cut > 1 and fnt.width(word[:cut], size) > width:
                        cut -= 1
                    lines.append(word[:cut])
                    word = word[cut:]
                line = word
            lines.append(line)
        return lines

    def para(self, text: str, font: str = "R", size: float = 10, color: str = _INK,
             indent: float = 0, gap: float = 0, shade: Optional[str] = None,
             max_lines: int = 0) -> None:
        lines = self.wrap(text, font, size, self.width - indent - (8 if shade else 0))
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines] + ["..."]
        leading = size * 1.38
        for line in lines:
            self.ensure(leading)
            if shade:
                self.rect(self.M + indent, self.y - leading + 1.5, self.width - indent, leading, shade)
            self.y -= leading
            self.text(self.M + indent + (4 if shade else 0), self.y + size * 0.32, line, font, size, color)
        self.y -= gap

    def rule(self, color: str = "#d0d7de") -> None:
        self.rect(self.M, self.y, self.width, 0.7, color)
        self.y -= 10

    def render(self, footer: str) -> bytes:
        objects: List[bytes] = []

        def add(header: bytes, stream: Optional[bytes] = None, raw: int = 0) -> int:
            if stream is not None:
                head = header % ((len(stream), raw) if raw else (len(stream),))
                objects.append(head + b"\nstream\n" + stream + b"\nendstream")
            else:
                objects.append(header)
            return len(objects)

        for n, page in enumerate(self.pages, 1):
            self.pages[n - 1] = page + [
                "BT /FR 8 Tf %s rg %.2f %.2f Td <%s> Tj ET"
                % (self._rgb("#8c959f"), self.M, self.M - 18,
                   self.fonts["R"].encode("%s  \u00b7  %s" % (footer, t("Page %d", n))))]
        catalog, pages_obj = add(b""), add(b"")          # filled in below
        font_ids = {key: font.objects(add) for key, font in self.fonts.items()}
        resources = "<< /Font << %s >> >>" % " ".join("/F%s %d 0 R" % kv for kv in font_ids.items())
        kids = []
        for page in self.pages:
            content = add(b"<< /Length %d /Filter /FlateDecode >>",
                          zlib.compress("\n".join(page).encode("latin-1")))
            kids.append(add(("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] /Resources %s "
                             "/Contents %d 0 R >>" % (pages_obj, self.W, self.H, resources,
                                                      content)).encode()))
        objects[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages_obj
        objects[pages_obj - 1] = ("<< /Type /Pages /Count %d /Kids [%s] >>" % (
            len(kids), " ".join("%d 0 R" % k for k in kids))).encode()
        out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
        out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
        out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objects) + 1, catalog, xref)
        return bytes(out)


def render_pdf(report: ScanReport, findings: Sequence[Finding], filter_note: str = "") -> bytes:
    pdf = _Pdf()
    name, detail = i18n.verdict(report)
    pdf.para(t("Scan report"), "B", 19, gap=2)
    pdf.para("%s  \u00b7  %s" % (report.target, _when(report)), "R", 8.5, _GRAY, gap=10)
    pdf.para(name, "B", 17, _VERDICT[report.verdict], gap=1)
    pdf.para(i18n.plain_verdict(report), "B", 12, gap=3)
    pdf.para("%s  \u00b7  %s %d/100  \u00b7  %s" % (
        detail, t("Risk score"), report.risk_score,
        ", ".join(report.engines) or t("no known engine detected")), "R", 9.5, _GRAY, gap=10)
    x = pdf.M
    pdf.ensure(40)
    for label, value, color in _summary(report):
        pdf.text(x, pdf.y - 16, value, "B", 16, color)
        pdf.text(x, pdf.y - 29, label, "R", 8, _GRAY)
        x += pdf.width / 6
    pdf.y -= 42
    pdf.rule()
    pdf.para(t("Findings"), "B", 12.5, gap=1)
    note = t("Showing %d of %d findings", len(findings), len(report.findings))
    pdf.para(note + ("  \u00b7  " + filter_note if filter_note else ""), "R", 8.5, _GRAY, gap=8)
    if not findings:
        pdf.para(t("No findings match the current filter."), "R", 10, _GRAY)
    for f in findings:
        color = _GRAY if f.suppressed else _COLORS[f.severity.name]
        pdf.ensure(74)
        pdf.rect(pdf.M, pdf.y - 13, 3, 13, color)
        pdf.para(i18n.title(f), "B", 11, indent=9, gap=0)
        meta = "%s  \u00b7  %s  \u00b7  %s %d%%  \u00b7  %s  \u00b7  %s" % (
            i18n.severity(f.severity), i18n.category(f.category), t("Confidence"),
            round(f.confidence * 100), f.rule_id, _where(f))
        if f.quarantined:
            meta += "  \u00b7  " + t("Quarantined")
        pdf.para(meta, "B", 8, color, indent=9, gap=3)
        if f.suppressed:
            pdf.para(t("Suppressed: %s", i18n.suppression(f)), "R", 9, _PURPLE, indent=9, gap=2)
        pdf.para(i18n.reason(f), "R", 9.5, indent=9, gap=2)
        pdf.para(t("What should I do") + ": " + i18n.advice(f), "R", 9.5, _GRAY, indent=9, gap=4)
        pdf.para(i18n.evidence(f), "R", 8.5, _INK, indent=9, gap=3, shade="#f1f3f5", max_lines=6)
        if f.snippet and f.snippet != f.evidence:
            pdf.para(f.snippet, "R", 8.5, _GRAY, indent=9, gap=3, shade="#f6f8fa", max_lines=8)
        pdf.y -= 9
    for heading, items in ((t("Quarantined files"), [str(q.get("original", "")) for q in report.quarantined]),
                           (t("Notes"), report.notes)):
        if items:
            pdf.ensure(40)
            pdf.para(heading, "B", 12.5, gap=3)
            for item in items:
                pdf.para("-  " + item, "R", 8.5, _GRAY, indent=4, gap=1)
            pdf.y -= 8
    return pdf.render(t("Generated by %s %s", TOOL_NAME, TOOL_VERSION))


def export_pdf(report: ScanReport, findings: Sequence[Finding], path: str,
               filter_note: str = "") -> None:
    data = render_pdf(report, findings, filter_note)
    with open(path, "wb") as fh:
        fh.write(data)
