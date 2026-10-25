"""Command-line front end: ``python -m gamescan <path> [options]``."""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

from . import export, i18n, launcher, models, settings, system
from .context import ContextEngine, HashAllowlist
from .defender import DefenderScan
from .handlers import engine_files
from .memory import MemoryCenter
from .models import TOOL_NAME, TOOL_VERSION, ScanReport, Severity
from .signatures import DEFAULT_URL, SignatureDatabase, SignatureError
from .quarantine import Quarantine
from .reputation import VirusTotalClient
from .rules import RuleEngine
from .scanner import Scanner, neutral_scanner

_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[38;5;208m", "MEDIUM": "\033[93m",
          "LOW": "\033[96m", "DIM": "\033[90m", "END": "\033[0m"}


def _print_report(report: ScanReport, show_suppressed: bool, minimum: Severity) -> None:
    tty = sys.stdout.isatty()
    paint = (lambda s, c: _COLOR[c] + s + _COLOR["END"]) if tty else (lambda s, c: s)
    shown = [f for f in report.active if f.severity >= minimum]
    shown.sort(key=lambda f: (-f.severity, -f.confidence, f.file, f.line or 0))
    for f in shown:
        where = f.file + (":%d" % f.line if f.line else "")
        print("%s %s  %s" % (paint("[%-8s]" % f.severity.name, f.severity.name), f.rule_id, f.title))
        print("    %s  (confidence %d%%)%s" % (where, round(f.confidence * 100),
                                              "  [QUARANTINED]" if f.quarantined else ""))
        print("    %s" % f.reason)
        print("    evidence: %s" % f.evidence)
    if show_suppressed:
        for f in report.suppressed:
            where = f.file + (":%d" % f.line if f.line else "")
            print(paint("[suppressed] %s  %s  %s\n    why: %s"
                        % (f.rule_id, f.title, where, f.suppression_reason), "DIM"))
    c = report.counts()
    print()
    for note in report.notes:
        print(paint("note: " + note, "DIM"))
    print("Target   : %s" % report.target)
    print("Engines  : %s" % (", ".join(report.engines) or "none detected"))
    print("Files    : %d scanned, %d not applicable, %.1fs"
          % (report.files_scanned, report.files_skipped, report.duration))
    if report.bytes_total:
        print("Coverage : %.1f %% of %.1f MB lie in files the scanner reads"
              % (100.0 * report.coverage, report.bytes_total / 1048576.0))
    print("Findings : %d critical, %d high, %d medium, %d low  (%d suppressed)"
          % (c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], len(report.suppressed)))
    if report.quarantined:
        print("Isolated : %d file(s) moved to quarantine" % len(report.quarantined))
    mx = report.max_severity
    print("Verdict  : %s - %s" % (paint(report.verdict, mx.name if mx else "DIM"),
                                  report.verdict_detail))


def _watch(scanner: Scanner, folders: Optional[List[str]]) -> int:
    """Real-time protection in the terminal until interrupted (experimental: not in 0.9-beta)."""
    from .monitor import RealTimeMonitor
    if not folders:
        known = system.known_folders()
        folders = [known[k] for k in ("Downloads", "Desktop") if k in known]
    scanner.memory = False                       # single-file scans do not belong in the history

    def report(path: str, result: ScanReport) -> None:
        worst = result.max_severity
        flag = "  [QUARANTINED]" if result.quarantined else ""
        print("%s  %-11s %s%s" % (time.strftime("%H:%M:%S"), result.verdict, path, flag))
        if worst is not None and worst >= Severity.HIGH:
            for f in sorted(result.active, key=lambda f: -f.severity)[:4]:
                print("          %-8s %s" % (f.severity.name, f.title))

    monitor = RealTimeMonitor(folders, scanner.scan, report)
    if not monitor.folders:
        print("error: nothing to watch", file=sys.stderr)
        return 3
    print("Watching (Ctrl+C to stop):\n  " + "\n  ".join(monitor.folders))
    monitor.start()
    try:
        while monitor.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        monitor.stop()
    return 0


def _say(text: str) -> None:
    """Print, also on a console whose code page lacks some Turkish letters."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "ascii"
        print(text.encode(encoding, "replace").decode(encoding))


def _launch(args, game_arguments: List[str]) -> int:
    """``--launch``: a scan nothing in the profile can soften, then the game, a
    question, or a refusal."""
    if not os.path.isfile(args.launch):
        print("error: not a file: %s" % args.launch, file=sys.stderr)
        return 3
    cfg = settings.load()
    i18n.set_language(i18n.detect_default())     # the questions follow the app's language
    # the benchmark's scanner (launcher.launch_scanner, shared with the window)
    scanner = launcher.launch_scanner(cfg, yara=args.yara, strict=args.strict, amsi=not args.no_amsi,
                                      factory=neutral_scanner)
    minimum = Severity[args.min_severity]
    return launcher.secure_launch(
        args.launch, scanner, game_arguments, out=_say,
        show=lambda report: _print_report(report, args.show_suppressed, minimum))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="gamescan", description="%s %s - static malware triage for game folders."
        % (TOOL_NAME, TOOL_VERSION))
    ap.add_argument("path", nargs="?", help="game folder or single file (omit to open the GUI)")
    ap.add_argument("--gui", action="store_true", help="open the graphical interface")
    ap.add_argument("--json", metavar="FILE", help="write the JSON report to FILE ('-' = stdout)")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    ap.add_argument("--pdf", metavar="FILE", help="write a PDF report to FILE")
    ap.add_argument("--strict", action="store_true",
                    help="do not trust files just because they sit in engine/library locations")
    ap.add_argument("--allowlist", metavar="FILE", default=HashAllowlist.default_path(),
                    help="SHA-256 allowlist JSON (default: %(default)s)")
    ap.add_argument("--yara", metavar="PATH", default=settings.DEFAULTS["yara_dir"],
                    help="YARA rule file or folder (default: %(default)s)")
    ap.add_argument("--vt-key", metavar="KEY", default=os.environ.get("VT_API_KEY", ""),
                    help="VirusTotal API key: verify executables by SHA-256 "
                         "(default: $VT_API_KEY; only hashes are sent)")
    ap.add_argument("--vt-max", metavar="N", type=int, default=20,
                    help="maximum VirusTotal lookups per scan (default: %(default)s)")
    ap.add_argument("--no-amsi", action="store_true",
                    help="do not show extracted content to the Windows antimalware engine")
    ap.add_argument("--defender-scan", action="store_true",
                    help="also run Windows Defender (MpCmdRun, detection only) on the target")
    ap.add_argument("--vt-min-age", metavar="DAYS", type=float, default=None,
                    help="a clean VirusTotal result only dismisses findings once the file "
                         "has been known this many days (default: the saved setting, 30)")
    ap.add_argument("--quarantine", action="store_true",
                    help="move files with HIGH/CRITICAL findings to quarantine")
    ap.add_argument("--quick", action="store_true",
                    help="scan Downloads, Desktop, temp and Startup folders")
    ap.add_argument("--system", action="store_true",
                    help="scan autostart entries and the programs currently running")
    ap.add_argument("--full", action="store_true", help="scan every fixed drive (slow)")
    ap.add_argument("--watch", action="store_true",
                    help="(experimental, off in this version) real-time protection: keep watching PATH (or Downloads and Desktop) "
                         "and scan new files until Ctrl+C")
    ap.add_argument("--update-signatures", action="store_true",
                    help="download the known-malware hash list, then continue")
    ap.add_argument("--abusech-key", metavar="KEY", default=os.environ.get("ABUSECH_AUTH_KEY", ""),
                    help="abuse.ch Auth-Key for --update-signatures (default: $ABUSECH_AUTH_KEY, "
                         "then the key saved in Settings; free at https://auth.abuse.ch/)")
    ap.add_argument("--import-hashes", metavar="FILE",
                    help="add SHA-256 hashes from a text/CSV file to the blocklist")
    ap.add_argument("--no-memory", action="store_true",
                    help="do not use or update the memory center (no learning, no history)")
    ap.add_argument("--show-suppressed", action="store_true",
                    help="also list suppressed findings and why they were suppressed")
    ap.add_argument("--min-severity", choices=[s.name for s in Severity], default="LOW",
                    help="lowest severity to print and to include in HTML/PDF")
    ap.add_argument("--allow-unsigned-engine-files", action="store_true",
                    help="exempt engine components that are built like the real ones even "
                         "without their vendor's signature (NW.js, Ren'Py's Python, SDL, ... "
                         "are never signed); by default only a vendor signature exempts")
    ap.add_argument("--launch", metavar="EXECUTABLE",
                    help="secure launcher: scan the executable's game folder and start the "
                         "game if the verdict is CLEAN or LIKELY SAFE; ask first for REVIEW, "
                         "SUSPICIOUS or a part that could not be inspected; refuse what is "
                         "dangerous (arguments after a lone -- are passed to the game)")
    argv, game_arguments = launcher.split_arguments(argv)
    args = ap.parse_args(argv)
    if args.allow_unsigned_engine_files:
        engine_files.REQUIRE_VENDOR_SIGNATURE = False
    if args.launch:
        return _launch(args, game_arguments)
    if args.watch and not models.EXPERIMENTAL_PROTECTION:
        ap.error("--watch (real-time protection) is experimental and switched off in %s"
                 % TOOL_VERSION)

    maintenance = args.update_signatures or args.import_hashes
    pc_scan = args.quick or args.system or args.full or args.watch
    if args.gui or not (args.path or pc_scan or maintenance):
        from .gui import main as gui_main
        return gui_main(args.path)
    if args.path and not os.path.exists(args.path):
        ap.error("path not found: %s" % args.path)

    cfg = settings.load()
    signatures = SignatureDatabase()
    try:
        if args.import_hashes:
            result = signatures.import_file(args.import_hashes)
            print("Imported : %d hashes in the file, %d new" % (result.listed, result.added))
        if args.update_signatures:
            result = signatures.update(cfg.get("signature_url") or DEFAULT_URL,
                                       args.abusech_key or cfg.get("abusech_key", ""))
            print("Updated  : %d hashes in the list, %d new" % (result.listed, result.added))
    except (SignatureError, OSError) as exc:
        print("error: signature update failed - %s" % exc, file=sys.stderr)
        return 3
    if maintenance and not (args.path or pc_scan):
        print("Database : %d known-malware hashes" % signatures.count())
        return 0

    rules = RuleEngine()
    if args.yara and os.path.exists(args.yara):
        rules.load_yara(args.yara)
    reputation = None
    if args.vt_key:
        reputation = VirusTotalClient(args.vt_key,
                                      os.path.join(settings.DIR, "virustotal_cache.json"))
    memory = None
    if not args.no_memory and settings.load().get("memory_enabled", True):
        try:
            memory = MemoryCenter()
        except Exception as exc:
            print("note: memory center unavailable (%s)" % exc, file=sys.stderr)
    context = ContextEngine(
        HashAllowlist(args.allowlist), strict=args.strict, memory=memory,
        trusted_publishers=cfg.get("trusted_publishers"),
        vt_min_age_days=args.vt_min_age if args.vt_min_age is not None
        else float(cfg.get("vt_min_age_days", 30)))
    scanner = Scanner(context=context, rules=rules,
                      reputation=reputation, max_lookups=args.vt_max, memory=memory,
                      signatures=signatures, quarantine=Quarantine(),
                      amsi=not args.no_amsi and bool(cfg.get("amsi_enabled", True)),
                      defender=DefenderScan() if args.defender_scan or cfg.get("defender_scan")
                      else None,
                      auto_quarantine=args.quarantine)
    if args.watch:
        return _watch(scanner, [args.path] if args.path else None)
    extra = None
    if args.full:
        target, label = system.fixed_drives(), "Full scan"
    elif args.system:
        entries = system.startup_entries()
        target, label = system.system_scan_targets(), "Startup items and running programs"
        extra = system.autorun_findings(entries)
    elif args.quick:
        target, label = system.quick_scan_targets(), "Quick scan"
    else:
        target, label = args.path, None
    report = scanner.scan(target, label=label, extra=extra)
    minimum = Severity[args.min_severity]
    if args.json == "-":
        print(report.to_json())
    else:
        _print_report(report, args.show_suppressed, minimum)
        if args.json:
            report.save(args.json)
            print("Report   : %s" % os.path.abspath(args.json))
    chosen = sorted((f for f in report.active if f.severity >= minimum),
                    key=lambda f: (-f.severity, -f.confidence, f.file, f.line or 0))
    note = "severity: %s and above" % minimum.name if minimum > Severity.LOW else ""
    if args.html:
        export.export_html(report, chosen, args.html, note)
    if args.pdf:
        export.export_pdf(report, chosen, args.pdf, note)
    mx = report.max_severity
    return 2 if mx and mx >= Severity.HIGH else 1 if mx else 0
