"""Command line interface: ``python -m loganalyzer FILE [FILE ...]``."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from . import __version__
from .detectors import RULES, Config, run_rules
from .models import Severity
from .parsers import parse_file
from .report import Summary, render_html, render_json, render_text


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _hours(value: str) -> tuple[int, int]:
    try:
        start, end = (int(x) for x in value.split("-"))
        if not (0 <= start <= 23 and 0 <= end <= 24 and start != end):
            raise ValueError
        return start, end
    except ValueError:
        raise argparse.ArgumentTypeError("expected START-END in hours, e.g. 08-20") from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Detect brute force, scanning, web attacks and other suspicious activity "
                    "in Linux auth logs and Apache/nginx access logs.",
    )
    p.add_argument("files", nargs="+", type=Path, help="log files to analyse (.gz is fine)")
    p.add_argument("-f", "--format", choices=["auto", "auth", "web"], default="auto",
                   help="log format of the inputs (default: detect per file)")
    p.add_argument("-r", "--report", choices=["text", "json", "html"],
                   help="report format (default: from --output extension, else text)")
    p.add_argument("-o", "--output", type=Path, help="write the report to this file instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="show the evidence log lines in text reports")
    p.add_argument("--min-severity", type=_severity, default=Severity.LOW,
                   help="hide findings below this level (default: low)")
    p.add_argument("--fail-on", type=_severity, metavar="SEVERITY",
                   help="exit with status 1 if any finding is at or above this level (for CI / cron)")
    p.add_argument("--rules", help=f"comma-separated rules to run (default: all). Available: {', '.join(RULES)}")
    p.add_argument("--year", type=int, help="year for syslog timestamps, which do not include one")
    p.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    t = p.add_argument_group("thresholds")
    d = Config()
    t.add_argument("--ssh-threshold", type=int, default=d.ssh_bruteforce_threshold,
                   help="failed SSH logins from one IP that count as brute force (default: %(default)s)")
    t.add_argument("--ssh-window", type=int, default=int(d.ssh_bruteforce_window.total_seconds() // 60),
                   metavar="MIN", help="time window for --ssh-threshold in minutes (default: %(default)s)")
    t.add_argument("--scan-threshold", type=int, default=d.web_scan_threshold,
                   help="distinct 404 paths from one IP that count as a scan (default: %(default)s)")
    t.add_argument("--http-threshold", type=int, default=d.http_bruteforce_threshold,
                   help="login POSTs from one IP that count as brute force (default: %(default)s)")
    t.add_argument("--work-hours", type=_hours, default=d.work_hours, metavar="START-END",
                   help="logins outside these hours are flagged (default: 08-20)")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    only = None
    if args.rules:
        only = {r.strip() for r in args.rules.split(",") if r.strip()}
        unknown = only - RULES.keys()
        if unknown:
            parser.error(f"unknown rule(s): {', '.join(sorted(unknown))}")

    results = []
    for path in args.files:
        if not path.is_file():
            parser.error(f"{path}: no such file")
        try:
            results.append(parse_file(path, args.format, args.year))
        except ValueError as exc:
            parser.error(str(exc))

    config = Config(
        ssh_bruteforce_threshold=args.ssh_threshold,
        ssh_bruteforce_window=timedelta(minutes=args.ssh_window),
        web_scan_threshold=args.scan_threshold,
        http_bruteforce_threshold=args.http_threshold,
        work_hours=args.work_hours,
    )
    events = [e for r in results for e in r.events]
    findings = [f for f in run_rules(events, config, only) if f.severity >= args.min_severity]
    summary = Summary(files=results, findings=findings, generated_at=datetime.now())

    report = args.report
    if report is None:
        suffix = args.output.suffix.lower() if args.output else ""
        report = {".json": "json", ".html": "html", ".htm": "html"}.get(suffix, "text")

    if report == "json":
        out = render_json(summary)
    elif report == "html":
        out = render_html(summary)
    else:
        use_color = (not args.no_color and args.output is None and sys.stdout.isatty()
                     and "NO_COLOR" not in os.environ)
        if use_color and os.name == "nt":
            os.system("")  # turns on ANSI escape handling in the Windows console
        out = render_text(summary, color=use_color, verbose=args.verbose)

    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"Report written to {args.output} ({len(findings)} findings)", file=sys.stderr)
    else:
        sys.stdout.write(out)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in findings):
        return 1
    return 0
