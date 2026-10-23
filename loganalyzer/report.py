"""Render findings as a terminal report, JSON, or a standalone HTML page."""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from . import __version__
from .models import Finding, Severity
from .parsers import ParseResult


@dataclass
class Summary:
    files: list[ParseResult]
    findings: list[Finding]
    generated_at: datetime

    @property
    def total_events(self) -> int:
        return sum(len(f.events) for f in self.files)

    def by_severity(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s.name.lower(): counts.get(s, 0) for s in sorted(Severity, reverse=True)}

    def top_ips(self, n: int = 5) -> list[tuple[str, int, Severity]]:
        """IPs ranked by worst finding, then by number of findings."""
        worst: dict[str, Severity] = {}
        counts: Counter[str] = Counter()
        for f in self.findings:
            if f.ip:
                counts[f.ip] += 1
                worst[f.ip] = max(worst.get(f.ip, Severity.INFO), f.severity)
        ranked = sorted(counts, key=lambda ip: (-worst[ip], -counts[ip], ip))
        return [(ip, counts[ip], worst[ip]) for ip in ranked[:n]]


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------

COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[37m",
}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def render_text(summary: Summary, color: bool = False, verbose: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    lines = [c(BOLD, "Log analysis report"), ""]
    for f in summary.files:
        lines.append(f"  {f.path}  [{f.fmt}]  {f.total_lines} lines, {len(f.events)} events"
                     + (f", {f.unparsed_lines} unrecognised" if f.unparsed_lines else ""))
    lines.append("")

    if not summary.findings:
        lines.append(c(BOLD, "No findings.") + " Nothing suspicious at the current thresholds.")
        return "\n".join(lines) + "\n"

    counts = "  ".join(c(COLORS[Severity[name.upper()]], f"{name.upper()} {n}")
                       for name, n in summary.by_severity().items() if n)
    lines += [f"{len(summary.findings)} findings:  {counts}", ""]

    for i, f in enumerate(summary.findings, 1):
        tag = c(COLORS[f.severity], f"[{f.severity.name}]")
        lines.append(f"{i:>2}. {tag} {c(BOLD, f.title)}")
        lines.append(f"    {f.description}")
        span = f.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        if f.last_seen != f.first_seen:
            span += " -> " + f.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(c(DIM, f"    rule={f.rule}  events={f.count}  {span}"))
        if verbose:
            lines += [c(DIM, f"      | {ev}") for ev in f.evidence]
        lines.append("")

    top = summary.top_ips()
    if top:
        lines.append(c(BOLD, "Top offending IPs"))
        for ip, n, worst in top:
            lines.append(f"  {ip:<40} {n} finding(s), worst {c(COLORS[worst], worst.name)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(summary: Summary) -> str:
    return json.dumps(
        {
            "generator": f"loganalyzer {__version__}",
            "generated_at": summary.generated_at.isoformat(timespec="seconds"),
            "files": [
                {"path": f.path, "format": f.fmt, "lines": f.total_lines, "events": len(f.events),
                 "unrecognised_lines": f.unparsed_lines}
                for f in summary.files
            ],
            "summary": summary.by_severity(),
            "findings": [f.to_dict() for f in summary.findings],
        },
        indent=2,
    ) + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log analysis report</title>
<style>
:root {{
  --bg: #f6f7f9; --card: #fff; --text: #1d2330; --muted: #5d6677; --border: #dde1e8; --code: #f0f2f5;
  --critical: #b3123b; --high: #d4471f; --medium: #b07d00; --low: #1f7fa8; --info: #6b7280;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg: #12151b; --card: #1b2029; --text: #e6e9ef; --muted: #9aa3b2; --border: #2c3340; --code: #141820;
          --critical: #ff5c7f; --high: #ff7a50; --medium: #e8b730; --low: #4fb6e0; --info: #9aa3b2; }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--text);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 1000px; margin: 0 auto; padding: 32px 16px 64px; }}
h1 {{ margin: 0 0 4px; font-size: 26px; }}
.meta {{ color: var(--muted); margin-bottom: 24px; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.tile {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; }}
.tile b {{ display: block; font-size: 26px; }}
.tile span {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: .04em; }}
section {{ margin-bottom: 28px; }}
h2 {{ font-size: 18px; margin: 0 0 12px; }}
table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border);
        border-radius: 10px; overflow: hidden; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }}
th {{ color: var(--muted); font-weight: 600; }}
details {{ background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--sev);
          border-radius: 10px; margin-bottom: 10px; }}
summary {{ cursor: pointer; padding: 12px 16px; display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }}
.badge {{ color: var(--sev); font-weight: 700; font-size: 12px; letter-spacing: .05em; min-width: 72px; }}
.title {{ font-weight: 600; flex: 1; }}
.when {{ color: var(--muted); font-size: 13px; }}
.body {{ padding: 0 16px 14px; }}
.body p {{ margin: 0 0 8px; }}
pre {{ background: var(--code); border-radius: 6px; padding: 10px; overflow-x: auto; font-size: 12.5px; margin: 0; }}
.sev-critical {{ --sev: var(--critical); }} .sev-high {{ --sev: var(--high); }} .sev-medium {{ --sev: var(--medium); }}
.sev-low {{ --sev: var(--low); }} .sev-info {{ --sev: var(--info); }}
.empty {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
</style>
</head>
<body>
<main>
<h1>Log analysis report</h1>
<div class="meta">Generated {generated} by loganalyzer {version} &middot; {events} events from {nfiles} file(s)</div>
<div class="tiles">{tiles}</div>
<section><h2>Findings</h2>{findings}</section>
{top_ips}
<section><h2>Input files</h2>
<table><tr><th>File</th><th>Format</th><th>Lines</th><th>Events</th><th>Unrecognised</th></tr>{files}</table>
</section>
</main>
</body>
</html>
"""


def render_html(summary: Summary) -> str:
    e = html.escape
    tiles = "".join(
        f'<div class="tile sev-{name}"><b style="color:var(--sev)">{n}</b><span>{name}</span></div>'
        for name, n in summary.by_severity().items()
    )
    if summary.findings:
        items = []
        for i, f in enumerate(summary.findings):
            sev = f.severity.name.lower()
            span = f.first_seen.strftime("%Y-%m-%d %H:%M:%S")
            if f.last_seen != f.first_seen:
                span += " &rarr; " + f.last_seen.strftime("%H:%M:%S" if f.last_seen.date() == f.first_seen.date()
                                                           else "%Y-%m-%d %H:%M:%S")
            items.append(
                f'<details class="sev-{sev}"{" open" if f.severity >= Severity.CRITICAL else ""}>'
                f'<summary><span class="badge">{sev.upper()}</span><span class="title">{e(f.title)}</span>'
                f'<span class="when">{span}</span></summary>'
                f'<div class="body"><p>{e(f.description)}</p>'
                f'<p class="when">rule <code>{e(f.rule)}</code> &middot; {f.count} event(s)</p>'
                f'<pre>{e(chr(10).join(f.evidence))}</pre></div></details>'
            )
        findings = "".join(items)
    else:
        findings = '<div class="empty">No findings. Nothing suspicious at the current thresholds.</div>'

    top = summary.top_ips(10)
    top_ips = ""
    if top:
        rows = "".join(
            f'<tr><td><code>{e(ip)}</code></td><td>{n}</td>'
            f'<td class="sev-{w.name.lower()}" style="color:var(--sev);font-weight:600">{w.name}</td></tr>'
            for ip, n, w in top
        )
        top_ips = (f"<section><h2>Top offending IPs</h2><table><tr><th>IP</th><th>Findings</th>"
                   f"<th>Worst severity</th></tr>{rows}</table></section>")

    files = "".join(
        f"<tr><td>{e(f.path)}</td><td>{f.fmt}</td><td>{f.total_lines}</td><td>{len(f.events)}</td>"
        f"<td>{f.unparsed_lines}</td></tr>"
        for f in summary.files
    )
    return HTML_TEMPLATE.format(
        generated=summary.generated_at.strftime("%Y-%m-%d %H:%M"),
        version=__version__,
        events=summary.total_events,
        nfiles=len(summary.files),
        tiles=tiles,
        findings=findings,
        top_ips=top_ips,
        files=files,
    )
