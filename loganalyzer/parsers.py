"""Parsers that turn raw log lines into Event objects.

Supported formats:
  auth - Linux syslog auth logs (/var/log/auth.log, /var/log/secure), classic
         "Oct 22 10:15:32" timestamps or RFC 3339 ones written by newer rsyslog.
  web  - Apache / nginx access logs in "combined" or "common" format.
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .models import Event

# ---------------------------------------------------------------------------
# auth.log
# ---------------------------------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
SSH_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from " + IP + r" port \d+"
)
SSH_ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP + r" port \d+")
SSH_INVALID_RE = re.compile(r"^Invalid user (?P<user>.*?) from " + IP + r"(?: port \d+)?$")
REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : (?P<body>.*)$")
SUDO_FIELD_RE = re.compile(r"(?P<key>TTY|PWD|USER|COMMAND)=(?P<value>.*?)(?: ; |$)")


def _parse_syslog_ts(text: str, year: int | None, now: datetime) -> datetime:
    if text[0].isdigit():
        ts = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return ts.replace(tzinfo=None)
    # Classic syslog has no year. Use the one we were given, or guess: the current
    # year unless that would put the event in the future (e.g. December logs read in January).
    ts = datetime.strptime(f"{year or now.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    if year is None and ts > now + timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts


def _auth_events(msg: str, prog: str) -> Iterator[tuple[str, dict]]:
    """Yield (action, fields) for one syslog message body."""
    repeated = REPEATED_RE.match(msg)
    if repeated:
        for _ in range(int(repeated["n"])):
            yield from _auth_events(repeated["msg"], prog)
        return

    if prog.startswith("sshd"):
        if m := SSH_FAILED_RE.search(msg):
            yield "ssh_failed", {
                "user": m["user"],
                "ip": m["ip"],
                "extra": {"method": m["method"], "invalid_user": bool(m["invalid"])},
            }
        elif m := SSH_ACCEPTED_RE.search(msg):
            yield "ssh_success", {"user": m["user"], "ip": m["ip"], "extra": {"method": m["method"]}}
        elif m := SSH_INVALID_RE.search(msg):
            yield "ssh_invalid_user", {"user": m["user"], "ip": m["ip"]}
    elif prog == "sudo":
        m = SUDO_RE.match(msg)
        if not m:
            return
        fields = {f["key"]: f["value"] for f in SUDO_FIELD_RE.finditer(m["body"])}
        extra = {"target_user": fields.get("USER", "root"), "command": fields.get("COMMAND", "")}
        if "incorrect password attempt" in m["body"] or "NOT in sudoers" in m["body"]:
            yield "sudo_failed", {"user": m["user"], "extra": extra}
        elif "COMMAND" in fields:
            yield "sudo", {"user": m["user"], "extra": extra}


def parse_auth_line(line: str, year: int | None = None, now: datetime | None = None) -> list[Event]:
    m = SYSLOG_RE.match(line)
    if not m:
        return []
    ts = _parse_syslog_ts(m["ts"], year, now or datetime.now())
    return [
        Event(timestamp=ts, source="auth", action=action, extra={"host": m["host"], **f.pop("extra", {})}, raw=line, **f)
        for action, f in _auth_events(m["msg"], m["prog"])
    ]


# ---------------------------------------------------------------------------
# Apache / nginx access logs
# ---------------------------------------------------------------------------

QUOTED = r'"(?P<{}>(?:[^"\\]|\\.)*)"'
WEB_RE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    + QUOTED.format("request")
    + r" (?P<status>\d{3}) (?P<size>\S+)"
    + r"(?: " + QUOTED.format("referer") + " " + QUOTED.format("ua") + ")?"
)


def parse_web_line(line: str, year: int | None = None, now: datetime | None = None) -> list[Event]:
    m = WEB_RE.match(line)
    if not m:
        return []
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return []
    parts = m["request"].split(" ")
    if len(parts) == 3:
        method, path = parts[0], parts[1]
    else:  # malformed request line, e.g. a raw TLS handshake or "-"
        method, path = None, m["request"]
    ua = m["ua"]
    return [
        Event(
            timestamp=ts,
            source="web",
            action="http",
            ip=m["ip"],
            user=None if m["user"] == "-" else m["user"],
            method=method,
            path=path,
            status=int(m["status"]),
            user_agent=None if ua in (None, "-") else ua.replace('\\"', '"'),
            raw=line,
        )
    ]


# ---------------------------------------------------------------------------
# File handling and format detection
# ---------------------------------------------------------------------------

LineParser = Callable[..., list[Event]]
PARSERS: dict[str, LineParser] = {"auth": parse_auth_line, "web": parse_web_line}
FORMAT_SIGNATURES = {"auth": SYSLOG_RE, "web": WEB_RE}


@dataclass
class ParseResult:
    path: str
    fmt: str
    total_lines: int = 0
    unparsed_lines: int = 0
    events: list[Event] = field(default_factory=list)


def detect_format(lines: Iterable[str], sample_size: int = 50) -> str | None:
    scores = dict.fromkeys(FORMAT_SIGNATURES, 0)
    seen = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        for fmt, regex in FORMAT_SIGNATURES.items():
            if regex.match(line):
                scores[fmt] += 1
        seen += 1
        if seen >= sample_size:
            break
    best = max(scores, key=scores.get)
    return best if scores[best] else None


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> ParseResult:
    path = Path(path)
    if fmt == "auto":
        with _open(path) as fh:
            detected = detect_format(fh)
        if detected is None:
            raise ValueError(f"{path}: could not detect log format (use --format auth|web)")
        fmt = detected
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt!r}")

    parser = PARSERS[fmt]
    result = ParseResult(path=str(path), fmt=fmt)
    now = datetime.now()
    signature = FORMAT_SIGNATURES[fmt]
    with _open(path) as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            result.total_lines += 1
            if not signature.match(line):
                result.unparsed_lines += 1
                continue
            for event in parser(line, year=year, now=now):
                event.file = path.name
                event.line_no = line_no
                result.events.append(event)
    return result
