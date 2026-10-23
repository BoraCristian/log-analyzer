"""Detection rules.

Every rule is a function ``rule(events, config) -> list[Finding]`` registered with
``@rule``. Events are always passed sorted by timestamp.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable
from urllib.parse import unquote_plus

from .models import Event, Finding, Severity


@dataclass
class Config:
    ssh_bruteforce_threshold: int = 5  # failed logins from one IP ...
    ssh_bruteforce_window: timedelta = timedelta(minutes=10)  # ... inside this window
    enumeration_threshold: int = 5  # distinct usernames tried by one IP
    work_hours: tuple[int, int] = (8, 20)  # logins outside [start, end) are "off hours"
    sudo_failure_threshold: int = 3
    web_scan_threshold: int = 20  # distinct 404 paths from one IP ...
    web_scan_window: timedelta = timedelta(minutes=10)
    http_bruteforce_threshold: int = 10  # POSTs to a login page from one IP ...
    http_bruteforce_window: timedelta = timedelta(minutes=5)
    max_evidence: int = 5


Rule = Callable[[list[Event], Config], list[Finding]]
RULES: dict[str, Rule] = {}


def rule(name: str):
    def register(fn: Rule) -> Rule:
        RULES[name] = fn
        return fn

    return register


def run_rules(events: Iterable[Event], config: Config | None = None, only: Iterable[str] | None = None) -> list[Finding]:
    config = config or Config()
    ordered = sorted(events, key=lambda e: e.timestamp)
    findings: list[Finding] = []
    for name, fn in RULES.items():
        if only is None or name in only:
            findings.extend(fn(ordered, config))
    findings.sort(key=lambda f: (-f.severity, f.first_seen))
    return findings


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def group_by(events: Iterable[Event], key: Callable[[Event], object]) -> dict[object, list[Event]]:
    groups: dict[object, list[Event]] = defaultdict(list)
    for e in events:
        k = key(e)
        if k is not None:
            groups[k].append(e)
    return groups


def busiest_window(events: list[Event], window: timedelta) -> tuple[int, datetime, datetime]:
    """Largest number of events falling inside any span of ``window`` (two-pointer sweep)."""
    best, best_start, best_end = 0, events[0].timestamp, events[0].timestamp
    start = 0
    for end, e in enumerate(events):
        while e.timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > best:
            best, best_start, best_end = end - start + 1, events[start].timestamp, e.timestamp
    return best, best_start, best_end


def evidence(events: list[Event], limit: int) -> list[str]:
    """First few raw lines plus the last one, so the start and end of an attack are both visible."""
    # one "message repeated N times" line expands to N events; show it once
    seen: set[tuple[str, int, str]] = set()
    unique = []
    for e in events:
        key = (e.file, e.line_no, e.raw)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    events = unique
    if len(events) <= limit:
        chosen = events
    else:
        chosen = events[: limit - 1] + [events[-1]]
    return [f"{e.location()}  {e.raw}" for e in chosen]


def finding(rule_name: str, severity: Severity, title: str, description: str, events: list[Event],
            config: Config, ip: str | None = None) -> Finding:
    return Finding(
        rule=rule_name,
        severity=severity,
        title=title,
        description=description,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        count=len(events),
        ip=ip,
        evidence=evidence(events, config.max_evidence),
    )


def fmt_window(window: timedelta) -> str:
    minutes = int(window.total_seconds() // 60)
    return f"{minutes} min" if minutes else f"{int(window.total_seconds())} s"


# ---------------------------------------------------------------------------
# auth.log rules
# ---------------------------------------------------------------------------


def _bruteforce_ips(events: list[Event], config: Config) -> dict[str, tuple[list[Event], int]]:
    failed = group_by((e for e in events if e.action == "ssh_failed"), lambda e: e.ip)
    hits = {}
    for ip, fails in failed.items():
        peak, _, _ = busiest_window(fails, config.ssh_bruteforce_window)
        if peak >= config.ssh_bruteforce_threshold:
            hits[ip] = (fails, peak)
    return hits


@rule("ssh_bruteforce")
def ssh_bruteforce(events: list[Event], config: Config) -> list[Finding]:
    out = []
    for ip, (fails, peak) in _bruteforce_ips(events, config).items():
        users = sorted({e.user for e in fails})
        shown = ", ".join(users[:5]) + (f" (+{len(users) - 5} more)" if len(users) > 5 else "")
        out.append(finding(
            "ssh_bruteforce", Severity.HIGH, f"SSH brute force from {ip}",
            f"{len(fails)} failed SSH logins, peaking at {peak} within {fmt_window(config.ssh_bruteforce_window)}. "
            f"Accounts targeted: {shown}.",
            fails, config, ip,
        ))
    return out


@rule("ssh_bruteforce_success")
def ssh_bruteforce_success(events: list[Event], config: Config) -> list[Finding]:
    """A successful login from an IP that was brute forcing: likely a compromised account."""
    out = []
    attackers = _bruteforce_ips(events, config)
    successes = group_by((e for e in events if e.action == "ssh_success"), lambda e: e.ip)
    for ip, (fails, _) in attackers.items():
        after = [s for s in successes.get(ip, []) if s.timestamp >= fails[0].timestamp]
        if not after:
            continue
        users = ", ".join(sorted({s.user for s in after}))
        out.append(finding(
            "ssh_bruteforce_success", Severity.CRITICAL, f"Successful login after brute force from {ip}",
            f"{ip} logged in as {users} after {len(fails)} failed attempts. Treat the account as compromised: "
            "check what that session did, rotate its credentials and block the IP.",
            sorted(fails[-2:] + after, key=lambda e: e.timestamp), config, ip,
        ))
    return out


@rule("user_enumeration")
def user_enumeration(events: list[Event], config: Config) -> list[Finding]:
    attempts = group_by(
        (e for e in events if e.action in ("ssh_failed", "ssh_invalid_user")), lambda e: e.ip
    )
    out = []
    for ip, evs in attempts.items():
        users = sorted({e.user for e in evs})
        if len(users) < config.enumeration_threshold:
            continue
        invalid = sorted({e.user for e in evs if e.action == "ssh_invalid_user" or e.extra.get("invalid_user")})
        out.append(finding(
            "user_enumeration", Severity.MEDIUM, f"Username enumeration / password spraying from {ip}",
            f"{len(users)} different usernames tried ({len(invalid)} do not exist on the host): "
            f"{', '.join(users[:10])}{' ...' if len(users) > 10 else ''}.",
            evs, config, ip,
        ))
    return out


@rule("off_hours_login")
def off_hours_login(events: list[Event], config: Config) -> list[Finding]:
    start, end = config.work_hours

    def off_hours(ts: datetime) -> bool:
        h = ts.hour
        return not (start <= h < end) if start < end else (end <= h < start)

    logins = [e for e in events if e.action == "ssh_success" and off_hours(e.timestamp)]
    out = []
    for (user, ip), evs in group_by(logins, lambda e: (e.user, e.ip)).items():
        times = ", ".join(e.timestamp.strftime("%H:%M") for e in evs[:5])
        out.append(finding(
            "off_hours_login", Severity.LOW, f"Off-hours login: {user} from {ip}",
            f"{len(evs)} successful login(s) outside working hours ({start:02d}:00-{end:02d}:00) at {times}.",
            evs, config, ip,
        ))
    return out


SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "su", "tcsh"}


@rule("sudo_root_shell")
def sudo_root_shell(events: list[Event], config: Config) -> list[Finding]:
    def is_shell(e: Event) -> bool:
        cmd = e.extra.get("command", "").split()
        return bool(cmd) and cmd[0].rsplit("/", 1)[-1] in SHELLS

    shells = [e for e in events if e.action == "sudo" and e.extra.get("target_user") == "root" and is_shell(e)]
    return [
        finding(
            "sudo_root_shell", Severity.MEDIUM, f"Interactive root shell via sudo by {user}",
            f"{user} opened a root shell {len(evs)} time(s) ({evs[0].extra['command']}). "
            "Commands typed in that shell are not logged by sudo.",
            evs, config,
        )
        for user, evs in group_by(shells, lambda e: e.user).items()
    ]


@rule("sudo_failures")
def sudo_failures(events: list[Event], config: Config) -> list[Finding]:
    out = []
    for user, evs in group_by((e for e in events if e.action == "sudo_failed"), lambda e: e.user).items():
        if len(evs) >= config.sudo_failure_threshold:
            out.append(finding(
                "sudo_failures", Severity.MEDIUM, f"Repeated sudo failures by {user}",
                f"{len(evs)} failed sudo attempts (wrong password or user not in sudoers).",
                evs, config,
            ))
    return out


# ---------------------------------------------------------------------------
# web access log rules
# ---------------------------------------------------------------------------

# (severity, description, pattern) - matched against the URL-decoded, lower-cased request path
ATTACK_PATTERNS: dict[str, tuple[Severity, str, re.Pattern]] = {
    "sql_injection": (Severity.HIGH, "SQL injection", re.compile(
        r"union(\s|/\*.*?\*/)+(all\s+)?select|'\s*(or|and)\s*'?\d*'?\s*=|\bor\s+\d+\s*=\s*\d+"
        r"|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|waitfor\s+delay|;\s*drop\s+table|'\s*--")),
    "xss": (Severity.MEDIUM, "Cross-site scripting (XSS)", re.compile(
        r"<\s*script|javascript:|on(error|load|mouseover|focus)\s*=|<\s*svg|<\s*iframe|alert\s*\(|document\.cookie")),
    "path_traversal": (Severity.HIGH, "Path traversal / file inclusion", re.compile(
        r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|c:\\windows|win\.ini|boot\.ini|php://(filter|input)")),
    "command_injection": (Severity.HIGH, "OS command injection", re.compile(
        r"(;|\||`|\$\(|&&)\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|python|perl)\b")),
    "log4shell": (Severity.CRITICAL, "Log4Shell (CVE-2021-44228)", re.compile(r"\$\{\s*jndi\s*:")),
    "sensitive_files": (Severity.LOW, "Sensitive file probing", re.compile(
        r"/\.env\b|/\.git(/|$)|/\.svn/|/\.ht(access|passwd)|wp-config\.php|/\.aws/|id_rsa|\.(sql|bak|old|swp)$"
        r"|/phpmyadmin|/server-status|/actuator(/|$)")),
}


def _decode(path: str) -> str:
    # decode twice to catch double-encoded payloads like %252e%252e%252f
    return unquote_plus(unquote_plus(path)).lower()


@rule("web_attack")
def web_attack(events: list[Event], config: Config) -> list[Finding]:
    matches: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.source != "web":
            continue
        target = _decode(e.path or "")
        ua = (e.user_agent or "").lower()
        for category, (_, _, pattern) in ATTACK_PATTERNS.items():
            # header-based exploits (Log4Shell) often arrive in the User-Agent
            if pattern.search(target) or (category == "log4shell" and pattern.search(ua)):
                matches[(e.ip, category)].append(e)

    out = []
    for (ip, category), evs in matches.items():
        severity, label, _ = ATTACK_PATTERNS[category]
        ok = [e for e in evs if e.status and 200 <= e.status < 300]
        desc = f"{len(evs)} request(s) carrying {label} payloads."
        if ok:
            desc += f" {len(ok)} got a 2xx response, so check whether the attack worked."
            if category == "sensitive_files":
                severity = Severity.HIGH  # the file was actually served
                desc += " Exposed: " + ", ".join(sorted({e.path for e in ok})[:5]) + "."
        out.append(finding("web_attack", severity, f"{label} from {ip}", desc, evs, config, ip))
    return out


@rule("web_scan")
def web_scan(events: list[Event], config: Config) -> list[Finding]:
    not_found = group_by((e for e in events if e.source == "web" and e.status == 404), lambda e: e.ip)
    out = []
    for ip, evs in not_found.items():
        # count each path once so a broken link refreshed 50 times is not a "scan"
        seen, unique = set(), []
        for e in evs:
            if e.path not in seen:
                seen.add(e.path)
                unique.append(e)
        if len(unique) < config.web_scan_threshold:
            continue
        peak, _, _ = busiest_window(unique, config.web_scan_window)
        if peak >= config.web_scan_threshold:
            out.append(finding(
                "web_scan", Severity.MEDIUM, f"Directory / vulnerability scan from {ip}",
                f"{len(unique)} distinct paths returned 404, up to {peak} within "
                f"{fmt_window(config.web_scan_window)}: looks like automated content discovery.",
                unique, config, ip,
            ))
    return out


SCANNER_AGENTS = {
    "sqlmap": "sqlmap", "nikto": "Nikto", "nmap": "Nmap", "masscan": "masscan", "zgrab": "ZGrab",
    "gobuster": "Gobuster", "dirbuster": "DirBuster", "dirb": "dirb", "ffuf": "ffuf", "feroxbuster": "feroxbuster",
    "wpscan": "WPScan", "nuclei": "Nuclei", "hydra": "Hydra", "acunetix": "Acunetix", "netsparker": "Netsparker",
    "openvas": "OpenVAS", "whatweb": "WhatWeb", "censysinspect": "Censys",
}
SCRIPT_AGENTS = {"curl": "curl", "wget": "Wget", "python-requests": "python-requests",
                 "python-urllib": "Python urllib", "go-http-client": "Go http client", "libwww-perl": "libwww-perl"}


@rule("suspicious_user_agent")
def suspicious_user_agent(events: list[Event], config: Config) -> list[Finding]:
    hits: dict[tuple[str, str, Severity], list[Event]] = defaultdict(list)
    for e in events:
        if e.source != "web":
            continue
        ua = (e.user_agent or "").lower()
        if not ua:
            hits[(e.ip, "an empty User-Agent", Severity.INFO)].append(e)
            continue
        for needle, name in SCANNER_AGENTS.items():
            if needle in ua:
                hits[(e.ip, name, Severity.MEDIUM)].append(e)
                break
        else:
            for needle, name in SCRIPT_AGENTS.items():
                if ua.startswith(needle):
                    hits[(e.ip, name, Severity.INFO)].append(e)
                    break

    return [
        finding(
            "suspicious_user_agent", severity, f"{tool} traffic from {ip}",
            f"{len(evs)} request(s) sent with {tool}"
            + (" (a known security scanner)." if severity >= Severity.MEDIUM else " (scripted client, not a browser)."),
            evs, config, ip,
        )
        for (ip, tool, severity), evs in hits.items()
    ]


LOGIN_PATH_RE = re.compile(r"login|signin|sign-in|logon|wp-login\.php|/auth|/session|xmlrpc\.php|/admin", re.I)


@rule("http_bruteforce")
def http_bruteforce(events: list[Event], config: Config) -> list[Finding]:
    posts = group_by(
        (e for e in events if e.source == "web" and e.method == "POST" and LOGIN_PATH_RE.search(e.path or "")),
        lambda e: e.ip,
    )
    out = []
    for ip, evs in posts.items():
        peak, _, _ = busiest_window(evs, config.http_bruteforce_window)
        if peak < config.http_bruteforce_threshold:
            continue
        paths = ", ".join(sorted({e.path.split("?")[0] for e in evs})[:3])
        # a redirect after a run of failures usually means the login went through
        redirects = [e for e in evs if e.status in (301, 302, 303)]
        severity = Severity.CRITICAL if redirects and len(evs) - len(redirects) >= config.http_bruteforce_threshold else Severity.HIGH
        desc = (f"{len(evs)} login POSTs to {paths}, up to {peak} within {fmt_window(config.http_bruteforce_window)}.")
        if severity is Severity.CRITICAL:
            desc += f" {len(redirects)} ended in a redirect, which often means a successful login."
        out.append(finding("http_bruteforce", severity, f"Web login brute force from {ip}", desc, evs, config, ip))
    return out
