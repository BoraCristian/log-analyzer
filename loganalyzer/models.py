"""Core data types shared by parsers, detectors and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from None

    def bump(self) -> Severity:
        return Severity(min(self + 1, Severity.CRITICAL))


@dataclass
class Event:
    """One normalised log line.

    Timestamps are naive datetimes in the wall-clock time written in the log;
    any timezone offset is dropped so events from different files can be sorted together.
    """

    timestamp: datetime
    source: str  # "auth" or "web"
    action: str  # e.g. ssh_failed, ssh_success, ssh_invalid_user, sudo, sudo_failed, http
    ip: str | None = None
    user: str | None = None
    # web-only fields
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    # anything else a parser wants to keep (sudo target user, command, auth method...)
    extra: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    file: str = ""
    line_no: int = 0

    def location(self) -> str:
        return f"{self.file}:{self.line_no}" if self.file else f"line {self.line_no}"


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int
    ip: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.name.lower(),
            "title": self.title,
            "description": self.description,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence": self.evidence,
        }
