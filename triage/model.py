from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TimelineEvent:
    timestamp: datetime          # always UTC
    source: str                  # "evtx" | "prefetch"
    host: str
    event_type: str              # short label, e.g. "logon", "execution"
    summary: str
    user: str = ""
    details: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    tz_assumed: bool = False
    source_ref: str = ""         # file:line for traceability back to the export
