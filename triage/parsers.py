"""Parsers for CSV exports of Windows artifacts.

Input formats are deliberately simple and documented in docs/input-formats.md.
They mirror the columns analysts typically get from EVTX and Prefetch export
tools, without depending on any one tool's exact schema.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .model import TimelineEvent
from .timestamps import TimestampError, parse_ts

LOGON_TYPES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service",
    "7": "unlock", "8": "network-cleartext", "9": "new-credentials",
    "10": "remote-interactive (RDP)", "11": "cached-interactive",
}

EVTX_REQUIRED = {"TimeCreated", "EventId", "Computer"}
PREFETCH_REQUIRED = {"ExecutableName", "LastRun", "SourceFilename"}


class ParseWarning(list):
    """Collects non-fatal row problems instead of crashing mid-triage."""


def _check_columns(path: Path, header: list[str] | None, required: set[str]) -> None:
    missing = required - set(header or [])
    if missing:
        raise ValueError(f"{path}: missing required columns {sorted(missing)}")


def _evtx_summary(row: dict) -> tuple[str, str]:
    eid = row["EventId"].strip()
    user = row.get("TargetUser", "").strip()
    src = row.get("SourceIp", "").strip()
    proc = row.get("ProcessName", "").strip()
    cmd = row.get("CommandLine", "").strip()
    svc = row.get("ServiceName", "").strip()

    if eid == "4624":
        lt = LOGON_TYPES.get(row.get("LogonType", "").strip(), row.get("LogonType", "?"))
        return "logon", f"Successful logon ({lt}) for {user or '?'}" + (f" from {src}" if src else "")
    if eid == "4625":
        return "logon-failure", f"Failed logon for {user or '?'}" + (f" from {src}" if src else "")
    if eid == "4688":
        return "process", f"Process created: {proc}" + (f" | {cmd}" if cmd else "")
    if eid == "4720":
        return "account", f"User account created: {user}"
    if eid == "4732":
        return "account", f"Member added to security-enabled local group: {user} -> {row.get('Details', '').strip()}"
    if eid == "7045":
        return "service", f"Service installed: {svc} ({row.get('Details', '').strip()})"
    if eid == "1102":
        return "log-cleared", "Security audit log was cleared"
    if eid == "4698":
        return "scheduled-task", f"Scheduled task created: {row.get('Details', '').strip()}"
    return "event", f"Event {eid}: {row.get('Details', '').strip()}"


def parse_evtx_csv(path: str | Path, assume_tz: str = "UTC",
                   warnings: ParseWarning | None = None) -> list[TimelineEvent]:
    path = Path(path)
    events: list[TimelineEvent] = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        _check_columns(path, reader.fieldnames, EVTX_REQUIRED)
        for lineno, row in enumerate(reader, start=2):
            try:
                ts = parse_ts(row["TimeCreated"], assume_tz)
            except TimestampError as exc:
                if warnings is not None:
                    warnings.append(f"{path.name}:{lineno}: skipped ({exc})")
                continue
            etype, summary = _evtx_summary(row)
            events.append(TimelineEvent(
                timestamp=ts.utc,
                source="evtx",
                host=row["Computer"].strip(),
                event_type=etype,
                summary=summary,
                user=row.get("TargetUser", "").strip(),
                details={k: v for k, v in row.items() if v and k not in ("TimeCreated",)},
                tz_assumed=ts.assumed_tz,
                source_ref=f"{path.name}:{lineno}",
            ))
    return events


def parse_prefetch_csv(path: str | Path, host: str = "UNKNOWN",
                       warnings: ParseWarning | None = None) -> list[TimelineEvent]:
    """Each Prefetch row can yield up to 8 execution events (LastRun + PreviousRun0-6).

    Prefetch timestamps are stored as UTC FILETIMEs, so no timezone assumption
    is applied here.
    """
    path = Path(path)
    events: list[TimelineEvent] = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        _check_columns(path, reader.fieldnames, PREFETCH_REQUIRED)
        run_cols = ["LastRun"] + [c for c in (reader.fieldnames or []) if c.startswith("PreviousRun")]
        for lineno, row in enumerate(reader, start=2):
            exe = row["ExecutableName"].strip()
            for col in run_cols:
                raw = (row.get(col) or "").strip()
                if not raw:
                    continue
                try:
                    ts = parse_ts(raw, "UTC")
                except TimestampError as exc:
                    if warnings is not None:
                        warnings.append(f"{path.name}:{lineno}:{col}: skipped ({exc})")
                    continue
                label = "last run" if col == "LastRun" else "previous run"
                events.append(TimelineEvent(
                    timestamp=ts.utc,
                    source="prefetch",
                    host=row.get("Host", "").strip() or host,
                    event_type="execution",
                    summary=f"{exe} executed ({label}; run count {row.get('RunCount', '?')})",
                    details={"executable": exe, "prefetch_file": row["SourceFilename"],
                             "run_count": row.get("RunCount", "")},
                    tz_assumed=False,
                    source_ref=f"{path.name}:{lineno}:{col}",
                ))
    return events
