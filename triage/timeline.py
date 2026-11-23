from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .model import TimelineEvent
from .timestamps import fmt_utc

CSV_FIELDS = ["timestamp_utc", "host", "source", "event_type", "user",
              "summary", "tags", "tz_assumed", "source_ref"]


def build_timeline(*event_lists: list[TimelineEvent],
                   start: datetime | None = None,
                   end: datetime | None = None,
                   tagged_only: bool = False) -> list[TimelineEvent]:
    merged = [e for lst in event_lists for e in lst]
    if start:
        merged = [e for e in merged if e.timestamp >= start]
    if end:
        merged = [e for e in merged if e.timestamp <= end]
    if tagged_only:
        merged = [e for e in merged if e.tags]
    # Stable sort: ties keep source order, then evtx before prefetch for readability
    merged.sort(key=lambda e: (e.timestamp, e.source != "evtx"))
    return merged


def write_csv(events: list[TimelineEvent], path: str | Path) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for e in events:
            w.writerow({
                "timestamp_utc": fmt_utc(e.timestamp), "host": e.host, "source": e.source,
                "event_type": e.event_type, "user": e.user, "summary": e.summary,
                "tags": ";".join(e.tags), "tz_assumed": e.tz_assumed, "source_ref": e.source_ref,
            })


def render_markdown(events: list[TimelineEvent], title: str = "Investigation timeline") -> str:
    lines = [f"# {title}", "",
             f"{len(events)} events, {sum(1 for e in events if e.tags)} tagged. All times UTC.", ""]
    if any(e.tz_assumed for e in events):
        lines += ["> Rows marked `*` had no timezone in the source; the `--evtx-tz` "
                  "assumption was applied. Verify against the host's configured timezone.", ""]
    lines += ["| Time (UTC) | Host | Source | Summary | Tags |", "|---|---|---|---|---|"]
    for e in events:
        star = "*" if e.tz_assumed else ""
        summary = e.summary.replace("|", "\\|")
        tags = ", ".join(f"`{t}`" for t in e.tags)
        lines.append(f"| {fmt_utc(e.timestamp)}{star} | {e.host} | {e.source} | {summary} | {tags} |")
    return "\n".join(lines) + "\n"
