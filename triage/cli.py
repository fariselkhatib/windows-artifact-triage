from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .parsers import ParseWarning, parse_evtx_csv, parse_prefetch_csv
from .rules import tag_events
from .timeline import build_timeline, render_markdown, write_csv
from .timestamps import parse_ts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="triage",
                                description="Build a normalized UTC timeline from Windows artifact exports.")
    p.add_argument("--evtx", nargs="*", default=[], help="EVTX export CSV(s)")
    p.add_argument("--prefetch", nargs="*", default=[], help="Prefetch export CSV(s)")
    p.add_argument("--prefetch-host", default="UNKNOWN", help="Host name for Prefetch rows without a Host column")
    p.add_argument("--evtx-tz", default="UTC",
                   help="IANA timezone applied to EVTX timestamps that lack an offset (e.g. America/Chicago)")
    p.add_argument("--start", help="Only include events at/after this time (ISO 8601)")
    p.add_argument("--end", help="Only include events at/before this time (ISO 8601)")
    p.add_argument("--tagged-only", action="store_true", help="Only output events with at least one tag")
    p.add_argument("--csv", help="Write timeline CSV to this path")
    p.add_argument("--md", help="Write Markdown timeline to this path (default: stdout)")
    args = p.parse_args(argv)

    if not args.evtx and not args.prefetch:
        p.error("provide at least one --evtx or --prefetch file")

    warnings = ParseWarning()
    evtx = [e for f in args.evtx for e in parse_evtx_csv(f, args.evtx_tz, warnings)]
    pf = [e for f in args.prefetch for e in parse_prefetch_csv(f, args.prefetch_host, warnings)]

    start = parse_ts(args.start).utc if args.start else None
    end = parse_ts(args.end).utc if args.end else None
    timeline = build_timeline(tag_events(evtx + pf), start=start, end=end, tagged_only=args.tagged_only)

    if args.csv:
        write_csv(timeline, args.csv)
    md = render_markdown(timeline)
    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
    elif not args.csv:
        sys.stdout.write(md)

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(f"{len(timeline)} events written ({sum(1 for e in timeline if e.tags)} tagged)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
