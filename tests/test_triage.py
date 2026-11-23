from datetime import datetime, timezone
from pathlib import Path

import pytest

from triage.cli import main
from triage.parsers import ParseWarning, parse_evtx_csv, parse_prefetch_csv
from triage.rules import tag_events
from triage.timeline import build_timeline, render_markdown
from triage.timestamps import TimestampError, parse_ts

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
EVTX = SAMPLES / "evtx_export.csv"
PF = SAMPLES / "prefetch_export.csv"


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


# --- timestamps -----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("2026-03-14T07:03:12Z", utc(2026, 3, 14, 7, 3, 12)),
    ("2026-03-14T02:09:00-05:00", utc(2026, 3, 14, 7, 9, 0)),
    ("134178877310000000", utc(2026, 3, 13, 15, 2, 11)),
])
def test_parse_ts_with_offset(raw, expected):
    t = parse_ts(raw)
    assert t.utc == expected
    assert t.assumed_tz is False


def test_naive_timestamp_uses_assumed_tz_and_dst():
    # March 14 2026 is after the US DST change, so Chicago is UTC-5
    t = parse_ts("03/14/2026 02:05:40 AM", "America/Chicago")
    assert t.utc == utc(2026, 3, 14, 7, 5, 40)
    assert t.assumed_tz is True


def test_naive_timestamp_winter_offset():
    t = parse_ts("2026-01-10 12:00:00", "America/Chicago")
    assert t.utc == utc(2026, 1, 10, 18, 0, 0)


def test_bad_timestamp_raises():
    with pytest.raises(TimestampError):
        parse_ts("not-a-timestamp")


# --- parsers --------------------------------------------------------------

def test_evtx_parser_skips_bad_rows_with_warning():
    w = ParseWarning()
    events = parse_evtx_csv(EVTX, "America/Chicago", w)
    assert len(events) == 17
    assert len(w) == 1 and "not-a-timestamp" in w[0]


def test_prefetch_expands_previous_runs():
    events = parse_prefetch_csv(PF)
    rclone = [e for e in events if "RCLONE" in e.summary]
    assert len(rclone) == 2
    chrome = [e for e in events if "CHROME" in e.summary]
    assert len(chrome) == 3  # LastRun + 2 previous, one stored as FILETIME


def test_missing_columns_rejected(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("Foo,Bar\n1,2\n")
    with pytest.raises(ValueError, match="missing required columns"):
        parse_evtx_csv(bad)


# --- rules ----------------------------------------------------------------

@pytest.fixture
def timeline():
    evtx = parse_evtx_csv(EVTX, "America/Chicago")
    pf = parse_prefetch_csv(PF)
    return build_timeline(tag_events(evtx + pf))


def test_bruteforce_burst_tagged_only_for_external_source(timeline):
    burst = [e for e in timeline if "brute-force:T1110" in e.tags]
    assert len(burst) == 6
    assert all(e.details.get("SourceIp") == "203.0.113.45" for e in burst)


def test_key_events_tagged(timeline):
    tags = {t for e in timeline for t in e.tags}
    for expected in ["rdp-logon:T1021.001", "persistence:T1543.003", "persistence:T1136.001",
                     "defense-evasion:T1070.001", "exfil-tool:T1567.002", "archive:T1560.001",
                     "discovery:T1033/T1087"]:
        assert expected in tags


def test_benign_not_tagged(timeline):
    chrome = [e for e in timeline if "CHROME" in e.summary]
    assert chrome and all(not e.tags for e in chrome)


def test_timeline_sorted_and_normalized(timeline):
    stamps = [e.timestamp for e in timeline]
    assert stamps == sorted(stamps)
    assert all(s.tzinfo == timezone.utc or s.utcoffset().total_seconds() == 0 for s in stamps)


def test_window_filter(timeline):
    evtx = parse_evtx_csv(EVTX, "America/Chicago")
    window = build_timeline(tag_events(evtx), start=utc(2026, 3, 14, 7, 3), end=utc(2026, 3, 14, 7, 10))
    assert window[0].summary.startswith("Successful logon (remote-interactive")
    assert all(utc(2026, 3, 14, 7, 3) <= e.timestamp <= utc(2026, 3, 14, 7, 10) for e in window)


def test_markdown_flags_assumed_tz(timeline):
    md = render_markdown(timeline)
    assert "--evtx-tz" in md
    assert "2026-03-14T07:05:40Z*" in md


# --- cli ------------------------------------------------------------------

def test_cli_end_to_end(tmp_path):
    out_csv, out_md = tmp_path / "t.csv", tmp_path / "t.md"
    rc = main(["--evtx", str(EVTX), "--prefetch", str(PF), "--evtx-tz", "America/Chicago",
               "--csv", str(out_csv), "--md", str(out_md), "--tagged-only"])
    assert rc == 0
    rows = out_csv.read_text().splitlines()
    assert rows[0].startswith("timestamp_utc")
    assert len(rows) > 10
    assert "RCLONE.EXE" in out_md.read_text()
