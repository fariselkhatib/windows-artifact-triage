"""Timestamp normalization.

Exported Windows artifacts rarely agree on timestamp format. EVTX exports from
different tools emit ISO 8601 with or without offsets, US-style local strings,
or raw FILETIME values. Everything here becomes a timezone-aware UTC datetime.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# FILETIME = 100ns intervals since 1601-01-01 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_NAIVE_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
)


@dataclass(frozen=True)
class NormalizedTime:
    utc: datetime
    assumed_tz: bool  # True when the source had no offset and we applied one


class TimestampError(ValueError):
    pass


def parse_ts(raw: str, assume_tz: str = "UTC") -> NormalizedTime:
    """Parse a timestamp string into UTC.

    assume_tz is applied only when the source string carries no offset.
    The result records whether that assumption was made, so analysts can see
    which rows depend on it.
    """
    if raw is None or not str(raw).strip():
        raise TimestampError("empty timestamp")
    s = str(raw).strip()

    # Raw FILETIME (all digits, 17-18 chars is typical for modern dates)
    if s.isdigit() and len(s) >= 17:
        dt = _FILETIME_EPOCH + timedelta(microseconds=int(s) // 10)
        return NormalizedTime(dt, assumed_tz=False)

    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
        for fmt in _NAIVE_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            raise TimestampError(f"unrecognized timestamp: {s!r}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(assume_tz))
        return NormalizedTime(dt.astimezone(timezone.utc), assumed_tz=True)
    return NormalizedTime(dt.astimezone(timezone.utc), assumed_tz=False)


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
