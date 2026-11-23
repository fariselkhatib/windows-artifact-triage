"""Lightweight tagging rules.

These are triage hints, not detections. A tag means "look here first", never
"this is malicious". Each rule maps to a MITRE ATT&CK technique where one fits.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .model import TimelineEvent

# Executables worth a second look when they show up in Prefetch or 4688.
SUSPECT_BINARIES = {
    "PSEXESVC.EXE": "lateral-movement:T1569.002",
    "PSEXEC.EXE": "lateral-movement:T1569.002",
    "RCLONE.EXE": "exfil-tool:T1567.002",
    "7Z.EXE": "archive:T1560.001",
    "WINRAR.EXE": "archive:T1560.001",
    "MIMIKATZ.EXE": "credential-access:T1003",
    "PROCDUMP.EXE": "credential-access:T1003.001",
    "ANYDESK.EXE": "remote-access:T1219",
    "NGROK.EXE": "tunneling:T1572",
    "ADFIND.EXE": "discovery:T1087.002",
}

RECON_COMMANDS = ("whoami", "net group", "net user", "nltest", "ipconfig /all", "quser")

EVENT_TAGS = {
    "1102": "defense-evasion:T1070.001",
    "7045": "persistence:T1543.003",
    "4720": "persistence:T1136.001",
    "4732": "privilege:T1098",
    "4698": "persistence:T1053.005",
}


def tag_events(events: list[TimelineEvent],
               burst_threshold: int = 5,
               burst_window: timedelta = timedelta(minutes=10)) -> list[TimelineEvent]:
    for ev in events:
        eid = ev.details.get("EventId", "").strip() if ev.source == "evtx" else ""
        if eid in EVENT_TAGS:
            ev.tags.append(EVENT_TAGS[eid])
        if eid == "4624" and ev.details.get("LogonType", "").strip() == "10":
            ev.tags.append("rdp-logon:T1021.001")

        exe = ""
        if ev.source == "prefetch":
            exe = ev.details.get("executable", "").upper()
        elif eid == "4688":
            exe = ev.details.get("ProcessName", "").replace("/", "\\").split("\\")[-1].upper()
            cmd = ev.details.get("CommandLine", "").lower()
            if any(c in cmd for c in RECON_COMMANDS):
                ev.tags.append("discovery:T1033/T1087")
        if exe in SUSPECT_BINARIES:
            ev.tags.append(SUSPECT_BINARIES[exe])

    _tag_failed_logon_bursts(events, burst_threshold, burst_window)
    return events


def _tag_failed_logon_bursts(events, threshold, window):
    """Tag 4625s that are part of a burst from one source IP (spray / brute force)."""
    by_src = defaultdict(list)
    for ev in events:
        if ev.event_type == "logon-failure":
            by_src[ev.details.get("SourceIp", "") or "?"].append(ev)
    for group in by_src.values():
        group.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(group)):
            while group[end].timestamp - group[start].timestamp > window:
                start += 1
            if end - start + 1 >= threshold:
                for ev in group[start:end + 1]:
                    if "brute-force:T1110" not in ev.tags:
                        ev.tags.append("brute-force:T1110")
