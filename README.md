# windows-artifact-triage

![tests](https://github.com/fariselkhatib/windows-artifact-triage/actions/workflows/tests.yml/badge.svg)

Turn messy Windows artifact exports into one sorted, UTC-normalized investigation timeline, with triage tags that point you at what to read first.

## The problem

Early in an endpoint investigation you usually have a pile of exports: Security/System event logs from one tool, Prefetch from another, each with its own timestamp format. Some carry offsets, some are local time with no zone, Prefetch can hand you raw FILETIMEs. Merging them by hand is slow and it's where timezone mistakes creep into a report.

This tool:

- Parses EVTX and Prefetch CSV exports
- Normalizes every timestamp to UTC (ISO 8601, offset-aware, US-style local, FILETIME)
- **Flags every row where a timezone had to be assumed**, so the report never silently depends on a guess
- Expands Prefetch `LastRun` + `PreviousRun*` into separate execution events
- Tags events with MITRE ATT&CK hints (RDP logons, failed-logon bursts, service installs, account creation, log clearing, known dual-use tools)
- Keeps a `source_ref` (file:line:column) on every row so any finding traces back to the raw export
- Outputs CSV (for Timeline Explorer / Excel) and Markdown (for case notes)

## Data source

All sample data in `samples/` is **synthetic**. Host names use `.lab.example`, IPs come from documentation ranges (RFC 5737). The scenario is a fictional external brute force into RDP, followed by discovery, local persistence, staging with 7-Zip, rclone exfil, and log clearing.

Input column formats are in [docs/input-formats.md](docs/input-formats.md). Most EVTX/Prefetch export tools can produce these columns directly or with a quick column rename.

## How to run

Requires Python 3.10+. No third-party dependencies.

```bash
git clone https://github.com/fariselkhatib/windows-artifact-triage.git
cd windows-artifact-triage

python -m triage \
  --evtx samples/evtx_export.csv \
  --prefetch samples/prefetch_export.csv \
  --evtx-tz America/Chicago \
  --csv timeline.csv --md timeline.md
```

Useful flags:

| Flag | What it does |
|---|---|
| `--evtx-tz` | IANA zone applied only to EVTX timestamps with no offset (DST handled) |
| `--start` / `--end` | Scope the timeline to a window (ISO 8601) |
| `--tagged-only` | Drop untagged rows for a quick first pass |
| `--prefetch-host` | Host name for Prefetch exports without a `Host` column |

Run the tests:

```bash
pip install pytest
python -m pytest -q
```

## Sample output

Excerpt from [docs/sample_timeline.md](docs/sample_timeline.md). `*` marks a row where the `--evtx-tz` assumption was applied.

| Time (UTC) | Source | Summary | Tags |
|---|---|---|---|
| 2026-03-14T07:01:02Z | evtx | Failed logon for svc_backup from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T07:03:12Z | evtx | Successful logon (remote-interactive (RDP)) for svc_backup from 203.0.113.45 | `rdp-logon:T1021.001` |
| 2026-03-14T07:05:40Z* | evtx | Process created: cmd.exe /c whoami /all | `discovery:T1033/T1087` |
| 2026-03-14T07:09:00Z | evtx | User account created: helpdesk_tmp | `persistence:T1136.001` |
| 2026-03-14T07:12:00Z | evtx | Service installed: PSEXESVC | `persistence:T1543.003` |
| 2026-03-14T07:18:11Z | prefetch | 7Z.EXE executed (last run; run count 1) | `archive:T1560.001` |
| 2026-03-14T07:31:05Z | prefetch | RCLONE.EXE executed (last run; run count 2) | `exfil-tool:T1567.002` |
| 2026-03-14T07:48:55Z | evtx | Security audit log was cleared | `defense-evasion:T1070.001` |

What an analyst gets from this in under a minute: the successful RDP logon lands two minutes after a failed-logon burst from the same external IP, and Prefetch independently corroborates the 4688 process events for 7-Zip and rclone.

## Limitations

Read these before trusting the output on a real case.

- **Tags are triage hints, not detections.** `rclone.exe` or `PsExec` running is not proof of anything. Admins use both. Tags tell you where to look.
- **Timezone assumption is global.** `--evtx-tz` applies to every naive EVTX timestamp. If exports came from hosts in different zones, process them separately.
- **Prefetch caveats apply.** Prefetch can be disabled (common on servers and some SSD configs), only keeps the last 8 run times, and the `LastRun` time is roughly 10 seconds after actual execution start. Absence of a Prefetch file is not absence of execution.
- **No raw EVTX parsing.** This reads CSV exports, not `.evtx` binaries. Use your preferred EVTX export tool first.
- **Small rule set.** The suspect-binary list and event-ID tags are intentionally short and readable. Extend `triage/rules.py` for your environment.
- **Failed-logon burst logic is per source IP.** Distributed sprays from many IPs won't trip it.
- **Not tested on huge exports.** Everything loads into memory. Fine for a host triage, not for a fleet.

## Project layout

```
triage/
  timestamps.py   # format detection + UTC normalization
  parsers.py      # EVTX / Prefetch CSV readers
  rules.py        # ATT&CK-mapped tagging
  timeline.py     # merge, filter, CSV + Markdown output
  cli.py
samples/          # synthetic exports
tests/            # pytest suite
docs/             # input formats, sample output
```

## License

MIT. See [LICENSE](LICENSE).
