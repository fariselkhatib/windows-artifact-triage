# Input formats

Both inputs are UTF-8 CSV with a header row. Column order doesn't matter. Extra columns are ignored (EVTX extras are kept in `details`).

## EVTX export

| Column | Required | Notes |
|---|---|---|
| `TimeCreated` | yes | ISO 8601 (with or without offset), `MM/DD/YYYY hh:mm:ss AM`, or FILETIME |
| `EventId` | yes | e.g. 4624, 4625, 4688, 4720, 4732, 4698, 7045, 1102 |
| `Computer` | yes | Host name |
| `Channel` | no | Security, System, etc. |
| `TargetUser` | no | Account the event is about |
| `LogonType` | no | Numeric, for 4624/4625 |
| `SourceIp` | no | For logon events |
| `ProcessName` | no | Full path, for 4688 |
| `CommandLine` | no | For 4688 (requires command-line auditing enabled on the host) |
| `ServiceName` | no | For 7045 |
| `Details` | no | Free text; used for group name (4732), service path (7045), task name (4698) |

Timestamps without an offset get the `--evtx-tz` zone and are flagged `tz_assumed=True`.

## Prefetch export

| Column | Required | Notes |
|---|---|---|
| `ExecutableName` | yes | e.g. `RCLONE.EXE` |
| `LastRun` | yes | Treated as UTC |
| `SourceFilename` | yes | Path to the `.pf` file |
| `PreviousRun0`..`PreviousRun6` | no | Each non-empty value becomes its own execution event |
| `RunCount` | no | Shown in summary |
| `Host` | no | Falls back to `--prefetch-host` |
