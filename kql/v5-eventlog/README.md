# v5 — Event-log detections (Security / System channels)

Corroborates the process (`v1`), registry (`v4`), and behavioral layers from the **native Windows
event logs** — the Security and System channels plus PowerShell/WMI Operational logs. This matters
because many environments ship Windows Event Logs to Sentinel via **WEF / Azure Monitor Agent**
*without* Defender for Endpoint tables. This pack keeps working there: nothing here depends on
`DeviceProcessEvents` / `DeviceRegistryEvents`.

It also closes the last persistence blind spot on the coverage map — **WMI event subscriptions**.

## Queries

| # | File | What it catches | MITRE | Fidelity |
|---|---|---|---|---|
| 1 | `01_security_log_cleared.kql` | Security log cleared (Event 1102) | T1070.001 | High |
| 2 | `02_other_logs_cleared.kql` | System/PowerShell/WinRM log cleared (Event 104) | T1070.001 | High |
| 3 | `03_audit_policy_changed.kql` | Audit subcategory set to no-auditing (Event 4719) | T1562.002 | Medium |
| 4 | `04_service_installed.kql` | Suspicious service install (Event 7045 / 4697) | T1543.003, T1569.002 | Medium |
| 5 | `05_scheduled_task_created.kql` | Task with LOLBin action / masquerade (Event 4698/4702) | T1053.005 | Medium |
| 6 | `06_service_starttype_disabled.kql` | Security service set to disabled (Event 7040) | T1685 | High |
| 7 | `07_powershell_scriptblock.kql` | Decoded malicious script block (Event 4104) | T1059.001, T1027.010 | Medium |
| 8 | `08_wmi_event_subscription.kql` | **WMI permanent subscription persistence** (5861 / Sysmon 19-21) | T1546.003 | High |
| 9 | `09_capstone_eventlog_chain.kql` | Weighted multi-phase event-log kill chain | Multi | Keystone |

## Why event logs, when we already have process + registry telemetry

- **Different sensor, different failure mode.** If Defender is blinded (ETW-Ti patch, agent
  disabled) the Security/System channels — forwarded off-host via WEF — may still record the
  1102 log-clear, the 7045 service install, the 7040 service-disable. Defense in depth.
- **Self-witnessing anti-forensics.** Clearing the Security log *writes* Event 1102 to it; disabling
  a subcategory writes 4719. The act of hiding leaves the highest-fidelity artifact in the pack.
- **Decoded PowerShell.** Script Block Logging (4104) captures the decoded content even when
  `-EncodedCommand` was used — seeing through obfuscation that command-line rules miss.
- **The WMI persistence gap.** T1546.003 was the last `0` on the persistence row; `08` closes it.

## Corroboration map (event-log ↔ other layers)

| This pack | Corroborates |
|---|---|
| `01`/`02` log clear, `03` audit policy | `v4/04` registry audit-tamper |
| `04` service install | `v4/06` registry service-install |
| `05` scheduled task | `v4/08` registry TaskCache |
| `06` service disable | `v4/05` registry Defender-service-disable |
| `07` script block | `v2/01` encoded PowerShell, `v1/05c` LSASS reflection |

## Prerequisites

Some of these require non-default audit settings:

- **4719** (audit policy change) — audit *Audit Policy Change* (on by default on servers).
- **4698/4702** (scheduled task) — audit *Other Object Access Events*, **or** collect the Task
  Scheduler Operational log.
- **4104** (script block) — enable **PowerShell Script Block Logging** (GPO / registry).
- **5861** (WMI subscription) — collect **Microsoft-Windows-WMI-Activity/Operational**; Sysmon
  19/20/21 is the higher-fidelity alternative.
- **1102 / 104 / 7045 / 7040** — collected by default in the Security / System channels.

## Data sources

- `SecurityEvent` (Windows Security channel) and `Event` (System / PowerShell / WMI-Activity)
  via WEF / Azure Monitor Agent into Sentinel.
- Where a Defender `DeviceEvents` equivalent exists (WMI subscription), it is included commented.

## Limitations

- An operator who clears logs *and* the forwarding is host-local loses the artifact — forward
  Security/System channels off-host (WEF) so the clear is captured before it is destroyed.
- 4698/4104/5861 need the audit settings above; without them those queries return nothing.
- These corroborate, they do not replace, the `v1`/`v4` endpoint layers — deploy together.
