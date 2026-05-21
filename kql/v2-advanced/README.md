# v2 — Advanced detections

Closes the biggest gaps in v1: obfuscated commands, file-less credential theft, and cross-host attack chains.

## Queries

| # | File | What it catches | MITRE | Fidelity |
|---|---|---|---|---|
| 1 | `01_encoded_powershell.kql` | Multi-layer obfuscation scoring | T1059.001, T1027.010 | Score 3 |
| 2 | `02_dcsync_mdi.kql` | DCSync via Defender for Identity | T1003.006 | Score 3 |
| 3 | `03_dcsync_event_4662.kql` | DCSync via Event 4662 replication GUIDs | T1003.006 | Score 3 |
| 4 | `04_capstone_account_cross_device.kql` | Multi-phase, multi-host, by account | Multi | Keystone |

## Why these matter

**Encoded PowerShell:** The v1 detections match literal strings. An attacker using `-EncodedCommand` defeats them. The scoring approach in query 1 alerts on combinations of encoding + obfuscation + suspicious intent.

**DCSync:** ntds.dit can be stolen without touching the filesystem by requesting AD replication directly. Query 2 (MDI) and 3 (raw 4662) are the only reliable detections — endpoint file/process events miss this entirely.

**Cross-device capstone:** Volt Typhoon spreads activity across hosts. The v1 capstone groups by device and misses this. Query 4 groups by account across all hosts in a 24-hour window. `PhaseCount >= 3` is the incident-grade signal.

## Data sources

- `DeviceProcessEvents` (encoded PowerShell)
- `SecurityEvent` Event 4662 (DCSync raw)
- `IdentityDirectoryEvents` if you have Defender for Identity (DCSync MDI)

## Prerequisites for DCSync (Event 4662)

1. **Audit Directory Service Access** policy enabled on Domain Controllers (success and failure)
2. **SACL on the domain naming context** auditing the "Everyone" principal for:
   - Replicating Directory Changes
   - Replicating Directory Changes All
   - Replicating Directory Changes In Filtered Set

Without the SACL, no Event 4662 records are written even though the auditing policy is enabled.
