# Changelog

All notable changes to this detection pack will be documented in this file.

## [v3.0] - 2026-05-21

### Added
- Edge device telemetry detection pack (`kql/v3-edge/`)
  - Fortinet SSL-VPN exploit indicators (CVE-2022-42475)
  - Cisco RV320/325 exploit indicators (CVE-2024-39717, legacy)
  - VPN authentication from anomalous geography
  - KV-botnet beaconing detection (port 8443, NetFlow)
  - DNS hunting for dynamic-DNS providers used by KV-botnet
  - Edge device configuration drift detection
  - EOL device inventory query
  - Edge-to-endpoint capstone correlation
- Resource Development tactic to MITRE layer for KV-botnet (T1584, T1584.005)

### Changed
- MITRE layer updated to v3 with 11 technique uplifts
- Initial Access tactic coverage: 0.50 → 2.00
- Command & Control coverage: 1.33 → 1.83
- Blind spot count: 15 → 10

## [v2.0] - 2026-05-21

### Added
- Encoded PowerShell multi-layer scoring detection
- DCSync detection via Event 4662 + replication GUIDs
- Account-based cross-device capstone correlation

### Changed
- MITRE layer updated to ATT&CK v19.1 (Defense Evasion split)
- Stealth (TA0005) and Defense Impairment (TA0112) tactics
- T1562 retirement and T1685 introduction

## [v1.0] - 2026-05-21

### Added
- Initial endpoint detection pack
  - LOTL discovery commands
  - netsh portproxy detection (process + registry)
  - ntdsutil IFM credential theft
  - Alternative credential dump methods
  - NTDS.dit file landing detection
  - 7zip/RAR staging + .gif masquerade
  - Impacket wmiexec lateral movement
  - Multi-phase device-based capstone
- MITRE ATT&CK Navigator coverage layer
- Coverage CSV export
- Initial documentation
