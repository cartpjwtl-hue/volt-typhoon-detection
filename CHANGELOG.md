# Changelog

All notable changes to this detection pack will be documented in this file.

## [Unreleased] - 2026-07-18

### Added
- `docs/RESEARCH.md` - academic bibliography grounding the pack, mapping each arXiv paper to the
  repo assets/functions it informed. Honest split: one paper (arXiv:2108.10422) directly shaped
  code (`05c`), the rest is supporting literature.
- **Continuous research monitoring**: `scripts/research_monitor.py` (stdlib-only arXiv API query,
  diffs against cited IDs, refreshes an auto-managed candidate block, flags withdrawn IDs) driven by
  `.github/workflows/research-monitor.yml` (weekly schedule, proposes changes as a PR for review).

## [v5.0] - 2026-06-27

### Added
- **Event-log detection pack** (`kql/v5-eventlog/`) - Security/System channel corroboration that
  works without Defender endpoint tables (WEF / Azure Monitor Agent): Security log clear (1102),
  other-log clear (104), audit-policy disable (4719), service install (7045/4697), scheduled task
  (4698/4702), security-service disable (7040), PowerShell script block (4104), and an event-log
  capstone.
- **WMI Event Subscription persistence** (`kql/v5-eventlog/08`, T1546.003) - WMI-Activity 5861 /
  Sysmon 19-21 detection of FilterToConsumer bindings with code-executing consumers. Closes the
  last persistence blind spot.
- **Sigma rule conversions** (`sigma/`) - 10 vendor-neutral rules across process_creation,
  registry_set, process_access, event-log, and wmi_event sources.
- **Sentinel analytics rules** (`sentinel/`) - scheduled-rule YAML with Host/Account/Process entity
  mappings + an ARM template (`deploy_analytics_rules.json`) that deploys them into a workspace.

### Changed
- MITRE layer + CSV: T1546.003 (WMI Event Subscription) uplifted 0 -> 2. Persistence 1.33 -> 1.67;
  blind spots 6 -> 5; single-phase 34 -> 35.
- `kql/v1-endpoint/05_ntds_alt_methods.kql` - back-ported the comsvcs `#24` / `#+24` ordinal
  evasion fix (previously only in `05b`).

## [Unreleased-cred-access] - 2026-06-27

### Added
- `kql/v1-endpoint/05b_alt_dump_methods_v2.kql` - all-inclusive rewrite of Phase 3b.
  The original only covered vssadmin + reg save + esentutl + comsvcs. v2 covers the full
  alternate credential-dump surface, method-classified with per-method MITRE mapping:
  - Shadow-copy creation: vssadmin, diskshadow, wbadmin, wmic shadowcopy, PowerShell
    Win32_ShadowCopy, ntdsutil snapshot
  - NTDS / hive extraction: esentutl /y|/vss, copy from GLOBALROOT shadow, ntdsutil ifm,
    reg save/export of SAM/SYSTEM/SECURITY
  - LSASS memory dump: comsvcs MiniDump, procdump, createdump, sqldumper, rdrleakdiag,
    WerFault abuse, nanodump/dumpert, PowerShell Out-Minidump
  Mirrors the utility list used by the Phase 3 registry detections (05d NTDS, 05e VSS) and
  adds a VSS-registry corroboration union so the process and registry layers agree.
  Includes: PowerShell-native NTDS reads (Copy-Item/Get-Content/[IO.File], DSInternals,
  Invoke-NinjaCopy), handle-duplication LSASS tools, .NET reflection / inline-compile LSASS
  dumps, comsvcs #24 ordinal evasion, and vshadow.exe. Destructive shadow abuse (T1490) is
  intentionally out of scope.
- `kql/v1-endpoint/05c_lsass_handle_access.kql` - behavioral LSASS handle-access detection
  (Sysmon EID 10 / MDE `OpenProcessApiCall`) keyed on dump-capable `GrantedAccess` masks and
  unbacked (UNKNOWN) call stacks. Closes the direct-syscall / ETW-patch / reflection blind
  spot that command-line rules cannot see. Grounded in arXiv:2108.10422 (empirical EDR-evasion
  assessment).
- `kql/v1-endpoint/05f_lsass_cred_registry_tamper.kql` - registry-side credential-exposure &
  protection tampering: WDigest `UseLogonCredential` downgrade, RunAsPPL / Credential Guard
  disable, SSP `Security Packages` injection, and password-filter `Notification Packages`.

### Changed
- Consolidated all NTDS / credential-access detections under Phase 3 (`kql/v1-endpoint/`),
  including the registry-based ones. Relocated from `kql/v4-registry/`:
  `02_ntds_registry.kql -> 05d_ntds_registry.kql`, `03_vss_registry.kql -> 05e_vss_registry.kql`,
  `12_lsass_cred_registry_tamper.kql -> 05f_lsass_cred_registry_tamper.kql`. They still consume
  `DeviceRegistryEvents` / Sysmon 12-14. The v4-registry pack retains C2 / defense-impairment /
  persistence / lateral-prep registry rules; file numbers 02, 03, 12 are intentionally vacated.
  The registry capstone keeps its own inline NTDS/VSS logic and is unaffected.
- MITRE v4 layer + CSV: T1003.001 (LSASS Memory) uplifted 1 -> 3 (behavioral + cmdline +
  registry-enabler coverage); added T1547.005 (Security Support Provider) and T1556.002
  (Password Filter DLL). Credential Access 1.62 -> 1.89, Persistence 1.20 -> 1.33.
  Technique count 62 -> 64; high-fidelity 10 -> 11.

## [v4.0] - 2026-06-27

### Added
- Registry-layer detection pack (`kql/v4-registry/`) — 11 queries on `DeviceRegistryEvents`
  (or Sysmon Event ID 12/13/14):
  - PortProxy `v*tov*` rule creation (obfuscation-proof netsh C2 relay artifact)
  - NTDS database-path / diagnostics tampering, and VSS footprint from LOLBin parents
  - Event-log channel / audit-policy disable via registry
  - Microsoft Defender policy flips **plus** security-service (`WinDefend`/`Sense`/`WdNisSvc`) disable
  - Service install via suspicious `ImagePath`/`ServiceDll`
  - AutoRun keys + Winlogon `Userinit`/`Shell` hijacks
  - Scheduled-task `TaskCache` registration / Microsoft-folder masquerade
  - WinRM remoting + weak-auth enablement; RDP enable / NLA disable
  - Revamped weighted registry-only kill-chain capstone (account + multi-host, tactic-spread scoring)
- Modify Registry (T1112) to the MITRE layer — CISA AA24-038A explicitly tags the PortProxy
  registry modification as `[T1112]`
- New techniques mapped: T1112, T1543.003, T1021.001, T1562.002

### Changed
- MITRE layer updated to v4 (`volt_typhoon_attack_layer_v19_v4.json`) + coverage CSV
- Defense Impairment tactic coverage: 0.00 → 2.00
- Persistence tactic coverage: 0.50 → 1.20
- Lateral Movement tactic coverage: 1.25 → 1.60
- Execution 2.20 → 2.40; Stealth 2.00 → 2.12
- Technique count 58 → 62; blind spots 10 → 6; high-fidelity 9 → 10

### Notes
- DWORD registry values are matched in both decimal (`"1"`) and hex (`"0x00000001"`) form,
  since sensors render them differently.
- Volt Typhoon avoids malware persistence (re-access via valid accounts), so the autorun /
  service / scheduled-task queries are defense-in-depth, not VT signatures — documented in the
  pack README.

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
