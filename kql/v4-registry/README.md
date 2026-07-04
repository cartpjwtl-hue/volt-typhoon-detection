# v4 — Registry-layer detections

Registry is the ground-truth telemetry layer. Command lines lie, process names get
masqueraded, file paths get renamed — but when a Windows feature is *used*, the OS writes
specific registry keys as a side effect, and the operator has no control over that. If they
want the feature to work, the write happens.

That makes registry detection:

- **Obfuscation-proof** — encoded PowerShell still produces the same key
- **Tool-agnostic** — same key regardless of which binary invoked the feature
- **High-fidelity** — most of these keys are rarely touched in normal operations

The cost: you need `DeviceRegistryEvents` (Defender XDR) **or** Sysmon Event ID 12/13/14
ingested. Without one of those, this entire category is invisible.

## Queries

| # | File | What it catches | MITRE | Fidelity |
|---|---|---|---|---|
| 1 | `01_portproxy_registry.kql` | PortProxy `v*tov*` rule creation — the netsh C2 relay | T1090.001, T1112 | High |
| 4 | `04_audit_policy_tamper.kql` | Event-log channel / audit policy disabled | T1562.002, T1070.001 | High |
| 5 | `05_defender_tamper.kql` | Defender policy flips **+ security-service disable** | T1685, T1112 | High |
| 6 | `06_service_install.kql` | Service `ImagePath`/`ServiceDll` from staging paths | T1543.003 | Medium |
| 7 | `07_autorun_keys.kql` | Run keys + Winlogon Userinit/Shell hijacks | T1547.001 | Medium |
| 8 | `08_scheduled_task_registry.kql` | TaskCache task registration / masquerade | T1053.005 | Medium |
| 9 | `09_winrm_enable.kql` | WinRM remoting / weak-auth enablement | T1021.006 | High |
| 10 | `10_rdp_enable.kql` | RDP enabled / NLA disabled | T1021.001 | High |
| 11 | `11_capstone_registry_chain.kql` | Weighted multi-phase registry-only kill chain | Multi | Keystone |

> **Credential-access registry detections live in Phase 3, not here.** The NTDS-registry,
> VSS-registry, and LSASS-credential-registry (WDigest / RunAsPPL / SSP) rules are registry-based
> but they detect *credential access*, so they are filed with the rest of Phase 3 in
> `kql/v1-endpoint/` (`05d_ntds_registry.kql`, `05e_vss_registry.kql`,
> `05f_lsass_cred_registry_tamper.kql`). They still require the same `DeviceRegistryEvents` /
> Sysmon 12-14 telemetry as this pack. File numbers 02, 03 and 12 are intentionally vacated by
> that move. The capstone (`11`) keeps its own inline NTDS/VSS registry logic, so it is unaffected.

## What makes v4 different from the draft patterns

These queries were verified against CISA AA24-038A, the Microsoft `DeviceRegistryEvents`
schema, and public detection research (Elastic, Unit 42, THE DFIR Report). Three accuracy
points that trip up naïve registry rules and are handled here:

- **DWORD rendering varies.** Some sensors render a DWORD as decimal (`"1"`), others as hex
  (`"0x00000001"`). Every value comparison in this pack matches **both** forms — a rule that
  only checks `== "1"` silently misses half its detections.
- **Disabling the *service* ≠ flipping a *policy*.** `05_defender_tamper.kql` covers both the
  Defender policy/feature values **and** setting `Services\WinDefend|Sense|WdNisSvc\Start` to
  `4` (disabled) / `3` (manual) — a separate, commonly-missed tamper vector.
- **Control-set path.** Defender/Sysmon log the live control set (`ControlSet001`), not the
  `CurrentControlSet` symlink. Substring matching on `\Services\PortProxy\` catches
  `ControlSet001/002/CurrentControlSet` alike.

## Deployment priorities

| Priority | Queries | Rationale |
|---|---|---|
| **P1 alert now** | 01 PortProxy, 05 Defender tamper, 04 Audit tamper | Near-zero FP; disabling defenses or standing up a relay is never routine |
| **Alert once allow-listed** | 09 WinRM, 10 RDP | Promote after allow-listing management subnets / automation accounts |
| **Hunt → promote** | 06 Service, 07 AutoRun, 08 Scheduled task | Run as hunts for a week, tune, then promote |
| **Every 30 min** | 11 Capstone | Registry-only kill chain is rare and high-confidence |

## Honest scoping — Volt Typhoon and persistence

Volt Typhoon is notable for **avoiding** malware-based persistence: they re-access via valid
accounts (T1078) rather than dropping Run keys, services, or scheduled tasks. So queries 6–8
are **defense-in-depth**, not VT signatures — they close documented blind spots on the coverage
map and catch a deviation from the playbook (or a co-resident commodity actor), but you should
not expect them to fire on a textbook Volt Typhoon operation. Queries 1, 9, and 10 map directly
to documented VT tradecraft; 4 and 5 cover the defense-impairment behaviors the group has used
to blind logging and AV. (The credential-access registry rules that map to VT's ntds.dit theft
now live in Phase 3 — see `kql/v1-endpoint/05d–05f`.)

## Data sources

- `DeviceRegistryEvents` (Microsoft Defender for Endpoint / Defender XDR), **or**
- Sysmon Event ID 12 (key create/delete), 13 (value set), 14 (key/value rename) mapped to the
  equivalent columns.

## Limitations

- Requires registry telemetry; if neither Defender nor Sysmon registry events are ingested,
  this whole layer is blind.
- Some keys (VSS, service installs, scheduled tasks) have legitimate writers — pair with
  process context and the allow-lists noted in each header.
- Registry corroborates but does not replace the process/file detections in `v1-endpoint/`;
  deploy both layers for defense in depth.
