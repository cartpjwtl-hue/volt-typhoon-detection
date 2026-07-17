# Volt Typhoon Detection Pack

[![ATT&CK v19.1](https://img.shields.io/badge/MITRE%20ATT%26CK-v19.1-red)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Defender%20XDR%20%7C%20Sentinel-blue)](https://learn.microsoft.com/en-us/defender-xdr/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

KQL detection pack, MITRE ATT&CK Navigator coverage map, and threat intelligence documentation for **Volt Typhoon** (a.k.a. BRONZE SILHOUETTE, Vanguard Panda, Voltzite, Insidious Taurus) — the PRC state-sponsored group pre-positioning in US critical infrastructure.

Covers the full living-off-the-land kill chain: `netsh portproxy`, `ntds.dit` theft via `ntdsutil`, DCSync replication abuse, KV-botnet C2, and Impacket-style lateral movement.

---

## What's in here

| Folder | Purpose |
|---|---|
| `kql/v1-endpoint/` | Phase-by-phase endpoint detections (Defender XDR) |
| `kql/v2-advanced/` | Encoded PowerShell, DCSync, cross-device capstone |
| `kql/v3-edge/` | Edge device telemetry (Fortinet/Cisco CEF, NetFlow, DNS) |
| `kql/v4-registry/` | Registry ground-truth detections (DeviceRegistryEvents / Sysmon 12-14) |
| `mitre/` | ATT&CK Navigator layer JSON + coverage CSV |
| `docs/` | Methodology, kill chain reference, deployment guide |
| `diagrams/` | Kill chain and coverage visualizations |

## Quick start

### 1. Visualize coverage in MITRE Navigator

```bash
# Open https://mitre-attack.github.io/attack-navigator/
# Click "Open Existing Layer" → "Upload from local"
# Select: mitre/volt_typhoon_attack_layer_v19_v4.json
```

### 2. Deploy a single high-fidelity detection

Start with DCSync — near-zero false positives, highest single-rule value:

```kql
// kql/v2-advanced/03_dcsync_event_4662.kql
SecurityEvent
| where EventID == 4662 and AccessMask has "0x100"
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c")
| where SubjectUserName !endswith "$" and SubjectUserName !startswith "MSOL_"
```

### 3. Deploy the full pack

See `docs/DEPLOYMENT.md` for the recommended rollout order and tuning notes.

## Coverage at a glance

```
Tactic                       Score   Status
─────────────────────────────────────────────
Execution                     2.40   ████████████  Strong
Stealth (v19)                 2.12   ██████████░░  Strong
Initial access                2.00   ██████████░░  Strong (v3)
Defense impairment (v19)      2.00   ██████████░░  Strong (v4)
Credential access             1.89   █████████░░░  Solid (v4)
Command & control             1.83   █████████░░░  Solid
Discovery                     1.70   ████████░░░░  Solid
Collection                    1.67   ████████░░░░  Solid
Lateral movement              1.60   ████████░░░░  Solid (v4)
Persistence                   1.33   ██████░░░░░░  Partial (v4)
Resource development          1.00   █████░░░░░░░  Partial
Exfiltration                  0.50   ██░░░░░░░░░░  Exposed
```

**64 techniques mapped • 11 high-fidelity • 34 single-phase • 13 partial • 6 blind spots**

## Detection highlights

| Detection | What it catches | Fidelity |
|---|---|---|
| `netsh portproxy` | The signature Volt Typhoon C2 tunnel | High |
| `ntdsutil ifm` | File-based AD password database theft | High |
| `Event 4662 + GUIDs` | DCSync replication abuse | High |
| `wmiprvse → cmd → ADMIN$` | Impacket wmiexec lateral movement | High |
| Encoded PowerShell scoring | Multi-layer obfuscation hunt | High |
| Cross-device capstone | Account-based kill chain correlation | Keystone |
| KV-botnet 8443 beaconing | NetFlow-based C2 detection | Medium |
| PortProxy registry write | Obfuscation-proof C2 relay artifact | High |
| Defender / EDR registry tamper | Policy flips + security-service disable | High |
| Registry kill-chain capstone | Weighted registry-only multi-phase chain | Keystone |

## Roadmap

### Delivered artifacts

- [x] **v1 — Endpoint detections** (`kql/v1-endpoint/`) — Phase 1-5 LOTL kill chain: discovery, netsh
  portproxy (process + registry), ntdsutil IFM, alt credential-dump, ntds.dit landing, .gif
  staging masquerade, Impacket wmiexec, device capstone
- [x] **Phase 3 credential-access expansion** (`kql/v1-endpoint/05b–05f`) — all-inclusive alternate
  dump methods (shadow-copy / NTDS / hive / LSASS, method-classified), behavioral LSASS
  handle-access (Sysmon EID10 / MDE `OpenProcessApiCall`, arXiv:2108.10422), and the relocated
  registry cred-access rules (NTDS, VSS, LSASS WDigest/RunAsPPL/SSP)
- [x] **v2 — Advanced detections** (`kql/v2-advanced/`) — DCSync (Event 4662 + MDI), encoded
  PowerShell scoring, account-based cross-device capstone
- [x] **v3 — Edge device telemetry** (`kql/v3-edge/`) — Fortinet/Cisco CEF exploit indicators, VPN
  auth anomaly, KV-botnet 8443 NetFlow beaconing, DNS DDNS hunting, config drift, EOL inventory,
  edge-to-endpoint capstone
- [x] **v4 — Registry ground-truth pack** (`kql/v4-registry/`) — PortProxy (C2), Defender/EDR &
  audit tamper (defense-impairment), service/autorun/scheduled-task (persistence), WinRM/RDP
  (lateral-prep), weighted registry-only kill-chain capstone
- [x] **MITRE ATT&CK v19.1 coverage layer** (`mitre/`) — Navigator layer JSON (v1/v2/v3/v4) +
  coverage CSV, 64 techniques scored across 12 tactics
- [x] **Documentation** (`docs/`) — methodology, kill-chain reference, deployment guide; kill-chain
  and ntds-two-paths diagrams

### Planned artifacts

- [ ] **v5 — Event-log pack** — Event 1102/104 log-clear, 4698 scheduled task, 7045 service install,
  4688 process create — to corroborate the registry layer from the Security/System channels
- [ ] **WMI Event Subscription persistence** (T1546.003) — last remaining persistence blind spot
- [ ] **`05_ntds_alt_methods.kql` back-port** — apply the comsvcs `#24` ordinal fix to the original
  v1 query (currently only in `05b`)
- [ ] **Sigma rule conversions** of the KQL detections
- [ ] **Sentinel analytics rule YAML** with entity mappings, packaged as an ARM template

## Honest about limitations

This pack will catch a Volt Typhoon operator running their documented playbook unmodified. It will **not** catch:

- Unknown zero-day initial access vectors
- Highly customized post-exploitation tradecraft beyond documented TTPs
- Insider threats mimicking these techniques with prior authorization
- Activity entirely contained within unmonitored network segments

Defense in depth is the answer, not "more KQL." See `docs/METHODOLOGY.md` for the full reasoning.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

- **CISA AA24-038A** — Joint advisory on PRC state-sponsored actors compromising US critical infrastructure
- **Lumen Black Lotus Labs** — KV-botnet investigation
- **Microsoft Threat Intelligence** — Volt Typhoon disclosure (May 2023)
- **MITRE ATT&CK** — Framework and Navigator
- **Palo Alto Unit 42** — Insidious Taurus (Volt Typhoon) threat brief, PortProxy registry path
- Detection patterns referenced from public research by SlimKQL, cyb3rmik3, reprise99, Elastic Security, and SnareSolutions

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding queries, improving coverage, or correcting TTPs.
