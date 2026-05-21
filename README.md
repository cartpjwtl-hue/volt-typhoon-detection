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
| `mitre/` | ATT&CK Navigator layer JSON + coverage CSV |
| `docs/` | Methodology, kill chain reference, deployment guide |
| `diagrams/` | Kill chain and coverage visualizations |

## Quick start

### 1. Visualize coverage in MITRE Navigator

```bash
# Open https://mitre-attack.github.io/attack-navigator/
# Click "Open Existing Layer" → "Upload from local"
# Select: mitre/volt_typhoon_attack_layer_v19_v3.json
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
Execution                     2.20   ████████████  Strong
Stealth (v19)                 2.00   ██████████░░  Strong
Initial access                2.00   ██████████░░  Strong (v3)
Command & control             1.83   █████████░░░  Solid
Discovery                     1.70   ████████░░░░  Solid
Collection                    1.67   ████████░░░░  Solid
Credential access             1.62   ████████░░░░  Solid
Lateral movement              1.25   ██████░░░░░░  Partial
Resource development          1.00   █████░░░░░░░  Partial
Persistence                   0.50   ██░░░░░░░░░░  Exposed
Exfiltration                  0.50   ██░░░░░░░░░░  Exposed
Defense impairment (v19)      0.00   ░░░░░░░░░░░░  Blind spot
```

**58 techniques mapped • 9 high-fidelity • 23 single-phase • 16 partial • 10 blind spots**

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

## Roadmap

- [x] v1 — Endpoint detections for documented LOTL techniques
- [x] v2 — DCSync, encoded PowerShell, cross-device capstone
- [x] v3 — Edge device telemetry (Fortinet, Cisco, NetFlow, DNS)
- [ ] v4 — Defense Impairment pack (Event 1102/104, T1685 EDR tamper)
- [ ] v5 — Persistence pack (WMI subscriptions, scheduled tasks)
- [ ] Sigma rule conversions
- [ ] Sentinel analytics rule YAML packaged ARM template

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
- Detection patterns referenced from public research by SlimKQL, cyb3rmik3, reprise99, Elastic Security, and SnareSolutions

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding queries, improving coverage, or correcting TTPs.
