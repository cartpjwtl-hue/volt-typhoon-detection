# Methodology

How this detection pack is built, scored, and intended to be used.

## Threat model

This pack targets **Volt Typhoon** (G1017) specifically — a PRC state-sponsored group focused on pre-positioning in US critical infrastructure for potential disruption. Their signature characteristic is **living-off-the-land (LOTL)**: using legitimate Windows utilities for malicious purposes, with no custom malware to fingerprint.

The pack also catches **adjacent threat actors** using the same techniques (Salt Typhoon, Mustang Panda subsets, some Scattered Spider tradecraft, generic ransomware operators using Impacket).

## Detection principles

1. **Prefer high-fidelity, low-volume signals.** A single Event 4662 with the right GUID is more valuable than a thousand process command-line hits.
2. **Score honestly.** Partial coverage is yellow, not green. A query that fires only on the dumbest variant of a TTP doesn't get credit for catching the technique.
3. **Correlate before alerting.** Individual LOTL commands have admin false positives. Combinations don't.
4. **Document false positive sources.** Every query header lists known FP sources so reviewers can tune intelligently.
5. **Never assume Defender XDR sees everything.** Some attacks live in network telemetry, identity logs, or edge device syslogs — explicitly call out where KQL alone is insufficient.

## Scoring system (0–3)

| Score | Meaning | Example |
|---|---|---|
| **3** | High-fidelity / capstone — alert-grade, near-zero FPs | DCSync Event 4662 with replication GUIDs |
| **2** | Single-phase detection — tunable to alert quality | `netsh portproxy` command line |
| **1** | Hunting only / partial — needs context to be useful | Generic PowerShell encoded command flag |
| **0** | Blind spot — no telemetry available for this technique | Initial exploit on a SOHO router with no syslog |

A tactic's overall score is the average across its techniques.

## Coverage gaps (intentional and known)

This pack does not pretend to be exhaustive. The following gaps are deliberate and documented:

### Defense Impairment (TA0112) — 0.00 coverage

EDR tamper detection (T1685), event log clearing (T1070.001), and audit policy modification (T1562 retirement targets) are not covered in the current version. Addressing them requires:
- Event 1102 (audit log cleared) and Event 104 (System log cleared) alerts
- Service start/stop monitoring on EDR and AV processes
- Registry monitoring for Defender configuration keys
- BYOVD (bring-your-own-vulnerable-driver) signal collection

Planned for v4.

### Persistence (TA0003) — 0.50 coverage

Scheduled tasks (T1053.005), WMI event subscriptions (T1546.003), and Run keys (T1547.001) are partially covered. Volt Typhoon's documented persistence is light compared to ransomware actors, but anything that establishes long-dwell access deserves coverage. Planned for v5.

### Exfiltration channels (TA0010) — 0.50 coverage

Once data is exfiltrated, you've already lost. This pack focuses on the chain *before* exfiltration. Egress-side detection requires NetFlow/proxy telemetry and DLP integration that varies wildly per environment — too environment-specific to package as portable KQL.

### Edge devices outside Windows telemetry

KV-botnet activity on consumer SOHO routers cannot be detected by any Windows-side query. The v3 edge pack handles enterprise edge devices that emit syslog. Consumer-grade routers in remote-worker home offices remain a structural blind spot addressable only by policy (mandate corporate-managed devices) and identity controls (phishing-resistant MFA, conditional access with device posture).

## Why we wrote the cross-device capstone the way we did

The single most important insight in this pack: **Volt Typhoon spreads activity across hosts deliberately**. They run discovery from one foothold, build the proxy on another, dump credentials from a third, and pivot from a fourth. The v1 capstone, which grouped by `DeviceName`, missed this entirely.

The v2 capstone groups by `AccountName` and aggregates across hosts. When `PhaseCount >= 3` and `DeviceCount >= 2` fire together, there is no benign administrator explanation. That's the keystone alert.

## On honesty and limitations

Detection engineering is full of marketing claims of "100% Volt Typhoon coverage." This pack is not that. It catches a Volt Typhoon operator running their documented playbook. It will miss:

- A skilled operator obfuscating known commands
- Custom tradecraft outside CISA/Microsoft advisories
- Activity on assets that don't send telemetry
- Insider threats mimicking these techniques
- Future variants we haven't seen yet

**Defense in depth is the answer.** Identity controls (MFA, conditional access), least privilege, network segmentation, EDR, and incident response capability all matter as much as the queries in this repo.

## References

This pack draws on public research and advisories:

- CISA AA24-038A — PRC state-sponsored actors compromising US critical infrastructure
- Microsoft Threat Intelligence — Volt Typhoon disclosure (May 2023) and ongoing reporting
- Lumen Black Lotus Labs — KV-botnet investigation series
- US DOJ — KV-botnet disruption announcement
- MITRE ATT&CK Group G1017
- Detection patterns referenced from public research by Florian Roth (Sigma project), SpecterOps, Elastic Security, SnareSolutions, and various community contributors

Detection signatures should be considered open intelligence and contributed back to the community where possible.
