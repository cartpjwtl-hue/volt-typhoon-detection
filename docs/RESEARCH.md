# Research & references

Academic grounding for the detection pack. This file exists so every design decision that leans on
published research is traceable to its source, and so the reading list stays current.

**Honest split.** Only **one** paper directly shaped code in this repo (`arXiv:2108.10422`, which
motivated the behavioral LSASS rule `05c` and its documented blind spot). Everything else is
**supporting literature** — it corroborates an approach the pack already takes (multi-phase
correlation, ATT&CK coverage scoring, persistence detection) but was not a source for a specific
query. Each entry says which it is, and which repo asset it maps to.

> Primary (non-academic) sources — CISA AA24-038A, Microsoft Threat Intelligence, Lumen Black Lotus
> Labs, Palo Alto Unit 42, Elastic — are credited in the root [`README.md`](../README.md#acknowledgments).
> This file tracks the peer-reviewed / arXiv literature.

---

## 1. Directly informed the pack

### An Empirical Assessment of Endpoint Security Systems Against APT Attack Vectors
`arXiv:2108.10422` · Karantzas & Patsakis · *J. Cybersecur. Priv.* 2021 · https://arxiv.org/abs/2108.10422
Red-team assessment demonstrating that EDRs are evadable: LSASS dumped via **direct syscalls**
(`NtReadVirtualMemory`), **ETW-Ti telemetry patching** (`EtwTiLogReadWriteVm`), Outflank **Dumpert**,
and early-bird injection into `WerFault.exe`.
**Maps to →** `kql/v1-endpoint/05c_lsass_handle_access.kql` (behavioral handle-access + unbacked
`CallTrace` tell), the honest "a blinded sensor can still suppress this" limitation in that header,
and the defense-in-depth pointer to `05f` (RunAsPPL / Credential Guard as the real mitigation). Also
referenced by `sigma/procaccess_lsass_handle.yml`.

---

## 2. Supporting literature (corroborates an approach; not a code source)

### Accurate and Scalable Detection and Investigation of Cyber Persistence Threats
`arXiv:2407.18832` · *IEEE TDSC* 2026 · https://arxiv.org/abs/2407.18832
Introduces a Cyber Persistence Detector dedicated to registry/service/task/WMI persistence.
**Maps to →** the v4 persistence rules (`06_service_install`, `07_autorun_keys`,
`08_scheduled_task_registry`), the v5 event-log equivalents, and `v5-eventlog/08_wmi_event_subscription`.

### ProvAgent: Threat Detection Based on Identity-Behavior Binding
`arXiv:2603.09358` · https://arxiv.org/abs/2603.09358
Provenance-graph APT detection that binds **identity to behavior** and resists mimicry/evasion.
**Maps to →** the correlation design of the capstones: account-based cross-device (`v2/04`) and the
weighted registry/event-log kill-chains (`v4/11`, `v5/09`) — same "correlate by identity across
phases" premise.

### Decoding the MITRE Engenuity ATT&CK Enterprise Evaluation
`arXiv:2401.15878` · *AsiaCCS* 2024 · https://arxiv.org/abs/2401.15878
Analysis of real-world EDR performance in the ATT&CK evaluations, including OS Credential Dumping.
**Maps to →** the coverage-scoring methodology in `mitre/`, the "native Defender overlap" reasoning,
and the *Honest about limitations* section of the README.

### Multi-Source Cybersecurity Logs: An ATT&CK-Labeled Dataset and SLM Evaluation
`arXiv:2606.18190` · https://arxiv.org/abs/2606.18190
Windows-endpoint dataset with system/network/browser events labeled by ATT&CK technique ID.
**Maps to →** a validation/testing resource, and support for the multi-source (process + registry +
event-log) correlation the capstones rely on.

### Synthetic APTs: the Collapse of TTP-Based Attribution
`arXiv:2606.07158` · https://arxiv.org/abs/2606.07158
Shows emulated APTs can faithfully reproduce documented TTPs, weakening TTP-based attribution.
**Maps to →** context for `v3-edge/` emulation coverage and the honest caveat that the pack catches
the *documented playbook*, not novel/attributed tradecraft.

### Further reading (peripheral)
- `arXiv:2509.05698` — KnowHow: applying high-level CTI knowledge to provenance detection.
- `arXiv:2306.00934` — Interpreting GNN-based IDS detections using provenance graphs.
- `arXiv:2508.21323` — LLM-driven provenance forensics for threat investigation.
- `arXiv:2407.16928` — Causality-preserving cyberattack modeling (credential dumping as an action).

---

## 3. Maintenance

This file is **continuously monitored**. A scheduled GitHub Action
([`.github/workflows/research-monitor.yml`](../.github/workflows/research-monitor.yml)) runs
[`scripts/research_monitor.py`](../scripts/research_monitor.py) weekly, queries the arXiv API for the
pack's topic set, and refreshes the auto-managed block below:

- **Adds** — new candidate papers not already listed here are appended for human review.
- **Removals** — any arXiv ID cited above that arXiv no longer resolves (withdrawn/replaced) is
  flagged for review.

Sections 1 and 2 are **curated** (human-reviewed); promote a candidate into them by hand. The block
between the markers is machine-managed — do not edit it by hand.

<!-- RESEARCH-MONITOR:BEGIN -->
### Candidate papers (auto-discovered, pending review)

| arXiv | Published | Title |
|---|---|---|
| [2608.12444](https://arxiv.org/abs/2608.12444) | 2026-08-12 | Non-Degenerate Risk Certification for Automated Security Decisions: A Decision-Contract Theory with ATT\&CK-Aligned Triage as a Worked Instance |
| [2608.01639](https://arxiv.org/abs/2608.01639) | 2026-08-03 | Mutate to Bypass: Autonomous Endpoint Evasion via Knowledge-Driven Multi-Agent Orchestration |
| [2608.00901](https://arxiv.org/abs/2608.00901) | 2026-08-02 | A Decade of Healthcare Cyber Threats: Empirical Analysis, Evidence-Based Prioritisation, and AI Threat Model |
| [2608.00895](https://arxiv.org/abs/2608.00895) | 2026-08-01 | Multi-LLM Consensus Framework for Evaluating Banking-Sector NIDS Dataset Coverage of MITRE ATT&CK Techniques |
| [2607.27661](https://arxiv.org/abs/2607.27661) | 2026-07-30 | Strategy Phasing of Cyber Attacks on Digital Substations |
| [2607.26791](https://arxiv.org/abs/2607.26791) | 2026-07-29 | SecRespond: Benchmarking AI Agents for Real-World Post-Compromise Incident Response |
| [2607.24348](https://arxiv.org/abs/2607.24348) | 2026-07-27 | DeepFaith: Evidence-Grounded LLMs for Faithful Incident Reporting in Multi-Stage APT Defense |
| [2607.13087](https://arxiv.org/abs/2607.13087) | 2026-07-13 | GDM AI Control Roadmap |
| [2607.05989](https://arxiv.org/abs/2607.05989) | 2026-07-07 | ProvICS: A Provenance-based Intrusion Detection for Industrial Control Systems |
| [2607.00440](https://arxiv.org/abs/2607.00440) | 2026-07-01 | Minos: A Multi-Agent Collaborative Framework for Provenance-Based Backward Tracking |
| [2606.30586](https://arxiv.org/abs/2606.30586) | 2026-06-29 | A Hybrid Framework For Crypto-Ransomware Detection In Enterprise Shared Storage |
| [2606.21389](https://arxiv.org/abs/2606.21389) | 2026-06-19 | From Production SIEM to Reusable Cybersecurity Artifacts |
| [2606.21377](https://arxiv.org/abs/2606.21377) | 2026-06-19 | ARENA: An Architecture for Measuring the Transferability of Autonomous Cyber Defense |
| [2606.08700](https://arxiv.org/abs/2606.08700) | 2026-06-07 | AutoSUT: The Environment Semantics Gap in Structured CTI for Adversary Emulation |
| [2606.08173](https://arxiv.org/abs/2606.08173) | 2026-06-06 | AI-Native Closed-Loop Security for 6G-Enabled Cyber-Physical Systems: From Edge Detection to Network-Wide Mitigation |
| [2606.05252](https://arxiv.org/abs/2606.05252) | 2026-06-03 | From Attack Simulation to SIEM Rule: Deterministic Detection-as-Code Synthesis with Probe-Level Traceability |
| [2605.29269](https://arxiv.org/abs/2605.29269) | 2026-05-28 | HunterAgent: Neuro-Symbolic Attack Trace Reconstruction under Anti-Forensics |
| [2605.18624](https://arxiv.org/abs/2605.18624) | 2026-05-18 | Learning to Look Benign: Targeted Evasion of Malware Detectors via API Import Injection |
| [2605.13337](https://arxiv.org/abs/2605.13337) | 2026-05-13 | Context-Aware Web Attack Detection in Open-Source SIEM Systems via MITRE ATT&CK-Enriched Behavioral Profiling |
| [2605.11682](https://arxiv.org/abs/2605.11682) | 2026-05-12 | HySecTwin: A Knowledge-Driven Digital Twin Framework Augmented with Hybrid Reasoning for Cyber-Physical Systems |
| [2605.07812](https://arxiv.org/abs/2605.07812) | 2026-05-08 | GRASP -- Graph-Based Anomaly Detection Through Self-Supervised Classification |
| [2604.06148](https://arxiv.org/abs/2604.06148) | 2026-04-07 | Who Governs the Machine? A Machine Identity Governance Taxonomy (MIGT) for AI Systems Operating Across Enterprise and Geopolitical Boundaries |
| [2604.04442](https://arxiv.org/abs/2604.04442) | 2026-04-06 | Explainable Autonomous Cyber Defense using Adversarial Multi-Agent Reinforcement Learning |
| [2603.22982](https://arxiv.org/abs/2603.22982) | 2026-03-24 | How Far Should We Need to Go : Evaluate Provenance-based Intrusion Detection Systems in Industrial Scenarios |
| [2603.21296](https://arxiv.org/abs/2603.21296) | 2026-03-22 | DeepXplain: XAI-Guided Autonomous Defense Against Multi-Stage APT Campaigns |
| [2603.19658](https://arxiv.org/abs/2603.19658) | 2026-03-20 | ProHunter: A Comprehensive APT Hunting System Based on Whole-System Provenance |
| [2603.16969](https://arxiv.org/abs/2603.16969) | 2026-03-17 | DeepStage: Learning Autonomous Defense Policies Against Multi-Stage APT Campaigns |
| [2603.07560](https://arxiv.org/abs/2603.07560) | 2026-03-08 | Learning the APT Kill Chain: Temporal Reasoning over Provenance Data for Attack Stage Estimation |
| [2602.19831](https://arxiv.org/abs/2602.19831) | 2026-02-23 | An Explainable Memory Forensics Approach for Malware Analysis |
| [2602.02929](https://arxiv.org/abs/2602.02929) | 2026-02-03 | RPG-AE: Neuro-Symbolic Graph Autoencoders with Rare Pattern Mining for Provenance-Based Anomaly Detection |
| [2601.22983](https://arxiv.org/abs/2601.22983) | 2026-01-30 | PIDSMaker: Building and Evaluating Provenance-based Intrusion Detection Systems |
| [2602.00204](https://arxiv.org/abs/2602.00204) | 2026-01-30 | Semantic-Aware Advanced Persistent Threat Detection Using Autoencoders on LLM-Encoded System Logs |
| [2601.08328](https://arxiv.org/abs/2601.08328) | 2026-01-13 | APT-MCL: An Adaptive APT Detection System Based on Multi-View Collaborative Provenance Graph Learning |
| [2512.21248](https://arxiv.org/abs/2512.21248) | 2025-12-24 | Industrial Ouroboros: Deep Lateral Movement via Living Off the Plant |
| [2511.20480](https://arxiv.org/abs/2511.20480) | 2025-11-25 | Ranking-Enhanced Anomaly Detection Using Active Learning-Assisted Attention Adversarial Dual AutoEncoders |
| [2511.17761](https://arxiv.org/abs/2511.17761) | 2025-11-21 | StealthCup: Realistic, Multi-Stage, Evasion-Focused CTF for Benchmarking IDS |
| [2510.11398](https://arxiv.org/abs/2510.11398) | 2025-10-13 | Living Off the LLM: How LLMs Will Change Adversary Tactics |
| [2506.21688](https://arxiv.org/abs/2506.21688) | 2025-06-26 | CyGym: A Simulation-Based Game-Theoretic Analysis Framework for Cybersecurity |
| [2501.03898](https://arxiv.org/abs/2501.03898) | 2025-01-07 | SPECTRE: A Hybrid System for an Adaptative and Optimised Cyber Threats Detection, Response and Investigation in Volatile Memory |
| [2412.04259](https://arxiv.org/abs/2412.04259) | 2024-12-05 | SCADE: Scalable Framework for Anomaly Detection in High-Performance System |

### ⚠ Cited IDs that no longer resolve on arXiv (review — withdrawn/replaced?)

- `arXiv:2108.10422`
- `arXiv:2306.00934`
- `arXiv:2401.15878`
- `arXiv:2407.16928`
- `arXiv:2407.18832`
- `arXiv:2508.21323`
- `arXiv:2509.05698`
- `arXiv:2603.09358`
- `arXiv:2606.07158`
- `arXiv:2606.18190`

_Last run: 2026-08-17 · 50 candidate(s), 10 removal flag(s)._
<!-- RESEARCH-MONITOR:END -->
