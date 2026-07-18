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

_Not yet populated. The first scheduled run of `research-monitor` will fill this in._

_Last run: never._
<!-- RESEARCH-MONITOR:END -->
