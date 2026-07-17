# MITRE ATT&CK Coverage Layers

Three versioned coverage layers showing how the detection pack has evolved.

## Files

| File | ATT&CK Version | Coverage | Use this if... |
|---|---|---|---|
| `volt_typhoon_attack_layer_v1.json` | v15 | Endpoint only | You're on an older Navigator instance |
| `volt_typhoon_attack_layer_v19_v2.json` | v19.1 | Endpoint + DCSync + encoded PS | You haven't added edge telemetry yet |
| `volt_typhoon_attack_layer_v19_v3.json` | v19.1 | Endpoint + edge | You haven't added registry telemetry yet |
| **`volt_typhoon_attack_layer_v19_v4.json`** | **v19.1** | **Endpoint + edge + registry** | **Current — use this one** |
| `volt_typhoon_coverage_v19_v4.csv` | v19.1 | Same data as v4 | Pivot tables, exec reports |

## How to use

1. Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **"Open Existing Layer"** → **"Upload from local"**
3. Select `volt_typhoon_attack_layer_v19_v4.json`

The heatmap renders with detection coverage scored 0–3:
- **Red (0)** — Blind spot, no telemetry
- **Yellow (1)** — Hunting only / partial
- **Light green (2)** — Single-phase detection
- **Dark green (3)** — High-fidelity / capstone

## Coverage summary (v4)

64 techniques across 12 tactics:
- 11 high-fidelity
- 34 single-phase
- 13 partial / hunting
- 6 blind spots

Strongest tactics: Execution (2.40), Stealth (2.12), Defense Impairment (2.00), Initial Access (2.00).
Weakest tactics: Exfiltration (0.50), Resource Development (1.00), Persistence (1.33).

The v4 registry pack closes the two former weak spots: Defense Impairment **0.00 → 2.00** and
Persistence **0.50 → 1.20** (Lateral Movement also rises 1.25 → 1.60).

See the root `README.md` and `docs/METHODOLOGY.md` for the full scoring rationale.
