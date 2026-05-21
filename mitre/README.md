# MITRE ATT&CK Coverage Layers

Three versioned coverage layers showing how the detection pack has evolved.

## Files

| File | ATT&CK Version | Coverage | Use this if... |
|---|---|---|---|
| `volt_typhoon_attack_layer_v1.json` | v15 | Endpoint only | You're on an older Navigator instance |
| `volt_typhoon_attack_layer_v19_v2.json` | v19.1 | Endpoint + DCSync + encoded PS | You haven't added edge telemetry yet |
| **`volt_typhoon_attack_layer_v19_v3.json`** | **v19.1** | **Endpoint + edge** | **Current — use this one** |
| `volt_typhoon_coverage_v19_v3.csv` | v19.1 | Same data as v3 | Pivot tables, exec reports |

## How to use

1. Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **"Open Existing Layer"** → **"Upload from local"**
3. Select `volt_typhoon_attack_layer_v19_v3.json`

The heatmap renders with detection coverage scored 0–3:
- **Red (0)** — Blind spot, no telemetry
- **Yellow (1)** — Hunting only / partial
- **Light green (2)** — Single-phase detection
- **Dark green (3)** — High-fidelity / capstone

## Coverage summary (v3)

58 techniques across 12 tactics:
- 9 high-fidelity
- 23 single-phase
- 16 partial / hunting
- 10 blind spots

Strongest tactics: Execution (2.20), Stealth (2.00), Initial Access (2.00).
Weakest tactics: Defense Impairment (0.00), Exfiltration (0.50), Persistence (0.50).

See the root `README.md` and `docs/METHODOLOGY.md` for the full scoring rationale.
