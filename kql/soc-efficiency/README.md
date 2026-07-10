# SOC efficiency — operational metrics

Not detections — these queries measure how the SOC itself performs when handling the incidents the detection packs generate.

## Queries

| # | File | What it measures | Data source |
|---|---|---|---|
| 1 | `01_t1_t2_escalation_metrics.kql` | T1 time-before-escalation and T2 mean-time-to-close per incident | `SecurityIncident` |

## How query 1 works

The `SecurityIncident` table writes a new row every time an incident is modified. The query serializes each incident's rows chronologically and compares `Owner.userPrincipalName` against the previous row to find owner changes — a change of owner is treated as an escalation (T1 → T2 handoff). If an incident is handed off more than once, the **last** owner change before closure is used.

For every closed incident it reports:

- **T1_TimeBeforeEscalation** — incident creation until the escalation
- **T2_TimeToClose** — escalation until the incident was closed
- **T2_MTTC_Hours** — the T2 phase in hours, for dashboard-friendly reporting

## Caveats

- Only incidents with a `Closed` status row are included (`join kind=inner` + `isnotempty(ClosedTime)`).
- Incidents closed by the original owner without a handoff never appear — this measures escalated incidents only.
- The owner-change heuristic can't distinguish a T1 → T2 escalation from any other reassignment (e.g. shift change within the same tier).
