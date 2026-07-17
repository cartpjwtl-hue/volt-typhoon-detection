# Microsoft Sentinel analytics rules

Production-ready packaging of the pack's highest-fidelity detections as **Microsoft Sentinel
scheduled analytics rules**, with entity mappings for investigation graph / UEBA correlation.

Two consumable formats:

| Path | Format | Use |
|---|---|---|
| `analytics/*.yaml` | Sentinel rule YAML (Azure-Sentinel repo schema) | Import via the content-hub / `az sentinel`, or review per-rule |
| `deploy_analytics_rules.json` | ARM template | One-click deploy of all rules into a workspace |

## Rules included

| Rule | Severity | Tactic | Technique | Data type |
|---|---|---|---|---|
| PortProxy Registry Rule Creation | High | C2 / Defense Evasion | T1090.001, T1112 | `DeviceRegistryEvents` |
| NTDS.dit Theft via ntdsutil IFM | High | Credential Access | T1003.003 | `DeviceProcessEvents` |
| LSASS Dump via comsvcs MiniDump | High | Credential Access | T1003.001 | `DeviceProcessEvents` |
| Security Event Log Cleared | High | Defense Evasion | T1070.001 | `SecurityEvent` |

The `analytics/` folder additionally carries each rule as standalone YAML (same four rules). Extend
the set by converting any `kql/**` detection — the pattern is identical.

## Deploy the ARM template

Portal: **Deploy a custom template** → load `deploy_analytics_rules.json` → supply `workspaceName`.

CLI:

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file sentinel/deploy_analytics_rules.json \
  --parameters workspaceName=<your-sentinel-workspace> rulesEnabled=true
```

The template creates `Microsoft.SecurityInsights/alertRules` (kind `Scheduled`) resources under the
named workspace, keyed by stable GUIDs so re-deploying **updates** rather than duplicates.

## Entity mappings

Every rule maps `Host` and `Account` (and `Process` where available) so alerts populate the Sentinel
investigation graph and feed entity behavior analytics. Adjust `columnName`s if you rename projected
columns.

## Notes

- `queryFrequency` / `queryPeriod` default to **1 hour**; tune per rule and per data latency. The
  registry/process rules can run tighter (10-15 min) in high-value environments.
- `requiredDataConnectors` in the YAML declare the dependency (`MicrosoftThreatProtection` for the
  Device* tables, `SecurityEvents` for `SecurityEvent`). Deploy the matching data connector first.
- Rules are `status: Available` / `enabled: true` by default — set `rulesEnabled=false` on the ARM
  deployment to stage them disabled and enable after tuning.
- The KQL here is the trimmed, alert-shaped form. The full logic (scoring, allow-lists, hex/decimal
  DWORD handling) lives in the `kql/**` source files — port additional tuning from there.
