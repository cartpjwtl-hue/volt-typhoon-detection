# Sigma rules

Vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma) conversions of the pack's highest-value
detections. Sigma is a generic signature format for log events — convert these to your SIEM's query
language (Sentinel/Defender KQL, Splunk SPL, Elastic, QRadar, …) with `sigma convert` (pySigma) or
the SigmaHQ backends.

## Rules

| File | Detects | MITRE | Log source |
|---|---|---|---|
| `proc_netsh_portproxy.yml` | netsh portproxy C2 relay | T1090.001 | process_creation |
| `proc_ntdsutil_ifm.yml` | ntds.dit theft via ntdsutil IFM | T1003.003 | process_creation |
| `proc_comsvcs_lsass_minidump.yml` | LSASS dump via comsvcs (incl. `#24`) | T1003.001 | process_creation |
| `registry_portproxy.yml` | PortProxy registry rule | T1090.001, T1112 | registry_set |
| `registry_defender_tamper.yml` | Defender policy/service disable | T1562.001, T1112 | registry_set |
| `registry_wdigest_downgrade.yml` | WDigest plaintext downgrade | T1003.001, T1112 | registry_set |
| `procaccess_lsass_handle.yml` | LSASS handle access (dump-capable) | T1003.001 | process_access (Sysmon 10) |
| `eventlog_security_log_cleared.yml` | Security log cleared (1102) | T1070.001 | windows/security |
| `eventlog_service_install.yml` | Suspicious service install (7045) | T1543.003, T1569.002 | windows/system |
| `wmi_event_subscription.yml` | WMI permanent subscription persistence | T1546.003 | wmi_event (Sysmon 19-21) |

## Convert to your SIEM

```bash
pip install sigma-cli pysigma-backend-microsoft365defender pysigma-backend-splunk

# Microsoft Defender / Sentinel KQL
sigma convert -t microsoft365defender sigma/proc_netsh_portproxy.yml

# Splunk
sigma convert -t splunk sigma/registry_portproxy.yml
```

## Field-mapping notes

- **Tuned KQL is authoritative.** These Sigma rules are portable equivalents of the pack's KQL;
  the KQL files carry the fuller logic (severity scoring, hex/decimal DWORD handling, allow-lists).
  Treat Sigma as the starting point and re-apply your environment's tuning after conversion.
- **`registry_set` Details field.** DWORD rendering differs by backend/agent (`1` vs
  `DWORD (0x00000001)`); both forms are listed. Adjust to your registry-event source.
- **`process_access`** requires Sysmon Event ID 10 (or an EDR that emits handle-access events).
- **`wmi_event`** maps to Sysmon Event ID 19/20/21; field names (`Consumer`, `Destination`) follow
  the Sysmon WMI schema.
- **Status is `experimental`** on every rule — validate against your data before promoting to alert.
