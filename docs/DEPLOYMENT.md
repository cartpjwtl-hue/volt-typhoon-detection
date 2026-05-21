# Deployment Guide

Recommended rollout order for the detection pack. Don't deploy everything at once — tune each detection before moving to the next.

## Prerequisites

- **Microsoft Defender XDR** or **Microsoft Sentinel** with the following tables active:
  - `DeviceProcessEvents`
  - `DeviceRegistryEvents`
  - `DeviceFileEvents`
  - `SecurityEvent` (for DCSync via Event 4662)
- For v3 edge queries: **CommonSecurityLog** populated by a CEF data connector and at least one of:
  - Fortinet FortiGate syslog
  - Cisco syslog
  - DnsEvents (Sentinel DNS connector)
- For DCSync detection: **Audit Directory Service Access** policy enabled on DCs, plus a SACL on the domain naming context for the three replication rights

## Rollout phases

### Phase 1 — Day 1 (deploy as P1 alerts, near-zero false positives)

These have such low false-positive rates that you can promote them to alerts immediately.

| Query | Severity | Why first |
|---|---|---|
| `v2-advanced/03_dcsync_event_4662.kql` | Critical | After filtering DC accounts and MSOL_, anything left is essentially malicious |
| `v1-endpoint/02_netsh_portproxy_process.kql` | High | netsh portproxy is rare in normal environments |
| `v1-endpoint/03_netsh_portproxy_registry.kql` | High | Registry corroboration of the above |
| `v1-endpoint/04_ntdsutil_ifm.kql` | Critical | ntdsutil `ifm create full` outside change window is rarely benign |
| `v1-endpoint/08_impacket_wmiexec.kql` | High | The exact parent-child + ADMIN$ pattern is Impacket's signature |

### Phase 2 — Week 1 (deploy after tuning)

Run as scheduled hunts for one week, allow-list known sources, then promote to alerts.

| Query | Tuning effort |
|---|---|
| `v1-endpoint/01_discovery_lotl.kql` | Allow-list IT inventory tools, jump boxes, admin accounts |
| `v1-endpoint/05_ntds_alt_methods.kql` | Allow-list backup software paths |
| `v1-endpoint/06_ntds_file_landing.kql` | Allow-list backup destination paths |
| `v2-advanced/01_encoded_powershell.kql` | Filter known installer signatures; tune Score threshold |
| `v1-endpoint/07_staging_gif_masquerade.kql` | Low FP rate but check archive software in use |

### Phase 3 — Week 1 (capstone deployment)

Deploy the capstone after individual detections are tuned. It joins their evidence into incident-grade alerts.

| Query | Notes |
|---|---|
| `v2-advanced/04_capstone_account_cross_device.kql` | Schedule every 30 minutes. PhaseCount ≥ 3 = automatic incident |
| `v1-endpoint/09_capstone_device.kql` | Single-host fallback if account-based capstone misses cross-host chains |

### Phase 4 — Week 2-4 (edge telemetry, requires ingestion work)

| Query | Prerequisite |
|---|---|
| `v3-edge/01_fortinet_exploit.kql` | FortiGate CEF connector configured |
| `v3-edge/02_cisco_router_exploit.kql` | Cisco syslog → CEF |
| `v3-edge/03_vpn_auth_anomaly.kql` | VPN appliance syslog ingestion |
| `v3-edge/04_kvbotnet_beaconing.kql` | NetFlow/IPFIX export from perimeter |
| `v3-edge/05_dns_ddns_hunting.kql` | DnsEvents data connector |
| `v3-edge/06_edge_config_drift.kql` | Network device admin syslog |
| `v3-edge/07_eol_device_inventory.kql` | Sentinel watchlist `Edge_Device_Inventory` populated |
| `v3-edge/08_capstone_edge_to_endpoint.kql` | Phase 1–3 deployed AND edge ingestion live |

## Tuning principles

1. **Run as hunting query for one week first.** Look at every result. Build the allow-list before turning on alerts.
2. **Use UEBA-style baselining where possible.** "This account has never run this command before" filters more accurately than "this command is suspicious."
3. **Tag your DCs and Tier-0 assets.** Many detections gain critical context when joined against `DeviceInfo` with role information.
4. **Don't ignore yellow.** A score-2 detection isn't ready for P1 alerting but is valuable as a daily hunt review.

## Incident response — what to do when a capstone fires

The cross-device capstone is designed to be incident-grade. When it fires with `PhaseCount >= 3`:

1. **Isolate** every host in `DevicesTouched` immediately (Defender → "Isolate device")
2. **Disable** the `AccountName` in Active Directory and revoke active Kerberos tickets
3. **Snapshot** the affected DCs before further investigation
4. **Hunt** for the missing phases — if you see Discovery + Proxy + NTDS, the operator likely also did persistence and lateral movement; query for those next
5. **Escalate** to your IR retainer / leadership per your playbook

The capstone tells you the chain happened. It does not tell you you've found everything. Assume persistence exists and hunt for it.

## What this pack does not deploy

- **Sigma rules** (planned — see roadmap)
- **Sentinel analytics rule YAML** (planned)
- **Defense Impairment detections** (v4 roadmap)
- **Persistence detections** (v5 roadmap)

If you need any of these now, see `CONTRIBUTING.md` — PRs welcome.
