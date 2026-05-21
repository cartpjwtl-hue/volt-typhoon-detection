# v3 — Edge device telemetry

Detections for the initial-access blind spot: Fortinet/Cisco exploits, KV-botnet C2, edge-to-endpoint chain correlation.

## Queries

| # | File | What it catches | MITRE | Fidelity |
|---|---|---|---|---|
| 1 | `01_fortinet_exploit.kql` | FortiGate SSL-VPN exploit indicators | T1190 | Score 2 |
| 2 | `02_cisco_router_exploit.kql` | Cisco RV/ASA/IOS exploit indicators | T1190 | Score 2 |
| 3 | `03_vpn_auth_anomaly.kql` | VPN logins from anomalous geography | T1133, T1078 | Score 2 |
| 4 | `04_kvbotnet_beaconing.kql` | Periodic outbound on port 8443 | T1090.003, T1572 | Score 2 |
| 5 | `05_dns_ddns_hunting.kql` | DNS to dynamic-DNS providers | T1071.001 | Score 1 |
| 6 | `06_edge_config_drift.kql` | Off-hours firewall config changes | T1584, T1098 | Score 2 |
| 7 | `07_eol_device_inventory.kql` | EOL device hygiene hunt | Pre-detection | Asset hygiene |
| 8 | `08_capstone_edge_to_endpoint.kql` | Edge compromise + endpoint chain on same account | Multi | Keystone |

## Data sources

- **`CommonSecurityLog`** populated by the CEF data connector
- **`DnsEvents`** from the Sentinel DNS connector
- **`DeviceProcessEvents`** (for the edge-to-endpoint capstone)
- Sentinel watchlist `Edge_Device_Inventory` (for query 7)

## Setup steps

1. **Install the CEF data connector** in Microsoft Sentinel
2. **Configure a Linux syslog forwarder** (or Azure Monitor Agent) to receive CEF from edge devices
3. **Enable CEF forwarding** on FortiGate / Cisco / etc:
   - FortiGate: `config log syslogd setting` → `set format cef` → `set server <forwarder-ip>`
   - Cisco ASA: `logging host <forwarder-ip> 6/udp` with proper format
4. **Verify data flow** with a sanity-check query:
   ```kql
   CommonSecurityLog
   | summarize count() by DeviceVendor, DeviceProduct
   ```
5. **Enable NetFlow export** from perimeter devices for query 4
6. **Enable DNS query logging** for query 5
7. **Populate the EOL inventory watchlist** for query 7

## Coverage impact

Adding edge telemetry lifts these techniques on the MITRE map:
- T1190 Exploit Public-Facing App: 0 → 2
- T1133 External Remote Services: 0 → 2
- T1078 Valid Accounts: 1 → 2
- T1090.003 Multi-hop Proxy: 1 → 2
- T1572 Protocol Tunneling: 1 → 2
- T1584.005 Botnet: NEW → 1

**Initial Access tactic: 0.50 → 2.00** (4× uplift).

## Limitations

- **Consumer SOHO routers** don't emit syslog. Compensate with policy (corporate devices, block split tunneling) and identity controls (phishing-resistant MFA, conditional access).
- **NetFlow query** assumes you have visibility into outbound traffic. If your firewall doesn't export flows, this query produces nothing.
- **DNS DDNS hunting** misses attackers using DoH (DNS over HTTPS) to bypass internal resolvers. Block external DoH at the firewall.
