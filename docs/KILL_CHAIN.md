# Volt Typhoon Kill Chain Reference

Quick reference for the attack chain that this detection pack targets.

## The chain in one paragraph

Break in quietly through an exposed edge device → look around to figure out where you landed → turn Windows into a tunnel using netsh portproxy → steal the password vault from Active Directory (either by copying ntds.dit or by DCSync replication abuse) → disguise the loot as a .gif image → jump to the next box using Impacket's WMI execution.

## Phase 1 — Initial access

**What:** Exploit an internet-facing device or use stolen valid credentials against VPN/RDP.

**How (observed):**
- Fortinet FortiGate (CVE-2022-42475 and successors)
- Ivanti Connect Secure
- Cisco RV320/325 SMB routers (legacy + CVE-2024-39717)
- NETGEAR ProSafe and end-of-life SOHO devices (KV-botnet)
- Valid credentials against SSL-VPN appliances

**Detection:** v3-edge queries 1, 2, 3.

**MITRE:** T1190, T1133, T1078

## Phase 2 — Discovery

**What:** Quick reconnaissance to understand the environment.

**How:** Living-off-the-land — `cmd`, `net`, `wmic`, `nltest`, occasional curl/PowerShell to external IP geolocation services.

**Signature commands:**
- `net group "Domain Admins" /domain` — who has DA rights?
- `net localgroup administrators` — who has local admin?
- `wmic logicaldisk get caption,description,providername` — what drives are mounted?
- `systeminfo` — OS, patch level, domain membership
- `ip-api.com` or `ipinfo.io` queries — what's my external IP?

**Detection:** v1-endpoint query 1.

**MITRE:** T1087, T1087.001, T1087.002, T1016, T1082, T1057, T1033

## Phase 3 — C2 tunnel via netsh portproxy

**What:** Convert a compromised internal host into a TCP port forwarder. Pivots traffic from edge into the internal network without dropping malware.

**Canonical command:**
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=<InternalIP> connectport=8443
```

**Persistence:** Writes to `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`.

**Alternative tunneling:** Fast Reverse Proxy (FRP), Earthworm, Impacket built-in proxies.

**Detection:** v1-endpoint queries 2 (process) and 3 (registry).

**MITRE:** T1090.001 (Internal Proxy), T1572 (Protocol Tunneling)

## Phase 4 — Credential access

**Two paths to ntds.dit:**

### Path A — File-based via ntdsutil IFM
**Canonical command:**
```
ntdsutil "ac i ntds" "ifm create full C:\Windows\Temp\tmp\temp.dit"
```
Touches disk. Detectable via process events and file events.

**Detection:** v1-endpoint queries 4, 5, 6.

### Path B — Replication-based via DCSync
Requests AD replication rights using the DRSUAPI protocol. Hashes returned over the network. **Never touches disk.**

**Detection:** v2-advanced queries 2 (MDI) and 3 (Event 4662 with replication GUIDs).

**MITRE:** T1003.003 (NTDS), T1003.006 (DCSync), T1003.001, T1003.002, T1003.004

## Phase 5 — Staging & exfiltration

**What:** Compress the loot, disguise it as something innocuous.

**Signature behavior:**
- 7zip or RAR with password protection and encrypted headers (`-mhe -p`)
- Rename output to `.gif`, `.jpg`, or `.png` extension
- Move to a publicly-writable location for later retrieval

**Detection:** v1-endpoint query 7.

**MITRE:** T1560.001 (Archive via Utility), T1036.008 (Masquerade File Type)

## Phase 6 — Lateral movement

**What:** Move to the next host using stolen credentials.

**Signature tool:** Impacket `wmiexec.py` — leaves a distinctive fingerprint:
- Parent: `wmiprvse.exe`
- Child: `cmd.exe`
- Output redirect: `\\127.0.0.1\ADMIN$\__<timestamp>`

**Detection:** v1-endpoint query 8.

**MITRE:** T1047 (WMI), T1021.002 (SMB/Admin Shares)

## The capstone

Any single phase has plausible benign explanations:
- Admins do discovery
- Developers occasionally use port forwarding
- Backup software touches AD database paths
- IT runs WMI scripts

**Combinations under one account in 24 hours do not.** The cross-device capstone (v2-advanced query 4) is the keystone — it correlates phases across multiple hosts and produces incident-grade alerts when `PhaseCount >= 3`.

## Visual summary

See `diagrams/volt_typhoon_kill_chain.svg` for the visual version of this reference.
