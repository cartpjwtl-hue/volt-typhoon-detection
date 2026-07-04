# v1 — Endpoint detections

Phase-by-phase KQL detections targeting Microsoft Defender XDR and Sentinel endpoint tables.

## Queries

| # | File | What it catches | MITRE | Fidelity |
|---|---|---|---|---|
| 1 | `01_discovery_lotl.kql` | LOTL recon commands | T1087, T1016, T1082 | Score 2 |
| 2 | `02_netsh_portproxy_process.kql` | netsh portproxy creation | T1090.001 | Score 3 |
| 3 | `03_netsh_portproxy_registry.kql` | PortProxy registry corroboration | T1090.001 | Score 3 |
| 4 | `04_ntdsutil_ifm.kql` | ntdsutil IFM AD database theft | T1003.003 | Score 3 |
| 5 | `05_ntds_alt_methods.kql` | vssadmin / reg save / comsvcs MiniDump | T1003 | Score 2 |
| 5b | `05b_alt_dump_methods_v2.kql` | **All-inclusive** alt credential-dump: shadow-copy (vssadmin/diskshadow/wbadmin/wmic/PS/ntdsutil snapshot) + NTDS/hive extraction + LSASS dump LOLBins, method-classified, with VSS-registry corroboration | T1003, T1003.001-.004, T1006 | Score 2-3 |
| 6 | `06_ntds_file_landing.kql` | ntds.dit file written outside backup paths | T1003.003 | Score 2 |
| 7 | `07_staging_gif_masquerade.kql` | 7zip + .gif rename trick | T1560.001, T1036.008 | Score 2 |
| 8 | `08_impacket_wmiexec.kql` | Impacket lateral movement signature | T1047 | Score 3 |
| 9 | `09_capstone_device.kql` | Multi-phase correlation on one device | Multi | Capstone |

## Data sources

All queries assume Microsoft Defender XDR or Sentinel with:
- `DeviceProcessEvents`
- `DeviceRegistryEvents`
- `DeviceFileEvents`

## Limitations

- Catches the documented Volt Typhoon playbook unmodified
- Obfuscation may defeat string matching — see `v2-advanced/01_encoded_powershell.kql`
- Single-device chain correlation misses cross-host attacks — see `v2-advanced/04_capstone_account_cross_device.kql`
- Edge device exploitation invisible — see `v3-edge/`
