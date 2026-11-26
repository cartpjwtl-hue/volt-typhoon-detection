# Volt Typhoon — All Detection Queries (KQL)

> Generated from `actors/volt_typhoon.md` and `docs/04_ATOM_AND_LOLBIN_FUNCTIONS.md`.
> Source of truth is the markdown in the repo; this is a single-file roll-up of every query.

**9 behavior rules** (kill-chain order) · **3 proposed functions**

## Index

- [`BEH-IA-001`](#beh-ia-001) — Risk-Flagged Authentication Sequence on PublicFacing Asset · _Medium_
- [`BEH-DE-002`](#beh-de-002) — Pre-Pivot Recon & Evasion on OT-Adjacent Host · _Medium_
- [`BEH-CA-008`](#beh-ca-008) — Credential Harvesting Beyond MDE Native · _Medium_
- [`BEH-CA-011`](#beh-ca-011) — Alternative Credential Dump Paths (VSS / NTDS / HIVE / LSASS) · _High_
- [`BEH-CA-012`](#beh-ca-012) — NTDS Database Path & Diagnostics Registry Tampering · _High_
- [`BEH-CA-013`](#beh-ca-013) — LSASS Credential Exposure & Protection Downgrade · _Critical_
- [`BEH-LM-003`](#beh-lm-003) — Authenticated Boundary Crossing into CIP_Jump · _Medium_
- [`BEH-PE-010`](#beh-pe-010) — Local Account / Persistence on CIP-Adjacent Host · _Medium_
- [`BEH-C2-014`](#beh-c2-014) — netsh PortProxy Relay (process + registry) · _High_


## BEH-IA-001 — Risk-Flagged Authentication Sequence on PublicFacing Asset

- **Phase:** Initial Access  ·  **Severity:** Medium
- **Platform:** Microsoft Defender XDR (+ Sentinel data sources)  ·  **Frequency:** Every 15 min  ·  **Lookback:** 4 h *(Open Q: low-and-slow → may become dynamic)*
- **MITRE:** T1078.002, T1110.003, T1133, T1621, T1539
- **Atoms:** `ATOM-IA-RISKAUTH`

```kql
// BEH-IA-001 — Risk-Flagged Authentication Sequence on PublicFacing Asset
// Platform: Microsoft Defender XDR | Frequency: 15min | Lookback: 4h (Open Q)
// Functions: Get_CIP_Accounts(), Get_SuppressedSources()
// Tables: CloudAppEvents, IdentityLogonEvents
let RecentLockouts =
    IdentityLogonEvents
    | where Timestamp > ago(24h)
    | where ActionType == "Account locked out"
    | project LockoutTime = Timestamp, Account = tolower(AccountUpn);
let RiskyAuth =
    CloudAppEvents
    | where Timestamp > ago(4h)
    | where ActionType in~ ("LogOn", "UserLoggedIn", "Add-Mailbox-Auth-Success")   // Validate ActionType in tenant
    | where RawEventData has_any ("Success", "success")
    | where RiskLevelDuringSignIn in~ ("Low", "Medium", "High")                    // Validate casing in tenant
    | where IPCategory == "Other" or IPTags has "Guest_WiFi"                       // untrusted source context
    | where IPAddress !in (Get_SuppressedSources())                                // exclude known-good scanners
    | extend Account = tolower(AccountUpn), AppName = Application,
             SourceContext = case(IPTags has "Guest_WiFi", "Guest_WiFi",
                                  IPCategory == "Other", "External", "Unknown")
    | project Timestamp, Account, IPAddress, AppName, RiskLevel = RiskLevelDuringSignIn, SourceContext;
let CIPAccountSuccess =
    RiskyAuth
    | join kind=inner (Get_CIP_Accounts() | project Account = tolower(AccountUpn)) on Account
    | extend Trigger = "5a-CIPAccount";
let LockoutPrecedesSuccess =
    RiskyAuth
    | join kind=inner RecentLockouts on Account
    | where Timestamp > LockoutTime
    | extend Trigger = "5b-PostLockoutSuccess";
union CIPAccountSuccess, LockoutPrecedesSuccess
| extend AlertSeverity = "Medium",
         AlertDetail = strcat("Risk-flagged auth: ", Account, " | App: ", AppName, " | Risk: ", RiskLevel,
                              " | Source: ", SourceContext, " | IP: ", IPAddress, " | Trigger: ", Trigger),
         PlaybookHint = strcat("Watch BEH-DE-002 / BEH-LM-003 on ", Account, " next 4-12h")
| project Timestamp, Account, IPAddress, AppName, RiskLevel, SourceContext, Trigger, AlertSeverity, AlertDetail, PlaybookHint
```

## BEH-DE-002 — Pre-Pivot Recon & Evasion on OT-Adjacent Host

- **Phase:** Defense Evasion / Discovery  ·  **Severity:** Medium
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 1 hour  ·  **Lookback:** 2 h rolling *(Open Q: low-and-slow)*
- **MITRE:** T1562.001, T1070.001, T1059.003, T1218.011, T1069.002, T1018, T1049, T1016
- **Atoms:** `ATOM-DISC-LOLBIN-CLUSTER`, `ATOM-DE-LOGCLEAR`, `ATOM-DE-DEFIMPAIR`

```kql
// BEH-DE-002 — Pre-Pivot Reconnaissance & Evasion on OT-Adjacent Host
// Platform: Microsoft Defender XDR | Frequency: 1h | Lookback: 2h
// Functions: Get_CIP_Jump_Hosts(), Get_CIP_Mgmt_Hosts(), IsInMaintenanceWindow()
// Tables: DeviceProcessEvents, DeviceEvents
let CIP_Hosts =
    union (Get_CIP_Jump_Hosts()), (Get_CIP_Mgmt_Hosts())
    | project DeviceId, DeviceName, AssetClass, SafetyCritical = DeviceTags has "SafetyCritical";
let LOLBins = dynamic(["netstat.exe","ipconfig.exe","net.exe","net1.exe","wmic.exe","nltest.exe",
                       "ping.exe","arp.exe","whoami.exe","quser.exe","systeminfo.exe","tasklist.exe",
                       "rundll32.exe","regsvr32.exe"]);
let DefSvcs = dynamic(["MsSense","WinDefend","Sense","MsMpEng","mpssvc","wscsvc"]);
let Discovery =
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | where FileName in~ (LOLBins)
    | where InitiatingProcessFileName !in~ ("explorer.exe","userinit.exe")
    | join kind=inner CIP_Hosts on DeviceId
    | summarize BinCount = dcount(FileName), BinList = make_set(FileName, 10), DiscoveryTime = min(Timestamp)
        by DeviceId, DeviceName, AssetClass, SafetyCritical, InitiatingProcessAccountName, bin(Timestamp, 10m)
    | where BinCount >= 3;
let Evasion =
    union
    (DeviceEvents
        | where Timestamp > ago(2h)
        | where ActionType in~ ("EventLogCleared","SecurityLogCleared")
        | extend EvasionType = "LogCleared"),
    (DeviceProcessEvents
        | where Timestamp > ago(2h)
        | where FileName in~ ("sc.exe","net.exe","net1.exe","reg.exe")
        | where ProcessCommandLine has_any (DefSvcs)
        | where ProcessCommandLine has_any ("stop","delete","disable")
        | extend EvasionType = "DefenseImpair")
    | join kind=inner CIP_Hosts on DeviceId
    | project DeviceId, EvasionTime = Timestamp, EvasionType, InitiatingProcessAccountName;
Discovery
| join kind=inner Evasion on DeviceId
| where abs(datetime_diff("minute", DiscoveryTime, EvasionTime)) <= 120
| where IsInMaintenanceWindow(DeviceName, DiscoveryTime) == false
| extend AlertDetail = strcat("Pre-pivot sequence on ", DeviceName, " (", AssetClass, ")",
                              " | Discovery: ", strcat_array(BinList, ","),
                              " | Evasion: ", EvasionType, " | Account: ", InitiatingProcessAccountName)
| project DiscoveryTime, EvasionTime, DeviceName, AssetClass, SafetyCritical,
          InitiatingProcessAccountName, BinList, EvasionType, AlertDetail
```

## BEH-CA-008 — Credential Harvesting Beyond MDE Native

- **Phase:** Credential Access  ·  **Severity:** Medium
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 30 min  ·  **Lookback:** 2 h rolling
- **MITRE:** T1555.003 (browser), T1555.004 (Windows cred mgr / DPAPI), T1558.003 (Kerberoasting), T1552.001
- **Atoms:** `ATOM-CA-BROWSERCRED`, `ATOM-CA-DPAPI`, `ATOM-CA-KERBEROAST` (native-MDI backstop)

```kql
// BEH-CA-008 — Credential Harvesting Beyond MDE Native
// Platform: Microsoft Defender XDR | Frequency: 30min | Lookback: 2h
// Tables: DeviceFileEvents, IdentityLogonEvents
// NOTE: DCSync (T1003.006) and core Kerberoasting are MDI-native — (C) here is a tunable backstop.
let BrowserCredFiles = dynamic([
    @"\Google\Chrome\User Data\Default\Login Data",
    @"\Microsoft\Edge\User Data\Default\Login Data",
    @"\Mozilla\Firefox\Profiles\", "logins.json", "key4.db"]);
let LegitBrowsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe"]);
let BrowserCredAccess =
    DeviceFileEvents
    | where Timestamp > ago(2h)
    | where ActionType in~ ("FileCreated","FileModified","FileRead")
    | where FolderPath has_any (BrowserCredFiles) or FileName in~ ("logins.json","key4.db")
    | where InitiatingProcessFileName !in~ (LegitBrowsers)
    | extend Technique = "T1555.003-BrowserCreds",
             AlertDetail = strcat("Browser cred file accessed by ", InitiatingProcessFileName, " on ", DeviceName);
let DPAPIPath = @"\Microsoft\Protect\";
let LegitDPAPIAccessors = dynamic(["lsass.exe","svchost.exe","explorer.exe","winlogon.exe","system"]);
let DPAPIAccess =
    DeviceFileEvents
    | where Timestamp > ago(2h)
    | where FolderPath has DPAPIPath
    | where InitiatingProcessFileName !in~ (LegitDPAPIAccessors)
    | extend Technique = "T1555.004-DPAPI",
             AlertDetail = strcat("DPAPI master key access by ", InitiatingProcessFileName, " on ", DeviceName);
let Kerberoasting =
    IdentityLogonEvents
    | where Timestamp > ago(2h)
    | where ActionType == "Kerberos service ticket request"
    | summarize SPNCount = dcount(ServiceName), SPNList = make_set(ServiceName, 20), First = min(Timestamp)
        by AccountName, bin(Timestamp, 5m)
    | where SPNCount >= 10
    | extend Technique = "T1558.003-Kerberoasting", DeviceName = "DomainController",
             InitiatingProcessFileName = "kerberos",
             AlertDetail = strcat("Kerberoasting: ", AccountName, " requested ", SPNCount, " distinct SPNs in 5m");
union BrowserCredAccess, DPAPIAccess, (Kerberoasting | extend Timestamp = First)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, Technique, AlertDetail
```

## BEH-CA-011 — Alternative Credential Dump Paths (VSS / NTDS / HIVE / LSASS)

- **Phase:** Credential Access  ·  **Severity:** High — Medium for bare shadow-copy creation and PowerShell inline-compile
- **Platform:** Microsoft Defender XDR (Custom Detection) — Sentinel-compatible  ·  **Frequency:** Every 1 hour  ·  **Lookback:** 24 h detection / 30 d hunt (`let lookback`)
- **MITRE:** T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1006, T1059.001
- **Atoms:** `ATOM-CA-LSASS-COMSVCS`, `-LSASS-LOLBIN`, `-LSASS-HANDLEDUP`, `-LSASS-REFLECTION`, `ATOM-CA-NTDS-IFM/-VSS/-ESENTUTL/-PSCOPY/-DSINTERNALS`, `ATOM-CA-HIVE-REGSAVE`

```kql
// BEH-CA-011 - Alternative Credential Dump Paths (VSS / NTDS / HIVE / LSASS)
// Platform:   Microsoft Defender XDR Custom Detection | Sentinel-compatible
// Frequency:  Every 1h | Lookback: 24h detection, 30d hunt
// Tables:     DeviceProcessEvents, DeviceRegistryEvents
// MITRE:      T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1006, T1059.001
// Supersedes: Phase 3b v1 (vssadmin + reg save + esentutl + comsvcs only)
// Scope note: destructive shadow abuse (vssadmin/wmic delete shadows, T1490) is OUT of
//             scope - this rule is credential access, not recovery inhibition.
let lookback  = 24h;                                    // hunt mode: 30d
let ps_hosts  = dynamic(["powershell.exe","pwsh.exe"]);
let copy_bins = dynamic(["cmd.exe","xcopy.exe","robocopy.exe","copy.exe"]);
let proc_dumps =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | extend Cmd = tolower(ProcessCommandLine)
    | extend ParentIsPS = InitiatingProcessFileName in~ (ps_hosts)
    | extend DumpMethod = case(
        // --- A. Shadow-copy creation --------------------------------------------
        FileName =~ "vssadmin.exe" and Cmd has "create shadow",         "VSS:vssadmin",
        FileName =~ "diskshadow.exe"
            and (Cmd has_any ("create","expose","/s") or Cmd has_any (".dsh",".txt")),
                                                                        "VSS:diskshadow",
        FileName =~ "wbadmin.exe" and Cmd has "start backup",           "VSS:wbadmin",
        FileName =~ "vshadow.exe"
            and Cmd has_any ("-p","-nw","-script","-exec"),             "VSS:vshadow",
        FileName =~ "wmic.exe"
            and Cmd has "shadowcopy" and Cmd has "call create",         "VSS:wmic",
        FileName in~ (ps_hosts)
            and Cmd has "win32_shadowcopy" and Cmd has "create",        "VSS:powershell-cim",
        FileName =~ "ntdsutil.exe" and Cmd has "snapshot",              "VSS:ntdsutil-snapshot",
        // --- B. NTDS / registry-hive extraction ----------------------------------
        FileName =~ "ntdsutil.exe"
            and Cmd has_any ("ifm","create full","ac i ntds","activate instance ntds"),
                                                                        "NTDS:ntdsutil-ifm",
        FileName =~ "esentutl.exe"
            and (Cmd has "/vss" or (Cmd has "/y" and Cmd has "ntds") or Cmd has "ntds.dit"),
                                                                        "NTDS:esentutl-copy",
        Cmd has "globalroot"
            and Cmd has_any ("ntds.dit", @"\config\system", @"\config\security",
                             @"\config\sam"),                           "NTDS:shadow-copy-out",
        // PowerShell-native read/copy of the .dit - no VSS utility involved
        FileName in~ (ps_hosts) and Cmd has "ntds.dit"
            and Cmd has_any ("copy-item","get-content","[io.file]","::readallbytes",
                             "::copy","set-content","move-item"),       "NTDS:powershell-copy",
        // Offline .dit parsing (DSInternals) and raw-handle read (NinjaCopy)
        Cmd has_any ("get-addbaccount","get-addbbackupkey","get-bootkey","dsinternals"),
                                                                        "NTDS:dsinternals",
        Cmd has "invoke-ninjacopy",                                     "NTDS:ninjacopy",
        FileName in~ (copy_bins) and Cmd has "ntds.dit",                "NTDS:filecopy",
        FileName =~ "reg.exe"
            and Cmd has_any ("save","export") and Cmd has @"hklm\sam",  "HIVE:reg-save-SAM",
        FileName =~ "reg.exe"
            and Cmd has_any ("save","export")
            and Cmd has @"hklm\security",                               "HIVE:reg-save-SECURITY",
        FileName =~ "reg.exe"
            and Cmd has_any ("save","export") and Cmd has @"hklm\system",
                                                                        "HIVE:reg-save-SYSTEM",
        // --- C. LSASS memory dump -------------------------------------------------
        FileName =~ "rundll32.exe" and Cmd has "comsvcs.dll"
            and Cmd has_any ("minidump","#24","#+24","# 24"),           "LSASS:comsvcs",
        FileName has_any ("procdump","procdump64") and Cmd has "lsass", "LSASS:procdump",
        FileName =~ "createdump.exe" and Cmd has_any ("lsass","-f"),    "LSASS:createdump",
        FileName =~ "sqldumper.exe"
            and Cmd has_any ("lsass","0x01100","0x0110","-f"),          "LSASS:sqldumper",
        FileName =~ "rdrleakdiag.exe" and Cmd has "fullmemdmp",         "LSASS:rdrleakdiag",
        FileName =~ "werfault.exe" and Cmd has "lsass",                 "LSASS:werfault",
        FileName has_any ("nanodump","dumpert","mimikatz","lsassy","handlekatz",
                          "forkdump","malseclogon","pypykatz"),         "LSASS:known-tool",
        // Handle duplication - steal an existing lsass handle instead of opening one
        Cmd has_any ("--dup","--handle","--fork","duplicatehandle") and Cmd has "lsass",
                                                                        "LSASS:handle-dup",
        // .NET reflection reaching MiniDumpWriteDump in dbghelp/dbgcore
        FileName in~ (ps_hosts)
            and Cmd has_any ("minidumpwritedump","dbghelp.dll","dbgcore.dll")
            and Cmd has_any ("add-type","dllimport","getdelegateforfunctionpointer",
                             "reflection.emit","[reflection.assembly]","getprocaddress",
                             "system.runtime.interopservices"),         "LSASS:dotnet-reflection",
        FileName in~ (ps_hosts)
            and Cmd has_any ("out-minidump","minidumpwritedump"),       "LSASS:ps-minidump",
        // Inline C#/VB compilation hosted by PowerShell - hunt-grade signal only
        ParentIsPS and FileName in~ ("csc.exe","vbc.exe"),              "LSASS:inline-compile",
        "Other")
    | where DumpMethod != "Other"
    | extend Category = tostring(split(DumpMethod, ":")[0])
    | extend Technique = case(
        Category == "VSS",                                      "T1003.003 / T1006",
        Category == "NTDS",                                     "T1003.003",
        Category == "HIVE" and DumpMethod endswith "SAM",       "T1003.002",
        Category == "HIVE" and DumpMethod endswith "SECURITY",  "T1003.004",
        Category == "HIVE",                                     "T1003.002 (SYSTEM boot key)",
        Category == "LSASS",                                    "T1003.001",
                                                                "T1003")
    | extend Severity = case(
        DumpMethod == "LSASS:inline-compile",                   "Medium",
        Category in ("NTDS","LSASS","HIVE"),                    "High",
        Category == "VSS" and Cmd has "ntds",                   "High",
                                                                "Medium")
    | extend Phase = "CredAccess-AltDump"
    | project Timestamp, DeviceName, AccountName, Category, DumpMethod, Technique, Severity,
              FileName, Evidence = ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, Phase;
// Registry corroboration: the same shadow-copy utilities leave a VSS footprint in the
// registry (mirrors 05e). Fires even when the command line is obfuscated or the
// process event is missed - process and registry layers reinforce each other.
let vss_registry =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has_any (@"\Services\VSS\Diag", @"\Services\VSS\Settings",
                                 @"\Microsoft\Windows NT\CurrentVersion\Diagnostics\VSS")
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wmic.exe",
                                           "ntdsutil.exe","diskshadow.exe","vssadmin.exe",
                                           "esentutl.exe","wbadmin.exe","vshadow.exe")
    | extend Category    = "VSS",
             DumpMethod  = strcat("VSS-registry:", tolower(InitiatingProcessFileName)),
             Technique   = "T1003.003 / T1006",
             Severity    = "Medium",
             Phase       = "CredAccess-AltDump",
             AccountName = InitiatingProcessAccountName,
             FileName    = InitiatingProcessFileName,
             Evidence    = RegistryKey
    | project Timestamp, DeviceName, AccountName, Category, DumpMethod, Technique, Severity,
              FileName, Evidence,
              InitiatingProcessFileName, InitiatingProcessCommandLine, Phase;
union proc_dumps, vss_registry
| order by Timestamp desc
```

## BEH-CA-012 — NTDS Database Path & Diagnostics Registry Tampering

- **Phase:** Credential Access  ·  **Severity:** High — Medium for diagnostics verbosity, Low for default-path pointer writes
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 1 hour  ·  **Lookback:** 24 h detection / 30 d hunt (`let lookback`)
- **MITRE:** T1003.003 (NTDS), T1112 (Modify Registry)
- **Atoms:** `ATOM-CA-NTDS-REGTAMPER`

```kql
// BEH-CA-012 - NTDS Database Path / Diagnostics Registry Tampering
// Platform:  Microsoft Defender XDR Custom Detection
// Frequency: Every 1h | Lookback: 24h detection, 30d hunt
// Tables:    DeviceRegistryEvents
// MITRE:     T1003.003 (NTDS), T1112 (Modify Registry)
// Corroborates the process/file ntdsutil detection (v1 04/05/06) from the registry side.
let lookback = 24h;                                     // hunt mode: 30d
let pointer_values = dynamic(["DSA Database file","Database log files path",
                              "DSA Working Directory","Database backup path",
                              "DSA Database Epoch"]);
let staging_paths  = dynamic([@"\temp\", @"\public\", @"\users\", @"\perflogs\",
                              @"\windows\tasks\", @"\programdata\", @"\$recycle.bin\"]);
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where RegistryKey has_any (@"\Services\NTDS\Parameters", @"\Services\NTDS\Diagnostics")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
// The pointer values that matter, plus any data landing in an operator staging path
| extend IsPathPointer  = RegistryValueName in~ (pointer_values)
| extend SuspiciousData = tolower(RegistryValueData) has_any (staging_paths)
                          or tolower(RegistryValueData) has_any (".dit","ntds.dit")
| extend NonDefaultPath = IsPathPointer
                          and isnotempty(RegistryValueData)
                          and not(tolower(RegistryValueData) startswith @"c:\windows\ntds")
| extend DiagVerbosity  = RegistryKey has @"\Services\NTDS\Diagnostics"
                          and RegistryValueData !in ("0","0x00000000","")
| where IsPathPointer or SuspiciousData or DiagVerbosity
| extend Severity = case(
    NonDefaultPath,  "High",
    SuspiciousData,  "High",
    DiagVerbosity,   "Medium",
                     "Low")
| extend Technique = "T1003.003 / T1112"
| extend Phase     = "CredAccess-NTDS-Registry"
| project Timestamp, DeviceName, Severity, Technique, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData, PreviousRegistryValueData,
          IsPathPointer, SuspiciousData, NonDefaultPath, DiagVerbosity,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, Phase
| order by Timestamp desc
```

## BEH-CA-013 — LSASS Credential Exposure & Protection Downgrade

- **Phase:** Credential Access — with a Defense Evasion component (protection downgrade)  ·  **Severity:** Critical (SSP / password-filter); High (protection downgrade); Medium (weakened auth levels)
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 1 hour  ·  **Lookback:** 24 h detection / 30 d hunt (`let lookback`)
- **MITRE:** T1112, T1003.001, T1547.005, T1556.002, T1562.001
- **Atoms:** `ATOM-DE-WDIGESTUP`, `ATOM-DE-LSAPROTDOWN`, `ATOM-CA-SSP-INJECT`

```kql
// BEH-CA-013 - LSASS Credential Exposure and Protection Downgrade (registry enablers)
// Platform:  Microsoft Defender XDR Custom Detection
// Frequency: Every 1h | Lookback: 24h detection, 30d hunt
// Tables:    DeviceRegistryEvents
// MITRE:     T1112, T1003.001, T1547.005, T1556.002, T1562.001
let lookback = 24h;                                     // hunt mode: 30d
let on  = dynamic(["1","0x00000001"]);
let off = dynamic(["0","0x00000000"]);                  // v2 fix: v1 had "1" in the off set
let weak_lmcompat = dynamic(["0","1","2","0x00000000","0x00000001","0x00000002"]);
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| extend TamperAction = case(
    // (a) Force reversible / plaintext credentials to be cached in LSASS
    RegistryKey has @"\SecurityProviders\WDigest"
        and RegistryValueName =~ "UseLogonCredential"
        and RegistryValueData in (on),                      "WDigest-PlaintextEnabled",
    RegistryKey has @"\Control\Lsa"
        and RegistryValueName =~ "LmCompatibilityLevel"
        and RegistryValueData in (weak_lmcompat),           "LmCompat-Weakened",
    RegistryKey has @"\Control\Lsa"
        and RegistryValueName =~ "NoLmHash"
        and RegistryValueData in (on),                      "NoLmHash-Disabled",
    // (b) Disable the protection that keeps user-mode tools out of LSASS
    RegistryKey has @"\Control\Lsa"
        and RegistryValueName =~ "RunAsPPL"
        and RegistryValueData in (off),                     "LSAProtection-Disabled",
    RegistryKey has @"\Control\Lsa"
        and RegistryValueName =~ "RunAsPPLBoot"
        and RegistryValueData in (off),                     "LSAProtectionBoot-Disabled",
    RegistryKey has_any (@"\Control\Lsa", @"\DeviceGuard")
        and RegistryValueName =~ "LsaCfgFlags"
        and RegistryValueData in (off),                     "CredentialGuard-Disabled",
    RegistryKey has @"\DeviceGuard"
        and RegistryValueName =~ "EnableVirtualizationBasedSecurity"
        and RegistryValueData in (off),                     "VBS-Disabled",
    // (c) Load attacker code into LSASS: SSP / AP injection and password filter DLL
    RegistryKey has_any (@"\Control\Lsa", @"\Control\Lsa\OSConfig")
        and RegistryValueName in~ ("Security Packages","Authentication Packages"),
                                                            "SSP-PackageAdded",
    RegistryKey has @"\Control\Lsa"
        and RegistryValueName =~ "Notification Packages",   "PasswordFilter-Added",
    "Other")
| where TamperAction != "Other"
// For SSP / password-filter packages, surface what was ADDED vs the prior value
| extend PkgNew = split(tolower(replace_string(RegistryValueData, "\r\n", " ")), " ")
| extend PkgOld = split(tolower(replace_string(
                        coalesce(PreviousRegistryValueData, ""), "\r\n", " ")), " ")
| extend AddedPackages = iff(
        TamperAction in ("SSP-PackageAdded","PasswordFilter-Added"),
        set_difference(PkgNew, PkgOld, dynamic([""])),
        dynamic([]))
| where TamperAction !in ("SSP-PackageAdded","PasswordFilter-Added")
     or array_length(AddedPackages) > 0
| extend Severity = case(
    TamperAction in ("SSP-PackageAdded","PasswordFilter-Added"),         "Critical",
    TamperAction in ("WDigest-PlaintextEnabled","LSAProtection-Disabled",
                     "LSAProtectionBoot-Disabled","CredentialGuard-Disabled",
                     "VBS-Disabled"),                                    "High",
                                                                         "Medium")
// GPO / svchost under SYSTEM sets these during policy apply - weight non-SYSTEM higher
| extend AuthoredBySystem = InitiatingProcessAccountName in~ ("system","local system")
                            and InitiatingProcessFileName in~ ("svchost.exe","services.exe",
                                                               "gpscript.exe")
| extend Phase = "CredAccess-LSASS-RegistryEnabler"
| project Timestamp, DeviceName, Severity, TamperAction, RegistryKey, RegistryValueName,
          RegistryValueData, PreviousRegistryValueData, AddedPackages, AuthoredBySystem,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, Phase
| order by Timestamp desc
```

## BEH-LM-003 — Authenticated Boundary Crossing into CIP_Jump

- **Phase:** Lateral Movement  ·  **Severity:** Medium
- **Platform:** Microsoft Defender XDR (DeviceLogonEvents)  ·  **Frequency:** Every 15 min  ·  **Lookback:** 4 h alert · 30 d baseline watchlist *(all lookbacks under eval)*
- **MITRE:** T1021.001 (RDP), T1021.002 (SMB/admin shares), T1078.002, T1563.002 (RDP hijack)
- **Atoms:** `ATOM-LM-BOUNDARY`

```kql
// BEH-LM-003 — Authenticated Boundary Crossing into CIP_Jump
// Platform: Microsoft Defender XDR | Frequency: 15min | Lookback: 4h | Baseline: 30d watchlist
// Functions: Get_CIP_Jump_Hosts(), Get_CIP_Mgmt_Hosts(), Get_CIP_Accounts(), IsInMaintenanceWindow()
// Tables: DeviceLogonEvents, DeviceInfo
let JumpHosts = Get_CIP_Jump_Hosts();
let MgmtHosts = Get_CIP_Mgmt_Hosts();
let CIPAccounts = Get_CIP_Accounts();
let PubFacing =
    DeviceInfo
    | where Timestamp > ago(1d)
    | where DeviceTags has "PublicFacing"
    | summarize arg_max(Timestamp, *) by DeviceName
    | project SourceDevice = DeviceName, SourceIsPublic = true;
let AuthBaseline = externaldata (Account:string, TargetHost:string)
    [@"https://<store>/cip_auth_baseline.csv"] with (format="csv", ignoreFirstRecord=true);
DeviceLogonEvents
| where Timestamp > ago(4h)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| join kind=inner JumpHosts on DeviceId                                        // P1: destination is CIP_Jump
| join kind=leftanti MgmtHosts on $left.RemoteDeviceName == $right.DeviceName  // P2: source NOT CIP_Mgmt
| join kind=leftanti CIPAccounts on $left.AccountName == $right.AccountName    // P3: account NOT in CIP AD group
| join kind=leftanti AuthBaseline
    on $left.AccountName == $right.Account and $left.DeviceName == $right.TargetHost  // P4: no 30d baseline
| where IsInMaintenanceWindow(DeviceName, Timestamp) == false                  // P5: not maintenance
| join kind=leftouter PubFacing on $left.RemoteDeviceName == $right.SourceDevice
| extend SourceTag = iif(SourceIsPublic == true, "PublicFacing", "Untagged_IT"),
         AlertDetail = strcat("Boundary crossing: ", AccountName, " -> CIP_Jump ", DeviceName,
                              " from ", RemoteDeviceName, " (", SourceTag, ") | Logon ", LogonType)
| project Timestamp, AccountName, DeviceName, RemoteDeviceName, RemoteIP, LogonType, SourceTag, AlertDetail
```

## BEH-PE-010 — Local Account / Persistence on CIP-Adjacent Host

- **Phase:** Persistence  ·  **Severity:** Medium
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 15 min  ·  **Lookback:** 2 h rolling
- **MITRE:** T1136.001, T1053.005, T1543.003, T1547.001, T1505.003
- **Atoms:** `ATOM-PE-LOCALACCT`, `ATOM-PE-SCHTASK`, `ATOM-PE-SERVICE`, `ATOM-PE-RUNKEY`, `ATOM-PE-WEBSHELL`

```kql
// BEH-PE-010 — Local Account / Persistence on CIP-Adjacent Host
// Platform: Microsoft Defender XDR | Frequency: 15min | Lookback: 2h
// Functions: Get_CIP_Jump_Hosts(), Get_CIP_Mgmt_Hosts(), IsInMaintenanceWindow()
// Tables: DeviceEvents, DeviceProcessEvents, DeviceRegistryEvents
let CIP_Hosts =
    union (Get_CIP_Jump_Hosts()), (Get_CIP_Mgmt_Hosts())
    | project DeviceId, DeviceName, AssetClass, SafetyCritical = DeviceTags has "SafetyCritical";
let LocalAcct =
    DeviceEvents
    | where Timestamp > ago(2h)
    | where ActionType == "UserAccountCreated"
    | join kind=inner CIP_Hosts on DeviceId
    | extend Technique = "T1136.001-LocalAccount", Artifact = tostring(parse_json(AdditionalFields).TargetUser);
let SchedTask =
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has_any ("/create","-create")
    | join kind=inner CIP_Hosts on DeviceId
    | extend Technique = "T1053.005-ScheduledTask", Artifact = ProcessCommandLine;
let ServiceCreate =
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | where FileName =~ "sc.exe"
    | where ProcessCommandLine has "create"
    | join kind=inner CIP_Hosts on DeviceId
    | extend Technique = "T1543.003-Service", Artifact = ProcessCommandLine;
let AutoRun =
    DeviceRegistryEvents
    | where Timestamp > ago(2h)
    | where ActionType in~ ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
    | join kind=inner CIP_Hosts on DeviceId
    | extend Technique = "T1547.001-RunKey", Artifact = strcat(RegistryKey, "\\", RegistryValueName);
union LocalAcct, SchedTask, ServiceCreate, AutoRun
| where IsInMaintenanceWindow(DeviceName, Timestamp) == false
| extend AlertDetail = strcat(Technique, " on CIP-adjacent ", DeviceName, " (", AssetClass, ")",
                              " | Account ", coalesce(AccountName, InitiatingProcessAccountName),
                              " | Artifact: ", substring(tostring(Artifact), 0, 200))
| project Timestamp, DeviceName, AssetClass, SafetyCritical, AccountName, Technique, Artifact, AlertDetail
```

## BEH-C2-014 — netsh PortProxy Relay (process + registry)

- **Phase:** Command & Control — with a Lateral Movement enabler component  ·  **Severity:** High on create/modify — P1 when `ConnectAddress` in CIP/OT space; Medium on enumerate/delete
- **Platform:** Microsoft Defender XDR (Custom Detection)  ·  **Frequency:** Every 15 minutes  ·  **Lookback:** 24 h detection / 30 d hunt (`let lookback`)
- **MITRE:** T1090.001 (Internal Proxy), T1112 (Modify Registry — relay persistence)
- **Atoms:** `ATOM-C2-PORTPROXY-NETSH`, `ATOM-C2-PORTPROXY-REG`

```kql
// BEH-C2-014 - netsh PortProxy Relay (process + registry)
// Platform:  Microsoft Defender XDR Custom Detection
// Frequency: Every 15m | Lookback: 24h detection, 30d hunt
// Tables:    DeviceProcessEvents, DeviceRegistryEvents
// MITRE:     T1090.001 (Internal Proxy), T1112 (Modify Registry)
// Promote to P1 when ConnectAddress lands in CIP / OT address space.
let lookback = 24h;                                     // hunt mode: 30d
// netsh resolves any unique prefix: "netsh i p a v4tov4 ..." == the full command
let netsh_pp = @"\bnetsh(\.exe)?\s+i\w*\s+p\w*\s+(a|add|s|set|d|del|sh|show|res)";
let portproxy_proc =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "netsh.exe"
    | extend Cmd = tolower(ProcessCommandLine)
    | where Cmd has "portproxy"
         or Cmd has_any ("v4tov4","v4tov6","v6tov4","v6tov6")
         or Cmd matches regex netsh_pp
    | extend SubCommand = case(
        Cmd has_any (" add "," a "),                            "ProxyCreated",
        Cmd has_any (" set "," s "),                            "ProxyModified",
        Cmd has_any (" delete "," del "," d "),                 "ProxyDeleted",
        Cmd has_any (" show "," sh "),                          "ProxyEnumerated",
        Cmd has "reset",                                        "ProxyReset",
                                                                "Other")
    | extend MapType     = extract(@"(v[46]tov[46])", 1, Cmd),
             ListenAddr  = extract(@"listenaddress\s*=\s*([^\s]+)", 1, Cmd),
             ListenPort  = extract(@"listenport\s*=\s*(\d+)", 1, Cmd),
             ConnectAddr = extract(@"connectaddress\s*=\s*([^\s]+)", 1, Cmd),
             ConnectPort = extract(@"connectport\s*=\s*(\d+)", 1, Cmd)
    | extend Source    = "Process",
             Technique = "T1090.001",
             Severity  = iff(SubCommand in ("ProxyCreated","ProxyModified"), "High", "Medium"),
             Phase     = "C2-PortProxy"
    | project Timestamp, DeviceName, AccountName, Source, SubCommand, Severity, Technique,
              MapType, ListenAddr, ListenPort, ConnectAddr, ConnectPort,
              Evidence = ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, Phase;
// Registry persistence. Value name is <listenaddress>/<listenport>, value data is
// <connectaddress>/<connectport>. Covers all four address-family maps, not just v4tov4.
let portproxy_reg =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has @"\Services\PortProxy"
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | extend MapType     = extract(@"PortProxy\\(v[46]tov[46])", 1, RegistryKey),
             ListenAddr  = tostring(split(RegistryValueName, "/")[0]),
             ListenPort  = extract(@"/(\d+)\s*$", 1, RegistryValueName),
             ConnectAddr = tostring(split(RegistryValueData, "/")[0]),
             ConnectPort = extract(@"/(\d+)\s*$", 1, RegistryValueData)
    | extend Source      = "Registry",
             SubCommand  = "ProxyPersisted",
             Severity    = "High",
             Technique   = "T1090.001 / T1112",
             Phase       = "C2-PortProxy-Registry",
             AccountName = InitiatingProcessAccountName
    | project Timestamp, DeviceName, AccountName, Source, SubCommand, Severity, Technique,
              MapType, ListenAddr, ListenPort, ConnectAddr, ConnectPort,
              Evidence = RegistryKey,
              InitiatingProcessFileName, InitiatingProcessCommandLine, Phase;
union portproxy_proc, portproxy_reg
| order by Timestamp desc
```

---

# Proposed semantic functions


## Get_LOLBins

_Get_LOLBins() — canonical living-off-the-land binary inventory_

```kql
// Get_LOLBins() — canonical living-off-the-land binary inventory
// Class: SEMANTIC (technique-bearing) | Back with a Watchlist for updates
// Columns: FileName, Category, Technique, DefaultSeverity, Notes
let Get_LOLBins = () {
    datatable(FileName:string, Category:string, Technique:string, DefaultSeverity:string, Notes:string)
    [
      "net.exe",      "Discovery",       "T1087",     "Low",    "account/group enum",
      "net1.exe",     "Discovery",       "T1087",     "Low",    "net.exe alias",
      "nltest.exe",   "Discovery",       "T1482",     "Low",    "domain trust discovery",
      "netstat.exe",  "Discovery",       "T1049",     "Low",    "network connections",
      "ipconfig.exe", "Discovery",       "T1016",     "Low",    "network config",
      "arp.exe",      "Discovery",       "T1018",     "Low",    "remote system discovery",
      "whoami.exe",   "Discovery",       "T1033",     "Low",    "owner/user discovery",
      "quser.exe",    "Discovery",       "T1033",     "Low",    "logged-on users",
      "systeminfo.exe","Discovery",      "T1082",     "Low",    "system info",
      "tasklist.exe", "Discovery",       "T1057",     "Low",    "process discovery",
      "wmic.exe",     "Execution",       "T1047",     "Medium", "WMI exec/recon/shadow",
      "rundll32.exe", "DefenseEvasion",  "T1218.011", "Medium", "proxy exec (comsvcs dump)",
      "regsvr32.exe", "DefenseEvasion",  "T1218.010", "Medium", "proxy exec / squiblydoo",
      "certutil.exe", "CommandAndControl","T1105",    "Medium", "download / encode",
      "bitsadmin.exe","CommandAndControl","T1105",    "Medium", "download",
      "netsh.exe",    "CommandAndControl","T1090.001","High",   "portproxy relay (VT signature)",
      "mshta.exe",    "Execution",       "T1218.005", "Medium", "HTA exec",
      "schtasks.exe", "Persistence",     "T1053.005", "Medium", "scheduled task",
      "sc.exe",       "Persistence",     "T1543.003", "Medium", "service create",
      "reg.exe",      "CredentialAccess","T1003.002", "High",   "hive save",
      "esentutl.exe", "CredentialAccess","T1003.003", "High",   "ntds copy",
      "ntdsutil.exe", "CredentialAccess","T1003.003", "High",   "ntds ifm/snapshot",
      "vssadmin.exe", "CredentialAccess","T1003.003", "Medium", "shadow copy"
    ]
};
// usage in BEH-DE-002:  | where FileName in~ (toscalar( ... )) — or join Get_LOLBins() on FileName
```

## Get_ActionTypeMap

_Get_ActionTypeMap() — atom vocabulary from atoms/atom_catalog.json, for KQL_

```kql
// Get_ActionTypeMap() — atom vocabulary from atoms/atom_catalog.json, for KQL
// Class: SEMANTIC | one row per (atom, match rule). Back with a Watchlist synced
// from atom_catalog.json so JSON stays the single source of truth.
let Get_ActionTypeMap = () {
    datatable(AtomId:string, Phase:string, Technique:string, Source:string,
              MatchTable:string, MatchField:string, MatchOp:string, MatchValue:string)
    [
      "ATOM-C2-PORTPROXY-NETSH","CommandAndControl","T1090.001","custom",
          "DeviceProcessEvents","ProcessCommandLine","has_all","interface;portproxy;add",
      "ATOM-CA-LSASS-COMSVCS","CredentialAccess","T1003.001","custom",
          "DeviceProcessEvents","ProcessCommandLine","has_all","comsvcs.dll;minidump",
      "ATOM-DISC-LOLBIN-CLUSTER","Discovery","T1059","custom",
          "DeviceProcessEvents","FileName","in_lolbins","",       // resolved via Get_LOLBins()
      "ATOM-CA-DCSYNC","CredentialAccess","T1003.006","native-mdi",
          "AlertInfo","Title","has","Suspected DCSync"
      // … full catalog synced from atom_catalog.json
    ]
};
```

## Classify_Atoms

_Classify_Atoms() — emit a normalized atom-event stream from raw telemetry._

```kql
// Classify_Atoms() — emit a normalized atom-event stream from raw telemetry.
// Class: SEMANTIC | PILOT: DeviceProcessEvents only. Pre-filter BEFORE calling in prod.
let Classify_Atoms = (lookback:timespan = 24h) {
    let lol = Get_LOLBins();
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | extend Cmd = tolower(ProcessCommandLine)
    | extend AtomId = case(
        FileName =~ "netsh.exe"   and Cmd has_all ("portproxy","add"),         "ATOM-C2-PORTPROXY-NETSH",
        FileName =~ "rundll32.exe" and Cmd has "comsvcs.dll" and Cmd has "minidump","ATOM-CA-LSASS-COMSVCS",
        FileName in~ (dynamic(["vssadmin.exe","diskshadow.exe","wbadmin.exe","vshadow.exe"])), "ATOM-CA-NTDS-VSS",
        FileName in~ (toscalar(lol | summarize make_set(FileName))),          "ATOM-DISC-LOLBIN-CLUSTER",
        "")
    | where AtomId != ""
    | project Timestamp, DeviceId, DeviceName, Account = AccountName, AtomId,
              Source = "custom", Evidence = ProcessCommandLine
};
// then: Classify_Atoms() | (chain via matrix)  — one function feeds every hunt
```
