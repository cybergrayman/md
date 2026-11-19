# Security Operations Center (SOC) Guideline

**Operational reference for alert triage, threat investigation, endpoint forensics and incident response**


---

## Contents

1. [Purpose and scope](#1-purpose-and-scope)
2. [Analyst operating rules](#2-analyst-operating-rules)
3. [Situation quick index](#3-situation-quick-index)
4. [Detection playbooks by attack stage](#4-detection-playbooks-by-attack-stage)
5. [Windows event reference](#5-windows-event-reference)
6. [Living-off-the-land binaries (LOLBins)](#6-living-off-the-land-binaries-lolbins)
7. [Endpoint forensics with Velociraptor](#7-endpoint-forensics-with-velociraptor)
8. [File and binary analysis](#8-file-and-binary-analysis)
9. [Command reference](#9-command-reference)
10. [Incident response workflow](#10-incident-response-workflow)
11. [Documentation and reporting](#11-documentation-and-reporting)

---

## 1. Purpose and scope

### 1.1 Objectives

This guideline is the operational reference for the Security Operations Center (SOC) and security analysis team. It helps analysts determine, for a given situation, where to look, what evidence to collect, which tool to use, why it is relevant and what to do next.

- Standardize alert triage, investigation, escalation and documentation.
- Provide quick access to relevant event IDs, query patterns, commands and tools.
- Define safe and repeatable use of analysis tools, including handling of malicious files.
- Consolidate operational checklists and investigation references into one guide.

### 1.2 Applicability

For SOC analysts (L1–L3), threat hunters, incident responders and security engineers investigating Windows, Linux, email and web-facing systems. The source guideline covers Sysmon and native Windows/Linux logging, Velociraptor endpoint forensics, PowerShell, and static-analysis tools including PEStudio, PE-bear, CFF Explorer, CyberChef, UPX, `strings`, `oletools` and `pffexport`.

### 1.3 How to use this guideline

1. Find the observed condition in the [Situation Quick Index](#3-situation-quick-index).
2. Follow the relevant [detection playbook](#4-detection-playbooks-by-attack-stage).
3. Use the [event reference](#5-windows-event-reference) and [command reference](#9-command-reference) to validate findings.
4. Use [Velociraptor](#7-endpoint-forensics-with-velociraptor) to collect endpoint evidence.
5. Follow [File and Binary Analysis](#8-file-and-binary-analysis) for suspicious files.
6. Preserve evidence, contain only with the required approval, and document the investigation.

### 1.4 Notation

| Notation | Meaning |
|---|---|
| `Sysmon N` | Event ID **N** in `Microsoft-Windows-Sysmon/Operational`. |
| `Security N` / `System N` | Event ID **N** in the Windows Security or System log. |
| `monospaced text` | A command, query, field, file name or path to enter as shown. |
| `<value>` | A placeholder to replace with a case-specific host, PID, file, IP address or account. |
| Field names | Typical parsed names. Splunk, Elastic and their add-ons may use different names; verify the fields in your SIEM. |

---

## 2. Analyst operating rules

### 2.1 Golden rules

1. **Set the time range first.** Scope the SIEM search to the incident window; widen it only when necessary.
2. **Work backwards and forwards.** Trace from the alert to the root cause, then establish the full scope across affected hosts, accounts and files.
3. **Make every finding reproducible.** Record the host, UTC timestamp, log source, event ID and exact field values.
4. **Do not execute suspicious files on production systems.** Analyse them only on an approved, isolated analyst workstation.
5. **Hash before reputation checks.** Use file hashes for threat-intelligence lookups. Do not upload internal files to public services without approval.
6. **Preserve before changing.** Where safe, collect volatile evidence—processes, connections, files and memory if required—before containment.
7. **Avoid alerting the attacker.** Do not take visible action on a compromised host or account until containment is coordinated.
8. **Do not interpret missing logs as proof of no activity.** Sysmon filters, DCOM-launched processes, SMB file writes and evasive file operations can create telemetry gaps. Validate on the endpoint with Velociraptor.
9. **Pivot every new indicator.** Search each hash, file name, IP, domain, account, service and scheduled-task name across relevant hosts.
10. **Defang indicators in tickets and reports.** Use forms such as `hxxp` and `[.]`; use the real value when searching in security tools.
11. **Escalate early.** Do not wait for complete certainty when escalation criteria are met.

### 2.2 Severity and escalation

| Severity | Typical situations | Required action |
|---|---|---|
| **Critical** | Ransomware or mass file encryption; domain controller or domain administrator compromise; LSASS, SAM or `NTDS.dit` credential theft; confirmed active data exfiltration. | Escalate immediately to the L3/IR lead and SOC manager. Start incident response and contain with approval. |
| **High** | Confirmed malware execution or C2 beaconing; webshell on a server; lateral movement; new privileged account or unauthorized group change; security tool disabled or tampered with. | Escalate to L2/L3 within the applicable SLA. Request host isolation and account action with approval. |
| **Medium** | Encoded or obfuscated PowerShell or LOLBin abuse not yet confirmed malicious; phishing link clicked without confirmed execution; brute force without a successful logon. | L1/L2 investigates. Escalate when malicious activity is confirmed. |
| **Low** | Blocked attempts; isolated failed logons; policy violations; antivirus detection automatically remediated. | Document, verify remediation, then close or tune the detection. |

---

## 3. Situation quick index

Use the first evidence source as the starting point, then follow the referenced playbook.

| Situation                                                | Check first                                                                         | Playbook / section                                                                            |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Suspected phishing or user clicked a link/attachment     | Mail gateway; mailbox export (PST); Sysmon 1, 11 and 3 on the user's host           | [4.1 Initial access](#41-initial-access), [8.5 File-type analysis](#85-analysis-by-file-type) |
| ClickFix / fake CAPTCHA or user pasted and ran a command | PowerShell 4104; Sysmon 1 with `explorer.exe` parent; `RunMRU` registry key         | [4.1](#41-initial-access)                                                                     |
| Web server compromise or webshell                        | New `.aspx`, `.php` or `.jsp` files; web process spawning a shell; web access logs  | [4.1](#41-initial-access)                                                                     |
| Suspicious process or command line                       | Sysmon 1 / Security 4688; parent, path, command line, user and `OriginalFileName`   | [4.2 Execution](#42-execution)                                                                |
| Encoded or obfuscated PowerShell                         | PowerShell 4104 `ScriptBlockText`; decode with CyberChef                            | [4.2](#42-execution), [8.3 Tool selection](#83-tool-selection)                                |
| New service, scheduled task or autorun                   | 4697/7045, 4698, Sysmon 12–14 and Sysmon 19–21                                      | [4.3 Persistence](#43-persistence)                                                            |
| Suspicious DLL load or DLL sideloading                   | Sysmon 7 and 29; compare DLL location with the EXE folder                           | [4.3](#43-persistence), [8.4 Indicator interpretation](#84-reading-the-indicators)            |
| Security tool disabled, tampered with or crashed         | Defender 5001/5007/5013; Sysmon 6, 4 and 16                                         | [4.4 Defence evasion](#44-defence-evasion-and-privilege-escalation)                           |
| LSASS access or credential dumping                       | Sysmon 10 targeting `lsass.exe`; `.dmp` files; SilentProcessExit registry keys      | [4.5 Credential access](#45-credential-access)                                                |
| Kerberoasting or unusual Kerberos activity               | Security 4769 (encryption type `0x17`), 4768 and 4771                               | [4.5](#45-credential-access)                                                                  |
| Brute force or password spraying                         | 4625 status/substatus, 4771 and 4740                                                | [4.5](#45-credential-access)                                                                  |
| Lateral movement (SMB, PsExec, WMI, WinRM, RDP or DCOM)  | 4624 types 3/10; 5140/5145; 7045/4697; Sysmon 17/18 and 3                           | [4.6 Discovery and lateral movement](#46-discovery-and-lateral-movement)                      |
| Process creation event is missing                        | Events carrying the PID (Sysmon 22/3/7/10); Security 4688 hexadecimal PID           | [4.6](#46-discovery-and-lateral-movement)                                                     |
| C2, beaconing or suspicious DNS                          | Sysmon 3; Sysmon 22 `QueryName`/`QueryResults`; proxy logs                          | [4.7 Command and control](#47-command-and-control)                                            |
| Data staging or exfiltration                             | Sysmon 11 archive/script creation; PowerShell 4104; Sysmon 3 volume; BITS activity  | [4.8 Collection and exfiltration](#48-collection-and-exfiltration)                            |
| Ransomware or mass encryption                            | Sysmon 11 ransom-note creation; `sc.exe`/7045 deployment; shadow-copy deletion      | [4.9 Impact](#49-impact-ransomware)                                                           |
| Need endpoint files or evidence                          | Velociraptor VFS collection or hunt                                                 | [7. Endpoint forensics](#7-endpoint-forensics-with-velociraptor)                              |
| File activity suspected but no log exists                | Velociraptor file search using the incident time window                             | [7](#7-endpoint-forensics-with-velociraptor)                                                  |
| Suspicious EXE, DLL, driver, script, document or email   | Static-analysis workflow                                                            | [8. File and binary analysis](#8-file-and-binary-analysis)                                    |
| Linux host compromise                                    | Authentication logs, web access logs, processes, cron/systemd, SSH keys and keytabs | [9.2 Linux](#92-linux)                                                                        |

---

## 4. Detection playbooks by attack stage

Each playbook identifies the behaviour, useful telemetry and confirmation or follow-up steps. Investigations do not always begin at initial access; follow the evidence wherever it leads.

### 4.1 Initial access

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Phishing email or user-executed content | Mail gateway; Exchange/Microsoft 365 audit; mailbox export (PST) analysed with `pffexport` | Review sender, Return-Path, Received chain, SPF/DKIM/DMARC results, URLs and attachments. Search for the same indicators across mailboxes and endpoints. |
| User-run command or ClickFix-style instruction | PowerShell 4104; Sysmon 1; RunMRU | Reconstruct the command and its parent process. Identify downloaded content, URLs and subsequent process execution. |
| Suspicious attachment or downloaded file | Sysmon 11/1/3; browser and proxy logs; mailbox evidence | Correlate the email or download time with file creation and execution. Hash the file and follow Section 8. |
| Webshell or compromised web application | Web access logs; new `.aspx`, `.php` or `.jsp` files; web-server process activity | Look for a web process spawning `cmd.exe`, PowerShell or another shell. Collect the webshell and preserve the relevant access logs. |
| Unusual authentication preceding execution | Security 4624/4625; VPN and identity-provider logs | Correlate source address, account and logon time with endpoint activity. Review failed logons followed by successful logons. |

### 4.2 Execution

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Suspicious process or command line | Sysmon 1; Security 4688 | Review image path, command line, parent process, user, hashes and `OriginalFileName`. Trace the process tree. |
| Encoded PowerShell | PowerShell 4104 `ScriptBlockText`; Sysmon 1 | Decode the content (for `-EncodedCommand`, decode as UTF-16LE). Identify URLs, commands, payloads and follow-on processes. |
| Uncommon or random-named executable on a server or domain controller | Sysmon 1; file metadata and signature | Check path, signer, hash, creation time and parent process. Correlate with service creation and network activity. |
| Script execution (`.ps1`, `.bat`, `.vbs`, `.js`, `.hta`) | Sysmon 1/11; PowerShell 4104 | Read the script or collect it with Velociraptor. Identify downloaded tools, destinations and persistence actions. |
| LOLBin used for download, decode or proxy execution | Sysmon 1 / Security 4688 | Inspect the full argument list and parent process. See [Section 6](#6-living-off-the-land-binaries-lolbins). |

### 4.3 Persistence

| Persistence method | Evidence sources | Confirmation and next step |
|---|---|---|
| New or modified service | Security 4697; System 7045; Sysmon 12–14 | Review service name, image path, account and creator process. Hash and analyse the binary. |
| Scheduled task | Security 4698/4702/4699; Task Scheduler operational log | Inspect task XML, author, triggers, actions and executable path. Identify the creating account and process. |
| Registry autorun | Sysmon 12–14; registry hives | Review Run/RunOnce and other autorun locations. Validate the target path and binary. |
| WMI event subscription | Sysmon 19–21; WMI repository/artifacts | Correlate event filter, consumer and binding. Identify the command or script executed. |
| DLL sideloading or search-order hijack | Sysmon 7 and 29; file metadata | Compare the DLL path, hash, signer and size with the legitimate system copy. Identify the signed EXE that loaded it. |

### 4.4 Defence evasion and privilege escalation

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Security product disabled or configuration changed | Defender 5001/5007/5013; Sysmon 4/6/16 | Identify the account and process responsible. Review policy and service changes. |
| Driver load or security tool crash | Sysmon 6; System and application logs | Check driver signature and hash; correlate with service installation and endpoint protection failures. |
| Timestamp manipulation | File timestamps; NTFS metadata | Compare creation, modification and access times with surrounding events. Do not rely on PE compile time alone. |
| Payload hidden in Alternate Data Streams | NTFS ADS; Sysmon 15 | Enumerate streams, extract safely and analyse the content as a separate file. |
| Unexpected privileged logon or privilege change | Security 4672, 4728/4732/4756 and 4624 | Identify the account, source host and change initiator. Validate whether the action was authorized. |

### 4.5 Credential access

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| LSASS access or dumping | Sysmon 10 targeting `lsass.exe`; dump files; process command lines | Review `GrantedAccess` values (examples in the source include `0x1010`, `0x1410`, `0x1438`, `0x143a` and `0x1fffff`). Look for tools or commands such as `procdump -ma lsass` and `rundll32`. |
| SilentProcessExit technique | Registry keys; process and file activity | Inspect relevant SilentProcessExit registry configuration and correlate it with dump-file creation. |
| Registry hive or `NTDS.dit` theft | Process command lines; file access and creation; Sysmon 9 | Look for `reg save`, hive copies and access to domain database files. Treat confirmed credential material exposure as Critical. |
| Kerberoasting | Security 4769; Kerberos telemetry | Look for unusual volumes of service-ticket requests and weak encryption types such as `0x17`; identify the requesting account and targeted service accounts. |
| Brute force or password spraying | Security 4625; Kerberos 4771; account lockout 4740 | Brute force: many failures against one account. Password spraying: fewer attempts distributed across many accounts. Correlate source IPs and any subsequent successful logon. |
| DPAPI or browser credential theft | Process execution, file access and endpoint artifacts | Identify credential-access utilities, including renamed tools, and determine which users and browsers were affected. |

### 4.6 Discovery and lateral movement

| Technique / behaviour | Evidence sources | Confirmation and next step |
|---|---|---|
| Account and host discovery | Security and endpoint process telemetry | Identify the account and host; discovery commonly precedes lateral movement. Pivot on commands and destination systems. |
| SMB / administrative shares | Sysmon 3 to TCP 445; Security 4624 type 3; 5140/5145 | Review source host, account, share name and relative target path. Look for `ADMIN$`, `C$` and `IPC$`. |
| PsExec or remote service execution | Service creation 7045/4697; Sysmon 1/3 | Correlate the remote logon with service installation and the executable path, often in a system or temporary directory. |
| WMI / DCOM | Sysmon 3 to TCP 135 and high ports; process telemetry | Identify the source process, remote host and account. Review WMI provider activity and spawned processes. |
| WinRM / PowerShell remoting | Sysmon 3 to TCP 5985/5986; Security 4624 type 3; `wsmprovhost.exe`; PowerShell 4104 | Reconstruct the remote command and identify the initiating account and source endpoint. |
| RDP | Sysmon 3 to TCP 3389; `mstsc.exe`; Security 4624 type 10 (type 7 may appear on reconnect); Terminal Services logs | Correlate source IP, account and session with subsequent activity. |
| Pass-the-hash or explicit credential use | Security 4624/4648; authentication package and logon details | Correlate the source host, account and authentication type with remote access and process execution. |
| Missing process-creation event | Sysmon 3/7/10/22; Security 4688 | Pivot using PID, process GUID, network connection or image-load events. Account for hexadecimal PID representation in Security 4688. |

### 4.7 Command and control

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Suspicious outbound connection or beaconing | Sysmon 3; proxy and firewall logs | Map the connection to the process, user and host. Look for periodic connections, unusual destinations and unexpected ports. |
| Suspicious DNS | Sysmon 22 (`QueryName`, `QueryResults`); DNS resolver logs | Review domain age/reputation, query frequency and resolved addresses. Pivot the domain and IP across endpoints. |
| PowerShell or script-based C2 | PowerShell 4104; Sysmon 1/3 | Decode scripts and identify callback URLs, intervals, user agents and downloaded payloads. |
| Named-pipe communication | Sysmon 17/18 | Record pipe names as indicators and correlate client/server processes and hosts. |
| Unusual service or protocol traffic | Firewall, proxy and endpoint network events | Validate against the asset baseline and expected application behaviour. |

### 4.8 Collection and exfiltration

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Archive creation or downloaded archiver | Sysmon 1/11; PowerShell 4104 | Identify archive utility, command line, source files, output path and user. Inspect archive contents only in an isolated lab. |
| Staging in temporary or shared folders | Sysmon 11; file-system artifacts; Velociraptor | Establish which files were staged, when, by which process and whether they were compressed or renamed. |
| Large or unusual outbound transfer | Sysmon 3; proxy, firewall and network-flow telemetry | Correlate destination, process, bytes transferred and timing with staging activity. |
| BITS-based transfer | BITS client operational logs; process and network telemetry | Identify job owner, remote URL, local destination and completion state. |

### 4.9 Impact (ransomware)

| Behaviour / clue | Evidence sources | Confirmation and next step |
|---|---|---|
| Mass file modification or encryption | Sysmon 11; file-system telemetry; endpoint response data | Identify the process, affected paths, start time and number of files. Preserve representative encrypted files. |
| Ransom note creation | Sysmon 11; file-system artifacts | Collect the note and identify the process that created it. Search for the same note name/content across hosts. |
| Service deployment or remote execution | System 7045; Security 4697; Sysmon 1 | Determine how the encryptor was deployed and which account/host initiated it. |
| Shadow-copy deletion or recovery inhibition | Process command lines; System events; VSS artifacts | Look for `vssadmin`, `wmic` or related commands and identify the initiating process. |
| Encryption library or scheme identified | Static analysis of the ransomware binary | Record relevant library names and indicators. Decryption/recovery decisions belong to the IR lead and should use approved keys/tools in a lab. |

---

## 5. Windows event reference

> Event availability depends on audit policy, Sysmon configuration, Windows version and log retention. Event IDs are investigative pivots, not standalone proof of malicious activity.

### 5.1 Sysmon events

| Event ID | Event / data | Investigative use | MITRE ATT&CK reference in source |
|---:|---|---|---|
| 1 | Process creation | Image, command line, parent process, user, hashes and process GUIDs. | T1059 / execution-related |
| 3 | Network connection | Process-associated network connections; correlate image, destination and port. | T1071 (context-dependent) |
| 6 | Driver loaded | Identify loaded drivers, signature and suspicious/vulnerable drivers. | T1014 (context-dependent) |
| 7 | Image loaded | DLL loads; useful for sideloading and unexpected module paths. | T1129 |
| 8 | CreateRemoteThread | Remote thread creation; investigate injection behaviour. | T1055 |
| 9 | RawAccessRead | Direct volume reads such as `\\.\C:`; possible access to locked files. | T1006 |
| 10 | Process access | Access to sensitive processes such as LSASS. | T1003.001 |
| 11 | File created | Dropped payloads, scripts, archives and ransom notes. | T1105 / T1486 (context-dependent) |
| 12–14 | Registry create/set/rename | Run keys, services, IFEO/SilentProcessExit and Defender policy changes. | T1547.001, T1112 |
| 15 | File stream created | Alternate Data Streams; `Zone.Identifier` may contain download origin data. | T1564.004 |
| 17–18 | Named pipe created/connected | Named-pipe-based inter-process communication and lateral movement clues. | T1559 (context-dependent) |
| 19–21 | WMI event filter/consumer/binding | WMI event subscription persistence. | T1546.003 |
| 22 | DNS query | Query name and results; suspicious DNS and C2 pivots. | T1071.004 |
| 25 | Process tampering | Process hollowing or image replacement. | T1055.012 |
| 29 | File executable detected (configuration-dependent) | May assist in identifying executable files and suspicious drops. | Validate against deployed Sysmon schema |

### 5.2 Windows Security log

| Event ID | Event | Investigative use | MITRE ATT&CK reference in source |
|---:|---|---|---|
| 4624 | Successful logon | Review logon type, source IP, workstation and authentication package. Types 3 and 10 are useful for remote access and RDP. | T1078, T1021 |
| 4625 | Failed logon | Review status/substatus, source IP, target account and authentication package. | T1110 |
| 4634 / 4647 | Logoff | Pair with 4624 using Logon ID to estimate session duration. | — |
| 4648 | Logon using explicit credentials | Identify the account whose credentials were supplied and the process/source host. | T1550 (context-dependent) |
| 4672 | Special privileges assigned | Identify privileged logons and correlate with account and source host. | — |
| 4688 | Process creation | Review new process, command line, parent process and creator PID. | T1059 (context-dependent) |
| 4697 | Service installed | Identify service creation, service account and binary path. | T1543.003 |
| 4698 / 4702 / 4699 | Scheduled task created / updated / deleted | Inspect task XML, command, author and triggers. | T1053.005 |
| 4720 | User account created | Identify creator and newly created account. | T1136 |
| 4728 / 4732 / 4756 | Member added to security-enabled group | Detect unexpected group membership changes, including privileged groups. | T1098 (context-dependent) |
| 4740 | Account locked out | Identify target account and caller/source context. | T1110 (context-dependent) |
| 4768 | Kerberos TGT requested | Review account, client address and pre-authentication details. | T1558 (context-dependent) |
| 4769 | Kerberos service ticket requested | Review service account, ticket encryption type and request volume; `0x17` may indicate RC4 use. | T1558.003 |
| 4771 | Kerberos pre-authentication failed | Identify failed Kerberos authentication and source. | T1110 |
| 5140 | Network share accessed | Identify access to shares such as `ADMIN$`, `C$` and `IPC$`. | T1021.002 |
| 5145 | Detailed file share access | Review share name, relative target name and access requested. | T1021.002, T1570 |

### 5.3 Other Windows logs

| Log / provider | Event ID or artifact | Investigative use |
|---|---|---|
| System / Service Control Manager | 7045 | Service installation; correlate with 4697 and process creation. |
| PowerShell Operational | 4103 / 4104 | Module logging and script-block content. Long script blocks may be split across multiple events. |
| Microsoft Defender | 5001 / 5007 / 5013 | Protection disabled, configuration changed or tamper-protection activity. Confirm event meaning for the installed Defender version. |
| Sysmon service | 4 / 16 | Service state changes and Sysmon configuration changes. |
| Task Scheduler Operational | Task registration and execution records | Correlate task name, action, trigger and execution account. |
| TerminalServices logs | RDP session events | Correlate remote logon and session lifecycle with Security 4624. |
| BITS Client Operational | BITS job records | Investigate background downloads and transfers. |

### 5.4 Logon types (4624 / 4625)

| Type | Name | Typical meaning |
|---:|---|---|
| 2 | Interactive | Console logon at the keyboard. |
| 3 | Network | SMB/share access, WMI and other network logons. |
| 4 | Batch | Scheduled task or batch job. |
| 5 | Service | Service account logon. |
| 7 | Unlock | Workstation unlock; may appear on RDP reconnect. |
| 8 | NetworkCleartext | Credentials sent in clear text (for example, IIS Basic authentication). |
| 9 | NewCredentials | `runas /netonly`; supplied credentials used for outbound connections. |
| 10 | RemoteInteractive | Remote Desktop / Terminal Services logon. |
| 11 | CachedInteractive | Cached domain credentials used when a domain controller is unavailable. |

### 5.5 Key fields to read

| Event / source | Important fields | Notes |
|---|---|---|
| Sysmon 1 | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `ProcessGuid`, `ParentProcessGuid`, `Hashes` | Use process GUIDs where possible; PIDs can be reused. |
| Security 4688 | `NewProcessName`, `CommandLine`, `ParentProcessName`, `NewProcessId`, `ProcessId` | Creator PID may be represented in hexadecimal. |
| PowerShell 4104 | `ScriptBlockText`, `Path`, `ScriptBlockId` | Long scripts may be split over several events; reconstruct the full script block. |
| Sysmon 3 | `Image`, `ProcessId`, `DestinationIp`, `DestinationPort`, `Protocol` | Field names vary by parser and SIEM. |
| Sysmon 22 | `QueryName`, `QueryResults`, `Image`, `ProcessId` | Correlate DNS queries to the originating process. |
| Security 4624 | `TargetUserName`, `LogonType`, `IpAddress`, `WorkstationName`, `LogonId` | Pair with 4634/4647 and related events using Logon ID. |
| Security 4769 | `TargetUserName`, `ServiceName`, `TicketEncryptionType`, `IpAddress` | Review unusual service-ticket volume and encryption type. |

---

## 6. Living-off-the-land binaries (LOLBins)

Legitimate Windows utilities can be abused to download, decode, execute or proxy malicious content. Review the full command line, parent process, user, file paths and resulting network activity.

| Binary / utility | Suspicious use to investigate | ATT&CK reference in source |
|---|---|---|
| `certutil.exe` | Downloading files or decoding Base64 content. | T1105 / T1140 |
| `bitsadmin.exe` | Background file transfer. | T1197 |
| `mshta.exe` | Executing HTA or script content. | T1218.005 |
| `rundll32.exe` | Loading DLL exports or proxy execution. | T1218.011 |
| `regsvr32.exe` | Registering or executing scriptlet/DLL content. | T1218.010 |
| `reg.exe` | Registry modification, including persistence and security-setting changes. | T1112 |
| `wmic.exe` | WMI discovery or remote execution. | T1047 |
| `schtasks.exe` | Scheduled-task persistence or remote task execution. | T1053.005 |
| `sc.exe` | Service creation, modification or remote service execution. | T1543.003 / T1569.002 |
| `comsvcs.dll` | `MiniDump` export abused to dump LSASS. | T1003.001 |
| `msiexec.exe` | Installer-based execution or remote package retrieval. | T1218.007 |
| `installutil.exe` | .NET assembly execution through a trusted utility. | T1218.004 |
| `cscript.exe` / `wscript.exe` | Script execution. | T1059.005 |

---

## 7. Endpoint forensics with Velociraptor

Use Velociraptor to validate SIEM findings and collect endpoint artifacts, especially when logs are missing or incomplete. Prefer approved remote collection and preserve collection identifiers and hashes.

| Need | Velociraptor approach | What to capture / why |
|---|---|---|
| Collect a suspicious file | Use VFS or an appropriate file-collection artifact; export the file from collection results. | Preserve the original path, host, timestamps and hash. Analyse the exported copy in an isolated environment. |
| Review file metadata | Inspect file properties in VFS. | Record hashes, size, timestamps and signature details. |
| Search for files created in an incident window | Use file search with a bounded time range and relevant paths/names. | Find planted files that may not have generated a retained log event. |
| Investigate process activity | Collect relevant process and execution artifacts. | Correlate process, user, command line and timestamps with SIEM telemetry. |
| Review NTFS activity | Use appropriate NTFS/MFT artifacts and inspect the parent file with the NTFS accessor. | Reconstruct file creation and modification activity, including files no longer present. |
| Compare suspicious binaries | Collect candidate files and compare hashes, timestamps and signatures with known-good copies. | Identify replaced or modified binaries. |
| Offline timeline / deeper investigation | Collect relevant event logs, filesystem artifacts and other host evidence. | Build a timeline and validate suspected activity. |
| Linux endpoint triage | Use relevant Linux artifacts such as file finder, cron, users and SSH authorized keys (for example, `Linux.Sys.Crontab`, `Linux.Sys.Users` and `Linux.Ssh.AuthorizedKeys`). | Identify persistence, account changes and SSH access. |
| Email investigation | Collect the exported mailbox (PST) from its source location. | Preserve the original email, headers and attachments for analysis. |

---

## 8. File and binary analysis

### 8.1 Safe handling

- Never open or execute suspicious files on a production or corporate endpoint.
- Use an approved, isolated analysis workstation or lab.
- Preserve the original file and analyse a working copy.
- Record source host, original path, acquisition time, file timestamps and SHA-256 hash.
- Do not upload internal files to public analysis services without approval.
- Treat memory dumps and credential material as sensitive evidence.

### 8.2 Standard analysis workflow

| Step | Activity | Tool / method | Output |
|---:|---|---|---|
| 1 | Acquire | Velociraptor or approved evidence collection | Original file, source details and evidence record. |
| 2 | Identify and hash | `Get-FileHash`; PEStudio; file identification | SHA-256 (and MD5/SHA-1 if required), file type and size. |
| 3 | Reputation | Threat-intelligence platform using the hash | Known/unknown reputation; retain lookup details. |
| 4 | Signature | Authenticode signature inspection | Signer, issuer, thumbprint, validity and timestamp. |
| 5 | Headers and metadata | PEStudio, PE-bear, CFF Explorer | Compile timestamp, architecture, sections, imports, exports and debug information. |
| 6 | Packing | PEStudio, PE-bear, CFF Explorer | Section names, raw/virtual sizes, entropy and import count. |
| 7 | Unpack if appropriate | UPX on a copy, when UPX packing is identified | Unpacked copy; repeat identification, hash and metadata checks. |
| 8 | Capabilities | Imports and exports in PE-bear/CFF Explorer | API use, entry points and suspicious capabilities. |
| 9 | Strings | `strings`, PEStudio | URLs, IPs, domains, commands, paths, PDB paths and crypto references. |
| 10 | Embedded content | Appropriate format-specific tools | Extracted resources, scripts, documents or embedded payloads. |
| 11 | Report | Case notes / evidence record | Findings, indicators, hashes, tools used and limitations. |

### 8.3 Tool selection

| Tool | Primary use |
|---|---|
| PEStudio | PE triage, imports, strings, indicators and suspicious properties. |
| PE-bear | PE structure, sections, imports, exports and debug information. |
| CFF Explorer | PE headers, section data, address conversion and resource inspection. |
| UPX (via WSL) | Unpack UPX-packed files; work on a copy and re-hash the result. |
| `strings` | Extract readable strings from binaries and other files. |
| CyberChef | Decode Base64, PowerShell encodings and other encoded content without executing it. |
| `oletools` (`olevba`, etc.) | Inspect Office macros, auto-execution triggers, suspicious calls and URLs without opening Office documents. |
| `pffexport` | Export and inspect PST mailbox content and attachments. |
| `Get-AuthenticodeSignature` | Verify a file's Authenticode signature and certificate details. |

### 8.4 Reading the indicators

| Finding | Possible meaning | Recommended action |
|---|---|---|
| Sections named `UPX0`, `UPX1` or `UPX2` (including `UPX0` with raw size 0) | UPX-packed executable. | Unpack a copy with UPX and analyse the unpacked file. |
| Very few imports, mainly library loading, function resolution and memory-protection changes | Packed file or shellcode loader resolving APIs at runtime. | Review entropy and unpacking indicators; treat as a possible loader. |
| Packed file has few imports but unpacked copy has many more | Packing concealed the program's actual capabilities. | Focus on imports, exports and strings in the unpacked copy. |
| Random-looking export name alongside standard exports | Possible proxy DLL or loader export. | Record as an IOC and identify how it is invoked; correlate with `rundll32` activity. |
| High entropy (approximately 7.5–8.0) in data/resource section or overlay | Encrypted or compressed content may be present. | Record offsets and adjacent key/IV material; escalate deeper extraction to L3/lab analysis. |
| Many exports forwarded to a genuine system DLL of the same name | Possible proxy DLL built for sideloading. | Identify the signed EXE that loads it (Sysmon 7) and determine how the DLL was dropped. |
| System-DLL-like name in an application or writable folder; unusually large or recent | Possible DLL search-order hijack or sideloading. | Compare hash, signer and size with the legitimate `System32` copy. |
| PDB/debug-symbol path present | May reveal developer username, project, framework or build configuration. | Record the path as threat intelligence and search for related samples. |
| Compile timestamp at Unix epoch (1970) or in the future | Timestamp may be forged, zeroed or manipulated. | Do not use PE compile time as the incident timeline. |
| Compile timestamp shortly before the incident | Potentially purpose-built sample. | Raise priority and check for related samples or infrastructure. |
| File name differs from `OriginalFilename`, or vendor-style name lacks that vendor's signature | Renamed or masquerading tool. | Identify using strings, version information and threat intelligence. |
| Signer unrelated to claimed product, or status such as `UnknownError` / `HashMismatch` | Stolen, fake or unrelated certificate, or tampered file. | Record signer and SHA-1 thumbprint as indicators; hunt for the thumbprint. |
| Crypto-library names or functions in suspected ransomware strings | May identify encryption implementation. | Inform the IR lead; use the finding to guide approved recovery assessment. |
| Hard-coded cloud-storage URLs with plausible names | Possible payload staging infrastructure. | Hunt and block through approved proxy/DNS processes. |
| Service-style binary or `ServiceMain` entry point | May be designed to run as a service. | Find matching service-installation events 7045/4697. |
| Embedded or concealed payload | Additional content may be hidden in resources or overlays. | Extract safely and analyse as a normal PE or relevant file type. |

**PE address note:** A PE file may reference data by RVA (memory address) or file offset (position on disk). They are not interchangeable. The source guideline recommends using CFF Explorer's Address Converter rather than manual calculations. When measuring a blob, use the same address type for both its start and end.

### 8.5 Analysis by file type

| File type | Typical situation | Analysis approach |
|---|---|---|
| EXE / DLL | Dropped payload, sideloaded DLL, renamed tool or service binary | Follow the full workflow in [8.2](#82-standard-analysis-workflow) and interpret findings using [8.4](#84-reading-the-indicators). |
| Driver (`.sys`) | Sysmon 6 unsigned or known-vulnerable driver; antivirus crash/failure | Check signature and hash against known vulnerable-driver lists; correlate with the service that loaded it and antivirus failures. |
| PowerShell, batch, VBS/JS, HTA | Download cradle, staging or persistence | Read from 4104 or the collected file; decode with CyberChef; extract URLs, paths and downloaded tools. |
| Web scripts (`.aspx`, `.ashx`, `.php`, `.jsp`) | Webshell | Look for command execution (`Process.Start`, `cmd.exe`, `eval`, `exec`), Base64 blobs and download URLs. Decode safely. |
| Office documents | Phishing attachment or file uploaded to an internal portal | Use `oletools` to inspect macros, auto-execution, suspicious calls, injection targets and URLs. |
| Email (PST, EML, MSG) | Phishing origin | Use `pffexport` for PST. Review From, Reply-To, Return-Path, Received chain, Authentication-Results and Message-ID; extract attachments and URLs. |
| Alternate Data Stream | Scheduled task or command references `file:stream` | Extract with Velociraptor or PowerShell and analyse the stream as a separate file. |
| Memory dump (`.dmp`) | LSASS dump found on a host | Do not open on a normal workstation. Collect, hash and store as sensitive evidence; treat as credential compromise. |
| Encrypted files | Ransomware recovery assessment | Identify algorithm/library from the binary. Attempt decryption only in an approved lab with authorized keys/tools. |
| Linux ELF | Payload in temporary or web directories | Use `sha256sum`, `file`, `strings`, `readelf` and `objdump -p`. Avoid `ldd` on untrusted binaries because it may execute code. |
| Archives (`.zip`, `.7z`) | Tool output or exfiltration staging | Hash and list contents in the lab; do not extract on the compromised host. |

---

## 9. Command reference

Run commands through approved remote tooling (EDR or Velociraptor) wherever possible. Save output to the case folder. Replace every `<placeholder>` with a case-specific value. Commands are triage aids; validate syntax and permissions in your environment before use.

### 9.1 Windows (PowerShell)

#### Files, hashes and signatures

| Task | Command |
|---|---|
| Hash a file | `Get-FileHash -Algorithm SHA256 <path>` |
| Hash files in a folder | `Get-ChildItem <dir> -Recurse -File \| Get-FileHash -Algorithm SHA256` |
| Check a signature | `Get-AuthenticodeSignature <path> \| Format-List *` |
| Read signer certificate | `(Get-AuthenticodeSignature <path>).SignerCertificate \| Format-List Subject,Issuer,Thumbprint,NotBefore,NotAfter` |
| Find files modified in the last 24 hours | `Get-ChildItem <path> -Recurse -File -ErrorAction SilentlyContinue \| Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }` |
| List alternate data streams | `Get-Item <file> -Stream *` |
| Read an ADS to an evidence file | `Get-Content -Path <file> -Stream <stream> -Encoding Byte -ReadCount 0 \| Set-Content -Path <out>.infected -Encoding Byte` |

> In PowerShell 7, use `-AsByteStream` instead of `-Encoding Byte` where applicable.

#### Decode Base64 and inspect scripts

```powershell
# Find Base64 decoding in scripts
Get-ChildItem <path> -Recurse -Include *.ps1,*.psm1,*.bat,*.vbs,*.js -ErrorAction SilentlyContinue |
  Select-String -Pattern 'FromBase64String'

# Decode Base64 to a file
[IO.File]::WriteAllBytes('<output-file>', [Convert]::FromBase64String($b64))

# Alternative: certutil
certutil -decode <encoded.txt> <decoded.bin>

# Decode a PowerShell -EncodedCommand value (Base64 is UTF-16LE)
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

#### Processes and network

```powershell
# Processes with parent, path and command line
Get-CimInstance Win32_Process |
  Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine

# Running processes whose executable is not validly signed
Get-CimInstance Win32_Process |
  Where-Object { $_.ExecutablePath -and (Get-AuthenticodeSignature $_.ExecutablePath).Status -ne 'Valid' } |
  Select-Object Name,ProcessId,ExecutablePath

# Established TCP connections with owning process
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,
    @{Name='Process';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

# DNS cache
Get-DnsClientCache
```

To identify processes whose parent no longer exists:

```powershell
$ids = (Get-CimInstance Win32_Process).ProcessId
Get-CimInstance Win32_Process |
  Where-Object { $ids -notcontains $_.ParentProcessId } |
  Select-Object Name,ProcessId,ParentProcessId,CommandLine
```

#### Persistence and configuration

```powershell
# Run / RunOnce keys (supply the relevant registry key path)
Get-ItemProperty <Run-or-RunOnce-key-path> -ErrorAction SilentlyContinue

# Scheduled tasks and their actions
Get-ScheduledTask |
  Select-Object TaskName,TaskPath,State,
    @{Name='Action';Expression={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}}

# Services, binary path and account
Get-CimInstance Win32_Service |
  Select-Object Name,State,StartMode,StartName,PathName

# WMI event subscription: filter, consumer and binding
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

# Search registry data for URLs or PowerShell references
reg query HKLM /f "http" /s /d
reg query HKCU /f "powershell" /s /d

# Defender state and exclusions
Get-MpComputerStatus |
  Select-Object RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
Get-MpPreference |
  Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension
```

#### Event logs

```powershell
# PowerShell script blocks containing common download/decode activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Where-Object { $_.Message -match 'DownloadString|IEX|FromBase64String|WebClient' } |
  Select-Object TimeCreated,Message

# Successful and failed logons (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)}

# Sysmon process events containing certutil
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'certutil' }
```

#### Containment (approval required)

Prefer EDR network isolation because it may preserve analyst and EDR access. Only if that option is unavailable and isolation is approved:

```powershell
Disable-NetAdapter -Name "<adapter>" -Confirm:$false
```

> Disabling the network adapter can also terminate your remote access. Coordinate before running it.

### 9.2 Linux

`<auth-log>` is distribution-specific (for example, Debian/Ubuntu and RHEL/CentOS use different locations). Run with appropriate privileges and write output to the case folder, not to suspicious directories.

#### Accounts and authentication

| Task | Command |
|---|---|
| Successful logins | `last -a` |
| Failed logins | `lastb -a` |
| Failed/invalid authentication messages | `grep -Ei 'failed|invalid' <auth-log>` |
| Count failed SSH attempts by source IP | `grep 'Failed password' <auth-log> \| awk '{print $(NF-3)}' \| sort \| uniq -c \| sort -nr` |
| sudo / su usage | `grep -E 'sudo:|su:' <auth-log>`; where available, `ausearch -m USER_CMD` |
| Accounts with UID 0 | `awk -F: '$3==0 {print $1}' /etc/passwd` |
| New user creation | `grep -E 'useradd|adduser' <auth-log>` |
| SSH authorized keys | `find / -name 'authorized_keys*' -exec ls -la {} \\; 2>/dev/null` |
| Kerberos keytab entries | `klist -k <keytab-file>` |

#### Processes and network

```bash
# Process tree and command lines
ps auxf
ps -eo pid,ppid,user,lstart,cmd

# Processes running from temporary paths or deleted binaries
ls -l /proc/*/exe 2>/dev/null | grep -E '<temp-path>|deleted'

# Open files that have been deleted
lsof +L1

# Connections with process information
ss -tunap

# Possible reverse-shell processes owning sockets
ss -tunap | grep -E '(bash|sh|dash|python[2-9. ]*|perl|nc|ncat|socat)'

# Process details (replace PID)
tr '\0' ' ' < /proc/<PID>/cmdline
tr '\0' '\n' < /proc/<PID>/environ
cat /proc/<PID>/maps

# Recover a running (even deleted) executable
cp /proc/<PID>/exe <evidence-dir>/<PID>.bin

# Dump process memory (requires gdb)
gcore -o <evidence-dir>/core <PID>
```

#### Persistence and file system

```bash
# Running services and timers
systemctl list-units --type=service --state=running
systemctl list-timers --all
grep -R 'ExecStart' <systemd-unit-directories> 2>/dev/null

# Cron entries for all users
for u in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"
done
ls -la <system-cron-directories>

# Files modified in the last 24 hours
find / -xdev -type f -mtime -1 2>/dev/null

# ELF binaries in suspicious locations
find <directories> -type f -exec file {} + 2>/dev/null | grep ELF

# SUID and SGID files
find / -xdev -type f -perm /6000 2>/dev/null

# Files matching a name pattern
find / -xdev -iname '<pattern>' 2>/dev/null

# Web exploitation attempts in access logs
grep -Ei 'curl|wget|base64|/bin/sh|/bin/bash|python|%24%28|\$\(' <web-access-log>
```

#### Network, malware triage and containers

```bash
# Firewall rules
iptables -L -n -v
nft list ruleset

# Capture traffic and DNS
tcpdump -i any -nn -w <evidence-dir>/capture.pcap
tcpdump -i any -nn port 53

# Hash and identify a file
sha256sum <file>
file <file>

# Static checks; do not execute the sample
strings -a <file> | grep -Ei 'http|curl|wget'
readelf -h -S <file>
objdump -p <file>   # dependencies; prefer this to ldd for untrusted binaries

# YARA scan
yara -r <rules.yar> <path>

# Rootkit checks
chkrootkit
rkhunter --check --sk

# Kernel modules
lsmod
modinfo <module>
journalctl -k | grep -i module

# Docker
docker ps -a
docker inspect <id>
docker logs <id>

# Kubernetes
kubectl get pods -A
kubectl describe pod <pod> -n <namespace>
kubectl logs <pod> -n <namespace>
```

---

## 10. Incident response workflow

| Phase | Key actions | Primary owner |
|---|---|---|
| 1. Detect and triage | Validate the alert, rule out false positives, assign severity using [Section 2.2](#22-severity-and-escalation), and open a ticket. | L1 |
| 2. Investigate and scope | Build the timeline; identify root cause, affected hosts, accounts and data; collect indicators. | L2/L3 |
| 3. Preserve evidence | Collect volatile data (processes, connections and memory where needed), files and logs using Velociraptor. Hash and store evidence. | L2/L3 |
| 4. Contain | Isolate hosts using EDR; disable or reset accounts; revoke sessions/tokens; block indicators at proxy, firewall, mail gateway and EDR. Obtain approval. | IR lead (with approval) |
| 5. Eradicate | Remove persistence (services, tasks, Run keys, WMI, cron/systemd, SSH keys, ADS payloads, webshells and planted DLLs); patch the exploited vulnerability and rotate credentials. | IR team with IT |
| 6. Recover | Restore from known-clean backups or rebuild systems where trust is lost. Apply heightened monitoring. | IT with SOC |
| 7. Lessons learned | Document root cause, detection/logging gaps and new detections; update this guideline. | SOC manager |

### Credential-compromise rule

If LSASS, SAM/SECURITY hives or `NTDS.dit` were dumped, reset every exposed account. If `NTDS.dit` was taken, perform a domain-wide reset including the `krbtgt` account twice, respecting the replication interval between resets. Coordinate this action with the domain/identity team and the incident-response lead.

### Linux host response

Capture volatile evidence; contain at network level; lock compromised accounts; remove persistence (cron, systemd and SSH keys); rotate keytabs; triage and analyse binaries; take a forensic image if required; determine root cause; patch and harden; then monitor.

---

## 11. Documentation and reporting

A case record must allow another analyst to reproduce the conclusions from the ticket alone.

| Report item | What to record |
|---|---|
| Summary | What happened, when (UTC), where, who, severity and current status. |
| Timeline | Each step with timestamp, host, log source, event ID and key field values. |
| Affected assets | Hosts, accounts, data and services. |
| Indicators of compromise | SHA-256 hashes, file names and paths, IPs, defanged domains/URLs, registry keys, service/task names, named pipes, certificate thumbprints and PDB paths. |
| Evidence | Velociraptor collection/hunt IDs, file hashes, storage location and chain of custody. |
| MITRE ATT&CK mapping | Technique IDs for each confirmed step. |
| Actions and approvals | Containment and eradication actions, approver and time of approval. |
| Root cause and recommendations | Initial access vector, control gaps and detection improvements. |

**Before closing the incident:** verify that the evidence, timeline, decisions and conclusions are sufficiently detailed for an independent analyst to reproduce the investigation.

---

*End of guideline.*
