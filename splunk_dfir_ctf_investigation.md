
# Splunk DFIR Hunting Cheatsheet

### Windows, PowerShell, authentication, persistence, file access and network pivots

A practical Splunk reference for blue-team CTFs. Follow the sections in order: start with the account and host, identify execution, trace scripts and network connections, inspect file access and persistence, then correlate everything into a timeline. Skip or revisit steps when challenge clues point elsewhere.

> **Before running:** Confirm your `index`, `sourcetype`, `host` field, and field names. Windows XML, classic Windows Event Log, Sysmon, and network data often use different field names. The examples below use common names; adapt them to your data model.

---

## Contents

0. [Initial Data Exploration & Triage (CTF Quick Start)](#0-initial-data-exploration--triage-ctf-quick-start)
1. [Successful and failed logon analysis](#1-successful-and-failed-logon-analysis)
2. [Windows process execution](#2-windows-process-execution)
3. [PowerShell script-block investigation](#3-powershell-script-block-investigation)
4. [Encoded and hidden PowerShell execution](#4-encoded-and-hidden-powershell-execution)
5. [Suspicious PowerShell download and execution patterns](#5-suspicious-powershell-download-and-execution-patterns)
6. [URL extraction from raw events](#6-url-extraction-from-raw-events)
7. [Network and DNS investigation](#7-network-and-dns-investigation)
8. [Windows file activity and share access](#8-windows-file-activity-and-share-access)
9. [Sensitive document access: PDF, DOC, XLS and TXT](#9-sensitive-document-access-pdf-doc-xls-and-txt)
10. [File-server activity investigation](#10-file-server-activity-investigation)
11. [Persistence hunting](#11-persistence-hunting)
12. [Credential dumping & privilege escalation](#12-credential-dumping--privilege-escalation)
13. [User activity reconstruction on a workstation](#13-user-activity-reconstruction-on-a-workstation)
14. [Build an incident timeline](#14-build-an-incident-timeline)
15. [Quick Event ID reference](#15-quick-event-id-reference)
16. [SPL and field-validation notes](#16-spl-and-field-validation-notes)
17. [DFIR investigation workflow](#17-dfir-investigation-workflow)

---

## 0. Initial Data Exploration & Triage (CTF Quick Start)

**Use case:** Quickly discover what indexes, sourcetypes, hosts, and Event IDs exist in an unfamiliar CTF Splunk environment before writing targeted queries.

**List all indexes, sourcetypes, and hosts:**

```spl
| tstats count where index=* by index sourcetype host
| sort 0 - count
```

**Discover available fields and sample values in a sourcetype:**

```spl
index=* sourcetype=*
| head 100
| fieldsummary
| table field count distinct_count values
```

**Top Event IDs across Windows logs:**

```spl
index=* EventCode=*
| stats count by sourcetype EventCode
| sort 0 - count
```

---

## 1. Successful and failed logon analysis

**Use case:** Summarize successful and failed Windows authentication events by account, computer, and logon type. Useful for identifying brute-force attempts, unusual logons, and suspicious remote access.

**Events:**
* **4624:** Successful logon.
* **4625:** Failed logon.

```spl
index=* sourcetype=xmlwineventlog (EventCode=4624 OR EventCode=4625)
| where NOT TargetUserName IN ("ANONYMOUS LOGON","LOCAL SERVICE","NETWORK SERVICE","-")
| where NOT match(TargetUserName,"^(DWM-\d+|UMFD-\d+)$")
| where NOT match(TargetUserName,"\$$")
| eval LogonTypeDesc=case(
    LogonType=="2","Interactive (Local)",
    LogonType=="3","Network",
    LogonType=="4","Batch",
    LogonType=="5","Service",
    LogonType=="7","Unlock",
    LogonType=="8","NetworkCleartext",
    LogonType=="9","NewCredentials",
    LogonType=="10","RDP",
    LogonType=="11","CachedInteractive",
    true(),"Other")
| stats
    count(eval(EventCode=4624)) as Successful_Logons
    count(eval(EventCode=4625)) as Failed_Logons
    by TargetUserName Computer LogonTypeDesc
| sort 0 - Successful_Logons
```

**Logon type reference:**

| Type | Meaning | Investigation use |
| :--- | :--- | :--- |
| **2** | Interactive | Local/console sign-in |
| **3** | Network | Network resource access, including shares |
| **4** | Batch | Scheduled/batch activity |
| **5** | Service | Service account logon |
| **7** | Unlock | Workstation unlock |
| **8** | NetworkCleartext | Credentials supplied in cleartext form to the authentication package |
| **9** | NewCredentials | RunAs with alternate credentials |
| **10** | RemoteInteractive | Remote Desktop (RDP) |
| **11** | CachedInteractive | Cached domain logon |

**Investigate:**
* Many failures followed by a success (password spraying / brute force).
* Successful RDP logons at unusual times.
* Network logons from unexpected source IPs.
* Service or batch logons by unexpected accounts.
* Accounts authenticating to unusual computers.

**Important corrections and caveats:**
* The original exclusion expression had invalid SPL syntax around `SYSTEM`, `DWM-2`, and `DWM-1`. The corrected query excludes `DWM` and `UMFD` virtual accounts using a regex.
* `TargetUserName` and `Computer` are common XML field names, but sourcetype/field extraction may differ.
* Preserve `IpAddress`, `WorkstationName`, `LogonProcessName`, and `AuthenticationPackageName` when investigating individual events.
* Excluding machine accounts ending in `$` is useful for a human-account summary, but can hide machine-account abuse. Run a separate machine-account hunt when relevant.
* `LogonType` may be numeric. If the description mapping does not match, normalize it with `tostring(LogonType)` first.

**To retain source IPs in the summary:**

```spl
| stats
    count(eval(EventCode=4624)) as Successful_Logons
    count(eval(EventCode=4625)) as Failed_Logons
    values(IpAddress) as Source_IPs
    by TargetUserName Computer LogonTypeDesc
```

---

## 2. Windows process execution

**Use case:** Find programs launched on a Windows endpoint. This is usually an early step when investigating initial execution, suspicious tools, lateral movement, or malware execution.

**Events:**
* **Sysmon 1:** Process creation; provides process and parent-process context.
* **Security 4688:** A new process was created; command-line visibility depends on audit policy.

```spl
index=* (EventCode=1 OR EventCode=4688)
| table _time host User EventCode Image ParentImage ProcessId ParentProcessId CommandLine NewProcessName ParentProcessName
| sort 0 _time
```

**Investigate:** Unusual parent-child relationships (e.g., `winword.exe` or `w3wp.exe` spawning `cmd.exe` or `powershell.exe`), execution from `AppData`, `Temp`, `Public`, or `Downloads` folders, command-line arguments, service accounts running interactive tools, and processes launched shortly before suspicious network activity.

**Useful pivots:** `Image`, `NewProcessName`, `CommandLine`, `ParentImage`, `ParentProcessName`, `ProcessGuid`, `ParentProcessGuid`, `ProcessId`, `Hashes`.

---

## 3. PowerShell script-block investigation

**Use case:** Inspect PowerShell code processed by the PowerShell engine. This can expose commands, script content, download cradles, and in-memory execution that may not be obvious from process creation alone.

**Event:** PowerShell **4104 — Script Block Logging**.

```spl
index=main sourcetype=wineventlog EventCode=4104
| table _time host User ComputerName ScriptBlockId ScriptBlockText
| sort 0 _time
```

**Hunt for suspicious script content:**

```spl
index=main sourcetype=wineventlog EventCode=4104
| search ScriptBlockText="*Invoke-Expression*"
    OR ScriptBlockText="*DownloadString*"
    OR ScriptBlockText="*DownloadFile*"
    OR ScriptBlockText="*Invoke-WebRequest*"
    OR ScriptBlockText="*FromBase64String*"
    OR ScriptBlockText="*Net.WebClient*"
    OR ScriptBlockText="*Start-BitsTransfer*"
| table _time host User ScriptBlockId ScriptBlockText
| sort 0 _time
```

**Investigate:** The full script block, script-block ID, user, host, URLs, IP addresses, file paths, encoded content, and related process-creation events.

> **Field note:** Event 4104 commonly stores script content in `ScriptBlockText`, not `CommandLine`. Large scripts may be split across multiple 4104 events. Correlate using `ScriptBlockId` and the event sequence where available.

---

## 4. Encoded and hidden PowerShell execution

**Use case:** Find PowerShell launched with options commonly used to obscure execution or avoid interactive visibility. These switches are not malicious by themselves; validate the command and surrounding activity.

**Events:** Sysmon 1 and Security 4688.

```spl
index=* (EventCode=1 OR EventCode=4688)
| search CommandLine="*EncodedCommand*"
    OR CommandLine="*-enc *"
    OR CommandLine="*ExecutionPolicy Bypass*"
    OR CommandLine="*-ep Bypass*"
    OR CommandLine="*WindowStyle Hidden*"
    OR CommandLine="*-w hidden*"
    OR CommandLine="*-NoProfile*"
    OR CommandLine="*-nop*"
| table _time host User Image ParentImage NewProcessName ParentProcessName CommandLine
| sort 0 _time
```

**Investigate:** Decode Base64 content where present (note: PowerShell Base64 is typically UTF-16LE encoded), identify the parent process, determine whether the command downloaded or executed a payload, and correlate with 4104, DNS, proxy, and file-creation events.

> **Field note:** `CommandLine` is not universal. Security 4688 may use `ProcessCommandLine`; Sysmon commonly uses `CommandLine`. Check the actual event fields.

---

## 5. Suspicious PowerShell download and execution patterns

**Use case:** Identify script content or command lines associated with downloading and executing remote content.

**For 4104 script content:**

```spl
index=main EventCode=4104
| search ScriptBlockText="*Invoke-Expression*"
    OR ScriptBlockText="*iex *"
    OR ScriptBlockText="*Invoke-WebRequest*"
    OR ScriptBlockText="*iwr *"
    OR ScriptBlockText="*DownloadString*"
    OR ScriptBlockText="*DownloadFile*"
    OR ScriptBlockText="*Net.WebClient*"
    OR ScriptBlockText="*Start-BitsTransfer*"
| table _time host User ScriptBlockId ScriptBlockText
| sort 0 _time
```

**For process command lines:**

```spl
index=* (EventCode=1 OR EventCode=4688)
| search CommandLine="*powershell*"
    AND (CommandLine="*DownloadString*"
         OR CommandLine="*DownloadFile*"
         OR CommandLine="*Invoke-WebRequest*"
         OR CommandLine="* -enc *"
         OR CommandLine="*EncodedCommand*")
| table _time host User Image ParentImage CommandLine
| sort 0 _time
```

**Investigate:** Remote URL, destination path, downloaded filename, process that initiated the request, hash and reputation of the payload, and whether the downloaded file executed.

---

## 6. URL extraction from raw events

**Use case:** Extract HTTP/HTTPS URLs embedded in raw log events. Useful for quick IOC discovery across proxy, endpoint, email, or other logs that contain URLs.

```spl
index=*
| rex field=_raw "(?<url>https?://[^\s\">]+)"
| where isnotnull(url)
| table _time host sourcetype url
| dedup url
```

**What it does:**
1. Searches events across indexes.
2. Extracts a URL beginning with `http://` or `https://`.
3. Stores the extracted value in a field called `url`.
4. Displays the timestamp, host, sourcetype, and URL.
5. Removes duplicate URL values.

**Investigate:** Suspicious domains, URL paths, download endpoints, IP-based URLs, repeated requests, and URLs seen shortly before malware execution.

**Caution:** This is a basic URL extractor. It may include trailing punctuation or miss URLs that are encoded, split, or stored in structured fields. For proxy logs, prefer the parsed URL field if available.

---

## 7. Network and DNS investigation

**Use case:** Pivot from an endpoint or user to network activity. Search DNS, proxy, and firewall data using the host, source IP, destination IP, or domain discovered in endpoint logs.

**DNS example (Network or Sysmon 22):**

```spl
index=* (sourcetype="dns" OR EventCode=22)
| table _time host src_ip Image QueryName QueryResults
| sort 0 _time
```

**Proxy example:**

```spl
index=* sourcetype="proxy"
| table _time host User src_ip dest_host url http_method status
| sort 0 _time
```

**Firewall / Sysmon Network Connection (EventCode 3) example:**

```spl
index=* (sourcetype="firewall" OR EventCode=3)
| table _time host Image src_ip SourceIp dest_ip DestinationIp dest_port DestinationPort action bytes_in bytes_out
| sort 0 _time
```

**Investigate:** Rare domains, newly observed destinations, unusual ports, denied/allowed connection sequences, large outbound transfers (exfiltration), and connections immediately after script or process execution.

> **Field note:** Network field names vary widely. For example, a firewall may use `src`, `dst`, `dpt`, `sentbyte`, or vendor-specific fields instead of `src_ip`, `dest_ip`, and `bytes_out`.

---

## 8. Windows file activity and share access

**Use case:** Identify file creation, deletion, access, and share activity. These events help establish whether a suspicious process staged, modified, accessed, or deleted files.

| Event | Meaning | Use |
| :--- | :--- | :--- |
| **Sysmon 11** | FileCreate | New file or overwrite |
| **Sysmon 23** | FileDelete archived | Deleted file archived by Sysmon |
| **Sysmon 26** | FileDelete detected | File deletion detected |
| **Security 4663** | Object access | Audited file/folder access |
| **Security 4660** | Object deleted | Object deletion |
| **Security 5140** | Network share accessed | Share-level access |
| **Security 5145** | Detailed share access check | Path and requested access |
| **Security 4670** | Permissions changed | ACL/permission modification |

**Sysmon file creation example:**

```spl
index=* EventCode=11
| table _time host User Image TargetFilename
| sort 0 _time
```

**Share access example:**

```spl
index=* (EventCode=5140 OR EventCode=5145)
| table _time host SubjectUserName ShareName RelativeTargetName IpAddress AccessMask
| sort 0 _time
```

**Investigate:** Unusual file paths, bulk access, file creation by scripting tools or archive utilities (`7z.exe`, `rar.exe`), deletion after staging, permission changes, and activity from unexpected client addresses.

---

## 9. Sensitive document access: PDF, DOC, XLS and TXT

**Use case:** Find Windows file-share access events involving documents with selected extensions. This is useful when investigating access to business documents or possible data collection.

**Event:** Security 5145 — detailed file-share access check.

```spl
index=* host=* EventCode=5145
| regex RelativeTargetName="(?i)\.(pdf|doc|docx|xls|xlsx|txt)$"
| table _time host SubjectUserName ShareName RelativeTargetName IpAddress AccessMask
| sort 0 _time
```

**What the fields tell you:**
* `SubjectUserName`: Account making the access request.
* `ShareName`: Accessed share.
* `RelativeTargetName`: Path/name relative to the share.
* `IpAddress`: Source address of the client.
* `AccessMask`: Requested access rights (e.g., `0x1` = ReadData/ListDirectory).

**Investigate:** Unusual users, bulk access, sensitive directories, access from unexpected source IPs, and activity shortly before archive creation or outbound transfers.

> **Regex note:** Match against `RelativeTargetName`, not `_raw`, when that parsed field is available. The original `_raw` expression only matches when the entire raw event ends with the extension, which is often not true for XML events. Event 5145 records an access check; it does not by itself prove that a file was successfully read or exfiltrated.

**Common extensions:**

| Extension | File type |
| :--- | :--- |
| `.pdf` | PDF document |
| `.doc`, `.docx` | Microsoft Word |
| `.xls`, `.xlsx` | Microsoft Excel |
| `.txt` | Plain-text file |

---

## 10. File-server activity investigation

**Use case:** Review suspicious activity on a file server, including process execution, PowerShell, authentication, scheduled tasks, and network indicators.

```spl
index=* sourcetype=* (EventCode=4688 OR EventCode=1 OR EventCode=4104 OR EventCode=4698 OR EventCode=4624 OR EventCode=4625
    OR sourcetype="dns" OR sourcetype="proxy" OR sourcetype="firewall")
host="files"
| eval Event=coalesce(EventCode,sourcetype)
| eval Process=coalesce(NewProcessName,process_name,Image,CommandLine)
| table _time host User Event Process ParentProcessName ParentImage CommandLine ScriptBlockText src_ip dest_ip dest_host url
| sort 0 _time
```

**Why investigate a file server?**
* Attackers may enumerate and collect sensitive shared documents.
* Compromised accounts may access shares outside their normal pattern.
* Ransomware may encrypt or delete files across network shares.
* Attackers may stage archives before exfiltration.

**Useful Windows Security events:**
* **4663:** An attempt was made to access an object; auditing/SACLs must be configured.
* **4660:** An object was deleted.
* **5140:** A network share was accessed.
* **5145:** A network share object was checked for access.
* **4670:** Permissions on an object were changed.

> **Tip:** Avoid excluding `SYSTEM` and service accounts at the start of an investigation. Doing so can hide useful activity. Review service-account events and filter only when the context is understood.

---

## 11. Persistence hunting

**Use case:** Find mechanisms that allow an attacker or unwanted program to execute again after logoff, reboot, or another trigger.

### 11.1 Registry Run and RunOnce keys

**Events:** Sysmon 12, 13, and 14. Event 13 records registry value setting; Event 12 records key/value creation or deletion; Event 14 records key/value rename.

```spl
index=* (EventCode=12 OR EventCode=13 OR EventCode=14)
| where like(TargetObject,"%\\CurrentVersion\\Run%")
    OR like(TargetObject,"%\\CurrentVersion\\RunOnce%")
| table _time host User EventCode Image TargetObject Details
| sort 0 _time
```

**Investigate:** Value name and data, executable path, modifying process, user context, signature, and file hash. Event 13's `TargetObject` usually includes the value name, so matching the key prefix with wildcards is more reliable than exact equality.

### 11.2 Scheduled task creation

**Events:** Security 4698 (scheduled task created); Sysmon 1 can reveal `schtasks.exe` or PowerShell task cmdlets.

```spl
index=* (EventCode=4698 OR EventCode=1 OR EventCode=4688)
| search CommandLine="*schtasks*"
    OR CommandLine="*Register-ScheduledTask*"
    OR CommandLine="*New-ScheduledTask*"
| table _time host User EventCode Image ParentImage CommandLine TaskName
| sort 0 _time
```

**Investigate:** Task name, task XML/action, trigger, run-as account, executable/script path, and creator.

### 11.3 Startup folder file creation

**Event:** Sysmon 11 — FileCreate.

```spl
index=* EventCode=11
| where like(TargetFilename,"%\\Start Menu\\Programs\\Startup\\%")
| table _time host User Image TargetFilename
| sort 0 _time
```

Check both per-user and all-user Startup folders. Also investigate scripts, shortcuts, and files created by unusual parent processes.

### 11.4 Windows service persistence

**Evidence sources:** Sysmon 12/13 for registry changes under the Services key; Security 4697 or System 7045 for service installation.

```spl
index=* (EventCode=12 OR EventCode=13)
| where like(TargetObject,"%\\Services\\%")
| table _time host User EventCode Image TargetObject Details
| sort 0 _time
```

```spl
index=* (EventCode=4697 OR EventCode=7045)
| table _time host User EventCode ServiceName ImagePath ServiceFileName
| sort 0 _time
```

**Investigate:** Service name, binary path, start type, service account, signer, hash, and installation time. Field names differ by source and Windows event parser.

### 11.5 WMI persistence

**Events:** Sysmon 19, 20, and 21 — WMI filter, consumer, and binding activity.

```spl
index=* (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time host User EventCode Operation EventType Name Destination
| sort 0 _time
```

**Investigate:** Filter query, consumer command/script, binding relationship, and the process/user that created the subscription.

### 11.6 Persistence-related file deletion or tampering

Do not treat Sysmon Event 23 as DLL injection. Event 23 is file deletion with archiving; Event 26 is file deletion detected without archiving; Event 25 is process tampering.

```spl
index=* (EventCode=23 OR EventCode=26 OR EventCode=25)
| table _time host User EventCode Image TargetFilename Details
| sort 0 _time
```

---

## 12. Credential dumping & privilege escalation

**Use case:** Detect attempts to dump credentials from LSASS memory, harvest Kerberos tickets, or create privileged local/domain accounts.

**LSASS process access (Sysmon 10):**

```spl
index=* EventCode=10
| where like(TargetImage,"%\\lsass.exe")
| table _time host SourceImage TargetImage GrantedAccess CallTrace
| sort 0 _time
```

**Account creation & privilege group changes (Security 4720, 4728, 4732):**

```spl
index=* (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time host EventCode SubjectUserName TargetUserName MemberName GroupName
| sort 0 _time
```

**Anti-forensics / Audit log clearing (Security 1102, System 104):**

```spl
index=* (EventCode=1102 OR EventCode=104)
| table _time host EventCode SubjectUserName Channel
| sort 0 _time
```

---

## 13. User activity reconstruction on a workstation

**Use case:** Build a cross-source timeline for a named user on a specific endpoint. Combine process creation, PowerShell, task creation, authentication, and network telemetry.

```spl
index=* sourcetype=* (EventCode=4688 OR EventCode=1 OR EventCode=4104 OR EventCode=4698 OR EventCode=4624 OR EventCode=4625
    OR sourcetype="dns" OR sourcetype="proxy" OR sourcetype="firewall")
host="PC01" User="*james*"
| eval Event=coalesce(EventCode,sourcetype)
| eval Process=coalesce(NewProcessName,process_name,Image,CommandLine)
| table _time host User Event Process ParentProcessName ParentImage CommandLine ScriptBlockText src_ip dest_ip dest_host url
| sort 0 _time
```

**Use it to answer:**
* When did the user log in?
* What processes and scripts did they execute?
* Did they create scheduled tasks or other persistence?
* Which domains, URLs, and IP addresses did the host contact?
* Did the activity lead to file creation, privilege escalation, or lateral movement?

> **Important:** A filter such as `host="PC01" User="*james*"` can exclude network events if their `host` or `User` fields identify the log collector or are absent. Search endpoint and network data separately, then correlate on time, IP, domain, and host.

---

## 14. Build an incident timeline

**Use case:** Put endpoint events into chronological order to understand the sequence of activity. Start broad, then narrow the time range and host after finding suspicious evidence.

```spl
index=* host="PC01"
    (EventCode=4624 OR EventCode=4625 OR EventCode=4688 OR EventCode=1
     OR EventCode=4104 OR EventCode=4698 OR EventCode=11 OR EventCode=13)
| eval Event=coalesce(EventCode,sourcetype)
| table _time host User Event Image ParentImage CommandLine ScriptBlockText TargetObject TargetFilename
| sort 0 _time
```

**Timeline questions:**
1. Which account authenticated first?
2. What was the first suspicious process?
3. Which parent process launched it?
4. Was PowerShell used to retrieve or execute content?
5. Was a file created or a registry value changed?
6. Was a scheduled task or service installed?
7. Did the host communicate with an external destination?
8. Did the attacker access shares or move to another host?

**Correlation keys:** Timestamp, hostname, username, process GUID, process ID, source/destination IP, domain, file path, and hash.

---

## 15. Quick Event ID reference

| Event ID | Source | Meaning | Common DFIR use |
| :--- | :--- | :--- | :--- |
| **1** | Sysmon | Process creation | Execution and parent-child analysis |
| **3** | Sysmon | Network connection | Endpoint-to-IP/port mapping |
| **7** | Sysmon | Image loaded | DLL loading and side-loading investigation |
| **8** | Sysmon | CreateRemoteThread | Possible process injection |
| **10** | Sysmon | ProcessAccess | LSASS dumping and suspicious process access |
| **11** | Sysmon | FileCreate | File staging and Startup folder activity |
| **12** | Sysmon | Registry object create/delete | Registry persistence changes |
| **13** | Sysmon | Registry value set | Run keys and service `ImagePath` changes |
| **14** | Sysmon | Registry key/value rename | Registry manipulation |
| **15** | Sysmon | File stream created | Alternate data streams / Mark-of-the-Web |
| **16** | Sysmon | Sysmon configuration change | Logging configuration tampering |
| **19** | Sysmon | WMI event filter | WMI persistence |
| **20** | Sysmon | WMI event consumer | WMI persistence |
| **21** | Sysmon | WMI consumer-to-filter binding | WMI persistence |
| **22** | Sysmon | DNS query | Domain and possible C2 investigation |
| **23** | Sysmon | FileDelete archived | File deletion (archived) |
| **24** | Sysmon | Clipboard change | Clipboard activity |
| **25** | Sysmon | ProcessTampering | Process hollowing/tampering |
| **26** | Sysmon | FileDelete detected | File deletion (detected) |
| **104** | System | System log cleared | Anti-forensics / log tampering |
| **1102** | Security | Audit log cleared | Anti-forensics / log tampering |
| **4104** | PowerShell | Script block logging | Script content and download cradles |
| **4624** | Security | Successful logon | Authentication analysis |
| **4625** | Security | Failed logon | Failed authentication / brute force |
| **4660** | Security | Object deleted | File/object deletion |
| **4663** | Security | Object access | Audited file access |
| **4670** | Security | Permissions changed | ACL modification |
| **4688** | Security | Process creation | Process execution |
| **4697** | Security | Service installed | Service persistence |
| **4698** | Security | Scheduled task created | Scheduled task persistence |
| **4720** | Security | User account created | Rogue account persistence |
| **4728 / 4732** | Security | User added to security group | Privilege escalation (Domain/Local Admins) |
| **4769** | Security | Kerberos service ticket requested | Kerberoasting detection (`TicketEncryptionType=0x17`) |
| **5140** | Security | Network share accessed | Share access |
| **5145** | Security | Detailed share access check | File/share path and requested access |
| **7045** | System | Service installed | Service persistence |

---

## 16. SPL and field-validation notes

### Wildcards: `IN` versus `like()`

`IN` is for exact values. It does not behave like a wildcard matcher.

**Avoid:**

```spl
| search CommandLine IN ("*schtasks*","*powershell*")
```

**Use:**

```spl
| where like(CommandLine,"%schtasks%") OR like(CommandLine,"%powershell%")
```

### Regex matching

Use `regex` to filter events with a regular expression:

```spl
| regex RelativeTargetName="(?i)\.(pdf|doc|docx|xls|xlsx|txt)$"
```

Use `match()` inside `where`:

```spl
| where match(TargetUserName,"(?i)^admin")
```

### Extracting a URL

```spl
| rex field=_raw "(?<url>https?://[^\s\">]+)"
```

### Normalize fields

Different sources may call the same concept by different names. Use `coalesce()` to create a common field when the candidates are known:

```spl
| eval Process=coalesce(NewProcessName,process_name,Image,CommandLine)
```

### Process tree reconstruction (`ProcessGuid` / `ParentProcessGuid`)

When investigating Sysmon logs, link parent and child processes accurately (avoiding PID reuse issues):

```spl
index=* EventCode=1
| eval ParentProc=ParentImage." (".ParentProcessGuid.")"
| eval ChildProc=Image." (".ProcessGuid.")"
| stats values(ChildProc) as Spawned_Processes by host User ParentProc
```

### Validate before trusting a query

* Check that the event actually contains the expected Event ID.
* Run `| fieldsummary` or inspect raw events to confirm field names.
* Check whether the event is from Sysmon, Security, System, PowerShell, DNS, proxy, or firewall.
* Confirm timestamp timezone (often UTC in CTFs) and host naming conventions.
* Verify whether auditing and Sysmon configuration captured the activity.
* Treat absence of an event as absence of evidence, not proof that the activity did not occur.

---

## Final reminder

These searches are **investigation starting points**, not proof of compromise. Validate suspicious activity by correlating endpoint, authentication, file, and network evidence. Adapt field names and `index`/`sourcetype` filters to the environment before relying on the results.

---

## 17. DFIR investigation workflow

Use this sequence during a blue-team investigation or CTF:

1. **Identify the affected host and account.** Start with `4624`/`4625` and endpoint inventory.
2. **Find process execution.** Review Sysmon `1` and Security `4688`; capture parent process and command line.
3. **Inspect PowerShell.** Review `4104` script blocks and correlate with process creation.
4. **Look for payload retrieval.** Extract URLs and pivot into DNS, proxy, and firewall logs.
5. **Check persistence.** Review Run keys, scheduled tasks, services, Startup folders, and WMI.
6. **Check credential access & privilege escalation.** Inspect LSASS access (`Sysmon 10`), Kerberos anomalies (`4769`), and account/group modifications (`4720`/`4728`/`4732`).
7. **Check file activity.** Identify file creation, access, deletion, share access, and permission changes.
8. **Investigate lateral movement.** Pivot on accounts, source IPs, remote logons, remote process execution, and destination hosts.
9. **Build the timeline.** Correlate timestamps, users, process GUIDs, IPs, paths, and hashes.
10. **Record IOCs and evidence.** Preserve hashes, URLs, domains, IPs, filenames, accounts, and exact timestamps.
