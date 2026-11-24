# Elastic Security KQL

### Elastic Security KQL — DFIR & Blue-Team CTF Hunting Handbook

A practical, investigation-ordered reference 

---

## CTF investigation order

1. [Validate the data and set the time window](#1-validate-data-and-time-window)
2. [Authentication: successful and failed logons](#2-authentication-successful-and-failed-logons)
3. [Process execution](#3-process-execution)
4. [PowerShell script-block activity](#4-powershell-script-block-activity)
5. [Encoded and hidden execution](#5-encoded-and-hidden-execution)
6. [Download cradles and suspicious script activity](#6-download-cradles-and-suspicious-script-activity)
7. [URLs, DNS and network connections](#7-urls-dns-and-network-connections)
8. [File creation, modification and deletion](#8-file-creation-modification-and-deletion)
9. [Sensitive document access and collection](#9-sensitive-document-access-and-collection)
10. [File-server and SMB activity](#10-file-server-and-smb-activity)
11. [Persistence hunting](#11-persistence-hunting)
12. [Privilege escalation and lateral movement](#12-privilege-escalation-and-lateral-movement)
13. [User and host activity reconstruction](#13-user-and-host-activity-reconstruction)
14. [Build the incident timeline](#14-build-the-incident-timeline)
15. [Field and KQL validation notes](#15-field-and-kql-validation-notes)
16. [Condensed CTF workflow](#16-condensed-ctf-workflow)

---

## 1. Validate data and time window

**Purpose:** Confirm which data is available before relying on a hunt.

Start broad in Discover or Security → Discover/Events. Set the time picker to
the challenge period and inspect the available data views / data streams.

```kql
*
```

Find Windows endpoint events:

```kql
event.category : process or event.category : authentication
```

Find events from a particular host:

```kql
host.name : "WORKSTATION01"
```

Find events for a particular user:

```kql
user.name : "j.smith"
```

Find events from Windows Sysmon:

```kql
winlog.channel : "Microsoft-Windows-Sysmon/Operational"
```

Find Windows Security log events:

```kql
winlog.channel : "Security"
```

**Check before proceeding**
- Confirm the data view / index pattern includes the challenge logs.
- Confirm the timestamp field and timezone.
- Inspect a raw event to learn the actual field names and ECS mappings.
- Confirm whether Windows events use `event.code`, `winlog.event_id`, or both.
- Confirm whether process command lines are in `process.command_line`.
- Do not assume every source uses ECS field names consistently.

---

## 2. Authentication: successful and failed logons

**Purpose:** Identify who accessed a host, from where, and whether authentication
was successful.

Windows Security:
- 4624 — successful logon
- 4625 — failed logon
- 4648 — logon using explicit credentials
- 4672 — special privileges assigned to a new logon
- 4776 — NTLM credential validation

Successful logons:

```kql
event.code : "4624"
```

Failed logons:

```kql
event.code : "4625"
```

Successful and failed logons for a user:

```kql
event.code : ("4624" or "4625") and user.name : "j.smith"
```

Logons to a particular computer:

```kql
event.code : ("4624" or "4625") and host.name : "WORKSTATION01"
```

Remote interactive / RDP logons (Logon Type 10; field availability varies):

```kql
event.code : "4624" and winlog.event_data.LogonType : "10"
```

Explicit credential use:

```kql
event.code : "4648"
```

Privileged logon:

```kql
event.code : "4672"
```

**Investigate next**
- `user.name`, `user.domain`, `host.name`
- `source.ip`, `source.port`, `source.domain`
- `winlog.event_data.LogonType`
- `winlog.event_data.AuthenticationPackageName`
- `winlog.event_data.LogonProcessName`
- `winlog.event_data.WorkstationName`

Do not automatically exclude machine accounts (`*$`), service accounts, or
system identities. They can be relevant to service abuse and lateral movement.
Logon type 3 is a network logon; it is not automatically malicious.

---

## 3. Process execution

**Purpose:** Find programs launched on endpoints and identify suspicious parent-child
relationships, command lines, users and paths.

Sysmon Event ID 1:

```kql
event.code : "1" and winlog.provider_name : "Microsoft-Windows-Sysmon"
```

Windows Security 4688:

```kql
event.code : "4688" and winlog.channel : "Security"
```

Suspicious command interpreters:

```kql
process.name : ("cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe")
```

Execution from common user-writable locations:

```kql
process.executable : (*\\AppData\\* or *\\Temp\\* or *\\Downloads\\* or *\\Users\\Public\\*)
```

Suspicious parent processes:

```kql
process.parent.name : ("winword.exe" or "excel.exe" or "outlook.exe" or "w3wp.exe" or "services.exe")
```

A particular executable or host:

```kql
process.name : "rundll32.exe" and host.name : "WORKSTATION01"
```

**Investigate next**
- `process.name`, `process.executable`, `process.command_line`
- `process.parent.name`, `process.parent.executable`
- `process.pid`, `process.entity_id`
- `process.parent.pid`, `process.parent.entity_id`
- `user.name`, `host.name`, `@timestamp`

A suspicious process name alone is not proof of compromise. Validate the path,
parent process, command line, signer/hash and surrounding activity.

---

## 4. PowerShell script-block activity

**Purpose:** Search PowerShell Script Block Logging (Windows PowerShell
Operational Event ID 4104).

```kql
event.code : "4104"
```

PowerShell script-block events from the expected channel:

```kql
event.code : "4104" and winlog.channel : "Microsoft-Windows-PowerShell/Operational"
```

Search for common execution and decoding functions:

```kql
event.code : "4104" and
powershell.file.script_block_text : (
  "*Invoke-Expression*" or "*IEX*" or "*FromBase64String*" or
  "*Invoke-Command*" or "*Add-Type*"
)
```

Search for download-related functions:

```kql
event.code : "4104" and
powershell.file.script_block_text : (
  "*DownloadString*" or "*DownloadFile*" or "*Invoke-WebRequest*" or
  "*Start-BitsTransfer*" or "*Net.WebClient*"
)
```

**Field fallback:** Depending on the integration and ingest pipeline, script text
may instead be stored in `winlog.event_data.ScriptBlockText`,
`message`, or another custom field. Inspect a raw 4104 event and adapt the query.

**Investigate next**
- Script block text
- `powershell.file.script_block_id` / `ScriptBlockId`
- `process.entity_id`, `process.pid`
- `user.name`, `host.name`, `@timestamp`

A script block can be split across multiple 4104 events. Correlate by ScriptBlockId
and sequence/fragment fields where present. A 4104 event records script content;
it does not by itself prove that every statement completed successfully.

---

## 5. Encoded and hidden execution

**Purpose:** Find PowerShell or command interpreter launches that use encoded
commands, hidden windows, or execution-policy bypasses.

```kql
process.name : "powershell.exe" and
process.command_line : (
  "*-EncodedCommand*" or "*-enc *" or "*-e *" or
  "*-WindowStyle Hidden*" or "*-w hidden*" or
  "*-ExecutionPolicy Bypass*" or "*-ep Bypass*" or
  "*-NoProfile*" or "*-nop*"
)
```

Include PowerShell 7:

```kql
process.name : ("powershell.exe" or "pwsh.exe") and
process.command_line : ("*EncodedCommand*" or "*ExecutionPolicy Bypass*" or "*WindowStyle Hidden*")
```

Look for command shells launching PowerShell:

```kql
process.parent.name : ("cmd.exe" or "wscript.exe" or "cscript.exe" or "winword.exe" or "excel.exe")
and process.name : ("powershell.exe" or "pwsh.exe")
```

**Investigate next**
- Recover and decode the Base64 command offline.
- Identify URLs, file paths, payload names and follow-on commands.
- Pivot to 4104 script-block events around the same time.
- Correlate parent/child process IDs and entity IDs.

These switches are investigative indicators, not proof of malicious activity.
Validate the decoded command and execution context.

---

## 6. Download cradles and suspicious script activity

**Purpose:** Identify scripts that retrieve content and execute it, or utilities
commonly used to stage payloads.

PowerShell download patterns:

```kql
process.command_line : (
  "*DownloadString*" or "*DownloadFile*" or "*Invoke-WebRequest*" or
  "*iwr *" or "*Start-BitsTransfer*" or "*Net.WebClient*"
)
```

PowerShell in-memory execution patterns:

```kql
process.command_line : (
  "*IEX*" or "*Invoke-Expression*" or "*FromBase64String*" or
  "*Reflection.Assembly*"
)
```

Common LOLBins and transfer utilities:

```kql
process.name : (
  "certutil.exe" or "bitsadmin.exe" or "mshta.exe" or "rundll32.exe" or
  "regsvr32.exe" or "curl.exe" or "wget.exe"
)
```

Certutil download/decode use:

```kql
process.name : "certutil.exe" and
process.command_line : ("*-urlcache*" or "*-decode*")
```

**Investigate next**
- Parent process and initiating user
- Download URL and destination file
- File hash and signature
- Subsequent process execution
- DNS, proxy and firewall activity at the same time

---

## 7. URLs, DNS and network connections

**Purpose:** Trace external communication, C2 infrastructure, payload hosting
and possible data exfiltration.

DNS events:

```kql
event.category : network and network.protocol : "dns"
```

DNS query for a domain:

```kql
dns.question.name : "example.com"
```

Suspicious or known domain indicators:

```kql
dns.question.name : ("example.com" or "bad-domain.test")
```

Network connections to an IP:

```kql
event.category : network and destination.ip : "203.0.113.10"
```

Connections from a host:

```kql
event.category : network and host.name : "WORKSTATION01"
```

Connections to common web ports:

```kql
event.category : network and destination.port : (80 or 443 or 8080 or 8443)
```

HTTP events and URLs (field availability depends on integration):

```kql
url.domain : "example.com" or url.full : "*example.com*"
```

Outbound connections from a process:

```kql
process.name : "powershell.exe" and event.category : network
```

**Investigate next**
- `source.ip`, `source.port`
- `destination.ip`, `destination.port`
- `network.direction`, `network.transport`, `network.protocol`
- `dns.question.name`, `dns.resolved_ip`
- `url.domain`, `url.full`, `http.request.method`
- `process.name`, `process.executable`, `user.name`, `host.name`

Not every network integration records process attribution. Firewall, proxy, DNS
and endpoint network events may use different host fields. Correlate by IP,
hostname and time. Check whether an event represents an allowed, blocked or
failed connection.

---

## 8. File creation, modification and deletion

**Purpose:** Find payload drops, scripts, archives, staged data and cleanup.

Sysmon Event ID 11 — file creation:

```kql
event.code : "11" and winlog.provider_name : "Microsoft-Windows-Sysmon"
```

Sysmon Event ID 23 — file deletion archived:

```kql
event.code : "23"
```

Sysmon Event ID 26 — file deletion detected:

```kql
event.code : "26"
```

Files created in common staging locations:

```kql
event.code : "11" and
file.path : (*\\Temp\\* or *\\AppData\\* or *\\Downloads\\* or *\\Users\\Public\\*)
```

Suspicious script and executable extensions:

```kql
file.extension : ("exe" or "dll" or "ps1" or "bat" or "cmd" or "vbs" or "js")
```

Archive files:

```kql
file.extension : ("zip" or "7z" or "rar" or "cab")
```

**Investigate next**
- `file.path`, `file.name`, `file.extension`
- `file.hash.sha256`, `file.hash.md5`
- `process.name`, `process.executable`, `user.name`
- `host.name`, `@timestamp`

File event coverage depends on Sysmon configuration and endpoint telemetry.
A missing file event does not establish that a file was not created or accessed.

---

## 9. Sensitive document access and collection

**Purpose:** Investigate possible collection of business documents before staging
or exfiltration.

Windows Security 5145 — detailed file-share access check:

```kql
event.code : "5145"
```

Filter likely document extensions when the path is available:

```kql
event.code : "5145" and
winlog.event_data.RelativeTargetName : (
  "*.pdf" or "*.doc" or "*.docx" or "*.xls" or "*.xlsx" or "*.txt" or "*.csv"
)
```

Search for archive utility execution:

```kql
process.name : ("7z.exe" or "7za.exe" or "rar.exe" or "winrar.exe" or "tar.exe")
```

Search for common data staging tools:

```kql
process.name : (" robocopy.exe" or "xcopy.exe" or "esentutl.exe")
```

**Investigate next**
- `winlog.event_data.SubjectUserName`
- `winlog.event_data.ShareName`
- `winlog.event_data.RelativeTargetName`
- `winlog.event_data.IpAddress`
- `winlog.event_data.AccessMask`
- File server, source workstation and user
- Archive creation and subsequent outbound connections

5145 is a detailed share access check; it does not alone prove that data was
successfully read or exfiltrated. Audit policy and share/file SACL configuration
affect visibility. Check the actual event fields in the raw document.

---

## 10. File-server and SMB activity

**Purpose:** Investigate share enumeration, access to sensitive files, unusual
client hosts and possible collection from a file server.

Share access:

```kql
event.code : ("5140" or "5145")
```

Detailed share access from a user:

```kql
event.code : "5145" and winlog.event_data.SubjectUserName : "j.smith"
```

Access to a particular share:

```kql
event.code : ("5140" or "5145") and
winlog.event_data.ShareName : "*Finance*"
```

Object access auditing:

```kql
event.code : "4663"
```

File deletion:

```kql
event.code : "4660"
```

Permission changes:

```kql
event.code : "4670"
```

**Investigate next**
- Client IP and workstation
- Account used to access the share
- Share name and relative target path
- Access mask / requested access
- Volume and frequency of access
- Archive tools and outbound network connections

A file-server event may identify the server as `host.name`, while the client is
represented by a separate source/workstation field. Do not assume the server's
hostname is the origin of the access.

---

## 11. Persistence hunting

**Purpose:** Identify mechanisms that make malicious code execute again after
logon, reboot or on a schedule.

### Run / RunOnce registry keys

Sysmon Event ID 13 — registry value set:

```kql
event.code : "13" and
registry.path : (
  "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" or
  "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"
)
```

Windows `Load` value:

```kql
registry.path : "*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load*"
```

### Scheduled tasks

Security Event ID 4698 — scheduled task created:

```kql
event.code : "4698"
```

Task Scheduler operational log events (inspect task event IDs and provider):

```kql
winlog.channel : "Microsoft-Windows-TaskScheduler/Operational"
```

Process execution through schtasks:

```kql
process.name : "schtasks.exe"
```

### Services

Security 4697 / System 7045:

```kql
event.code : ("4697" or "7045")
```

Service control utility:

```kql
process.name : "sc.exe" and process.command_line : "*create*"
```

### Startup folder

```kql
file.path : "*\\Start Menu\\Programs\\Startup\\*"
```

### WMI persistence

Sysmon WMI events:
- 19 — WMI event filter
- 20 — WMI event consumer
- 21 — consumer-to-filter binding

```kql
event.code : ("19" or "20" or "21") and
winlog.provider_name : "Microsoft-Windows-Sysmon"
```

**Important event ID distinction**
- Sysmon 12/13/14 are registry events.
- Sysmon 15 is FileCreateStreamHash, not service installation.
- Sysmon 22 is DNS query.
- Sysmon 23/26 are file deletion telemetry.
- Sysmon 25 is process tampering.
- Service installation is commonly Security 4697 or System 7045.

**Investigate next**
- Registry key/value and data
- Task name, task action and run-as account
- Service name, image path and service account
- WMI filter, consumer and binding
- Creator process, user and timestamp

---

## 12. Privilege escalation and lateral movement

**Purpose:** Find privilege changes, credential misuse and movement between hosts.

Special privileges assigned:

```kql
event.code : "4672"
```

Explicit credentials:

```kql
event.code : "4648"
```

Remote interactive logons:

```kql
event.code : "4624" and winlog.event_data.LogonType : "10"
```

Network logons:

```kql
event.code : "4624" and winlog.event_data.LogonType : "3"
```

Remote service creation:

```kql
event.code : ("4697" or "7045")
```

PsExec-like execution:

```kql
process.name : ("psexec.exe" or "psexec64.exe" or "paexec.exe")
```

Remote management utilities:

```kql
process.name : ("wmic.exe" or "winrs.exe" or "mstsc.exe" or "sc.exe")
```

SSH activity (where Linux/SSH telemetry exists):

```kql
event.category : authentication and process.name : "sshd"
```

**Investigate next**
- Source host/IP → destination host
- Account and logon type
- New service or remote process
- Parent process and command line
- Authentication events before and after execution
- Same account appearing on multiple hosts in a short time

No single event proves lateral movement. Correlate authentication, process and
network evidence across both source and destination systems.

---

## 13. User and host activity reconstruction

**Purpose:** Reconstruct activity for a specific user or endpoint across multiple
event categories.

All events for a user:

```kql
user.name : "j.smith"
```

All events for a host:

```kql
host.name : "WORKSTATION01"
```

User activity on a particular host:

```kql
user.name : "j.smith" and host.name : "WORKSTATION01"
```

Process, authentication and network events for a user:

```kql
user.name : "j.smith" and
(event.category : process or event.category : authentication or event.category : network)
```

Suspicious PowerShell activity for that user:

```kql
user.name : "j.smith" and
(process.name : ("powershell.exe" or "pwsh.exe") or event.code : "4104")
```

**How to use the results**
1. Filter by user and host.
2. Sort by `@timestamp` ascending to build the sequence.
3. Open important events and inspect the full JSON.
4. Pivot on `process.entity_id`, PID, parent process, source IP and destination IP.
5. Repeat on any newly discovered host or account.

KQL filters records; it does not perform a cross-index join or produce a
chronological narrative automatically. Use Timeline, Discover sorting, and
available correlation fields to assemble the story.

---

## 14. Build the incident timeline

**Purpose:** Turn individual findings into a defensible sequence of attacker
actions.

Use the strongest known pivot first:

```kql
host.name : "WORKSTATION01"
```

Then narrow by user:

```kql
host.name : "WORKSTATION01" and user.name : "j.smith"
```

Then inspect suspicious process activity:

```kql
host.name : "WORKSTATION01" and event.category : process
```

Then inspect network activity:

```kql
host.name : "WORKSTATION01" and event.category : network
```

Then inspect file activity:

```kql
host.name : "WORKSTATION01" and event.category : file
```

**Record each key event**
- UTC timestamp and original timezone
- Hostname and user/account
- Event provider, channel and event code
- Process, parent process and command line
- Source/destination IP, port, domain and URL
- File path, hash and action
- Evidence source and the exact KQL filter used

Normalize timestamps before answering questions that request an exact UTC time.
Use process entity IDs, PIDs, logon IDs and host/user/time pivots where available.

---

## 15. Field and KQL validation notes

### KQL syntax reminders

Exact match:

```kql
user.name : "j.smith"
```

Multiple values:

```kql
event.code : ("4624" or "4625")
```

Wildcard:

```kql
process.command_line : "*EncodedCommand*"
```

Exists:

```kql
process.command_line : *
```

Boolean logic:

```kql
host.name : "WORKSTATION01" and event.category : process
```

Negation:

```kql
not user.name : "SYSTEM"
```

Group conditions:

```kql
host.name : "WORKSTATION01" and
(event.code : "4624" or event.code : "4625")
```

### Common ECS fields

| Purpose | Common ECS field |
|---|---|
| Timestamp | `@timestamp` |
| Host | `host.name` |
| Username | `user.name` |
| Domain | `user.domain` |
| Event category | `event.category` |
| Event action | `event.action` |
| Event code | `event.code` |
| Process name | `process.name` |
| Process path | `process.executable` |
| Command line | `process.command_line` |
| Parent process | `process.parent.name` |
| Process ID | `process.pid` |
| Process entity ID | `process.entity_id` |
| File path | `file.path` |
| File hash | `file.hash.sha256` |
| Source IP | `source.ip` |
| Destination IP | `destination.ip` |
| Destination port | `destination.port` |
| DNS query | `dns.question.name` |
| URL | `url.full` |

### Common mistakes

- **Wrong field name:** inspect a raw event. A Windows field may be under
  `winlog.event_data.*`, while an ECS-normalized field may also exist.
- **Wrong event-code type:** `event.code` is commonly a keyword/string. Quote
  event IDs, for example `"4624"`.
- **Wildcard assumptions:** use `*` as the wildcard. KQL does not support
  regular expressions.
- **Case sensitivity:** keyword matching is generally case-insensitive in
  standard Kibana KQL, but behavior depends on field mapping/normalization.
- **Missing data:** a query only finds events that were collected and indexed.
  Check the data view, time picker, ingest pipeline and audit configuration.
- **No SPL commands:** KQL cannot use `stats`, `eval`, `rex`, `table`, `dedup`
  or `sort`. Use Kibana UI features or another query language/tool for those tasks.
- **Field not searchable:** inspect the mapping and raw document; the field may
  be analyzed, nested, renamed or not indexed for search.

---

## 16. Condensed CTF workflow

Use this as the default CTF sequence. Follow challenge clues when they point to a
specific host, user, IP, file or time range.

1. **Read the challenge brief.** Extract usernames, hostnames, IPs, domains,
   filenames, time range, suspicious tools and exact questions.
2. **Validate the data.** Select the correct data view, set the time range,
   inspect raw events and identify the actual field names.
3. **Establish identity.** Search 4624/4625, logon type, source IP, workstation
   and authentication package. Keep service and machine accounts in scope.
4. **Find execution.** Search Sysmon 1 / 4688. Record process, parent, command
   line, user, host, PID and entity ID.
5. **Inspect scripts.** Search 4104 and script text for download, decode,
   in-memory execution and suspicious commands.
6. **Decode commands.** Recover encoded arguments and identify payload names,
   paths, URLs and execution methods.
7. **Trace network activity.** Pivot to DNS, proxy, firewall and endpoint
   network events. Record source, destination, port, action and time.
8. **Trace files and collection.** Search file creation/deletion, hashes,
   archive utilities, share access and sensitive document paths.
9. **Check persistence.** Review Run keys, scheduled tasks, services, Startup
   folders and WMI.
10. **Investigate privilege escalation and lateral movement.** Pivot through
    privileged logons, explicit credentials, remote logons, service creation
    and newly accessed hosts.
11. **Reconstruct and timeline.** Sort by timestamp and correlate host, user,
    process entity ID, IP, URL, file path and hash.
12. **Answer with evidence.** Keep the exact event, timestamp, host, account,
    field/value and KQL filter for every answer. Separate confirmed evidence
    from assumptions.

### CTF evidence worksheet

| Question | Evidence to capture |
|---|---|
| Initial access | User, source IP, target host, logon type, timestamp |
| Initial execution | Process, parent, command line, user, timestamp |
| Script / payload | Script block, decoded command, URL, file path, hash |
| C2 | Domain/IP, port, protocol, process, first/last seen |
| Persistence | Registry/task/service/WMI artifact, creator, run-as account |
| Lateral movement | Source host, destination host, account, remote logon/process |
| Collection | Share/path, accessed files, account, archive/staging path |
| Exfiltration | Destination, protocol/port, bytes or transfer evidence, timestamp |

**Remember:** KQL is a filtering language, not a complete investigation pipeline.
Use it to narrow the evidence, then use Discover, Timeline, event details and
correlation pivots to reconstruct what happened.
