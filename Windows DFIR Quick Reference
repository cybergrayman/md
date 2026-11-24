# Windows Forensic Analysis — DFIR Quick Reference

> **Purpose:** Reference for Windows endpoint investigations, SOC triage, DFIR exercises and CTFs.  

---

## Table of Contents

- [1. Investigation workflow](#1-investigation-workflow)
- [2. Windows time and timeline rules](#2-windows-time-and-timeline-rules)
- [3. Program execution artifacts](#3-program-execution-artifacts)
- [4. System identification and persistence](#4-system-identification-and-persistence)
- [5. File and folder access](#5-file-and-folder-access)
- [6. Deleted-file evidence](#6-deleted-file-evidence)
- [7. User accounts and logons](#7-user-accounts-and-logons)
- [8. Network and location artifacts](#8-network-and-location-artifacts)
- [9. USB and removable-device activity](#9-usb-and-removable-device-activity)
- [10. Browser activity](#10-browser-activity)
- [11. Windows event log quick reference](#11-windows-event-log-quick-reference)
- [12. Evidence correlation checklist](#12-evidence-correlation-checklist)
- [13. Common interpretation cautions](#13-common-interpretation-cautions)
- [14. Key artifact path index](#14-key-artifact-path-index)
- [15. Source and version notes](#15-source-and-version-notes)

---

## 1. Investigation workflow

Use the following sequence to keep an investigation evidence-led.

1. **Establish the system:** hostname, OS version/build, time zone, user profiles and system boot/shutdown context.
2. **Define the incident window:** record the suspected start/end time and convert all timestamps to a common time standard.
3. **Identify the user:** correlate account/SID information, logons, RDP activity and profile artifacts.
4. **Establish execution:** review Prefetch, UserAssist, Amcache, Shimcache, BAM/DAM, SRUM and event logs.
5. **Establish user intent/activity:** inspect LNK files, Jump Lists, RecentDocs, Open/Save MRU, ShellBags and browser artifacts.
6. **Check persistence:** inspect Run keys, services and other autostart locations.
7. **Check external movement:** correlate USB history, network profiles, WLAN logs, browser downloads and file access.
8. **Build a timeline:** normalize timestamps, correlate independent artifacts and identify gaps.
9. **Document findings:** record source artifact, path, timestamp and time zone, user, host, interpretation, confidence and supporting evidence.

### First-pass questions

| Question | Start with |
|---|---|
| What program ran? | Prefetch, UserAssist, BAM/DAM, Amcache, Shimcache, event logs |
| What file was opened? | LNK, Jump Lists, RecentDocs, Open/Save MRU, Office MRU |
| Which folders were browsed? | ShellBags, TypedPaths, RecentDocs |
| Which account was used? | SAM, Security EVTX, profile hives |
| Was RDP used? | Security events 4778/4779; logon event 4624 type 10 |
| Was a USB device connected? | USBSTOR, setupapi.dev.log, MountedDevices, PnP events |
| Which networks were known? | NetworkList registry keys, WLAN AutoConfig log |
| Which websites were visited? | Browser history, cookies, cache, session restore |

---

## 2. Windows time and timeline rules

### Timestamp sources

| Source | What it represents | Important caution |
|---|---|---|
| `$STANDARD_INFORMATION` (NTFS MFT) | File metadata timestamps | Can be changed by file operations and timestomping |
| `$FILE_NAME` (NTFS MFT) | Filename attribute timestamps | May differ from `$STANDARD_INFORMATION` |
| LNK timestamps | Shortcut and target metadata | Shortcut creation/modification is not always the exact file-open time |
| Registry key LastWrite | Last write to a registry key | Not a timestamp for every value inside the key |
| EVTX event timestamp | Event time recorded by Windows | Check host time zone, clock drift and event XML fields |
| Prefetch timestamps | Prefetch file creation/modification and embedded run history | Interpret according to OS version and artifact behavior |

### NTFS timestamp interpretation

The reference material distinguishes `$STANDARD_INFORMATION` from `$FILE_NAME`. Their timestamps can behave differently during creation, modification, rename, copy, move and deletion.

| Operation | `$STANDARD_INFORMATION` | `$FILE_NAME` |
|---|---|---|
| Create | Creation-related timestamps reflect file creation | Reflects file creation |
| Modify data | Modified/access/metadata behavior can reflect the data change | Generally does not reflect ordinary data modification |
| Rename | Metadata-change time can change | Filename attribute timestamps can change |
| Copy | New-file timestamps can reflect copy time; some values may be inherited | Timestamps commonly reflect copy operation |
| Move within same volume | Often retains original file timestamps | Usually retains original values |
| Move across volumes | Behavior differs between CLI move and Explorer cut/paste | May reflect move/copy operation |
| Delete | Deletion itself does not guarantee a useful timestamp update | Deletion itself does not guarantee a useful timestamp update |

**Do not rely on a single timestamp.** Compare MFT attributes, USN Journal (if available), event logs, LNK/Jump Lists, Prefetch and application records. The poster's detailed timestamp chart was based on Windows 10 version 1903 testing; validate behavior on the examined OS.

### Time-zone checks

- Registry: `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
- Record the system time zone and whether daylight-saving changes apply.
- Distinguish UTC from local time in every timeline entry.
- Check for clock drift and time changes before correlating endpoint events with network/security logs.

---

## 3. Program execution artifacts

| Artifact | Location | What it can show | Interpretation |
|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\` | Executable name, run history, referenced files/directories and device handles | Strong execution evidence when valid; availability depends on configuration and OS |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | GUI-launched programs, run count, last run and focus data | ROT-13 encoded values; primarily GUI execution |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program/driver presence, paths, metadata and SHA-1 values | Presence is not proof of execution |
| Shimcache / AppCompatCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Executable paths and file metadata | Presence alone does not prove execution; post-XP versions do not provide a reliable execution time |
| BAM/DAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` and `...\dam\State\UserSettings\<SID>` | Executable path and last execution time | Windows 10+; retention/availability varies |
| SRUM | `C:\Windows\System32\SRU\SRUDB.dat` | Application resource use, user association and network usage | ESE database; useful for application/network correlation |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Files/items opened through applications; AppID association | Automatic Jump Lists can contain embedded LNK data |
| Taskbar Feature Usage | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` | Taskbar interaction counters | GUI-focused; not a direct execution timestamp |

### Practical execution interpretation

- **Prefetch:** identify the executable, inspect run count and embedded last-run timestamps, then inspect referenced files and directories.
- **UserAssist:** decode ROT-13 names and correlate run/focus counters with other execution evidence.
- **Amcache:** use hashes and file metadata to identify suspicious binaries; do not claim execution from Amcache alone.
- **Shimcache:** treat as compatibility-cache evidence of file presence, not standalone proof of execution.
- **BAM/DAM:** correlate SID to the user and compare last-run time with other artifacts.
- **SRUM:** investigate application/network usage around the incident window and correlate application identity, user and traffic volume.
- **Jump Lists:** identify the application AppID and the files/documents represented in the Jump List.

### Useful execution pivots

- Suspicious executable path in a user-writable directory.
- Unusual binary in `Temp`, `Downloads`, `AppData`, `ProgramData` or a public profile.
- Execution close to a suspicious logon, archive extraction, script launch or outbound connection.
- Binary hash or signer inconsistent with the claimed application.
- Execution evidence on multiple artifacts with compatible timestamps.

---

## 4. System identification and persistence

### System identification

| Item | Registry location | Values / use |
|---|---|---|
| OS version/build | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | ProductName, EditionID, DisplayVersion, CurrentBuildNumber, InstallTime |
| Previous OS build history | `SYSTEM\Setup\Source OS` | Historical build/update information |
| Computer name | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | Hostname for log correlation |
| Time zone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Time-zone configuration |
| Last shutdown | `SYSTEM\CurrentControlSet\Control\Windows` | Shutdown Time value |

### Common autostart locations

| Mechanism | Registry / location |
|---|---|
| Current-user Run | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` |
| Current-user RunOnce | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| Machine Run | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Machine RunOnce | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` |
| Explorer policy Run | `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` |
| Services | `SYSTEM\CurrentControlSet\Services` |

For services, inspect the service name, `ImagePath`, account, start type, creation/install time and related System/Security events. A service `Start` value of `0x02` indicates automatic start in the referenced poster.

**Do not stop at these locations.** This is a starter list, not a complete persistence inventory. Also review scheduled tasks, WMI subscriptions, startup folders, drivers, logon scripts and other mechanisms when the investigation scope requires them.

---

## 5. File and folder access

| Artifact | Location | What it can reveal |
|---|---|---|
| RecentDocs | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently accessed files/folders and MRU ordering |
| OpenSave MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` | Files selected in common Open/Save dialogs |
| LastVisited MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Application used and last directory accessed through dialog |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Recent/frequent items associated with applications |
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\` | Target path, volume, network share and target metadata |
| Office Recent | `NTUSER.DAT\Software\Microsoft\Office\<version>\UserMRU\...` | Recent documents opened by Office applications |
| ShellBags | `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags` and `BagMRU` | Folders browsed, including some network/removable locations |
| TypedPaths | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Paths manually entered into Explorer address bar |
| WordWheelQuery | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | File Explorer search terms |

### LNK files — high-value fields

Inspect:
- Target path and filename.
- Target file creation, modification and access timestamps, where available.
- Volume name, type and serial number.
- Network share/UNC path details.
- Machine name and original location.
- Shortcut creation and modification timestamps.

LNK files can remain after the original target is deleted or moved. A shortcut is evidence of a reference to a target; validate whether the target existed and when it was accessed.

### Jump Lists

- `AutomaticDestinations`: application-specific Jump List data.
- AppID maps the Jump List to an application.
- Entries can contain LNK-like metadata about accessed files.
- Correlate with LNK, RecentDocs, Prefetch and application execution evidence.

### ShellBags

Use ShellBags to identify directories browsed through Explorer, including folders on local disks, network shares and removable media. Correlate with USB/network evidence before attributing access to a specific device or share.

---

## 6. Deleted-file evidence

| Artifact | Location | What it can show |
|---|---|---|
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` | `$I` metadata and `$R` content for recycled files |
| Thumbcache | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\` | Thumbnail images of previously viewed content |
| Thumbs.db | Folder-specific `Thumbs.db` files | Thumbnail and, on some older systems, filename metadata |
| Windows Search | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | Indexed file metadata and sometimes partial content |
| Windows Search GatherLogs | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex` | Candidate/indexing activity |

### Recycle Bin

- `$I*` files: metadata such as original path/name and deletion time.
- `$R*` files: corresponding recycled file content.
- Map the SID directory to the relevant user account.
- Recycle Bin coverage depends on deletion method and application behavior; permanent deletion may bypass it.

### Thumbnail artifacts

- Thumbcache databases are user-specific and stored under the Explorer profile directory.
- Thumbnail data may preserve evidence of images/documents even when the original file is no longer present.
- Cross-reference cache IDs and Windows Search metadata where possible.

---

## 7. User accounts and logons

### Local account artifacts

| Artifact | Location | Use |
|---|---|---|
| SAM | `C:\Windows\System32\config\SAM` | Local account records and account metadata |
| User profile hives | `C:\Users\<user>\NTUSER.DAT` | Per-user activity and configuration |
| USRCLASS | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shell and Explorer activity |

The accessible poster identifies SAM as a source for local account/SID mapping and last-login/password-change information. Correlate with Security logs; do not rely on SAM alone for a full authentication timeline.

### Important Security event IDs

| Event ID | Meaning | Investigative use |
|---:|---|---|
| 4624 | Successful logon | Identify account, logon type, source and session |
| 4625 | Failed logon | Password guessing, invalid account or failed access |
| 4634 | Logoff | Session termination |
| 4647 | User-initiated logoff | User logoff activity |
| 4648 | Logon using explicit credentials | RunAs or explicit credential use |
| 4672 | Special privileges assigned to new logon | Privileged account/session |
| 4720 | User account created | Account creation |
| 4768 | Kerberos TGT requested | Kerberos authentication |
| 4769 | Kerberos service ticket requested | Service/resource access |
| 4771 | Kerberos pre-authentication failed | Failed Kerberos authentication |
| 4776 | NTLM credential validation | NTLM success/failure |
| 4778 | RDP session connected/reconnected | Remote session activity |
| 4779 | RDP session disconnected | Remote session disconnect |

### Logon types

| Type | Meaning |
|---:|---|
| 2 | Interactive / console |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |
| 12 | CachedRemoteInteractive |
| 13 | CachedUnlock |

**Where to look:** Security events are generally in `C:\Windows\System32\winevt\Logs\Security.evtx`. Domain authentication events may be recorded on domain controllers; local/workgroup authentication is recorded on the relevant workstation/server.

### RDP investigation

Correlate:
- 4624 with Logon Type 10.
- 4778 and 4779 session events.
- Source IP/hostname fields.
- Account name and SID.
- Target host, session time and subsequent process activity.

---

## 8. Network and location artifacts

| Artifact | Location | What it can show |
|---|---|---|
| NetworkList signatures | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` and `Unmanaged` | Known wired/wireless networks and profile details |
| NetworkList NLA cache | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache` | Network identification/cache information |
| WLAN AutoConfig log | `Microsoft-Windows-WLAN-AutoConfig/Operational.evtx` | Wireless connection attempts and outcomes |
| SRUM | `C:\Windows\System32\SRU\SRUDB.dat` | Per-application network/resource usage |
| Time-zone registry | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Local-time interpretation |

### WLAN event IDs

| Event ID | Meaning |
|---:|---|
| 11000 | Wireless association started |
| 8001 | Successful connection |
| 8002 | Failed connection |
| 8003 | Disconnection |
| 6100 | Network diagnostics (System log) |

Use SSID/BSSID and network profile information as leads. Geolocation based on wireless identifiers requires external reference data and should not be treated as definitive without validation.

### SRUM

Database: `C:\Windows\System32\SRU\SRUDB.dat`

Important table identifiers referenced in the poster:

| Identifier | Description |
|---|---|
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | Network Data Usage |
| `{d10ca2fe-6fcf-4f6d-848e-b2e99266af89}` | Application Resource Usage |
| `{DD6636C4-8929-4683-974E-22C046A43763}` | Network Connectivity Usage |

SRUM can help connect an application/user to network usage and bytes sent/received. Retention and available records vary. Correlate with firewall, proxy, DNS, EDR and network telemetry.

---

## 9. USB and removable-device activity

| Question | Artifact / location |
|---|---|
| What USB device was connected? | `SYSTEM\CurrentControlSet\Enum\USBSTOR` and `...\Enum\USB` |
| What is its serial number? | USBSTOR device instance path |
| When was it installed? | `C:\Windows\inf\setupapi.dev.log` |
| When was it last connected/removed? | USBSTOR device `Properties` key |
| Which user used it? | `SYSTEM\MountedDevices`, user `NTUSER.DAT\...\MountPoints2` |
| Which drive letter was assigned? | `SYSTEM\MountedDevices` |
| What files may have been accessed? | LNK, RecentDocs, Jump Lists, ShellBags |

### USB timestamp properties

Within the device property key referenced by the poster:

`SYSTEM\CurrentControlSet\Enum\USBSTOR\<device>\<serial>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\`

| Property | Meaning |
|---|---|
| `0064` | First install (Windows 7–10 in the poster) |
| `0066` | Last connected (Windows 8–10 in the poster) |
| `0067` | Last removal (Windows 8–10 in the poster) |

### SetupAPI and PnP

- Windows 7+: `C:\Windows\inf\setupapi.dev.log`
- System log event 20001: Plug and Play driver installation attempt.
- Event details may include timestamp, device information, serial number and status.
- SetupAPI log timestamps are local time according to the poster.

### USB investigation sequence

1. Extract vendor/product/version and serial from USBSTOR.
2. Identify first-install, last-connected and last-removal values where present.
3. Correlate serial number with SetupAPI and PnP event records.
4. Map volume/device identifiers to drive letter and volume name.
5. Identify user association through MountedDevices and MountPoints2.
6. Search LNK, RecentDocs, Jump Lists and ShellBags for files/folders accessed around connection time.
7. Correlate possible file staging with archive creation, copy tools and outbound transfer evidence.

**Caution:** `MountedDevices` generally reflects current/last mappings, not a complete historical record of every drive-letter assignment.

---

## 10. Browser activity

### Browser artifacts

| Browser/artifact | Common location from the accessible poster |
|---|---|
| Internet Explorer history | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat` |
| Firefox history | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` |
| Chrome history | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` |
| Firefox cookies | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite` |
| Chrome cache | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache` |
| Firefox cache | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<profile>\Cache` |
| Chrome session data | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\` |
| IE/Edge legacy cache | `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` |

Browser profile paths and database names change across versions. Check all user profiles and browser channels, not only `Default`.

### What to examine

- History: URL, visit time, visit count and search terms.
- Downloads: source URL, target path, start/end time and file metadata.
- Cookies: domain and session-related evidence.
- Cache: locally stored page components and downloaded/viewed resources.
- Session restore: previously open tabs, referring sites and session end context.
- Local file URLs: `file:///` entries can show local or network file references; they do not prove the file was opened inside a browser.

### Browser investigation pivots

1. Identify the relevant user profile.
2. Determine browser/version and profile location.
3. Extract history and downloads for the incident window.
4. Search for suspicious domains, IPs, file-sharing sites and webmail.
5. Correlate downloaded filenames/hashes with file-system and execution artifacts.
6. Check session/cookie/cache evidence for context.
7. Correlate browser activity with DNS, proxy, firewall and endpoint telemetry.

---

## 11. Windows event log quick reference

| Log | Event ID | Meaning / pivot |
|---|---:|---|
| Security | 4624 | Successful logon |
| Security | 4625 | Failed logon |
| Security | 4648 | Explicit credentials |
| Security | 4672 | Special privileges |
| Security | 4697 | Service installed (Security auditing) |
| Security | 4720 | User account created |
| Security | 4768 | Kerberos TGT request |
| Security | 4769 | Kerberos service ticket |
| Security | 4771 | Kerberos pre-authentication failure |
| Security | 4776 | NTLM credential validation |
| Security | 4778 / 4779 | RDP session connect/disconnect |
| System | 7034 | Service terminated unexpectedly |
| System | 7035 | Service control sent |
| System | 7036 | Service started/stopped |
| System | 7040 | Service start type changed |
| System | 7045 | Service installed |
| System | 20001 | Plug and Play driver install attempt |
| WLAN AutoConfig/Operational | 8001 | Wireless connection successful |
| WLAN AutoConfig/Operational | 8002 | Wireless connection failed |
| WLAN AutoConfig/Operational | 8003 | Wireless disconnect |
| WLAN AutoConfig/Operational | 11000 | Wireless association started |

### Event log locations

- Security: `%SystemRoot%\System32\winevt\Logs\Security.evtx`
- System: `%SystemRoot%\System32\winevt\Logs\System.evtx`
- WLAN: `Microsoft-Windows-WLAN-AutoConfig/Operational.evtx`

Use the event's XML details, not only the rendered summary. Capture the computer, provider, channel, event ID, record ID, UTC/local timestamp, user/SID, source address and relevant process/service/device fields.

---

## 12. Evidence correlation checklist

### Execution
- [ ] Identify suspicious process name, full path and hash.
- [ ] Check Prefetch and embedded run history.
- [ ] Check UserAssist and decode ROT-13 values.
- [ ] Check Amcache and Shimcache, treating them as presence/compatibility evidence.
- [ ] Check BAM/DAM and map SID to user.
- [ ] Check SRUM for application/network usage.
- [ ] Correlate with Security, System, Sysmon and EDR telemetry.

### User/file activity
- [ ] Identify the logged-on user and profile.
- [ ] Review LNK files and target metadata.
- [ ] Review Jump Lists and AppIDs.
- [ ] Review RecentDocs and Open/Save MRU.
- [ ] Review ShellBags, TypedPaths and WordWheelQuery.
- [ ] Review Office MRU and browser download records.

### Persistence
- [ ] Review Run/RunOnce keys.
- [ ] Review services and service install/start events.
- [ ] Review scheduled tasks, WMI and startup folders as in-scope.
- [ ] Compare suspicious persistence creation time with first execution and logon.

### Network/exfiltration
- [ ] Review NetworkList and WLAN history.
- [ ] Review SRUM network usage.
- [ ] Review browser history/downloads/cache.
- [ ] Correlate DNS, proxy, firewall, VPN and EDR events.
- [ ] Identify unusual destinations, transfer tools and staging archives.

### USB/data movement
- [ ] Identify USB device serial and vendor/product.
- [ ] Establish first install, last connect and removal times where available.
- [ ] Map the device to a user and drive letter.
- [ ] Review LNK, RecentDocs, Jump Lists and ShellBags around the connection time.
- [ ] Look for archive creation, copy utilities and subsequent outbound traffic.

### Timeline/evidence handling
- [ ] Normalize timestamps and document time zone.
- [ ] Record artifact path and collection source.
- [ ] Preserve original evidence and work from forensic copies.
- [ ] Hash collected files where appropriate.
- [ ] Separate observed facts from interpretation and hypothesis.
- [ ] Record limitations, missing logs and retention gaps.

---

## 13. Common interpretation cautions

1. **Artifact presence is not always proof of execution.** Amcache and Shimcache require corroboration.
2. **A registry key LastWrite time is not a timestamp for every value.**
3. **Prefetch may be disabled, absent or limited by OS/configuration.**
4. **LNK and Jump List records show references/activity, but should be corroborated with target existence and other artifacts.**
5. **Browser `file:///` history entries do not prove a file was opened in the browser.**
6. **A USB device's last drive-letter mapping is not a complete history of every mapping.**
7. **Timestamp behavior differs by NTFS attribute and file operation.**
8. **Legacy poster paths may not match current Windows 11 or current browser versions.**
9. **Event logs may be cleared, rolled over, disabled or incomplete.**
10. **Absence of an artifact is not proof that an action did not occur.**

---

## 14. Key artifact path index

| Artifact | Path |
|---|---|
| Prefetch | `C:\Windows\Prefetch\` |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| SRUM | `C:\Windows\System32\SRU\SRUDB.dat` |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` |
| Thumbcache | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\` |
| Windows Search DB | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` |
| Recent LNK | `%APPDATA%\Microsoft\Windows\Recent\` |
| Automatic Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` |
| Custom Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\` |
| NTUSER hive | `C:\Users\<user>\NTUSER.DAT` |
| USRCLASS hive | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| SAM hive | `C:\Windows\System32\config\SAM` |
| SYSTEM hive | `C:\Windows\System32\config\SYSTEM` |
| SOFTWARE hive | `C:\Windows\System32\config\SOFTWARE` |
| Security EVTX | `%SystemRoot%\System32\winevt\Logs\Security.evtx` |
| System EVTX | `%SystemRoot%\System32\winevt\Logs\System.evtx` |
| SetupAPI log | `C:\Windows\inf\setupapi.dev.log` |
| Chrome History | `%LOCALAPPDATA%\Google\Chrome\User Data\<profile>\History` |
| Firefox places | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` |
| IE/legacy Edge WebCache | `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV*.dat` |

---

## 15. Reference and version notes

### Reference basis

- Core artifact descriptions and reference paths are based on a publicly accessible Windows Forensic Analysis reference, edition `DFPS_FOR500_v4.13_10-22` (2022).
- This document is an independently organized quick reference for offline DFIR and CTF use; it is not a verbatim reproduction of the source material.
- The workflow, evidence-correlation checklist and interpretation cautions are practical organization added for investigation use.

### Validation before use

Validate artifact paths and behavior against the actual Windows version/build, browser version, logging configuration and forensic acquisition. Treat this document as a quick-reference starting point, not a substitute for validating evidence in the acquired image.
