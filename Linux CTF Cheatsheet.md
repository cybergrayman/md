# LINUX CTF CHEATSHEET

## Contents
1. [File Search & Content](#file-search--content)
2. [File & Directory Operations](#file--directory-operations)
3. [Encoding, Crypto & Executables](#encoding-crypto--executables)
4. [Network & Services](#network--services)
5. [Process & Privilege Investigation](#process--privilege-investigation)
6. [Users, Logs & Incident Response](#users-logs--incident-response)
7. [Download & Archive](#download--archive)
8. [Netcat & Shell Scripts](#netcat--shell-scripts)

---

## FILE SEARCH & CONTENT

| Task | Command |
| :--- | :--- |
| Search recursively for a word | `grep -rn "word" folder/` |
| Search "Snacks" in `contents.txt` recursively | `grep -rin "Snacks" . --include="contents.txt"` |
| Find a file by name | `find . -name "filename"` |
| Find files owned by a specific user | `find / -user username 2>/dev/null \| grep -v "^/proc\|^/sys"` |
| Find files with SUID permissions (privesc) | `find / -perm -4000 2>/dev/null` |
| List 30 most recently modified files on disk | `find / -xdev -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\n" 2>/dev/null \| sort \| tail -n 30` |
| Display a file | `cat filename` |
| View large file with pagination/search | `less filename` |
| Check true file type (magic bytes) | `file filename` |
| Search printable strings for a keyword | `strings home.jpg \| grep Henchman` |

## FILE & DIRECTORY OPERATIONS

| Task | Command |
| :--- | :--- |
| List all files including hidden ones | `ls -la` |
| Change directory | `cd foldername` |
| Move up one directory | `cd ..` |
| Delete a file | `rm filename.txt` |
| Create an empty file | `touch filename.txt` |
| Copy a file to a directory | `cp /var/backups/encoded.hex /home/assistant/toolbox/` |
| Compare two files | `diff file1.txt file2.txt` |

## ENCODING, CRYPTO & EXECUTABLES

| Task | Command |
| :--- | :--- |
| Decode Base64 from a file | `base64 -d filename` |
| Decode Base64 from a string | `echo "SGVsbG8=" \| base64 -d` |
| Convert hex dump back to binary/text | `xxd -r -p encoded.hex` |
| Decode ROT13 cipher | `tr 'A-Za-z' 'N-ZA-Mn-za-m' < filename` |
| Generate MD5 / SHA256 hash | `md5sum filename` / `sha256sum filename` |
| Locate an executable | `which base64` |
| Display the current PATH | `echo $PATH` |
| Locate ExifTool | `which exiftool` |
| Show ExifTool version | `exiftool -ver` |
| Print the default ExifTool script/source | `cat "$(which exiftool)"` |
| Run ExifTool directly (verify path exists) | `/usr/bin/exiftool home.jpg` |

## NETWORK & SERVICES

| Task | Command |
| :--- | :--- |
| Show listening TCP ports / connections | `netstat -ant` |
| Show TCP/UDP connections with owning PID | `sudo netstat -antp` or `sudo ss -tupn` |
| Show listening ports (modern `netstat` alt) | `ss -tulpn` |
| Catch short-lived/beaconing connections (`SYN_SENT`) | `while true; do sudo ss -tupn \| grep <PORT>; sleep 0.1; done` |
| Show network interfaces | `netstat -ani` |
| Access local web service on port 8080 | `curl localhost:8080` |
| View HTTP response headers | `curl -I localhost:8080` |
| List files exposed by local web service | `curl localhost:8080/files/` |
| Connect to local service on port 9000 | `curl localhost:9000` |
| Allow curl to accept HTTP/0.9 response | `curl --http0.9 localhost:9000` |

## PROCESS & PRIVILEGE INVESTIGATION

| Task | Command |
| :--- | :--- |
| List all running processes | `ps -aux` |
| List processes without truncating long usernames (`+`) | `ps -eo user:25,pid,ppid,cmd` |
| Catch short-lived spawning processes in real time | `while true; do ps -eo user:25,pid,cmd \| grep -E "nc\|socat\|bash\|python\|sh"; sleep 0.2; done` |
| Inspect open files & network sockets of a PID | `sudo ls -la /proc/<PID>/fd` |
| Inspect environment variables of a running PID | `sudo strings /proc/<PID>/environ` |
| Check current user and group memberships | `id` |
| List commands current user can run via `sudo` | `sudo -l` |
| View system & user scheduled cron jobs | `cat /etc/crontab` / `sudo ls -la /etc/cron* /var/spool/cron/crontabs/` |
| View cron jobs for a specific user | `sudo crontab -u <username> -l` |
| View environment variables (look for secrets) | `env` |

## USERS, LOGS & INCIDENT RESPONSE

| Task | Command |
| :--- | :--- |
| Enumerate all local user accounts & shells | `cat /etc/passwd` |
| Find hidden backdoor accounts with root UID (`0`) | `awk -F: '$3 == 0 {print $1}' /etc/passwd` |
| Check a specific user's saved bash history | `sudo cat /home/<username>/.bash_history` |
| Check if history files were wiped or symlinked | `sudo ls -la /home/<username>/.*history* /root/.*history* 2>/dev/null` |
| Trace user `su`, `sudo`, and SSH activity in logs | `sudo grep -i "<username>" /var/log/auth.log /var/log/syslog 2>/dev/null` |
| Search logs & files for a C2 IP or port | `sudo grep -rn "<IP_OR_PORT>" /etc/ /var/ /home/ /opt/ /tmp/ 2>/dev/null` |

## DOWNLOAD & ARCHIVE

| Task | Command |
| :--- | :--- |
| Download an archive from local web service | `curl localhost:8080/files/archive.tar.gz -o archive.tar.gz` |
| Download a file using `wget` | `wget http://localhost:8080/files/archive.tar.gz` |
| Extract a gzip-compressed tar archive | `tar -xvzf archive.tar.gz` |
| Extract a `.zip` archive | `unzip archive.zip` |

## NETCAT & SHELL SCRIPTS

| Task | Command |
| :--- | :--- |
| Connect interactively to a service | `nc localhost 9000` |
| Receive service output and save as a file | `nc localhost 9000 > magic.sh` |
| Start a local listener (reverse shells) | `nc -lvnp 4444` |
| Make a script executable | `chmod +x magic.sh` |
| Check file permissions | `ls -l magic.sh` |
| Run a script in the current directory | `./magic.sh` |
| Disconnect / stop a running command | `Ctrl + C` |

---

> **Quick CTF Investigation Notes:**
> * **Truncated usernames (`+`):** `ps -aux` truncates usernames over 8 characters (e.g., `shadow_+`). Always verify with `ps -eo user:25,pid,cmd` and `/etc/passwd`.
> * **Masqueraded binaries:** Watch for leading dots in system paths (e.g., `/bin/.bash`).
> * **Tilde (`~`) expansion:** `~` always resolves to *your* current user's home directory, not the folder you `cd`'d into.

<sub>Linux CTF command reference. Verify file paths and service details against the target environment.</sub>
