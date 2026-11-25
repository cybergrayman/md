# LINUX CTF CHEATSHEET

## Contents
1. [File Search & Content](#file-search--content)
2. [File & Directory Operations](#file--directory-operations)
3. [Encoding, Crypto & Executables](#encoding-crypto--executables)
4. [Network & Services](#network--services)
5. [Process & Privilege Investigation](#process--privilege-investigation)
6. [Download & Archive](#download--archive)
7. [Netcat & Shell Scripts](#netcat--shell-scripts)

---

## FILE SEARCH & CONTENT

| Task | Command |
| :--- | :--- |
| Search recursively for a word | `grep -rn "word" folder/` |
| Search "Snacks" in `contents.txt` recursively | `grep -rin "Snacks" . --include="contents.txt"` |
| Find a file by name | `find . -name "filename"` |
| Find files owned by a specific user | `find / -user username 2>/dev/null` |
| Find files with SUID permissions (privesc) | `find / -perm -4000 2>/dev/null` |
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
| Show listening ports (modern `netstat` alt) | `ss -tulpn` |
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
| Check current user and group memberships | `id` |
| List commands current user can run via `sudo` | `sudo -l` |
| View scheduled cron jobs | `cat /etc/crontab` |
| View environment variables (look for secrets) | `env` |

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

<sub>Linux CTF command reference. Verify file paths and service details against the target environment.</sub>
