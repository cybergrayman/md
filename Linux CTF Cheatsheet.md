# LINUX CTF CHEATSHEET

**Quick command reference · Q1--Q6**

## FILE SEARCH & CONTENT

  -------------------------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- -------------------------------------------------
  Search recursively for a word       `grep -rn "word" folder/`

  Search "Snacks" in contents.txt     `grep -rin "Snacks" . --include="contents.txt"`
  files recursively                   

  Find a file by name                 `find . -name "filename"`

  Display a file                      `cat filename`

  Search printable strings for a      `strings home.jpg \| grep Henchman`
  keyword                       
  
  -------------------------------------------------------------------------------------

## FILE & DIRECTORY OPERATIONS

  --------------------------------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- --------------------------------------------------------
  Change directory                    `cd foldername`

  Move up one directory               `cd ..`

  Delete a file                       `rm filename.txt`

  Create an empty file                `touch filename.txt`

  Copy a file to a directory          `cp /var/backups/encoded.hex /home/assistant/toolbox/`

  Compare two files                   `diff file1.txt file2.txt`
  
  --------------------------------------------------------------------------------------------

## ENCODING & EXECUTABLES

  -----------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- -----------------------------------
  Decode Base64                       `base64 -d filename`

  Locate an executable                `which base64`

  Display the current PATH            `echo $PATH`

  Locate ExifTool                     `which exiftool`

  Show ExifTool version               `exiftool -ver`

  Print the default ExifTool          `cat "$(which exiftool)"`
  script/source                       

  Run ExifTool directly (challenge    `/usr/bin/exiftool home.jpg`
  path; verify it exists)             
  
  -----------------------------------------------------------------------

## NETWORK & SERVICES

  -----------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- -----------------------------------
  Show listening TCP ports /          `netstat -ant`
  connections                         

  Show network interfaces             `netstat -ani`

  Access local web service on port    `curl localhost:8080`
  8080                                

  List files exposed by local web     `curl localhost:8080/files/`
  service                             

  Connect to local service on port    `curl localhost:9000`
  9000                                

  Allow curl to accept HTTP/0.9       `curl --http0.9 localhost:9000`
  response                            
  
  -----------------------------------------------------------------------

## PROCESS INVESTIGATION

  TASK             COMMAND
  ---------------- -----------
  List processes   `ps -aux`

## DOWNLOAD & ARCHIVE

  --------------------------------------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- --------------------------------------------------------------
  Download an archive from local web  `curl localhost:8080/files/archive.tar.gz -o archive.tar.gz`
  service                             

  Extract a gzip-compressed tar       `tar -xvzf archive.tar.gz`
  archive                 
  
  --------------------------------------------------------------------------------------------------

## NETCAT & SHELL SCRIPTS

  -----------------------------------------------------------------------
  TASK                                COMMAND
  ----------------------------------- -----------------------------------
  Receive service output and save as  `nc localhost 9000 > magic.sh`
  a file                              

  Make a script executable            `chmod +x magic.sh`

  Check file permissions              `ls -l magic.sh`

  Run a script in the current         `./magic.sh`
  directory                           

  Disconnect / stop a running command `Ctrl + C`
  
  -----------------------------------------------------------------------

------------------------------------------------------------------------

`<sub>`{=html}Linux CTF command reference. Verify file paths and service
details against the target environment.`</sub>`{=html}
