There are various tools and ways to enumerate. Try to use those tools that suit your environment and provide stealth.

### Local

```powershell

whoami /all

DNS Primary Suffix: small.domain.local

```

### BloodHound

```bash
bloodhound-python -u '' -p '' -d domain.local  -dc dc01.domain.local -ns 172.11.11.1   -c All  --dns-timeout 10 --dns-tcp
```

### Adalanche 

on target

```powershell
.\Adalanche.exe collect activedirectory --domain domain.local

(objectClass=trustedDomain)
```

locally

`adalanche analyze`
## Sharphoud

```
SharpHound.exe --CollectionMethod All,Trusts --Domain domain.local --SearchForest
```

### Windows Native: Get-ADTrust

Reference: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps

```powershell

# import within powershell if available
Import-Module activedirectory

Get-ADTrust -Filter *

```

### Powerview

https://powersploit.readthedocs.io/en/latest/Recon/?q=Trusts&check_keywords=yes&area=default#domain-trust-functions

```powershell
IWR -Uri "https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1" -OutFile PowerView.ps1

Set-ExecutionPolicy Bypass

. .\PowerView.ps1
```

```powershell
# lookup for specific domain
Get-DomainTrust -Domain terra.local

# general lookup
Get-DomainTrustMapping
```
