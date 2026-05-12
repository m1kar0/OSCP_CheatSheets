There are various tools and ways to enumerate. Try to use those tools that suit your environment and provide stealth.

### BloodHound

```bash
bloodhound-python -u '' -p '' -d domain.local  -dc dc01.domain.local -ns 172.11.11.1   -c All  --dns-timeout 10 --dns-tcp
```

## Sharphoud

```
SharpHound.exe --CollectionMethod All,Trusts --Domain domain.local --SearchForest
```

### Windows Local


```powershell

whoami /all

DNS Primary Suffix: small.domain.local

```


Reference: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps

```powershell

# import within powershell if available
Import-Module activedirectory

Get-ADDomain
Get-ADForest
Get-ADTrust -Filter *

```

### Powerview

https://powersploit.readthedocs.io/en/latest/Recon/?q=Trusts&check_keywords=yes&area=default#domain-trust-functions

But be aware that there is an old and new version of Powerview. Some older functions are not present in the newer version.

```powershell
IWR -Uri "https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1" -OutFile PowerView.ps1

Set-ExecutionPolicy Bypass -Scope Process -Froce

. .\PowerView.ps1
```

```powershell
# lookup for specific domain
Get-DomainTrust -Domain terra.local

# general lookup
Get-DomainTrustMapping
```
