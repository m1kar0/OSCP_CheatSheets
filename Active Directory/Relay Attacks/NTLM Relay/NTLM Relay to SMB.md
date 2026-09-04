**NTLM relay to SMB** — SMB is the Windows file-sharing protocol. Whenever SMB signing (a per-message integrity check that binds the session to the original client) is not enforced on a server, you relay a victim's NTLM authentication to that server and it treats your connection as the victim. What you can actually do there depends entirely on that client's privileges.

Common scenarios:
- Relay a **Domain Admin** to a critical application server and **execute commands** as admin.
- Relay an **unprivileged user** to a file server and access files on their behalf.

**Note:** SMB signing is enforced on Domain Controllers by default - but *not* on a default Exchange member server, so an Exchange host can be a valid relay target.

## Discovery

List SMB servers and detect whether SMB signing is enforced:

```bash

cme smb 'SUBNET'

```

Generate a list of targets that do not enforce SMB signing:

```bash

cme smb 'SUBNET' --gen-relay-list './hosts/smb_nosigning.txt'

```

## Exploitation

Use `ntlmrelayx.py` in SOCKS mode:

```bash

ntlmrelayx.py -tf './hosts/smb_nosigning.txt' -socks -smb2support

```

**Warning:** In SOCKS mode, use IP addresses for targets, not short names or FQDNs - ntlmrelayx does not resolve them.

Once a session is established, run any Impacket script through proxychains. When prompted for a password, leave it blank and ntlmrelayx uses the existing session instead of creating a new one:

```bash

proxychains smbclient.py 'DOMAIN/USER_NAME@TARGET'

```

See how to collect the captured hashes in [NTLM Credentials Gathering](../../Poisoning/NTLM%20Credentials%20Gathering.md).

## References

- CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
- ntlmrelayx.py - https://github.com/fortra/impacket
- The Hacker Recipes - NTLM Relay - https://www.thehacker.recipes/ad/movement/ntlm/relay
- hackndo - https://en.hackndo.com/ntlm-relay/
