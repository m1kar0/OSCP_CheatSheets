**Golden Ticket** — forge a Kerberos TGT using the `krbtgt` account's key. Because every TGT is encrypted/signed with `krbtgt`, a forged one lets you impersonate any user (including Domain Admins) with arbitrary group membership, for domain-wide access and long-term persistence.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisites: `krbtgt` NT hash / AES key + domain SID (from [Dump NTDS.dit](../Credential%20Dumping/Dump%20NTDS.dit.md) / DCSync).
- Forge: `ticketer.py` (Linux) and mimikatz `kerberos::golden` / Rubeus `golden` (Windows).
- Use the ticket → [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).
- Persistence angle + detection (double `krbtgt` reset to invalidate), and contrast with [Silver Ticket](../Kerberos%20Attacks/Silver%20Ticket.md) and [Diamond/Sapphire](../Kerberos%20Attacks/Diamond%20and%20Sapphire%20Tickets.md).

## References

- The Hacker Recipes - Golden ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
