**Silver Ticket** — forge a Kerberos Service Ticket (TGS) using a **service or computer account's** key. Unlike a Golden Ticket it never contacts the DC (no `krbtgt` needed) - it targets one service on one host, making it stealthier but narrower.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisites: the target service/computer account hash + domain SID + the SPN.
- Forge: `ticketer.py -spn ...` (Linux), mimikatz `kerberos::golden /service` / Rubeus `silver` (Windows).
- Impersonate a local admin → use the ticket via [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).
- Relationship to [Machine Account to Local Admin (S4U2self)](../Delegation%20Attacks/Computer%20Account%20to%20Local%20Admin.md) and [Golden Ticket](../Persistence/Golden%20Ticket.md); PAC-validation caveat.

## References

- The Hacker Recipes - Silver ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
