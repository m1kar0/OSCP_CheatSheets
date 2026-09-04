**Diamond & Sapphire tickets** — stealthier TGT forgery that avoids the anomalies of a Golden Ticket. A **Diamond ticket** decrypts a *real* TGT with the `krbtgt` key, modifies its PAC, and re-encrypts it (so it inherits legitimate fields). A **Sapphire ticket** goes further, embedding a real privileged user's PAC obtained via S4U2self+u2u.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: `krbtgt` key (same as [Golden Ticket](../Persistence/Golden%20Ticket.md)) + valid domain creds.
- Rubeus `diamond` / Impacket `ticketer.py` sapphire mode (`-impersonate` + `-request`).
- Why they evade common Golden-ticket detections (valid PAC structure, real ticket times), and residual detection.

## References

- The Hacker Recipes - Diamond ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond
- The Hacker Recipes - Sapphire ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire
