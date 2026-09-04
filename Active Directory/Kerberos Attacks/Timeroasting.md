**Timeroasting** — abuse the unauthenticated MS-SNTP (authenticated NTP) flow: send a crafted NTP request referencing a computer/trust account's RID and the DC returns a MAC computed from that account's password hash, which is crackable offline. Needs no credentials.

## TODO

Placeholder - full write-up pending. Should cover:
- `timeroast.py` (SecuraBV) against the DC's UDP/123; output crackable with `hashcat -m 31300`.
- Why it works (MS-SNTP MAC keyed by the machine/trust account RC4 hash), and that only weak machine passwords crack.
- Trust-account variant; detection (unusual NTP auth requests).

## References

- Secura - Timeroasting - https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory
- Timeroast (tool) - https://github.com/SecuraBV/Timeroast
