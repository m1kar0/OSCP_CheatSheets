**Timeroasting** — pull a computer or trust account's password out of the domain controller's clock service, with no credentials at all. Windows DCs answer authenticated-NTP (MS-SNTP) time requests, so if you craft one that names an account by its RID — the numeric tail of the account's SID — the DC replies with a MAC (a keyed checksum) computed from that account's password hash. Mechanically: you feed that MAC to `hashcat -m 31300` and crack it offline; only weak machine or trust passwords fall, but weak ones do turn up.

```
you -> DC:  MS-SNTP time request naming an account RID
DC  -> you: reply + MAC keyed by that account's RC4 hash
you:        crack the MAC offline (hashcat -m 31300)
```

## TODO

Placeholder - full write-up pending. Should cover:
- `timeroast.py` (SecuraBV) against the DC's UDP/123; output crackable with `hashcat -m 31300`.
- Why it works (MS-SNTP MAC keyed by the machine/trust account RC4 hash), and that only weak machine passwords crack.
- Trust-account variant; detection (unusual NTP auth requests).

## References

- Secura - Timeroasting - https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory
- Timeroast (tool) - https://github.com/SecuraBV/Timeroast
