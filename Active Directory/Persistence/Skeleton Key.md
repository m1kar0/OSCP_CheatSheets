**Skeleton Key** — patch LSASS on a Domain Controller (mimikatz `misc::skeleton`) so a master password is accepted for *any* domain account alongside the real one. Grants stealthy, domain-wide authentication until the DC reboots (in-memory only).

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin / code execution on the DC.
- `mimikatz misc::skeleton`; default master password (`mimikatz`), usage examples (`net use`, PtH-style access).
- Volatility (memory-only; lost on reboot) and detection (LSASS tampering, `misc::skeleton` signatures, RC4 downgrade).

## References

- The Hacker Recipes / ADSecurity - Skeleton Key - https://adsecurity.org/?p=1275
