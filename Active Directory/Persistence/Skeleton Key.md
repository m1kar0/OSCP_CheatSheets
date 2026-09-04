**Skeleton Key** — patch the memory of a Domain Controller so that one **fixed, hardcoded** master password logs in as *any* domain account, while each account's own password still works too. The trick tampers with LSASS (the Windows process that handles logins and holds credential secrets) using mimikatz `misc::skeleton`, injecting a backdoor into how it checks passwords. You do not get to choose the password — `misc::skeleton` always sets it to `mimikatz` — so after that you can authenticate as any user with that one password: a stealthy, domain-wide backdoor. It lives only in memory, so it grants access until the DC reboots and is lost on restart.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin / code execution on the DC.
- `mimikatz misc::skeleton`; default master password (`mimikatz`), usage examples (`net use`, PtH-style access).
- Volatility (memory-only; lost on reboot) and detection (LSASS tampering, `misc::skeleton` signatures, RC4 downgrade).

## References

- The Hacker Recipes / ADSecurity - Skeleton Key - https://adsecurity.org/?p=1275
