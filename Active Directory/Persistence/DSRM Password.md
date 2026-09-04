**DSRM password abuse** — every DC has a local Directory Services Restore Mode administrator account (the local SAM `Administrator`). Sync it to a known password and flip a registry value to allow its use for network logon, giving a stealthy local-admin backdoor on the DC.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin / admin on the DC.
- Read/set the DSRM hash (mimikatz `token::elevate` + `lsadump::sam`), `ntdsutil "set dsrm password"`.
- Enable network use: `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2`, then PtH as `DC\Administrator`.
- Detection (registry value, DSRM logon events).

## References

- ADSecurity - DSRM persistence - https://adsecurity.org/?p=1714
