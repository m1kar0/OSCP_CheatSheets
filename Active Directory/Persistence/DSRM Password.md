**DSRM password abuse** — every Domain Controller keeps a hidden local admin account for emergencies, and you can quietly convert it into a lasting backdoor into the DC. That account is the Directory Services Restore Mode (DSRM) administrator — the DC's local SAM `Administrator`, meant for repairing AD when it won't boot normally. Set (or sync) its password to something you know, then flip the registry value `DsrmAdminLogonBehavior` to `2` so the account may log on over the network instead of only at the recovery console. You now hold a stealthy local-admin login on the DC — usable via pass-the-hash — that survives independently of any domain account.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin / admin on the DC.
- Read/set the DSRM hash (mimikatz `token::elevate` + `lsadump::sam`), `ntdsutil "set dsrm password"`.
- Enable network use: `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2`, then PtH as `DC\Administrator`.
- Detection (registry value, DSRM logon events).

## References

- ADSecurity - DSRM persistence - https://adsecurity.org/?p=1714
