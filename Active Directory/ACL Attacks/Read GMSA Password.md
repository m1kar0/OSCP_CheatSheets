**Read GMSA password** — group Managed Service Accounts store their auto-rotated password in the `msDS-ManagedPassword` attribute, readable only by principals listed in `msDS-GroupMSAMembership` (the `ReadGMSAPassword` BloodHound edge). If you control such a principal, you can recover the gMSA's NT hash and act as that (often privileged) account.

## TODO

Placeholder - full write-up pending. Should cover:
- Discovery: BloodHound `ReadGMSAPassword` edge; enumerate gMSAs and who can read them.
- Read: `gMSADumper.py` (Linux), `Get-ADServiceAccount ... -Properties msDS-ManagedPassword` / GMSAPasswordReader (Windows) → derive NT hash.
- Use the hash (PtH / tickets) via [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md); contrast with Golden GMSA (KDS root key).

## References

- The Hacker Recipes - Kerberos / gMSA - https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword
- gMSADumper - https://github.com/micahvandeusen/gMSADumper
