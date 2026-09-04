**GPO abuse** — if you have edit rights over a Group Policy Object (or the OU it is linked to), you can push a malicious policy (scheduled task, startup script, local-admin membership) to every computer/user in scope for code execution and privilege escalation. General technique; see [GPO Onsite Attack](GPO%20Onsite%20Attack.md) for the trust-path variant.

## TODO

Placeholder - full write-up pending. Should cover:
- Discovery: BloodHound `GenericWrite`/`WriteDacl`/`GPLink` edges on GPOs/OUs; `Get-DomainGPO`.
- Abuse: `SharpGPOAbuse` (add scheduled task / local admin / startup script), or `pyGPOAbuse` (Linux).
- Scope control (target a single OU), cleanup, and detection (GPO version bumps, SYSVOL changes).

## References

- The Hacker Recipes - GPO abuse - https://www.thehacker.recipes/ad/movement/group-policies
- SharpGPOAbuse - https://github.com/FSecureLABS/SharpGPOAbuse
- pyGPOAbuse - https://github.com/Hackndo/pyGPOAbuse
