**GPO abuse** — a Group Policy Object (GPO — a bundle of settings that Active Directory pushes down to the computers and users it is linked to) is applied automatically and with high privilege on every machine in its scope. If you hold edit rights over a GPO, or over the OU (organizational unit — a container of AD objects) the GPO is linked to, you can drop in a malicious setting — a scheduled task, a startup script, or adding yourself to the local Administrators group — and it runs everywhere in scope, handing you code execution and privilege escalation. This is the general technique; see [GPO Onsite Attack](GPO%20Onsite%20Attack.md) for the trust-path variant.

## TODO

Placeholder - full write-up pending. Should cover:
- Discovery: BloodHound `GenericWrite`/`WriteDacl`/`GPLink` edges on GPOs/OUs; `Get-DomainGPO`.
- Abuse: `SharpGPOAbuse` (add scheduled task / local admin / startup script), or `pyGPOAbuse` (Linux).
- Scope control (target a single OU), cleanup, and detection (GPO version bumps, SYSVOL changes).

## References

- The Hacker Recipes - GPO abuse - https://www.thehacker.recipes/ad/movement/group-policies
- SharpGPOAbuse - https://github.com/FSecureLABS/SharpGPOAbuse
- pyGPOAbuse - https://github.com/Hackndo/pyGPOAbuse
