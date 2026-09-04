**AdminSDHolder / SDProp** — the `AdminSDHolder` object's ACL is stamped onto all protected (Tier-0) groups and their members every ~60 minutes by the SDProp process. Writing a malicious ACE (e.g. `GenericAll` for a controlled user) onto AdminSDHolder yields self-healing rights over Domain Admins et al. - a durable persistence primitive.

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: write access to `CN=AdminSDHolder,CN=System,...` (Domain Admin, or a delegated ACL).
- Add ACE: PowerView `Add-DomainObjectAcl -TargetIdentity 'AdminSDHolder' -Rights All`; verify propagation to protected principals.
- Detection + cleanup (remove the ACE; note `adminCount=1` residue), and link to [ACL abuse primitives](../ACL%20Attacks/_Intro%20to%20ACL%20Attacks.md).

## References

- The Hacker Recipes - AdminSDHolder - https://www.thehacker.recipes/ad/persistence/adminsdholder
