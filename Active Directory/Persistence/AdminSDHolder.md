**AdminSDHolder / SDProp** — plant one permission on a single special object and Active Directory itself keeps re-granting you control over its most powerful groups. Every ~60 minutes a background process called SDProp copies the ACL (access control list — the set of permission entries on an object) from the `AdminSDHolder` object onto every protected Tier-0 group (Domain Admins, Enterprise Admins, and so on) and their members, overwriting whatever is there. Write a malicious ACE (an ACE — one entry in that permission list, e.g. `GenericAll` for a user you control) onto AdminSDHolder and SDProp stamps that right onto Domain Admins for you, self-healing even after a defender removes it — a durable persistence primitive.

```
you: write GenericAll ACE -> AdminSDHolder object
SDProp timer (~60 min) -> copies its ACL onto
  Domain Admins, Enterprise Admins + members
=> your rights re-appear even after cleanup
```

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: write access to `CN=AdminSDHolder,CN=System,...` (Domain Admin, or a delegated ACL).
- Add ACE: PowerView `Add-DomainObjectAcl -TargetIdentity 'AdminSDHolder' -Rights All`; verify propagation to protected principals.
- Detection + cleanup (remove the ACE; note `adminCount=1` residue), and link to [ACL abuse primitives](../ACL%20Attacks/_Intro%20to%20ACL%20Attacks.md).

## References

- The Hacker Recipes - AdminSDHolder - https://www.thehacker.recipes/ad/persistence/adminsdholder
