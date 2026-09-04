**ACL / DACL attacks** — Active Directory objects each carry a security descriptor (DACL) of ACEs granting principals rights over them. When a low-privileged principal holds a dangerous ACE over a user, group, computer, or the domain object, that right can be converted into credentials, group membership, or code execution. These are the edges BloodHound draws in red - the backbone of most AD privilege-escalation paths.

## The abusable rights

| Right / BloodHound edge | What it grants | Abuse |
| --- | --- | --- |
| `GenericAll` | full control | anything below (reset password, add member, RBCD, shadow creds, targeted kerberoast) |
| `GenericWrite` / `WriteProperty` | write attributes | Shadow Credentials, Targeted Kerberoasting, RBCD, logon-script |
| `WriteDacl` | edit the object's DACL | grant yourself `GenericAll` or `DS-Replication-Get-Changes` (DCSync) |
| `WriteOwner` | change the owner | take ownership → then `WriteDacl` |
| `ForceChangePassword` / `User-Force-Change-Password` | reset the password | reset a user's password (no old password needed) |
| `AddMember` / `Self` (`AddSelf`) | modify group membership | add a principal you control to the group |
| `AllExtendedRights` | all extended rights | includes ForceChangePassword, ReadGMSAPassword, ReadLAPSPassword, DCSync |

## Discovery

**Method 1: BloodHound** - mark owned principals, then look for outbound `GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner`/`ForceChangePassword`/`AddMember`/`ReadGMSAPassword`/`ReadLAPSPassword` edges (and shortest paths to high value).

**Method 2: PowerView** - find dangerous ACLs on a target:

```powershell

$TARGET = "Domain Admins"
Get-DomainObjectAcl -Identity $TARGET -Domain DOMAIN -ResolveGUIDs |
  Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword" -or
    ($_.ActiveDirectoryRights -match "WriteProperty" -and $_.ObjectAceType -notmatch "Validated|Self")
  } |
  Select-Object @{Name='Identity';Expression={ConvertFrom-SID $_.SecurityIdentifier}}, ActiveDirectoryRights, ObjectAceType, IsInherited |
  Sort-Object Identity, ActiveDirectoryRights

```

Enumerate every principal with `GenericAll` across the domain (filter well-known SIDs):

```powershell

Get-DomainObjectAcl -ResolveGUIDs -Identity * -Domain DOMAIN |
  Where-Object { ($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.AceQualifier -eq 'AccessAllowed') -and ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') } |
  ForEach-Object { [PSCustomObject]@{ ObjectDN=$_.ObjectDN; Principal=(ConvertFrom-SID $_.SecurityIdentifier); Rights=$_.ActiveDirectoryRights } } |
  Format-Table -AutoSize

```

**Method 3: from Linux** - `dacledit.py -action read -principal 'USER_NAME' -target 'TARGET' 'DOMAIN/USER_NAME:USER_PASS'`, or `bloodyAD --host DC_IP -d DOMAIN -u USER_NAME -p USER_PASS get writable`.

## Where to go next

- Convert the edge into access - see [DACL Abuse Primitives](DACL%20Abuse%20Primitives.md).
- Specific high-value primitives: [Shadow Credentials](Shadow%20Credentials%20Attack%20Guide.md), [Targeted Kerberoasting](Targeted%20Kerberoasting.md), [Read GMSA Password](Read%20GMSA%20Password.md), [Read LAPS Password](Read%20LAPS%20Password.md), [RBCD](../Delegation%20Attacks/RBCD%20Attack.md), self-grant [DCSync](../Credential%20Dumping/DCSync.md), and [AdminSDHolder](../Persistence/AdminSDHolder.md) persistence.

## References

- The Hacker Recipes - Abusing ACEs - https://www.thehacker.recipes/ad/movement/dacl/
- HackTricks - ACL/DACL abuse - https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html
- SpecterOps - An ACE Up the Sleeve - https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf
