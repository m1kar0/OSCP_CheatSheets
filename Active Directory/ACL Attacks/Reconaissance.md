
### Manual

**Goal**: finding dangerous ACLs.

```powershell

$TARGET="Domain Admins"

Get-DomainObjectAcl -Identity $TARGET -Domain inlanefreight.ad -ResolveGUIDs |
  Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword" -or
    ($_.ActiveDirectoryRights -match "WriteProperty" -and $_.ObjectAceType -notmatch "Validated|Self")
  } |
  Select-Object @{
            Name='Identity';
            Expression={Convert-SidToName $_.SecurityIdentifier}
          },
          ActiveDirectoryRights,
          ObjectAceType,
          IsInherited,
          SecurityIdentifier |
  Sort-Object Identity, ActiveDirectoryRights

```

### BloodHound