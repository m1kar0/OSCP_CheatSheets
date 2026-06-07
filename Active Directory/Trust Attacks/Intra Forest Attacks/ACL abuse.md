
Get all Principals that have GenericAll over some Object:

``` powershell
#import powerview

Get-DomainObjectAcl -ResolveGUIDs -Identity * -Domain inlanefreight.ad |
  Where-Object {
    ($_.ActiveDirectoryRights -match 'GenericAll') -and
    ($_.AceQualifier -eq 'AccessAllowed') -and
    ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')  # filters out most built-in/well-known SIDs
  } |
  ForEach-Object {
    $Principal = ConvertFrom-SID $_.SecurityIdentifier
    [PSCustomObject]@{
      ObjectDN             = $_.ObjectDN
      Principal            = $Principal
      Rights               = $_.ActiveDirectoryRights
      Inherited            = $_.IsInherited
      AceType              = $_.AceType
    }
  } | Format-Table -AutoSize
```

## Adding Group members

```powershell

# adding memeber from CHILD.local.domain to a group in local.domain

PS C:\Users\Administrator\Desktop> Add-DomainGroupMember -Identity "Admins Group" -Members "CHILD\bob" -Domain domain.local -Verbose


```