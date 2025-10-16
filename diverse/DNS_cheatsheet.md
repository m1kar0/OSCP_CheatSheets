# Pentesting DNS

## Discovery

* DNS runs on TCP and UDP ports 53

```bash

nmap -p53 --open -sC 123.132.34.23

```

* Banner grabbing

`dig version.bind CHAOS TXT @DNS`

* Return all info

`dig any victim.com @<DNS_IP>`

## Lookup

* direct

`dig google.com`

* reverse

`dig -x 192.168.0.2 @<DNS_IP>`

### nslookup

```powershell

nslookup -type=TXT info.domain.com 192.168.xxx.xxx

```

## Records

* DNS server may have following records

```text

NS - Nameserver records 
A - contains the IP address of hostname 
MX - Mail Exchange records with mail
PTR - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
CNAME - Canonical Name Records are used to create aliases for other host records like Subdomains
TXT - Text records can contain any arbitrary data like SPF records

```

* Get txt record

`dig -t txt dns.google.com`

### AS lookup

* Every corp registers its IP range with AS number.
* Here is the way of finding that out: https://hackertarget.com/as-ip-lookup/

## DNS Zone Transfer

This misconfiguration may reveal hiffen domains and hosts behind firewalls and other defences.

```bash
# taken from https://book.hacktricks.xyz/

dig axfr @<DNS_IP> #Try zone transfer without domain
dig axfr @<DNS_IP> <DOMAIN> #Try zone transfer guessing the domain

```

## Using nslookup

Alternative way especially for windows

```bash
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...
```

Zone traversal

`dnsrecon -d target.com -t axfr`



## Sub/Domain takeover

## Recon with DNSreaper

```bash
sudo docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/domains.txt
```

`domains.txt`: list of domains to check

## Domain takeover in general

It is possible sometimes to takeover DNS zones. Depends if zone is vulnerable. 
Look for `SERVFAIL` fault.

https://github.com/indianajson/can-i-take-over-dns

## AWS DNS

### AWS buckets

see: https://0xpatrik.com/takeover-proofs/

1. get some CNAME

```bash



```

2. check CNAME

```powershell

# {bucketname}.s3.amazonaws.com
^[a-z0-9\.\-]{0,63}\.?s3.amazonaws\.com$

# {bucketname}.s3-website(.|-){region}.amazonaws.com (+ possible China region)
^[a-z0-9\.\-]{3,63}\.s3-website[\.-](eu|ap|us|ca|sa|cn)-\w{2,14}-\d{1,2}\.amazonaws.com(\.cn)?$

# {bucketname}.s3(.|-){region}.amazonaws.com
^[a-z0-9\.\-]{3,63}\.s3[\.-](eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$

# {bucketname}.s3.dualstack.{region}.amazonaws.com
^[a-z0-9\.\-]{3,63}\.s3.dualstack\.(eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$

```
3. test for subdomain takeover possibility

``` bash
http -b GET http://{SOURCE DOMAIN NAME} | grep -E -q '<Code>NoSuchBucket</Code>|<li>Code: NoSuchBucket</li>' && echo "Subdomain takeover may be possible" || echo "Subdomain takeover is not possible"

```

## Subdomain enumeration

### sublister

sublister [-h] -d DOMAIN [-b [BRUTEFORCE]] [-p PORTS] [-v [VERBOSE]] [-t THREADS] [-e ENGINES] [-o OUTPUT] [-n]
