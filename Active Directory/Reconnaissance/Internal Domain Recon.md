**Internal domain recon** — work out an organization's internal Active Directory domain name (like `corp.contoso.com`) from the outside, before you have any foothold, because almost every later AD attack needs that name. The highest-yield trick: many internet-facing endpoints (ADFS, Exchange/OWA) still accept NTLM authentication, and when you send them an NTLM negotiate message they answer with a challenge that leaks the AD domain, NetBIOS name, and server FQDN in cleartext — you just decode it.

```
you -> GET + NTLM Type-1 (Negotiate)     -> ADFS/OWA endpoint
you <- 401 WWW-Authenticate: NTLM Type-2 challenge
       Type-2 discloses AD domain, NetBIOS, server FQDN
```

Sources:
- OSINT (public documents, leaks, lists of servers / internal links).
- Web portals (e.g. the domain shown in a login dropdown).
- NTLM reconnaissance against NTLM-enabled web endpoints.

## NTLMRecon

Finds NTLM-enabled web endpoints, sends fake authentication requests, and reads AD Domain Name, Server name, DNS Domain Name, FQDN, and Parent DNS Domain from the NTLMSSP response.

```shell

proxychains ntlmrecon --input https://adfs.contoso.com --outfile results.csv
cat results.csv
# URL,AD Domain Name,Server Name,DNS Domain Name,FQDN,Parent DNS Domain
# https://adfs.contoso.com/adfs/ls/wia,CORP,HAH703C,corp.contoso.com,HAH703C.corp.contoso.com,contoso.com

```

## Nmap http-ntlm-info

```shell

nmap -sT -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/EWS EXCHANGE_HOST
nmap -sT -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/adfs/ls/wia ADFS_HOST
# All *-ntlm-info scripts at once
nmap --script=*-ntlm-info --script-timeout=60s TARGET

```

```shell

| http-ntlm-info:
|   Target_Name: DOMAIN
|   NetBIOS_Domain_Name: DOMAIN
|   NetBIOS_Computer_Name: HOSTNAME
|   DNS_Domain_Name: domain.parent
|   DNS_Computer_Name: hostname.domain.parent
|_  DNS_Tree_Name: parent

```

## Raw HTTP request

A single request to an ADFS/Exchange NTLM endpoint discloses the hostname and internal domain in the `WWW-Authenticate` challenge:

```http

GET /adfs/services/trust/2005/windowstransport HTTP/1.1
Host: adfs.company.com
Authorization: Negotiate TlRMTVNTUAABAAAAl5JI4gAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Negotiate TlRMTVNTUAACAAAA...

```

Decode the challenge with the ntlm-challenge-decoder Burp extension.

**Warning:** This recon is not stealthy and may alert the blue team - use VPNs/proxies to conceal activity.

## References

- NTLMRecon - https://github.com/pwnfoo/NTLMRecon
- ntlm-challenge-decoder (Burp) - https://github.com/PortSwigger/ntlm-challenge-decoder
