**Identify Domain Controllers** — find the IP of the on-premise Domain Controllers (DCs — the servers that run Active Directory and authenticate every login) once you are on the internal network, since nearly every AD attack is aimed at them. DCs are usually the network's DNS servers, so you start from your own DNS/DHCP settings, then confirm a host really is a DC by checking that Kerberos (TCP 88) answers, and finally query AD's own SRV DNS records (`_kerberos._tcp`, `_ldap._tcp`, ...) which point straight at every DC.

## 1. Check your network configuration

DCs are often the default DNS servers. If DHCP configured your network, check that first.

```bash

# Linux
cat /etc/resolv.conf

```

```batch

REM Windows - check "DNS Servers"
ipconfig /all
REM Domain-joined machine + domain session
echo %LOGONSERVER%

```

## 2. Confirm the target is a DC

Default DNS servers are not always DCs. Check whether Kerberos (TCP 88) is reachable:

```console

$ nc -v DNS_IP 88
Ncat: Connected to DNS_IP:88

$ nmap -p88 -sV -Pn -n DNS_IP
PORT   STATE SERVICE      VERSION
88/tcp open  kerberos-sec Microsoft Windows Kerberos

```

**Note:** If Kerberos is not reachable, the host is most likely a standalone DNS server, not a DC.

## 3. Use AD default DNS records

Active Directory registers several SRV records you can query to find DCs:

```bash

nslookup -type=srv _kerberos._tcp.DNS_SUFFIX DNS_IP
nslookup -type=srv _kpasswd._tcp.DNS_SUFFIX DNS_IP
nslookup -type=srv _gc._tcp.DNS_SUFFIX DNS_IP
nslookup -type=srv _ldap._tcp.DNS_SUFFIX DNS_IP

```

**Note:** The DNS server IP is optional if `/etc/resolv.conf` is set correctly.

```console

$ nslookup -type=srv _kerberos._tcp.domain.local 10.0.0.10
_kerberos._tcp.domain.local    service = 0 100 88 dc01.domain.local.

```

## References

- The Hacker Recipes - AD recon - https://www.thehacker.recipes/ad/recon
