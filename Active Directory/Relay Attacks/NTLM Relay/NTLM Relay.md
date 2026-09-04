**NTLM relay** — a weakness in NTLM lets an attacker relay an authentication meant for service A to service B, impersonating the victim on the target service. If the relayed identity has enough privilege on the target, this can lead to code execution. It works whenever you can force a user or computer to authenticate to your machine.

Two things to line up for any relay:

**Source of the relay** - how you get a victim to authenticate to you:
- [LLMNR and NBT-NS Poisoning](../../Poisoning/LLMNR%20and%20NBT-NS%20Poisoning.md)
- [DHCP Poisoning](DHCP%20Poisoning.md)
- [Coercing Authentication](../../Coercion/Coercing%20Authentication.md)

**Target of the relay** - a vulnerable service on a domain-joined machine:
- [NTLM Relay to SMB](NTLM%20Relay%20to%20SMB.md)
- [NTLM Relay to LDAP](NTLM%20Relay%20to%20LDAP.md)
- [NTLM Relay to ADCS](NTLM%20Relay%20to%20ADCS.md)
- [NTLM Relay to MSSQL](NTLM%20Relay%20to%20MSSQL.md)
- [NTLM Relay to SCCM](NTLM%20Relay%20to%20SCCM.md)

## Caution

Depending on the target service and chosen attack, extra steps may be needed to clean up artifacts left behind.

## References

- ntlmrelayx.py - https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
- MultiRelay - https://github.com/lgandx/Responder/wiki/MultiRelay
- A comprehensive guide on relaying (2022) - https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/
- NTLM Relay - https://en.hackndo.com/ntlm-relay/
