**Tier Zero server isolation** — internal networks should follow a tiered model where the most sensitive servers (DCs, CAs, backup servers, SCCM, etc.) are not reachable by regular users. Where that segmentation is missing, any remote-access service exposed on a Tier Zero server is a finding ("network segmentation issue").

## Discovery

Enumerate the Tier Zero servers first.

### DCs, RODCs, DNS, ADCS

Use BloodHound, PingCastle, Certipy, or any AD enumeration tool to identify Domain Controllers, Read-Only DCs, DNS servers (usually on DCs), and Certificate Authorities.

### SCCM

```bash

# Remotely with sccmhunter (domain user)
python3 sccmhunter.py find -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' -dc-ip 'DC_IP'

```

Or via LDAP - query objects of class `mSSMSManagementPoint` (see [LDAP Recon](LDAP%20Recon.md)):

```

"objectClass=mSSMSManagementPoint"

```

Or locally via WMI from a domain-joined machine (check `CurrentManagementEndpoint`):

```powershell

Get-WmiObject -Class SMS_Authority -Namespace root\CCM

```

Follow-ups: [SCCM Distribution Points](../SCCM%20Attacks/SCCM%20Distribution%20Points.md), [SCCM NAA Credentials](../SCCM%20Attacks/SCCM%20NAA%20Credentials.md), [NTLM Relay to SCCM](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20SCCM.md).

### Veeam Backup

Scan for hosts listening on TCP 9401 (narrow the list to known domain computers first - see [Domain User Enumeration](Domain%20User%20Enumeration.md)):

```bash

nmap -p9401 --open -sV TARGET_SUBNET
nmap -p9401 --open -sV -iL TARGET_FILE

```

```console

PORT     STATE SERVICE VERSION
9401/tcp open  mc-nmf  .NET Message Framing

```

## Exploitation

Port-scan each Tier Zero server. Any service usable for remote access / command execution (SMB, WMI, RDP, WinRM, ...) reachable from a user segment is a segmentation issue. Known exceptions:
- TCP 445 must be reachable on DCs (GPO deployment, logon scripts).
- RPC ports must be reachable on ADCS servers (certificate delivery).

## References

- Attacking the Microsoft Configuration Manager (SCCM/MECM) - https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/
