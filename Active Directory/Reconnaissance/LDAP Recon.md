**LDAP recon** — ask Active Directory targeted questions directly over LDAP (the directory protocol AD speaks) instead of hoovering up the whole domain with BloodHound. Any authenticated user can read most of the directory, so you send a filter (for example, only accounts that have a service name set) and get back just the objects and attributes you asked for — handy when you want one specific answer fast. Do it with `ldapsearch` on Linux, `[ADSISearcher]` on a domain-joined Windows box, or the all-in-one `ldeep`.

## Method 1: ldapsearch (Linux)

```bash

ldapsearch -x -H ldap://DC_IP -D 'USER_NAME@DOMAIN' -w 'USER_PASS' -b 'DOMAIN_DN' "LDAP_QUERY_HERE" "OPTIONAL_ATTRIBUTES"

```

**Note:** `DOMAIN_DN` is the domain's Distinguished Name. For `domain.local` it is `dc=domain,dc=local`.

## Method 2: PowerShell (domain-joined Windows)

```powershell

([ADSISearcher]("LDAP_QUERY_HERE")).FindAll() | % {$_.Properties}

```

## Method 3: All-in-one with ldeep

`ldeep` enumerates more objects than the BloodHound ingestors (e.g. the subnet list).

```bash

ldeep ldap -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' -s 'ldap://DC_IP' all './recon/DOMAIN'

```

**Note:** The last argument is the output-file path prefix.

## Common queries

- List AS-REP roastable users - see [ASREP Roasting](../Kerberos%20Attacks/ASREP%20Roasting.md)
- List Kerberoastable users - see [Kerberoasting](../Kerberos%20Attacks/Kerberoasting.md)
- List CAs and certificate templates - see [ADCS Configuration Issues](../ADCS%20Attacks/ADCS%20Configuration%20Issues%20%28ESC1-8%29.md)
- List SCCM servers - see [Tier Zero Server Isolation](Tier%20Zero%20Server%20Isolation.md)
- List pre-Windows 2000 computer accounts - see [Pre-Windows 2000 Computers](Pre-Windows%202000%20Computers.md)
- Get `MachineAccountQuota` - see [Computer Account Creation](Computer%20Account%20Creation%20%28MAQ%29.md)

## References

- ldeep - https://github.com/franc-pentest/ldeep
- Useful LDAP queries for AD pentesting - https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/
