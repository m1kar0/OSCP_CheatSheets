**Domain user enumeration** — build a clean list of valid domain usernames, the prerequisite for any [password spraying](Domain%20Password%20Spraying.md) or bruteforce attack. You harvest the `sAMAccountName` of every account from data you can already read — an existing BloodHound dump, Impacket's `GetADUsers.py`, or `ldapdomaindump` — then normalise it (lowercase, strip the domain suffix, transliterate accents) so the names feed cleanly into your spraying tool.

## Method 1: BloodHound + jq

Parse an existing BloodHound dump (see [BloodHound and JQ](BloodHound%20and%20JQ.md)):

```bash

# List enabled users, strip quotes, take the sAMAccountName, lowercase it
cat BLOODHOUND_users.json | jq '.data[].Properties | select (.enabled == true) | .name' | sed s/'"'//g | awk -F '@' '{ print tolower($1) }' | sort -u
# Same for domain-joined machines
cat BLOODHOUND_computers.json | jq '.data[].Properties | select (.enabled == true) | .name' | sed s/'"'//g | awk -F '@' '{ print tolower($1) }' | sort -u

```

## Method 2: GetADUsers.py (impacket)

```bash

# Skip impacket's header lines, take the username, lowercase, transliterate non-ASCII
GetADUsers.py 'DOMAIN/USER_NAME:USER_PASS' -dc-ip DC_IP -all | tail -n +6 | awk '{ print tolower($1) }' | iconv -f utf-8 -t ascii//translit | sort -u

```

**Note:** `-all` is needed to list users without an email, but it also includes disabled accounts. The transliteration matters because many tools (e.g. Metasploit) choke on non-ASCII - converting `é` to `e` is fine, AD understands it.

## Method 3: ldapdomaindump + jq

```bash

cat domain_users.json | jq -r '.[].attributes.sAMAccountName[]' | tr '[:upper:]' '[:lower:]' | sort -u

```

A list of valid users is the prerequisite for [Domain Password Spraying](Domain%20Password%20Spraying.md).

## References

- BloodHound.py - https://github.com/fox-it/BloodHound.py
- impacket - https://github.com/fortra/impacket
- ldapdomaindump - https://github.com/dirkjanm/ldapdomaindump
